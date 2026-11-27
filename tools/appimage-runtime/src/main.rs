//! AppImage runtime of DIW MY WALLET, written for this project so that the AppImage carries no GPL or LGPL code
//! (the official type2-runtime links libfuse statically). The file is this static executable followed by a SquashFS
//! image of the AppDir, as in an AppImage type 2. Instead of mounting the image with FUSE, the first start unpacks it
//! into the user's cache (one folder per image, named by a digest of its superblock and size) and every start runs
//! AppRun from there. So no FUSE is needed; the first start of a new version takes a few seconds longer.
//!
//! Options (the rest of the arguments go to the app):
//!   --appimage-extract          unpack the image into ./squashfs-root and exit
//!   --appimage-extract-and-run  accepted for compatibility; this runtime always does that
//!   --appimage-offset           print the offset of the image in this file
//!   --appimage-version          print the runtime version
//!   --appimage-help             print this help

use backhand::{FilesystemReader, InnerNode};
use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{exit, Command};
use std::time::{Duration, SystemTime};

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Cache folders not used for this long are removed by the next start of any version.
const KEEP_UNUSED: Duration = Duration::from_secs(14 * 24 * 3600);

fn main() {
    if let Err(e) = run() {
        eprintln!("AppImage runtime: {e}");
        exit(1);
    }
}

fn run() -> io::Result<()> {
    let me = fs::canonicalize("/proc/self/exe")?;
    let offset = image_offset(&me)?;
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    match args.first().and_then(|a| a.to_str()) {
        Some("--appimage-offset") => {
            println!("{offset}");
            return Ok(());
        }
        Some("--appimage-version") => {
            println!("diw-appimage-runtime {VERSION}");
            return Ok(());
        }
        Some("--appimage-help") => {
            println!(
                "--appimage-extract          unpack into ./squashfs-root\n\
                 --appimage-extract-and-run  run (always unpacks into the cache first)\n\
                 --appimage-offset           offset of the SquashFS image\n\
                 --appimage-version          runtime version"
            );
            return Ok(());
        }
        Some("--appimage-extract") => {
            let target = env::current_dir()?.join("squashfs-root");
            extract(&me, offset, &target)?;
            println!("{}", target.display());
            return Ok(());
        }
        _ => {}
    }
    let args: Vec<OsString> =
        args.into_iter().filter(|a| a.to_str() != Some("--appimage-extract-and-run")).collect();

    let cache = cache_root()?;
    fs::create_dir_all(&cache)?;
    let key = image_key(&me, offset)?;
    let appdir = cache.join(&key);
    if !appdir.join("AppRun").exists() {
        // Unpack beside the final folder and rename it into place: a folder under the final name is always complete,
        // and two starts at once both succeed (the second one drops its copy).
        let partial = cache.join(format!(".{key}.{}", std::process::id()));
        let _ = fs::remove_dir_all(&partial);
        eprintln!("Preparing the app for its first start in {} ...", appdir.display());
        extract(&me, offset, &partial)?;
        if fs::rename(&partial, &appdir).is_err() {
            let _ = fs::remove_dir_all(&partial);
            if !appdir.join("AppRun").exists() {
                return Err(io::Error::other(format!("cannot create {}", appdir.display())));
            }
        }
    }
    touch(&appdir);
    remove_unused(&cache, &key);

    let err = Command::new(appdir.join("AppRun"))
        .args(&args)
        .env("APPIMAGE", &me)
        .env("APPDIR", &appdir)
        .env("ARGV0", env::args_os().next().unwrap_or_default())
        .env("OWD", env::current_dir().unwrap_or_default())
        .exec();
    Err(io::Error::other(format!("cannot start {}: {err}", appdir.join("AppRun").display())))
}

/// End of this ELF file: the section header table is its last part, and the image starts right after it.
fn image_offset(me: &Path) -> io::Result<u64> {
    let mut header = [0u8; 64];
    File::open(me)?.read_exact(&mut header)?;
    if &header[..4] != b"\x7fELF" || header[4] != 2 || header[5] != 1 {
        return Err(io::Error::other("not a 64-bit little-endian ELF file"));
    }
    let shoff = u64::from_le_bytes(header[0x28..0x30].try_into().unwrap());
    let shentsize = u16::from_le_bytes(header[0x3a..0x3c].try_into().unwrap()) as u64;
    let shnum = u16::from_le_bytes(header[0x3c..0x3e].try_into().unwrap()) as u64;
    Ok(shoff + shentsize * shnum)
}

/// FNV-1a over the SquashFS superblock (creation time, sizes, table positions) and the file length.
fn image_key(me: &Path, offset: u64) -> io::Result<String> {
    let mut file = File::open(me)?;
    let length = file.metadata()?.len();
    let mut superblock = [0u8; 96];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut superblock)?;
    if &superblock[..4] != b"hsqs" {
        return Err(io::Error::other("no SquashFS image after the runtime"));
    }
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in superblock.iter().chain(length.to_le_bytes().iter()) {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    Ok(format!("{hash:016x}"))
}

fn cache_root() -> io::Result<PathBuf> {
    let base = match env::var_os("XDG_CACHE_HOME").filter(|v| !v.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(env::var_os("HOME").ok_or_else(|| io::Error::other("HOME is not set"))?).join(".cache"),
    };
    Ok(base.join("diw-appimage"))
}

/// Unpacks the image into `target`: folders, files with their permission bits, symbolic links. Paths that would
/// leave `target` are refused.
fn extract(me: &Path, offset: u64, target: &Path) -> io::Result<()> {
    let reader = BufReader::new(File::open(me)?);
    let fs = FilesystemReader::from_reader_with_offset(reader, offset).map_err(io::Error::other)?;
    fs::create_dir_all(target)?;
    let mut dirs = Vec::new();
    for node in fs.files() {
        let relative: PathBuf = node.fullpath.components().filter(|c| !matches!(c, Component::RootDir)).collect();
        if relative.components().any(|c| !matches!(c, Component::Normal(_))) {
            return Err(io::Error::other(format!("unsafe path {}", node.fullpath.display())));
        }
        let path = target.join(&relative);
        let mode = (node.header.permissions & 0o7777) as u32;
        match &node.inner {
            InnerNode::Dir(_) => {
                fs::create_dir_all(&path)?;
                dirs.push((path, mode));
            }
            InnerNode::File(file) => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut out = File::create(&path)?;
                io::copy(&mut fs.file(file).reader(), &mut out)?;
                out.flush()?;
                fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
            }
            InnerNode::Symlink(link) => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                symlink(&link.link, &path)?;
            }
            // Devices, pipes and sockets have no place in an AppDir.
            _ => {}
        }
    }
    // Folder permissions last, so a read-only folder does not stop its own contents.
    for (path, mode) in dirs.into_iter().rev() {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode | 0o700))?;
    }
    Ok(())
}

fn touch(dir: &Path) {
    if let Ok(f) = File::open(dir) {
        let _ = f.set_modified(SystemTime::now());
    }
}

/// Removes cache folders of other images that no start has used for KEEP_UNUSED, and partial ones of crashed starts.
fn remove_unused(cache: &Path, keep: &str) {
    let Ok(entries) = fs::read_dir(cache) else { return };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_str() == Some(keep) {
            continue;
        }
        let old = entry
            .metadata()
            .and_then(|m| m.modified())
            .map(|t| now.duration_since(t).unwrap_or_default() > KEEP_UNUSED)
            .unwrap_or(false);
        if old {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}
