#!/usr/bin/env bash
# Builds the Linux x86_64 AppImage from the jpackage app image of :app:createReleaseDistributable (the same ProGuard
# build and bundled Java runtime as the Windows MSI). The file is an AppImage type 2: a static runtime followed by a
# SquashFS of the AppDir, with the magic bytes AI 02 at offset 8.
#
# The runtime is this project's own tools/appimage-runtime (Rust, static musl, pure-Rust SquashFS and gzip): the
# official type2-runtime links libfuse statically, and native code shipped with the app may not contain GPL, LGPL or
# AGPL components (AGENTS.md). It does not mount the image: the first start unpacks it into
# ~/.cache/diw-appimage/<digest>/ and every start runs AppRun from there, so no FUSE is needed.
#
# AppDir layout: AppRun starts usr/lib/DIW-MY-WALLET/bin/DIW-MY-WALLET (the jpackage launcher finds its runtime and
# jars relative to itself), with the desktop entry and the icon at the top as the AppImage format asks.
# Needs cargo with rustup (tools/appimage-runtime/rust-toolchain.toml installs the pinned Rust and the musl target)
# and mksquashfs (squashfs-tools). Paths are relative to the repository root.
# Usage: tools/linux-appimage.sh <app image folder> <output .AppImage>
set -euo pipefail
cd "$(dirname "$0")/.."
[ $# -eq 2 ] || { echo "Usage: $0 <app image folder> <output .AppImage>" >&2; exit 2; }
image=$1
out=$2
name=DIW-MY-WALLET
[ -x "$image/bin/$name" ] || { echo "$image/bin/$name not found: pass the folder of :app:createReleaseDistributable" >&2; exit 1; }
command -v mksquashfs > /dev/null || { echo "mksquashfs not found: install squashfs-tools" >&2; exit 1; }

echo "== runtime"
(cd tools/appimage-runtime && cargo build --release --locked --target x86_64-unknown-linux-musl)
runtime=tools/appimage-runtime/target/x86_64-unknown-linux-musl/release/diw-appimage-runtime

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
appdir=$work/AppDir
mkdir -p "$appdir/usr/lib"
cp -a "$image" "$appdir/usr/lib/$name"

cat > "$appdir/AppRun" <<'SH'
#!/bin/sh
here=$(dirname "$(readlink -f "$0")")
exec "$here/usr/lib/DIW-MY-WALLET/bin/DIW-MY-WALLET" "$@"
SH
chmod 755 "$appdir/AppRun"

cat > "$appdir/diw-my-wallet.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=DIW MY WALLET
Comment=Digital credentials, signatures and documents
Comment[zh_TW]=數位憑證、電子簽章與文件
Comment[zh_CN]=数字凭证、电子签章与文件
Exec=DIW-MY-WALLET %U
Icon=diw-my-wallet
Categories=Office;Security;
Terminal=false
DESKTOP
cp app/icons/app-icon.png "$appdir/diw-my-wallet.png"
ln -s diw-my-wallet.png "$appdir/.DirIcon"
cp LICENSE NOTICE "$appdir/"

echo "== SquashFS"
# gzip: the runtime reads it in pure Rust (zlib-rs).
mksquashfs "$appdir" "$work/app.squashfs" -root-owned -noappend -comp gzip -quiet
mkdir -p "$(dirname "$out")"
cat "$runtime" "$work/app.squashfs" > "$out"
# AppImage type 2 magic in the ELF identification padding (bytes 8 to 10), which the loader ignores.
printf 'AI\002' | dd of="$out" bs=1 seek=8 count=3 conv=notrunc status=none
chmod 755 "$out"
# The runtime must find the image exactly where it was appended.
offset=$("$(realpath "$out")" --appimage-offset)
[ "$offset" = "$(stat -c %s "$runtime")" ] || { echo "Runtime reports offset $offset, expected $(stat -c %s "$runtime")" >&2; exit 1; }
ls -l "$out"
