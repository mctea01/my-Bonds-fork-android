#!/usr/bin/env bash
# Builds the Linux x86_64 AppImage from the jpackage app image of :app:createReleaseDistributable (the same ProGuard
# build and bundled Java runtime as the Windows MSI). An AppImage is the static AppImage type 2 runtime followed by a
# SquashFS of the AppDir; the runtime mounts it with FUSE (fusermount or fusermount3, no libfuse2 needed) or, with
# --appimage-extract-and-run, unpacks it to a temporary folder first. The runtime is a pinned release of
# AppImage/type2-runtime (MIT), checked against its SHA-256; appimagetool is not used.
#
# AppDir layout: AppRun starts usr/lib/DIW-MY-WALLET/bin/DIW-MY-WALLET (the jpackage launcher finds its runtime and
# jars relative to itself), with the desktop entry and the icon at the top as the AppImage format asks.
# Needs mksquashfs (squashfs-tools 4.4 or later, for zstd) and curl.
# Usage: tools/linux-appimage.sh <app image folder> <output .AppImage>
set -euo pipefail
cd "$(dirname "$0")/.."
[ $# -eq 2 ] || { echo "Usage: $0 <app image folder> <output .AppImage>" >&2; exit 2; }
image=$1
out=$2
name=DIW-MY-WALLET
runtime_version=20251108
runtime_sha256=2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d
[ -x "$image/bin/$name" ] || { echo "$image/bin/$name not found: pass the folder of :app:createReleaseDistributable" >&2; exit 1; }
command -v mksquashfs > /dev/null || { echo "mksquashfs not found: install squashfs-tools" >&2; exit 1; }

# The runtime, downloaded once into the cache and checked every time.
cache=${XDG_CACHE_HOME:-$HOME/.cache}/diw-appimage
runtime=$cache/runtime-x86_64-$runtime_version
mkdir -p "$cache"
if [ ! -f "$runtime" ]; then
    curl -fsSL --retry 3 -o "$runtime.part" \
        "https://github.com/AppImage/type2-runtime/releases/download/$runtime_version/runtime-x86_64"
    mv "$runtime.part" "$runtime"
fi
echo "$runtime_sha256  $runtime" | sha256sum -c --quiet - || { rm -f "$runtime"; echo "AppImage runtime checksum mismatch" >&2; exit 1; }

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

mksquashfs "$appdir" "$work/app.squashfs" -root-owned -noappend -comp zstd -quiet
mkdir -p "$(dirname "$out")"
cat "$runtime" "$work/app.squashfs" > "$out"
chmod 755 "$out"
ls -l "$out"
