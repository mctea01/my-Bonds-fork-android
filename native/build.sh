#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# A release matrix runs this script on each desktop host. Cross builds require
# the corresponding SDK/linker in Cargo's target configuration.
NDK_VERSION=28.2.13676358
CARGO_NDK_VERSION=4.1.2
host=$(rustc -vV | sed -n 's/^host: //p')
targets=${1:-all}
if [[ "$targets" == all ]]; then
    targets=x86_64-unknown-linux-gnu,x86_64-pc-windows-gnu,aarch64-apple-darwin,android
fi
targets=${targets//host/$host}
IFS=',' read -ra selected <<< "$targets"
for target in "${selected[@]}"; do
    if [[ "$target" == android ]]; then
        : "${ANDROID_HOME:?Set ANDROID_HOME to an installed Android SDK}"
        export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$NDK_VERSION"
        [[ -f "$ANDROID_NDK_HOME/source.properties" ]] || { echo "Pinned NDK is missing" >&2; exit 1; }
        grep -Eq "Pkg.Revision *= *$NDK_VERSION$" "$ANDROID_NDK_HOME/source.properties" || exit 1
        [[ "$(cargo ndk --version)" == "cargo-ndk $CARGO_NDK_VERSION" ]] || { echo "Pinned cargo-ndk is required" >&2; exit 1; }
        rustup target add aarch64-linux-android x86_64-linux-android
        cargo ndk -t arm64-v8a -t x86_64 --platform 29 -o dist/android build --release --locked -p diw-zk-ffi
    else
        case "$target" in
            x86_64-unknown-linux-gnu) platform=linux-x86_64; library=libdiw_zk.so ;;
            x86_64-pc-windows-gnu|x86_64-pc-windows-msvc) platform=windows-x86_64; library=diw_zk.dll ;;
            aarch64-apple-darwin) platform=macos-aarch64; library=libdiw_zk.dylib ;;
            *) echo "Unsupported desktop target" >&2; exit 1 ;;
        esac
        rustup target add "$target"
        cargo build --release --locked -p diw-zk-ffi --target "$target"
        mkdir -p "dist/resources/zk/native/$platform"
        cp "target/$target/release/$library" "dist/resources/zk/native/$platform/$library"
        # sha256sum on Linux and Git for Windows, shasum on macOS.
        path="dist/resources/zk/native/$platform/$library"
        if command -v sha256sum > /dev/null; then digest=$(sha256sum "$path"); else digest=$(shasum -a 256 "$path"); fi
        printf '%s\n' "${digest%% *}" > "$path.sha256"
    fi
done
