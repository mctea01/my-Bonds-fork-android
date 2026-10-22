#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
host=$(rustc -vV | sed -n 's/^host: //p')
targets=${1:-host}
targets=${targets//host/$host}
[[ "$(rustc --version)" == 'rustc 1.95.0 '* ]] || { echo 'Rust 1.95.0 is required' >&2; exit 1; }
python3 -I openac-age/prepare.py --sources-only
IFS=',' read -ra selected <<< "$targets"
for target in "${selected[@]}"; do
    if [[ "$target" == android ]]; then
        : "${ANDROID_HOME:?Set ANDROID_HOME}"
        export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/28.2.13676358"
        export ANDROID_NDK="$ANDROID_NDK_HOME"
        [[ -f "$ANDROID_NDK_HOME/source.properties" ]] || { echo 'Pinned Android NDK is required' >&2; exit 1; }
        grep -Eq 'Pkg.Revision *= *28.2.13676358$' "$ANDROID_NDK_HOME/source.properties"
        [[ "$(cargo ndk --version)" == 'cargo-ndk 4.1.2' ]] || { echo 'cargo-ndk 4.1.2 is required' >&2; exit 1; }
        rustup target add aarch64-linux-android x86_64-linux-android
        cargo ndk -t arm64-v8a -t x86_64 --platform 29 -o dist/android build --release --locked -p diw-zk-ffi --features openac
    else
        case "$target" in
            x86_64-unknown-linux-gnu) platform=linux-x86_64; library=libdiw_zk.so ;;
            x86_64-pc-windows-msvc|x86_64-pc-windows-gnu) platform=windows-x86_64; library=diw_zk.dll ;;
            aarch64-apple-darwin) platform=macos-aarch64; library=libdiw_zk.dylib ;;
            *) echo 'Unsupported OpenAC desktop target' >&2; exit 1 ;;
        esac
        rustup target add "$target"
        cargo build --release --locked -p diw-zk-ffi --features openac --target "$target"
        output="dist/resources/zk/native/$platform/$library"
        mkdir -p "$(dirname "$output")"
        cp "target/$target/release/$library" "$output"
        python3 - "$output" <<'PY'
import hashlib, pathlib, sys
path = pathlib.Path(sys.argv[1])
with path.open('rb') as source:
    digest = hashlib.file_digest(source, 'sha256').hexdigest()
path.with_suffix(path.suffix + '.sha256').write_text(digest + '\n')
PY
    fi
done
# Generate the expanded namespace separately. Claude can review and integrate it
# into core; this package does not overwrite WP0's checked-in Kotlin source.
mkdir -p openac-age/build/bindings
cargo build --lib --release --locked -p diw-zk-ffi --features openac,bindgen --target "$host"
cargo run --release --locked -p diw-zk-ffi --features openac,bindgen --target "$host" --bin uniffi-bindgen -- \
    generate --library "target/$host/release/$(case "$host" in *windows*) echo diw_zk.dll ;; *apple*) echo libdiw_zk.dylib ;; *) echo libdiw_zk.so ;; esac)" \
    --language kotlin --config diw-zk-ffi/uniffi.toml --out-dir openac-age/build/bindings
cargo run --release --locked -p diw-zk-ffi --features openac,bindgen --target "$host" --bin uniffi-bindgen -- \
    generate --library "target/$host/release/$(case "$host" in *windows*) echo diw_zk.dll ;; *apple*) echo libdiw_zk.dylib ;; *) echo libdiw_zk.so ;; esac)" \
    --language python --out-dir openac-age/build/python
case "$host" in
    *windows*) host_library=diw_zk.dll ;;
    *apple*) host_library=libdiw_zk.dylib ;;
    *) host_library=libdiw_zk.so ;;
esac
cp "target/$host/release/$host_library" "openac-age/build/python/$host_library"
