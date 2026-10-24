#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
cargo build --release --locked -p diw-zk-ffi
case "$(uname -s)" in
    Linux*) library=target/release/libdiw_zk.so ;;
    Darwin*) library=target/release/libdiw_zk.dylib ;;
    MINGW*|MSYS*) library=target/release/diw_zk.dll ;;
    *) echo "Unsupported host" >&2; exit 1 ;;
esac
cargo run --locked -p diw-zk-ffi --features bindgen --bin uniffi-bindgen -- generate \
    --library "$library" --language kotlin --config diw-zk-ffi/uniffi.toml \
    --out-dir ../core/src/jvmCommonMain/kotlin/diw/wallet/core/zk/native/generated
