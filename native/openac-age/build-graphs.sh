#!/usr/bin/env bash
# GPL compiler tools run here only; graph assets are never embedded in the app.
set -euo pipefail
cd "$(dirname "$0")"
python3 -I prepare.py
export CARGO_TARGET_DIR="$PWD/build/graph-tools"
# Keep graph-tool memory bounded; output graph hashes are checked independently.
export CARGO_PROFILE_RELEASE_LTO=thin
cargo build --release --locked --manifest-path .cache/circom-witnesscalc/Cargo.toml -p build-circuit
mkdir -p build/graphs
root="$PWD"
runtime="$root/build/graph-tools/release/build-circuit"
for name in show jwt_2k; do
    # The compiler may emit signal maps; keep all generated files in build/.
    (cd build/graphs && "$runtime" "$root/.cache/zkid/wallet-unit-poc/circom/circuits/main/$name.circom" \
        "$name.graph" -l "$root/.cache/zkid/wallet-unit-poc/circom/node_modules" -p secq256r1)
done
python3 -I package_graphs.py
