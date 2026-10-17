# OpenAC age profile

This package hosts Bonds `openac-age-v1` on WP0's shared `diw_zk` library.
`VERSIONS.json` pins zkID, the original Bonds overlay, Spartan2, both R1CS and
verifying keys, and the witness-graph runtime and assets. The Circom constraints
and Bonds public-signal order remain unchanged.

The application uses the MIT circom-witnesscalc runtime at
`d48eb7c97857d46b8a75c94ab96f769207263245`, with Claude's checked-in secq256r1
patch. It does not use Mopro, witnesscalc-adapter, C++ witnesscalc or GMP.
The vendored runtime contains the patched library source, protobuf definitions,
header and build script. Standalone compiler/CLI workspaces and their test
harness are excluded. Wallet hosting disables diagnostics and builds only an
rlib; the mathematical changes are exactly the checked-in patch.
`prepare.py` checks the upstream revision, patch, patched source files and the
vendored runtime hashes. It rejects unexpected changes instead of updating pins.

## Build the native library

Install Rust 1.90.0, Python 3.11.8 or newer, Git, protoc and libclang. The native
library does not require a Circom compiler, GMP or a C++ runtime. Android uses
cargo-ndk 4.1.2 and NDK 28.2.13676358.

```sh
./native/openac-age/build.sh host
./native/openac-age/build.sh android
```

Desktop targets are Linux x86_64, Windows x86_64 (MSVC or GNU), and macOS arm64.
Use the target's normal linker/SDK. Runtime dependencies and source are portable;
platform execution results belong in the PR handoff, not an assumed support claim.
Outputs use WP0's existing `native/dist` layout. Use `-Pdiw.zkNative=skip` with
Gradle after preparing the OpenAC libraries so the default runtime-only build
does not overwrite them.

Expanded Kotlin and Python bindings are generated in this package's `build`
directory. This package does not overwrite WP0's checked-in Kotlin source;
Claude owns that integration. Existing runtime API signatures remain compatible.

## Build and package separate graph assets

Graph generation additionally needs Node/Corepack and Circom 2.2.3. Sources use
circomlib 2.0.5 and @zk-email/circuits 6.3.4 from the pinned yarn lockfile.
The compiler tool is built with its upstream Cargo.lock (Circom revision
`ad44e915a12bb047b05745c2884aad9cc8326bc6`).

```sh
./native/openac-age/build-graphs.sh
```

The script checks the original Bonds R1CS hashes, builds both graphs and checks
their exact lengths and hashes from the design. `package_graphs.py` writes
reproducible gzip archives and `build/graphs/assets.fragment.json` for the WP0
asset-manifest integration. Re-run the generator to check graph reproducibility.
The graph files and archives stay outside Git and outside the native library.
The user uploads the archives to the `openac-age-graph-v1` Release; these scripts
do not create or publish Releases.

The native engine loads graphs from `<documents>/graphs/jwt_2k.graph` and
`<documents>/graphs/show.graph`, checking their SHA-256 before evaluation.
The test asset installer copies verified local graph builds and downloads the
six existing Bonds assets using WP0's manifest with compressed/expanded size
and hash checks. The application will use WP0's asset store after Claude merges
the generated graph manifest fragment; the test installer is not an App downloader.

## Synthetic acceptance

```sh
python3 -I native/openac-age/tests/generate_wasm_vectors.py
python3 -I native/openac-age/install_assets.py native/openac-age/build/assets/circom
cargo test --release --locked --manifest-path native/Cargo.toml -p openac-age
OPENAC_TEST_ASSETS="$PWD/native/openac-age/build/assets/circom" \
  cargo test --release --locked --manifest-path native/Cargo.toml -p openac-age \
  pinned_graphs_match_circom_wasm_vectors -- --ignored
OPENAC_TEST_ASSETS="$PWD/native/openac-age/build/assets/circom" \
OPENAC_FFI_OUTPUT="$PWD/native/openac-age/build/ffi-proof/circom" \
  cargo test --release --locked --manifest-path native/Cargo.toml -p openac-age \
  synthetic_prepare_show_reblind_and_independent_policy -- --ignored --nocapture
python3 -I native/openac-age/tests/verify_ffi.py \
  native/openac-age/build/python native/openac-age/build/ffi-proof/circom \
  --assets native/openac-age/build/assets/circom
```

Rust tests generate ES256 issuer/holder keys, an SD-JWT and birth-date disclosure.
The fixed upstream synthetic inputs required by WP7 are fetched at the pinned
zkID revision; their reference witness hashes are reproduced with Circom wasm.
No real credentials are stored. Tests cover graph-hash rejection, full Prepare,
Show and shared reblinding, authenticated public signals, changed cutoff, issuer
key and nonce, and rejection of proofs using different shared randomness.
The Python test exercises the generated UniFFI C ABI, including a fresh proof
through every export. Only timings and sizes are printed.

The verifier independently pins both verifying keys. Its public-signal reader
verifies both proofs and their shared-commitment linkage, returning Prepare's
6 and Show's 156 decimal fields. This does not replace the age-policy check.
Each serialized proof is limited to 2,000,000 bytes.

With an x86_64 emulator using at least 4 GB RAM, run
`./native/openac-age/test-android.sh` for the same full synthetic native test.
`./native/test-android.sh` separately checks native loading/self-test through the
actual R8 release APK. Use physical devices for performance measurements.

## Private workers and cancellation

Each operation uses a dedicated 64 MB thread and an isolated Rayon pool.
Private worker panic payloads and upstream runtime diagnostics are suppressed.
UniFFI errors use fixed codes. Private inputs and witness artifacts use
owner-only files on Unix; input writes are atomic.

Long exports take WP0's cancellation token. Hashing polls it in bounded chunks;
computation phases check it before publishing. Graph evaluation and Spartan's
synchronous calls cannot be interrupted internally: the worker is joined before
returning cancellation. Reblinding retains the original per-operation private
instance/witness because the pinned upstream reblinder returns stale blind-value
metadata. Only the newly verified proof is published, allowing another reblind
without changing Spartan or the constraints. The caller must use a private
operation directory and delete private inputs/caches after completion or cancellation.

## Licensing

The App's runtime is MIT/Apache-compatible source plus the existing WP0 bindings;
GPL/LGPL witnesscalc and GMP are absent. Circom and the linked `build-circuit`
compiler are GPL build tools, not application dependencies.

The separately downloaded R1CS, keys and graphs compile MIT zkID circuits and
GPL-3.0-or-later circomlib 2.0.5 templates. The design distributes these assets
under GPL-3.0 separately from the App; this is the design's licensing inference,
not a legal opinion. NOTICE lists corresponding source and rebuild instructions.
License copies are in `licenses`. The original Bonds predicate/patch retain
their Apache-2.0 attribution; hosting changes do not change their statements.
