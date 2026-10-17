# OpenAC age profile

This package hosts the Bonds `openac-age-v1` profile on the WP0 shared native
library. Source revisions, circuit hashes and verifying-key hashes are pinned
in `VERSIONS.json`. `prepare.py` refuses another zkID revision and checks both
compiled R1CS hashes against the released Bonds assets.

The source basis is zkID's Mopro 0.3.5 mobile application. Its application-level
Mopro scaffolding is replaced by WP0's UniFFI 0.29.4 namespace, avoiding a second
native library and a competing generated namespace. The proof implementation,
Bonds predicate and circuit patch retain their original provenance.

## Build

Use Python 3.11.8 or newer, Git, Node/Corepack, Circom 2.2.3, CMake 3.18 or newer,
GNU Make, GNU m4, and the pinned Rust 1.90.0 toolchain. The first build fetches the pinned
sources and compiles the witness calculators. Allow several gigabytes of RAM
and disk space; run large builds sequentially on constrained machines.

```sh
./native/openac-age/build.sh host
./native/openac-age/build.sh android
```

Android requires cargo-ndk 4.1.2 and NDK 28.2.13676358. Desktop target names are
`x86_64-unknown-linux-gnu`, `x86_64-pc-windows-gnu` and
`aarch64-apple-darwin`. Build macOS on an Apple SDK host. Windows uses Git Bash,
Python and the MinGW GNU C/C++ toolchain; MSVC is not supported by GMP's build.
Cross builds require the target's linker and SDK.

Outputs use WP0's existing `native/dist` layout. After building this backend,
use `-Pdiw.zkNative=skip` for Gradle so its runtime-only build does not overwrite
the prepared OpenAC library. No build workflow or other package's Gradle file
is changed here.

Expanded Kotlin bindings are generated into `build/bindings`. This package does
not overwrite WP0's checked-in generated Kotlin file; that integration belongs
to Claude. Existing runtime function signatures remain compatible.

## Synthetic acceptance test

```sh
python3 -I native/openac-age/install_assets.py native/openac-age/build/assets/circom
cargo test --manifest-path native/Cargo.toml -p openac-age --no-default-features
OPENAC_TEST_ASSETS="$PWD/native/openac-age/build/assets/circom" \
OPENAC_FFI_OUTPUT="$PWD/native/openac-age/build/ffi-proof/circom" \
  cargo test --release --locked --manifest-path native/Cargo.toml -p openac-age \
  synthetic_prepare_show_reblind_and_independent_policy -- --ignored --nocapture
python3 -I native/openac-age/tests/verify_ffi.py \
  native/openac-age/build/python native/openac-age/build/ffi-proof/circom \
  --assets native/openac-age/build/assets/circom
```

The asset installer uses the WP0 manifest, checks compressed and expanded
lengths and SHA-256, and limits decompression to the pinned length. Application
downloads still use WP0's `ZkAssetStore`. The Rust verifier independently pins
both verifying keys before deserializing them. Its authenticated public-signal
reader returns Prepare's 6 and Show's 156 decimal field elements, after proof
verification and shared-commitment linkage. Reading signals alone does not
apply the age policy.

Tests generate ES256 issuer and holder keys, an SD-JWT and birth-date disclosure.
No real credentials are stored. The full test proves Prepare and Show, reblinds
both with shared randomness, verifies the independently supplied statement and
rejects a changed cutoff, issuer key and nonce.
The generated Python bindings exercise the same C ABI as Kotlin: the optional
`--assets` mode also proves and reblinds a fresh synthetic presentation through
all native exports, rather than only verifying a retained Rust proof.

After building Android and starting an x86_64 emulator with at least 4 GB RAM,
run `./native/openac-age/test-android.sh` to execute that complete synthetic test
on Android. It builds the native test executable, installs verified public
assets, and removes its remote test directory on exit. This is separate from
`./native/test-android.sh`, which checks the shared runtime through the actual
R8 release APK. Software-emulated devices are useful for correctness checks;
use a physical device for performance measurements.

## Private inputs and cancellation

Each operation runs on a dedicated 64 MB thread and an isolated Rayon pool.
Panic payloads are suppressed only on these private workers. Runtime diagnostics
are removed from the vendored hosting layer. Witness-calculator assertions throw
fixed exceptions; they neither abort the wallet nor disappear under `NDEBUG`.
Errors crossing UniFFI contain fixed codes. Private input writes are atomic and
use owner-only permissions on Unix. Witness artifacts also use owner-only files.

Long UniFFI operations take WP0's cancellation token. Cancellation is checked
while hashing assets, between proof phases and before publishing results. The
upstream Spartan call is synchronous; an in-progress call is joined before
returning cancellation, rather than leaving a worker processing private input.
Reblinding publishes only the verified presentation proof and retains the
original private instance and witness. The pinned upstream reblinder's returned
cache has stale blind-variable metadata and cannot be used for another reblind.
The application must allocate one private documents directory per operation
and remove its witness/input artifacts when it no longer needs them.

## Third-party source and distribution

`patches/predicate.rs` and `patches/zkid-mobile.patch` preserve the original Bonds
overlay; `src/predicate.rs` removes standalone UniFFI derives, redacts errors and
uses atomic private writes. The predicate's statements and public order are
unchanged. `vendor/ecdsa-spartan2` is the pinned zkID source after the Bonds patch,
with pinned dependency revisions, diagnostics disabled and bounded proof decoding.
`vendor/witnesscalc-adapter` derives from the specified `e5a82bc` revision, with
portable `c_ulong`, bounded allocation, fixed errors and a checked static build
driver. `build_witness.py` modifies generated hosting code only; it does not
change R1CS constraints.

The Bonds overlay is Apache-2.0; zkID and Spartan2 are MIT; circom-scotia and the
adapter offer MIT/Apache-2.0. **witnesscalc is GPL-3.0**, and statically linked GMP
6.2.1 offers LGPL-3.0-or-later/GPL-2.0-or-later. OpenAC-enabled binary distribution
must account for those licenses. Keep the corresponding pinned source, build
scripts and relinkable native archives when distributing artifacts. License
copies are in `licenses`; source acquisition is reproduced by `prepare.py`.
Claude must review the distribution terms before release.
