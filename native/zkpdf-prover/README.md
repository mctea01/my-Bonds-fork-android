# zkPDF v1 native runtime

This crate implements the frozen segmented WP3b interface. It accepts windows,
records and slot boundaries, not PDF files. Kotlin remains responsible for signed
revision selection, CMS trust, SHA continuation between windows and V5–V7/V10.
`PUBLIC_SPEC.md` remains the verifier contract.

The runtime uses official Noir beta.15 Rust crates at
`83245db91dcf63420ef4bcbbd85b98f397fee663` and a static Barretenberg 2.1.9 at
`f2bed7ed073966bb2a2dcdd02a133d11bf2996d3`. The C++ bridge fixes the flavor to
zero-knowledge UltraHonk and Poseidon2. Production fixes native workers to two, catches
C++ exceptions, suppresses upstream diagnostic hooks, disables polynomial disk
spilling and uses an authenticated memory CRS factory. No runtime download or
CLI subprocess is used. Noir foreign calls are rejected. Witness encoding is
explicit beta.15 legacy bincode plus gzip, independent of environment settings.
See `NOTICE` and `../Cargo.lock` for licenses and dependency pins.

## Build on Linux

Prerequisites: Rust 1.95, C++20 compiler (tested GCC 14), CMake, Ninja, Git and
Python 3. Full workspace tests additionally need protoc and libclang for OpenAC.
The C++ build tool fetches pinned sources during this explicit build step only.

```sh
cd native
python3 -I zkpdf-prover/tools/build_bb.py \
  --target x86_64-unknown-linux-gnu --build "$PWD/target/bb-x86_64-unknown-linux-gnu"
export ZKPDF_BB_SOURCE="$PWD/target/bb-source"
export ZKPDF_BB_BUILD="$PWD/target/bb-x86_64-unknown-linux-gnu"
DIW_ZK_FEATURES=zkpdf ./build.sh host
RUST_MIN_STACK=67108864 cargo test --workspace --locked --features diw-zk-ffi/zkpdf
./generate-bindings.sh
cd ..
```

`generate-bindings.sh` emits all exports in a runtime-only build. It does not
need to link a proof backend to generate the identical transport API.

The C++ compiler suppresses two GCC 14 warnings as errors in upstream sources
(missing aggregate initializers and vector insertion array-bounds diagnostics).
It retains other upstream diagnostics and does not alter circuit or proof code.

For macOS arm64, run the same build on a macOS arm64 host using
`--target aarch64-apple-darwin` and AppleClang. For Android, install the pinned
NDK/cargo-ndk from `native/README.md`, then run
`DIW_ZK_FEATURES=zkpdf native/build.sh android`; each ABI requires its own CMake
build directory. `build.sh` supplies the API-29 NDK wrapper through
`ZKPDF_CXX`/`ZKPDF_AR`, independently of cargo-ndk's rewritten `CXX` and
`CXXFLAGS`. It reports elapsed seconds and library bytes for each ABI.
Android build results are recorded in `docs/research/p4-benchmarks.md`.
macOS has not been built in this Linux workspace. Windows is currently blocked by upstream POSIX dependencies
(`sys/random.h`, `sys/mman.h` and allocation/file APIs); the build tool fails
explicitly rather than substituting a different backend version. Windows zkPDF is currently unsupported; no POSIX port is attempted.

## Assets

Install the ten `pdf_*.json` ACIR artifacts, their ten `pdf_*.vk` files and
`bn254_g1.dat`/`bn254_g2.dat` directly in `assets_dir`. The G1 prefix contains
2^21+1 points (134,217,792 bytes); G2 is 128 bytes. The flat layout matches the
existing Kotlin asset store's identifier restrictions. Runtime verifies the
exact bytes it passes to ACVM/Barretenberg. ACIR/VK hashes are read at compile
time from `VERSIONS`; CRS hashes and sizes are checked against `assets.json` by
the asset build tool.

```sh
python3 -I native/circuits/tools/build_assets.py --download-crs
```

This requires pinned nargo beta.15 and bb 2.1.9 on PATH, or `NARGO`/`BB`.
`--download-crs` is an explicit build-time option; omit it for offline rebuilding
with existing CRS. The tool verifies all frozen hashes and package catalog
entries, including deterministic gzip files. Because frozen ACIR JSON contains
absolute debug source paths, it canonicalizes only `file_map` paths to the
frozen compilation root before checking the complete file hash.

The catalog URLs point to the `zkpdf-v1` release, which the `zkPDF assets`
workflow (`.github/workflows/zkpdf-assets.yml`, run by hand) builds with this tool
and publishes without ever replacing a published file. Both Gradle feature
allowlists accept zkpdf. To require the host backend and execute the Kotlin test:

```sh
DIW_ZK_FEATURES=zkpdf ZKPDF_ASSETS_DIR="$PWD/native/circuits/target/zkpdf-assets" \
  ./gradlew :core:compileKotlinJvm :app:compileKotlinDesktop :test-servers:test \
  -Pdiw.zkNative=require
```

## API behavior

`check` performs bounded decompression, lexical/profile validation and advice
preparation, then returns exact segment counts and encoded size estimates. It
does not load assets, execute ACVM or produce proofs. Predicate truth is checked
by the circuit during proof generation. All failures expose fixed codes only.

`prove` generates a fresh 248-bit commitment salt, authenticates assets, runs
ACVM and generates/self-verifies each segment sequentially. It polls cancellation
before work, between ACVM/proving and before publishing results. C++ proving is
not interruptible mid-segment. Calls share a backend mutex because upstream CRS
and workers are process-global. Progress carries the kind, one-based position
in the whole composition and total segment count.

`verify` first reconstructs all verifier-owned fields and checks canonical field
encodings, segment order/flags/counts and every commitment join. It then verifies
every proof against the pinned composition-specific key. It never accepts a
policy-only result as a proof. `verify_opening` separately checks a disclosed
slot's frozen SHA-256 opening; the consumer must use a digest returned by a
successful proof verification.

WP3b leaves some record definitions implicit. The implementation makes
`WindowPublic.blocks`, anchor ordinal/total and slot indices `u32`;
`ZkPdfPlan` provides composition, counts for each segment family, total segments,
estimated proof bytes and public input bytes. `AnchorInput.ordinal` is a required one-based occurrence of the exact v2 record.
Zero or an unavailable occurrence fails with `anchor_ordinal` during both check
and prove preparation, before asset access or progress callbacks. The independent
verifier's ordinal/total policy is still mandatory. SHA segments follow the
verifier's ordered windows. Inflate/lex segmentation is fixed by composition and
actual plaintext length; the latter remains private and is enforced by the
circuits' full non-final segments and final/end checks.

## Synthetic tests and measurements

```sh
python3 -I native/circuits/tools/pdf_fixture_chain.py \
  --export-json test-servers/src/test/resources/zkpdf
export ZKPDF_ASSETS_DIR="$PWD/native/circuits/target/zkpdf-assets"
cargo test --manifest-path native/Cargo.toml --release -p zkpdf-prover \
  --features bb --locked execute_synthetic_acvm -- --ignored --nocapture
cargo test --manifest-path native/Cargo.toml --release -p zkpdf-prover \
  --features bb --locked z9_and_z13 -- --ignored
cargo build --manifest-path native/Cargo.toml --release -p zkpdf-prover \
  --features bb --locked --example synthetic_bench
native/target/release/examples/synthetic_bench student "$ZKPDF_ASSETS_DIR" /tmp/zkpdf-rust/student
native/target/release/examples/synthetic_bench travel-rc4 "$ZKPDF_ASSETS_DIR" /tmp/zkpdf-rust/travel-rc4
ZKPDF_SYNTHETIC_OUTPUT=/tmp/zkpdf-rust cargo test --manifest-path native/Cargo.toml \
  --release -p zkpdf-prover --features bb --locked real_proof_rejections -- --ignored
```

The benchmark accepts only the two embedded fictional documents. An optional
fourth argument selects `zkpdf-v1-desktop` for additional composition coverage. It reports
per-segment ACVM, proving, self-verification time, proof/public-input bytes and
Linux RSS. On Linux it resets VmHWM via `/proc/self/clear_refs` at each segment;
the maximum is reported for the complete proof. Total wall time also includes
bounded advice generation, asset verification and CRS initialization. Run the
two commands sequentially, without concurrent builds or proofs, for measurements.
The additional phone/desktop vectors test cross-segment inflate history and
lexical state. No real documents or personal information are used.

For both interoperability directions, set `ZKPDF_SYNTHETIC_OUTPUT` while running
`execute_synthetic_acvm` to save its synthetic gzip witnesses, then run
`python3 -I native/circuits/tools/rust_cli_interop.py --assets "$ZKPDF_ASSETS_DIR"
--rust /tmp/zkpdf-rust --acvm /tmp/zkpdf-acvm --output /tmp/zkpdf-cli`.
Set `ZKPDF_CLI_PROOFS=/tmp/zkpdf-cli` for `real_proof_rejections` to require Rust
verification of all CLI proofs as well as the real-bundle negative cases.

`claim_records` and `claim_digests` have twelve entries indexed by slot; disabled
records are empty and disabled digests are zero. Anchor ordinal/total vectors
follow the supplied enabled-anchor order. The optional `ZKPDF_DESKTOP_BUNDLE`
path on `real_proof_rejections` adds validation of a separately generated desktop
student bundle and rejects mixing its inflate/lex proofs into the phone bundle.

## Accepted empty-tail boundary

The frozen circuits accept one additional empty final inflate segment (and its
matching lexical segment) when plaintext length is a multiple of `SEG_PLAIN`.
The generator consumes the end marker eagerly and `check` excludes that empty
pair. Public-input policy accepts both forms, including at `MAX_PLAIN=40960`;
proof verification remains mandatory. Never identify or deduplicate a document
by segment count, proof bundle bytes or their hash.

Ordinary Rust regressions cover phone and desktop boundaries, second-occurrence
slot selection, independent verifier ordinals and fixed pre-generation errors.
The following opt-in tests also execute frozen constraints:

```sh
ZKPDF_ASSETS_DIR="$PWD/native/circuits/target/zkpdf-assets" cargo test \
  --manifest-path native/Cargo.toml --release -p zkpdf-prover --features bb \
  --locked frozen_empty_final_segment_boundary -- --ignored
ZKPDF_ASSETS_DIR="$PWD/native/circuits/target/zkpdf-assets" cargo test \
  --manifest-path native/Cargo.toml --release -p zkpdf-prover --features bb \
  --locked second_occurrence_executes_frozen_acvm -- --ignored
```

## Worker measurements

`bench-workers` is an explicit measurement-only feature. It requires
`ZKPDF_BENCH_WORKERS=1`, `2` or `4` at compile time and embeds that fixed count
in the C++ bridge. Without this feature production always uses two workers,
regardless of that environment variable. Do not enable it in packaged builds.
Run each build and its two synthetic processes sequentially, without other builds
or proofs. Metrics include the compiled worker count; results are in
`docs/research/p4-benchmarks.md`.

```sh
host=$(rustc -vV | sed -n 's/^host: //p')
for workers in 1 2 4; do
  ZKPDF_BENCH_WORKERS="$workers" cargo build --manifest-path native/Cargo.toml \
    --release --locked --target "$host" -p zkpdf-prover --features bench-workers --example synthetic_bench
  for fixture in student travel-rc4; do
    "native/target/$host/release/examples/synthetic_bench" "$fixture" "$ZKPDF_ASSETS_DIR" \
      "/tmp/zkpdf-workers-$workers/$fixture"
  done
done
```
