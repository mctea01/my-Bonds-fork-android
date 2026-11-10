# Isolated native dependency probes

These tools are research artifacts, not application integrations. They never
modify the production loader, Cargo manifests, Gradle configuration, or CI.
Run them from the repository root on Linux x86_64 with Python 3.11+, a C
compiler, and binutils. Use only libraries from the pinned trusted sources.

## DIW runtime without JVM

Install Rust **1.99.1**, as pinned in `native/rust-toolchain.toml`. The workspace
MSRV of 1.95 and older documentation do not override that pin. Use a separate
build directory and preserve `Cargo.lock`:

```sh
CARGO_TARGET_DIR=/tmp/diw-runtime-target cargo +1.99.1 build \
  --manifest-path native/Cargo.toml --locked -p diw-zk-ffi --no-default-features
python3 tools/native-research/probe_runtime.py \
  --library /tmp/diw-runtime-target/debug/libdiw_zk.so \
  --out /tmp/diw-runtime-probe
```

The runner compiles a C caller, inspects ELF imports/exports, then uses `dlopen`
and the versioned UniFFI C ABI. It checks contract 29 and the two function
checksums before calling the SHA-256 self-test and reading/freeing native info.
It does not test proof engines or all serialized fields. `result.json` contains
commands, exit codes, source/library hashes, and the observed status. Diagnostic
metadata failures remain visible in command exit codes; smoke status describes
the C call, not successful completion of every inspection command.

## OPRF Rust vectors

```sh
CARGO_TARGET_DIR=/tmp/diw-oprf-target cargo +1.99.1 test \
  --manifest-path native/Cargo.toml --locked -p diw-zk-ffi \
  --no-default-features --features oprf --lib
```

This tests Rust API behavior, including public synthetic keys, randomized
blinding, proof/key binding, invalid inputs, and a public zkPassport key hash.
It does not exercise the OPRF C ABI or the BB-backed disclosure circuit.

## Longfellow without JVM

```sh
python3 tools/native-research/longfellow_probe.py \
  --output /tmp/diw-longfellow.json
```

The runner downloads the Linux x86_64 library from the fixed Multipaz commit,
checks its SHA-256 before use, and links a C caller in a disposable directory.
`--library /path/to/libzkp.so` uses a local copy with the same hash check.
All six exports are called, but proof generation and successful proof
verification remain untested. The source declarations follow the fixed Rust
exports because the upstream C header is stale.

Reports and limits: [research summary](../../docs/research/native-dependencies/research-summary.md).

## Archive inventory

```sh
python3 tools/native-research/inspect_archives.py /path/to/library.jar /path/to/library.aar > /tmp/native-entries.csv
```

This hashes each archive and its native/WASM entries without extracting or
executing them. It does not recursively inspect nested archives, resolve
dependencies, or claim that observed entries are used by a particular target.

## Windows GNU BB without JVM

See the [Windows BB report](../../docs/research/native-dependencies/bb-windows-link-poc.md)
for pinned checkouts, archive hashes, prerequisites, and the complete command.
`probe_bb_windows.py` builds the original DIW bridge and isolated C callers with
Zig 0.15.1, inspects PE imports, and optionally runs them under Wine. Inputs are
revision/hash checked; use a new empty output directory outside the repository.
No production build script is changed. The C++ helper tests original environment
hooks and error redaction. Wine smoke results do not establish native Windows,
MSVC, or minimum CPU compatibility. Without a fixture, proof verification is
not tested.

Add `--proof-fixture /external/outer_count_4_disclose.json` to also build a C
verifier for the hash-pinned public synthetic fixture. With Wine, it accepts the
original proof, rejects changed public inputs/proof and whole-field truncation,
and accepts the restored original again. The runner rejects any other fixture
before compilation. The [proof report](../../docs/research/native-dependencies/bb-windows-proof-poc.md)
provides its exact URL/hash and limits: embedded fixture key only, no registry or
wallet policy acceptance, no prover or proof regeneration. Without `--wine`,
this remains a link experiment and `positive_proof` stays `not-tested`.

## Longfellow Windows GNU source build

`probe_longfellow_windows.py` checks the fixed Multipaz/submodule revisions,
exact research patch and experimental Cargo.lock, builds a DLL with Rust 1.99.1
and MinGW GCC, and optionally runs a C verifier under Wine. Prepare the external
checkout using the [Longfellow Windows report](../../docs/research/native-dependencies/longfellow-windows-poc.md).
The six-manifest patch enables sha2/asm only outside Windows; unchanged upstream
source fails on Windows. No algorithm, version, circuit or proof format changes.

The C probe checks all six exports, LLP64/high size_t bits, a successful circuit
allocation/free, and an upstream public proof with changed attribute/transcript/
proof rejection. v7 materialization still reads the compile-time source path;
this experiment does not provide relocatable packaging, native Windows or MSVC
acceptance, or a successful prover. All outputs remain outside the repository.
