# ZK native runtime

The native runtime uses the Rust version pinned in rust-toolchain.toml (1.99.1; the workspace minimum of
1.95 comes from TLSNotary alpha.15), UniFFI 0.29.4, cargo-ndk 4.1.2,
and Android NDK 28.2.13676358. Dependencies are locked in Cargo.lock.
Install the toolchain through rustup, install cargo-ndk with
`cargo install cargo-ndk --version 4.1.2 --locked`, and install the pinned
NDK through Android SDK Manager. Set ANDROID_HOME to the SDK directory.

From the repository root:

```sh
native/build.sh host
native/build.sh android
native/generate-bindings.sh
(cd native && cargo test --workspace --locked)
./gradlew :core:compileKotlinJvm :app:compileKotlinDesktop :test-servers:test
./gradlew :app:assembleRelease
```

The Gradle JVM resource task builds the host library; the Android JNI merge
task builds arm64-v8a and x86_64. `-Pdiw.zkNative` (or `DIW_ZK_NATIVE`) picks
how: `auto` (default) builds only when bash and cargo (and, for Android,
cargo-ndk 4.1.2 and the pinned NDK under ANDROID_HOME) are installed and
otherwise packages no library, so the app reports ZK as unavailable; `require`
always builds and fails without the tools; `skip` never builds; `prebuilt`
never builds but fails unless the libraries are already in `native/dist` (CI
builds them in separate jobs and passes them in as artifacts).
`DIW_ZK_ANDROID_ABIS` (default `arm64-v8a,x86_64`) limits `native/build.sh
android` to some ABIs. Each 64-bit ABI also builds the runtime-only library
of its 32-bit sibling (`armeabi-v7a`, `x86`, about 1 MB): the app installs on
32-bit devices and decodes JPEG 2000 portraits with it, but no proof backend
exists there (Barretenberg needs 128-bit integers and a 64-bit `size_t`,
Multipaz ships no 32-bit Longfellow, and the provers need more memory than a
32-bit process has).
On Windows the tasks run Git for Windows' bash, because `bash` there starts WSL. Both use release Rust libraries. The Android
application uses its existing R8 release build plus native/zk.pro. Do not edit
the generated Kotlin binding. It uses the JNA cleaner on both platforms,
including Android versions without java.lang.ref.Cleaner.

`native/build.sh all` requests Linux x86_64, Windows x86_64, macOS arm64, and
the two Android ABIs. Cross compiling requires the appropriate platform SDK
and Cargo linker configuration. It fails if any requested target cannot be
built; it never silently substitutes a host binary.

Two desktop targets are cross-built on a Linux x86_64 host, and `build.sh`
sets the linker and compilers for them:

- `native/build.sh aarch64-unknown-linux-gnu` (`linux-aarch64`): needs
  `g++-aarch64-linux-gnu`. An arm64 host builds it as `host`.
- `native/build.sh x86_64-pc-windows-gnullvm` (`windows-x86_64`): uses
  llvm-mingw (clang, lld, libc++, libunwind, compiler-rt and the mingw-w64
  UCRT), which `zkpdf-prover/tools/llvm_mingw.py` fetches as a release pinned
  by SHA-256 into `target/`; `LLVM_MINGW_ROOT` names an existing copy instead.
  This is the only way to get the zkPDF backend on Windows (see
  `zkpdf-prover/README.md`). The script checks that the DLLs import Windows
  system libraries only (the UCRT is part of Windows 10 and later) and that
  nothing built by GCC is in them, so they carry no libstdc++ or libgcc. A
  Windows host still builds its own MSVC library without zkPDF.

CI (`.github/workflows/github-actions-ci.yml`) builds the libraries in their
own jobs: `native-android` runs `android` on Linux once per ABI
(`DIW_ZK_ANDROID_ABIS`), `native-linux` runs `host` on Linux x86_64,
`native-windows` cross-builds `x86_64-pc-windows-gnullvm` on Linux, and
`native-desktop` runs `host` on macOS arm64.
Each uploads only `dist/android/<abi>/libdiw_zk.so` or `dist/resources` as a
`zk-native-*` artifact; the Gradle jobs download them back into the same
`native/dist` paths and run with `DIW_ZK_NATIVE=prebuilt`, so they need no
Rust, NDK, protoc, libclang or CMake. Local builds are unchanged: without
`prebuilt` Gradle still runs `native/build.sh` itself.

Before invoking generated bindings, call `ZkNative.load(appPrivateDirectory)`.
On desktop it verifies the packaged library digest and atomically extracts a
versioned copy into that directory. Android resolves the library from APK JNI
directories through JNA. The core runtime does not query platform APIs; the
app supplies platform information.

`native_info()` advertises only the backends compiled in. The Cargo features
`openac` (age proof), `tlsn` (zkTLS), `zkpdf` (zkPDF, zkPassport verification
and proving; it implies `oprf`), `oprf` (the project OPRF alone) and `bb5`
(the separate Barretenberg 5 library for zkPassport circuits before 0.22.0,
needs `zkpdf`) select them; `DIW_ZK_FEATURES` passes
the list to `build.sh`, and release builds use `openac,tlsn,zkpdf` plus `bb5`
where that library ships. A library built without a feature keeps the
exported functions and answers `Unsupported`. Which platform carries which
backend is in `docs/STATUS.md` (section 3.5). `self_test()` runs the
shared SHA-256 known-answer test on a dedicated worker. Backend work must use
`run_worker`, poll `ZkCancelToken::check()` at bounded intervals, and self-verify
before returning proof output. The caller chooses the stack size (64 MiB for
OpenAC). Workers are joined even when cancelled. Backend errors must contain
fixed codes, never private input; do not panic with private data or log it.

The asset resource `zk/assets.json` is generated from native/assets.json.
Its SHA-256 is pinned in ZkAssetManifest.
`FileZkAssetStore.bundled` verifies that digest before accepting the manifest.
The explicit catalog constructor is for synthetic tests or another independently
verified catalog; do not pass catalogs from credentials, URLs, or user input.
Interrupted transfers retain a partial compressed file and resume with Range.
Malformed responses, integrity failures, installation errors, and cancellation
delete temporary files. Cancellation propagates CancellationException, preserving
structured coroutine cancellation. Only files with the expected installed hash
are returned from `path`. The app owns the original HttpClient; close the store
when no longer needed to release its child client's resources.

Memory tiers are recommendations. Low RAM and disk space do not remove loaded
backends; unsupported ABIs or missing engines do. Longfellow is supplied by
Multipaz separately and must be included in ZkNativeStatus only after it loads.
Windows callers should use the qualified `windows-x86_64` ABI identifier so
capability evaluation can explain its unavailable Longfellow library.
