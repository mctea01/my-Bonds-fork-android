# ZK native runtime

The WP0 runtime uses Rust 1.90.0, UniFFI 0.29.4, cargo-ndk 4.1.2,
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
task builds arm64-v8a and x86_64. Both use release Rust libraries. The Android
application uses its existing R8 release build plus native/zk.pro. Do not edit
the generated Kotlin binding. It uses the JNA cleaner on both platforms,
including Android versions without java.lang.ref.Cleaner.

`native/build.sh all` requests Linux x86_64, Windows x86_64, macOS arm64, and
the two Android ABIs. Cross compiling requires the appropriate platform SDK
and Cargo linker configuration. It fails if any requested target cannot be
built; it never silently substitutes a host binary. The release workflow
should run `host` on Linux x86_64, Windows x86_64 (MSYS bash), and macOS arm64,
and `android` on Linux. Merge the `dist/resources` artifacts to package all
desktop platforms into one jar, or ship just the current platform's artifact.

Before invoking generated bindings, call `ZkNative.load(appPrivateDirectory)`.
On desktop it verifies the packaged library digest and atomically extracts a
versioned copy into that directory. Android resolves the library from APK JNI
directories through JNA. App platform information and settings UI are owned
by the integration work package; the core runtime does not query platform APIs.

`native_info()` advertises only implemented backends. The `zkpdf`, `tlsn`,
and `openac` Cargo features reserve dependencies for WP3b, WP5, and WP7;
their empty crates do not advertise proof capability. `self_test()` runs the
shared SHA-256 known-answer test on a dedicated worker. Backend work must use
`run_worker`, poll `ZkCancelToken::check()` at bounded intervals, and self-verify
before returning proof output. The caller chooses the stack size (64 MiB for
OpenAC). Workers are joined even when cancelled. Backend errors must contain
fixed codes, never private input; do not panic with private data or log it.

The asset resource `zk/assets.json` is generated from native/assets.json to
stay within WP0's file allowlist. Its SHA-256 is pinned in ZkAssetManifest.
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
