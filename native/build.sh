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
    targets=x86_64-unknown-linux-gnu,x86_64-pc-windows-gnullvm,aarch64-apple-darwin,android
fi
targets=${targets//host/$host}
# Optional proof backends (DIW_ZK_FEATURES, set by Gradle's diw.zkFeatures). The exports exist in every build;
# a backend left out reports Unsupported. OpenAC needs protoc and libclang to build its witness runtime.
# bb5 is not a feature of diw-zk-ffi but the separate Barretenberg 5 library (zkpassport-bb5) for zkPassport proofs
# of circuits before 0.22.0; it needs zkpdf and goes to dist/android-bb5 (the on-demand module) or next to diw_zk.
features=${DIW_ZK_FEATURES:-}
if [[ -n "$features" ]]; then
    [[ "$features" != ,* && "$features" != *, && "$features" != *,,* ]] || { echo "Invalid DIW_ZK_FEATURES list" >&2; exit 1; }
    IFS=',' read -ra backends <<< "$features"
    for backend in "${backends[@]}"; do
        case "$backend" in
            openac|tlsn|zkpdf|oprf|bb5) ;;
            *) echo "Unsupported DIW_ZK_FEATURES entry" >&2; exit 1 ;;
        esac
    done
fi
with_bb5=false
if [[ ",$features," == *,bb5,* ]]; then
    [[ ",$features," == *,zkpdf,* ]] || { echo "bb5 needs zkpdf in DIW_ZK_FEATURES" >&2; exit 1; }
    with_bb5=true
    ffi_features=$(printf '%s' ",$features," | sed 's/,bb5,/,/; s/^,//; s/,$//')
else
    ffi_features=$features
fi
feature_args=()
[[ -z "$ffi_features" ]] || feature_args=(--features "$ffi_features")
# Android ABIs for the android target (DIW_ZK_ANDROID_ABIS, a comma list); CI builds one ABI per job to bound disk use.
android_abis=${DIW_ZK_ANDROID_ABIS:-arm64-v8a,x86_64}
IFS=',' read -ra abis <<< "$android_abis"
abi_args=()
for abi in "${abis[@]}"; do
    case "$abi" in
        arm64-v8a|x86_64) abi_args+=(-t "$abi") ;;
        *) echo "Unsupported DIW_ZK_ANDROID_ABIS entry" >&2; exit 1 ;;
    esac
done
# Static C++ sources are acquired only by this explicit build step.
bb_build_override=${ZKPDF_BB_BUILD:-}
# The bridge compiler and archiver given by the caller; a cross target sets its own and must not pass it on.
bridge_cxx_override=${ZKPDF_CXX:-}
bridge_ar_override=${ZKPDF_AR:-}
build_zkpdf() {
    local bb_target=$1
    [[ ",$features," == *,zkpdf,* ]] || return 0
    export ZKPDF_BB_SOURCE=${ZKPDF_BB_SOURCE:-"$PWD/target/bb-source"}
    export ZKPDF_BB_BUILD=${bb_build_override:-"$PWD/target/bb-$bb_target"}
    if [[ ! -f "$ZKPDF_BB_BUILD/lib/libbarretenberg.a" || ! -f "$ZKPDF_BB_BUILD/_deps/libdeflate-build/libdeflate.a" ]]; then
        python3 -I zkpdf-prover/tools/build_bb.py --source "$ZKPDF_BB_SOURCE" --build "$ZKPDF_BB_BUILD" --target "$bb_target"
    fi
}
# Barretenberg 5 for the zkpassport-bb5 library, built the same way from its own pinned source.
build_bb5() {
    local bb_target=$1
    "$with_bb5" || return 0
    export DIW_BB5_SOURCE=${DIW_BB5_SOURCE:-"$PWD/target/bb-v5"}
    export DIW_BB5_BUILD="$PWD/target/bb5-$bb_target"
    if [[ ! -f "$DIW_BB5_BUILD/lib/libbarretenberg.a" || ! -f "$DIW_BB5_BUILD/_deps/libdeflate-build/libdeflate.a" ]]; then
        python3 -I zkpdf-prover/tools/build_bb.py --version v5 --source "$DIW_BB5_SOURCE" --build "$DIW_BB5_BUILD" --target "$bb_target"
    fi
}
IFS=',' read -ra selected <<< "$targets"
for target in "${selected[@]}"; do
    if [[ "$target" == android ]]; then
        : "${ANDROID_HOME:?Set ANDROID_HOME to an installed Android SDK}"
        export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$NDK_VERSION"
        [[ -f "$ANDROID_NDK_HOME/source.properties" ]] || { echo "Pinned NDK is missing" >&2; exit 1; }
        grep -Eq "Pkg.Revision *= *$NDK_VERSION$" "$ANDROID_NDK_HOME/source.properties" || exit 1
        [[ "$(cargo ndk --version)" == "cargo-ndk $CARGO_NDK_VERSION" ]] || { echo "Pinned cargo-ndk is required" >&2; exit 1; }
        rustup target add aarch64-linux-android x86_64-linux-android armv7-linux-androideabi i686-linux-android
        if [[ ",$features," == *,zkpdf,* ]]; then
            for abi in "${abis[@]}"; do
                abi_started=$SECONDS
                if [[ "$abi" == arm64-v8a ]]; then rust_target=aarch64-linux-android; clang_target=aarch64-linux-android;
                else rust_target=x86_64-linux-android; clang_target=x86_64-linux-android; fi
                export ZKPDF_BB_BUILD=${bb_build_override:-"$PWD/target/bb-$rust_target"}
                build_zkpdf "$rust_target"
                case "$(uname -s)" in Linux*) ndk_host=linux-x86_64 ;; Darwin*) ndk_host=darwin-x86_64 ;; *) exit 1 ;; esac
                zkpdf_cxx="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$ndk_host/bin/${clang_target}29-clang++"
                zkpdf_ar="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$ndk_host/bin/llvm-ar"
                # cargo-ndk replaces CXX and moves target selection to CXXFLAGS.
                # Keep the bridge's explicit API/ABI wrapper independent of it.
                ZKPDF_CXX="$zkpdf_cxx" ZKPDF_AR="$zkpdf_ar" cargo ndk -t "$abi" --platform 29 -o dist/android build --release --locked -p diw-zk-ffi ${feature_args[@]+"${feature_args[@]}"}
                printf 'zkpdf_android abi=%s build_seconds=%s library_bytes=%s\n' \
                    "$abi" "$((SECONDS - abi_started))" "$(wc -c < "dist/android/$abi/libdiw_zk.so")"
                if "$with_bb5"; then
                    build_bb5 "$rust_target"
                    ZKPDF_CXX="$zkpdf_cxx" ZKPDF_AR="$zkpdf_ar" cargo ndk -t "$abi" --platform 29 -o dist/android-bb5 build --release --locked -p zkpassport-bb5 --features bb
                    printf 'bb5_android abi=%s library_bytes=%s\n' "$abi" "$(wc -c < "dist/android-bb5/$abi/libdiw_bb5.so")"
                fi
            done
            if "$with_bb5"; then
                # bundletool needs every module with native code to list the base's ABIs, and the base carries 32-bit
                # libraries from its dependencies. There is no 32-bit Barretenberg: those get an empty one.
                for abi in armeabi-v7a x86; do
                    if [[ "$abi" == x86 ]]; then clang_target=i686-linux-android; else clang_target=armv7a-linux-androideabi; fi
                    mkdir -p "dist/android-bb5/$abi"
                    "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$ndk_host/bin/${clang_target}29-clang" -shared -nostdlib \
                        -Wl,-soname,libdiw_bb5_none.so -o "dist/android-bb5/$abi/libdiw_bb5_none.so" -x c /dev/null
                done
            fi
        else
            cargo ndk "${abi_args[@]}" --platform 29 -o dist/android build --release --locked -p diw-zk-ffi ${feature_args[@]+"${feature_args[@]}"}
        fi
        # The 32-bit ABIs have no proof backend: Barretenberg needs 128-bit integers and a 64-bit size_t, Multipaz ships
        # no 32-bit Longfellow, and the provers need more memory than a 32-bit process has. The app still installs
        # there and decodes JPEG 2000 portraits with this library, so each 64-bit ABI brings the runtime-only library
        # of its 32-bit sibling (about 1 MB).
        for abi in "${abis[@]}"; do
            if [[ "$abi" == arm64-v8a ]]; then sibling=armeabi-v7a; else sibling=x86; fi
            cargo ndk -t "$sibling" --platform 29 -o dist/android build --release --locked -p diw-zk-ffi
        done
    else
        if [[ -n "$bridge_cxx_override" ]]; then export ZKPDF_CXX=$bridge_cxx_override; else unset ZKPDF_CXX; fi
        if [[ -n "$bridge_ar_override" ]]; then export ZKPDF_AR=$bridge_ar_override; else unset ZKPDF_AR; fi
        case "$target" in
            x86_64-unknown-linux-gnu) platform=linux-x86_64; library=libdiw_zk.so ;;
            aarch64-unknown-linux-gnu) platform=linux-aarch64; library=libdiw_zk.so
                # From an x86_64 host the distribution's GNU cross tools (g++-aarch64-linux-gnu) compile and link it.
                if [[ "$host" != "$target" ]]; then
                    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER:-aarch64-linux-gnu-gcc}
                    export CC_aarch64_unknown_linux_gnu=${CC_aarch64_unknown_linux_gnu:-aarch64-linux-gnu-gcc}
                    export CXX_aarch64_unknown_linux_gnu=${CXX_aarch64_unknown_linux_gnu:-aarch64-linux-gnu-g++}
                    export AR_aarch64_unknown_linux_gnu=${AR_aarch64_unknown_linux_gnu:-aarch64-linux-gnu-ar}
                    export ZKPDF_CXX=${bridge_cxx_override:-aarch64-linux-gnu-g++} ZKPDF_AR=${bridge_ar_override:-aarch64-linux-gnu-ar}
                fi ;;
            # A Windows host builds its own target, without zkPDF.
            x86_64-pc-windows-msvc) platform=windows-x86_64; library=diw_zk.dll ;;
            # With zkPDF the library is cross-built on Linux, the way Barretenberg is, with llvm-mingw
            # (zkpdf-prover/tools/llvm_mingw.py fetches the pinned release): clang and lld with libc++, libunwind,
            # compiler-rt and the mingw-w64 UCRT, so the DLL carries no GCC runtime (libstdc++, libgcc).
            # x86_64-pc-windows-gnu is accepted as the earlier name of this build.
            x86_64-pc-windows-gnullvm|x86_64-pc-windows-gnu) target=x86_64-pc-windows-gnullvm
                platform=windows-x86_64; library=diw_zk.dll
                [[ "$(uname -s)" == Linux ]] || { echo "The Windows library is cross-built on Linux" >&2; exit 1; }
                LLVM_MINGW_ROOT=$(python3 -I zkpdf-prover/tools/llvm_mingw.py)
                export LLVM_MINGW_ROOT
                mingw_bin=$LLVM_MINGW_ROOT/bin
                export CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER=$mingw_bin/x86_64-w64-mingw32-clang
                # crt-static links libunwind into the DLL instead of importing libunwind.dll.
                export CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_RUSTFLAGS="-C target-feature=+crt-static -C strip=symbols"
                export CC_x86_64_pc_windows_gnullvm=$mingw_bin/x86_64-w64-mingw32-clang
                export CXX_x86_64_pc_windows_gnullvm=$mingw_bin/x86_64-w64-mingw32-clang++
                export AR_x86_64_pc_windows_gnullvm=$mingw_bin/llvm-ar
                # OpenAC's witness runtime reads its C header with libclang.
                export BINDGEN_EXTRA_CLANG_ARGS_x86_64_pc_windows_gnullvm="--sysroot=$LLVM_MINGW_ROOT"
                export ZKPDF_CXX=${bridge_cxx_override:-$mingw_bin/x86_64-w64-mingw32-clang++}
                export ZKPDF_AR=${bridge_ar_override:-$mingw_bin/llvm-ar} ;;
            # One minimum macOS for Barretenberg, the bridge and rustc (otherwise each object targets a different one).
            aarch64-apple-darwin) platform=macos-aarch64; library=libdiw_zk.dylib; export MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-14.0} ;;
            *) echo "Unsupported desktop target" >&2; exit 1 ;;
        esac
        build_zkpdf "$target"
        rustup target add "$target"
        cargo build --release --locked -p diw-zk-ffi ${feature_args[@]+"${feature_args[@]}"} --target "$target"
        libraries=("$library")
        if "$with_bb5"; then
            build_bb5 "$target"
            cargo build --release --locked -p zkpassport-bb5 --features bb --target "$target"
            libraries+=("${library/diw_zk/diw_bb5}")
        fi
        mkdir -p "dist/resources/zk/native/$platform"
        for name in "${libraries[@]}"; do
            cp "target/$target/release/$name" "dist/resources/zk/native/$platform/$name"
            # sha256sum on Linux and Git for Windows, shasum on macOS.
            path="dist/resources/zk/native/$platform/$name"
            if command -v sha256sum > /dev/null; then digest=$(sha256sum "$path"); else digest=$(shasum -a 256 "$path"); fi
            printf '%s\n' "${digest%% *}" > "$path.sha256"
            if [[ "$target" == x86_64-pc-windows-gnullvm ]]; then
                # The DLL may import Windows system libraries only (the UCRT is part of Windows 10 and later), and
                # nothing compiled by GCC may be in it: such objects carry a "GCC: (" ident string.
                imports=$("$LLVM_MINGW_ROOT/bin/llvm-objdump" -p "$path" | sed -n 's/^[[:space:]]*DLL Name: //p' | tr 'A-Z' 'a-z' | sort -u)
                for import in $imports; do
                    case "$import" in
                        kernel32.dll|ntdll.dll|advapi32.dll|bcrypt.dll|bcryptprimitives.dll|ws2_32.dll|userenv.dll|psapi.dll) ;;
                        api-ms-win-core-*.dll|api-ms-win-crt-*.dll) ;;
                        *) echo "$name imports $import" >&2; exit 1 ;;
                    esac
                done
                if grep -a -q 'GCC: (' "$path"; then echo "$name contains GCC-built objects" >&2; exit 1; fi
                printf 'windows_library name=%s bytes=%s imports=%s\n' "$name" "$(wc -c < "$path")" "$(echo $imports)"
            fi
        done
    fi
done
