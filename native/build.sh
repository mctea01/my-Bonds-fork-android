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
    targets=x86_64-unknown-linux-gnu,x86_64-pc-windows-gnu,aarch64-apple-darwin,android
fi
targets=${targets//host/$host}
# Optional proof backends (DIW_ZK_FEATURES, set by Gradle's diw.zkFeatures). The exports exist in every build;
# a backend left out reports Unsupported. OpenAC needs protoc and libclang to build its witness runtime.
features=${DIW_ZK_FEATURES:-}
if [[ -n "$features" ]]; then
    [[ "$features" != ,* && "$features" != *, && "$features" != *,,* ]] || { echo "Invalid DIW_ZK_FEATURES list" >&2; exit 1; }
    IFS=',' read -ra backends <<< "$features"
    for backend in "${backends[@]}"; do
        case "$backend" in
            openac|tlsn|zkpdf) ;;
            *) echo "Unsupported DIW_ZK_FEATURES entry" >&2; exit 1 ;;
        esac
    done
fi
feature_args=()
[[ -z "$features" ]] || feature_args=(--features "$features")
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
build_zkpdf() {
    local bb_target=$1
    [[ ",$features," == *,zkpdf,* ]] || return 0
    export ZKPDF_BB_SOURCE=${ZKPDF_BB_SOURCE:-"$PWD/target/bb-source"}
    export ZKPDF_BB_BUILD=${bb_build_override:-"$PWD/target/bb-$bb_target"}
    if [[ ! -f "$ZKPDF_BB_BUILD/lib/libbarretenberg.a" || ! -f "$ZKPDF_BB_BUILD/_deps/libdeflate-build/libdeflate.a" ]]; then
        python3 -I zkpdf-prover/tools/build_bb.py --source "$ZKPDF_BB_SOURCE" --build "$ZKPDF_BB_BUILD" --target "$bb_target"
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
        rustup target add aarch64-linux-android x86_64-linux-android
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
            done
        else
            cargo ndk "${abi_args[@]}" --platform 29 -o dist/android build --release --locked -p diw-zk-ffi ${feature_args[@]+"${feature_args[@]}"}
        fi
    else
        case "$target" in
            x86_64-unknown-linux-gnu) platform=linux-x86_64; library=libdiw_zk.so ;;
            x86_64-pc-windows-gnu|x86_64-pc-windows-msvc) platform=windows-x86_64; library=diw_zk.dll ;;
            # One minimum macOS for Barretenberg, the bridge and rustc (otherwise each object targets a different one).
            aarch64-apple-darwin) platform=macos-aarch64; library=libdiw_zk.dylib; export MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-14.0} ;;
            *) echo "Unsupported desktop target" >&2; exit 1 ;;
        esac
        build_zkpdf "$target"
        rustup target add "$target"
        cargo build --release --locked -p diw-zk-ffi ${feature_args[@]+"${feature_args[@]}"} --target "$target"
        mkdir -p "dist/resources/zk/native/$platform"
        cp "target/$target/release/$library" "dist/resources/zk/native/$platform/$library"
        # sha256sum on Linux and Git for Windows, shasum on macOS.
        path="dist/resources/zk/native/$platform/$library"
        if command -v sha256sum > /dev/null; then digest=$(sha256sum "$path"); else digest=$(shasum -a 256 "$path"); fi
        printf '%s\n' "${digest%% *}" > "$path.sha256"
    fi
done
