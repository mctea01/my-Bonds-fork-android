#!/usr/bin/env python3
"""Build the pinned static backend. Network access occurs only at build time."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time

# v6 is the backend of every circuit the app proves; v5 only verifies zkPassport proofs of circuits before 0.22.0
# and ships as an optional component. v5 tracks its generated constants header itself.
VERSIONS = {
    "v6": ("v6.0.0", "0219f11d8133970df3974fe5ae65e006bf8c193a",
           "6367ab71dbdf5d3362289ed1cf3dd4517a94c9e8113f5fed10378aa49a730873"),
    "v5": ("v5.0.0", "7aa2bd616d632801fe65d97ee8a4434f26886b40", None),
}
NATIVE = Path(__file__).resolve().parents[2]


def run(command):
    subprocess.run([str(x) for x in command], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", choices=sorted(VERSIONS), default="v6")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    tag, revision, constants_sha256 = VERSIONS[args.version]
    default = "target/bb-source" if args.version == "v6" else "target/bb-" + args.version
    source, build = (args.source or NATIVE / default).resolve(), args.build.resolve()
    started = time.monotonic()
    if not source.exists():
        run(["git", "clone", "--filter=blob:none", "--no-checkout", "--depth=1", "--branch", tag,
             "https://github.com/AztecProtocol/aztec-packages.git", source])
        run(["git", "-C", source, "sparse-checkout", "set", "barretenberg"])
        run(["git", "-C", source, "checkout", "--detach", revision])
    if subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip() != revision:
        raise SystemExit("bb_revision")
    # The DSL includes Aztec protocol constants that upstream generates from the Noir protocol sources
    # with a TypeScript tool at configure time. cpp/aztec_constants.hpp is that tool's output for the v6 revision
    # (cpp.json selection), pinned by hash, so the build needs neither Node nor the protocol sources.
    if constants_sha256:
        constants = Path(__file__).resolve().parents[1] / "cpp/aztec_constants.hpp"
        if hashlib.sha256(constants.read_bytes()).hexdigest() != constants_sha256:
            raise SystemExit("bb_constants")
        shutil.copyfile(constants, source / "barretenberg/cpp/src/barretenberg/aztec/aztec_constants.hpp")
    run(["git", "-C", source, "diff", "--exit-code", "--quiet", "HEAD", "--", "barretenberg"])
    # BB_LITE drops the server-side subsystems (lmdb, world state, IPC, Node module) and AVM=OFF the Aztec VM;
    # neither is reachable from the UltraHonk prove and verify calls the bridge makes.
    flags = ["-DCMAKE_BUILD_TYPE=Release", "-DAVM=OFF", "-DBB_LITE=ON", "-DDISABLE_ASM=ON",
             "-DENABLE_PIC=ON", "-DCMAKE_POSITION_INDEPENDENT_CODE=ON", "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
             "-DCMAKE_CXX_FLAGS=-Wno-error=missing-field-initializers -Wno-error=array-bounds"]
    # Replaces the CMAKE_CXX_FLAGS above (the last -D wins) with the same warnings plus the baseline.
    portable = ["-DCMAKE_PROJECT_INCLUDE=" + str(Path(__file__).resolve().parent / "portable_x86_64.cmake"),
                "-DCMAKE_C_FLAGS=-march=x86-64-v2",
                "-DCMAKE_CXX_FLAGS=-march=x86-64-v2 -Wno-error=missing-field-initializers -Wno-error=array-bounds"]
    if args.target == "x86_64-unknown-linux-gnu":
        if platform.system() != "Linux":
            raise SystemExit("native_linux_host_required")
        flags += portable
    elif args.target == "aarch64-apple-darwin":
        if platform.system() != "Darwin":
            raise SystemExit("native_macos_host_required")
        # The same minimum as native/build.sh gives rustc and the bridge, so every object agrees.
        flags += ["-DARM=ON", "-DCMAKE_OSX_ARCHITECTURES=arm64",
                  "-DCMAKE_OSX_DEPLOYMENT_TARGET=" + os.environ.get("MACOSX_DEPLOYMENT_TARGET", "14.0")]
    elif args.target in ("aarch64-linux-android", "x86_64-linux-android"):
        ndk = Path(os.environ["ANDROID_NDK_HOME"])
        abi = "arm64-v8a" if args.target.startswith("aarch64") else "x86_64"
        flags += ["-DCMAKE_TOOLCHAIN_FILE=" + str(ndk / "build/cmake/android.toolchain.cmake"),
                  "-DANDROID_ABI=" + abi, "-DANDROID_PLATFORM=android-29", "-DANDROID_STL=c++_static"]
        flags += ["-DARM=ON"] if abi == "arm64-v8a" else portable
    else:
        # Upstream only cross-compiles Windows from Linux with its zig toolchain, and its
        # dependency fetches run through sh; a CLI executable would break the runtime contract.
        raise SystemExit("bb_windows_port_required")
    run(["cmake", "-S", source / "barretenberg/cpp", "-B", build, "-G", "Ninja", *flags])
    run(["cmake", "--build", build, "--target", "barretenberg", "vm2_stub", "libdeflate_static", "--parallel", args.jobs])
    # acir_format references the AVM recursion entry points; upstream links their stubs into
    # executables only, so archive them next to libbarretenberg.a for the bridge.
    stub = build / "src/barretenberg/vm2_stub/CMakeFiles/vm2_stub.dir"
    archive = build / "lib/libzkpdf_vm2_stub.a"
    archive.unlink(missing_ok=True)
    run([os.environ.get("ZKPDF_AR") or os.environ.get("AR", "ar"), "rcs", archive, *sorted(stub.rglob("*.o"))])
    result = {"revision": revision, "target": args.target,
              "build_seconds": round(time.monotonic() - started, 3),
              "static_library_bytes": (build / "lib/libbarretenberg.a").stat().st_size}
    (build / "zkpdf-build.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
