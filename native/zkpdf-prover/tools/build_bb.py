#!/usr/bin/env python3
"""Build the pinned static backend. Network access occurs only at build time."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time

REVISION = "f2bed7ed073966bb2a2dcdd02a133d11bf2996d3"
MSGPACK = "5ee9a1c8c325658b29867829677c7eb79c433a98"
NATIVE = Path(__file__).resolve().parents[2]


def run(command):
    subprocess.run([str(x) for x in command], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=NATIVE / "target/bb-source")
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    source, build = args.source.resolve(), args.build.resolve()
    started = time.monotonic()
    if not source.exists():
        run(["git", "clone", "--filter=blob:none", "--no-checkout", "--depth=1", "--branch", "v2.1.9",
             "https://github.com/AztecProtocol/aztec-packages.git", source])
        run(["git", "-C", source, "sparse-checkout", "set", "barretenberg"])
        run(["git", "-C", source, "checkout", "--detach", REVISION])
    if subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip() != REVISION:
        raise SystemExit("bb_revision")
    run(["git", "-C", source, "diff", "--exit-code", "--quiet", "HEAD", "--", "barretenberg"])
    flags = ["-DCMAKE_BUILD_TYPE=Release", "-DDISABLE_AZTEC_VM=ON", "-DDISABLE_ASM=ON",
             "-DCMAKE_POSITION_INDEPENDENT_CODE=ON", "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
             "-DCMAKE_CXX_FLAGS=-Wno-error=missing-field-initializers -Wno-error=array-bounds"]
    if args.target == "x86_64-unknown-linux-gnu":
        if platform.system() != "Linux":
            raise SystemExit("native_linux_host_required")
        flags += ["-DTARGET_ARCH=x86-64"]
    elif args.target == "aarch64-apple-darwin":
        if platform.system() != "Darwin":
            raise SystemExit("native_macos_host_required")
        flags += ["-DARM=ON", "-DCMAKE_OSX_ARCHITECTURES=arm64"]
    elif args.target in ("aarch64-linux-android", "x86_64-linux-android"):
        ndk = Path(os.environ["ANDROID_NDK_HOME"])
        abi = "arm64-v8a" if args.target.startswith("aarch64") else "x86_64"
        flags += ["-DCMAKE_TOOLCHAIN_FILE=" + str(ndk / "build/cmake/android.toolchain.cmake"),
                  "-DANDROID_ABI=" + abi, "-DANDROID_PLATFORM=android-29", "-DANDROID_STL=c++_static"]
        flags += ["-DARM=ON"] if abi == "arm64-v8a" else ["-DTARGET_ARCH=x86-64"]
    else:
        # Upstream 2.1.9 has POSIX dependencies; silently substituting another
        # version or a CLI executable would violate the frozen runtime contract.
        raise SystemExit("bb_2_1_9_windows_port_required")
    run(["cmake", "-S", source / "barretenberg/cpp", "-B", build, "-G", "Ninja", *flags])
    # ExternalProject's default clone can omit this non-advertised exact commit.
    # Fetch it explicitly, retaining upstream's revision and stamp contract.
    msgpack = build / "_deps/msgpack-c/src/msgpack-c"
    if not (msgpack / ".git").exists():
        msgpack.mkdir(parents=True, exist_ok=True)
        run(["git", "-C", msgpack, "init"])
        run(["git", "-C", msgpack, "remote", "add", "origin", "https://github.com/AztecProtocol/msgpack-c.git"])
    run(["git", "-C", msgpack, "fetch", "--depth=1", "origin", MSGPACK])
    run(["git", "-C", msgpack, "checkout", "--detach", MSGPACK])
    stamp = msgpack.parent / "msgpack-c-stamp"
    shutil.copyfile(stamp / "msgpack-c-gitinfo.txt", stamp / "msgpack-c-gitclone-lastrun.txt")
    run(["cmake", "--build", build, "--target", "barretenberg", "libdeflate_static", "--parallel", args.jobs])
    result = {"revision": REVISION, "target": args.target,
              "build_seconds": round(time.monotonic() - started, 3),
              "static_library_bytes": (build / "lib/libbarretenberg.a").stat().st_size}
    (build / "zkpdf-build.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
