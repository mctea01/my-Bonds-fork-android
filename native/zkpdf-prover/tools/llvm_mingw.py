#!/usr/bin/env python3
"""Print the directory of the pinned llvm-mingw toolchain, fetching it first when it is missing.

llvm-mingw is clang and lld with libc++, libunwind, compiler-rt and the mingw-w64 UCRT: the Windows libraries built
with it carry no GCC runtime. LLVM_MINGW_ROOT names an existing copy of the same release instead. Network access
occurs only at build time."""
import hashlib
import os
from pathlib import Path
import platform
import subprocess
import sys
import urllib.request

RELEASE = "20251104"
ASSET = "llvm-mingw-" + RELEASE + "-ucrt-ubuntu-22.04-x86_64.tar.xz"
SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
NATIVE = Path(__file__).resolve().parents[2]


def main():
    given = os.environ.get("LLVM_MINGW_ROOT")
    root = Path(given).resolve() if given else NATIVE / "target" / ("llvm-mingw-" + RELEASE)
    if not (root / "bin/x86_64-w64-mingw32-clang++").exists():
        if given:
            raise SystemExit("llvm_mingw_root")
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            raise SystemExit("native_linux_host_required")
        root.parent.mkdir(parents=True, exist_ok=True)
        archive = root.parent / ASSET
        url = "https://github.com/mstorsjo/llvm-mingw/releases/download/" + RELEASE + "/" + ASSET
        digest = hashlib.sha256()
        with urllib.request.urlopen(url, timeout=120) as response, open(archive, "wb") as output:
            while block := response.read(1 << 20):
                digest.update(block)
                output.write(block)
        if digest.hexdigest() != SHA256:
            archive.unlink()
            print("llvm_mingw_sha256 " + digest.hexdigest(), file=sys.stderr)
            raise SystemExit("llvm_mingw_sha256")
        staging = root.parent / (root.name + ".partial")
        subprocess.run(["rm", "-rf", str(staging)], check=True)
        staging.mkdir()
        subprocess.run(["tar", "-xJf", str(archive), "--strip-components=1", "-C", str(staging)], check=True)
        archive.unlink()
        staging.rename(root)
    print(root)


if __name__ == "__main__":
    main()
