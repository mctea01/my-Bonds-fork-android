#!/usr/bin/env python3
"""Print the directory of the pinned Zig toolchain, fetching it first when it is missing.

Zig drives the Linux compatibility libraries (native/build.sh, cargo-zigbuild): it links against a chosen glibc
version instead of the build host's, so the libraries load on older distributions. ZIG_ROOT names an existing copy
of the same release instead. Network access occurs only at build time."""
import hashlib
import os
from pathlib import Path
import platform
import subprocess
import sys
import urllib.request

RELEASE = "0.14.1"
# From https://ziglang.org/download/index.json for this release.
ASSETS = {
    "x86_64": ("zig-x86_64-linux-" + RELEASE + ".tar.xz",
               "24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c"),
    "aarch64": ("zig-aarch64-linux-" + RELEASE + ".tar.xz",
                "f7a654acc967864f7a050ddacfaa778c7504a0eca8d2b678839c21eea47c992b"),
}
NATIVE = Path(__file__).resolve().parents[2]


def main():
    given = os.environ.get("ZIG_ROOT")
    root = Path(given).resolve() if given else NATIVE / "target" / ("zig-" + RELEASE)
    if not (root / "zig").exists():
        if given:
            raise SystemExit("zig_root")
        machine = platform.machine().lower().replace("arm64", "aarch64").replace("amd64", "x86_64")
        if platform.system() != "Linux" or machine not in ASSETS:
            raise SystemExit("native_linux_host_required")
        asset, sha256 = ASSETS[machine]
        root.parent.mkdir(parents=True, exist_ok=True)
        archive = root.parent / asset
        url = "https://ziglang.org/download/" + RELEASE + "/" + asset
        digest = hashlib.sha256()
        with urllib.request.urlopen(url, timeout=120) as response, open(archive, "wb") as output:
            while block := response.read(1 << 20):
                digest.update(block)
                output.write(block)
        if digest.hexdigest() != sha256:
            archive.unlink()
            print("zig_sha256 " + digest.hexdigest(), file=sys.stderr)
            raise SystemExit("zig_sha256")
        staging = root.parent / (root.name + ".partial")
        subprocess.run(["rm", "-rf", str(staging)], check=True)
        staging.mkdir()
        subprocess.run(["tar", "-xJf", str(archive), "--strip-components=1", "-C", str(staging)], check=True)
        archive.unlink()
        staging.rename(root)
    print(root)


if __name__ == "__main__":
    main()
