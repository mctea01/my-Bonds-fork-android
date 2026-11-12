#!/usr/bin/env python3
"""Download a hash-pinned Linux library and run a research-only C ABI probe."""
import argparse
import hashlib
import json
import pathlib
import platform
import subprocess
import tempfile
import urllib.request

REVISION = "a015c9d93874fe6e09df1354006353ce6f94751d"
SHA256 = "d7b7a64ea444a268b5bf444fa4f283ddf0f551ef0f5ae38e7d0a65f10d2dd3dc"
URL = ("https://raw.githubusercontent.com/openwallet-foundation/multipaz/"
       + REVISION + "/multipaz-longfellow/src/jvmMain/resources/"
       "nativeLibs/linux-x86_64/libzkp.so")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=pathlib.Path,
                        help="Use an existing copy, with the same SHA-256 check")
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        parser.error("This probe is limited to Linux x86_64")
    report = {"upstream_revision": REVISION, "url": URL, "sha256": SHA256,
              "platform": platform.platform(), "commands": [],
              "status": "not-tested", "proof_correctness": "not-tested"}

    def run(command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        report["commands"].append({"argv": command, "returncode": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            raise RuntimeError("Probe command failed: " + command[0])
        return result

    try:
        with tempfile.TemporaryDirectory(prefix="diw-longfellow-") as directory:
            root = pathlib.Path(directory)
            library = root / "libzkp.so"
            if args.library:
                data = args.library.read_bytes()
            else:
                with urllib.request.urlopen(URL, timeout=60) as response:
                    data = response.read()
            actual = hashlib.sha256(data).hexdigest()
            report["actual_sha256"] = actual
            if actual != SHA256:
                raise RuntimeError("Library SHA-256 mismatch")
            library.write_bytes(data)
            run(["cc", "--version"])
            run(["getconf", "GNU_LIBC_VERSION"])
            run(["readelf", "-d", str(library)])
            run(["readelf", "--version-info", str(library)])
            run(["nm", "-D", "--defined-only", str(library)])
            source = pathlib.Path(__file__).with_suffix(".c").resolve()
            executable = root / "probe"
            report["probe_source_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
            run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(source),
                 "-L" + str(root), "-Wl,-rpath," + str(root), "-lzkp", "-o", str(executable)])
            report["status"] = "linked"
            run([str(executable)])
            report["status"] = "smoke-tested"
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("smoke-tested: C ABI only; proof correctness remains not-tested")


if __name__ == "__main__":
    main()
