#!/usr/bin/env python3
"""Compile and run the isolated Linux DIW C ABI probe; save auditable evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("This probe currently supports Linux only")
    library = args.library.resolve(strict=True)
    source = Path(__file__).with_name("runtime_probe.c").resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    with library.open("rb") as stream:
        library_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    report = {
        "scope": "isolated-runtime-smoke; not proof or wallet acceptance",
        "platform": platform.platform(),
        "library": str(library),
        "library_sha256": library_hash,
        "probe_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "status": "not-tested",
        "commands": [],
    }

    def run(command, name):
        try:
            proc = subprocess.run(command, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, timeout=60)
            code, output = proc.returncode, proc.stdout
        except (OSError, subprocess.TimeoutExpired) as exc:
            code, output = -1, str(exc)
        (out / name).write_text(output, encoding="utf-8")
        report["commands"].append({"argv": command, "exit_code": code, "log": name})
        return code

    try:
        # Inspect ELF metadata without executing the library through ldd.
        run([args.cc, "--version"], "compiler.log")
        run(["readelf", "-h", "-d", "-V", str(library)], "elf.log")
        run(["nm", "-D", "--defined-only", str(library)], "exports.log")
        executable = out / "runtime_probe"
        report["status"] = "build-attempted"
        if run([args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror", str(source),
                "-ldl", "-o", str(executable)], "compile.log") != 0:
            return 1
        # This link is against libdl; only the following run tests DIW loading.
        if run([str(executable), str(library)], "smoke.log") != 0:
            return 1
        report["status"] = "smoke-tested"
        return 0
    finally:
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(report["status"])


if __name__ == "__main__":
    sys.exit(main())
