#!/usr/bin/env python3
"""Reproduce the Apache-2.0 startup graph; no circomlib templates are included."""
import hashlib
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def main():
    compiler = ROOT / "build/graph-tools/release" / ("build-circuit.exe" if os.name == "nt" else "build-circuit")
    output = ROOT / "build/graphs/self_test.graph"
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(compiler), str(ROOT / "tests/fixtures/self_test.circom"),
        str(output), "-p", "secq256r1"], cwd=output.parent, check=True)
    generated = output.read_bytes()
    if generated != (ROOT / "tests/fixtures/self_test.graph").read_bytes():
        raise SystemExit("Startup graph differs from the checked-in synthetic vector")
    if hashlib.sha256(generated).hexdigest() != "12ff5a6b46868654f6c0f94d6c119da1a78f789e2b7fee658b3c4eefb1cde1f3":
        raise SystemExit("Startup graph checksum mismatch")
    print("Synthetic secq256r1 startup graph reproduced")


if __name__ == "__main__":
    main()
