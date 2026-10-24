#!/usr/bin/env python3
"""Reproduce only synthetic reference hashes; never print witness/input data."""
import hashlib
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def main():
    subprocess.run(["python3", "-I", str(ROOT / "prepare.py")], check=True)
    circom = ROOT / ".cache/zkid/wallet-unit-poc/circom"
    output = ROOT / "build/wasm-vectors"
    output.mkdir(parents=True, exist_ok=True)
    for name, folder, expected in [
        ("jwt_2k", "jwt", "a3ac60db590b8e8e0e3d5483febda90bf8c89a73c2df9be4108a13c51ea149ac"),
        ("show", "show", "53538ff17f49eb1a9a1615e3794f3a257ff4e88f67f4d02f1ab4f3b599389ef8"),
    ]:
        generated = circom / f"build/{name}/{name}_js"
        target = output / (name + ".wtns")
        subprocess.run(["node", str(generated / "generate_witness.js"),
            str(generated / (name + ".wasm")), str(circom / f"inputs/{folder}/2k/default.json"),
            str(target)], check=True)
        with target.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != expected:
            raise SystemExit("Synthetic reference witness differs from the pinned vector")
    print("Circom wasm synthetic reference vectors reproduced")


if __name__ == "__main__":
    main()
