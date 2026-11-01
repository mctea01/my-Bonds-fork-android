#!/usr/bin/env python3
"""Cross-check the two fictional Rust bundles and produce pinned CLI proofs.

Run after synthetic_bench and execute_synthetic_acvm with output directories.
The reverse Rust verification is the opt-in real_proof_rejections test.
"""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess

KINDS = {"sha_content": "pdf_sha_content_v1", "sha_opaque": "pdf_sha_opaque_v1",
         "inflate0": "pdf_inflate_seg0_v1", "inflate": "pdf_inflate_seg_v1",
         "lex": "pdf_lex_seg_v1", "claim": "pdf_claim_v1", "pred": "pdf_pred_v1"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("assets", "rust", "acvm", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--bb", default="bb")
    args = parser.parse_args()
    if subprocess.check_output([args.bb, "--version"], text=True).strip() != "2.1.9":
        raise SystemExit("bb_version")
    pins = dict(line.strip().split("=", 1) for line in
                (Path(__file__).resolve().parents[1] / "VERSIONS").read_text().splitlines()
                if line and not line.startswith("#"))
    environment = dict(os.environ, HARDWARE_CONCURRENCY="2")
    for name, expected in [("bn254_g1.dat", "ea6069e3563ad79f186d1c0088499309cbdaeb54254346760ffec7fe15ae49cd"),
                           ("bn254_g2.dat", "01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f")]:
        if hashlib.sha256((args.assets / name).read_bytes()).hexdigest() != expected:
            raise SystemExit("crs_integrity")
    def run(command):
        result = subprocess.run([args.bb, *map(str, command)], env=environment,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode:
            raise SystemExit("cli_interop_failed")
    settings = ["-s", "ultra_honk", "--oracle_hash", "poseidon2", "-c", args.assets]
    for fixture in ("student", "travel-rc4"):
        for directory in sorted((args.rust / fixture).iterdir()):
            if not directory.is_dir():
                continue
            kind = directory.name.rsplit("-", 1)[0]
            package = KINDS[kind]
            for extension, pin in [("json", "acir"), ("vk", "vk")]:
                expected = pins["zkpdf-v1-phone." + package + "." + pin + "_sha256"]
                if hashlib.sha256((args.assets / (package + "." + extension)).read_bytes()).hexdigest() != expected:
                    raise SystemExit("circuit_integrity")
            vk = args.assets / (package + ".vk")
            run(["verify", *settings, "-k", vk, "-p", directory / "proof", "-i", directory / "public_inputs"])
            output = args.output / fixture / directory.name
            output.mkdir(parents=True, exist_ok=True)
            run(["prove", *settings, "-b", args.assets / (package + ".json"), "-k", vk,
                 "-w", args.acvm / fixture / directory.name / "witness.gz", "-o", output, "--verify"])
            print(fixture + "/" + directory.name + ": Rust-to-CLI passed; CLI proof generated", flush=True)


if __name__ == "__main__":
    main()
