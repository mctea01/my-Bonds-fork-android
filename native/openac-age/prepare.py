#!/usr/bin/env python3
"""Check pinned sources and reproduce the Bonds R1CS/wasm build artifacts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
CACHE = ROOT / ".cache"
VERSIONS = json.loads((ROOT / "VERSIONS.json").read_text())
CIRCUITS = {name: VERSIONS[name + "_r1cs_sha256"] for name in ("jwt_2k", "show")}


def run(*args, cwd=None, env=None):
    subprocess.run([str(arg) for arg in args], cwd=cwd, env=env, check=True)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_digest(path):
    # Git for Windows may check out text with CRLF; artifact hashes stay binary.
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def checkout(name, url, revision):
    path = CACHE / name
    if not path.exists():
        run("git", "clone", "--filter=blob:none", "--no-checkout", url, path)
        run("git", "config", "core.autocrlf", "false", cwd=path)
        run("git", "checkout", "--detach", revision, cwd=path)
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()
    if actual != revision:
        raise SystemExit(f"Refusing unpinned {name} revision")
    return path


def apply_patch(source, patch):
    with tempfile.NamedTemporaryFile(dir=CACHE, suffix=".patch", delete=False) as temporary:
        temporary.write(patch.read_bytes().replace(b"\r\n", b"\n"))
        normalized = Path(temporary.name)
    try:
        applied = subprocess.run(["git", "apply", "--reverse", "--check", str(normalized)],
                                 cwd=source, capture_output=True).returncode == 0
        if not applied:
            run("git", "apply", "--check", normalized, cwd=source)
            run("git", "apply", normalized, cwd=source)
    finally:
        normalized.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources-only", action="store_true")
    parser.add_argument("--force", action="store_true", help="Recompile cached R1CS/wasm")
    args = parser.parse_args()
    CACHE.mkdir(exist_ok=True)
    zkid = checkout("zkid", "https://github.com/privacy-ethereum/zkID.git", VERSIONS["zkid"])
    apply_patch(zkid, ROOT / "patches/zkid-mobile.patch")
    runtime = checkout("circom-witnesscalc", "https://github.com/iden3/circom-witnesscalc.git", VERSIONS["circom_witnesscalc"])
    patch = ROOT / "patches/circom-witnesscalc-secq256r1.patch"
    if source_digest(patch) != VERSIONS["circom_witnesscalc_patch_sha256"]:
        raise SystemExit("Witness runtime patch checksum mismatch")
    apply_patch(runtime, patch)
    changed = subprocess.check_output(["git", "diff", "--name-only"], cwd=runtime, text=True).splitlines()
    expected = VERSIONS["patched_source_sha256"]
    if set(changed) != set(expected) or any(source_digest(runtime / name) != value for name, value in expected.items()):
        raise SystemExit("Witness runtime source differs from the pinned patch")
    for name, expected in VERSIONS["runtime_bundle_sha256"].items():
        if source_digest(ROOT / "vendor/circom-witnesscalc" / name) != expected:
            raise SystemExit("Vendored witness runtime checksum mismatch")
    if args.sources_only:
        return
    version = subprocess.check_output(["circom", "--version"], text=True).strip()
    if version != "circom compiler 2.2.3":
        raise SystemExit("Circom 2.2.3 is required")
    circom = zkid / "wallet-unit-poc/circom"
    env = os.environ.copy()
    env["YARN_NODE_LINKER"] = "node-modules"
    run("corepack", "yarn", "install", "--immutable", cwd=circom, env=env)
    for name, expected in CIRCUITS.items():
        output = circom / "build" / name
        output.mkdir(parents=True, exist_ok=True)
        r1cs = output / f"{name}.r1cs"
        wasm = output / f"{name}_js/{name}.wasm"
        if args.force or not r1cs.is_file() or not wasm.is_file():
            run("circom", f"circuits/main/{name}.circom", "--r1cs", "--wasm", "--sym",
                "--prime", "secq256r1", "--O2", "-l", "node_modules", "-o", output, cwd=circom)
        if digest(r1cs) != expected:
            raise SystemExit(f"{name} does not match the pinned Bonds circuit")
    print("Pinned age R1CS and wasm artifacts verified")


if __name__ == "__main__":
    main()
