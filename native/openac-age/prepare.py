#!/usr/bin/env python3
"""Fetch pinned build sources and reproduce the Bonds age circuit artifacts."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parent
CACHE = ROOT / ".cache"
ZKID = "b395e09c225ff45b003f0087c28e2e208e22f944"
WITNESSCALC = "707dc54877ad3226042d959d7ec956ae540a9a3e"
GMP_SHA256 = "fd4829912cddd12f84181c3451cc752be224643e87fac497b69edddadc49b4f2"
CIRCUITS = {
    "jwt_2k": "d4f8b34dfd454234872a34f47ea486545cb4d989c41ed75f856268718251dc6a",
    "show": "3809e70502fa90f2038760da5f1399a1e3eb17923e5af872edf3dfa0b7d37a9a",
}


def run(*args, cwd=None, env=None):
    subprocess.run([str(arg) for arg in args], cwd=cwd, env=env, check=True)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def checkout(name, url, revision):
    path = CACHE / name
    if not path.exists():
        run("git", "clone", "--filter=blob:none", "--no-checkout", url, path)
        run("git", "checkout", "--detach", revision, cwd=path)
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()
    if actual != revision:
        raise SystemExit(f"Refusing unpinned {name} revision")
    return path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources-only", action="store_true")
    parser.add_argument("--force", action="store_true", help="Recompile cached circuits")
    args = parser.parse_args()
    CACHE.mkdir(exist_ok=True)
    zkid = checkout("zkid", "https://github.com/privacy-ethereum/zkID.git", ZKID)
    patch = ROOT / "patches/zkid-mobile.patch"
    applied = subprocess.run(["git", "apply", "--reverse", "--check", str(patch)],
                             cwd=zkid, capture_output=True).returncode == 0
    if not applied:
        run("git", "apply", "--check", patch, cwd=zkid)
        run("git", "apply", patch, cwd=zkid)
    witness = checkout("witnesscalc", "https://github.com/zkmopro/witnesscalc.git", WITNESSCALC)
    run("git", "submodule", "update", "--init", "--recursive", cwd=witness)
    archive = CACHE / "gmp-6.2.1.tar.xz"
    if not archive.exists():
        temporary = archive.with_suffix(".part")
        urllib.request.urlretrieve("https://ftp.gnu.org/gnu/gmp/gmp-6.2.1.tar.xz", temporary)
        temporary.replace(archive)
    if digest(archive) != GMP_SHA256:
        raise SystemExit("GMP archive checksum mismatch")
    if not (CACHE / "gmp-6.2.1/configure").is_file():
        with tarfile.open(archive) as source:
            source.extractall(CACHE, filter="data")
    if args.sources_only:
        return
    version = subprocess.check_output(["circom", "--version"], text=True).strip()
    if version != "circom compiler 2.2.3":
        raise SystemExit("Circom 2.2.3 is required")
    circom = zkid / "wallet-unit-poc/circom"
    env = os.environ.copy()
    env["YARN_NODE_LINKER"] = "node-modules"
    run("corepack", "yarn", "install", "--immutable", cwd=circom, env=env)
    destination = ROOT / "vendor/circom/build/cpp"
    destination.mkdir(parents=True, exist_ok=True)
    for name, expected in CIRCUITS.items():
        r1cs = circom / f"build/{name}/{name}.r1cs"
        generated = [circom / f"build/cpp/{name}.{extension}" for extension in ("cpp", "dat")]
        if args.force or not r1cs.is_file() or not all(path.is_file() for path in generated):
            run("bash", "scripts/compile.sh", name, cwd=circom, env=env)
        if digest(r1cs) != expected:
            raise SystemExit(f"{name} does not match the pinned Bonds circuit")
        for extension in ("cpp", "dat"):
            shutil.copy2(circom / f"build/cpp/{name}.{extension}", destination)
    print("Pinned age circuits reproduced successfully")


if __name__ == "__main__":
    main()
