#!/usr/bin/env python3
"""Build frozen zkPDF assets with pinned tools; invoke with python3 -I.

CRS acquisition is an explicit build-time action (--download-crs). Runtime
consumers must verify the manifest and never download missing CRS files.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CRS = {
    "bn254_g1.dat": (134217792, "ea6069e3563ad79f186d1c0088499309cbdaeb54254346760ffec7fe15ae49cd", "g1.dat"),
    "bn254_g2.dat": (128, "01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f", "g2.dat"),
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require(condition, code):
    if not condition:
        raise ValueError(code)


def pins():
    entries = {}
    for line in (ROOT / "VERSIONS").read_text().splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            require(key not in entries, "duplicate_version_key")
            entries[key] = value
    require(entries["nargo"] == "1.0.0-beta.15", "nargo_pin")
    require(entries["noirc_commit"] == "83245db91dcf63420ef4bcbbd85b98f397fee663", "noirc_pin")
    require(entries["bb"] == "2.1.9" and entries["oracle_hash"] == "poseidon2"
            and entries["zero_knowledge"] == "true" and entries["disable_zk"] == "false", "backend_pin")
    return entries


def checked_crs(directory, download):
    directory.mkdir(parents=True, exist_ok=True)
    for name, (size, expected, remote) in CRS.items():
        path = directory / name
        if not path.exists() and download:
            request = urllib.request.Request("https://crs.aztec.network/" + remote,
                                             headers={"Range": "bytes=0-" + str(size - 1)})
            temporary = path.with_suffix(".part")
            try:
                with urllib.request.urlopen(request, timeout=120) as response, temporary.open("wb") as output:
                    remaining = size + 1
                    while remaining:
                        chunk = response.read(min(1024 * 1024, remaining))
                        if not chunk:
                            break
                        output.write(chunk)
                        remaining -= len(chunk)
                require(temporary.stat().st_size == size and digest(temporary) == expected, "crs_integrity")
                temporary.replace(path)
            finally:
                temporary.unlink(missing_ok=True)
        require(path.is_file() and path.stat().st_size == size and digest(path) == expected, "crs_integrity")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nargo", default=os.environ.get("NARGO", "nargo"))
    parser.add_argument("--bb", default=os.environ.get("BB", "bb"))
    parser.add_argument("--output", type=Path, default=ROOT / "target/zkpdf-assets")
    parser.add_argument("--crs", type=Path)
    parser.add_argument("--download-crs", action="store_true")
    args = parser.parse_args()
    versions = pins()
    nargo_version = subprocess.check_output([args.nargo, "--version"], text=True)
    require(nargo_version.splitlines()[0] == "nargo version = " + versions["nargo"]
            and versions["noirc_commit"] in nargo_version, "nargo_version")
    require(subprocess.check_output([args.bb, "--version"], text=True).strip() == versions["bb"], "bb_version")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    crs = (args.crs or output / "crs").resolve()
    checked_crs(crs, args.download_crs)
    environment = dict(os.environ, RAYON_NUM_THREADS="1", HARDWARE_CONCURRENCY="2")
    mappings = {}
    built = {}
    for key, package in versions.items():
        if not key.startswith("zkpdf-v1-") or not key.endswith(".package"):
            continue
        identity = key.removesuffix(".package")
        flags = versions[identity + ".compile_flags"]
        expected = (versions[identity + ".acir_sha256"], versions[identity + ".vk_sha256"])
        if package in built:
            require(built[package] == (flags, expected), "shared_asset_pin")
        else:
            print(package + ": compile and check frozen hashes", flush=True)
            installed_acir = output / (package + ".json")
            installed_vk = output / (package + ".vk")
            if (installed_acir.is_file() and installed_vk.is_file()
                    and digest(installed_acir) == expected[0] and digest(installed_vk) == expected[1]):
                built[package] = (flags, expected)
                mappings[identity] = {"acir": package + ".json", "vk": package + ".vk",
                                      "acir_sha256": expected[0], "vk_sha256": expected[1]}
                continue
            command = [args.nargo, "compile", "--program-dir", str(ROOT), "--package", package]
            if flags != "default":
                require(flags == "--bounded-codegen", "compile_flags")
                command.append(flags)
            subprocess.run(command, env=environment, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            acir = ROOT / "target" / (package + ".json")
            require(digest(acir) == expected[0], "acir_integrity:" + package)
            with tempfile.TemporaryDirectory(dir=output) as temporary:
                subprocess.run([args.bb, "write_vk", "-s", "ultra_honk", "--oracle_hash", "poseidon2",
                                "-b", str(acir), "-o", temporary, "-c", str(crs)],
                               env=environment, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                vk = Path(temporary) / "vk"
                require(digest(vk) == expected[1], "vk_integrity:" + package)
                shutil.copyfile(acir, output / (package + ".json"))
                shutil.copyfile(vk, output / (package + ".vk"))
            built[package] = (flags, expected)
        mappings[identity] = {"acir": package + ".json", "vk": package + ".vk",
                              "acir_sha256": expected[0], "vk_sha256": expected[1]}
    require(len(mappings) == 14 and len(built) == 10, "composition_count")
    (output / "manifest.json").write_text(json.dumps(mappings, indent=2) + "\n")
    print("Ten distinct assets and fourteen composition mappings verified")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        # Tool failures must not dump compiler inputs or subprocess output.
        code = str(error) if isinstance(error, ValueError) else type(error).__name__
        print("zkpdf_asset_build_failed:" + code, file=sys.stderr)
        raise SystemExit(1) from None
