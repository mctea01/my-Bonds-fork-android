#!/usr/bin/env python3
"""Build frozen zkPDF assets with pinned tools; invoke with python3 -I.

CRS acquisition is an explicit build-time action (--download-crs). Runtime
consumers must verify the manifest and never download missing CRS files.
"""
import argparse
import hashlib
import gzip
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


def package_gzip(data):
    encoded = bytearray(gzip.compress(data, compresslevel=9, mtime=0))
    # Frozen catalog packaging uses OS=3. Python 3.13 changed compress(mtime=0)
    # to OS=255; pin this metadata byte independently of Python/host defaults.
    encoded[9] = 3
    return bytes(encoded)


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
    require(entries["nargo"] == "1.0.0-rc.3", "nargo_pin")
    require(entries["noirc_commit"] == "5a7ee9bf5ed8973076df7bb0d2b723024db09ae7", "noirc_pin")
    require(entries["bb"] == "6.0.0" and entries["oracle_hash"] == "poseidon2"
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


def build(args, environment, crs, output, package, flags, expected):
    command = [args.nargo, "compile", "--program-dir", str(ROOT), "--package", package]
    # nargo 1.0.0-rc.3 removed --bounded-codegen; every package compiles with default flags.
    require(flags == "default", "compile_flags")
    subprocess.run(command, env=environment, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    acir = ROOT / "target" / (package + ".json")
    # VERSIONS hashes complete nargo JSON, including debug source paths.
    # Canonicalize only those paths to the frozen build root. ABI,
    # bytecode and all other data must still match the frozen digest.
    artifact = json.loads(acir.read_bytes())
    frozen_root = "/workspace/my-Bonds-fork-android/native/circuits/"
    for item in artifact.get("file_map", {}).values():
        path = item.get("path", "").replace("\\", "/")
        prefix = ROOT.as_posix() + "/"
        if path.startswith(prefix):
            item["path"] = frozen_root + path[len(prefix):]
    acir.write_text(json.dumps(artifact, ensure_ascii=False, separators=(",", ":")))
    require(args.repin or digest(acir) == expected[0], "acir_integrity:" + package)
    with tempfile.TemporaryDirectory(dir=output) as temporary:
        vk = Path(temporary) / "vk"
        if args.vk_tool is None:
            subprocess.run([args.bb, "write_vk", "-s", "ultra_honk", "--oracle_hash", "poseidon2",
                            "-b", str(acir), "-o", temporary, "-c", str(crs)],
                           env=environment, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run([str(args.vk_tool), str(crs), str(acir), str(vk)],
                           env=environment, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        require(args.repin or digest(vk) == expected[1], "vk_integrity:" + package)
        shutil.copyfile(acir, output / (package + ".json"))
        shutil.copyfile(vk, output / (package + ".vk"))
    return digest(output / (package + ".json")), digest(output / (package + ".vk"))


def repin_versions(actual):
    lines = []
    for line in (ROOT / "VERSIONS").read_text().splitlines():
        key = line.split("=", 1)[0]
        identity, _, kind = key.rpartition(".")
        if identity in actual and kind in ("acir_sha256", "vk_sha256"):
            line = key + "=" + actual[identity][0 if kind == "acir_sha256" else 1]
        lines.append(line)
    (ROOT / "VERSIONS").write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nargo", default=os.environ.get("NARGO", "nargo"))
    parser.add_argument("--bb", default=os.environ.get("BB", "bb"))
    # Local alternative to the bb CLI: zkpdf-prover's zkpdf-vk binary, linked against the same
    # pinned barretenberg revision. CI keeps the upstream CLI, so both paths must agree.
    parser.add_argument("--vk-tool", type=Path)
    # Writes the new hashes into VERSIONS and native/assets.json instead of requiring the frozen ones;
    # only for a deliberate toolchain upgrade.
    parser.add_argument("--repin", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "target/zkpdf-assets")
    parser.add_argument("--crs", type=Path)
    parser.add_argument("--download-crs", action="store_true")
    args = parser.parse_args()
    versions = pins()
    nargo_version = subprocess.check_output([args.nargo, "--version"], text=True)
    require(nargo_version.splitlines()[0] == "nargo version = " + versions["nargo"]
            and versions["noirc_commit"] in nargo_version, "nargo_version")
    if args.vk_tool is None:
        reported = subprocess.check_output([args.bb, "--version"], text=True).strip().removeprefix("v")
        require(reported == versions["bb"], "bb_version")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    crs = (args.crs or output).resolve()
    checked_crs(crs, args.download_crs)
    for name in CRS:
        if crs / name != output / name:
            shutil.copyfile(crs / name, output / name)
    environment = dict(os.environ, RAYON_NUM_THREADS="1", HARDWARE_CONCURRENCY="2")
    mappings = {}
    built = {}
    actual = {}
    for key, package in versions.items():
        if not key.startswith("zkpdf-v1-") or not key.endswith(".package"):
            continue
        identity = key.removesuffix(".package")
        flags = versions[identity + ".compile_flags"]
        expected = (versions[identity + ".acir_sha256"], versions[identity + ".vk_sha256"])
        if package in built:
            require(built[package][0] == flags and (args.repin or built[package][1] == expected), "shared_asset_pin")
            hashes = built[package][1]
        else:
            print(package + ": compile and check " + ("new" if args.repin else "frozen") + " hashes", flush=True)
            installed_acir = output / (package + ".json")
            installed_vk = output / (package + ".vk")
            if (not args.repin and installed_acir.is_file() and installed_vk.is_file()
                    and digest(installed_acir) == expected[0] and digest(installed_vk) == expected[1]):
                hashes = expected
            else:
                hashes = build(args, environment, crs, output, package, flags, expected)
            built[package] = (flags, hashes)
        actual[identity] = hashes
        mappings[identity] = {"acir": package + ".json", "vk": package + ".vk",
                              "acir_sha256": hashes[0], "vk_sha256": hashes[1]}
    require(len(mappings) == 14 and len(built) == 10, "composition_count")
    if args.repin:
        repin_versions(actual)
    (output / "manifest.json").write_text(json.dumps(mappings, indent=2) + "\n")
    catalog_path = ROOT.parent / "assets.json"
    catalog = json.loads(catalog_path.read_text())
    entries = [entry for entry in catalog if entry["backend"] == "NOIR_ULTRAHONK"]
    require(len(entries) == 22, "asset_catalog_count")
    for entry in entries:
        path = output / entry["id"]
        packaged = path.with_suffix(path.suffix + ".gz")
        if args.repin:
            packaged.write_bytes(package_gzip(path.read_bytes()))
            entry.update(gzipSha256=digest(packaged), gzipBytes=packaged.stat().st_size,
                         installedSha256=digest(path), installedBytes=path.stat().st_size)
            continue
        require(path.stat().st_size == entry["installedBytes"]
                and digest(path) == entry["installedSha256"], "catalog_installed_integrity")
        if not packaged.is_file() or digest(packaged) != entry["gzipSha256"]:
            packaged.write_bytes(package_gzip(path.read_bytes()))
        require(packaged.stat().st_size == entry["gzipBytes"]
                and digest(packaged) == entry["gzipSha256"], "catalog_gzip_integrity")
    if args.repin:
        catalog_path.write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n")
    print("Ten distinct circuits, fourteen composition mappings and CRS verified")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        # Tool failures must not dump compiler inputs or subprocess output.
        code = str(error) if isinstance(error, ValueError) else type(error).__name__
        print("zkpdf_asset_build_failed:" + code, file=sys.stderr)
        raise SystemExit(1) from None
