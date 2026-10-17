#!/usr/bin/env python3
"""Install pinned public OpenAC assets in the Bonds-compatible native layout."""
import argparse
import gzip
import hashlib
import json
import os
import shutil
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parent


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def install(destination):
    destination = destination.resolve()
    versions = json.loads((ROOT / "VERSIONS.json").read_text())
    for name, pin in versions["graphs"].items():
        target = destination / "graphs" / (name + ".graph")
        if target.exists() and target.stat().st_size == pin["bytes"] and digest(target) == pin["sha256"]:
            continue
        source = ROOT / "build/graphs" / (name + ".graph")
        if not source.exists() or source.stat().st_size != pin["bytes"] or digest(source) != pin["sha256"]:
            raise SystemExit("Run build-graphs.sh to prepare the verified graph assets")
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(".graph.part")
        temporary.unlink(missing_ok=True)
        try:
            try:
                os.link(source, temporary)
            except OSError:
                shutil.copyfile(source, temporary)
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
    manifest = json.loads((ROOT.parent / "assets.json").read_text())
    for asset in manifest:
        if asset["backend"] != "OPENAC_SPARTAN2":
            continue
        name = asset["id"]
        if name == "jwt_2k.r1cs":
            target = destination / "build/jwt/jwt_js/jwt.r1cs"
        elif name == "show.r1cs":
            target = destination / "build/show/show_js/show.r1cs"
        elif name.endswith(".graph"):
            target = destination / "graphs" / name
        else:
            target = destination / "keys" / name
        if target.exists() and target.stat().st_size == asset["installedBytes"] and digest(target) == asset["installedSha256"]:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        compressed = target.with_suffix(target.suffix + ".gz.part")
        expanded = target.with_suffix(target.suffix + ".part")
        try:
            urllib.request.urlretrieve(asset["urls"][0], compressed)
            if compressed.stat().st_size != asset["gzipBytes"] or digest(compressed) != asset["gzipSha256"]:
                raise RuntimeError("Compressed asset checksum mismatch")
            with gzip.open(compressed, "rb") as source, expanded.open("wb") as output:
                remaining = asset["installedBytes"]
                while block := source.read(min(1024 * 1024, remaining + 1)):
                    remaining -= len(block)
                    if remaining < 0:
                        raise RuntimeError("Expanded asset exceeds its pinned size")
                    output.write(block)
            if expanded.stat().st_size != asset["installedBytes"] or digest(expanded) != asset["installedSha256"]:
                raise RuntimeError("Installed asset checksum mismatch")
            expanded.replace(target)
            print(f"Verified public asset: {name}")
        finally:
            compressed.unlink(missing_ok=True)
            expanded.unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path, help="A directory named circom, matching the Bonds layout")
    args = parser.parse_args()
    if args.destination.name != "circom":
        raise SystemExit("The documents directory must be named circom")
    install(args.destination)
