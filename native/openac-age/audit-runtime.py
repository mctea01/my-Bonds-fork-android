#!/usr/bin/env python3
"""Audit normal dependencies for every shipped OpenAC target; no build tools."""
import json
import hashlib
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent
TARGETS = ("x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
           "aarch64-apple-darwin", "aarch64-linux-android", "x86_64-linux-android")


def main():
    output = ROOT / "build/licenses"
    output.mkdir(parents=True, exist_ok=True)
    for target in TARGETS:
        common = ["--manifest-path", str(ROOT.parent / "Cargo.toml"),
                  "--locked", "--features", "diw-zk-ffi/openac"]
        metadata = json.loads(subprocess.check_output(["cargo", "metadata", *common,
            "--format-version", "1", "--filter-platform", target]))
        packages = {package["id"]: package for package in metadata["packages"]}
        nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
        start = next(package["id"] for package in packages.values()
                     if package["name"] == "diw-zk-ffi")
        pending, visited = [start], set()
        while pending:
            node_id = pending.pop()
            if node_id in visited:
                continue
            visited.add(node_id)
            for dependency in nodes[node_id]["deps"]:
                if any(kind["kind"] is None for kind in dependency["dep_kinds"]):
                    pending.append(dependency["pkg"])
        report = []
        for node_id in sorted(visited):
            package = packages[node_id]
            license_id = package.get("license") or ""
            license_evidence = None
            if not license_id and package["name"] == "spartan2":
                revision = json.loads((ROOT / "VERSIONS.json").read_text())["spartan2"]
                license_path = package.get("license_file")
                if revision not in (package.get("source") or "") or not license_path:
                    raise SystemExit("Unpinned Spartan2 license source")
                evidence = (Path(package["manifest_path"]).parent / license_path).read_bytes()
                evidence = evidence.replace(b"\r\n", b"\n")
                if evidence != (ROOT / "licenses/Spartan2-MIT.txt").read_bytes().replace(b"\r\n", b"\n"):
                    raise SystemExit("Spartan2 license differs from the reviewed MIT copy")
                license_id = "MIT"
                license_evidence = hashlib.sha256(evidence).hexdigest()
            if not license_id or re.search(r"\b(?:A?GPL|LGPL)(?:-|\b)", license_id):
                raise SystemExit("Unapproved runtime license: " + package["name"])
            if package["name"] in ("witnesscalc-adapter", "gmp", "gmp-mpfr-sys",
                                    "compiler", "build-circuit"):
                raise SystemExit("Build-only component entered the runtime graph")
            item = {"name": package["name"], "version": package["version"], "license": license_id}
            if license_evidence:
                item["license_file_sha256"] = license_evidence
            report.append(item)
        (output / (target + ".json")).write_text(json.dumps(report, indent=2) + "\n")
        tree = subprocess.check_output(["cargo", "tree", *common, "-p", "diw-zk-ffi",
            "-e", "normal", "--target", target], text=True)
        (output / (target + ".txt")).write_text(tree)
        print(f"{target}: {len(visited)} normal packages; no GPL/LGPL/AGPL or legacy witness dependencies")


if __name__ == "__main__":
    main()
