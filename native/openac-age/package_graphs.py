#!/usr/bin/env python3
"""Verify graph bytes and create reproducible, separately distributed archives."""
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main():
    versions = json.loads((ROOT / "VERSIONS.json").read_text())
    packaged = []
    for name, pin in versions["graphs"].items():
        path = ROOT / "build/graphs" / (name + ".graph")
        data = path.read_bytes()
        if len(data) != pin["bytes"] or hashlib.sha256(data).hexdigest() != pin["sha256"]:
            raise SystemExit("Graph does not match the pinned circuit")
        archive = gzip.compress(data, compresslevel=9, mtime=0)
        path.with_suffix(".graph.gz").write_bytes(archive)
        packaged.append({"id": name + ".graph", "backend": "OPENAC_SPARTAN2", "role": ["prover"],
            "urls": ["https://github.com/mctea01/my-Bonds-fork-android/releases/download/openac-age-graph-v1/" + name + ".graph.gz"],
            "gzipSha256": hashlib.sha256(archive).hexdigest(), "gzipBytes": len(archive),
            "installedSha256": pin["sha256"], "installedBytes": pin["bytes"],
            "license": "MIT (zkID) AND GPL-3.0-or-later (circomlib 2.0.5)"})
    (ROOT / "build/graphs/assets.fragment.json").write_text(json.dumps(packaged, indent=2) + "\n")
    print("Verified graph assets and deterministic gzip archives; no Release was created")


if __name__ == "__main__":
    main()
