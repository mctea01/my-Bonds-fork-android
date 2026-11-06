#!/usr/bin/env python3
"""Install the published zkPDF assets for tests; invoke with python3 -I.

Downloads every NOIR_ULTRAHONK entry of native/assets.json, checks the gzip and
the installed SHA-256 and size, and writes the flat layout that zkpdf_prove and
zkpdf_verify read (ZKPDF_ASSETS_DIR). Files already present with the right hash
are kept. Exits with 3 when the release is not published yet, so CI can skip the
zkPDF proof test with a warning instead of failing.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import sys
import urllib.error
import urllib.request

NATIVE = Path(__file__).resolve().parents[2]
NOT_PUBLISHED = 3


def digest(data):
    return hashlib.sha256(data).hexdigest()


def installed(path, entry):
    if not path.is_file() or path.stat().st_size != entry["installedBytes"]:
        return False
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest() == entry["installedSha256"]


def download(url, size):
    with urllib.request.urlopen(url, timeout=300) as response:
        data = response.read(size + 1)
    if len(data) != size:
        raise ValueError("gzip_size")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    catalog = json.loads((NATIVE / "assets.json").read_text(encoding="utf-8"))
    entries = [entry for entry in catalog if entry["backend"] == "NOIR_ULTRAHONK"]
    if len(entries) != 22:
        raise SystemExit("asset_catalog_count")
    for entry in entries:
        path = output / entry["id"]
        if installed(path, entry):
            continue
        if not entry["urls"]:
            print("zkPDF assets have no download address", file=sys.stderr)
            return NOT_PUBLISHED
        packed = None
        for url in entry["urls"]:
            try:
                packed = download(url, entry["gzipBytes"])
                break
            except urllib.error.HTTPError as error:
                if error.code != 404:
                    raise
        if packed is None:
            print("zkPDF assets are not published yet: " + entry["id"], file=sys.stderr)
            return NOT_PUBLISHED
        if digest(packed) != entry["gzipSha256"]:
            raise SystemExit("gzip_integrity:" + entry["id"])
        data = gzip.decompress(packed)
        if len(data) != entry["installedBytes"] or digest(data) != entry["installedSha256"]:
            raise SystemExit("installed_integrity:" + entry["id"])
        temporary = path.with_suffix(path.suffix + ".part")
        temporary.write_bytes(data)
        temporary.replace(path)
    print("Installed and checked " + str(len(entries)) + " zkPDF assets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
