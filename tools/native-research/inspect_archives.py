#!/usr/bin/env python3
"""List and hash native/WASM entries in explicit local JAR/AAR/ZIP inputs."""
import argparse
import csv
import hashlib
from pathlib import Path
import sys
import zipfile


def inspect(path):
    with path.open("rb") as source:
        archive_hash = hashlib.file_digest(source, "sha256").hexdigest()
    with zipfile.ZipFile(path) as archive:
        for entry in sorted(archive.infolist(), key=lambda item: item.filename):
            name = entry.filename.lower()
            if entry.is_dir() or not (name.endswith((".so", ".dll", ".dylib", ".jnilib", ".a", ".lib", ".wasm")) or ".so." in name):
                continue
            with archive.open(entry) as source:
                digest = hashlib.file_digest(source, "sha256").hexdigest()
            yield {
                "archive": path.name, "archive_sha256": archive_hash,
                "entry": entry.filename, "bytes": entry.file_size,
                "entry_sha256": digest,
                "kind": "wasm-host-contract-review" if name.endswith(".wasm") else "native-binary",
                "status": "archive-observed;not-loaded",
            }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", nargs="+", type=Path)
    args = parser.parse_args()
    writer = csv.DictWriter(sys.stdout, fieldnames=["archive", "archive_sha256", "entry", "bytes", "entry_sha256", "kind", "status"], lineterminator="\n")
    writer.writeheader()
    for path in args.archives:
        writer.writerows(inspect(path))


if __name__ == "__main__":
    main()
