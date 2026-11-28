#!/usr/bin/env python3
"""Lists the Rust crates linked into one native library, with their license files, for the app's third-party list.

native/build.sh runs it after each library it builds and writes the result next to the library as
<library>.third-party.json. The app build (app/third-party.gradle.kts) merges these files into the About page's list,
so the list names exactly the crates of the libraries that are packaged. Proc-macro and build-only crates are left out:
they run while compiling and are not part of the library. The project's own crates (native/<crate>) are left out too.

Usage: third_party.py --package diw-zk-ffi [--features a,b] --target <rust triple> [--runtime x,y] --out <file>
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

NATIVE = Path(__file__).resolve().parent
LICENSE_FILE = re.compile(r"^(licen[cs]e|copying|notice|copyright|unlicense)([-_.].*)?$", re.I)
MAX_FILE = 256 * 1024


def run(args):
    return subprocess.run(args, cwd=NATIVE, check=True, capture_output=True, text=True, encoding="utf-8").stdout


def license_files(crate_dir: Path):
    """License files of the crate, or of its repository root for crates in a git checkout or a vendored tree."""
    parts = crate_dir.parts
    if "checkouts" in parts and parts.index("checkouts") + 2 < len(parts):
        root = Path(*parts[: parts.index("checkouts") + 3])
    elif crate_dir.is_relative_to(NATIVE / "vendor") and crate_dir != NATIVE / "vendor":
        root = NATIVE / "vendor" / crate_dir.relative_to(NATIVE / "vendor").parts[0]
    elif crate_dir.is_relative_to(NATIVE / "openac-age" / "vendor"):
        root = NATIVE / "openac-age" / "vendor" / crate_dir.relative_to(NATIVE / "openac-age" / "vendor").parts[0]
    else:
        root = crate_dir
    d = crate_dir
    while True:
        found = sorted(f for f in d.iterdir() if f.is_file() and LICENSE_FILE.match(f.name) and f.stat().st_size <= MAX_FILE)
        if found or d == root or root not in d.parents:
            return found
        d = d.parent


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--package", required=True)
    p.add_argument("--features", default="")
    p.add_argument("--target", required=True)
    p.add_argument("--runtime", default="", help="comma list of linked runtimes (see third-party/components.json)")
    p.add_argument("--library", default="")
    p.add_argument("--out", required=True)
    a = p.parse_args()
    target = re.sub(r"\.\d+\.\d+$", "", a.target)  # zigbuild's <triple>.<glibc>
    tree = ["cargo", "tree", "-q", "--locked", "-p", a.package, "-e", "normal,no-proc-macro", "--target", target,
            "--prefix", "none", "-f", "{p}"]
    if a.features:
        tree += ["--features", a.features]
    wanted = set()
    for line in run(tree).splitlines():
        m = re.match(r"^(\S+) v(\S+)", line.strip())
        if m:
            wanted.add((m.group(1), m.group(2)))
    meta = json.loads(run(["cargo", "metadata", "--format-version", "1", "--locked", "--all-features", "--filter-platform", target]))
    texts, crates = {}, []
    for pkg in meta["packages"]:
        if (pkg["name"], pkg["version"]) not in wanted:
            continue
        wanted.discard((pkg["name"], pkg["version"]))
        crate_dir = Path(pkg["manifest_path"]).parent
        if crate_dir.parent == NATIVE:
            continue  # this project's own crates
        files = []
        for f in license_files(crate_dir):
            body = f.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").strip() + "\n"
            key = "h:" + hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]
            texts[key] = body
            files.append({"name": f.name, "text": key})
        source = pkg.get("source") or ""
        crates.append({
            "name": pkg["name"],
            "version": pkg["version"],
            "license": (pkg.get("license") or "").strip(),
            "url": pkg.get("repository") or pkg.get("homepage") or ("https://crates.io/crates/" + pkg["name"] if source.startswith("registry+") else ""),
            "source": "git" if source.startswith("git+") else "path" if not source else "crates.io",
            "files": files,
        })
    if wanted:
        sys.exit("third_party.py: not in cargo metadata: " + ", ".join(sorted(f"{n} {v}" for n, v in wanted)))
    crates.sort(key=lambda c: (c["name"], c["version"]))
    out = {
        "format": 1,
        "library": a.library,
        "package": a.package,
        "target": target,
        "features": [f for f in a.features.split(",") if f],
        "runtime": [r for r in a.runtime.split(",") if r],
        "crates": crates,
        "texts": dict(sorted(texts.items())),
    }
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"third_party library={a.library or a.package} target={target} crates={len(crates)} texts={len(texts)}")


if __name__ == "__main__":
    main()
