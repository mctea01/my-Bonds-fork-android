#!/usr/bin/env python3
"""Build a pinned, research-patched Longfellow DLL and optionally test under Wine.

Prepare an external checkout, apply the supplied six-manifest SHA-2 patch, and
copy the supplied experimental Cargo.lock first. No production files are edited.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import time

MULTIPAZ = "a015c9d93874fe6e09df1354006353ce6f94751d"
LONGFELLOW = "d5e6be77336933d50bf7f25a954f8ec273eb51ce"
SPEC_HASH = "8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121"
ASSETS = {
    "testcases/src/vectors.rs": "c540b0a1c1eaf948a5dc7a82a3fb66cb19ae072d6ad4f801da64041f21323817",
    "artifacts/circuits/" + SPEC_HASH + ".lfa2": "94c665e8a4067f5cd10153c96164afcecfbb1a41afa513f4a8c99ae01723a2f0",
    "artifacts/proofs/" + SPEC_HASH + ".bin": "3cb762b110ddc5b309f3b067ff3e891381a479f291dd4903e8c19c5d987bbe91",
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["multipaz", "cargo", "cargo-home", "rustup-home", "gcc", "out"]:
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ["wine", "wineserver", "wine-prefix", "wine-dll-path"]:
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--embed-assets", action="store_true", help="Also require the isolated LFA2 embedding patch")
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    repo = here.parents[1]
    out = args.out.resolve()
    source = args.multipaz.resolve(strict=True)
    for path in [out, source]:
        if path == repo or repo in path.parents:
            parser.error("Source and output must be outside the repository")
    if out.exists() and any(out.iterdir()):
        parser.error("Use a new empty output directory")
    if args.wine_prefix and (args.wine_prefix.resolve() == repo or repo in args.wine_prefix.resolve().parents):
        parser.error("Wine prefix must be outside the repository")
    out.mkdir(parents=True, exist_ok=True)
    wrapper = source / "multipaz-longfellow/rust"
    upstream = wrapper / "longfellow-zk"
    mdoc = upstream / "rust/applications/mdoc_zk"
    gcc = args.gcc.resolve(strict=True)
    ar = gcc.parent / "x86_64-w64-mingw32-ar"
    report = {"host": platform.platform(), "target": "x86_64-pc-windows-gnu",
              "status": "not-tested", "proof_verification": "not-tested",
              "native_windows_execution": "not-tested", "prover": "not-tested",
              "scope": "Research-only six-manifest patch; DLL C ABI and public v7/1 fixture",
              "commands": [], "inputs": {}, "artifacts": {}}

    def run(command, label, *, cwd=wrapper, env=None, timeout=120):
        record = {"argv": [str(a) for a in command], "cwd": str(cwd), "log": label + ".log"}
        report["commands"].append(record)
        start = time.monotonic()
        with (out / record["log"]).open("w") as log:
            try:
                result = subprocess.run(record["argv"], cwd=cwd, env=env, stdout=log,
                                        stderr=subprocess.STDOUT, timeout=timeout)
                record["exit_code"] = result.returncode
            except (OSError, subprocess.TimeoutExpired) as error:
                record["error"] = type(error).__name__
                raise
            finally:
                record["seconds"] = round(time.monotonic() - start, 3)
        if result.returncode:
            raise RuntimeError(f"{label} failed; see {out / record['log']}")
        return (out / record["log"]).read_text()

    try:
        for name, path, revision in [("multipaz", source, MULTIPAZ), ("longfellow", upstream, LONGFELLOW)]:
            actual = run(["git", "rev-parse", "HEAD"], name + "-revision", cwd=path).strip()
            if actual != revision:
                raise ValueError(name + " revision mismatch")
            if run(["git", "ls-files", "--others", "--exclude-standard"], name + "-untracked", cwd=path).strip():
                raise ValueError(name + " has unexpected untracked files")
            report["inputs"][name] = {"path": str(path), "revision": revision}
        status = run(["git", "status", "--porcelain"], "multipaz-status", cwd=source)
        if status != " M multipaz-longfellow/rust/longfellow-zk\n":
            raise ValueError("Multipaz must differ only in its research-patched submodule")
        patch = here / "longfellow-windows-sha2.patch"
        actual_patch = run(["git", "diff", "--no-ext-diff", "--unified=0", "HEAD"], "longfellow-patch", cwd=upstream)
        expected_patch = patch.read_text()
        if args.embed_assets:
            asset_patch = here / "longfellow-embedded-assets.patch"
            # Git emits paths in sorted order; artifacts precedes the six manifests.
            expected_patch = asset_patch.read_text() + expected_patch
            report["inputs"]["asset_patch"] = {"path": str(asset_patch), "sha256": digest(asset_patch)}
            catalog_path = here / "longfellow-embedded-assets.json"
            catalog = json.loads(catalog_path.read_text())
            if catalog["longfellow_revision"] != LONGFELLOW or len(catalog["assets"]) != 12:
                raise ValueError("Unexpected embedded asset catalog")
            for asset in catalog["assets"]:
                path = upstream / asset["path"]
                if digest(path) != asset["sha256"] or path.stat().st_size != asset["bytes"]:
                    raise ValueError("Embedded asset SHA-256 mismatch")
            report["inputs"]["asset_catalog"] = {"path": str(catalog_path), "sha256": digest(catalog_path)}
            report["scope"] += "; 12 unchanged prior-version LFA2 archives embedded"
        if actual_patch != expected_patch:
            raise ValueError("Longfellow must have exactly the supplied research patch")
        lock = here / "longfellow-windows.Cargo.lock"
        if digest(wrapper / "Cargo.lock") != digest(lock):
            raise ValueError("Use the supplied experimental Cargo.lock")
        for name, path in [("patch", patch), ("lock", lock), ("runner", Path(__file__).resolve()),
                           ("probe", here / "longfellow_windows_probe.c"), ("abi_probe", here / "longfellow_probe.c")]:
            report["inputs"][name] = {"path": str(path), "sha256": digest(path)}
        for relative, expected in ASSETS.items():
            path = mdoc / relative
            if digest(path) != expected:
                raise ValueError("Fixture SHA-256 mismatch: " + relative)
            report["inputs"][relative] = {"path": str(path), "sha256": expected}
        # Only public verifier metadata is extracted; no mdoc body is logged/copied.
        vectors = (mdoc / "testcases/src/vectors.rs").read_text()
        fixture = vectors.split("pub static BIRTHDATE_1971_09_01_MDOC_3: TestDataStatic = TestDataStatic {", 1)[1].split("\n};", 1)[0]
        header = []
        for key in ["pkx", "pky", "now", "doc_type"]:
            value = re.search(key + r': "([^"]+)"', fixture)[1]
            header.append("static const char fixture_" + key + "[] = " + json.dumps(value) + ";")
        transcript = re.search(r"transcript: &\[(.*?)\]", fixture, re.S)[1]
        header.append("static const uint8_t fixture_transcript[] = {" +
                      ",".join(re.findall(r"0x[0-9a-fA-F]{2}", transcript)) + "};")
        (out / "longfellow_fixture.h").write_text("\n".join(header) + "\n")
        environment = dict(os.environ, CARGO_HOME=str(args.cargo_home.resolve()),
                           RUSTUP_HOME=str(args.rustup_home.resolve()), CARGO_TARGET_DIR=str(out / "target"),
                           CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0", RUSTFLAGS="",
                           CC_x86_64_pc_windows_gnu=str(gcc), AR_x86_64_pc_windows_gnu=str(ar),
                           CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=str(gcc),
                           PATH=str(gcc.parent) + os.pathsep + os.environ.get("PATH", ""))
        for key in ["CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"]:
            environment.pop(key, None)
        report["build_environment"] = {key: environment[key] for key in ["CARGO_HOME", "RUSTUP_HOME",
            "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "RUSTFLAGS", "CC_x86_64_pc_windows_gnu",
            "AR_x86_64_pc_windows_gnu", "CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER"]}
        # Preserve argv[0] for the cargo -> rustup multicall symlink.
        cargo = [args.cargo.absolute(), "+1.99.1"]
        run(cargo + ["--version"], "cargo-version", env=environment)
        run([gcc, "--version"], "gcc-version")
        run([ar, "--version"], "ar-version")
        tree = run(cargo + ["tree", "--locked", "--target", "x86_64-pc-windows-gnu", "-e", "features"], "windows-features", env=environment)
        if "sha2-asm" in tree or 'sha2 feature "asm"' in tree:
            raise ValueError("Windows dependency graph still enables SHA-2 assembly")
        run(cargo + ["tree", "--locked", "--target", "x86_64-unknown-linux-gnu", "-e", "features", "-i", "sha2-asm"], "linux-asm-preserved", env=environment)
        report["status"] = "build-attempted"
        run(cargo + ["build", "--release", "--locked", "--target", "x86_64-pc-windows-gnu"], "build", env=environment, timeout=1200)
        lib = out / "target/x86_64-pc-windows-gnu/release"
        for name in ["zkp.dll", "libzkp.dll.a", "libzkp.a"]:
            report["artifacts"][name] = {"sha256": digest(lib / name), "bytes": (lib / name).stat().st_size}
        shutil.copyfile(lib / "zkp.dll", out / "zkp.dll")
        run([gcc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-I", out,
             here / "longfellow_windows_probe.c", lib / "libzkp.dll.a", "-o", out / "probe.exe"], "c-link")
        report["artifacts"]["probe.exe"] = {"sha256": digest(out / "probe.exe")}
        for name in ["zkp.dll", "probe.exe"]:
            run(["objdump", "-f", out / name], name + "-format")
            command = ["objdump", "-p", str(out / name)]
            metadata = subprocess.run(command, capture_output=True, text=True, timeout=60)
            log_name = name + "-imports-exports.log"
            report["commands"].append({"argv": command, "log": log_name,
                "exit_code": metadata.returncode, "filter": "Before The Function Table; omit unwind tables"})
            # Omit large unwind tables, retaining import/export metadata.
            (out / log_name).write_text(metadata.stdout.split("The Function Table")[0] + metadata.stderr)
            if metadata.returncode:
                raise RuntimeError("PE metadata inspection failed")
            report["artifacts"][name]["dll_imports"] = re.findall(r"DLL Name: (\S+)", metadata.stdout)
        report["status"] = "linked"
        if args.wine:
            wine = args.wine.resolve(strict=True)
            wine_env = dict(os.environ, WINEPREFIX=str(args.wine_prefix.resolve() if args.wine_prefix else out / "wine-prefix"),
                            WINEARCH="win64", WINELOADER=str(wine), WINEDEBUG="-all", WINEDLLOVERRIDES="mscoree,mshtml=d")
            if args.wineserver:
                wine_env["WINESERVER"] = str(args.wineserver.resolve(strict=True))
            if args.wine_dll_path:
                wine_env["WINEDLLPATH"] = str(args.wine_dll_path.resolve(strict=True))
            report["wine_environment"] = {k: v for k, v in wine_env.items() if k.startswith("WINE")}
            run([wine, "--version"], "wine-version", env=wine_env)
            paths = [mdoc / "artifacts/circuits" / (SPEC_HASH + ".lfa2"), mdoc / "artifacts/proofs" / (SPEC_HASH + ".bin")]
            # Wine's standard Z: mapping points at the Linux filesystem root.
            stdout = run([wine, out / "probe.exe", *["Z:" + str(p).replace("/", "\\") for p in paths]],
                         "wine-probe", cwd=out, env=wine_env, timeout=300)
            if "valid_after_rejections=passed" not in stdout:
                raise RuntimeError("Proof result missing")
            report["status"] = "smoke-tested-under-wine"
            report["proof_verification"] = "public v7/1 proof accepted; attribute/transcript/proof changes rejected; restored proof accepted"
        if digest(wrapper / "Cargo.lock") != digest(lock):
            raise ValueError("Build changed experimental lockfile")
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(report["status"] + ": native Windows, MSVC, and prover remain not-tested")


if __name__ == "__main__":
    main()
