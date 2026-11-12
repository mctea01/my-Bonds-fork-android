#!/usr/bin/env python3
"""Compare baseline and embedded Longfellow DLLs with their source checkout hidden.

Only use a dedicated external research checkout: it is temporarily renamed and
restored in finally. No build may run against that checkout during this probe.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["build-dir", "baseline-dir", "out"]:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    repo = here.parents[1]
    build = args.build_dir.resolve(strict=True)
    baseline = args.baseline_dir.resolve(strict=True)
    out = args.out.resolve()
    for path in [build, baseline, out]:
        if path == repo or repo in path.parents:
            parser.error("Build, baseline, and output must be outside the repository")
    if out.exists() and any(out.iterdir()):
        parser.error("Use a new empty output directory")
    report = {"status": "not-tested", "native_windows_execution": "not-tested",
              "prover": "not-tested", "commands": [], "inputs": {}, "source_restored": False}
    out.mkdir(parents=True, exist_ok=True)
    source = None
    hidden = None
    renamed = False

    def run(command, label, cwd, env=None, timeout=300):
        record = {"argv": [str(x) for x in command], "cwd": str(cwd), "log": label + ".log"}
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
        return result.returncode, (out / record["log"]).read_text()

    try:
        built = json.loads((build / "result.json").read_text())
        original = json.loads((baseline / "result.json").read_text())
        for metadata in [original, built]:
            if (metadata["target"] != "x86_64-pc-windows-gnu" or
                    metadata["inputs"]["multipaz"]["revision"] != "a015c9d93874fe6e09df1354006353ce6f94751d" or
                    metadata["inputs"]["longfellow"]["revision"] != "d5e6be77336933d50bf7f25a954f8ec273eb51ce"):
                raise ValueError("Unexpected build target or source revisions")
        if "asset_patch" in original["inputs"] or original["status"] not in ["linked", "smoke-tested-under-wine"]:
            raise ValueError("Baseline must be a successful build without embedded assets")
        for key in ["patch", "lock", "probe", "abi_probe"]:
            if original["inputs"][key]["sha256"] != built["inputs"][key]["sha256"]:
                raise ValueError("Baseline and embedded build inputs differ: " + key)
        report["inputs"]["baseline_build_report"] = {"sha256": digest(baseline / "result.json")}
        report["inputs"]["embedded_build_report"] = {"sha256": digest(build / "result.json")}
        for key in ["asset_patch", "asset_catalog", "runner", "probe", "abi_probe", "lock", "patch"]:
            item = built["inputs"][key]
            if digest(Path(item["path"])) != item["sha256"]:
                raise ValueError("Build input has changed: " + key)
        if built["status"] not in ["linked", "smoke-tested-under-wine"]:
            raise ValueError("Embedded build has not linked successfully")
        source = Path(built["inputs"]["multipaz"]["path"]).resolve(strict=True)
        if source == repo or repo in source.parents or source in repo.parents:
            raise ValueError("Source must be a dedicated external research checkout")
        if Path(original["inputs"]["multipaz"]["path"]) != source:
            raise ValueError("This control expects both builds to refer to the same source path")
        hidden = source.with_name(source.name + ".relocation-hidden")
        if hidden.exists():
            raise ValueError("Hidden-source path already exists; restore/inspect it first")
        for path in [build, baseline, out, Path(built["wine_environment"]["WINEPREFIX"])]:
            if path == source or source in path.parents:
                raise ValueError("Probe files and Wine prefix must be outside the source checkout")
        upstream = source / "multipaz-longfellow/rust/longfellow-zk"
        actual = subprocess.check_output(["git", "diff", "--no-ext-diff", "--unified=0", "HEAD"], cwd=upstream, text=True)
        expected = (here / "longfellow-embedded-assets.patch").read_text() + (here / "longfellow-windows-sha2.patch").read_text()
        if actual != expected:
            raise ValueError("Source differs from the two research patches")
        for label, root, metadata in [("baseline", baseline, original), ("embedded", build, built)]:
            dll = root / "zkp.dll"
            if digest(dll) != metadata["artifacts"]["zkp.dll"]["sha256"]:
                raise ValueError(label + " DLL SHA-256 mismatch")
            report["inputs"][label + "_dll"] = {"sha256": digest(dll), "bytes": dll.stat().st_size}
        if digest(build / "probe.exe") != built["artifacts"]["probe.exe"]["sha256"]:
            raise ValueError("C proof caller SHA-256 mismatch")
        report["inputs"]["proof_caller"] = {"sha256": digest(build / "probe.exe")}
        report["inputs"]["runner"] = {"sha256": digest(Path(__file__).resolve())}
        report["inputs"]["assets_probe"] = {"sha256": digest(here / "longfellow_assets_probe.c")}
        reference = out / "reference"
        reference.mkdir()
        catalog = json.loads((here / "longfellow-embedded-assets.json").read_text())
        for asset in catalog["assets"]:
            path = upstream / asset["path"]
            if digest(path) != asset["sha256"]:
                raise ValueError("Reference circuit SHA-256 mismatch")
            shutil.copyfile(path, reference / path.name)
        report["inputs"]["asset_catalog"] = {"sha256": digest(here / "longfellow-embedded-assets.json")}
        proof_input = next(v for k, v in built["inputs"].items() if k.startswith("artifacts/proofs/"))
        if digest(Path(proof_input["path"])) != proof_input["sha256"]:
            raise ValueError("Reference proof SHA-256 mismatch")
        shutil.copyfile(proof_input["path"], reference / "proof.bin")
        report["inputs"]["proof"] = {"sha256": proof_input["sha256"]}
        for name, root in [("control", baseline), ("relocated", build)]:
            directory = out / name
            directory.mkdir()
            shutil.copyfile(root / "zkp.dll", directory / "zkp.dll")
            shutil.copyfile(build / "probe.exe", directory / "probe.exe")
        gcc = built["build_environment"]["CC_x86_64_pc_windows_gnu"]
        code, _ = run([gcc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                       here / "longfellow_assets_probe.c",
                       build / "target/x86_64-pc-windows-gnu/release/libzkp.dll.a",
                       "-o", out / "relocated/assets.exe"], "assets-c-link", out)
        if code:
            raise RuntimeError("Asset caller build failed")
        report["inputs"]["assets_exe"] = {"sha256": digest(out / "relocated/assets.exe")}
        environment = dict(os.environ, **built["wine_environment"])
        environment["WINEDLLOVERRIDES"] = "mscoree,mshtml,winedbg=d"
        report["wine_environment"] = {key: environment[key] for key in built["wine_environment"]}
        wine = environment["WINELOADER"]
        circuit_name = Path(built["inputs"][next(k for k in built["inputs"] if k.startswith("artifacts/circuits/"))]["path"]).name

        def windows(path):
            return "Z:" + str(path).replace("/", "\\")

        proof_args = [windows(reference / circuit_name), windows(reference / "proof.bin")]
        source.rename(hidden)
        renamed = True
        report["source_path"] = str(source)
        report["hidden_source_path"] = str(hidden)
        report["source_absent_during_tests"] = not source.exists()
        if source.exists():
            raise RuntimeError("Original source path remains accessible")
        code, output = run([wine, out / "control/probe.exe", *proof_args], "baseline-missing-source",
                           out / "control", environment, timeout=60)
        if code == 0 or "Failed to read lfa2 archive file" not in output:
            raise RuntimeError("Baseline did not reproduce the expected source-path failure")
        report["baseline_control"] = "expected nonzero exit with missing source archive panic"
        code, output = run([wine, out / "relocated/assets.exe", windows(reference)], "all-assets-relocated",
                           out / "relocated", environment)
        if code or "all_12_prior_circuits=passed" not in output:
            raise RuntimeError("Relocated circuit comparison failed")
        code, output = run([wine, out / "relocated/probe.exe", *proof_args], "proof-relocated",
                           out / "relocated", environment)
        if code or "valid_after_rejections=passed" not in output:
            raise RuntimeError("Relocated proof suite failed")
        report["status"] = "relocation-smoke-tested-under-wine"
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        if renamed:
            hidden.rename(source)
            report["source_restored"] = source.exists() and not hidden.exists()
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(report["status"] + ": source restored; native Windows and prover remain not-tested")


if __name__ == "__main__":
    main()
