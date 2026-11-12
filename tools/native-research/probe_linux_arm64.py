#!/usr/bin/env python3
"""Cross-build pinned Longfellow and DIW runtime, then call C ABIs under QEMU.

Requires an external clean Multipaz checkout, the experimental Longfellow lock,
Rust 1.99.1 with aarch64-unknown-linux-gnu, and an extracted Debian cross toolchain.
QEMU user emulation is not physical ARM64 acceptance or a performance benchmark.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import time

from probe_longfellow_windows import MULTIPAZ, LONGFELLOW, ASSETS, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["multipaz", "toolchain-root", "cargo", "cargo-home", "rustup-home", "out"]:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    repo = here.parents[1]
    out = args.out.resolve()
    source = args.multipaz.resolve(strict=True)
    for path in [out, source]:
        if path == repo or repo in path.parents:
            parser.error("Source checkout and output must be outside the repository")
    if out.exists() and any(out.iterdir()):
        parser.error("Use a new empty output directory")
    out.mkdir(parents=True, exist_ok=True)
    wrapper = source / "multipaz-longfellow/rust"
    upstream = wrapper / "longfellow-zk"
    mdoc = upstream / "rust/applications/mdoc_zk"
    toolchain = args.toolchain_root.resolve(strict=True)
    gcc = toolchain / "usr/bin/aarch64-linux-gnu-gcc-14"
    ar = toolchain / "usr/bin/aarch64-linux-gnu-ar"
    qemu = toolchain / "usr/bin/qemu-aarch64"
    sysroot = toolchain / "usr/aarch64-linux-gnu"
    host_lib = toolchain / "usr/lib/x86_64-linux-gnu"
    report = {"host": platform.platform(), "target": "aarch64-unknown-linux-gnu",
              "project_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip(),
              "status": "not-tested", "physical_arm64": "not-tested", "prover": "not-tested",
              "cross_architecture_proof_generation": "not-tested", "cpu_model": "QEMU max",
              "scope": "Unmodified Longfellow sources; experimental lock; DIW runtime-only; QEMU user emulation",
              "commands": [], "inputs": {}, "artifacts": {}}

    def run(command, label, *, cwd=wrapper, env=None, timeout=120):
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
        if result.returncode:
            raise RuntimeError(f"{label} failed; see {out / record['log']}")
        return (out / record["log"]).read_text()

    try:
        for name, path, revision in [("multipaz", source, MULTIPAZ), ("longfellow", upstream, LONGFELLOW)]:
            actual = run(["git", "rev-parse", "HEAD"], name + "-revision", cwd=path).strip()
            dirty = run(["git", "status", "--porcelain", "--untracked-files=all"], name + "-status", cwd=path)
            if actual != revision or dirty:
                raise ValueError(name + " must be clean at the pinned revision")
            report["inputs"][name] = {"path": str(path), "revision": revision}
        lock = here / "longfellow-windows.Cargo.lock"
        if digest(wrapper / "Cargo.lock") != digest(lock):
            raise ValueError("Use the existing experimental Longfellow Cargo.lock")
        for name, path in [("runner", Path(__file__).resolve()), ("pin_module", here / "probe_longfellow_windows.py"),
                           ("lock", lock), ("arm64_probe", here / "longfellow_arm64_probe.c"),
                           ("abi_probe", here / "longfellow_probe.c"), ("runtime_probe", here / "runtime_probe.c"),
                           ("diw_lock", repo / "native/Cargo.lock"), ("gcc", gcc), ("ar", ar), ("qemu", qemu)]:
            report["inputs"][name] = {"path": str(path), "sha256": digest(path)}
        for relative, expected in ASSETS.items():
            path = mdoc / relative
            if digest(path) != expected:
                raise ValueError("Public fixture SHA-256 mismatch: " + relative)
            report["inputs"][relative] = {"path": str(path), "sha256": expected}
        fixture = (mdoc / "testcases/src/vectors.rs").read_text().split(
            "pub static BIRTHDATE_1971_09_01_MDOC_3: TestDataStatic = TestDataStatic {", 1)[1].split("\n};", 1)[0]
        header = []
        for key in ["pkx", "pky", "now", "doc_type"]:
            header.append("static const char fixture_" + key + "[] = " +
                          json.dumps(re.search(key + r': "([^"]+)"', fixture)[1]) + ";")
        transcript = re.search(r"transcript: &\[(.*?)\]", fixture, re.S)[1]
        header.append("static const uint8_t fixture_transcript[] = {" +
                      ",".join(re.findall(r"0x[0-9a-fA-F]{2}", transcript)) + "};")
        (out / "longfellow_fixture.h").write_text("\n".join(header) + "\n")
        # GCC's Debian linker scripts contain /usr/aarch64-linux-gnu paths.
        # A local sysroot and host binutils library path make extraction relocatable.
        cc = out / "cross-cc"
        cc.write_text("#!/usr/bin/env python3\nimport os,sys\n" +
                      "os.environ['LD_LIBRARY_PATH']=" + repr(str(host_lib)) + "\n" +
                      "gcc=" + repr(str(gcc)) + "\n" +
                      "os.execv(gcc,[gcc," + repr("--sysroot=" + str(toolchain)) + ",*sys.argv[1:]])\n")
        cc.chmod(0o755)
        environment = dict(os.environ, CARGO_HOME=str(args.cargo_home.resolve()), RUSTUP_HOME=str(args.rustup_home.resolve()),
                           CARGO_TARGET_DIR=str(out / "target-longfellow"), CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0",
                           RUSTFLAGS="-C target-feature=+aes,+sha2", CC_aarch64_unknown_linux_gnu=str(cc),
                           AR_aarch64_unknown_linux_gnu=str(ar), CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=str(cc),
                           LD_LIBRARY_PATH=str(host_lib), PATH=str(gcc.parent) + os.pathsep + os.environ.get("PATH", ""))
        for key in ["CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"]:
            environment.pop(key, None)
        keys = ["CARGO_HOME", "RUSTUP_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "RUSTFLAGS",
                "CC_aarch64_unknown_linux_gnu", "AR_aarch64_unknown_linux_gnu", "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER", "LD_LIBRARY_PATH"]
        report["longfellow_build_environment"] = {k: environment[k] for k in keys}
        cargo = [args.cargo.absolute(), "+1.99.1"]
        run(cargo + ["--version"], "cargo-version", env=environment)
        run([cc, "--version"], "gcc-version", env=environment)
        run([ar, "--version"], "ar-version", env=environment)
        run([qemu, "--version"], "qemu-version")
        run([args.cargo.absolute().with_name("rustc"), "+1.99.1", "--print", "cfg", "--target", "aarch64-unknown-linux-gnu",
             "-C", "target-feature=+aes,+sha2"], "longfellow-target-cfg", env=environment)
        run(cargo + ["tree", "--locked", "--target", "aarch64-unknown-linux-gnu", "-e", "features", "-i", "sha2-asm"],
            "longfellow-asm-enabled", env=environment)
        report["status"] = "build-attempted"
        run(cargo + ["build", "--release", "--locked", "--target", "aarch64-unknown-linux-gnu"],
            "longfellow-build", env=environment, timeout=1200)
        shutil.copyfile(out / "target-longfellow/aarch64-unknown-linux-gnu/release/libzkp.so", out / "libzkp.so")
        runtime_env = dict(environment, CARGO_TARGET_DIR=str(out / "target-runtime"), RUSTFLAGS="")
        report["runtime_build_environment"] = {k: runtime_env[k] for k in keys}
        run(cargo + ["build", "--release", "--locked", "--target", "aarch64-unknown-linux-gnu", "-p", "diw-zk-ffi",
                     "--no-default-features"], "runtime-build", cwd=repo / "native", env=runtime_env, timeout=1200)
        shutil.copyfile(out / "target-runtime/aarch64-unknown-linux-gnu/release/libdiw_zk.so", out / "libdiw_zk.so")
        run([cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-I", out, here / "longfellow_arm64_probe.c",
             "-L" + str(out), "-Wl,-rpath,$ORIGIN", "-lzkp", "-o", out / "longfellow-probe"], "longfellow-c-link", env=environment)
        run([cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", here / "runtime_probe.c", "-ldl",
             "-o", out / "runtime-probe"], "runtime-c-link", env=environment)
        for name in ["libzkp.so", "libdiw_zk.so", "longfellow-probe", "runtime-probe"]:
            report["artifacts"][name] = {"sha256": digest(out / name), "bytes": (out / name).stat().st_size}
            run(["readelf", "-h", out / name], name + "-header")
            run(["readelf", "-d", out / name], name + "-dynamic")
            run(["readelf", "--version-info", out / name], name + "-versions")
        run(["nm", "-D", "--defined-only", out / "libzkp.so"], "longfellow-exports")
        report["status"] = "linked"
        # Do not pass host loader paths into the emulated process.
        execution_env = dict(os.environ)
        for key in ["LD_LIBRARY_PATH", "LD_PRELOAD", "QEMU_LD_PREFIX", "QEMU_SET_ENV", "QEMU_UNSET_ENV", "QEMU_CPU"]:
            execution_env.pop(key, None)
        execute = [qemu, "-cpu", "max", "-L", sysroot]
        runtime_output = run(execute + [out / "runtime-probe", out / "libdiw_zk.so"], "runtime-qemu", cwd=out, env=execution_env)
        if "contract=29 checksums=matched sha256_abc=passed native_info=read_and_freed" not in runtime_output:
            raise RuntimeError("Runtime result missing")
        paths = [mdoc / path for path in ASSETS if path.startswith("artifacts/")]
        proof_output = run(execute + [out / "longfellow-probe", *paths], "longfellow-qemu", cwd=out, env=execution_env, timeout=900)
        if "valid_after_rejections=passed" not in proof_output or "aarch64_aes_pmull_sha2_hwcap=present" not in proof_output:
            raise RuntimeError("ARM64 proof result missing")
        if digest(wrapper / "Cargo.lock") != digest(lock) or digest(repo / "native/Cargo.lock") != report["inputs"]["diw_lock"]["sha256"]:
            raise ValueError("Build changed a lockfile")
        report["status"] = "smoke-tested-under-qemu"
        report["runtime"] = "C dlopen, UniFFI handshake, SHA-256 abc, native_info/free passed"
        report["longfellow"] = "LP64, crypto HWCAP, circuit allocation/free, public proof accepted, attribute/transcript/proof changes rejected, original accepted again"
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(report["status"] + ": physical ARM64, prover, and bidirectional proof generation remain not-tested")


if __name__ == "__main__":
    main()
