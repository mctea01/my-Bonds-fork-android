#!/usr/bin/env python3
"""Build Linux ARM64 BB callers and execute pinned public vectors under QEMU.

Uses the official static archive, original DIW bridge and existing C callers.
Emulation does not establish physical ARM64 or minimum CPU/OS support.
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

PINS = {
    "bb_source": "0219f11d8133970df3974fe5ae65e006bf8c193a",
    "msgpack_source": "c0334576ed657fb3b3c49e8e61402989fb84146d",
    "tracy_source": "5d542dc09f3d9378d005092a4ad446bd405f819a",
    "deflate_source": "96836d7d9d10e3e0d53e6edb54eb908514e336c4",
}
ARCHIVE_SHA256 = "332e6bde4d9c040e83035aafb4cd817fb8b1c2e28b19587ed46ff30cdc13d1a1"
CONSTANTS_SHA256 = "6367ab71dbdf5d3362289ed1cf3dd4517a94c9e8113f5fed10378aa49a730873"
BRIDGE_SHA256 = "645bdd6f584a0969318391b8d3cc71f6a320cdbc8854af39a9cd777808faf16b"
FIXTURE_SHA256 = "a7470d4c4e71a24da90cfed8ec026cae24d4c7adbbd6f905bfffecad5655067d"
DEFLATE_SOURCES = [
    "lib/arm/cpu_features.c", "lib/utils.c", "lib/x86/cpu_features.c",
    "lib/deflate_compress.c", "lib/deflate_decompress.c", "lib/adler32.c",
    "lib/zlib_compress.c", "lib/zlib_decompress.c", "lib/crc32.c",
    "lib/gzip_compress.c", "lib/gzip_decompress.c",
]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zig", type=Path, required=True)
    parser.add_argument("--bb-archive", type=Path, required=True)
    for name in PINS:
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--proof-fixture", type=Path, required=True)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--sysroot", type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    out = args.out.resolve()
    if out == repo or repo in out.parents:
        parser.error("Use an output directory outside the repository")
    if out.exists() and any(out.iterdir()):
        parser.error("Use a new empty output directory to preserve earlier evidence")
    for name in PINS:
        source = getattr(args, name).resolve(strict=True)
        if source == repo or repo in source.parents:
            parser.error("Use source checkouts outside the repository")
        if out == source or source in out.parents or out in source.parents:
            parser.error("Output and source directories must not overlap")
    out.mkdir(parents=True, exist_ok=True)
    zig = str(args.zig.resolve(strict=True))
    archive = args.bb_archive.resolve(strict=True)
    probe = Path(__file__).with_name("bb_windows_probe.c").resolve()
    hooks = probe.with_name("bb_windows_hooks.cpp")
    bridge = repo / "native/zkpdf-prover/cpp/bridge.cpp"
    constants = bridge.with_name("aztec_constants.hpp")
    report = {
        "project_revision": subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip(),
        "host": platform.platform(), "target": "aarch64-linux-gnu.2.35",
        "status": "not-tested", "physical_arm64_execution": "not-tested",
        "prover": "not-tested", "cross_architecture_proof_generation": "not-tested",
        "positive_proof": "not-tested", "bb_source_build": "not-tested",
        "scope": "official BB archive + source-built libdeflate + unmodified DIW bridge",
        "inputs": {}, "commands": [], "artifacts": {},
    }

    def run(command, label, *, timeout=300, env=None):
        start = time.monotonic()
        logfile = out / (label + ".log")
        record = {"argv": [str(a) for a in command], "log": logfile.name}
        report["commands"].append(record)
        with logfile.open("w") as log:
            try:
                process = subprocess.run(record["argv"], stdout=log, stderr=subprocess.STDOUT,
                                         env=env, timeout=timeout)
                record["exit_code"] = process.returncode
            except (OSError, subprocess.TimeoutExpired) as error:
                record["error"] = type(error).__name__
                raise
            finally:
                record["seconds"] = round(time.monotonic() - start, 3)
        if process.returncode:
            raise RuntimeError(f"{label} failed; see {logfile}")
        return logfile.read_text()

    try:
        qemu = args.qemu.resolve(strict=True)
        sysroot = args.sysroot.resolve(strict=True)
        for name, path in [("zig", Path(zig)), ("qemu", qemu),
                           ("target_libc", sysroot / "lib/libc.so.6"),
                           ("target_loader", sysroot / "lib/ld-linux-aarch64.so.1")]:
            report["inputs"][name] = {"path": str(path), "sha256": digest(path)}
        report["execution_environment"] = "QEMU user-mode on x86_64; target glibc sysroot"
        report["sysroot"] = str(sysroot)
        run([qemu, "--version"], "qemu-version")
        version = run([zig, "version"], "zig-version").strip()
        if version != "0.15.1":
            raise ValueError("Use Zig 0.15.1, matching the pinned upstream build image")
        for name, revision in PINS.items():
            path = getattr(args, name).resolve(strict=True)
            actual = run(["git", "-C", path, "rev-parse", "HEAD"], name + "-revision").strip()
            dirty = run(["git", "-C", path, "status", "--porcelain", "--untracked-files=normal"], name + "-status")
            if actual != revision or dirty.strip():
                raise ValueError(f"{name} must be a clean checkout at {revision}")
            report["inputs"][name] = {"path": str(path), "revision": actual}
        for name, path, expected in [("bb_archive", archive, ARCHIVE_SHA256), ("bridge", bridge, BRIDGE_SHA256),
                                     ("constants", constants, CONSTANTS_SHA256)]:
            actual = digest(path)
            if actual != expected:
                raise ValueError(f"{name} SHA-256 mismatch")
            report["inputs"][name] = {"path": str(path), "sha256": actual}
        for name, path in [("probe", probe), ("hooks", hooks), ("runner", Path(__file__).resolve())]:
            report["inputs"][name] = {"path": str(path), "sha256": digest(path)}
        if args.proof_fixture:
            fixture = args.proof_fixture.resolve(strict=True)
            if digest(fixture) != FIXTURE_SHA256:
                raise ValueError("proof fixture SHA-256 mismatch")
            data = json.loads(fixture.read_text())
            if data["bbVersion"] != "6.0.0" or data["circuit"] != "outer_count_4":
                raise ValueError("Unexpected proof fixture metadata")
            header = ["/* Generated from the hash-pinned public synthetic fixture. */"]
            encoded_fields = {}
            for key, name, count in [("vkeyFields", "vk", 115), ("proof", "proof", 458),
                                     ("publicInputs", "public", 9)]:
                values = data[key]
                if len(values) != count or any(not isinstance(v, str) or
                        not re.fullmatch(r"0x[0-9a-fA-F]{1,64}", v) for v in values):
                    raise ValueError("Unexpected fixture field encoding/count")
                raw = b"".join(int(v, 16).to_bytes(32, "big") for v in values)
                encoded_fields[key] = {"fields": count, "bytes": len(raw),
                                       "sha256": hashlib.sha256(raw).hexdigest()}
                header.append("static uint8_t fixture_" + name + "[] = {\n" +
                              ",\n".join(",".join(f"0x{b:02x}" for b in raw[i:i + 16])
                                          for i in range(0, len(raw), 16)) + "\n};")
            (out / "proof_fixture.h").write_text("\n".join(header) + "\n")
            proof_probe = probe.with_name("bb_windows_proof_probe.c")
            report["inputs"]["proof_fixture"] = {"path": str(fixture), "sha256": FIXTURE_SHA256,
                                                   "encoded_fields": encoded_fields}
            report["inputs"]["proof_probe"] = {"path": str(proof_probe), "sha256": digest(proof_probe)}
            report["negative_proof"] = "not-tested"
        report["status"] = "build-attempted"
        cc = [zig, "cc", "-target", "aarch64-linux-gnu.2.35", "-mcpu=baseline"]
        cxx = [zig, "c++", "-target", "aarch64-linux-gnu.2.35", "-mcpu=baseline"]
        objects = []
        for i, relative in enumerate(DEFLATE_SOURCES):
            obj = out / f"deflate-{i}.o"
            run(cc + ["-O2", "-DNDEBUG",
                      "-I", args.deflate_source.resolve(), "-c", args.deflate_source.resolve() / relative,
                      "-o", obj], f"deflate-{i}")
            objects.append(obj)
        deflate = out / "libdeflate.a"
        run([zig, "ar", "rcs", deflate, *objects], "deflate-archive")
        report["artifacts"][deflate.name] = {"sha256": digest(deflate), "status": "object-produced"}
        # A header overlay avoids changing the fixed upstream source checkout.
        include = out / "include/barretenberg/aztec"
        include.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(constants, include / constants.name)
        flags = ["-std=c++20", "-O2", "-DDISABLE_ASM=1", "-DDISABLE_AZTEC_VM=1",
                 "-DNO_PAR_ALGOS", "-DNDEBUG", "-DMSGPACK_NO_BOOST",
                 "-DMSGPACK_USE_STD_VARIANT_ADAPTOR", "-DZKPDF_WORKERS=2"]
        includes = ["-I", out / "include", "-I", args.bb_source.resolve() / "barretenberg/cpp/src",
                    "-I", args.msgpack_source.resolve() / "include", "-I", args.tracy_source.resolve() / "public"]
        bridge_obj = out / "diw_bridge.o"
        run(cxx + flags + includes + ["-c", bridge, "-o", bridge_obj], "bridge-compile")
        report["artifacts"][bridge_obj.name] = {"sha256": digest(bridge_obj), "status": "object-produced"}
        hooks_obj = out / "hooks.o"
        run(cxx + ["-std=c++20", "-O2", "-Wall", "-Wextra", "-Werror", "-c", hooks, "-o", hooks_obj], "hooks-compile")
        modes = ["bbapi", "diw-bridge"] + (["diw-proof"] if args.proof_fixture else [])
        for mode in modes:
            obj = out / (mode + ".o")
            defines = ["-DDIW_BRIDGE_TEST"] if mode == "diw-bridge" else []
            caller = proof_probe if mode == "diw-proof" else probe
            run(cc + ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", *defines,
                      "-I", out, "-c", caller, "-o", obj], mode + "-compile")
            exe = out / (mode + ".elf")
            # Lazy archive extraction preserves DIW-provided env hooks. Never whole-archive.
            inputs = [obj, hooks_obj, bridge_obj] if mode != "bbapi" else [obj]
            run(cxx + inputs + [archive, deflate, "-pthread", "-o", exe],
                mode + "-link", timeout=900)
            report["artifacts"][exe.name] = {"sha256": digest(exe), "bytes": exe.stat().st_size,
                                               "status": "linked"}
            header = run(["readelf", "-h", exe], mode + "-header")
            if not re.search(r"Machine:\s+AArch64", header):
                raise ValueError("Expected an AArch64 executable")
            run(["readelf", "-d", exe], mode + "-dynamic")
            run(["readelf", "--version-info", exe], mode + "-versions")
        report["status"] = "linked"
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("QEMU_") and key not in ("LD_LIBRARY_PATH", "LD_PRELOAD")}
        for cpu in ("max", "cortex-a53"):
            for mode in modes:
                stdout = run([qemu, "-cpu", cpu, "-L", sysroot, out / (mode + ".elf")],
                             mode + "-qemu-" + cpu, timeout=300, env=environment)
                markers = (["ultrahonk_public_fixture=passed", "changed_public_input=rejected",
                            "changed_proof_field=rejected", "truncated_proof_field=rejected",
                            "valid_after_rejections=passed"] if mode == "diw-proof" else
                           ["bbapi_blake2s_abc=passed", "allocation_free=passed", "malformed=passed"])
                if "DIW_SYNTHETIC_" in stdout or any(marker not in stdout for marker in markers):
                    raise RuntimeError("Probe result missing or diagnostic canary leaked")
                if mode == "diw-bridge" and "redaction=passed low_memory=off" not in stdout:
                    raise RuntimeError("DIW environment hook validation missing")
                report["artifacts"][mode + ".elf"]["status"] = "smoke-tested-under-qemu"
        report["positive_proof"] = "passed-under-qemu; pinned upstream synthetic fixture"
        report["negative_proof"] = "passed-under-qemu; changed public input, changed proof field, truncated field"
        report["qemu_cpu_models"] = ["max", "cortex-a53"]
        report["status"] = "smoke-tested-under-qemu"
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(report["status"] + ": positive_proof=" + report["positive_proof"] +
          "; physical ARM64 execution remains not-tested")


if __name__ == "__main__":
    main()
