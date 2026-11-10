#!/usr/bin/env python3
"""Build isolated Windows GNU BB callers from hash/revision-pinned inputs.

This never edits production sources. Wine execution, when requested, is a
compatibility-layer smoke test and does not establish native Windows support.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time

PINS = {
    "bb_source": "0219f11d8133970df3974fe5ae65e006bf8c193a",
    "msgpack_source": "c0334576ed657fb3b3c49e8e61402989fb84146d",
    "tracy_source": "5d542dc09f3d9378d005092a4ad446bd405f819a",
    "deflate_source": "96836d7d9d10e3e0d53e6edb54eb908514e336c4",
}
ARCHIVE_SHA256 = "f401bb3a644d5be1163d1df95a2968f33fa053d4e2c7b065f16f436cbb644699"
CONSTANTS_SHA256 = "6367ab71dbdf5d3362289ed1cf3dd4517a94c9e8113f5fed10378aa49a730873"
BRIDGE_SHA256 = "645bdd6f584a0969318391b8d3cc71f6a320cdbc8854af39a9cd777808faf16b"
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
    parser.add_argument("--wine", type=Path, help="Optional wine64 executable")
    parser.add_argument("--wineserver", type=Path, help="Optional server path for a portable Wine installation")
    parser.add_argument("--wine-prefix", type=Path, help="Optional prepared Wine prefix outside the repository")
    parser.add_argument("--wine-dll-path", type=Path, help="Optional portable Wine builtin DLL directory")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    out = args.out.resolve()
    if out == repo or repo in out.parents:
        parser.error("Use an output directory outside the repository")
    if out.exists() and any(out.iterdir()):
        parser.error("Use a new empty output directory to preserve earlier evidence")
    out.mkdir(parents=True, exist_ok=True)
    zig = str(args.zig.resolve(strict=True))
    archive = args.bb_archive.resolve(strict=True)
    probe = Path(__file__).with_name("bb_windows_probe.c").resolve()
    hooks = probe.with_name("bb_windows_hooks.cpp")
    bridge = repo / "native/zkpdf-prover/cpp/bridge.cpp"
    constants = bridge.with_name("aztec_constants.hpp")
    report = {
        "project_revision": subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip(),
        "host": platform.platform(), "target": "x86_64-windows-gnu",
        "status": "not-tested", "native_windows_execution": "not-tested",
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
        report["status"] = "build-attempted"
        cc = [zig, "cc", "-target", "x86_64-windows-gnu"]
        cxx = [zig, "c++", "-target", "x86_64-windows-gnu"]
        objects = []
        for i, relative in enumerate(DEFLATE_SOURCES):
            obj = out / f"deflate-{i}.o"
            run(cc + ["-O2", "-DNDEBUG", "-DLIBDEFLATE_ASSEMBLER_DOES_NOT_SUPPORT_SHA3",
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
        for mode in ["bbapi", "diw-bridge"]:
            obj = out / (mode + ".o")
            defines = ["-DDIW_BRIDGE_TEST"] if mode == "diw-bridge" else []
            run(cc + ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", *defines,
                      "-c", probe, "-o", obj], mode + "-compile")
            exe = out / (mode + ".exe")
            # Lazy archive extraction preserves DIW-provided env hooks. Never whole-archive.
            inputs = [obj, hooks_obj, bridge_obj] if mode == "diw-bridge" else [obj]
            run(cxx + inputs + [archive, deflate, "-lbcrypt", "-lws2_32", "-lpsapi",
                                "-o", exe],
                mode + "-link", timeout=900)
            report["artifacts"][exe.name] = {"sha256": digest(exe), "bytes": exe.stat().st_size,
                                               "status": "linked"}
            run(["objdump", "-f", exe], mode + "-format")
            # Save just DLL dependencies; full unwind tables are very large.
            command = ["objdump", "-p", str(exe)]
            metadata = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
            import_log = out / (mode + "-imports.log")
            import_lines = [line.strip() for line in metadata.stdout.splitlines() if "DLL Name:" in line]
            import_log.write_text("\n".join(import_lines) + "\n" if metadata.returncode == 0 else metadata.stdout)
            report["commands"].append({"argv": command, "exit_code": metadata.returncode,
                                       "log": import_log.name, "filter": "DLL Name lines only"})
            if metadata.returncode:
                raise RuntimeError("PE import inspection failed")
            report["artifacts"][exe.name]["dll_imports"] = [line.strip().split(":", 1)[1].strip()
                                                            for line in import_lines]
        report["status"] = "linked"
        if args.wine:
            wine = args.wine.resolve(strict=True)
            run([wine, "--version"], "wine-version")
            prefix = args.wine_prefix.resolve() if args.wine_prefix else out / "wine-prefix"
            if prefix == repo or repo in prefix.parents:
                raise ValueError("Wine prefix must be outside the repository")
            environment = dict(os.environ, WINEPREFIX=str(prefix), WINEARCH="win64", WINELOADER=str(wine),
                               WINEDEBUG="-all", WINEDLLOVERRIDES="mscoree,mshtml=d")
            if args.wineserver:
                environment["WINESERVER"] = str(args.wineserver.resolve(strict=True))
            if args.wine_dll_path:
                environment["WINEDLLPATH"] = str(args.wine_dll_path.resolve(strict=True))
            report["wine_environment"] = {key: environment[key] for key in
                                           ["WINEPREFIX", "WINEARCH", "WINEDEBUG", "WINEDLLOVERRIDES", "WINESERVER", "WINEDLLPATH", "WINELOADER"]
                                           if key in environment}
            for mode in ["bbapi", "diw-bridge"]:
                stdout = run([wine, out / (mode + ".exe")], mode + "-wine", timeout=180, env=environment)
                if "DIW_SYNTHETIC_" in stdout or "bbapi_blake2s_abc=passed" not in stdout:
                    raise RuntimeError("Probe result missing or diagnostic canary leaked")
                if mode == "diw-bridge" and "redaction=passed low_memory=off" not in stdout:
                    raise RuntimeError("DIW environment hook validation missing")
                report["artifacts"][mode + ".exe"]["status"] = "smoke-tested-under-wine"
            report["status"] = "smoke-tested"
            report["execution_environment"] = "Wine compatibility layer on Linux; not native Windows"
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(report["status"] + ": positive proof and native Windows execution remain not-tested")


if __name__ == "__main__":
    main()
