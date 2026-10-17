#!/usr/bin/env python3
"""Build only the two pinned witness calculators, with static portable libraries."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
CACHE = ROOT / ".cache"


def run(*args, cwd=None, env=None):
    subprocess.run([str(arg) for arg in args], cwd=cwd, env=env, check=True)


def write_changed(path, contents):
    if not path.exists() or path.read_text() != contents:
        path.write_text(contents)


def main():
    target, output, circuits = sys.argv[1:]
    output = Path(output)
    circuits = Path(circuits)
    source = CACHE / "witnesscalc"
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    if revision != "707dc54877ad3226042d959d7ec956ae540a9a3e":
        raise SystemExit("Unpinned witnesscalc revision")
    if not (source / "depends/json/single_include/nlohmann/json.hpp").is_file():
        raise SystemExit("Run prepare.py before cargo build")
    work = output / "witnesscalc"
    work.mkdir(exist_ok=True)
    for folder in ("src", "build"):
        ignore = shutil.ignore_patterns("calcwit.cpp", "witnesscalc.cpp") if folder == "src" else None
        shutil.copytree(source / folder, work / folder, dirs_exist_ok=True, ignore=ignore)
    env = os.environ.copy()
    env.setdefault("CC_FOR_BUILD", "cc")
    cmake = ["-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_POSITION_INDEPENDENT_CODE=ON"]
    configure = ["--disable-shared", "--enable-static", "--with-pic", "--disable-assembly"]
    if target.endswith("linux-android"):
        ndk = Path(env.get("ANDROID_NDK_HOME") or env["ANDROID_NDK"])
        host = "darwin-x86_64" if sys.platform == "darwin" else "linux-x86_64"
        if sys.platform == "win32":
            host = "windows-x86_64"
        toolchain = ndk / "toolchains/llvm/prebuilt" / host / "bin"
        triple = "aarch64-linux-android" if target.startswith("aarch64") else "x86_64-linux-android"
        abi = "arm64-v8a" if target.startswith("aarch64") else "x86_64"
        suffix = ".cmd" if sys.platform == "win32" else ""
        env.update(CC=str(toolchain / f"{triple}26-clang{suffix}"),
                   CXX=str(toolchain / f"{triple}26-clang++{suffix}"),
                   AR=str(toolchain / "llvm-ar"), RANLIB=str(toolchain / "llvm-ranlib"))
        configure += [f"--host={triple}"]
        cmake += [f"-DCMAKE_TOOLCHAIN_FILE={ndk}/build/cmake/android.toolchain.cmake",
                  f"-DANDROID_ABI={abi}", "-DANDROID_PLATFORM=android-26", "-DANDROID_STL=c++_static"]
    elif target == "x86_64-pc-windows-gnu":
        env.update(CC="x86_64-w64-mingw32-gcc", CXX="x86_64-w64-mingw32-g++",
                   AR="x86_64-w64-mingw32-ar", RANLIB="x86_64-w64-mingw32-ranlib")
        configure += ["--host=x86_64-w64-mingw32"]
        cmake += ["-DCMAKE_SYSTEM_NAME=Windows", "-DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc",
                  "-DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++"]
    elif target.endswith("apple-darwin"):
        arch = "arm64" if target.startswith("aarch64") else "x86_64"
        env.update(CC="clang", CXX="clang++", CFLAGS=f"-arch {arch} -mmacosx-version-min=14.0",
                   LDFLAGS=f"-arch {arch} -mmacosx-version-min=14.0")
        configure += [f"--host={'aarch64' if arch == 'arm64' else 'x86_64'}-apple-darwin"]
        cmake += [f"-DCMAKE_OSX_ARCHITECTURES={arch}", "-DCMAKE_OSX_DEPLOYMENT_TARGET=14.0"]
    elif target != "x86_64-unknown-linux-gnu":
        raise SystemExit("Unsupported OpenAC native build target")
    gmp = output / "gmp"
    if not (gmp / "lib/libgmp.a").is_file():
        build = output / "gmp-build"
        build.mkdir(exist_ok=True)
        run("bash", CACHE / "gmp-6.2.1/configure", f"--prefix={gmp}", *configure, cwd=build, env=env)
        run("make", "-j2", cwd=build, env=env)
        run("make", "install", cwd=build, env=env)
    # Generated constraint assertions must throw a redacted exception, never abort
    # the wallet or disappear under NDEBUG. The R1CS itself remains unchanged.
    guard = '#include <stdexcept>\n#undef assert\n#define assert(x) do { if (!(x)) throw std::runtime_error("Invalid witness"); } while (0)\n'
    for name in ("jwt_2k", "show"):
        code = (circuits / f"{name}.cpp").read_text()
        code = re.sub(r"std::cout\s*<<.*?;", "(void)0;", code, flags=re.S)
        code = code.replace('#include "calcwit.hpp"', '#include "calcwit.hpp"\n' + guard + '\nnamespace CIRCUIT_NAME {') + '\n}\n'
        write_changed(work / f"src/{name}.cpp", code)
        shutil.copy2(circuits / f"{name}.dat", work / "src")
        for suffix in ("cpp", "h"):
            code = (source / f"src/witnesscalc_template.{suffix}").read_text()
            code = code.replace("@CIRCUIT_NAME@", name).replace("@CIRCUIT_NAME_CAPS@", name.upper())
            write_changed(work / f"src/witnesscalc_{name}.{suffix}", code)
    for name in ("calcwit.cpp", "witnesscalc.cpp"):
        path = work / "src" / name
        code = (source / "src" / name).read_text()
        code = re.sub(r"std::cerr\s*<<.*?;", "", code, flags=re.S)
        code = re.sub(r"fprintf\(stderr,.*?;", "", code, flags=re.S)
        # All exception messages are consumed privately by the Rust adapter.
        code = code.replace('namespace CIRCUIT_NAME {', guard + '\nnamespace CIRCUIT_NAME {', 1)
        write_changed(path, code)
    config = f'''cmake_minimum_required(VERSION 3.18)
project(diw_openac_witness LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS_RELEASE "-O1 -DNDEBUG")
include_directories("{gmp.as_posix()}/include" "{work.as_posix()}/src" "{work.as_posix()}/build" "{source.as_posix()}/depends/json/single_include")
add_library(fr STATIC build/fr.cpp build/fr_generic.cpp build/fr_raw_generic.cpp)
'''
    for name in ("jwt_2k", "show"):
        config += f'''add_library(witnesscalc_{name} STATIC src/calcwit.cpp src/witnesscalc.cpp src/{name}.cpp src/witnesscalc_{name}.cpp)
target_compile_definitions(witnesscalc_{name} PRIVATE CIRCUIT_NAME={name})
'''
    write_changed(work / "CMakeLists.txt", config)
    build = work / "cmake-build"
    run("cmake", "-S", work, "-B", build, *cmake, env=env)
    run("cmake", "--build", build, "--parallel", "1", env=env)
    package = work / "package/lib"
    package.mkdir(parents=True, exist_ok=True)
    for library in ("fr", "witnesscalc_jwt_2k", "witnesscalc_show"):
        shutil.copy2(build / f"lib{library}.a", package)
    shutil.copy2(gmp / "lib/libgmp.a", package)


if __name__ == "__main__":
    main()
