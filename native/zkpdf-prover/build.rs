use std::{env, path::PathBuf, process::Command};
fn main() {
    println!("cargo:rerun-if-changed=cpp/bridge.cpp");
    for name in [
        "ZKPDF_BB_SOURCE",
        "ZKPDF_BB_BUILD",
        "ZKPDF_CXX",
        "ZKPDF_AR",
        "CXX",
        "AR",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    if env::var_os("CARGO_FEATURE_BB").is_none() {
        return;
    }
    let workers = if env::var_os("CARGO_FEATURE_BENCH_WORKERS").is_some() {
        println!("cargo:rerun-if-env-changed=ZKPDF_BENCH_WORKERS");
        let value = env::var("ZKPDF_BENCH_WORKERS").expect("benchmark_workers_required");
        assert!(
            matches!(value.as_str(), "1" | "2" | "4"),
            "benchmark_workers_invalid"
        );
        value
    } else {
        "2".to_owned()
    };
    println!("cargo:rustc-env=ZKPDF_COMPILED_WORKERS={workers}");
    let source =
        PathBuf::from(env::var_os("ZKPDF_BB_SOURCE").expect("ZKPDF_BB_SOURCE is required"));
    let build = PathBuf::from(env::var_os("ZKPDF_BB_BUILD").expect("ZKPDF_BB_BUILD is required"));
    let revision = Command::new("git")
        .args(["-C"])
        .arg(&source)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("bb_revision");
    assert!(
        revision.status.success()
            && String::from_utf8_lossy(&revision.stdout).trim()
                == "0219f11d8133970df3974fe5ae65e006bf8c193a",
        "bb_revision"
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let target = env::var("TARGET").unwrap();
    let mut compiler = Command::new(
        env::var_os("ZKPDF_CXX")
            .or_else(|| env::var_os("CXX"))
            .unwrap_or("c++".into()),
    );
    compiler
        .args([
            "-std=c++20",
            "-O2",
            "-fPIC",
            "-DDISABLE_ASM=1",
            "-DDISABLE_AZTEC_VM=1",
            "-DNO_PAR_ALGOS",
            // The definitions every barretenberg object is compiled with, so the headers agree.
            "-DNDEBUG",
            "-DMSGPACK_NO_BOOST",
            "-DMSGPACK_USE_STD_VARIANT_ADAPTOR",
            "-pthread",
        ])
        .arg(format!("-DZKPDF_WORKERS={workers}"))
        .arg("-I")
        .arg(source.join("barretenberg/cpp/src"))
        .arg("-I")
        .arg(build.join("_deps/msgpack-c/src/msgpack-c/include"))
        .arg("-I")
        .arg(build.join("_deps/tracy-src/public"))
        .args(["-c", "cpp/bridge.cpp", "-o"])
        .arg(out.join("bridge.o"));
    if target.contains("windows-gnu") {
        // Built like Barretenberg itself (tools/windows_mingw.cmake): clang for MinGW-w64 with its libstdc++.
        compiler.args(["--target=x86_64-w64-mingw32", "-femulated-tls", "-include", "tools/mingw_libstdcxx.h"]);
    }
    assert!(
        compiler.status().expect("bb_bridge_compiler").success(),
        "bb_bridge_compile"
    );
    assert!(
        Command::new(
            env::var_os("ZKPDF_AR")
                .or_else(|| env::var_os("AR"))
                .unwrap_or("ar".into())
        )
        .arg("crs")
        .arg(out.join("libzkpdf_bridge.a"))
        .arg(out.join("bridge.o"))
        .status()
        .expect("bb_bridge_archiver")
        .success(),
        "bb_bridge_archive"
    );
    println!("cargo:rustc-link-search=native={}", out.display());
    println!(
        "cargo:rustc-link-search=native={}",
        build.join("lib").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        build.join("_deps/libdeflate-build").display()
    );
    println!("cargo:rustc-link-lib=static=zkpdf_bridge");
    println!("cargo:rustc-link-lib=static=barretenberg");
    println!("cargo:rustc-link-lib=static=zkpdf_vm2_stub");
    println!("cargo:rustc-link-lib=static=deflate");
    if target.contains("windows-gnu") {
        // The C++ runtime and winpthreads go into the DLL, which then needs system libraries only.
        for name in ["stdc++", "winpthread"] {
            println!("cargo:rustc-link-lib=static:-bundle={name}");
        }
        // Barretenberg's random engine.
        println!("cargo:rustc-link-lib=bcrypt");
        return;
    }
    println!(
        "cargo:rustc-link-lib={}",
        if target.contains("android") {
            "c++_static"
        } else if target.contains("apple") {
            "c++"
        } else {
            "stdc++"
        }
    );
    if target.contains("android") {
        println!("cargo:rustc-link-lib=c++abi");
    } else {
        println!("cargo:rustc-link-lib=pthread");
    }
}
