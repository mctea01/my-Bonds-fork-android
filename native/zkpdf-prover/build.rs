use std::{env, path::PathBuf, process::Command};
fn main() {
    println!("cargo:rerun-if-changed=cpp/bridge.cpp");
    for name in ["ZKPDF_BB_SOURCE", "ZKPDF_BB_BUILD", "CXX", "AR"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    if env::var_os("CARGO_FEATURE_BB").is_none() {
        return;
    }
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
                == "f2bed7ed073966bb2a2dcdd02a133d11bf2996d3",
        "bb_revision"
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let target = env::var("TARGET").unwrap();
    let mut compiler = Command::new(env::var_os("CXX").unwrap_or("c++".into()));
    compiler
        .args([
            "-std=c++20",
            "-O2",
            "-fPIC",
            "-DDISABLE_ASM=1",
            "-DDISABLE_AZTEC_VM=1",
            "-DNO_PAR_ALGOS",
            "-pthread",
        ])
        .arg("-I")
        .arg(source.join("barretenberg/cpp/src"))
        .arg("-I")
        .arg(build.join("_deps/msgpack-c/src/msgpack-c/include"))
        .arg("-I")
        .arg(build.join("_deps/tracy-src/public"))
        .args(["-c", "cpp/bridge.cpp", "-o"])
        .arg(out.join("bridge.o"));
    assert!(
        compiler.status().expect("bb_bridge_compiler").success(),
        "bb_bridge_compile"
    );
    assert!(
        Command::new(env::var_os("AR").unwrap_or("ar".into()))
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
    println!("cargo:rustc-link-lib=static=deflate");
    println!(
        "cargo:rustc-link-lib={}",
        if target.contains("apple") || target.contains("android") {
            "c++"
        } else {
            "stdc++"
        }
    );
    println!("cargo:rustc-link-lib=pthread");
}
