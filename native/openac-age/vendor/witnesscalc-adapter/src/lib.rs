pub use paste;
pub use serde_json;
use std::{env, path::Path, process::Command};

pub mod convert_type;
pub use convert_type::*;

#[doc(hidden)]
pub mod __macro_deps {
    pub use anyhow;
}

/// Macro to generate a witness for a given circuit
#[macro_export]
macro_rules! witness {
    ($x: ident) => {
        $crate::paste::paste! {
            #[allow(non_upper_case_globals)]
            const [<$x _CIRCUIT_DATA>]: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/witnesscalc/src/", stringify!($x), ".dat"));
            #[link(name = "witnesscalc_" [<$x>], kind = "static")]
            extern "C" {
                fn [<witnesscalc_ $x>](
                    circuit_buffer: *const std::os::raw::c_char,
                    circuit_size: std::ffi::c_ulong,
                    json_buffer: *const std::os::raw::c_char,
                    json_size: std::ffi::c_ulong,
                    wtns_buffer: *mut std::os::raw::c_char,
                    wtns_size: *mut std::ffi::c_ulong,
                    error_msg: *mut std::os::raw::c_char,
                    error_msg_maxsize: std::ffi::c_ulong,
                ) -> std::ffi::c_int;
            }
        }
        $crate::paste::item! {
            pub fn [<$x _witness>](json_input: &str) -> $crate::__macro_deps::anyhow::Result<Vec<u8>> {
                // FFI return codes
                const WITNESSCALC_OK: std::ffi::c_int = 0x0;
                const WITNESSCALC_ERROR_SHORT_BUFFER: std::ffi::c_int = 0x2;

                unsafe {
                    let json_input = std::ffi::CString::new(json_input).map_err(|_| $crate::__macro_deps::anyhow::anyhow!("Invalid witness input"))?;
                    let json_size = json_input.as_bytes().len() as std::ffi::c_ulong;

                    let circuit_buffer = [<$x _CIRCUIT_DATA>].as_ptr() as *const std::ffi::c_char;
                    let circuit_size = [<$x _CIRCUIT_DATA>].len() as std::ffi::c_ulong;

                    let mut error_msg = vec![0u8; 256]; // Error message buffer
                    let error_msg_ptr = error_msg.as_mut_ptr() as *mut std::ffi::c_char;

                    // Two-pass dynamic allocation:
                    // Pass 1: Probe with small buffer to query required size
                    let mut probe_buffer = vec![0u8; 1024]; // 1 KB probe buffer
                    let mut wtns_size: std::ffi::c_ulong = probe_buffer.len() as std::ffi::c_ulong;

                    let result = [<witnesscalc_ $x>](
                        circuit_buffer,
                        circuit_size,
                        json_input.as_ptr(),
                        json_size,
                        probe_buffer.as_mut_ptr() as *mut _,
                        &mut wtns_size as *mut _,
                        error_msg_ptr,
                        error_msg.len() as std::ffi::c_ulong,
                    );

                    // Pass 2: If buffer too small, allocate exact size and retry
                    let final_buffer = if result == WITNESSCALC_ERROR_SHORT_BUFFER {
                        // wtns_size now contains the required minimum size
                        let required_size = wtns_size as usize;
                        if required_size > 512 * 1024 * 1024 { return Err($crate::__macro_deps::anyhow::anyhow!("Witness size limit")); }

                        let mut wtns_buffer = vec![0u8; required_size];
                        let mut wtns_size: std::ffi::c_ulong = required_size as std::ffi::c_ulong;

                        let result = [<witnesscalc_ $x>](
                            circuit_buffer,
                            circuit_size,
                            json_input.as_ptr(),
                            json_size,
                            wtns_buffer.as_mut_ptr() as *mut _,
                            &mut wtns_size as *mut _,
                            error_msg_ptr,
                            error_msg.len() as std::ffi::c_ulong,
                        );

                        if result != WITNESSCALC_OK {

                            return Err($crate::__macro_deps::anyhow::anyhow!("Witness generation failed"));
                        }

                        wtns_buffer[..wtns_size as usize].to_vec()
                    } else if result == WITNESSCALC_OK {
                        // Success on first try with probe buffer (small witness)
                        probe_buffer[..wtns_size as usize].to_vec()
                    } else {
                        // Other error

                        return Err($crate::__macro_deps::anyhow::anyhow!("Witness generation failed"));
                    };

                    Ok(final_buffer)
                }
            }
        }
    };
}

/// Android, Linux, macOS and Windows GNU build driver. Sources are prepared and
/// pinned before Cargo starts; failed native builds are never accepted.
pub fn build_and_link(circuits_dir: &str) {
    let target = env::var("TARGET").expect("TARGET");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let script = root.join("build_witness.py");
    println!("cargo:rerun-if-changed={}", script.display());
    println!("cargo:rerun-if-changed={}", circuits_dir);
    let python = env::var("PYTHON").unwrap_or_else(|_| "python3".into());
    let status = Command::new(python)
        .arg("-I")
        .arg(script)
        .arg(&target)
        .arg(&out_dir)
        .arg(circuits_dir)
        .status()
        .expect("Native build driver");
    assert!(status.success(), "OpenAC native witness build failed");
    println!(
        "cargo:rustc-link-search=native={}/witnesscalc/package/lib",
        out_dir
    );
    for library in ["witnesscalc_jwt_2k", "witnesscalc_show", "fr", "gmp"] {
        println!("cargo:rustc-link-lib=static={}", library);
    }
    if target.contains("android") {
        println!("cargo:rustc-link-lib=static=c++_static");
        println!("cargo:rustc-link-lib=static=c++abi");
    } else if target.contains("apple") {
        println!("cargo:rustc-link-lib=c++");
    } else if target.contains("windows") {
        let compiler = env::var("CXX").unwrap_or_else(|_| "x86_64-w64-mingw32-g++".into());
        let output = Command::new(compiler)
            .arg("-print-file-name=libstdc++.a")
            .output()
            .expect("MinGW C++ runtime");
        assert!(output.status.success(), "MinGW C++ runtime lookup failed");
        let archive = String::from_utf8(output.stdout).expect("MinGW runtime path");
        let archive = Path::new(archive.trim());
        assert!(archive.is_file(), "Static MinGW C++ runtime is required");
        println!(
            "cargo:rustc-link-search=native={}",
            archive.parent().unwrap().display()
        );
        println!("cargo:rustc-link-lib=static=stdc++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
