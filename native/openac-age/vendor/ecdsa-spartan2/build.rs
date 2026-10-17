fn main() {
    // Legacy C++ witness paths are deliberately unavailable in this host.
    println!(r#"cargo:rustc-check-cfg=cfg(feature, values("native-witness"))"#);
    for size in ["base", "1k", "2k", "4k", "8k", "mdoc"] {
        println!("cargo:rustc-check-cfg=cfg(has_circuit_{})", size);
    }
}
