//! Build tooling: `vkey_hash <file.vk>` prints the registry leaf of a verification key, the
//! value circuit manifests list as a circuit's `hash`.
fn main() -> std::process::ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: vkey_hash <file.vk>");
        return std::process::ExitCode::from(2);
    };
    match std::fs::read(&path) {
        Ok(key) if !key.is_empty() && key.len() % 32 == 0 => {
            println!("0x{:0>64}", zkpassport_verify::vkey_hash(&key).to_str_radix(16));
            std::process::ExitCode::SUCCESS
        }
        _ => {
            eprintln!("vkey_hash_failed:key_read");
            std::process::ExitCode::FAILURE
        }
    }
}
