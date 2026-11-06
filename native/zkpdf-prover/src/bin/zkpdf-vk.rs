//! Build tooling: `zkpdf-vk <crs-dir> <artifact.json> <out.vk>` writes the verification key
//! that `bb write_vk -s ultra_honk --oracle_hash poseidon2` derives, through the linked backend.
use std::{env, fs, path::Path, process::ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: zkpdf-vk <crs-dir> <artifact.json> <out.vk>");
        return ExitCode::from(2);
    }
    let result = fs::read(&args[2])
        .map_err(|_| zkpdf_prover::Error("artifact_read"))
        .and_then(|artifact| zkpdf_prover::write_vk(Path::new(&args[1]), &artifact))
        .and_then(|vk| fs::write(&args[3], vk).map_err(|_| zkpdf_prover::Error("vk_write")));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("zkpdf_vk_failed:{}", error.0);
            ExitCode::FAILURE
        }
    }
}
