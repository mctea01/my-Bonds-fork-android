//! Development interoperability probe. Use only synthetic witness fixtures.
use std::{fs, path::PathBuf, time::Instant};

fn run() -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        return Err("arguments");
    }
    let artifact = fs::read(&args[0]).map_err(|_| "asset_read")?;
    let input = fs::read(&args[1]).map_err(|_| "input_read")?;
    let input = serde_json::from_slice(&input).map_err(|_| "input_json")?;
    let start = Instant::now();
    let result = zkpdf_prover::acir::execute(&artifact, &input).map_err(|e| e.0)?;
    let elapsed = start.elapsed().as_millis();
    let output = PathBuf::from(&args[2]);
    fs::create_dir_all(&output).map_err(|_| "output_create")?;
    fs::write(output.join("bytecode.gz"), result.bytecode).map_err(|_| "output_write")?;
    fs::write(output.join("witness.gz"), result.witness).map_err(|_| "output_write")?;
    fs::write(output.join("public_inputs"), result.public_inputs).map_err(|_| "output_write")?;
    println!("witness_ms={elapsed}");
    Ok(())
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(run).unwrap_or(Err("worker_panic"));
    if let Err(code) = result {
        eprintln!("zkpdf_probe_failed:{code}");
        std::process::exit(1);
    }
}
