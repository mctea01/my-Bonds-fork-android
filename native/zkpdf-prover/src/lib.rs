//! Offline witness execution for the frozen zkPDF v1 circuits.

mod acir;
mod assets;
mod field;
mod inflate;
mod lex;
mod prepare;
mod public;
mod verify;
pub use prepare::check;
mod types;
pub use types::*;
pub const NOIR_REVISION: &str = "1.0.0-rc.3+5a7ee9bf5ed8973076df7bb0d2b723024db09ae7";
pub const BB_REVISION: &str = "6.0.0+0219f11d8133970df3974fe5ae65e006bf8c193a";
/// Zero-knowledge UltraHonk proof size (fields of 32 bytes) for bb 6.0.0 with Poseidon2.
pub const PROOF_BYTES: usize = 14656;

/// Errors expose fixed codes only; upstream diagnostic payloads are discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(pub &'static str);
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "bb")]
mod backend;
#[cfg(feature = "bb")]
mod bbthread;
#[cfg(feature = "bb")]
mod runtime;
#[cfg(feature = "bb")]
pub use runtime::{prove, prove_with_metrics, verify, SegmentMetrics};

/// Build tooling: the verification key `bb write_vk` derives for a nargo artifact,
/// using the authenticated CRS in `crs_directory`.
#[cfg(feature = "bb")]
pub fn write_vk(crs_directory: &std::path::Path, artifact: &[u8]) -> Result<Vec<u8>> {
    backend::Session::open(crs_directory)?.vk(artifact)
}
/// Verifies another circuit's zero-knowledge UltraHonk (Poseidon2) proof with its verification key, as
/// zkPassport's subproofs are. `crs_directory` may hold the authenticated full CRS; without it only the
/// two ceremony constants verification needs are installed, and proving needs the process to start again.
#[cfg(feature = "bb")]
pub fn verify_ultrahonk(crs_directory: Option<&std::path::Path>, vk: &[u8], proof: &[u8], public_inputs: &[u8]) -> Result<()> {
    backend::Session::open_verifier(crs_directory)?.verify_any(vk, proof, public_inputs)
}
/// Executes a Noir artifact (`abi` and `bytecode`, as zkPassport publishes its circuits) with [inputs] and proves
/// it with the authenticated CRS in `crs_directory`, under [vk] or, without one, the key this backend derives: the
/// zero-knowledge UltraHonk (Poseidon2) proof, its public inputs (32 bytes per field) and the key used.
#[cfg(feature = "bb")]
pub fn prove_ultrahonk(
    crs_directory: &std::path::Path,
    artifact: &[u8],
    vk: Option<&[u8]>,
    inputs: &serde_json::Value,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let executed = acir::execute(artifact, inputs)?;
    let session = backend::Session::open(crs_directory)?;
    let vk = match vk {
        Some(v) => v.to_vec(),
        None => session.vk(artifact)?,
    };
    let proof = session.prove_any(&vk, &executed)?;
    Ok((proof, executed.public_inputs, vk))
}
/// The public inputs of [artifact] executed with [inputs], 32 bytes per field, without proving.
pub fn execute_public_inputs(artifact: &[u8], inputs: &serde_json::Value) -> Result<Vec<u8>> {
    Ok(acir::execute(artifact, inputs)?.public_inputs)
}
mod opening;
pub use opening::verify_opening;

#[cfg(test)]
mod regression_tests;
