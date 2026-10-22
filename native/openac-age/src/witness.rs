//! Independently pinned, separately installed witness graphs; no embedded circuits.
use super::*;

pub(crate) fn calculate(documents: &str, prepare: bool) -> Result<Vec<u8>, ZkProofError> {
    let (name, bytes, sha256, input) = if prepare {
        (
            "jwt_2k",
            93_459_128,
            "cc49cb201e406a03089d72217718b38941c893a970d5d809996605148a2ed63c",
            "jwt_input.json",
        )
    } else {
        (
            "show",
            551_178,
            "352eeef11b56b48d2ffe71ea6f4a7c305fa4840cd2c111ae10878722891482a3",
            "show_input.json",
        )
    };
    let graph = Path::new(documents)
        .join("graphs")
        .join(format!("{name}.graph"));
    pinned_asset(&graph, bytes, sha256)?;
    let input = Path::new(documents).join(input);
    if fs::metadata(&input).map_err(|_| storage_error())?.len() > 1024 * 1024 {
        return Err(ZkProofError::InvalidInput {
            message: "witness_input_size".into(),
        });
    }
    let inputs = fs::read_to_string(input).map_err(|_| storage_error())?;
    let graph = fs::read(graph).map_err(|_| storage_error())?;
    check_cancelled()?;
    let result =
        circom_witnesscalc::calc_witness(&inputs, &graph).map_err(|_| ZkProofError::Proof)?;
    check_cancelled()?;
    Ok(result)
}
