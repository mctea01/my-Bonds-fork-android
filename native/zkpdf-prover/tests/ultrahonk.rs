//! Verifies another circuit's UltraHonk proof with only the two CRS points verification needs. Opt-in: set
//! ZKPASSPORT_PROOF_FIXTURE to a JSON file with `vkeyFields`, `proof` and `publicInputs` hex field arrays,
//! such as zkPassport's packages/aztec/test-harness/fixtures/outer_count_4_disclose.json (bb 6.0.0).
#![cfg(feature = "bb")]

fn fields(v: &serde_json::Value, key: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for f in v[key].as_array().unwrap() {
        let h = f.as_str().unwrap().trim_start_matches("0x");
        let h = format!("{h:0>64}");
        out.extend((0..32).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap()));
    }
    out
}

#[test]
fn verifies_without_the_full_crs() {
    let Some(path) = std::env::var_os("ZKPASSPORT_PROOF_FIXTURE") else {
        eprintln!("ZKPASSPORT_PROOF_FIXTURE not set; skipped");
        return;
    };
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let (vk, proof, mut public) = (fields(&v, "vkeyFields"), fields(&v, "proof"), fields(&v, "publicInputs"));
    zkpdf_prover::verify_ultrahonk(None, &vk, &proof, &public).expect("valid proof");
    public[31] ^= 1;
    assert!(zkpdf_prover::verify_ultrahonk(None, &vk, &proof, &public).is_err());
}
