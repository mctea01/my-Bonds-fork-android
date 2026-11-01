use crate::{acir, assets, backend::Session, field, prepare, public, *};
use serde::Serialize;
use std::{path::Path, time::Instant};

/// Timing contains no witness, record, commitment, or file contents.
#[derive(Clone, Serialize)]
pub struct SegmentMetrics {
    pub kind: String,
    pub index: u32,
    pub witness_ms: u64,
    pub prove_ms: u64,
    pub verify_ms: u64,
    pub proof_bytes: u64,
    pub public_input_bytes: u64,
}
pub fn prove(
    input: &ZkPdfProveInput,
    cancelled: impl Fn() -> bool,
    progress: impl Fn(&str, u32, u32),
) -> Result<ZkPdfProveOutput> {
    prove_with_metrics(input, cancelled, progress, |_| {})
}
pub fn prove_with_metrics(
    input: &ZkPdfProveInput,
    cancelled: impl Fn() -> bool,
    progress: impl Fn(&str, u32, u32),
    metrics: impl Fn(SegmentMetrics),
) -> Result<ZkPdfProveOutput> {
    let poll = || {
        if cancelled() {
            Err(Error("cancelled"))
        } else {
            Ok(())
        }
    };
    poll()?;
    let start = Instant::now();
    let prepared = prepare::prepare(input, field::fresh_salt()?)?;
    poll()?;
    let directory = Path::new(&input.assets_dir);
    // Authenticate every required asset before beginning expensive proof work.
    for (kind, _, _) in &prepared.stages {
        assets::circuit(directory, &input.composition, kind, false)?;
        assets::circuit(directory, &input.composition, kind, true)?;
    }
    let session = Session::open(directory)?;
    let mut segments = Vec::new();
    for (ordinal, (kind, index, witness)) in prepared.stages.iter().enumerate() {
        poll()?;
        progress(kind, ordinal as u32 + 1, prepared.plan.total_segments);
        let artifact = assets::circuit(directory, &input.composition, kind, false)?;
        let vk = assets::circuit(directory, &input.composition, kind, true)?;
        let started = Instant::now();
        let executed = acir::execute(&artifact, witness)?;
        let witness_ms = started.elapsed().as_millis() as u64;
        if executed.public_inputs != public::encode(kind, witness)? {
            return Err(Error("witness_public_mismatch"));
        }
        poll()?;
        let started = Instant::now();
        let proof = session.prove(&vk, &executed)?;
        let prove_ms = started.elapsed().as_millis() as u64;
        let started = Instant::now();
        session.verify(&vk, &proof, &executed.public_inputs)?;
        let verify_ms = started.elapsed().as_millis() as u64;
        poll()?;
        metrics(SegmentMetrics {
            kind: kind.clone(),
            index: *index,
            witness_ms,
            prove_ms,
            verify_ms,
            proof_bytes: proof.len() as u64,
            public_input_bytes: executed.public_inputs.len() as u64,
        });
        segments.push(ZkPdfSegmentProof {
            kind: kind.clone(),
            index: *index,
            proof,
            public_inputs: executed.public_inputs,
        });
    }
    poll()?;
    Ok(ZkPdfProveOutput {
        bundle: ZkPdfBundle {
            composition: input.composition.clone(),
            segments,
        },
        mid_outs: prepared.mid_outs,
        anchor_ordinals: prepared.ordinals,
        anchor_totals: prepared.totals,
        claim_records: prepared.records,
        claim_digests: prepared.digests,
        prove_ms: start.elapsed().as_millis() as u64,
    })
}
pub fn verify(
    spec: &ZkPdfVerifierSpec,
    bundle: &ZkPdfBundle,
    assets_dir: &str,
) -> Result<ZkPdfVerified> {
    let verified = crate::verify::policy(spec, bundle)?;
    let directory = Path::new(assets_dir);
    let session = Session::open(directory)?;
    for segment in &bundle.segments {
        let vk = assets::circuit(directory, &spec.composition, &segment.kind, true)?;
        session.verify(&vk, &segment.proof, &segment.public_inputs)?;
    }
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(name: &str) -> (ZkPdfProveInput, ZkPdfVerifierSpec) {
        let source = if name == "student" {
            include_str!("../../../test-servers/src/test/resources/zkpdf/student.json")
        } else {
            include_str!("../../../test-servers/src/test/resources/zkpdf/travel-rc4.json")
        };
        let f: serde_json::Value = serde_json::from_str(source).unwrap();
        (
            serde_json::from_value(f["input"].clone()).unwrap(),
            serde_json::from_value(f["spec"].clone()).unwrap(),
        )
    }
    #[test]
    fn cancelled_before_any_work() {
        let (input, _) = fixture("student");
        assert!(
            prove(&input, || true, |_, _, _| panic!("unexpected_progress")).err()
                == Some(Error("cancelled"))
        );
    }
    #[test]
    #[ignore = "requires the two synthetic_bench proof bundles and authenticated assets"]
    fn real_proof_rejections_and_cli_interop() {
        let assets = std::env::var("ZKPDF_ASSETS_DIR").expect("assets_directory");
        let outputs = std::path::PathBuf::from(
            std::env::var_os("ZKPDF_SYNTHETIC_OUTPUT").expect("synthetic_output"),
        );
        let load = |name: &str| -> ZkPdfBundle {
            serde_json::from_slice(&std::fs::read(outputs.join(name).join("bundle.json")).unwrap())
                .unwrap()
        };
        let student = load("student");
        let travel = load("travel-rc4");
        for (name, bundle) in [("student", &student), ("travel-rc4", &travel)] {
            let (_, spec) = fixture(name);
            assert!(verify(&spec, bundle, &assets).is_ok());
            let mut changed = spec.clone();
            changed.anchors[0].ordinal = 2;
            assert!(verify(&changed, bundle, &assets).is_err());
            let mut changed = bundle.clone();
            changed.segments.swap(0, 1);
            assert!(verify(&spec, &changed, &assets).is_err());
            let mut changed = bundle.clone();
            changed.segments[0].public_inputs[31] ^= 1;
            assert!(verify(&spec, &changed, &assets).is_err());
            let mut changed = bundle.clone();
            changed.segments[0].proof[100] ^= 1;
            assert!(verify(&spec, &changed, &assets).is_err());
            // Exercise the exact self-verification primitive used by prove.
            {
                let session = Session::open(Path::new(&assets)).unwrap();
                let vk = assets::circuit(
                    Path::new(&assets),
                    &spec.composition,
                    &changed.segments[0].kind,
                    true,
                )
                .unwrap();
                assert!(session
                    .verify(
                        &vk,
                        &changed.segments[0].proof,
                        &changed.segments[0].public_inputs
                    )
                    .is_err());
            }
            let mut changed = bundle.clone();
            changed.composition = "zkpdf-v1-desktop".into();
            let mut desktop = spec.clone();
            desktop.composition = changed.composition.clone();
            assert!(verify(&desktop, &changed, &assets).is_err());
        }
        let (_, spec) = fixture("student");
        let mut changed = student;
        changed.segments[0] = travel.segments[0].clone();
        assert!(verify(&spec, &changed, &assets).is_err());
        // Optional external CLI proofs exercise the reverse direction with
        // the same frozen keys and expected public values.
        if let Some(directory) = std::env::var_os("ZKPDF_CLI_PROOFS") {
            let directory = std::path::PathBuf::from(directory);
            let session = Session::open(Path::new(&assets)).unwrap();
            for name in ["student", "travel-rc4"] {
                let (input, _) = fixture(name);
                let prepared = prepare::prepare(&input, field::number(42)).unwrap();
                for (kind, index, witness) in prepared.stages {
                    let root = directory.join(name).join(format!("{kind}-{index}"));
                    let proof = std::fs::read(root.join("proof")).unwrap();
                    let pi = std::fs::read(root.join("public_inputs")).unwrap();
                    assert!(pi == public::encode(&kind, &witness).unwrap());
                    let vk = assets::circuit(Path::new(&assets), &input.composition, &kind, true)
                        .unwrap();
                    assert!(session.verify(&vk, &proof, &pi).is_ok());
                }
            }
        }
    }
}
