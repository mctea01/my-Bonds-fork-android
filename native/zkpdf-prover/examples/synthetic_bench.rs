//! Only the committed fictional fixtures are accepted by this benchmark.
#[cfg(feature = "bb")]
fn main() {
    use std::{fs, path::PathBuf, time::Instant};
    use zkpdf_prover::*;
    let args: Vec<_> = std::env::args().collect();
    assert!(
        args.len() == 4 || args.len() == 5,
        "synthetic_bench_arguments"
    );
    let source = match args[1].as_str() {
        "student" => include_str!("../../../test-servers/src/test/resources/zkpdf/student.json"),
        "travel-rc4" => {
            include_str!("../../../test-servers/src/test/resources/zkpdf/travel-rc4.json")
        }
        _ => panic!("synthetic_fixture_required"),
    };
    let fixture: serde_json::Value = serde_json::from_str(source).unwrap();
    let mut input: ZkPdfProveInput = serde_json::from_value(fixture["input"].clone()).unwrap();
    let mut spec: ZkPdfVerifierSpec = serde_json::from_value(fixture["spec"].clone()).unwrap();
    input.assets_dir = args[2].clone();
    if let Some(composition) = args.get(4) {
        assert!(
            matches!(composition.as_str(), "zkpdf-v1-phone" | "zkpdf-v1-desktop"),
            "composition"
        );
        input.composition = composition.clone();
        spec.composition = composition.clone();
    }
    let out = PathBuf::from(&args[3]);
    fs::create_dir_all(&out).unwrap();
    let peak_kib = std::cell::Cell::new(0u64);
    let started = Instant::now();
    let result = prove_with_metrics(
        &input,
        || false,
        |_, _, _| {
            #[cfg(target_os = "linux")]
            fs::write("/proc/self/clear_refs", b"5").expect("rss_reset");
        },
        |metric| {
            let rss = fs::read_to_string("/proc/self/status").ok().and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("VmHWM:"))
                    .map(str::to_owned)
            });
            let kib = rss
                .as_deref()
                .and_then(|s| s.split_whitespace().nth(1))
                .and_then(|s| s.parse::<u64>().ok());
            if let Some(kib) = kib {
                peak_kib.set(peak_kib.get().max(kib));
            }
            println!(
                "{}",
                serde_json::json!({"segment":metric,"peak_rss_kib":kib})
            );
        },
    )
    .expect("synthetic_prove_failed");
    let verified = verify(&spec, &result.bundle, &args[2]).expect("synthetic_verify_failed");
    assert!(verified.claim_digests == result.claim_digests && verified.mid_outs == result.mid_outs);
    for segment in &result.bundle.segments {
        let directory = out.join(format!("{}-{}", segment.kind, segment.index));
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("proof"), &segment.proof).unwrap();
        fs::write(directory.join("public_inputs"), &segment.public_inputs).unwrap();
    }
    fs::write(
        out.join("bundle.json"),
        serde_json::to_vec(&result.bundle).unwrap(),
    )
    .unwrap();
    println!(
        "{}",
        serde_json::json!({"fixture":args[1], "composition":input.composition, "total_prove_ms":result.prove_ms,
        "total_with_verify_ms":started.elapsed().as_millis(),"segments":result.bundle.segments.len(),"peak_rss_kib":peak_kib.get()})
    );
}
#[cfg(not(feature = "bb"))]
fn main() {
    panic!("bb_feature_required");
}
