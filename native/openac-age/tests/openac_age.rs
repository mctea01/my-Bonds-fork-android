//! Synthetic ES256 SD-JWT generator and the complete linked age-proof acceptance test.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use openac_age::*;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

fn b64(value: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

fn coordinates(key: &SigningKey) -> (String, String) {
    let point = key.verifying_key().to_encoded_point(false);
    (
        b64(point.x().expect("P-256 x")),
        b64(point.y().expect("P-256 y")),
    )
}

fn fixture() -> (String, SigningKey, String, String) {
    let issuer = SigningKey::from_slice(&[7u8; 32]).expect("synthetic issuer key");
    let holder = SigningKey::from_slice(&[9u8; 32]).expect("synthetic holder key");
    let (issuer_x, issuer_y) = coordinates(&issuer);
    let (holder_x, holder_y) = coordinates(&holder);
    let disclosure = b64(br#"["synthetic-age-test-salt","birthdate","1990-01-01"]"#);
    let digest = b64(Sha256::digest(disclosure.as_bytes()));
    let header = b64(serde_json::to_vec(&json!({"alg":"ES256","typ":"vc+sd-jwt"})).unwrap());
    let payload = b64(serde_json::to_vec(&json!({
        "iss":"did:key:synthetic-openac-test-issuer", "nbf":1, "exp":4102444800u64,
        "cnf":{"jwk":{"kty":"EC","crv":"P-256","x":holder_x,"y":holder_y}},
        "vc":{"credentialSubject":{"_sd_alg":"sha-256","_sd":[digest]}}
    }))
    .unwrap());
    let signing_input = format!("{header}.{payload}");
    let signature: Signature = issuer.sign(signing_input.as_bytes());
    (
        format!(
            "{signing_input}.{}~{disclosure}~",
            b64(signature.to_bytes())
        ),
        holder,
        issuer_x,
        issuer_y,
    )
}

#[test]
fn prepare_input_is_synthetic_and_private() {
    let temporary = tempfile::tempdir().unwrap();
    let documents = temporary.path().join("circom");
    let (sd_jwt, _, x, y) = fixture();
    let prepared =
        create_age_prepare_input(documents.to_string_lossy().into_owned(), sd_jwt, x, y).unwrap();
    assert_eq!(prepared.claim_name, "birthdate");
    assert_eq!(prepared.claim_format, 2);
    assert!(documents.join("jwt_input.json").is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(documents.join("jwt_input.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn bad_inputs_do_not_overwrite_existing_witness_input() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("show_input.json");
    fs::write(&input, b"previous-synthetic-input").unwrap();
    let result = create_age_show_input(
        temporary.path().to_string_lossy().into_owned(),
        "short".into(),
        "synthetic-private-signature".into(),
        "birthdate".into(),
        2,
        20080901,
    );
    assert!(matches!(result, Err(ZkProofError::InvalidInput { .. })));
    assert_eq!(result.unwrap_err().to_string(), "Invalid OpenAC input");
    assert!(fs::read(input).unwrap() == b"previous-synthetic-input");
}

#[test]
fn cancellation_is_scoped_and_never_publishes_work() {
    let token = Arc::new(AtomicBool::new(true));
    let check = Arc::clone(&token);
    let result = with_cancellation(Arc::new(move || check.load(Ordering::Acquire)), || {
        panic!("cancelled work must not start")
    });
    assert!(matches!(result, Err::<(), _>(ZkProofError::Cancelled)));
    token.store(false, Ordering::Release);
    let temporary = tempfile::tempdir().unwrap();
    let (sd_jwt, _, x, y) = fixture();
    assert!(create_age_prepare_input(
        temporary.path().to_string_lossy().into_owned(),
        sd_jwt,
        x,
        y
    )
    .is_ok());
}

fn link_public_assets(source: &Path, documents: &Path) {
    for (from, to) in [
        ("graphs/jwt_2k.graph", "graphs/jwt_2k.graph"),
        ("graphs/show.graph", "graphs/show.graph"),
        ("build/jwt/jwt_js/jwt.r1cs", "build/jwt/jwt_js/jwt.r1cs"),
        (
            "build/show/show_js/show.r1cs",
            "build/show/show_js/show.r1cs",
        ),
        ("keys/prepare_proving.key", "keys/prepare_proving.key"),
        ("keys/prepare_verifying.key", "keys/prepare_verifying.key"),
        ("keys/show_proving.key", "keys/show_proving.key"),
        ("keys/show_verifying.key", "keys/show_verifying.key"),
    ] {
        let destination = documents.join(to);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        if fs::hard_link(source.join(from), &destination).is_err() {
            fs::copy(source.join(from), destination).expect("copy verified public asset");
        }
    }
}

#[test]
#[ignore = "Requires verified public assets; run explicitly after install_assets.py"]
fn synthetic_prepare_show_reblind_and_independent_policy() {
    let assets = std::env::var_os("OPENAC_TEST_ASSETS")
        .expect("OPENAC_TEST_ASSETS points to verified circom assets");
    let temporary = tempfile::tempdir().unwrap();
    let documents = temporary.path().join("circom");
    link_public_assets(Path::new(&assets), &documents);
    let docs = documents.to_string_lossy().into_owned();
    let (sd_jwt, holder, issuer_x, issuer_y) = fixture();
    let prepared =
        create_age_prepare_input(docs.clone(), sd_jwt, issuer_x.clone(), issuer_y.clone()).unwrap();
    let prepare = prove_jwt(docs.clone()).unwrap();
    let nonce = "synthetic-openac-request-nonce-0123456789".to_owned();
    let signature: Signature = holder.sign(nonce.as_bytes());
    create_age_show_input(
        docs.clone(),
        nonce.clone(),
        b64(signature.to_bytes()),
        prepared.claim_name.clone(),
        prepared.claim_format,
        20080901,
    )
    .unwrap();
    let show = prove_show(docs.clone()).unwrap();
    let original = fs::read(documents.join("keys/prepare_proof.bin")).unwrap();
    let cache_identity = || {
        [
            "prepare_instance.bin",
            "prepare_witness.bin",
            "show_instance.bin",
            "show_witness.bin",
        ]
        .map(|name| Sha256::digest(fs::read(documents.join("keys").join(name)).unwrap()))
    };
    let original_cache = cache_identity();
    let reblind_started = std::time::Instant::now();
    generate_shared_blinds(docs.clone()).unwrap();
    reblind_jwt(docs.clone()).unwrap();
    reblind_show(docs.clone()).unwrap();
    let reblind_ms = reblind_started.elapsed().as_millis();
    assert!(cache_identity() == original_cache);
    assert!(fs::read(documents.join("keys/prepare_proof.bin")).unwrap() != original);
    let accepted = |nonce: String, cutoff, x: String, y: String| {
        verify_age_presentation(
            docs.clone(),
            nonce,
            prepared.claim_name.clone(),
            prepared.claim_format,
            cutoff,
            x,
            y,
        )
        .unwrap()
    };
    let verify_started = std::time::Instant::now();
    assert!(accepted(
        nonce.clone(),
        20080901,
        issuer_x.clone(),
        issuer_y.clone()
    ));
    let verify_ms = verify_started.elapsed().as_millis();
    assert!(!accepted(
        nonce.clone(),
        20080902,
        issuer_x.clone(),
        issuer_y.clone()
    ));
    let wrong = SigningKey::from_slice(&[11u8; 32]).unwrap();
    assert!(!accepted(
        nonce.clone(),
        20080901,
        coordinates(&wrong).0,
        coordinates(&wrong).1
    ));
    assert!(!accepted(
        "different-synthetic-request-nonce".into(),
        20080901,
        issuer_x.clone(),
        issuer_y.clone()
    ));
    let signals = read_public_signals(docs.clone()).unwrap();
    assert_eq!(signals.prepare.len(), 6);
    assert_eq!(signals.show.len(), 156);
    // An optional private output directory lets the FFI smoke test verify this
    // same synthetic proof rather than repeating the expensive proving phase.
    if let Some(output) = std::env::var_os("OPENAC_FFI_OUTPUT") {
        let output = Path::new(&output);
        fs::create_dir_all(output.join("keys")).unwrap();
        for name in [
            "prepare_proof.bin",
            "show_proof.bin",
            "prepare_verifying.key",
            "show_verifying.key",
        ] {
            let target = output.join("keys").join(name);
            if target.exists() {
                fs::remove_file(&target).unwrap();
            }
            let source = documents.join("keys").join(name);
            if name.ends_with(".key") {
                if fs::hard_link(&source, &target).is_err() {
                    fs::copy(source, target).unwrap();
                }
            } else {
                fs::copy(source, target).unwrap();
            }
        }
        let (sd_jwt, _, _, _) = fixture();
        let data = serde_json::to_vec(&json!({"sd_jwt":sd_jwt, "nonce":nonce,
            "device_signature":b64(signature.to_bytes()),
            "claim_name":prepared.claim_name, "claim_format":prepared.claim_format,
            "cutoff":20080901, "issuer_x":issuer_x, "issuer_y":issuer_y}))
        .unwrap();
        let mut file = tempfile::NamedTempFile::new_in(output).unwrap();
        use std::io::Write;
        file.write_all(&data).unwrap();
        file.persist(output.join("synthetic-fixture.json")).unwrap();
    }
    // Each proof still verifies on its own, but a different shared blind breaks
    // the authenticated linkage and must reject the complete presentation.
    generate_shared_blinds(docs.clone()).unwrap();
    reblind_show(docs.clone()).unwrap();
    assert!(!accepted(nonce, 20080901, issuer_x, issuer_y));
    assert!(read_public_signals(docs).is_err());
    // Publish only timing/size measurements, never credential or proof contents.
    println!(
        "OpenAC synthetic proof accepted: prepare_ms={} show_ms={} reblind_ms={} verify_ms={} prepare_bytes={} show_bytes={}",
        prepare.total_ms, show.total_ms, reblind_ms, verify_ms, prepare.proof_size_bytes, show.proof_size_bytes
    );
}
