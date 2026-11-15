use super::*;
use std::io::Read;

const DOMAIN: &str = "verify.example.org";
const DATE: u64 = 1_789_000_000;
const ROOT: u64 = 0x1234;
const NULLIFIER: u64 = 987_654_321;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn age_vkey() -> (String, String) {
    let v: Value = serde_json::from_slice(&fixture("compare_age-0.21.1.json")).unwrap();
    (v["vkey"].as_str().unwrap().to_string(), v["vkey_hash"].as_str().unwrap().to_string())
}

fn encode(public: &[BigUint]) -> String {
    let mut bytes = Vec::new();
    for x in public {
        let b = x.to_bytes_be();
        bytes.extend(std::iter::repeat_n(0u8, 32 - b.len()));
        bytes.extend(b);
    }
    bytes.extend([7u8; 128]);
    format!("0x{}", hex::encode(bytes))
}

fn result(name: &str, public: Vec<BigUint>, committed: Value) -> ProofResult {
    ProofResult {
        proof: encode(&public),
        name: name.into(),
        version: Some("0.21.1".into()),
        vkey_hash: None,
        committed_inputs: Some(json!({ name: committed })),
    }
}

/// A disclosure proof whose parameter commitment matches `committed`, unless that cannot be computed.
fn disclosure(name: &str, committed: Value, chained: &BigUint, nullifier_type: u64) -> ProofResult {
    let public = |param: BigUint| {
        vec![chained.clone(), big(DATE), scope_hash(Some(DOMAIN)), big(0), param, big(nullifier_type), big(NULLIFIER), big(0)]
    };
    let draft = result(name, public(big(0)), committed.clone());
    let param = parameters(&parse(&draft).unwrap()).unwrap_or(big(1));
    result(name, public(param), committed)
}

fn mrz() -> Vec<u8> {
    let line1 = format!("{:<<44}", "P<TWNLIN<<MEI<HUA");
    let line2 = format!("{:<<44}", "A123456784TWN9001011F3001012");
    let mut b = format!("{line1}{line2}").into_bytes();
    b.resize(90, 0);
    b
}

fn mask(ranges: &[(usize, usize)]) -> Vec<u8> {
    let mut m = vec![0u8; 90];
    for (a, b) in ranges {
        m[*a..*b].iter_mut().for_each(|x| *x = 1);
    }
    m
}

fn disclose(ranges: &[(usize, usize)]) -> Value {
    let m = mask(ranges);
    let bytes: Vec<u8> = mrz().iter().zip(&m).map(|(b, k)| b * k).collect();
    json!({ "discloseMask": m, "disclosedBytes": bytes })
}

struct Case {
    proofs: Vec<ProofResult>,
    query: Value,
}

fn case(nullifier_type: u64) -> Case {
    let (c1, c2, c3) = (big(11), big(22), big(33));
    let proofs = vec![
        result("data_check_integrity_sa_sha256_dg_sha256", vec![c2.clone(), c3.clone()], Value::Null),
        result("sig_check_dsc_tbs_700_rsa_pkcs_2048_sha256", vec![big(ROOT), c1.clone()], Value::Null),
        result("sig_check_id_data_tbs_700_ecdsa_nist_p256_sha256", vec![c1, c2], Value::Null),
        disclosure("disclose_bytes", disclose(&[(0, 2), (2, 5), (5, 44)]), &c3, nullifier_type),
        disclosure("compare_age", json!({ "minAge": 18, "maxAge": 0 }), &c3, nullifier_type),
        disclosure("inclusion_check_nationality", json!({ "countries": ["TWN", "JPN"] }), &c3, nullifier_type),
        disclosure("exclusion_check_issuing_country", json!({ "countries": ["CHN", "PRK"] }), &c3, nullifier_type),
        disclosure(
            "bind",
            json!({ "data": { "user_address": "0x5e4B11F7B7995F5Cee0134692a422b045091112F", "custom_data": "email:test@test.com" } }),
            &c3,
            nullifier_type,
        ),
    ];
    let query = json!({
        "document_type": { "disclose": true },
        "issuing_country": { "disclose": true, "out": ["PRK", "CHN"] },
        "fullname": { "disclose": true },
        "age": { "gte": 18 },
        "nationality": { "in": ["JPN", "TWN"] },
        "bind": { "user_address": "0x5e4b11f7b7995f5cee0134692a422b045091112f", "custom_data": "email:test@test.com" },
    });
    Case { proofs, query }
}

fn request(c: &Case) -> Request {
    let (vkey, hash) = age_vkey();
    let names: Vec<String> = c.proofs.iter().map(|p| p.name.clone()).collect();
    let mut leaves: Vec<BigUint> = names.iter().map(|_| field(&hash).unwrap()).collect();
    leaves.sort();
    let root = hex32(&merkle_root(CIRCUIT_REGISTRY_HEIGHT, &leaves));
    let circuits: Map<String, Value> = names.iter().map(|n| (n.clone(), json!({ "hash": hash }))).collect();
    Request {
        proofs: c.proofs.clone(),
        query: c.query.clone(),
        domain: DOMAIN.into(),
        scope: None,
        dev_mode: false,
        validity: None,
        today: DATE as i64 + 3600,
        manifest: json!({ "version": "0.21.1", "root": root, "circuits": circuits }),
        vkeys: names.iter().map(|n| (n.clone(), vkey.clone())).collect(),
        certificate_root: hex32(&big(ROOT)),
        certificate_root_valid: true,
        circuit_root: root,
        circuit_root_valid: true,
        oprf_public_key_hash: None,
        facematch: None,
    }
}

fn run(req: &Request) -> (Value, usize) {
    let mut calls = 0;
    let out = verify(req, |vk, proof, public| {
        assert!(!vk.is_empty() && proof.len() == 128 && public.len() % 32 == 0);
        calls += 1;
        Ok(())
    });
    (out, calls)
}

fn errors(v: &Value) -> Vec<String> {
    v["errors"].as_array().unwrap().iter().map(|e| e.as_str().unwrap().to_string()).collect()
}

#[test]
fn scope_hashes_match_the_sdk() {
    assert_eq!(scope_hash(Some("demo.zkpassport.id")).to_str_radix(10), "128330325144884284706938150448666378461583566986604316337488678296895397668");
    assert_eq!(scope_hash(Some("bank.example.com:proof-of-age")).to_str_radix(10), "438076640478808858432993215079388181904956329822587278389590507144809552744");
    assert_eq!(scope_hash(Some("")), big(0));
    assert_eq!(scope_hash(None), big(0));
}

#[test]
fn packaged_key_hashes_to_its_registry_leaf() {
    let (vkey, hash) = age_vkey();
    let bytes = base64::engine::general_purpose::STANDARD.decode(vkey).unwrap();
    assert_eq!(bytes.len(), 3680);
    assert_eq!(hex32(&vkey_hash(&bytes)), hash);
}

#[test]
fn published_manifest_hashes_to_the_registry_root() {
    let mut text = String::new();
    flate2::read::GzDecoder::new(&fixture("manifest-0.21.1.json.gz")[..]).read_to_string(&mut text).unwrap();
    let mut manifest: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(circuit_root(&manifest).unwrap(), "0x070d61a69d948675774a2f56fdba0bd4ffede26308b468348762d1dc4c34b69d");
    manifest["circuits"]["compare_age"]["hash"] = json!("0x01");
    assert_eq!(circuit_root(&manifest).unwrap_err(), "manifest_root");
}

#[test]
fn bound_data_matches_the_sdk_encoding() {
    let data = format_bound(&json!({ "user_address": "0x5e4B11F7B7995F5Cee0134692a422b045091112F", "custom_data": "email:test@test.com" })).unwrap();
    let mut expected = vec![1, 0, 20, 94, 75, 17, 247, 183, 153, 95, 92, 238, 1, 52, 105, 42, 66, 43, 4, 80, 145, 17, 47, 3, 0, 19];
    expected.extend(b"email:test@test.com");
    assert_eq!(data, expected);
    assert!(format_bound(&json!({ "chain": "ethereum" })).is_none());
}

#[test]
fn valid_bundle_verifies_and_reports_only_proven_values() {
    let c = case(0);
    let (out, calls) = run(&request(&c));
    assert_eq!(errors(&out), Vec::<String>::new());
    assert_eq!(out["verified"], json!(true));
    assert_eq!(calls, 8);
    assert_eq!(out["names"][0], json!("sig_check_dsc_tbs_700_rsa_pkcs_2048_sha256"));
    assert_eq!(out["uniqueIdentifier"], json!(NULLIFIER.to_string()));
    assert_eq!(out["uniqueIdentifierType"], json!("NON_SALTED"));
    let d = &out["disclosed"];
    assert_eq!(d["documentCode"], json!("P"));
    assert_eq!(d["issuingCountry"], json!("TWN"));
    assert_eq!(d["lastName"], json!("LIN"));
    assert_eq!(d["givenNames"], json!("MEI HUA"));
    assert_eq!(d["layout"], json!("td3"));
    assert!(d.get("documentNumber").is_none() && d.get("birthdate").is_none());
    assert_eq!(out["conditions"]["compare_age"]["minAge"], json!(18));
    let info = inspect(&c.proofs).unwrap();
    assert_eq!(info["certificateRoot"], json!(hex32(&big(ROOT))));
    assert_eq!(info["timestamp"], json!(DATE));
}

#[test]
fn every_check_rejects_its_tampering() {
    let expect = |req: Request, error: &str| {
        let (out, calls) = run(&req);
        assert_eq!(out["verified"], json!(false), "{error}");
        assert!(errors(&out).iter().any(|e| e.starts_with(error)), "{error}: {:?}", errors(&out));
        assert_eq!(calls, 0, "{error}");
        assert!(out["uniqueIdentifier"].is_null());
    };
    let base = case(0);

    let mut r = request(&base);
    r.domain = "evil.example.org".into();
    expect(r, "scope:disclose_bytes");

    let mut r = request(&base);
    r.scope = Some("other".into());
    expect(r, "scope:");

    let mut r = request(&base);
    r.today = DATE as i64 + DEFAULT_VALIDITY as i64;
    expect(r, "date_expired:");

    let mut r = request(&base);
    r.today = DATE as i64 - 2 * 86_400;
    expect(r, "date_future:");

    let mut r = request(&base);
    r.certificate_root_valid = false;
    expect(r, "certificate_root");

    let mut r = request(&base);
    r.certificate_root = hex32(&big(ROOT + 1));
    expect(r, "certificate_root_mismatch");

    let mut r = request(&base);
    r.circuit_root_valid = false;
    expect(r, "circuit_root");

    let mut r = request(&base);
    r.manifest["circuits"]["compare_age"]["hash"] = json!("0x02");
    expect(r, "manifest_root");

    let mut r = request(&base);
    let other = r.vkeys["compare_age"].replacen('A', "B", 1);
    r.vkeys.insert("compare_age".into(), other);
    expect(r, "vkey:compare_age");

    let mut r = request(&base);
    r.query["age"] = json!({ "gte": 20 });
    expect(r, "query:age");

    let mut r = request(&base);
    r.query["nationality"] = json!({ "in": ["TWN"] });
    expect(r, "query:nationality");

    let mut r = request(&base);
    r.query["document_number"] = json!({ "disclose": true });
    expect(r, "query:document_number");

    let mut r = request(&base);
    r.query["birthdate"] = json!({ "gte": 1 });
    expect(r, "query_unsupported:birthdate");

    let mut r = request(&base);
    r.query["bind"]["custom_data"] = json!("email:other@test.com");
    expect(r, "query:bind");

    // Committed inputs that differ from what the proof committed to.
    let mut c = case(0);
    c.proofs[4].committed_inputs = Some(json!({ "compare_age": { "minAge": 21, "maxAge": 0 } }));
    let mut r = request(&c);
    r.query["age"] = json!({ "gte": 21 });
    expect(r, "parameters:compare_age");

    // An exclusion list that is not ascending.
    let mut c = case(0);
    c.proofs[6] = disclosure("exclusion_check_issuing_country", json!({ "countries": ["PRK", "CHN"] }), &big(33), 0);
    expect(request(&c), "parameters:exclusion_check_issuing_country");

    // A broken commitment chain.
    let mut c = case(0);
    c.proofs[5] = disclosure("inclusion_check_nationality", json!({ "countries": ["TWN", "JPN"] }), &big(34), 0);
    expect(request(&c), "commitment:inclusion_check_nationality");

    // Mock documents only in development mode.
    expect(request(&case(2)), "mock");
    let mut r = request(&case(2));
    r.dev_mode = true;
    assert_eq!(run(&r).0["verified"], json!(true));

    // Salted identifiers need the accepted OPRF key.
    expect(request(&case(1)), "oprf_key");

    // Disagreeing identifiers.
    let mut c = case(0);
    c.proofs[4] = disclosure("compare_age", json!({ "minAge": 18, "maxAge": 0 }), &big(33), 1);
    expect(request(&c), "nullifier_mismatch");

    // Missing proofs and unknown circuits.
    let mut c = case(0);
    c.proofs.remove(1);
    let (out, _) = run(&request(&c));
    assert_eq!(errors(&out), vec!["missing:sig_check_dsc".to_string()]);
    let mut c = case(0);
    c.proofs.push(result("compare_birthdate", vec![big(0); 8], Value::Null));
    assert_eq!(errors(&run(&request(&c)).0), vec!["unsupported:compare_birthdate".to_string()]);
}

#[test]
fn barretenberg_failure_stops_verification() {
    let req = request(&case(0));
    let mut calls = 0;
    let out = verify(&req, |_, _, _| {
        calls += 1;
        if calls == 2 { Err("rejected".into()) } else { Ok(()) }
    });
    assert_eq!(calls, 2);
    assert_eq!(out["verified"], json!(false));
    assert_eq!(errors(&out), vec!["proof:sig_check_id_data_tbs_700_ecdsa_nist_p256_sha256:rejected".to_string()]);
}

#[test]
fn identity_card_layout_reads_its_own_fields() {
    let mut zone = format!("{:<<30}", "IDTWNA123456784").into_bytes();
    zone.extend(format!("{:<<30}", "9001011F3001012TWN").bytes());
    zone.extend(format!("{:<<30}", "CHEN<<YI<TING").bytes());
    let m = mask(&[(0, 2), (2, 5), (30, 36), (45, 48), (60, 90)]);
    let bytes: Vec<u8> = zone.iter().zip(&m).map(|(b, k)| b * k).collect();
    let d = Disclosed::new(&json!({ "discloseMask": m, "disclosedBytes": bytes })).unwrap();
    let v = d.values();
    assert_eq!(v["layout"], json!("td1"));
    assert_eq!(v["documentCode"], json!("ID"));
    assert_eq!(v["birthdate"], json!("900101"));
    assert_eq!(v["nationality"], json!("TWN"));
    assert_eq!(v["lastName"], json!("CHEN"));
    assert_eq!(v["givenNames"], json!("YI TING"));
    assert!(d.covers("nationality") && !d.covers("document_number"));
}

/// The mock passport of zkPassport's own bb 6.0.0 proof fixture (packages/aztec/test-harness): its disclose
/// mask, disclosed bytes and the parameter commitment the circuit produced for them.
#[test]
fn disclose_commitment_matches_a_real_circuit_output() {
    let mask: Vec<u8> = "111111111111111111111111111111111111111111111111111110111111111011111110000000000000000000"
        .bytes()
        .map(|b| b - b'0')
        .collect();
    let mut bytes = b"P<AUSSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567".to_vec();
    bytes.push(0);
    bytes.extend(b"AUS881112");
    bytes.push(0);
    bytes.extend(b"M600101");
    bytes.resize(90, 0);
    let p = Proof {
        name: "disclose_bytes".into(),
        rank: 3,
        public: vec![],
        public_bytes: vec![],
        body: vec![],
        committed: json!({ "discloseMask": mask, "disclosedBytes": bytes }),
        vkey_hash: None,
    };
    assert_eq!(hex32(&parameters(&p).unwrap()), "0x0d9b28951df317e973975cd74ecffd626d07d5a0e19eed6d19612bb70f32862b");
    let d = Disclosed::new(&p.committed).unwrap().values();
    assert_eq!(d["givenNames"], json!("JOHNNY"));
    assert_eq!(d["birthdate"], json!("881112"));
    assert_eq!(d["expiryDate"], json!("600101"));
    assert_eq!(d["documentNumber"], json!("PA1234567"));
}

/// The mainnet certificate package of 2026-11 (its serialised tree left out) hashes to the root the registry
/// published for it, and changing one key changes the root.
#[test]
fn published_certificates_hash_to_the_registry_root() {
    let mut text = String::new();
    flate2::read::GzDecoder::new(&fixture("certificates-1398607f.json.gz")[..]).read_to_string(&mut text).unwrap();
    let out: Value = serde_json::from_str(&certificates::package_json(&text).unwrap()).unwrap();
    assert_eq!(out["root"], json!("0x1398607f65ee117db9e7de8a9a91e0c7bbe157d431c4cb2dcf764be3b1a101c2"));
    let keys = out["certificates"].as_array().unwrap();
    assert_eq!(keys.len(), 614);
    assert!(keys.iter().any(|k| k["country"] == json!("JPN")));
    let mut package: Value = serde_json::from_str(&text).unwrap();
    package["certificates"][0]["country"] = json!("ZZZ");
    assert_ne!(hex32(&certificates::root(&package).unwrap()), out["root"].as_str().unwrap());
    package["version"] = json!(2);
    assert_eq!(certificates::root(&package).unwrap_err(), "certificates_version");
}

// ---- FaceMatch --------------------------------------------------------------------------------------------

const FIXTURE_APP: &str = "diw.wallet.fixture";
const FIXTURE_SIGNER: &str = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11";
const FIXTURE_ROOT: u64 = 0x4242;

/// A FaceMatch proof chained to the case's documents whose commitment is `commitment`.
fn face(name: &str, committed: Value, commitment: BigUint, nullifier_type: u64) -> ProofResult {
    let public = vec![big(33), big(DATE), scope_hash(Some(DOMAIN)), big(0), commitment, big(nullifier_type), big(0), big(0)];
    ProofResult {
        proof: encode(&public),
        name: name.into(),
        version: Some("0.21.1".into()),
        vkey_hash: None,
        committed_inputs: Some(json!({ "facematch": committed })),
    }
}

fn face_commitment(root: BigUint, environment: u64, app: BigUint, fourth: BigUint, mode: u64) -> BigUint {
    poseidon2_hash(&[big(10), big(5), root, big(environment), app, fourth, big(mode)])
}

fn key_attested(environment: &str, code: u64, mode: &str) -> ProofResult {
    let signer = hex::decode(FIXTURE_SIGNER).unwrap();
    face(
        "diw_facematch_keyattest_rk_ecdsa_ik_p384_sha384",
        json!({ "mode": mode, "environment": environment, "rootKeyLeaf": hex32(&big(FIXTURE_ROOT)), "appId": FIXTURE_APP, "signerDigest": FIXTURE_SIGNER }),
        face_commitment(big(FIXTURE_ROOT), code, zk::hash_packed(FIXTURE_APP.as_bytes()), zk::hash_packed(&signer), if mode == "strict" { 2 } else { 1 }),
        4,
    )
}

fn self_declared(mode: &str) -> ProofResult {
    face(
        "diw_facematch_self",
        json!({ "mode": mode, "appId": FIXTURE_APP }),
        face_commitment(big(0), 0, zk::hash_packed(FIXTURE_APP.as_bytes()), big(0), if mode == "strict" { 2 } else { 1 }),
        4,
    )
}

fn policy(accept: &[&str]) -> FaceMatchPolicy {
    FaceMatchPolicy {
        accept: accept.iter().map(|a| a.to_string()).collect(),
        apps: vec![FaceMatchApp { app_id: FIXTURE_APP.into(), signers: vec![FIXTURE_SIGNER.to_uppercase()] }],
        allow_self_signed: false,
        roots: vec![hex32(&big(FIXTURE_ROOT))],
    }
}

/// The case with a FaceMatch proof and the query asking for `asked`. This project's circuits are pinned in the
/// build, so the fixture key cannot hash to them: their key error is expected and removed.
fn face_run(proof: ProofResult, asked: &str, policy: Option<FaceMatchPolicy>, dev_mode: bool) -> (Value, Vec<String>) {
    let mut c = case(0);
    let name = proof.name.clone();
    c.proofs.push(proof);
    c.query["facematch"] = json!({ "mode": asked });
    let mut req = request(&c);
    req.facematch = policy;
    req.dev_mode = dev_mode;
    let (out, _) = run(&req);
    let own = format!("vkey:{name}");
    let errors = errors(&out).into_iter().filter(|e| !(name.starts_with("diw_") && *e == own)).collect();
    (out, errors)
}

#[test]
fn packed_hashes_match_the_circuits() {
    // The official app ids, whose hashes the SDK publishes.
    assert_eq!(hex32(&zk::hash_packed(b"app.zkpassport.zkpassport")), "0x24d9929b248be7eeecaa98e105c034a50539610f3fdd4cb9c8983ef4100d615d");
    assert_eq!(hex32(&zk::hash_packed(b"YL5MS3Z639.app.zkpassport.zkpassport")), "0x1fa73686cf510f8f85757b0602de0dd72a13e68ae2092462be8b72662e7f179b");
    // Google's attestation roots (android.googleapis.com/attestation/root): registry leaf of key type 2.
    let keys: Value = serde_json::from_slice(&fixture("google-attestation-root-keys.json")).unwrap();
    let leaf = |kind: &str| {
        let mut bytes = vec![2u8];
        bytes.extend(hex::decode(keys[kind].as_str().unwrap()).unwrap());
        hex32(&zk::hash_packed(&bytes))
    };
    assert_eq!(leaf("rsa"), "0x16700a2d9168a194fc85f237af5829b5a2be05b8ae8ac4879ada34cf54a9c211");
    assert_eq!(leaf("p384"), "0x0e1889bec6c1d686abcf08360ff404f803ab345881ea8cba6aad33b7f7f7ffe0");
}

#[test]
fn pinned_circuits_are_listed() {
    let list: Value = serde_json::from_str(diw_circuits_json()).unwrap();
    let circuits = list["circuits"].as_object().unwrap();
    assert!(circuits.contains_key("diw_facematch_self"));
    assert!(circuits.iter().all(|(name, hash)| facematch::kind(name).is_some_and(|k| k != facematch::Kind::Official)
        && hash.as_str().and_then(field).is_some()));
    assert_eq!(facematch::kind("facematch_ios"), Some(facematch::Kind::Official));
    assert_eq!(facematch::kind("facematch_android_rk_rsa_ik_count_1_ik_ecdsa_p256_sha256_evm"), None);
}

#[test]
fn facematch_kinds_follow_the_policy() {
    // Self-declared: accepted only when the verifier says so, and reported as such.
    let (out, e) = face_run(self_declared("regular"), "regular", Some(policy(&["self"])), false);
    assert!(e.is_empty(), "{e:?}");
    assert_eq!(out["facematch"]["kind"], "self");
    assert_eq!(out["facematch"]["appId"], FIXTURE_APP);
    assert_eq!(out["facematch"]["environment"], "development");
    assert!(out["facematch"].get("rootKeyLeaf").is_none());
    // The bundle's identifier still comes from the other proofs.
    assert_eq!(out["uniqueIdentifierType"], "NON_SALTED");
    assert_eq!(face_run(self_declared("regular"), "regular", None, false).1, vec!["facematch_level:self"]);
    assert_eq!(face_run(self_declared("regular"), "regular", Some(policy(&["official", "keyattest"])), false).1, vec!["facematch_level:self"]);

    // Key attestation: the root, the app and the boot state are the verifier's to accept.
    let (out, e) = face_run(key_attested("production", 1, "strict"), "strict", Some(policy(&["keyattest"])), false);
    assert!(e.is_empty(), "{e:?}");
    assert_eq!(out["facematch"]["kind"], "keyattest");
    assert_eq!(out["facematch"]["signerDigest"], FIXTURE_SIGNER);
    assert_eq!(out["facematch"]["mode"], "strict");
    let mut other_root = policy(&["keyattest"]);
    other_root.roots.clear();
    assert_eq!(face_run(key_attested("production", 1, "regular"), "regular", Some(other_root), false).1, vec!["facematch_root"]);
    let mut other_app = policy(&["keyattest"]);
    other_app.apps[0].signers = vec!["bb".repeat(32)];
    assert_eq!(face_run(key_attested("production", 1, "regular"), "regular", Some(other_app), false).1, vec!["facematch_app"]);
    let mut no_apps = policy(&["keyattest"]);
    no_apps.apps.clear();
    assert_eq!(face_run(key_attested("production", 1, "regular"), "regular", Some(no_apps), false).1, vec!["facematch_app"]);
    assert_eq!(face_run(key_attested("self_signed", 2, "regular"), "regular", Some(policy(&["keyattest"])), false).1, vec!["facematch_environment"]);
    let mut own_system = policy(&["keyattest"]);
    own_system.allow_self_signed = true;
    let (out, e) = face_run(key_attested("self_signed", 2, "regular"), "regular", Some(own_system), false);
    assert!(e.is_empty(), "{e:?}");
    assert_eq!(out["facematch"]["environment"], "self_signed");
    assert_eq!(face_run(key_attested("development", 0, "regular"), "regular", Some(policy(&["keyattest"])), false).1, vec!["facematch_environment"]);
    assert!(face_run(key_attested("development", 0, "regular"), "regular", Some(policy(&["keyattest"])), true).1.is_empty());
    // A claimed environment the proof does not commit to.
    assert_eq!(
        face_run(key_attested("production", 0, "regular"), "regular", Some(policy(&["keyattest"])), false).1,
        vec!["parameters:diw_facematch_keyattest_rk_ecdsa_ik_p384_sha384"]
    );
}

#[test]
fn official_facematch_follows_the_sdk() {
    let android = |environment: &str, code: u64| {
        let app = field("0x24d9929b248be7eeecaa98e105c034a50539610f3fdd4cb9c8983ef4100d615d").unwrap();
        let root = field("0x16700a2d9168a194fc85f237af5829b5a2be05b8ae8ac4879ada34cf54a9c211").unwrap();
        let play: BigUint = "8544227306600425492560068004835614964118871262589609739238120993689090208159".parse().unwrap();
        face(
            "facematch_android_rk_rsa_ik_count_1_ik_ecdsa_p256_sha256",
            json!({ "mode": "regular", "environment": environment, "rootKeyLeaf": hex32(&root), "appIdHash": hex32(&app) }),
            face_commitment(root, code, app, play, 1),
            0,
        )
    };
    // Accepted without a policy; its own identifier does not have to be the bundle's.
    let (out, e) = face_run(android("production", 1), "regular", None, false);
    assert!(e.is_empty(), "{e:?}");
    assert_eq!(out["facematch"]["kind"], "official");
    assert_eq!(out["facematch"]["platform"], "android");
    assert_eq!(face_run(android("development", 0), "regular", None, false).1, vec!["facematch_environment"]);
    assert!(face_run(android("development", 0), "regular", None, true).1.is_empty());
    assert_eq!(face_run(android("production", 1), "regular", Some(policy(&["keyattest", "self"])), false).1, vec!["facematch_level:official"]);

    let ios = |app: &str| {
        let app = field(app).unwrap();
        let root = field("0x2532418a107c5306fa8308c22255792cf77e4a290cbce8a840a642a3e591340b").unwrap();
        face(
            "facematch_ios",
            json!({ "mode": "strict", "environment": "production", "rootKeyLeaf": hex32(&root), "appIdHash": hex32(&app) }),
            face_commitment(root, 1, app, big(0), 2),
            0,
        )
    };
    let (out, e) = face_run(ios("0x1fa73686cf510f8f85757b0602de0dd72a13e68ae2092462be8b72662e7f179b"), "strict", None, false);
    assert!(e.is_empty(), "{e:?}");
    assert_eq!(out["facematch"]["platform"], "ios");
    // Another app under Apple's root, and a mode the verifier did not ask for.
    assert_eq!(face_run(ios("0x1234"), "strict", None, false).1, vec!["facematch_app"]);
    assert_eq!(face_run(ios("0x1fa73686cf510f8f85757b0602de0dd72a13e68ae2092462be8b72662e7f179b"), "regular", None, false).1, vec!["query:facematch"]);
}

#[test]
fn facematch_is_bound_to_the_bundle() {
    // Asked for but not proven, and an unknown mode.
    let mut c = case(0);
    c.query["facematch"] = json!({ "mode": "regular" });
    assert_eq!(errors(&run(&request(&c)).0), vec!["query:facematch"]);
    assert_eq!(face_run(self_declared("regular"), "lenient", Some(policy(&["self"])), false).1, vec!["query:facematch"]);
    // A FaceMatch of another document: the commitment chain breaks.
    let mut other = self_declared("regular");
    let mut public = vec![big(34), big(DATE), scope_hash(Some(DOMAIN)), big(0)];
    public.push(face_commitment(big(0), 0, zk::hash_packed(FIXTURE_APP.as_bytes()), big(0), 1));
    public.extend([big(4), big(0), big(0)]);
    other.proof = encode(&public);
    assert_eq!(face_run(other, "regular", Some(policy(&["self"])), false).1, vec!["commitment:diw_facematch_self"]);
    // A mock document shows in the FaceMatch proof even when nothing else carries an identifier.
    let mut mock = self_declared("regular");
    public[0] = big(33);
    public[5] = big(2);
    mock.proof = encode(&public);
    assert_eq!(face_run(mock.clone(), "regular", Some(policy(&["self"])), false).1, vec!["mock"]);
    assert!(face_run(mock, "regular", Some(policy(&["self"])), true).1.is_empty());
    // Two FaceMatch proofs in one bundle.
    let mut c = case(0);
    c.proofs.push(self_declared("regular"));
    c.proofs.push(key_attested("production", 1, "regular"));
    assert_eq!(errors(&run(&request(&c)).0), vec!["duplicate"]);
}
