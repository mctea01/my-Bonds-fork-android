//! FaceMatch for the wallet's own zkPassport answers, with this project's circuits (native/circuits-zkpassport):
//! the statement an Android keystore key signs, and the circuit inputs for the key attestation and self-declared
//! circuits. The document part of the inputs is zkPassport's disclosure prologue from the vendored input
//! generation, with the private nullifier hidden: a FaceMatch proof never carries the holder's identifier.
use crate::ZkError;

#[cfg(feature = "zkpdf")]
mod build {
    use base64::Engine;
    use num_bigint::BigUint;
    use serde_json::{json, Map, Value};
    use zkpassport_core::bytes::{left_pad_with_zeros, right_pad_with_zeros};
    use zkpassport_core::commitments::{
        calculate_private_nullifier, hash_salt_dg1_dg2_hash_private_nullifier, normalize_dg2_hash, salted_value_hash_scalar,
    };
    use zkpassport_core::der::{Reader, Tlv};
    use zkpassport_core::disclosure::hash_algorithm_id_from_length;
    use zkpassport_core::facematch::{build_facematch_client_data, pack_and_hash_poseidon2};
    use zkpassport_core::input_gen::{
        expiry_from_mrz, hash_data_group, mrz_from_dg1, processed_sod_signature, scope_hash, InputGenSalts,
    };
    use zkpassport_core::integrity::{DG1_INPUT_SIZE, E_CONTENT_INPUT_SIZE};
    use zkpassport_core::poseidon2::poseidon2_hash;
    use zkpassport_core::signature::process_ecdsa_signature;
    use zkpassport_core::sod::parse_sod;

    /// The self-declared circuit, small enough to ship in the library.
    const SELF_CIRCUIT: &str = include_str!("../../circuits-zkpassport/artifacts/diw_facematch_self.json");
    const SELF: &str = "diw_facematch_self";
    const KEY_ATTESTATION: &str = "diw_facematch_keyattest_";
    // Sizes of the circuits' inputs (lib/facematch constants and tools/keyattest.py).
    const INTERMEDIATE_TBS_MAX: usize = 700;
    const CREDENTIAL_TBS_MAX: usize = 1000;
    const CLIENT_DATA_MAX: usize = 169;
    const APP_ID_MAX: usize = 100;
    const P256_ORDER: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    const P384_ORDER: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";

    type Res<T> = Result<T, String>;

    fn text<'a>(request: &'a Value, key: &str) -> Res<&'a str> {
        request.get(key).and_then(Value::as_str).ok_or_else(|| format!("request_{key}"))
    }

    fn b64(value: &str, what: &str) -> Res<Vec<u8>> {
        base64::engine::general_purpose::STANDARD.decode(value).map_err(|_| format!("request_{what}"))
    }

    fn hex_min(x: &BigUint) -> String {
        format!("0x{x:x}")
    }

    fn hex32(x: &BigUint) -> String {
        format!("0x{x:064x}")
    }

    fn mode(request: &Value) -> Res<u8> {
        match text(request, "mode")? {
            "regular" => Ok(1),
            "strict" => Ok(2),
            _ => Err("request_mode".into()),
        }
    }

    /// The DG2 hash the security object lists. When the photo file is given it must hash to it, so the photo
    /// the wallet compared is the one the proofs are about.
    fn dg2_hash(request: &Value, sod: &[u8]) -> Res<Vec<u8>> {
        let parsed = parse_sod(sod).map_err(|_| "sod".to_string())?;
        let listed = parsed.dg_hashes.iter().find(|(n, _)| *n == 2).map(|(_, h)| h.clone()).ok_or("dg2_hash")?;
        if let Some(dg2) = request.get("dg2").and_then(Value::as_str) {
            let hashed = hash_data_group(&b64(dg2, "dg2")?, &parsed.dg_hash_alg).map_err(|_| "dg2_hash".to_string())?;
            if hashed != listed {
                return Err("dg2_mismatch".into());
            }
        }
        Ok(listed)
    }

    /// zkPassport's disclosure prologue for this document, without the private nullifier.
    fn prologue(request: &Value) -> Res<Map<String, Value>> {
        let sod = b64(text(request, "sod")?, "sod")?;
        let dg1 = b64(text(request, "dg1")?, "dg1")?;
        let parsed = parse_sod(&sod).map_err(|_| "sod".to_string())?;
        let dg2_hash = dg2_hash(request, &sod)?;
        let master: BigUint = text(request, "salt")?.parse().map_err(|_| "request_salt".to_string())?;
        let salts = InputGenSalts::from_master(master).disclosure;
        let signature = processed_sod_signature(&parsed).map_err(|_| "sod".to_string())?;
        let mrz = mrz_from_dg1(&dg1).map_err(|_| "dg1".to_string())?;
        let expiry = expiry_from_mrz(&mrz).map_err(|_| "dg1".to_string())?;
        let dg1_padded = right_pad_with_zeros(&dg1, DG1_INPUT_SIZE);
        let e_content = right_pad_with_zeros(&parsed.e_content, E_CONTENT_INPUT_SIZE);
        let dg2_normalized = normalize_dg2_hash(&dg2_hash);
        let dg2_type = hash_algorithm_id_from_length(dg2_hash.len()).map_err(|_| "dg2_hash".to_string())?;
        let private_nullifier = calculate_private_nullifier(&dg1_padded, &e_content, &signature);
        let comm_in =
            hash_salt_dg1_dg2_hash_private_nullifier(&salts, &dg1_padded, &expiry, &dg2_normalized, dg2_type, &private_nullifier);
        let date = request.get("current_date_timestamp").and_then(Value::as_u64).ok_or("request_current_date_timestamp")?;
        let scope = request.get("service_scope").and_then(Value::as_str).unwrap_or("");
        let subscope = request.get("service_subscope").and_then(Value::as_str).unwrap_or("");
        let salted = |value: Value, salt: &BigUint| json!({ "value": value, "salt": hex_min(salt), "hash": "0x0" });
        let comm = format!("{comm_in:x}");
        let inputs = json!({
            "comm_in": format!("0x{}{comm}", if comm.len() % 2 == 1 { "0" } else { "" }),
            "current_date": date,
            // Only its salted hash: the circuit then returns no scoped nullifier.
            "salted_private_nullifier": {
                "value": "0x0",
                "salt": "0x0",
                "hash": hex_min(&salted_value_hash_scalar(&salts.private_nullifier_salt, &private_nullifier)),
            },
            "salted_expiry_date": salted(json!(expiry.as_bytes()), &salts.expiry_date_salt),
            "salted_dg1": salted(json!(dg1_padded), &salts.dg1_salt),
            "salted_dg2_hash": salted(json!(hex_min(&dg2_normalized)), &salts.dg2_hash_salt),
            "salted_dg2_hash_type": salted(json!(hex_min(&BigUint::from(dg2_type))), &salts.dg2_hash_salt),
            "nullifier_secret": "0x0",
            "service_scope": hex_min(&scope_hash(scope)),
            "service_subscope": hex_min(&scope_hash(subscope)),
        });
        match inputs {
            Value::Object(map) => Ok(map),
            _ => Err("inputs".into()),
        }
    }

    fn hash_packed(bytes: &[u8]) -> BigUint {
        BigUint::from_bytes_be(&pack_and_hash_poseidon2(bytes))
    }

    fn commitment(root: &BigUint, environment: u8, app: &BigUint, fourth: &BigUint, mode: u8) -> String {
        let n = |v: u64| BigUint::from(v);
        hex32(&poseidon2_hash(&[n(10), n(5), root.clone(), n(environment.into()), app.clone(), fourth.clone(), n(mode.into())]))
    }

    /// The commitment of the self-declared circuit: no root, no environment, no signer.
    pub fn self_commitment(app_id: &str, mode: u8) -> String {
        let zero = BigUint::from(0u8);
        commitment(&zero, 0, &hash_packed(app_id.as_bytes()), &zero, mode)
    }

    fn app_id(request: &Value) -> Res<&str> {
        let id = text(request, "app_id")?;
        if id.is_empty() || id.len() > APP_ID_MAX {
            return Err("request_app_id".into());
        }
        Ok(id)
    }

    /// The statement the keystore key signs: zkPassport's `ZKPassportAppAttest` for a face comparison, and the
    /// 32 bytes to sign with SHA256withECDSA.
    pub fn statement(request: &Value) -> Res<Value> {
        let sod = b64(text(request, "sod")?, "sod")?;
        let digest = dg2_hash(request, &sod)?;
        let embedding = request.get("embedding").and_then(Value::as_array).filter(|e| !e.is_empty()).ok_or("request_embedding")?;
        let mut floats = Vec::with_capacity(embedding.len() * 4);
        for value in embedding {
            let x = value.as_f64().filter(|x| x.is_finite()).ok_or("request_embedding")? as f32;
            floats.extend_from_slice(&(if x == 0.0 { 0.0f32 } else { x }).to_be_bytes());
        }
        let number = |key: &str| request.get(key).and_then(Value::as_i64).ok_or_else(|| format!("request_{key}"));
        let data = build_facematch_client_data(
            text(request, "app_version")?,
            mode(request)?,
            &digest,
            &pack_and_hash_poseidon2(&floats),
            number("cosine")?,
            Some(number("threshold")?),
        )
        .map_err(|_| "statement".to_string())?;
        if data.len() > CLIENT_DATA_MAX {
            return Err("statement_size".into());
        }
        let to_sign = left_pad_with_zeros(&pack_and_hash_poseidon2(&data), 32);
        Ok(json!({
            "clientData": base64::engine::general_purpose::STANDARD.encode(&data),
            "toSign": base64::engine::general_purpose::STANDARD.encode(to_sign),
        }))
    }

    enum Key {
        Ec(Vec<u8>),
        Rsa(Vec<u8>),
    }

    struct Certificate<'a> {
        tbs: &'a [u8],
        algorithm: String,
        signature: &'a [u8],
        key: Key,
    }

    fn child<'a>(parent: &Tlv<'a>, index: usize) -> Res<Tlv<'a>> {
        parent.children().map_err(|_| "chain".to_string())?.into_iter().nth(index).ok_or_else(|| "chain".to_string())
    }

    fn certificate(der: &[u8]) -> Res<Certificate<'_>> {
        let bad = |_| "chain".to_string();
        let whole = Reader::new(der).read().map_err(bad)?;
        let tbs = child(&whole, 0)?;
        let algorithm = child(&child(&whole, 1)?, 0)?.as_oid().map_err(bad)?;
        let signature = child(&whole, 2)?.bit_string_bytes().map_err(bad)?;
        let fields = tbs.children().map_err(bad)?;
        let first = usize::from(fields.first().map(|f| f.tag) == Some(0xa0));
        let spki = fields.get(first + 5).ok_or("chain")?;
        let kind = child(&child(spki, 0)?, 0)?.as_oid().map_err(bad)?;
        let bits = child(spki, 1)?.bit_string_bytes().map_err(bad)?;
        let key = match kind.as_str() {
            "1.2.840.10045.2.1" if bits.first() == Some(&4) && (bits.len() == 65 || bits.len() == 97) => Key::Ec(bits[1..].to_vec()),
            "1.2.840.113549.1.1.1" => {
                let pair = Reader::new(bits).read().map_err(bad)?;
                let modulus = child(&pair, 0)?.as_biguint();
                let exponent = child(&pair, 1)?.as_biguint();
                if modulus.bits() != 4096 || exponent != BigUint::from(65537u32) {
                    return Err("chain_unsupported".into());
                }
                Key::Rsa(modulus.to_bytes_be())
            }
            _ => return Err("chain_unsupported".into()),
        };
        Ok(Certificate { tbs: tbs.raw, algorithm, signature, key })
    }

    /// The signature of a certificate as the circuit of its signer reads it, and the digest it was made with.
    fn signed_by(signer: &Key, subject: &Certificate) -> Res<(Vec<u8>, &'static str)> {
        match (signer, subject.algorithm.as_str()) {
            (Key::Rsa(_), "1.2.840.113549.1.1.11") if subject.signature.len() <= 512 => {
                Ok((left_pad_with_zeros(subject.signature, 512), "sha256"))
            }
            (Key::Ec(point), algorithm @ ("1.2.840.10045.4.3.2" | "1.2.840.10045.4.3.3")) => {
                let size = point.len() / 2;
                let order = BigUint::parse_bytes(if size == 32 { P256_ORDER } else { P384_ORDER }.as_bytes(), 16).ok_or("chain")?;
                let raw = process_ecdsa_signature(subject.signature, size, &order);
                if raw.len() != size * 2 {
                    return Err("chain".into());
                }
                Ok((raw, if algorithm.ends_with(".2") { "sha256" } else { "sha384" }))
            }
            _ => Err("chain_unsupported".into()),
        }
    }

    fn padded(bytes: &[u8], size: usize) -> Res<Vec<u8>> {
        if bytes.len() > size {
            return Err("chain_unsupported".into());
        }
        Ok(right_pad_with_zeros(bytes, size))
    }

    /// The circuit and inputs for an attestation chain (leaf first, root last, as the keystore returns it).
    fn key_attestation(request: &Value, inputs: &mut Map<String, Value>) -> Res<(String, Value, Value)> {
        let list = request.get("chain").and_then(Value::as_array).ok_or("request_chain")?;
        let ders = list.iter().map(|c| c.as_str().ok_or("request_chain".to_string()).and_then(|c| b64(c, "chain"))).collect::<Res<Vec<_>>>()?;
        // One to three intermediates between the credential certificate and the root.
        if !(3..=5).contains(&ders.len()) {
            return Err("chain_unsupported".into());
        }
        let certificates = ders.iter().map(|d| certificate(d)).collect::<Res<Vec<_>>>()?;
        let (credential, root) = (&certificates[0], &certificates[certificates.len() - 1]);
        let Key::Ec(credential_key) = &credential.key else { return Err("chain_unsupported".into()) };
        if credential_key.len() != 64 {
            return Err("chain_unsupported".into());
        }
        let (root_kind, root_key) = match &root.key {
            Key::Rsa(modulus) => {
                let redc: BigUint = (BigUint::from(1u8) << (2 * 4096 + 6usize)) / BigUint::from_bytes_be(modulus);
                inputs.insert("root_key_redc_param".into(), json!(left_pad_with_zeros(&redc.to_bytes_be(), 513)));
                ("rsa", modulus.clone())
            }
            Key::Ec(point) if point.len() == 96 => ("ecdsa", point.clone()),
            Key::Ec(_) => return Err("chain_unsupported".into()),
        };
        inputs.insert("root_key".into(), json!(root_key));
        let mut name = format!("{KEY_ATTESTATION}rk_{root_kind}");
        // From the root down: each certificate under the key of the one above it.
        let mut signer = &root.key;
        let intermediates: Vec<&Certificate> = certificates[1..certificates.len() - 1].iter().rev().collect();
        for (i, intermediate) in intermediates.iter().enumerate() {
            let (signature, digest) = signed_by(signer, intermediate)?;
            if i == 0 && digest != if root_kind == "rsa" { "sha256" } else { "sha384" } {
                return Err("chain_unsupported".into());
            }
            let Key::Ec(point) = &intermediate.key else { return Err("chain_unsupported".into()) };
            let below = intermediates.get(i + 1).copied().unwrap_or(credential);
            let (_, next_digest) = signed_by(&intermediate.key, below)?;
            let curve = if point.len() == 64 { "p256" } else { "p384" };
            if curve == "p256" && next_digest != "sha256" {
                return Err("chain_unsupported".into());
            }
            name.push_str(&format!("_ik_{curve}_{next_digest}"));
            let n = i + 1;
            inputs.insert(format!("intermediate_{n}_key"), json!(point));
            inputs.insert(format!("intermediate_{n}_tbs"), json!(padded(intermediate.tbs, INTERMEDIATE_TBS_MAX)?));
            inputs.insert(format!("intermediate_{n}_sig"), json!(signature));
            signer = &intermediate.key;
        }
        let (signature, _) = signed_by(signer, credential)?;
        inputs.insert("credential_key".into(), json!(credential_key));
        inputs.insert("credential_tbs".into(), json!(padded(credential.tbs, CREDENTIAL_TBS_MAX)?));
        inputs.insert("credential_sig".into(), json!(signature));

        let data = b64(text(request, "client_data")?, "client_data")?;
        if data.len() > CLIENT_DATA_MAX {
            return Err("statement_size".into());
        }
        let order = BigUint::parse_bytes(P256_ORDER.as_bytes(), 16).ok_or("chain")?;
        let data_signature = process_ecdsa_signature(&b64(text(request, "signature")?, "signature")?, 32, &order);
        if data_signature.len() != 64 {
            return Err("request_signature".into());
        }
        inputs.insert("client_data".into(), json!(right_pad_with_zeros(&data, CLIENT_DATA_MAX)));
        inputs.insert("client_data_sig".into(), json!(data_signature));

        // What the verifier is told. The app and its signer are the wallet's own; the circuit reads them from
        // the attestation, so a wrong value here only makes the proof's commitment match no environment.
        let id = app_id(request)?;
        let signer_digest = hex::decode(text(request, "signer_digest")?).ok().filter(|d| d.len() == 32).ok_or("request_signer_digest")?;
        let mut leaf_input = vec![2u8];
        leaf_input.extend_from_slice(&root_key);
        let leaf = hash_packed(&leaf_input);
        let (app, signer_hash, mode) = (hash_packed(id.as_bytes()), hash_packed(&signer_digest), mode(request)?);
        let committed = json!({
            "mode": text(request, "mode")?,
            "appId": id,
            "rootKeyLeaf": hex32(&leaf),
            "signerDigest": hex::encode(&signer_digest),
        });
        let environments = json!({
            "production": commitment(&leaf, 1, &app, &signer_hash, mode),
            "self_signed": commitment(&leaf, 2, &app, &signer_hash, mode),
            "development": commitment(&leaf, 0, &app, &signer_hash, mode),
        });
        Ok((name, committed, environments))
    }

    #[cfg(test)]
    pub fn key_attestation_for_tests(request: &Value, inputs: &mut Map<String, Value>) -> Res<(String, Value, Value)> {
        key_attestation(request, inputs)
    }

    /// The circuit name, its inputs, the committed inputs for the verifier and, by environment, the parameter
    /// commitment the proof returns: the caller reads the environment the circuit found from the proof.
    pub fn inputs(request: &Value) -> Res<Value> {
        let mut inputs = prologue(request)?;
        let mode_number = mode(request)?;
        inputs.insert("facematch_mode".into(), json!(mode_number));
        match text(request, "kind")? {
            "self" => {
                let id = app_id(request)?;
                inputs.insert("app_id".into(), json!(right_pad_with_zeros(id.as_bytes(), APP_ID_MAX)));
                inputs.insert("app_id_length".into(), json!(id.len()));
                Ok(json!({
                    "name": SELF,
                    "circuit": SELF_CIRCUIT,
                    "inputs": inputs,
                    "committed": { "mode": text(request, "mode")?, "appId": id },
                    "environments": { "development": self_commitment(id, mode_number) },
                }))
            }
            "keyattest" => {
                let (name, committed, environments) = key_attestation(request, &mut inputs)?;
                Ok(json!({ "name": name, "inputs": inputs, "committed": committed, "environments": environments }))
            }
            _ => Err("request_kind".into()),
        }
    }
}

#[cfg(feature = "zkpdf")]
fn run(request_json: String, work: fn(&serde_json::Value) -> Result<serde_json::Value, String>) -> Result<String, ZkError> {
    crate::run_worker(16 * 1024 * 1024, crate::ZkCancelToken::new(), move |_| {
        let invalid = |reason: String| ZkError::InvalidInput { reason };
        let request = serde_json::from_str(&request_json).map_err(|_| invalid("request_json".into()))?;
        work(&request).map(|v| v.to_string()).map_err(invalid)
    })
}

#[cfg(not(feature = "zkpdf"))]
fn disabled() -> ZkError {
    ZkError::Unsupported { reason: "zkpassport_disabled".into() }
}

/// The verification key hashes of this project's FaceMatch circuits: `{"version", "circuits": {name: hash}}`.
#[uniffi::export]
pub fn zkpassport_facematch_circuits() -> Result<String, ZkError> {
    #[cfg(feature = "zkpdf")]
    {
        Ok(zkpassport_verify::diw_circuits_json().to_string())
    }
    #[cfg(not(feature = "zkpdf"))]
    {
        Err(disabled())
    }
}

/// The statement of a face comparison for the keystore key to sign. The request carries `sod` and optionally
/// `dg2` (base64), `app_version`, `mode` (`regular` or `strict`), the reference `embedding`, and the `cosine`
/// score and `threshold` as integers; the answer `clientData` and the 32 bytes `toSign` (base64).
#[uniffi::export]
pub fn zkpassport_facematch_statement(request_json: String) -> Result<String, ZkError> {
    #[cfg(feature = "zkpdf")]
    {
        run(request_json, build::statement)
    }
    #[cfg(not(feature = "zkpdf"))]
    {
        let _ = request_json;
        Err(disabled())
    }
}

/// The inputs of a FaceMatch circuit for a document. The request carries `kind` (`self` or `keyattest`), the
/// document and service fields of the proof session (`sod`, `dg1`, `dg2`, `salt`, `service_scope`,
/// `service_subscope`, `current_date_timestamp`), `mode` and `app_id`; for `keyattest` also `chain` (base64 DER,
/// leaf first), `client_data`, `signature` and `signer_digest`. The answer names the circuit (and holds the
/// self-declared one), its `inputs`, the `committed` inputs and the commitment per `environments`.
#[uniffi::export]
pub fn zkpassport_facematch_inputs(request_json: String) -> Result<String, ZkError> {
    #[cfg(feature = "zkpdf")]
    {
        run(request_json, build::inputs)
    }
    #[cfg(not(feature = "zkpdf"))]
    {
        let _ = request_json;
        Err(disabled())
    }
}

#[cfg(all(test, feature = "zkpdf"))]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    /// Chains made by native/circuits-zkpassport/tools/keyattest.py (`walletfixture`), with the inputs its own
    /// circuit checks use: the builder must read the same values out of the certificates.
    #[test]
    fn key_attestation_inputs_match_the_circuit_fixtures() {
        let cases: Value = serde_json::from_str(include_str!("../tests/data/keyattest-chains.json")).unwrap();
        for case in cases.as_array().unwrap() {
            let mut request = case.clone();
            request["mode"] = json!("regular");
            let mut inputs = serde_json::Map::new();
            let (name, committed, environments) = build::key_attestation_for_tests(&request, &mut inputs).unwrap();
            assert_eq!(json!(name), case["name"]);
            for (key, expected) in case["inputs"].as_object().unwrap() {
                assert_eq!(inputs.get(key), Some(expected), "{name}: {key}");
            }
            assert_eq!(inputs.len(), case["inputs"].as_object().unwrap().len(), "{name}");
            assert_eq!(committed["appId"], "diw.wallet.fixture");
            let distinct: std::collections::HashSet<&str> =
                environments.as_object().unwrap().values().map(|v| v.as_str().unwrap()).collect();
            assert_eq!(distinct.len(), 3);
            // The verifier, from the committed inputs alone, expects the commitment computed here for each
            // environment: a proof the holder matched to one of them passes the checker's parameter check.
            for (environment, expected) in environments.as_object().unwrap() {
                let mut stated = committed.clone();
                stated["environment"] = json!(environment);
                assert_eq!(zkpassport_verify::facematch_commitment(&name, &stated).as_deref(), expected.as_str(), "{name}: {environment}");
            }

            // A chain in another order, a missing root and a statement signed over other bytes are refused or differ.
            let mut reversed = request.clone();
            reversed["chain"].as_array_mut().unwrap().reverse();
            assert!(build::key_attestation_for_tests(&reversed, &mut serde_json::Map::new()).is_err());
            let mut short = request.clone();
            short["chain"].as_array_mut().unwrap().pop();
            assert!(build::key_attestation_for_tests(&short, &mut serde_json::Map::new()).is_err());
            let mut unsigned = request.clone();
            unsigned["signature"] = json!("AAAA");
            assert_eq!(build::key_attestation_for_tests(&unsigned, &mut serde_json::Map::new()).unwrap_err(), "request_signature");
        }
    }

    #[test]
    fn the_verifier_expects_the_self_declared_commitment() {
        for (mode, number) in [("regular", 1), ("strict", 2)] {
            let stated = json!({ "mode": mode, "appId": "diw.wallet.app" });
            assert_eq!(
                zkpassport_verify::facematch_commitment("diw_facematch_self", &stated),
                Some(build::self_commitment("diw.wallet.app", number))
            );
        }
    }

    #[test]
    fn requests_are_checked_before_any_work() {
        assert!(zkpassport_facematch_circuits().unwrap().contains("diw_facematch_self"));
        for request in ["{", "{}", r#"{"kind":"self","sod":"AA==","dg1":"AA==","mode":"regular","app_id":"a","salt":"1"}"#] {
            assert!(matches!(zkpassport_facematch_inputs(request.into()), Err(ZkError::InvalidInput { .. })));
            assert!(matches!(zkpassport_facematch_statement(request.into()), Err(ZkError::InvalidInput { .. })));
        }
    }
}
