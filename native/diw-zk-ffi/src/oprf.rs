//! The project's own salted unique identifier (docs/design/zkpassport.md 5.5): a single-key OPRF over BabyJubJub
//! with a Chaum-Pedersen proof, computed with TACEO's oprf-core so the values match what zkPassport's disclosure
//! circuits verify. The server holds the key (diw-wallet-server secret) and only ever sees the blinded query; the
//! wallet blinds, checks the proof and unblinds. Field elements travel as 0x hex or decimal strings.
use crate::ZkError;

/// zkPassport's OPRF domain separator (`OPRF_DEFAULT_DOMAIN_SEPARATOR`, matching the oprf-nr library).
pub const DOMAIN_SEPARATOR: u64 = 1_330_664_006;

#[cfg(feature = "oprf")]
mod imp {
    use ark_babyjubjub::{EdwardsAffine as Affine, Fq, Fr};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{PrimeField, Zero};
    use num_bigint::BigUint;
    use serde_json::{json, Value};
    use taceo_oprf_core::dlog_equality::DLogEqualityProof;
    use taceo_oprf_core::oprf::{client, BlindedOprfResponse, BlindingFactor};

    fn number(s: &str) -> Result<BigUint, String> {
        let s = s.trim();
        let parsed = match s.strip_prefix("0x") {
            Some(h) if !h.is_empty() && h.len() <= 64 => BigUint::parse_bytes(h.as_bytes(), 16),
            Some(_) => None,
            None if !s.is_empty() && s.len() <= 78 => BigUint::parse_bytes(s.as_bytes(), 10),
            None => None,
        };
        parsed.ok_or_else(|| "number".to_string())
    }

    fn base(s: &str) -> Result<Fq, String> {
        let n = number(s)?;
        if n >= Fq::MODULUS.into() {
            return Err("field_range".into());
        }
        Ok(Fq::from(n))
    }

    fn scalar(s: &str) -> Result<Fr, String> {
        let n = number(s)?;
        if n >= Fr::MODULUS.into() {
            return Err("scalar_range".into());
        }
        let x = Fr::from(n);
        if x.is_zero() {
            return Err("scalar_zero".into());
        }
        Ok(x)
    }

    fn hex<F: PrimeField>(f: F) -> String
    where
        BigUint: From<F>,
    {
        format!("0x{:x}", BigUint::from(f))
    }

    fn point_json(p: Affine) -> Value {
        json!({ "x": hex(p.x), "y": hex(p.y) })
    }

    /// A point of the prime-order subgroup other than the identity, from `{x, y}`.
    fn point(v: &Value) -> Result<Affine, String> {
        let x = base(v["x"].as_str().ok_or("point")?)?;
        let y = base(v["y"].as_str().ok_or("point")?)?;
        let p = Affine::new_unchecked(x, y);
        if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() || p.is_zero() {
            return Err("point".into());
        }
        Ok(p)
    }

    fn generator() -> Affine {
        Affine::generator()
    }

    /// Noir's `Poseidon2::hash([x, y], 2)`: the sponge zkPassport's circuits output as `oprf_pk_hash`.
    pub fn key_hash(p: Affine) -> Fq {
        let iv = Fq::from(2u64) * Fq::from(1u128 << 64);
        taceo_poseidon2::bn254::t4::permutation(&[p.x, p.y, Fq::zero(), iv])[0]
    }

    /// `{x, y, hash}` of the key behind [secret].
    pub fn public_key(secret: &str) -> Result<Value, String> {
        let k = scalar(secret)?;
        let p = (generator() * k).into_affine();
        let mut v = point_json(p);
        v["hash"] = hex(key_hash(p)).into();
        Ok(v)
    }

    /// The `oprf_pk_hash` of a public key `{x, y}`.
    pub fn public_key_hash(pk: &Value) -> Result<Value, String> {
        Ok(hex(key_hash(point(pk)?)).into())
    }

    /// The server's answer to a blinded query: k times the query and a proof that it used the key behind `pk`.
    pub fn evaluate(secret: &str, request: &Value) -> Result<Value, String> {
        let k = scalar(secret)?;
        let b = point(&request["blinded_query"])?;
        let c = (b * k).into_affine();
        let proof = DLogEqualityProof::proof(b, k, &mut rand::thread_rng());
        Ok(json!({
            "pk": point_json((generator() * k).into_affine()),
            "response_blinded": point_json(c),
            "dlog_e": hex(proof.e()),
            "dlog_s": hex(proof.s()),
        }))
    }

    /// A blinded [query] (the private nullifier) and its fresh blinding factor `beta`, which stays on the device.
    pub fn blind(query: &str) -> Result<Value, String> {
        let q = base(query)?;
        let beta = loop {
            let b = BlindingFactor::rand(&mut rand::thread_rng());
            if !b.beta().is_zero() {
                break b;
            }
        };
        let blinded = client::blind_query(q, beta);
        Ok(
            json!({ "beta": hex(beta.beta()), "blinded_query": point_json(blinded.blinded_query()) }),
        )
    }

    /// Checks the server's proof against the expected public key and returns the circuit's `oprf_proof` input and
    /// the OPRF output (the salted identifier before the circuit scopes it).
    pub fn finalize(request: &Value) -> Result<Value, String> {
        let q = base(request["query"].as_str().ok_or("query")?)?;
        let beta = BlindingFactor::from_scalar(scalar(request["beta"].as_str().ok_or("beta")?)?)
            .map_err(|_| "beta")?;
        let pk = point(&request["pk"])?;
        let response = point(&request["response_blinded"])?;
        let e = base(request["dlog_e"].as_str().ok_or("dlog_e")?)?;
        let s = scalar(request["dlog_s"].as_str().ok_or("dlog_s")?)?;
        let ds = Fq::from(super::DOMAIN_SEPARATOR);
        let blinded = BlindedOprfResponse::new(response);
        let prepared = beta.prepare();
        let output = client::finalize_query_and_verify_proof(
            pk,
            q,
            &blinded,
            &DLogEqualityProof::new(e, s),
            &prepared,
            ds,
        )
        .map_err(|_| "dlog_proof".to_string())?;
        let unblinded = blinded.unblind_response(&prepared);
        Ok(json!({
            "oprf_proof": {
                "pk": point_json(pk),
                "dlog_e": hex(e),
                "dlog_s": hex(s),
                "response_blinded": point_json(response),
                "response": point_json(unblinded),
                "beta": hex(beta.beta()),
            },
            "output": hex(output),
        }))
    }
}

#[cfg(feature = "oprf")]
fn run(f: impl FnOnce() -> Result<serde_json::Value, String>) -> Result<String, ZkError> {
    f().map(|v| v.to_string())
        .map_err(|reason| ZkError::InvalidInput { reason })
}

#[cfg(not(feature = "oprf"))]
fn disabled() -> ZkError {
    ZkError::Unsupported {
        reason: "oprf_disabled".into(),
    }
}

/// The public key `{x, y, hash}` of the OPRF secret key [secret] (a nonzero BabyJubJub scalar); `hash` is the
/// `oprf_pk_hash` the disclosure circuits output for it.
#[uniffi::export]
pub fn oprf_public_key(secret: String) -> Result<String, ZkError> {
    #[cfg(feature = "oprf")]
    {
        run(|| imp::public_key(&secret))
    }
    #[cfg(not(feature = "oprf"))]
    {
        let _ = secret;
        Err(disabled())
    }
}

/// The `oprf_pk_hash` (0x hex) of a public key `{"x", "y"}`, as a verifier compares it.
#[uniffi::export]
pub fn oprf_public_key_hash(pk_json: String) -> Result<String, ZkError> {
    #[cfg(feature = "oprf")]
    {
        run(|| {
            let pk: serde_json::Value = serde_json::from_str(&pk_json).map_err(|_| "pk_json")?;
            imp::public_key_hash(&pk)
        })
        .map(|s| s.trim_matches('"').to_string())
    }
    #[cfg(not(feature = "oprf"))]
    {
        let _ = pk_json;
        Err(disabled())
    }
}

/// Server side: answers `{"blinded_query": {x, y}}` with `pk`, `response_blinded`, `dlog_e` and `dlog_s`.
#[uniffi::export]
pub fn oprf_evaluate(secret: String, request_json: String) -> Result<String, ZkError> {
    #[cfg(feature = "oprf")]
    {
        run(|| {
            let request: serde_json::Value =
                serde_json::from_str(&request_json).map_err(|_| "request_json")?;
            imp::evaluate(&secret, &request)
        })
    }
    #[cfg(not(feature = "oprf"))]
    {
        let _ = (secret, request_json);
        Err(disabled())
    }
}

/// Wallet side: blinds [query]; returns `beta` (keep it private) and `blinded_query`.
#[uniffi::export]
pub fn oprf_blind(query: String) -> Result<String, ZkError> {
    #[cfg(feature = "oprf")]
    {
        run(|| imp::blind(&query))
    }
    #[cfg(not(feature = "oprf"))]
    {
        let _ = query;
        Err(disabled())
    }
}

/// Wallet side: `{query, beta, pk, response_blinded, dlog_e, dlog_s}` to the circuit's `oprf_proof` and `output`,
/// once the proof shows the server used the key behind `pk` (the caller checks `pk` is the project's key).
#[uniffi::export]
pub fn oprf_finalize(request_json: String) -> Result<String, ZkError> {
    #[cfg(feature = "oprf")]
    {
        run(|| {
            let request: serde_json::Value =
                serde_json::from_str(&request_json).map_err(|_| "request_json")?;
            imp::finalize(&request)
        })
    }
    #[cfg(not(feature = "oprf"))]
    {
        let _ = request_json;
        Err(disabled())
    }
}

#[cfg(all(test, feature = "oprf"))]
mod tests {
    use super::*;
    use serde_json::Value;

    fn json(s: Result<String, ZkError>) -> Value {
        serde_json::from_str(&s.unwrap()).unwrap()
    }

    fn round(secret: &str, query: &str) -> (Value, Value) {
        let blinded = json(oprf_blind(query.into()));
        let answer = json(oprf_evaluate(
            secret.into(),
            serde_json::json!({ "blinded_query": blinded["blinded_query"] }).to_string(),
        ));
        let mut request = answer.clone();
        request["query"] = query.into();
        request["beta"] = blinded["beta"].clone();
        (answer, json(oprf_finalize(request.to_string())))
    }

    #[test]
    fn output_is_deterministic_and_the_proof_binds_the_key() {
        let secret = "0x1234567890abcdef1234567890abcdef";
        let query = "0x25d736ccb33e663ca64bf23add154cb740c5fa863b518da3c1a584f856b48986";
        let (answer, first) = round(secret, query);
        let (_, second) = round(secret, query);
        assert_eq!(
            first["output"], second["output"],
            "blinding must not change the output"
        );
        assert_ne!(first["oprf_proof"]["beta"], second["oprf_proof"]["beta"]);
        let own = json(oprf_public_key(secret.into()));
        assert_eq!(
            answer["pk"],
            serde_json::json!({ "x": own["x"], "y": own["y"] })
        );
        let (_, other) = round("0x99", query);
        assert_ne!(first["output"], other["output"]);
        let (_, other_query) = round(secret, "0x1");
        assert_ne!(first["output"], other_query["output"]);

        // A response from another key, or a changed proof, is refused.
        let blinded = json(oprf_blind(query.into()));
        let mut forged = json(oprf_evaluate(
            "0x99".into(),
            serde_json::json!({ "blinded_query": blinded["blinded_query"] }).to_string(),
        ));
        forged["pk"] = answer["pk"].clone();
        forged["query"] = query.into();
        forged["beta"] = blinded["beta"].clone();
        assert!(oprf_finalize(forged.to_string()).is_err());
        let mut changed = json(oprf_evaluate(
            secret.into(),
            serde_json::json!({ "blinded_query": blinded["blinded_query"] }).to_string(),
        ));
        changed["query"] = query.into();
        changed["beta"] = blinded["beta"].clone();
        changed["dlog_s"] = "0x5".into();
        assert!(oprf_finalize(changed.to_string()).is_err());
    }

    #[test]
    fn key_hash_matches_zkpassports_constant() {
        // DEFAULT_OPRF_PUB_KEY and DEFAULT_OPRF_PUB_KEY_HASH of @zkpassport/utils.
        let pk = serde_json::json!({
            "x": "18166959201346800007624274454748264099569154910741994195889360204497718998925",
            "y": "17198643698593566948834308934687875815952052155871236424838876937611092999400",
        });
        let hash = oprf_public_key_hash(pk.to_string()).unwrap();
        let expected = num_bigint::BigUint::parse_bytes(
            b"1178201404428554206520802247552222388413553631367032661928167491793274360628",
            10,
        )
        .unwrap();
        assert_eq!(hash, format!("0x{expected:x}"));
        let own = json(oprf_public_key("0x1234".into()));
        let pk_only = serde_json::json!({ "x": own["x"], "y": own["y"] });
        assert_eq!(
            own["hash"].as_str().unwrap(),
            oprf_public_key_hash(pk_only.to_string()).unwrap()
        );
    }

    #[test]
    fn rejects_bad_keys_and_points() {
        assert!(oprf_public_key("0".into()).is_err());
        assert!(oprf_public_key("0x".into()).is_err());
        let off_curve =
            serde_json::json!({ "blinded_query": { "x": "0x1", "y": "0x2" } }).to_string();
        assert!(oprf_evaluate("0x5".into(), off_curve).is_err());
        assert!(oprf_blind(format!("0x{}", "f".repeat(64))).is_err());
    }

    /// zkPassport's disclosure circuit accepts this OPRF: with ZKPASSPORT_CIRCUIT a packaged disclosure circuit
    /// (compare_age) and ZKPASSPORT_INPUTS its inputs, the project's `oprf_proof` for the private nullifier with its
    /// output as `nullifier_secret` must execute (the circuit verifies the proof and the output), the outputs must
    /// differ from the unsalted run, and a changed proof or output must fail.
    #[cfg(feature = "zkpdf")]
    #[test]
    #[ignore = "requires a packaged disclosure circuit and its inputs"]
    fn disclosure_circuit_accepts_the_proof() {
        let read =
            |name: &str| std::fs::read_to_string(std::env::var_os(name).expect(name)).unwrap();
        let circuit = read("ZKPASSPORT_CIRCUIT");
        let mut inputs: Value = serde_json::from_str(&read("ZKPASSPORT_INPUTS")).unwrap();
        let plain = zkpdf_prover::execute_public_inputs(circuit.as_bytes(), &inputs).unwrap();
        let query = inputs["salted_private_nullifier"]["value"]
            .as_str()
            .unwrap()
            .to_string();
        let (_, done) = round("0x1234567890abcdef1234567890abcdef", &query);
        inputs["oprf_proof"] = done["oprf_proof"].clone();
        inputs["nullifier_secret"] = done["output"].clone();
        let salted = zkpdf_prover::execute_public_inputs(circuit.as_bytes(), &inputs).unwrap();
        assert_eq!(plain.len(), salted.len());
        assert_ne!(plain, salted);
        let mut broken = inputs.clone();
        broken["oprf_proof"]["dlog_s"] = "0x5".into();
        assert!(zkpdf_prover::execute_public_inputs(circuit.as_bytes(), &broken).is_err());
        let mut wrong = inputs.clone();
        wrong["nullifier_secret"] = "0x7".into();
        assert!(zkpdf_prover::execute_public_inputs(circuit.as_bytes(), &wrong).is_err());
    }
}
