//! zkPassport verifier exports (Z2). Bundles hold only public data, and verification uses the zkPDF
//! Barretenberg build, so all three exist only with the `zkpdf` feature.
use crate::{run_worker, ZkCancelToken, ZkError};

#[cfg(feature = "zkpdf")]
fn invalid(reason: String) -> ZkError {
    ZkError::InvalidInput { reason }
}

#[cfg(not(feature = "zkpdf"))]
fn disabled() -> ZkError {
    ZkError::Unsupported {
        reason: "zkpassport_disabled".into(),
    }
}

/// Version, circuit names, certificate registry root and proof date of a JSON array of proofs.
#[uniffi::export]
pub fn zkpassport_inspect(proofs_json: String) -> Result<String, ZkError> {
    #[cfg(feature = "zkpdf")]
    {
        zkpassport_verify::inspect_json(&proofs_json).map_err(invalid)
    }
    #[cfg(not(feature = "zkpdf"))]
    {
        let _ = proofs_json;
        Err(disabled())
    }
}

/// The circuit registry root a manifest hashes to; fails when it differs from the declared root.
#[uniffi::export]
pub fn zkpassport_circuit_root(manifest_json: String) -> Result<String, ZkError> {
    #[cfg(feature = "zkpdf")]
    {
        zkpassport_verify::circuit_root_json(&manifest_json).map_err(invalid)
    }
    #[cfg(not(feature = "zkpdf"))]
    {
        let _ = manifest_json;
        Err(disabled())
    }
}

/// The certificate registry root a packaged certificates file hashes to, and its CSCA keys by country, as JSON.
#[uniffi::export]
pub fn zkpassport_certificates(package_json: String) -> Result<String, ZkError> {
    #[cfg(feature = "zkpdf")]
    {
        zkpassport_verify::certificates::package_json(&package_json).map_err(invalid)
    }
    #[cfg(not(feature = "zkpdf"))]
    {
        let _ = package_json;
        Err(disabled())
    }
}

/// Checks a bundle and verifies every proof with Barretenberg. `crs_dir` is the zkPDF asset directory when
/// its full CRS is installed, so proving keeps working afterwards; without it only the two CRS points
/// verification needs are loaded. The JSON result carries `verified` and the error codes.
#[uniffi::export]
pub fn zkpassport_verify(request_json: String, crs_dir: Option<String>) -> Result<String, ZkError> {
    run_worker(64 * 1024 * 1024, ZkCancelToken::new(), move |_| {
        #[cfg(feature = "zkpdf")]
        {
            let dir = crs_dir.map(std::path::PathBuf::from);
            zkpassport_verify::verify_json(&request_json, |vk, proof, public| {
                zkpdf_prover::verify_ultrahonk(dir.as_deref(), vk, proof, public).map_err(|e| e.0.to_string())
            })
            .map_err(invalid)
        }
        #[cfg(not(feature = "zkpdf"))]
        {
            let _ = (request_json, crs_dir);
            Err(disabled())
        }
    })
}

/// zkPassport's proving pipeline (Z3), sequenced by its own sans-IO driver: `next` returns the command as JSON
/// (`fetch`, `prove`, `bridge_send`, `done`, `error` or `await`) and `provide` feeds back a fetched body or, for
/// `prove`, the hex of public inputs and proof that [zkpassport_prove] returns. The config carries the request
/// (`query`, `service_scope`, `chain_id`, `circuit_version`, `certificates_root`, ...) and the chip files.
#[derive(uniffi::Object)]
pub struct ZkPassportProofSession {
    #[cfg(feature = "zkpdf")]
    inner: std::sync::Mutex<zkpassport_ffi::driver::Session>,
}

#[uniffi::export]
impl ZkPassportProofSession {
    #[uniffi::constructor]
    pub fn new(config_json: String) -> Result<std::sync::Arc<Self>, ZkError> {
        #[cfg(feature = "zkpdf")]
        {
            let session = zkpassport_ffi::driver::Session::new(&config_json).map_err(invalid)?;
            Ok(std::sync::Arc::new(Self {
                inner: std::sync::Mutex::new(session),
            }))
        }
        #[cfg(not(feature = "zkpdf"))]
        {
            let _ = config_json;
            Err(disabled())
        }
    }

    /// The next command as JSON.
    pub fn next(&self) -> String {
        #[cfg(feature = "zkpdf")]
        {
            match self.inner.lock() {
                Ok(mut s) => s.next().to_string(),
                Err(_) => r#"{"action":"error","message":"session_state"}"#.into(),
            }
        }
        #[cfg(not(feature = "zkpdf"))]
        {
            r#"{"action":"error","message":"zkpassport_disabled"}"#.into()
        }
    }

    /// Feeds back the result of the command named [id]. Input generation runs here once the certificates and the
    /// manifest are both in, so the call runs on a worker with a large stack.
    pub fn provide(self: std::sync::Arc<Self>, id: String, data: String) -> Result<(), ZkError> {
        run_worker(64 * 1024 * 1024, ZkCancelToken::new(), move |_| {
            #[cfg(feature = "zkpdf")]
            {
                let mut s = self.inner.lock().map_err(|_| invalid("session_state".into()))?;
                s.provide(&id, &data).map_err(invalid)
            }
            #[cfg(not(feature = "zkpdf"))]
            {
                let _ = (self, id, data);
                Err(disabled())
            }
        })
    }
}

/// Proves one `prove` command of [ZkPassportProofSession] with the full CRS in `crs_dir`. The key this
/// Barretenberg derives from the command's packaged circuit must hash to `vkey_hash`, the circuit's leaf in a
/// manifest already checked against the circuit registry, before the circuit runs on the chip data: a circuit the
/// registry does not list could make private data public. Circuits keyed by another Barretenberg fail here too.
/// Returns JSON with `proof` (hex of public inputs then proof, as the driver and the bridge expect) and `vkey`.
#[uniffi::export]
pub fn zkpassport_prove(
    command_json: String,
    vkey_hash: String,
    crs_dir: String,
    cancel: std::sync::Arc<ZkCancelToken>,
) -> Result<String, ZkError> {
    run_worker(64 * 1024 * 1024, cancel, move |token| {
        #[cfg(feature = "zkpdf")]
        {
            let command: serde_json::Value = serde_json::from_str(&command_json).map_err(|_| invalid("command_json".into()))?;
            let circuit = command["circuit"].as_str().filter(|c| !c.is_empty()).ok_or_else(|| invalid("command_circuit".into()))?;
            let inputs = command.get("inputs").filter(|i| i.is_object()).ok_or_else(|| invalid("command_inputs".into()))?;
            let expected = vkey_hash.trim().trim_start_matches("0x").to_ascii_lowercase();
            if expected.is_empty() || expected.len() > 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(invalid("vkey_hash".into()));
            }
            let crs = std::path::Path::new(&crs_dir);
            let vk = zkpdf_prover::write_vk(crs, circuit.as_bytes()).map_err(|e| invalid(e.0.to_string()))?;
            if format!("{:064x}", zkpassport_verify::vkey_hash(&vk)) != format!("{expected:0>64}") {
                return Err(invalid("circuit_vkey_mismatch".into()));
            }
            token.check()?;
            let (proof, public, vk) =
                zkpdf_prover::prove_ultrahonk(crs, circuit.as_bytes(), Some(&vk), inputs).map_err(|e| invalid(e.0.to_string()))?;
            token.check()?;
            let mut joined = public;
            joined.extend_from_slice(&proof);
            Ok(serde_json::json!({
                "proof": hex::encode(joined),
                "vkey": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &vk),
            })
            .to_string())
        }
        #[cfg(not(feature = "zkpdf"))]
        {
            let _ = (command_json, vkey_hash, crs_dir, token);
            Err(disabled())
        }
    })
}

#[cfg(all(test, feature = "zkpdf"))]
mod tests {
    use super::*;

    #[test]
    fn session_starts_by_fetching_the_registry() {
        let config = serde_json::json!({
            "mode": "fast", "chain_id": 1, "circuit_version": "0.21.1", "certificates_root": "0xabc",
        });
        let session = ZkPassportProofSession::new(config.to_string()).unwrap();
        let first: serde_json::Value = serde_json::from_str(&session.next()).unwrap();
        assert_eq!(first["action"], "fetch");
        let urls: Vec<&str> = first["requests"].as_array().unwrap().iter().map(|r| r["url"].as_str().unwrap()).collect();
        assert_eq!(urls.len(), 2);
        assert!(urls[0].starts_with("https://certificates.zkpassport.id/mainnet"));
        assert!(urls[1].starts_with("https://circuits2.zkpassport.id/mainnet"));
        assert!(ZkPassportProofSession::new("{".into()).is_err());
        assert!(zkpassport_prove("{}".into(), "0x1".into(), ".".into(), ZkCancelToken::new()).is_err());
    }

    /// Proves a published zkPassport circuit and verifies the proof under the returned key:
    /// ZKPASSPORT_CIRCUIT is the packaged circuit, ZKPASSPORT_INPUTS its inputs, ZKPASSPORT_VKEY_HASH the hash of the
    /// key this Barretenberg derives (its manifest leaf for circuits built with it; derived here when unset) and
    /// ZKPDF_ASSETS_DIR the CRS. A wrong hash must stop before proving.
    #[test]
    #[ignore = "requires a packaged circuit, its inputs and the full CRS"]
    fn proves_a_packaged_circuit() {
        let read = |name: &str| std::fs::read_to_string(std::env::var_os(name).expect(name)).unwrap();
        let crs = std::env::var("ZKPDF_ASSETS_DIR").expect("ZKPDF_ASSETS_DIR");
        let hash = std::env::var("ZKPASSPORT_VKEY_HASH").unwrap_or_else(|_| {
            let vk = zkpdf_prover::write_vk(std::path::Path::new(&crs), read("ZKPASSPORT_CIRCUIT").as_bytes()).unwrap();
            format!("0x{:x}", zkpassport_verify::vkey_hash(&vk))
        });
        let inputs: serde_json::Value = serde_json::from_str(&read("ZKPASSPORT_INPUTS")).unwrap();
        let command = serde_json::json!({ "action": "prove", "id": 0, "circuit": read("ZKPASSPORT_CIRCUIT"), "inputs": inputs });
        let wrong = zkpassport_prove(command.to_string(), "0x1".into(), crs.clone(), ZkCancelToken::new());
        assert!(matches!(wrong, Err(ZkError::InvalidInput { reason }) if reason == "circuit_vkey_mismatch"));
        let out: serde_json::Value =
            serde_json::from_str(&zkpassport_prove(command.to_string(), hash, crs.clone(), ZkCancelToken::new()).unwrap()).unwrap();
        let joined = hex::decode(out["proof"].as_str().unwrap()).unwrap();
        let vk = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, out["vkey"].as_str().unwrap()).unwrap();
        let (pi, proof) = joined.split_at(joined.len() - zkpdf_prover::PROOF_BYTES);
        assert!(!pi.is_empty() && pi.len() % 32 == 0);
        zkpdf_prover::verify_ultrahonk(Some(std::path::Path::new(&crs)), &vk, proof, pi).unwrap();
    }
}
