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
