//! OpenAC exports share WP0's library and fixed, private-input-safe errors.
//!
//! The exports exist in every build: the checked-in bindings verify each
//! function checksum when the library loads. Without the `openac` feature the
//! backend below reports every operation as unsupported.

use crate::{ZkCancelToken, ZkError};
use std::sync::Arc;

#[cfg(feature = "openac")]
use openac_age as backend;

#[cfg(not(feature = "openac"))]
#[allow(dead_code)]
mod backend {
    use std::sync::Arc;

    pub enum ZkProofError {
        InvalidInput { message: String },
        Worker,
        Cancelled,
        Disabled,
    }

    pub struct AgePrepareInput {
        pub claim_name: String,
        pub claim_format: u8,
    }

    pub struct ProofResult {
        pub prep_ms: u64,
        pub prove_ms: u64,
        pub total_ms: u64,
        pub proof_size_bytes: u64,
        pub comm_w_shared: String,
    }

    pub struct PublicSignals {
        pub prepare: Vec<String>,
        pub show: Vec<String>,
    }

    pub fn with_cancellation<T>(
        _check: Arc<dyn Fn() -> bool + Send + Sync>,
        _work: impl FnOnce() -> Result<T, ZkProofError>,
    ) -> Result<T, ZkProofError> {
        Err(ZkProofError::Disabled)
    }

    pub fn create_age_prepare_input(
        _documents_path: String,
        _sd_jwt: String,
        _issuer_key_x: String,
        _issuer_key_y: String,
    ) -> Result<AgePrepareInput, ZkProofError> {
        Err(ZkProofError::Disabled)
    }

    pub fn create_age_show_input(
        _documents_path: String,
        _nonce: String,
        _device_signature: String,
        _claim_name: String,
        _claim_format: u8,
        _cutoff: u64,
    ) -> Result<(), ZkProofError> {
        Err(ZkProofError::Disabled)
    }

    pub fn prove_jwt(_documents_path: String) -> Result<ProofResult, ZkProofError> {
        Err(ZkProofError::Disabled)
    }

    pub fn prove_show(_documents_path: String) -> Result<ProofResult, ZkProofError> {
        Err(ZkProofError::Disabled)
    }

    pub fn reblind_jwt(_documents_path: String) -> Result<ProofResult, ZkProofError> {
        Err(ZkProofError::Disabled)
    }

    pub fn reblind_show(_documents_path: String) -> Result<ProofResult, ZkProofError> {
        Err(ZkProofError::Disabled)
    }

    pub fn generate_shared_blinds(_documents_path: String) -> Result<String, ZkProofError> {
        Err(ZkProofError::Disabled)
    }

    pub fn verify_age_presentation(
        _documents_path: String,
        _nonce: String,
        _claim_name: String,
        _claim_format: u8,
        _cutoff: u64,
        _expected_issuer_key_x: String,
        _expected_issuer_key_y: String,
    ) -> Result<bool, ZkProofError> {
        Err(ZkProofError::Disabled)
    }

    pub fn read_public_signals(_documents_path: String) -> Result<PublicSignals, ZkProofError> {
        Err(ZkProofError::Disabled)
    }
}

fn invoke<T>(
    cancel: Arc<ZkCancelToken>,
    operation: impl FnOnce() -> Result<T, backend::ZkProofError>,
) -> Result<T, ZkError> {
    // Install the shared hook first. Racing independent take_hook/set_hook
    // pairs could otherwise lose a private worker's redaction hook.
    crate::protect_worker_panics();
    cancel.check()?;
    let token = Arc::clone(&cancel);
    let result = backend::with_cancellation(Arc::new(move || token.check().is_err()), operation);
    cancel.check()?;
    result.map_err(error)
}

#[derive(uniffi::Record)]
pub struct AgePrepareInput {
    pub claim_name: String,
    pub claim_format: u8,
}

#[derive(uniffi::Record)]
pub struct OpenAcProofResult {
    pub prep_ms: u64,
    pub prove_ms: u64,
    pub total_ms: u64,
    pub proof_size_bytes: u64,
    pub comm_w_shared: String,
}

#[derive(uniffi::Record)]
pub struct OpenAcPublicSignals {
    pub prepare: Vec<String>,
    pub show: Vec<String>,
}

fn error(error: backend::ZkProofError) -> ZkError {
    match error {
        backend::ZkProofError::Cancelled => ZkError::Cancelled,
        backend::ZkProofError::InvalidInput { .. } => ZkError::InvalidInput {
            reason: "openac_input".into(),
        },
        backend::ZkProofError::Worker => ZkError::ResourceExhausted {
            reason: "openac_worker".into(),
        },
        #[cfg(not(feature = "openac"))]
        backend::ZkProofError::Disabled => ZkError::Unsupported {
            reason: "openac_disabled".into(),
        },
        #[allow(unreachable_patterns)]
        _ => ZkError::Internal { code: 7001 },
    }
}

impl From<backend::ProofResult> for OpenAcProofResult {
    fn from(value: backend::ProofResult) -> Self {
        Self {
            prep_ms: value.prep_ms,
            prove_ms: value.prove_ms,
            total_ms: value.total_ms,
            proof_size_bytes: value.proof_size_bytes,
            comm_w_shared: value.comm_w_shared,
        }
    }
}

#[uniffi::export]
pub fn create_age_prepare_input(
    documents_path: String,
    sd_jwt: String,
    issuer_key_x: String,
    issuer_key_y: String,
) -> Result<AgePrepareInput, ZkError> {
    crate::protect_worker_panics();
    let input =
        backend::create_age_prepare_input(documents_path, sd_jwt, issuer_key_x, issuer_key_y)
            .map_err(error)?;
    Ok(AgePrepareInput {
        claim_name: input.claim_name,
        claim_format: input.claim_format,
    })
}

#[uniffi::export]
pub fn create_age_show_input(
    documents_path: String,
    nonce: String,
    device_signature: String,
    claim_name: String,
    claim_format: u8,
    cutoff: u64,
) -> Result<(), ZkError> {
    crate::protect_worker_panics();
    backend::create_age_show_input(
        documents_path,
        nonce,
        device_signature,
        claim_name,
        claim_format,
        cutoff,
    )
    .map_err(error)
}

#[uniffi::export]
pub fn prove_jwt(
    documents_path: String,
    cancel: Arc<ZkCancelToken>,
) -> Result<OpenAcProofResult, ZkError> {
    invoke(cancel, || backend::prove_jwt(documents_path)).map(Into::into)
}

#[uniffi::export]
pub fn prove_show(
    documents_path: String,
    cancel: Arc<ZkCancelToken>,
) -> Result<OpenAcProofResult, ZkError> {
    invoke(cancel, || backend::prove_show(documents_path)).map(Into::into)
}

#[uniffi::export]
pub fn reblind_jwt(
    documents_path: String,
    cancel: Arc<ZkCancelToken>,
) -> Result<OpenAcProofResult, ZkError> {
    invoke(cancel, || backend::reblind_jwt(documents_path)).map(Into::into)
}

#[uniffi::export]
pub fn reblind_show(
    documents_path: String,
    cancel: Arc<ZkCancelToken>,
) -> Result<OpenAcProofResult, ZkError> {
    invoke(cancel, || backend::reblind_show(documents_path)).map(Into::into)
}

#[uniffi::export]
pub fn generate_shared_blinds(
    documents_path: String,
    cancel: Arc<ZkCancelToken>,
) -> Result<String, ZkError> {
    invoke(cancel, || {
        backend::generate_shared_blinds(documents_path)
    })
}

#[uniffi::export]
pub fn verify_age_presentation(
    documents_path: String,
    nonce: String,
    claim_name: String,
    claim_format: u8,
    cutoff: u64,
    expected_issuer_key_x: String,
    expected_issuer_key_y: String,
    cancel: Arc<ZkCancelToken>,
) -> Result<bool, ZkError> {
    invoke(cancel, || {
        backend::verify_age_presentation(
            documents_path,
            nonce,
            claim_name,
            claim_format,
            cutoff,
            expected_issuer_key_x,
            expected_issuer_key_y,
        )
    })
}

#[uniffi::export]
pub fn read_public_signals(
    documents_path: String,
    cancel: Arc<ZkCancelToken>,
) -> Result<OpenAcPublicSignals, ZkError> {
    let signals = invoke(cancel, || backend::read_public_signals(documents_path))?;
    Ok(OpenAcPublicSignals {
        prepare: signals.prepare,
        show: signals.show,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_proofs_never_access_documents() {
        let token = ZkCancelToken::new();
        token.cancel();
        assert!(matches!(
            prove_jwt("synthetic-private-path".into(), token),
            Err(ZkError::Cancelled)
        ));
    }

    #[cfg(not(feature = "openac"))]
    #[test]
    fn disabled_backend_is_unsupported() {
        assert!(matches!(
            prove_jwt("synthetic-private-path".into(), ZkCancelToken::new()),
            Err(ZkError::Unsupported { .. })
        ));
        assert!(matches!(
            create_age_prepare_input(String::new(), String::new(), String::new(), String::new()),
            Err(ZkError::Unsupported { .. })
        ));
        assert!(crate::native_info().zkid.is_none());
    }

    #[cfg(feature = "openac")]
    #[test]
    fn backend_errors_are_fixed_and_feature_is_registered() {
        let error = error(openac_age::ZkProofError::InvalidInput {
            message: "synthetic-private-value".into(),
        });
        assert_eq!(error.to_string(), "Invalid input");
        match error {
            ZkError::InvalidInput { reason } => assert_eq!(reason, "openac_input"),
            _ => panic!("unexpected error variant"),
        }
        assert_eq!(
            crate::native_info().zkid.as_deref(),
            Some(openac_age::ZKID_REVISION)
        );
    }
}
