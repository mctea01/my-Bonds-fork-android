//! OpenAC exports share WP0's library and fixed, private-input-safe errors.

use crate::{ZkCancelToken, ZkError};
use std::sync::Arc;

fn invoke<T>(
    cancel: Arc<ZkCancelToken>,
    operation: impl FnOnce() -> Result<T, openac_age::ZkProofError>,
) -> Result<T, ZkError> {
    // Install the shared hook first. Racing independent take_hook/set_hook
    // pairs could otherwise lose a private worker's redaction hook.
    crate::protect_worker_panics();
    cancel.check()?;
    let token = Arc::clone(&cancel);
    let result = openac_age::with_cancellation(Arc::new(move || token.check().is_err()), operation);
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

fn error(error: openac_age::ZkProofError) -> ZkError {
    match error {
        openac_age::ZkProofError::Cancelled => ZkError::Cancelled,
        openac_age::ZkProofError::InvalidInput { .. } => ZkError::InvalidInput {
            reason: "openac_input".into(),
        },
        openac_age::ZkProofError::Worker => ZkError::ResourceExhausted {
            reason: "openac_worker".into(),
        },
        _ => ZkError::Internal { code: 7001 },
    }
}

impl From<openac_age::ProofResult> for OpenAcProofResult {
    fn from(value: openac_age::ProofResult) -> Self {
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
        openac_age::create_age_prepare_input(documents_path, sd_jwt, issuer_key_x, issuer_key_y)
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
    openac_age::create_age_show_input(
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
    invoke(cancel, || openac_age::prove_jwt(documents_path)).map(Into::into)
}

#[uniffi::export]
pub fn prove_show(
    documents_path: String,
    cancel: Arc<ZkCancelToken>,
) -> Result<OpenAcProofResult, ZkError> {
    invoke(cancel, || openac_age::prove_show(documents_path)).map(Into::into)
}

#[uniffi::export]
pub fn reblind_jwt(
    documents_path: String,
    cancel: Arc<ZkCancelToken>,
) -> Result<OpenAcProofResult, ZkError> {
    invoke(cancel, || openac_age::reblind_jwt(documents_path)).map(Into::into)
}

#[uniffi::export]
pub fn reblind_show(
    documents_path: String,
    cancel: Arc<ZkCancelToken>,
) -> Result<OpenAcProofResult, ZkError> {
    invoke(cancel, || openac_age::reblind_show(documents_path)).map(Into::into)
}

#[uniffi::export]
pub fn generate_shared_blinds(
    documents_path: String,
    cancel: Arc<ZkCancelToken>,
) -> Result<String, ZkError> {
    invoke(cancel, || {
        openac_age::generate_shared_blinds(documents_path)
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
        openac_age::verify_age_presentation(
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
    let signals = invoke(cancel, || openac_age::read_public_signals(documents_path))?;
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
