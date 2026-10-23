//! TLSNotary exports, present in every build; without the tlsn feature they report Unsupported.
//! `extra_roots_der` adds roots the caller chose itself (a test CA, a user-imported root) to TLSNotary's Mozilla
//! roots; the Kotlin side rates the returned chain again with the wallet's own trust registry.
use crate::{ZkCancelToken, ZkError};
use std::sync::Arc;

/// Implementations must allow concurrent send/receive and close must unblock both.
#[uniffi::export(callback_interface)]
pub trait ZkTlsChannel: Send + Sync {
    fn send(&self, data: Vec<u8>) -> Result<(), ZkError>;
    fn receive(&self) -> Result<Vec<u8>, ZkError>;
    fn close(&self);
}
#[uniffi::export(callback_interface)]
pub trait ZkTlsRevealChooser: Send + Sync {
    fn choose(&self, transcript: ZkTlsTranscript) -> ZkTlsReveal;
}
#[derive(uniffi::Record)]
pub struct ZkTlsRequest {
    pub host: String,
    pub port: u16,
    pub request: Vec<u8>,
    pub max_sent: u32,
    pub max_recv: u32,
    pub mode: String,
}
#[derive(uniffi::Record)]
pub struct ZkTlsTranscript {
    pub sent: Vec<u8>,
    pub received: Vec<u8>,
    pub server_name: String,
    pub cert_chain_der: Vec<Vec<u8>>,
    pub time: u64,
    pub cipher_suite: String,
}
#[derive(uniffi::Record)]
pub struct ZkRange {
    pub start: u32,
    pub end: u32,
}
#[derive(uniffi::Record)]
pub struct ZkTlsReveal {
    pub sent: Vec<ZkRange>,
    pub received: Vec<ZkRange>,
    pub commit_sha256: Vec<ZkRange>,
}
/// A TLSNotary salted SHA-256 transcript commitment, not a raw plaintext hash.
#[derive(uniffi::Record)]
pub struct ZkTlsCommitment {
    pub range: ZkRange,
    pub alg: String,
    pub digest: Vec<u8>,
}
#[derive(uniffi::Record)]
pub struct ZkTlsVerified {
    pub server_name: String,
    pub cert_chain_der: Vec<Vec<u8>>,
    pub time: u64,
    pub sent: Vec<u8>,
    pub received: Vec<u8>,
    pub sent_mask: Vec<ZkRange>,
    pub received_mask: Vec<ZkRange>,
    pub commitments: Vec<ZkTlsCommitment>,
}

#[uniffi::export]
#[allow(clippy::too_many_arguments, unused_variables)]
pub fn zktls_prove(
    channel: Box<dyn ZkTlsChannel>,
    request: ZkTlsRequest,
    choose: Box<dyn ZkTlsRevealChooser>,
    cancel: Arc<ZkCancelToken>,
    request_hash: Vec<u8>,
    verifier_static_public: Vec<u8>,
    extra_roots_der: Vec<Vec<u8>>,
) -> Result<ZkTlsTranscript, ZkError> {
    #[cfg(not(feature = "tlsn"))]
    {
        Err(ZkError::Unsupported {
            reason: "tlsn_disabled".into(),
        })
    }
    #[cfg(feature = "tlsn")]
    {
        let hash = fixed(request_hash)?;
        let key = fixed(verifier_static_public)?;
        crate::run_worker(16 * 1024 * 1024, cancel, move |cancel| {
            let request = zktls::protocol::Request {
                host: request.host,
                port: request.port,
                request: request.request,
                max_sent: request.max_sent,
                max_recv: request.max_recv,
                mode: request.mode,
            };
            zktls::channel::run(
                Arc::new(Channel(channel)),
                Arc::new(move || cancel.check().is_err()),
                |wire| async move {
                    zktls::protocol::prove(
                        wire,
                        request,
                        hash,
                        key,
                        zktls::protocol::roots_with(extra_roots_der),
                        |input| {
                            let reveal = choose.choose(transcript(input.clone()));
                            Ok(zktls::protocol::Reveal {
                                sent: ranges(reveal.sent),
                                received: ranges(reveal.received),
                                commit_sha256: ranges(reveal.commit_sha256),
                            })
                        },
                    )
                    .await
                },
            )
            .map(transcript)
            .map_err(error)
        })
    }
}

#[uniffi::export]
#[allow(clippy::too_many_arguments, unused_variables)]
pub fn zktls_verify(
    channel: Box<dyn ZkTlsChannel>,
    expected_host: String,
    port: u16,
    max_sent: u32,
    max_recv: u32,
    mode: String,
    cancel: Arc<ZkCancelToken>,
    request_hash: Vec<u8>,
    verifier_static_private: Vec<u8>,
    extra_roots_der: Vec<Vec<u8>>,
) -> Result<ZkTlsVerified, ZkError> {
    #[cfg(not(feature = "tlsn"))]
    {
        Err(ZkError::Unsupported {
            reason: "tlsn_disabled".into(),
        })
    }
    #[cfg(feature = "tlsn")]
    {
        let hash = fixed(request_hash)?;
        let key = fixed(verifier_static_private)?;
        crate::run_worker(16 * 1024 * 1024, cancel, move |cancel| {
            zktls::channel::run(
                Arc::new(Channel(channel)),
                Arc::new(move || cancel.check().is_err()),
                |wire| {
                    zktls::protocol::verify(
                        wire,
                        expected_host,
                        port,
                        max_sent,
                        max_recv,
                        mode,
                        hash,
                        key,
                        zktls::protocol::roots_with(extra_roots_der),
                    )
                },
            )
            .map(|v| ZkTlsVerified {
                server_name: v.server_name,
                cert_chain_der: v.cert_chain_der,
                time: v.time,
                sent: v.sent,
                received: v.received,
                sent_mask: v.sent_mask.into_iter().map(range).collect(),
                received_mask: v.received_mask.into_iter().map(range).collect(),
                commitments: v
                    .commitments
                    .into_iter()
                    .map(|c| ZkTlsCommitment {
                        range: range(c.range),
                        alg: "SHA256".into(),
                        digest: c.digest,
                    })
                    .collect(),
            })
            .map_err(error)
        })
    }
}

#[cfg(feature = "tlsn")]
fn fixed(bytes: Vec<u8>) -> Result<[u8; 32], ZkError> {
    bytes.try_into().map_err(|_| ZkError::InvalidInput {
        reason: "key_or_hash_length".into(),
    })
}
#[cfg(feature = "tlsn")]
fn ranges(input: Vec<ZkRange>) -> Vec<std::ops::Range<usize>> {
    input
        .into_iter()
        .map(|r| r.start as usize..r.end as usize)
        .collect()
}
#[cfg(feature = "tlsn")]
fn range(r: std::ops::Range<usize>) -> ZkRange {
    ZkRange {
        start: r.start as u32,
        end: r.end as u32,
    }
}
#[cfg(feature = "tlsn")]
fn transcript(t: zktls::protocol::Transcript) -> ZkTlsTranscript {
    ZkTlsTranscript {
        sent: t.sent,
        received: t.received,
        server_name: t.server_name,
        cert_chain_der: t.cert_chain_der,
        time: t.time,
        cipher_suite: t.cipher_suite,
    }
}
#[cfg(feature = "tlsn")]
fn error(e: zktls::Error) -> ZkError {
    match e {
        zktls::Error::Input => ZkError::InvalidInput {
            reason: "tlsn_input".into(),
        },
        zktls::Error::Limit => ZkError::ResourceExhausted {
            reason: "tlsn_limit".into(),
        },
        zktls::Error::Cancelled => ZkError::Cancelled,
        zktls::Error::Protocol => ZkError::Internal { code: 501 },
        zktls::Error::Channel => ZkError::Internal { code: 502 },
        zktls::Error::Worker => ZkError::Internal { code: 503 },
    }
}
#[cfg(feature = "tlsn")]
struct Channel(Box<dyn ZkTlsChannel>);
#[cfg(feature = "tlsn")]
impl zktls::channel::Channel for Channel {
    fn send(&self, data: Vec<u8>) -> zktls::Result<()> {
        self.0.send(data).map_err(|_| zktls::Error::Channel)
    }
    fn receive(&self) -> zktls::Result<Vec<u8>> {
        self.0.receive().map_err(|_| zktls::Error::Channel)
    }
    fn close(&self) {
        self.0.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Closed;
    impl ZkTlsChannel for Closed {
        fn send(&self, _: Vec<u8>) -> Result<(), ZkError> {
            Err(ZkError::Internal { code: 999 })
        }
        fn receive(&self) -> Result<Vec<u8>, ZkError> {
            Err(ZkError::Internal { code: 999 })
        }
        fn close(&self) {}
    }
    #[test]
    fn availability_and_key_lengths() {
        let result = zktls_verify(
            Box::new(Closed),
            "example.com".into(),
            443,
            4096,
            1024,
            "proxy".into(),
            ZkCancelToken::new(),
            vec![0; 31],
            vec![0; 32],
            Vec::new(),
        );
        #[cfg(feature = "tlsn")]
        assert!(matches!(result, Err(ZkError::InvalidInput { .. })));
        #[cfg(not(feature = "tlsn"))]
        assert!(matches!(result, Err(ZkError::Unsupported { .. })));
    }
}
