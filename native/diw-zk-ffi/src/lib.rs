//! Shared native runtime and feature-gated proof backend exports.

use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Once,
};

thread_local! {
    static PRIVATE_WORKER: Cell<bool> = const { Cell::new(false) };
}

fn protect_worker_panics() {
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            // A backend panic may embed its witness. Preserve the host's hook
            // for every other thread, but never print a proof worker's payload.
            if !PRIVATE_WORKER.try_with(Cell::get).unwrap_or(false) {
                previous(info);
            }
        }));
    });
}

uniffi::setup_scaffolding!("diw_zk");

mod openac;
mod zktls;

#[derive(uniffi::Record)]
pub struct ZkNativeInfo {
    pub crate_version: String,
    pub features: Vec<String>,
    pub tlsn: Option<String>,
    pub noir: Option<String>,
    pub bb: Option<String>,
    pub zkid: Option<String>,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ZkError {
    #[error("Invalid input")]
    InvalidInput { reason: String },
    #[error("Unsupported operation")]
    Unsupported { reason: String },
    #[error("Resource limit reached")]
    ResourceExhausted { reason: String },
    #[error("Cancelled")]
    Cancelled,
    #[error("Internal error")]
    Internal { code: u32 },
}

#[derive(Default, uniffi::Object)]
pub struct ZkCancelToken {
    cancelled: AtomicBool,
}

#[uniffi::export]
impl ZkCancelToken {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

impl ZkCancelToken {
    /// Backends must poll at bounded intervals and before publishing results.
    pub fn check(&self) -> Result<(), ZkError> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(ZkError::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// Run a backend on a dedicated, joinable thread. Cancellation is cooperative;
/// returning early and leaving a worker processing private input is not allowed.
pub fn run_worker<T: Send + 'static>(
    stack_bytes: usize,
    cancel: Arc<ZkCancelToken>,
    work: impl FnOnce(Arc<ZkCancelToken>) -> Result<T, ZkError> + Send + 'static,
) -> Result<T, ZkError> {
    cancel.check()?;
    if !(1024 * 1024..=256 * 1024 * 1024).contains(&stack_bytes) {
        return Err(ZkError::InvalidInput {
            reason: "stack_size".into(),
        });
    }
    protect_worker_panics();
    let worker_cancel = Arc::clone(&cancel);
    let worker = std::thread::Builder::new()
        .name("diw-zk-worker".into())
        .stack_size(stack_bytes)
        .spawn(move || {
            PRIVATE_WORKER.set(true);
            work(worker_cancel)
        })
        .map_err(|_| ZkError::ResourceExhausted {
            reason: "worker_start".into(),
        })?;
    let result = worker.join().map_err(|_| ZkError::Internal { code: 1 })?;
    cancel.check()?;
    result
}

#[uniffi::export]
pub fn native_info() -> ZkNativeInfo {
    // Empty backend crates must never be advertised as usable proof engines.
    ZkNativeInfo {
        crate_version: env!("CARGO_PKG_VERSION").into(),
        features: {
            let mut features = vec!["runtime".to_string()];
            if cfg!(feature = "openac") {
                features.push("openac".into());
            }
            if cfg!(feature = "tlsn") {
                features.push("tlsn".into());
            }
            features
        },
        tlsn: {
            #[cfg(feature = "tlsn")]
            {
                Some(::zktls::TLSN_REVISION.into())
            }
            #[cfg(not(feature = "tlsn"))]
            {
                None
            }
        },
        noir: None,
        bb: None,
        zkid: {
            #[cfg(feature = "openac")]
            {
                Some(openac_age::ZKID_REVISION.into())
            }
            #[cfg(not(feature = "openac"))]
            {
                None
            }
        },
    }
}

#[uniffi::export]
pub fn self_test() -> bool {
    run_worker(1024 * 1024, ZkCancelToken::new(), |_| {
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        let runtime_ok = Sha256::digest(b"abc")[..] == expected;
        #[cfg(feature = "openac")]
        {
            Ok(runtime_ok && openac_age::self_test())
        }
        #[cfg(not(feature = "openac"))]
        {
            Ok(runtime_ok)
        }
    })
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_vector_and_info() {
        assert!(self_test());
        assert!(native_info().features.contains(&"runtime".into()));
        assert_eq!(
            native_info().features.contains(&"openac".into()),
            cfg!(feature = "openac")
        );
        assert_eq!(
            native_info().features.contains(&"tlsn".into()),
            cfg!(feature = "tlsn")
        );
        assert_eq!(native_info().tlsn.is_some(), cfg!(feature = "tlsn"));
    }

    #[test]
    fn cancellation_before_and_during_work() {
        let cancel = ZkCancelToken::new();
        cancel.cancel();
        assert!(matches!(
            run_worker(1024 * 1024, cancel, |_| Ok(())),
            Err(ZkError::Cancelled)
        ));
        assert!(matches!(
            run_worker(64 * 1024 * 1024, ZkCancelToken::new(), |token| {
                token.cancel();
                Ok(())
            }),
            Err(ZkError::Cancelled)
        ));
    }

    #[test]
    fn invalid_stack_and_error_redaction() {
        assert!(matches!(
            run_worker(0, ZkCancelToken::new(), |_| Ok(())),
            Err(ZkError::InvalidInput { .. })
        ));
        let error = ZkError::InvalidInput {
            reason: "synthetic-private-input".into(),
        };
        assert_eq!(error.to_string(), "Invalid input");
    }

    #[test]
    fn worker_panic_is_a_fixed_error() {
        let result: Result<(), ZkError> = run_worker(1024 * 1024, ZkCancelToken::new(), |_| {
            panic!("synthetic-private-witness");
        });
        assert!(matches!(result, Err(ZkError::Internal { code: 1 })));
    }
}
