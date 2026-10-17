//! Bonds OpenAC age profile with private-input-safe desktop and Android hosting.

use ecdsa_spartan2::{
    load_instance, load_proof, load_proving_key, load_shared_blinds, load_verifying_key,
    load_witness,
    paths::keys::*,
    prover::{prove_circuit_in_memory, reblind_in_memory},
    setup::{save_instance, save_proof, save_shared_blinds, save_witness},
    CircuitSize, PathConfig, PrepareCircuit, ShowCircuit, E,
};
use ff::{Field, PrimeField};
use num_bigint::BigUint;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use spartan2::traits::{circuit::SpartanCircuit, snark::R1CSSNARKTrait, Engine};
use std::{
    cell::{Cell, RefCell},
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Once},
    time::Instant,
};

mod predicate;
pub use predicate::AgePrepareInput;

pub const ZKID_REVISION: &str = "b395e09c225ff45b003f0087c28e2e208e22f944";
pub const PROVER_STACK_BYTES: usize = 64 * 1024 * 1024;

/// A small native known-answer/negative-input check without downloading assets.
pub fn self_test() -> bool {
    #[cfg(feature = "native-witness")]
    {
        worker(|| {
            let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
            if format!("{:x}", Sha256::digest(b"abc")) != expected {
                return Ok(false);
            }
            // The native calculator must reject an incomplete public test vector
            // through its checked C ABI, without aborting or exposing diagnostics.
            Ok(ecdsa_spartan2::circuits::show_circuit::show_witness("{}").is_err())
        })
        .unwrap_or(false)
    }
    #[cfg(not(feature = "native-witness"))]
    {
        false
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ZkProofError {
    #[error("Invalid OpenAC input")]
    InvalidInput { message: String },
    #[error("OpenAC storage operation failed")]
    IoError { message: String },
    #[error("OpenAC proof operation failed")]
    Proof,
    #[error("OpenAC worker unavailable")]
    Worker,
    #[error("OpenAC operation cancelled")]
    Cancelled,
}

pub struct ProofResult {
    pub prep_ms: u64,
    pub prove_ms: u64,
    pub total_ms: u64,
    pub proof_size_bytes: u64,
    pub comm_w_shared: String,
}

/// Verified public field elements, in circuit order, encoded as decimal.
pub struct PublicSignals {
    pub prepare: Vec<String>,
    pub show: Vec<String>,
}

thread_local! { static PRIVATE_WORKER: Cell<bool> = const { Cell::new(false) }; }
type CancellationCheck = Arc<dyn Fn() -> bool + Send + Sync>;
thread_local! { static CANCEL_CHECK: RefCell<Option<CancellationCheck>> = const { RefCell::new(None) }; }

/// Scope the host token to this operation without sharing cancellation across callers.
pub fn with_cancellation<T>(
    check: CancellationCheck,
    work: impl FnOnce() -> Result<T, ZkProofError>,
) -> Result<T, ZkProofError> {
    struct Restore(Option<CancellationCheck>);
    impl Drop for Restore {
        fn drop(&mut self) {
            CANCEL_CHECK.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let previous = CANCEL_CHECK.with(|slot| slot.replace(Some(check)));
    let _restore = Restore(previous);
    check_cancelled()?;
    work()
}

fn check_cancelled() -> Result<(), ZkProofError> {
    if CANCEL_CHECK.with(|slot| slot.borrow().as_ref().is_some_and(|check| check())) {
        Err(ZkProofError::Cancelled)
    } else {
        Ok(())
    }
}

fn worker<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, ZkProofError> + Send + 'static,
) -> Result<T, ZkProofError> {
    check_cancelled()?;
    let cancellation = CANCEL_CHECK.with(|slot| slot.borrow().clone());
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !PRIVATE_WORKER.try_with(Cell::get).unwrap_or(false) {
                previous(info);
            }
        }));
    });
    std::thread::Builder::new()
        .name("openac-proof".into())
        .stack_size(PROVER_STACK_BYTES)
        .spawn(move || {
            PRIVATE_WORKER.set(true);
            CANCEL_CHECK.with(|slot| *slot.borrow_mut() = cancellation.clone());
            // Upstream assertions can contain witnesses, including on Rayon threads.
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(2)
                .stack_size(PROVER_STACK_BYTES)
                .start_handler(move |_| {
                    PRIVATE_WORKER.set(true);
                    CANCEL_CHECK.with(|slot| *slot.borrow_mut() = cancellation.clone());
                })
                .build()
                .map_err(|_| ZkProofError::Worker)?;
            pool.install(move || {
                check_cancelled()?;
                let result = work();
                check_cancelled()?;
                result
            })
        })
        .map_err(|_| ZkProofError::Worker)?
        .join()
        .map_err(|_| ZkProofError::Proof)?
}

fn make_config(documents_path: &str) -> PathConfig {
    PathConfig {
        base_dir: documents_path.into(),
        is_mobile: true,
        circuit_size: CircuitSize::Kb2,
    }
}

fn storage_error() -> ZkProofError {
    ZkProofError::IoError {
        message: "storage".into(),
    }
}

fn pinned_asset(path: impl AsRef<Path>, size: u64, hash: &str) -> Result<(), ZkProofError> {
    let mut file = fs::File::open(path).map_err(|_| storage_error())?;
    if file.metadata().map_err(|_| storage_error())?.len() != size {
        return Err(ZkProofError::InvalidInput {
            message: "asset_identity".into(),
        });
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        check_cancelled()?;
        let count = file.read(&mut buffer).map_err(|_| storage_error())?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if format!("{:x}", digest.finalize()) != hash {
        return Err(ZkProofError::InvalidInput {
            message: "asset_identity".into(),
        });
    }
    Ok(())
}

fn pinned_verifying_keys(config: &PathConfig) -> Result<(), ZkProofError> {
    pinned_asset(
        config.key_path(PREPARE_VERIFYING_KEY),
        431866442,
        "9b45cc7462a236b1056d21c19e1e4dfc2cf52fd20538d43fbe072d9ed106e9d6",
    )?;
    pinned_asset(
        config.key_path(SHOW_VERIFYING_KEY),
        4862746,
        "f0c447a9757d182e8aa23083bc3dba5a9a22f3e0fcbb344724568cc3c83352d8",
    )
}

fn pinned_proving_assets(config: &PathConfig, prepare: bool) -> Result<(), ZkProofError> {
    pinned_verifying_keys(config)?;
    if prepare {
        pinned_asset(
            config.r1cs_path("jwt"),
            374342852,
            "d4f8b34dfd454234872a34f47ea486545cb4d989c41ed75f856268718251dc6a",
        )?;
        pinned_asset(
            config.key_path(PREPARE_PROVING_KEY),
            431866474,
            "853657d2e701215a65c5d97ab3cf5640e9aa8379ac6d106b7c82dc9b9d078e79",
        )
    } else {
        pinned_asset(
            config.r1cs_path("show"),
            4017428,
            "3809e70502fa90f2038760da5f1399a1e3eb17923e5af872edf3dfa0b7d37a9a",
        )?;
        pinned_asset(
            config.key_path(SHOW_PROVING_KEY),
            4862778,
            "809f24ca6ee003b684e2282b77f5a47279528edee7654a3801770a2ffca67831",
        )
    }
}

fn private_write(path: PathBuf, data: Vec<u8>) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&data)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

fn private_file(path: &Path) -> Result<(), ZkProofError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|_| storage_error())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| storage_error())?;
    }
    Ok(())
}

pub fn create_age_prepare_input(
    documents_path: String,
    sd_jwt: String,
    issuer_key_x: String,
    issuer_key_y: String,
) -> Result<AgePrepareInput, ZkProofError> {
    worker(move || {
        predicate::create_age_prepare_input(documents_path, sd_jwt, issuer_key_x, issuer_key_y)
    })
}

pub fn create_age_show_input(
    documents_path: String,
    nonce: String,
    device_signature: String,
    claim_name: String,
    claim_format: u8,
    cutoff: u64,
) -> Result<(), ZkProofError> {
    worker(move || {
        predicate::create_age_show_input(
            documents_path,
            nonce,
            device_signature,
            claim_name,
            claim_format,
            cutoff,
        )
    })
}

const PREPARE: [&str; 5] = [
    PREPARE_PROVING_KEY,
    PREPARE_VERIFYING_KEY,
    PREPARE_INSTANCE,
    PREPARE_WITNESS,
    PREPARE_PROOF,
];
const SHOW: [&str; 5] = [
    SHOW_PROVING_KEY,
    SHOW_VERIFYING_KEY,
    SHOW_INSTANCE,
    SHOW_WITNESS,
    SHOW_PROOF,
];

fn result(
    config: &PathConfig,
    names: [&str; 5],
    started: Instant,
) -> Result<ProofResult, ZkProofError> {
    let total_ms = started.elapsed().as_millis() as u64;
    let instance = load_instance(config.artifact_path(names[2])).map_err(|_| storage_error())?;
    Ok(ProofResult {
        prep_ms: 0,
        prove_ms: total_ms,
        total_ms,
        proof_size_bytes: fs::metadata(config.artifact_path(names[4]))
            .map_err(|_| storage_error())?
            .len(),
        comm_w_shared: format!("{:?}", instance.comm_W_shared),
    })
}

fn prove<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(
    config: &PathConfig,
    circuit: C,
    names: [&str; 5],
) -> Result<ProofResult, ZkProofError> {
    let started = Instant::now();
    let [key, verifying_key, instance_name, witness_name, proof_name] = names;
    pinned_proving_assets(config, key == PREPARE_PROVING_KEY)?;
    let pk = load_proving_key(config.key_path(key)).map_err(|_| storage_error())?;
    let (proof, instance, witness) =
        prove_circuit_in_memory(circuit, &pk).map_err(|_| ZkProofError::Proof)?;
    drop(pk);
    check_cancelled()?;
    let vk = load_verifying_key(config.key_path(verifying_key)).map_err(|_| storage_error())?;
    // Every proof is verified before its artifacts are published.
    proof.verify(&vk).map_err(|_| ZkProofError::Proof)?;
    check_cancelled()?;
    for name in [instance_name, witness_name, proof_name] {
        private_file(&config.artifact_path(name))?;
    }
    save_instance(config.artifact_path(instance_name), &instance).map_err(|_| storage_error())?;
    save_witness(config.artifact_path(witness_name), &witness).map_err(|_| storage_error())?;
    save_proof(config.artifact_path(proof_name), &proof).map_err(|_| storage_error())?;
    result(config, names, started)
}

pub fn prove_jwt(documents_path: String) -> Result<ProofResult, ZkProofError> {
    worker(move || {
        let config = make_config(&documents_path);
        let circuit = PrepareCircuit::new(
            config.clone(),
            Some(Path::new(&documents_path).join("jwt_input.json")),
        );
        prove(&config, circuit, PREPARE)
    })
}

pub fn prove_show(documents_path: String) -> Result<ProofResult, ZkProofError> {
    worker(move || {
        let config = make_config(&documents_path);
        let circuit = ShowCircuit::new(
            config.clone(),
            Some(Path::new(&documents_path).join("show_input.json")),
        );
        prove(&config, circuit, SHOW)
    })
}

pub fn generate_shared_blinds(documents_path: String) -> Result<String, ZkProofError> {
    worker(move || {
        let config = make_config(&documents_path);
        let path = config.artifact_path(SHARED_BLINDS);
        private_file(&path)?;
        save_shared_blinds::<E>(&path, &[<E as Engine>::Scalar::random(OsRng)])
            .map_err(|_| storage_error())?;
        Ok("Shared blinds generated".into())
    })
}

fn reblind_proof(config: PathConfig, names: [&str; 5]) -> Result<ProofResult, ZkProofError> {
    let started = Instant::now();
    let [key, verifying_key, instance_name, witness_name, proof_name] = names;
    pinned_proving_assets(&config, key == PREPARE_PROVING_KEY)?;
    let pk = load_proving_key(config.key_path(key)).map_err(|_| storage_error())?;
    let instance =
        load_instance(config.artifact_path(instance_name)).map_err(|_| storage_error())?;
    let witness = load_witness(config.artifact_path(witness_name)).map_err(|_| storage_error())?;
    let blinds = load_shared_blinds::<E>(config.artifact_path(SHARED_BLINDS))
        .map_err(|_| storage_error())?;
    let (proof, instance, witness) =
        reblind_in_memory(&pk, instance, witness, &blinds).map_err(|_| ZkProofError::Proof)?;
    drop(pk);
    check_cancelled()?;
    let vk = load_verifying_key(config.key_path(verifying_key)).map_err(|_| storage_error())?;
    proof.verify(&vk).map_err(|_| ZkProofError::Proof)?;
    check_cancelled()?;
    save_instance(config.artifact_path(instance_name), &instance).map_err(|_| storage_error())?;
    save_witness(config.artifact_path(witness_name), &witness).map_err(|_| storage_error())?;
    save_proof(config.artifact_path(proof_name), &proof).map_err(|_| storage_error())?;
    result(&config, names, started)
}

pub fn reblind_jwt(documents_path: String) -> Result<ProofResult, ZkProofError> {
    worker(move || reblind_proof(make_config(&documents_path), PREPARE))
}

pub fn reblind_show(documents_path: String) -> Result<ProofResult, ZkProofError> {
    worker(move || reblind_proof(make_config(&documents_path), SHOW))
}

pub fn verify_age_presentation(
    documents_path: String,
    nonce: String,
    claim_name: String,
    claim_format: u8,
    cutoff: u64,
    expected_issuer_key_x: String,
    expected_issuer_key_y: String,
) -> Result<bool, ZkProofError> {
    worker(move || {
        pinned_verifying_keys(&make_config(&documents_path))?;
        predicate::verify_age_presentation(
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

/// Read authenticated public signals; these do not replace the age policy check.
pub fn read_public_signals(documents_path: String) -> Result<PublicSignals, ZkProofError> {
    worker(move || {
        let config = make_config(&documents_path);
        pinned_verifying_keys(&config)?;
        let prepare =
            load_proof(config.artifact_path(PREPARE_PROOF)).map_err(|_| storage_error())?;
        let show = load_proof(config.artifact_path(SHOW_PROOF)).map_err(|_| storage_error())?;
        let prepare_vk = load_verifying_key(config.key_path(PREPARE_VERIFYING_KEY))
            .map_err(|_| storage_error())?;
        let show_vk =
            load_verifying_key(config.key_path(SHOW_VERIFYING_KEY)).map_err(|_| storage_error())?;
        let (prepare, show) =
            ecdsa_spartan2::prover::verify_linked(&prepare, &prepare_vk, &show, &show_vk)
                .ok_or(ZkProofError::Proof)?;
        let decimal = |values: Vec<<E as Engine>::Scalar>| {
            values
                .iter()
                .map(|v| BigUint::from_bytes_le(v.to_repr().as_ref()).to_str_radix(10))
                .collect()
        };
        Ok(PublicSignals {
            prepare: decimal(prepare),
            show: decimal(show),
        })
    })
}

#[cfg(test)]
mod hosting_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn worker_panic_is_redacted() {
        let result: Result<(), ZkProofError> = worker(|| panic!("synthetic-private-witness"));
        assert!(matches!(result, Err(ZkProofError::Proof)));
    }

    #[test]
    fn cancellation_during_work_discards_success() {
        let token = Arc::new(AtomicBool::new(false));
        let check = Arc::clone(&token);
        let result = with_cancellation(Arc::new(move || check.load(Ordering::Acquire)), || {
            worker(move || {
                token.store(true, Ordering::Release);
                Ok(42)
            })
        });
        assert!(matches!(result, Err(ZkProofError::Cancelled)));
    }

    #[test]
    fn wrong_asset_identity_and_oversized_proof_fail_safely() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), b"synthetic-public-asset").unwrap();
        let result = pinned_asset(file.path(), 22, "wrong-public-hash");
        assert!(matches!(result, Err(ZkProofError::InvalidInput { .. })));
        file.as_file().set_len(32 * 1024 * 1024 + 1).unwrap();
        assert!(load_proof(file.path()).is_err());
    }
}
