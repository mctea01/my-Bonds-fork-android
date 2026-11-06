//! Serialized access to Barretenberg's process-global CRS and worker state.
use crate::{acir::Executed, assets, public, Error, Result};
use std::io::Read;
use std::{
    path::Path,
    sync::{Mutex, MutexGuard},
};
/// The process-global CRS: none yet, verification only ([1]_1 and [x]_2), or the full G1 prefix.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Crs {
    None,
    Verifier,
    Full,
}
static BACKEND: Mutex<Crs> = Mutex::new(Crs::None);
unsafe extern "C" {
    fn zkpdf_bb_init(g1: *const u8, n1: usize, g2: *const u8, n2: usize) -> i32;
    fn zkpdf_bb_init_verifier() -> i32;
    fn zkpdf_bb_prove(
        acir: *const u8,
        na: usize,
        vk: *const u8,
        nv: usize,
        witness: *const u8,
        nw: usize,
        proof: *mut u8,
        np: usize,
        written: *mut usize,
        pi: *mut u8,
        ni: usize,
    ) -> i32;
    fn zkpdf_bb_vk(
        acir: *const u8,
        na: usize,
        vk: *mut u8,
        capacity: usize,
        written: *mut usize,
    ) -> i32;
    fn zkpdf_bb_verify(
        vk: *const u8,
        nv: usize,
        proof: *const u8,
        np: usize,
        pi: *const u8,
        ni: usize,
    ) -> i32;
}
// bbapi consumes decompressed serialization; the CLI performs this
// step in get_bytecode before calling exactly the same entry point.
fn unpack(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut out)
        .map_err(|_| Error("backend_encoding"))?;
    if out.len() > 512 * 1024 * 1024 {
        return Err(Error("backend_size"));
    }
    Ok(out)
}
pub struct Session {
    _guard: MutexGuard<'static, Crs>,
}
impl Session {
    pub fn open(directory: &Path) -> Result<Self> {
        // Authenticate even if another caller initialized the shared CRS.
        let (g1, g2) = assets::crs(directory)?;
        let mut guard = BACKEND.lock().map_err(|_| Error("backend_state"))?;
        match *guard {
            Crs::Full => {}
            // Barretenberg keeps the first CRS; proving needs the app to start again.
            Crs::Verifier => return Err(Error("crs_verifier_only")),
            Crs::None => {
                // SAFETY: verified buffers remain live, sizes are exact, the mutex
                // excludes all other calls, and C++ catches every exception.
                if unsafe { zkpdf_bb_init(g1.as_ptr(), g1.len(), g2.as_ptr(), g2.len()) } != 0 {
                    return Err(Error("crs_initialize"));
                }
                *guard = Crs::Full;
            }
        }
        Ok(Self { _guard: guard })
    }
    /// A session for verification only. With `directory` holding the authenticated full CRS that CRS is
    /// installed (so later proving still works); without it only the two ceremony constants are.
    pub fn open_verifier(directory: Option<&Path>) -> Result<Self> {
        if let Some(d) = directory {
            if assets::crs(d).is_ok() {
                return match Self::open(d) {
                    Err(Error("crs_verifier_only")) => Self::verifier_only(),
                    other => other,
                };
            }
        }
        Self::verifier_only()
    }
    fn verifier_only() -> Result<Self> {
        let mut guard = BACKEND.lock().map_err(|_| Error("backend_state"))?;
        if *guard == Crs::None {
            // SAFETY: no buffers cross the boundary; the mutex excludes all other calls.
            if unsafe { zkpdf_bb_init_verifier() } != 0 {
                return Err(Error("crs_initialize"));
            }
            *guard = Crs::Verifier;
        }
        Ok(Self { _guard: guard })
    }
    pub fn prove(&self, vk: &[u8], executed: &Executed) -> Result<Vec<u8>> {
        let bytecode = unpack(&executed.bytecode)?;
        let witness = unpack(&executed.witness)?;
        let mut proof = vec![0; 2 * crate::PROOF_BYTES];
        let mut written = 0usize;
        let mut pi = vec![0; executed.public_inputs.len()];
        // SAFETY: slices remain live and all output capacity is provided.
        let status = unsafe {
            zkpdf_bb_prove(
                bytecode.as_ptr(),
                bytecode.len(),
                vk.as_ptr(),
                vk.len(),
                witness.as_ptr(),
                witness.len(),
                proof.as_mut_ptr(),
                proof.len(),
                &mut written,
                pi.as_mut_ptr(),
                pi.len(),
            )
        };
        if status != 0 {
            return Err(Error("proof_failed"));
        }
        if written != crate::PROOF_BYTES {
            return Err(Error("proof_size"));
        }
        proof.truncate(written);
        if pi != executed.public_inputs {
            return Err(Error("proof_public_mismatch"));
        }
        Ok(proof)
    }
    /// Derives a verification key from a nargo artifact (build tooling only).
    pub fn vk(&self, artifact: &[u8]) -> Result<Vec<u8>> {
        let bytecode = unpack(&crate::acir::bytecode(artifact)?)?;
        let mut vk = vec![0; 16384];
        let mut written = 0usize;
        // SAFETY: slices remain live, capacity is passed and C++ catches every exception.
        let status = unsafe {
            zkpdf_bb_vk(
                bytecode.as_ptr(),
                bytecode.len(),
                vk.as_mut_ptr(),
                vk.len(),
                &mut written,
            )
        };
        if status != 0 || written == 0 || written > vk.len() {
            return Err(Error("vk_failed"));
        }
        vk.truncate(written);
        Ok(vk)
    }
    pub fn verify(&self, vk: &[u8], proof: &[u8], pi: &[u8]) -> Result<()> {
        public::decode(proof, crate::PROOF_BYTES / 32)?;
        self.verify_any(vk, proof, pi)
    }
    /// Any zero-knowledge UltraHonk (Poseidon2) proof: the size is checked by Barretenberg against the key.
    pub fn verify_any(&self, vk: &[u8], proof: &[u8], pi: &[u8]) -> Result<()> {
        if proof.is_empty() || proof.len() % 32 != 0 || pi.len() % 32 != 0 {
            return Err(Error("proof_encoding"));
        }
        public::decode(proof, proof.len() / 32)?;
        public::decode(pi, pi.len() / 32)?;
        // SAFETY: verified VK and canonically encoded fields are live slices;
        // the session lock excludes concurrent mutations of global state.
        if unsafe {
            zkpdf_bb_verify(
                vk.as_ptr(),
                vk.len(),
                proof.as_ptr(),
                proof.len(),
                pi.as_ptr(),
                pi.len(),
            )
        } == 0
        {
            Ok(())
        } else {
            Err(Error("proof_invalid"))
        }
    }
}
