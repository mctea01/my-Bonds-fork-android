//! Serialized access to Barretenberg's process-global CRS and worker state.
use crate::{acir::Executed, assets, public, Error, Result};
use std::io::Read;
use std::{
    path::Path,
    sync::{Mutex, MutexGuard},
};
static BACKEND: Mutex<bool> = Mutex::new(false);
unsafe extern "C" {
    fn zkpdf_bb_init(g1: *const u8, n1: usize, g2: *const u8, n2: usize) -> i32;
    fn zkpdf_bb_prove(
        acir: *const u8,
        na: usize,
        vk: *const u8,
        nv: usize,
        witness: *const u8,
        nw: usize,
        proof: *mut u8,
        np: usize,
        pi: *mut u8,
        ni: usize,
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
pub struct Session {
    _guard: MutexGuard<'static, bool>,
}
impl Session {
    pub fn open(directory: &Path) -> Result<Self> {
        // Authenticate even if another caller initialized the shared CRS.
        let (g1, g2) = assets::crs(directory)?;
        let mut guard = BACKEND.lock().map_err(|_| Error("backend_state"))?;
        if !*guard {
            // SAFETY: verified buffers remain live, sizes are exact, the mutex
            // excludes all other calls, and C++ catches every exception.
            if unsafe { zkpdf_bb_init(g1.as_ptr(), g1.len(), g2.as_ptr(), g2.len()) } != 0 {
                return Err(Error("crs_initialize"));
            }
            *guard = true;
        }
        Ok(Self { _guard: guard })
    }
    pub fn prove(&self, vk: &[u8], executed: &Executed) -> Result<Vec<u8>> {
        // bbapi consumes decompressed serialization; the CLI performs this
        // step in get_bytecode before calling exactly the same entry point.
        let unpack = |data: &[u8]| -> Result<Vec<u8>> {
            let mut out = Vec::new();
            flate2::read::GzDecoder::new(data)
                .take(512 * 1024 * 1024 + 1)
                .read_to_end(&mut out)
                .map_err(|_| Error("backend_encoding"))?;
            if out.len() > 512 * 1024 * 1024 {
                return Err(Error("backend_size"));
            }
            Ok(out)
        };
        let bytecode = unpack(&executed.bytecode)?;
        let witness = unpack(&executed.witness)?;
        let mut proof = vec![0; 16256];
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
                pi.as_mut_ptr(),
                pi.len(),
            )
        };
        if status != 0 {
            return Err(Error("proof_failed"));
        }
        if pi != executed.public_inputs {
            return Err(Error("proof_public_mismatch"));
        }
        Ok(proof)
    }
    pub fn verify(&self, vk: &[u8], proof: &[u8], pi: &[u8]) -> Result<()> {
        public::decode(proof, 508)?;
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
