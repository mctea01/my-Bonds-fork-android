//! Barretenberg 5 for zkPassport proofs of circuits before 0.22.0, which do not verify under bb v6 keys. It is a
//! library of its own, delivered apart from the app (a Play on-demand module on Android) and loaded by diw-zk-ffi
//! at run time. Only the functions below are exported, so its C++ symbols never meet those of the bb v6 build.
use std::os::raw::c_char;
use std::sync::Mutex;

pub const BB_REVISION: &str = "5.0.0+7aa2bd616d632801fe65d97ee8a4434f26886b40";
/// The C ABI version; diw-zk-ffi refuses a library with another one.
pub const ABI: u32 = 1;
const REVISION_C: &[u8] = b"5.0.0+7aa2bd616d632801fe65d97ee8a4434f26886b40\0";

/// The BN254 scalar field modulus, big-endian.
const MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d, 0x28, 0x33, 0xe8,
    0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

#[cfg(feature = "bb")]
unsafe extern "C" {
    fn diw_bb5_bridge_init() -> i32;
    fn diw_bb5_bridge_verify(vk: *const u8, nv: usize, proof: *const u8, np: usize, pi: *const u8, npi: usize) -> i32;
    #[cfg(feature = "vk")]
    fn diw_bb5_bridge_init_full(g1: *const u8, n1: usize) -> i32;
    #[cfg(feature = "vk")]
    fn diw_bb5_bridge_vk(acir: *const u8, na: usize, vk: *mut u8, capacity: usize, written: *mut usize) -> i32;
}

/// Whether the verifier CRS is installed; the lock also serializes calls into Barretenberg's global state.
static READY: Mutex<bool> = Mutex::new(false);

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Not a sequence of canonical field elements.
    Encoding,
    /// Barretenberg checked the proof and refused it.
    Rejected,
    /// Barretenberg could not run (a malformed key, or a build without it).
    Backend,
}

fn canonical(bytes: &[u8]) -> bool {
    bytes.len() % 32 == 0 && bytes.chunks_exact(32).all(|f| f < &MODULUS[..])
}

/// Verifies a zero-knowledge UltraHonk (Poseidon2) proof made with Barretenberg 5 under its key [vk].
pub fn verify(vk: &[u8], proof: &[u8], public_inputs: &[u8]) -> Result<(), Error> {
    if vk.is_empty() || vk.len() % 32 != 0 || proof.is_empty() || !canonical(proof) || !canonical(public_inputs) {
        return Err(Error::Encoding);
    }
    let mut ready = READY.lock().map_err(|_| Error::Backend)?;
    #[cfg(feature = "bb")]
    {
        // SAFETY: the bridge catches every C++ exception and copies the slices, which stay live for the call.
        if !*ready {
            if unsafe { diw_bb5_bridge_init() } != 0 {
                return Err(Error::Backend);
            }
            *ready = true;
        }
        match unsafe {
            diw_bb5_bridge_verify(
                vk.as_ptr(),
                vk.len(),
                proof.as_ptr(),
                proof.len(),
                public_inputs.as_ptr(),
                public_inputs.len(),
            )
        } {
            0 => Ok(()),
            1 => Err(Error::Rejected),
            _ => Err(Error::Backend),
        }
    }
    #[cfg(not(feature = "bb"))]
    {
        let _ = &mut ready;
        Err(Error::Backend)
    }
}

/// Tests only: installs a full CRS prefix ([g1] as 64-byte points) and derives the key of an ACIR program.
#[cfg(feature = "vk")]
pub fn write_vk(g1: &[u8], acir: &[u8]) -> Option<Vec<u8>> {
    let mut ready = READY.lock().ok()?;
    // SAFETY: as in [verify]; Barretenberg keeps the first CRS, so this runs before any verification.
    if !*ready {
        if unsafe { diw_bb5_bridge_init_full(g1.as_ptr(), g1.len()) } != 0 {
            return None;
        }
        *ready = true;
    }
    let mut vk = vec![0; 16384];
    let mut written = 0usize;
    let status = unsafe { diw_bb5_bridge_vk(acir.as_ptr(), acir.len(), vk.as_mut_ptr(), vk.len(), &mut written) };
    (status == 0 && written > 0 && written <= vk.len()).then(|| {
        vk.truncate(written);
        vk
    })
}

#[no_mangle]
pub extern "C" fn diw_bb5_abi() -> u32 {
    ABI
}

/// The pinned Barretenberg revision, NUL-terminated and static.
#[no_mangle]
pub extern "C" fn diw_bb5_revision() -> *const c_char {
    REVISION_C.as_ptr().cast()
}

/// 0 when the proof verifies, 1 when Barretenberg refuses it, 2 for malformed input and 3 when the backend fails.
///
/// # Safety
/// Each pointer must be valid for reads of its length (or the length be 0) for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn diw_bb5_verify(
    vk: *const u8,
    vk_len: usize,
    proof: *const u8,
    proof_len: usize,
    public_inputs: *const u8,
    public_inputs_len: usize,
) -> i32 {
    unsafe fn slice<'a>(p: *const u8, n: usize) -> Option<&'a [u8]> {
        if n == 0 {
            Some(&[])
        } else if p.is_null() {
            None
        } else {
            Some(unsafe { std::slice::from_raw_parts(p, n) })
        }
    }
    let (Some(vk), Some(proof), Some(pi)) =
        (unsafe { slice(vk, vk_len) }, unsafe { slice(proof, proof_len) }, unsafe { slice(public_inputs, public_inputs_len) })
    else {
        return 2;
    };
    match std::panic::catch_unwind(|| verify(vk, proof, pi)) {
        Ok(Ok(())) => 0,
        Ok(Err(Error::Rejected)) => 1,
        Ok(Err(Error::Encoding)) => 2,
        _ => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Vec<u8> {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../zkpassport-verify/tests/data/compare_age-0.21.1.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["bb_version"], "5.0.0");
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, v["vkey"].as_str().unwrap()).unwrap()
    }

    #[test]
    fn exports_its_revision_and_abi() {
        assert_eq!(diw_bb5_abi(), ABI);
        let s = unsafe { std::ffi::CStr::from_ptr(diw_bb5_revision()) };
        assert_eq!(s.to_str().unwrap(), BB_REVISION);
    }

    #[test]
    fn malformed_input_never_reaches_barretenberg() {
        let vk = key();
        assert_eq!(verify(&vk, &[], &[]), Err(Error::Encoding));
        assert_eq!(verify(&vk, &[0; 31], &[]), Err(Error::Encoding));
        assert_eq!(verify(&vk, &MODULUS, &[]), Err(Error::Encoding));
        assert_eq!(verify(&[], &[0; 32], &[]), Err(Error::Encoding));
        assert_eq!(unsafe { diw_bb5_verify(std::ptr::null(), 32, std::ptr::null(), 0, std::ptr::null(), 0) }, 2);
    }

    /// A proof of the right shape that zkPassport never made: Barretenberg 5 must refuse it, not crash.
    #[cfg(feature = "bb")]
    #[test]
    fn forged_proof_is_rejected() {
        let vk = key();
        let fields = |n: usize, seed: u8| -> Vec<u8> {
            (0..n).flat_map(|i| {
                let mut f = [0u8; 32];
                f[31] = seed.wrapping_add(i as u8);
                f[30] = (i >> 8) as u8;
                f
            }).collect()
        };
        let public_inputs = u32::from_be_bytes(vk[60..64].try_into().unwrap()) as usize;
        for size in [400, 456, 458, 500] {
            let r = verify(&vk, &fields(size, 7), &fields(public_inputs, 3));
            assert!(matches!(r, Err(Error::Rejected) | Err(Error::Backend)), "{size}: {r:?}");
        }
    }

    /// Derives the key of a packaged zkPassport circuit of a version before 0.22.0 and compares it with the one
    /// zkPassport published: DIW_BB5_CIRCUIT is the packaged circuit JSON, DIW_BB5_CRS a CRS prefix large enough.
    #[cfg(feature = "vk")]
    #[test]
    #[ignore = "requires a packaged circuit and a CRS prefix"]
    fn derives_the_published_key() {
        use std::io::Read;
        let text = std::fs::read_to_string(std::env::var_os("DIW_BB5_CIRCUIT").expect("DIW_BB5_CIRCUIT")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let b64 = |s: &str| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s).unwrap();
        let mut acir = Vec::new();
        flate2::read::GzDecoder::new(&b64(v["bytecode"].as_str().unwrap())[..]).read_to_end(&mut acir).unwrap();
        let g1 = std::fs::read(std::env::var_os("DIW_BB5_CRS").expect("DIW_BB5_CRS")).unwrap();
        let derived = write_vk(&g1, &acir).expect("vk");
        assert_eq!(derived, b64(v["vkey"].as_str().unwrap()));
    }
}
