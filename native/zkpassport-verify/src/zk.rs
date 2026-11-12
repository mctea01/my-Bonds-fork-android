//! The field helpers zkPassport's circuits and SDK (@zkpassport/utils) define: Poseidon2 over BN254, byte and
//! bit packing, verification key fields and the circuit registry tree. Written against the SDK's behaviour;
//! the published manifest root and packaged key hash in the tests pin them to the real values.

use acvm::{acir::FieldElement as F, AcirField};
use num_bigint::BigUint;

/// Height of the circuit registry tree.
pub const CIRCUIT_REGISTRY_HEIGHT: usize = 12;

fn to_field(x: &BigUint) -> F {
    F::from_be_bytes_reduce(&x.to_bytes_be())
}

fn from_field(f: F) -> BigUint {
    BigUint::from_bytes_be(&f.to_be_bytes())
}

/// Poseidon2 sponge as Noir's `Poseidon2::hash` and @zkpassport/poseidon2: width 4, rate 3, additive
/// absorption, IV = length << 64, output `state[0]`.
pub fn poseidon2_hash(inputs: &[BigUint]) -> BigUint {
    const RATE: usize = 3;
    let mut state = [F::zero(); RATE + 1];
    state[RATE] = F::from(inputs.len() as u128) * F::from(1u128 << 64);
    let duplex = |state: &mut [F; RATE + 1], cache: &[F]| {
        for (s, c) in state.iter_mut().zip(cache) {
            *s += *c;
        }
        let out = bn254_blackbox_solver::poseidon2_permutation(&state[..]).expect("width-4 permutation");
        state.copy_from_slice(&out);
    };
    let mut cache = Vec::with_capacity(RATE);
    for x in inputs {
        if cache.len() == RATE {
            duplex(&mut state, &cache);
            cache.clear();
        }
        cache.push(to_field(x));
    }
    duplex(&mut state, &cache);
    from_field(state[0])
}

/// `packBeBitsIntoField`: the first `max` 0/1 values, big-endian.
pub fn pack_be_bits(bits: &[u8], max: usize) -> BigUint {
    bits.iter().take(max).fold(BigUint::from(0u8), |acc, b| (acc << 1u32) + BigUint::from(*b))
}

/// `packBeBytesIntoFields`: big-endian chunks of `chunk` bytes where the first, possibly short, chunk of the
/// input lands in the last field.
pub fn pack_be_bytes(bytes: &[u8], chunk: usize) -> Vec<BigUint> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let total = bytes.len().div_ceil(chunk);
    let first = match bytes.len() % chunk {
        0 => chunk,
        r => r,
    };
    let mut out = vec![BigUint::from(0u8); total];
    let mut at = 0;
    for i in (0..total).rev() {
        let size = if i == total - 1 { first } else { chunk };
        out[i] = BigUint::from_bytes_be(&bytes[at..at + size]);
        at += size;
    }
    out
}

/// `ultraVkToFields`: the key's 32-byte big-endian fields.
pub fn vkey_fields(vkey: &[u8]) -> Vec<BigUint> {
    vkey.chunks(32).map(BigUint::from_bytes_be).collect()
}

/// `getNumberOfPublicInputs`.
pub fn num_public_inputs(name: &str) -> usize {
    if ["data_check_integrity", "sig_check_id_data", "sig_check_dsc"].iter().any(|p| name.starts_with(p)) {
        2
    } else {
        8
    }
}

/// Root of a binary Poseidon2 tree of `height` whose empty leaves are 0.
pub fn merkle_root(height: usize, leaves: &[BigUint]) -> BigUint {
    let mut level = leaves.to_vec();
    let mut zero = BigUint::from(0u8);
    for _ in 0..height {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).cloned().unwrap_or_else(|| zero.clone());
            next.push(poseidon2_hash(&[pair[0].clone(), right]));
        }
        if next.is_empty() {
            next.push(poseidon2_hash(&[zero.clone(), zero.clone()]));
        }
        zero = poseidon2_hash(&[zero.clone(), zero]);
        level = next;
    }
    level[0].clone()
}
