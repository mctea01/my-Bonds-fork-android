//! Canonical BN254 encoding and the frozen Poseidon2 commitment sponge.
use crate::{Error, Result};
pub use acvm::acir::FieldElement as F;
use acvm::AcirField;
use serde_json::Value;

pub fn number(n: usize) -> F {
    F::from(n)
}
pub fn ascii(s: &str) -> F {
    F::from_be_bytes_reduce(s.as_bytes())
}
pub fn json(f: F) -> Value {
    Value::String(format!("0x{}", f.to_hex()))
}
pub fn hash(fields: &[F]) -> Result<F> {
    bn254_blackbox_solver::poseidon_hash(fields).map_err(|_| Error("poseidon"))
}
pub fn commit(tag: usize, salt: F, data: &[F]) -> Result<F> {
    let mut fields = vec![number(tag), salt, number(data.len())];
    fields.extend_from_slice(data);
    hash(&fields)
}
pub fn pack(data: &[u8]) -> Vec<F> {
    data.chunks(31).map(F::from_be_bytes_reduce).collect()
}
pub fn bytes_commit(
    tag: usize,
    salt: F,
    index: Option<usize>,
    data: &[u8],
    capacity: usize,
) -> Result<F> {
    if data.len() > capacity {
        return Err(Error("commit_capacity"));
    }
    let mut padded = data.to_vec();
    padded.resize(capacity, 0);
    let mut fields = Vec::new();
    if let Some(index) = index {
        fields.push(number(index));
    }
    fields.push(number(data.len()));
    fields.extend(pack(&padded));
    commit(tag, salt, &fields)
}
pub fn fingerprint(data: &[u8], r: F) -> F {
    data.iter()
        .fold(F::zero(), |a, b| a * r + number(*b as usize))
}
pub fn power(r: F, mut n: usize) -> F {
    let mut result = F::one();
    let mut base = r;
    while n != 0 {
        if n & 1 != 0 {
            result = result * base;
        }
        base = base * base;
        n >>= 1;
    }
    result
}
pub fn fresh_salt() -> Result<F> {
    let mut bytes = [0u8; 31];
    getrandom::getrandom(&mut bytes).map_err(|_| Error("random_unavailable"))?;
    Ok(F::from_be_bytes_reduce(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frozen_known_answers() {
        let a = commit(1, number(42), &[number(0), number(1), number(2)]).unwrap();
        assert!(a.to_hex() == "0e38abf00bd0aeb288ed74a01e99cec931b4904f6ba8aec4b9aa762107256dea");
        let b = commit(2, number(42), &[]).unwrap();
        assert!(b.to_hex() == "2bea62b95fd366e7903877a49f491dcbb320cd4c7d1b26bb9ed8baa75a564cdf");
        assert!(pack(&[1, 2, 3]) == vec![number(66051)]);
    }
}
