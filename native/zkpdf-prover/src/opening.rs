//! Frozen SHA-256 field opening, used by disclosure consumers after verification.
use crate::{Error, Result};
use sha2::{Digest, Sha256};
pub fn verify_opening(slot: u32, salt: &[u8], records: &[u8], digest: &[u8]) -> Result<()> {
    if slot >= 12 || salt.len() != 16 || records.len() > 384 || digest.len() != 32 {
        return Err(Error("opening_shape"));
    }
    let mut padded = [0u8; 384];
    padded[..records.len()].copy_from_slice(records);
    let mut hash = Sha256::new();
    hash.update(b"diw-zkpdf-claim-v1");
    hash.update([slot as u8]);
    hash.update(salt);
    hash.update((records.len() as u16).to_be_bytes());
    hash.update(padded);
    if hash.finalize().as_slice() == digest {
        Ok(())
    } else {
        Err(Error("opening_digest"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn z5_slot_and_record_mutations_fail() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-servers/src/test/resources/zkpdf/student.json"
        ))
        .unwrap();
        let input: crate::ZkPdfProveInput =
            serde_json::from_value(fixture["input"].clone()).unwrap();
        let prepared = crate::prepare::prepare(&input, crate::field::number(42)).unwrap();
        for slot in input.slots {
            let index = slot.slot as usize;
            let record = &prepared.records[index];
            let digest = &prepared.digests[index];
            assert!(verify_opening(slot.slot, &slot.salt, record, digest).is_ok());
            assert!(verify_opening((slot.slot + 1) % 12, &slot.salt, record, digest).is_err());
            let mut changed = record.clone();
            changed[0] ^= 1;
            assert!(verify_opening(slot.slot, &slot.salt, &changed, digest).is_err());
        }
    }
}
