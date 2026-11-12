//! BBS signatures (BLS12-381-SHA-256) for the W3C bbs-2023 cryptosuite: baseline signatures and proofs, blind
//! signatures for anonymous holder binding, and credential-bound pseudonyms.
//!
//! The library is always built (no Cargo feature). Every operation runs on a private worker, so a panic inside the
//! curve library never prints a holder secret. Verification failures return `false`; malformed input is
//! `ZkError::InvalidInput`.

use crate::{run_worker, ZkCancelToken, ZkError};
use zkryptium::bbsplus::ciphersuites::BbsCiphersuite;
use zkryptium::bbsplus::commitment::BlindFactor;
use zkryptium::bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey};
use zkryptium::bbsplus::pseudonym::{BBSplusPseudonym, PseudonymSecret};
use zkryptium::keys::pair::KeyPair;
use zkryptium::schemes::algorithms::BbsBls12381Sha256;
use zkryptium::schemes::generics::{BlindSignature, Commitment, PoKSignature, Signature};

type Suite = BbsBls12381Sha256;

const STACK: usize = 8 * 1024 * 1024;
const PUBLIC_KEY_BYTES: usize = 96;
const SECRET_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 80;
const SCALAR_BYTES: usize = 32;
const POINT_G1_BYTES: usize = 48;
const MAX_MESSAGES: usize = 4096;

#[derive(uniffi::Record)]
pub struct BbsKeyPair {
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct BbsCommitment {
    pub commitment_with_proof: Vec<u8>,
    pub secret_prover_blind: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct BbsNymProof {
    pub proof: Vec<u8>,
    pub pseudonym: Vec<u8>,
}

fn invalid(reason: &str) -> ZkError {
    ZkError::InvalidInput {
        reason: reason.into(),
    }
}

fn run<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, ZkError> + Send + 'static,
) -> Result<T, ZkError> {
    run_worker(STACK, ZkCancelToken::new(), move |_| work())
}

fn check(work: impl FnOnce() -> Result<bool, ZkError> + Send + 'static) -> bool {
    run(work).unwrap_or(false)
}

fn public_key(bytes: &[u8]) -> Result<BBSplusPublicKey, ZkError> {
    if bytes.len() != PUBLIC_KEY_BYTES {
        return Err(invalid("public_key"));
    }
    BBSplusPublicKey::from_bytes(bytes).map_err(|_| invalid("public_key"))
}

fn secret_key(bytes: &[u8]) -> Result<BBSplusSecretKey, ZkError> {
    if bytes.len() != SECRET_KEY_BYTES {
        return Err(invalid("secret_key"));
    }
    BBSplusSecretKey::from_bytes(bytes).map_err(|_| invalid("secret_key"))
}

fn signature_bytes(bytes: &[u8]) -> Result<[u8; SIGNATURE_BYTES], ZkError> {
    bytes.try_into().map_err(|_| invalid("signature"))
}

fn scalar(bytes: &[u8], what: &str) -> Result<[u8; SCALAR_BYTES], ZkError> {
    bytes.try_into().map_err(|_| invalid(what))
}

fn blind_factor(bytes: &[u8]) -> Result<BlindFactor, ZkError> {
    BlindFactor::from_bytes(&scalar(bytes, "secret_prover_blind")?)
        .map_err(|_| invalid("secret_prover_blind"))
}

fn nym_secret(bytes: &[u8], what: &str) -> Result<PseudonymSecret, ZkError> {
    PseudonymSecret::from_bytes(&scalar(bytes, what)?).map_err(|_| invalid(what))
}

fn indexes(values: &[u64], count: usize) -> Result<Vec<usize>, ZkError> {
    let mut out = Vec::with_capacity(values.len());
    for v in values {
        let i = usize::try_from(*v).map_err(|_| invalid("disclosed_indexes"))?;
        if i >= count || out.last().is_some_and(|last| *last >= i) {
            return Err(invalid("disclosed_indexes"));
        }
        out.push(i);
    }
    Ok(out)
}

fn messages_ok(messages: &[Vec<u8>]) -> Result<(), ZkError> {
    if messages.len() > MAX_MESSAGES {
        Err(invalid("messages"))
    } else {
        Ok(())
    }
}

fn proof(bytes: &[u8]) -> Result<PoKSignature<Suite>, ZkError> {
    // A BBS proof is 3 G1 points and at least 4 scalars, plus whole scalars after that.
    let fixed = 3 * POINT_G1_BYTES + 4 * SCALAR_BYTES;
    if bytes.len() < fixed || (bytes.len() - fixed) % SCALAR_BYTES != 0 {
        return Err(invalid("proof"));
    }
    PoKSignature::<Suite>::from_bytes(bytes).map_err(|_| invalid("proof"))
}

fn commitment(bytes: &[u8]) -> Result<(), ZkError> {
    // commitment_with_proof is a G1 point and at least two scalars, plus whole scalars.
    if bytes.len() < POINT_G1_BYTES + 2 * SCALAR_BYTES
        || (bytes.len() - POINT_G1_BYTES) % SCALAR_BYTES != 0
    {
        return Err(invalid("commitment_with_proof"));
    }
    Ok(())
}

/// KeyGen of the BBS draft: a deterministic key pair from at least 32 bytes of key material.
#[uniffi::export]
pub fn bbs_generate_key_pair(
    key_material: Vec<u8>,
    key_info: Vec<u8>,
) -> Result<BbsKeyPair, ZkError> {
    if key_material.len() < <<Suite as zkryptium::schemes::algorithms::Scheme>::Ciphersuite as BbsCiphersuite>::IKM_LEN {
        return Err(invalid("key_material"));
    }
    run(move || {
        let pair = KeyPair::<Suite>::generate(&key_material, Some(&key_info), None)
            .map_err(|_| invalid("key_material"))?;
        Ok(BbsKeyPair {
            secret_key: pair.private_key().to_bytes().to_vec(),
            public_key: pair.public_key().to_bytes().to_vec(),
        })
    })
}

/// SkToPk.
#[uniffi::export]
pub fn bbs_public_key(secret_key_bytes: Vec<u8>) -> Result<Vec<u8>, ZkError> {
    run(move || {
        Ok(secret_key(&secret_key_bytes)?
            .public_key()
            .to_bytes()
            .to_vec())
    })
}

/// A uniformly random non-zero scalar (prover_nym, signer_nym_entropy).
#[uniffi::export]
pub fn bbs_random_scalar() -> Vec<u8> {
    PseudonymSecret::random().to_bytes().to_vec()
}

#[uniffi::export]
pub fn bbs_sign(
    secret_key_bytes: Vec<u8>,
    public_key_bytes: Vec<u8>,
    header: Vec<u8>,
    messages: Vec<Vec<u8>>,
) -> Result<Vec<u8>, ZkError> {
    messages_ok(&messages)?;
    run(move || {
        let sk = secret_key(&secret_key_bytes)?;
        let pk = public_key(&public_key_bytes)?;
        let signature = Signature::<Suite>::sign(Some(&messages), &sk, &pk, Some(&header))
            .map_err(|_| invalid("sign"))?;
        Ok(signature.to_bytes().to_vec())
    })
}

#[uniffi::export]
pub fn bbs_verify(
    public_key_bytes: Vec<u8>,
    signature: Vec<u8>,
    header: Vec<u8>,
    messages: Vec<Vec<u8>>,
) -> bool {
    check(move || {
        messages_ok(&messages)?;
        let pk = public_key(&public_key_bytes)?;
        let signature = Signature::<Suite>::from_bytes(&signature_bytes(&signature)?)
            .map_err(|_| invalid("signature"))?;
        Ok(signature
            .verify(&pk, Some(&messages), Some(&header))
            .is_ok())
    })
}

#[uniffi::export]
pub fn bbs_proof_gen(
    public_key_bytes: Vec<u8>,
    signature: Vec<u8>,
    header: Vec<u8>,
    presentation_header: Vec<u8>,
    messages: Vec<Vec<u8>>,
    disclosed_indexes: Vec<u64>,
) -> Result<Vec<u8>, ZkError> {
    messages_ok(&messages)?;
    run(move || {
        let pk = public_key(&public_key_bytes)?;
        let disclosed = indexes(&disclosed_indexes, messages.len())?;
        let signature = signature_bytes(&signature)?;
        let proof = PoKSignature::<Suite>::proof_gen(
            &pk,
            &signature,
            Some(&header),
            Some(&presentation_header),
            Some(&messages),
            Some(&disclosed),
        )
        .map_err(|_| invalid("proof_gen"))?;
        Ok(proof.to_bytes())
    })
}

#[uniffi::export]
pub fn bbs_proof_verify(
    public_key_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
    header: Vec<u8>,
    presentation_header: Vec<u8>,
    disclosed_messages: Vec<Vec<u8>>,
    disclosed_indexes: Vec<u64>,
) -> bool {
    check(move || {
        messages_ok(&disclosed_messages)?;
        if disclosed_messages.len() != disclosed_indexes.len() {
            return Ok(false);
        }
        let pk = public_key(&public_key_bytes)?;
        let proof = proof(&proof_bytes)?;
        let disclosed = indexes(&disclosed_indexes, MAX_MESSAGES)?;
        Ok(proof
            .proof_verify(
                &pk,
                Some(&disclosed_messages),
                Some(&disclosed),
                Some(&header),
                Some(&presentation_header),
            )
            .is_ok())
    })
}

/// Commitment for anonymous holder binding (Blind BBS): committed_messages holds the holder_secret.
#[uniffi::export]
pub fn bbs_commit(committed_messages: Vec<Vec<u8>>) -> Result<BbsCommitment, ZkError> {
    messages_ok(&committed_messages)?;
    run(move || {
        let (commitment, blind) = Commitment::<Suite>::commit(Some(&committed_messages))
            .map_err(|_| invalid("commit"))?;
        Ok(BbsCommitment {
            commitment_with_proof: commitment.to_bytes(),
            secret_prover_blind: blind.to_bytes().to_vec(),
        })
    })
}

#[uniffi::export]
pub fn bbs_blind_sign(
    secret_key_bytes: Vec<u8>,
    public_key_bytes: Vec<u8>,
    commitment_with_proof: Vec<u8>,
    header: Vec<u8>,
    messages: Vec<Vec<u8>>,
) -> Result<Vec<u8>, ZkError> {
    messages_ok(&messages)?;
    commitment(&commitment_with_proof)?;
    run(move || {
        let sk = secret_key(&secret_key_bytes)?;
        let pk = public_key(&public_key_bytes)?;
        let signature = BlindSignature::<Suite>::blind_sign(
            &sk,
            &pk,
            Some(&commitment_with_proof),
            Some(&header),
            Some(&messages),
        )
        .map_err(|_| invalid("commitment_with_proof"))?;
        Ok(signature.to_bytes().to_vec())
    })
}

#[uniffi::export]
pub fn bbs_blind_verify(
    public_key_bytes: Vec<u8>,
    signature: Vec<u8>,
    header: Vec<u8>,
    messages: Vec<Vec<u8>>,
    committed_messages: Vec<Vec<u8>>,
    secret_prover_blind: Vec<u8>,
) -> bool {
    check(move || {
        messages_ok(&messages)?;
        let pk = public_key(&public_key_bytes)?;
        let signature = BlindSignature::<Suite>::from_bytes(&signature_bytes(&signature)?)
            .map_err(|_| invalid("signature"))?;
        let blind = blind_factor(&secret_prover_blind)?;
        Ok(signature
            .verify_blind_sign(
                &pk,
                Some(&header),
                Some(&messages),
                Some(&committed_messages),
                Some(&blind),
            )
            .is_ok())
    })
}

/// Proof for a blind signature. The committed messages (the holder_secret) stay hidden.
#[uniffi::export]
pub fn bbs_blind_proof_gen(
    public_key_bytes: Vec<u8>,
    signature: Vec<u8>,
    header: Vec<u8>,
    presentation_header: Vec<u8>,
    messages: Vec<Vec<u8>>,
    committed_messages: Vec<Vec<u8>>,
    disclosed_indexes: Vec<u64>,
    secret_prover_blind: Vec<u8>,
) -> Result<Vec<u8>, ZkError> {
    messages_ok(&messages)?;
    run(move || {
        let pk = public_key(&public_key_bytes)?;
        let disclosed = indexes(&disclosed_indexes, messages.len())?;
        let blind = blind_factor(&secret_prover_blind)?;
        let signature = signature_bytes(&signature)?;
        let proof = PoKSignature::<Suite>::blind_proof_gen(
            &pk,
            &signature,
            Some(&header),
            Some(&presentation_header),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed),
            None,
            Some(&blind),
        )
        .map_err(|_| invalid("proof_gen"))?;
        Ok(proof.to_bytes())
    })
}

/// `length_messages` is the number of signer messages (lengthBBSMessages of bbs-2023).
#[uniffi::export]
pub fn bbs_blind_proof_verify(
    public_key_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
    header: Vec<u8>,
    presentation_header: Vec<u8>,
    length_messages: u64,
    disclosed_messages: Vec<Vec<u8>>,
    disclosed_indexes: Vec<u64>,
) -> bool {
    check(move || {
        messages_ok(&disclosed_messages)?;
        let l = usize::try_from(length_messages).map_err(|_| invalid("length_messages"))?;
        if l > MAX_MESSAGES || disclosed_messages.len() != disclosed_indexes.len() {
            return Ok(false);
        }
        let pk = public_key(&public_key_bytes)?;
        let proof = proof(&proof_bytes)?;
        let disclosed = indexes(&disclosed_indexes, l)?;
        Ok(proof
            .blind_proof_verify(
                &pk,
                Some(&header),
                Some(&presentation_header),
                Some(l),
                Some(&disclosed_messages),
                None,
                Some(&disclosed),
                None,
            )
            .is_ok())
    })
}

/// Commitment for credential-bound pseudonyms: committed_messages is empty (pseudonym) or holds the holder_secret
/// (holder binding and pseudonym); prover_nym is the holder's part of the nym secret.
#[uniffi::export]
pub fn bbs_nym_commit(
    committed_messages: Vec<Vec<u8>>,
    prover_nym: Vec<u8>,
) -> Result<BbsCommitment, ZkError> {
    messages_ok(&committed_messages)?;
    run(move || {
        let nym = nym_secret(&prover_nym, "prover_nym")?;
        let (commitment, blind) =
            Commitment::<Suite>::commit_with_nym(Some(&committed_messages), vec![nym])
                .map_err(|_| invalid("commit"))?;
        Ok(BbsCommitment {
            commitment_with_proof: commitment.to_bytes(),
            secret_prover_blind: blind.to_bytes().to_vec(),
        })
    })
}

#[uniffi::export]
pub fn bbs_nym_sign(
    secret_key_bytes: Vec<u8>,
    public_key_bytes: Vec<u8>,
    commitment_with_proof: Vec<u8>,
    header: Vec<u8>,
    signer_nym_entropy: Vec<u8>,
    messages: Vec<Vec<u8>>,
) -> Result<Vec<u8>, ZkError> {
    messages_ok(&messages)?;
    commitment(&commitment_with_proof)?;
    run(move || {
        let sk = secret_key(&secret_key_bytes)?;
        let pk = public_key(&public_key_bytes)?;
        let entropy = nym_secret(&signer_nym_entropy, "signer_nym_entropy")?;
        let signature = BlindSignature::<Suite>::blind_sign_with_nym(
            &sk,
            &pk,
            Some(&commitment_with_proof),
            1,
            Some(&header),
            &entropy,
            Some(&messages),
        )
        .map_err(|_| invalid("commitment_with_proof"))?;
        Ok(signature.to_bytes().to_vec())
    })
}

/// Verification and finalization: checks the signature and returns the nym_secret (prover_nym + signer_nym_entropy).
#[uniffi::export]
pub fn bbs_nym_finalize(
    public_key_bytes: Vec<u8>,
    signature: Vec<u8>,
    header: Vec<u8>,
    messages: Vec<Vec<u8>>,
    committed_messages: Vec<Vec<u8>>,
    prover_nym: Vec<u8>,
    signer_nym_entropy: Vec<u8>,
    secret_prover_blind: Vec<u8>,
) -> Result<Vec<u8>, ZkError> {
    messages_ok(&messages)?;
    run(move || {
        let pk = public_key(&public_key_bytes)?;
        let signature = BlindSignature::<Suite>::from_bytes(&signature_bytes(&signature)?)
            .map_err(|_| invalid("signature"))?;
        let nym = nym_secret(&prover_nym, "prover_nym")?;
        let entropy = nym_secret(&signer_nym_entropy, "signer_nym_entropy")?;
        let blind = blind_factor(&secret_prover_blind)?;
        let secrets = signature
            .verify_finalize_with_nym(
                &pk,
                Some(&header),
                Some(&messages),
                Some(&committed_messages),
                vec![nym],
                Some(&entropy),
                Some(&blind),
            )
            .map_err(|_| invalid("signature"))?;
        Ok(secrets
            .first()
            .ok_or_else(|| invalid("signature"))?
            .to_bytes()
            .to_vec())
    })
}

#[uniffi::export]
pub fn bbs_nym_proof_gen(
    public_key_bytes: Vec<u8>,
    signature: Vec<u8>,
    header: Vec<u8>,
    presentation_header: Vec<u8>,
    nym_secret_bytes: Vec<u8>,
    context_id: Vec<u8>,
    messages: Vec<Vec<u8>>,
    committed_messages: Vec<Vec<u8>>,
    disclosed_indexes: Vec<u64>,
    secret_prover_blind: Vec<u8>,
) -> Result<BbsNymProof, ZkError> {
    messages_ok(&messages)?;
    run(move || {
        let pk = public_key(&public_key_bytes)?;
        let disclosed = indexes(&disclosed_indexes, messages.len())?;
        let secret = nym_secret(&nym_secret_bytes, "nym_secret")?;
        let blind = blind_factor(&secret_prover_blind)?;
        let signature = signature_bytes(&signature)?;
        let (proof, pseudonym) = PoKSignature::<Suite>::proof_gen_with_nym(
            &pk,
            &signature,
            Some(&header),
            Some(&presentation_header),
            &vec![secret],
            &context_id,
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed),
            None,
            Some(&blind),
        )
        .map_err(|_| invalid("proof_gen"))?;
        Ok(BbsNymProof {
            proof: proof.to_bytes(),
            pseudonym: pseudonym.to_bytes(),
        })
    })
}

#[uniffi::export]
pub fn bbs_nym_proof_verify(
    public_key_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
    header: Vec<u8>,
    presentation_header: Vec<u8>,
    pseudonym: Vec<u8>,
    context_id: Vec<u8>,
    length_messages: u64,
    disclosed_messages: Vec<Vec<u8>>,
    disclosed_indexes: Vec<u64>,
) -> bool {
    check(move || {
        messages_ok(&disclosed_messages)?;
        let l = usize::try_from(length_messages).map_err(|_| invalid("length_messages"))?;
        if l > MAX_MESSAGES
            || disclosed_messages.len() != disclosed_indexes.len()
            || pseudonym.len() != POINT_G1_BYTES
        {
            return Ok(false);
        }
        let pk = public_key(&public_key_bytes)?;
        let proof = proof(&proof_bytes)?;
        let nym = BBSplusPseudonym::from_bytes(&pseudonym).map_err(|_| invalid("pseudonym"))?;
        let disclosed = indexes(&disclosed_indexes, l)?;
        Ok(proof
            .proof_verify_with_nym(
                &pk,
                Some(&header),
                Some(&presentation_header),
                &nym,
                &context_id,
                1,
                Some(l),
                Some(&disclosed_messages),
                None,
                Some(&disclosed),
                None,
            )
            .is_ok())
    })
}

#[cfg(test)]
mod tests {
    //! W3C Data Integrity BBS Cryptosuites v1.0 appendix A vectors (test-servers/src/test/resources/bbs-2023).
    use super::*;
    use serde_json::Value;

    fn vector(path: &str) -> Value {
        let file = format!(
            "{}/../../test-servers/src/test/resources/bbs-2023/{path}",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap()
    }

    fn hex_of(v: &Value, key: &str) -> Vec<u8> {
        hex::decode(v[key].as_str().unwrap()).unwrap()
    }

    /// The nonMandatory map of an add-base transformation, in index order.
    fn non_mandatory(transform: &Value) -> Vec<Vec<u8>> {
        let mut entries: Vec<(u64, Vec<u8>)> = transform["nonMandatory"]["value"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e[0].as_u64().unwrap(),
                    e[1].as_str().unwrap().as_bytes().to_vec(),
                )
            })
            .collect();
        entries.sort_by_key(|e| e.0);
        entries.into_iter().map(|e| e.1).collect()
    }

    fn header(hashes: &Value) -> Vec<u8> {
        [hex_of(hashes, "proofHash"), hex_of(hashes, "mandatoryHash")].concat()
    }

    fn presentation_header(disclosure: &Value) -> Vec<u8> {
        let o = disclosure["presentationHeader"].as_object().unwrap();
        (0..o.len())
            .map(|i| o[&i.to_string()].as_u64().unwrap() as u8)
            .collect()
    }

    fn selective(disclosure: &Value) -> Vec<u64> {
        disclosure["adjSelectiveIndexes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect()
    }

    fn keys() -> (Vec<u8>, Vec<u8>) {
        let k = vector("BBSKeyMaterial.json");
        (hex_of(&k, "privateKeyHex"), hex_of(&k, "publicKeyHex"))
    }

    #[test]
    fn key_pair_matches_vector() {
        let (sk, pk) = keys();
        assert_eq!(bbs_public_key(sk).unwrap(), pk);
        let generated = bbs_generate_key_pair(vec![7u8; 32], b"diw".to_vec()).unwrap();
        assert_eq!(
            bbs_public_key(generated.secret_key).unwrap(),
            generated.public_key
        );
        assert!(bbs_generate_key_pair(vec![7u8; 16], Vec::new()).is_err());
    }

    #[test]
    fn baseline_vectors() {
        let (sk, pk) = keys();
        for dir in ["prc/", ""] {
            let messages = non_mandatory(&vector(&format!("{dir}addBaseTransform.json")));
            let header = header(&vector(&format!("{dir}addHashData.json")));
            let expected = hex_of(
                &vector(&format!("{dir}addRawBaseSignatureInfo.json")),
                "bbsSignature",
            );
            // BBS signing is deterministic, so the issuer's signature is reproduced exactly.
            let signature =
                bbs_sign(sk.clone(), pk.clone(), header.clone(), messages.clone()).unwrap();
            assert_eq!(signature, expected);
            assert!(bbs_verify(
                pk.clone(),
                signature.clone(),
                header.clone(),
                messages.clone()
            ));
            assert!(!bbs_verify(
                pk.clone(),
                signature.clone(),
                b"other".to_vec(),
                messages.clone()
            ));

            let disclosure = vector(&format!("{dir}derivedDisclosureData.json"));
            let selected = selective(&disclosure);
            let disclosed: Vec<Vec<u8>> = selected
                .iter()
                .map(|i| messages[*i as usize].clone())
                .collect();
            let ph = presentation_header(&disclosure);
            assert!(bbs_proof_verify(
                pk.clone(),
                hex_of(&disclosure, "bbsProof"),
                header.clone(),
                ph.clone(),
                disclosed.clone(),
                selected.clone()
            ));
            assert!(!bbs_proof_verify(
                pk.clone(),
                hex_of(&disclosure, "bbsProof"),
                header.clone(),
                b"x".to_vec(),
                disclosed.clone(),
                selected.clone()
            ));

            let proof = bbs_proof_gen(
                pk.clone(),
                signature,
                header.clone(),
                ph.clone(),
                messages.clone(),
                selected.clone(),
            )
            .unwrap();
            assert!(bbs_proof_verify(
                pk.clone(),
                proof,
                header,
                ph,
                disclosed,
                selected
            ));
        }
    }

    #[test]
    fn anonymous_holder_binding_vectors() {
        let (sk, pk) = keys();
        let messages = non_mandatory(&vector("HolderBinding/addBaseTransform.json"));
        let header = header(&vector("HolderBinding/addHashData.json"));
        let commitment = vector("HolderBinding/commitmentInfo.json");
        let holder_secret = hex_of(
            &vector("FeatureInputs/holderSecret.json"),
            "holderSecretHex",
        );
        let blind = hex_of(&commitment, "secretProverBlind");
        let signature = bbs_blind_sign(
            sk.clone(),
            pk.clone(),
            hex_of(&commitment, "commitmentWithProof"),
            header.clone(),
            messages.clone(),
        )
        .unwrap();
        assert_eq!(
            signature,
            hex_of(
                &vector("HolderBinding/addRawBaseSignatureInfo.json"),
                "bbsSignature"
            )
        );
        assert!(bbs_blind_verify(
            pk.clone(),
            signature.clone(),
            header.clone(),
            messages.clone(),
            vec![holder_secret.clone()],
            blind.clone()
        ));
        assert!(!bbs_blind_verify(
            pk.clone(),
            signature.clone(),
            header.clone(),
            messages.clone(),
            vec![vec![1u8; 32]],
            blind.clone()
        ));

        let disclosure = vector("HolderBinding/derivedDisclosureData.json");
        let selected = selective(&disclosure);
        let disclosed: Vec<Vec<u8>> = selected
            .iter()
            .map(|i| messages[*i as usize].clone())
            .collect();
        let ph = presentation_header(&disclosure);
        let length = disclosure["lengthBBSMessages"].as_u64().unwrap();
        assert!(bbs_blind_proof_verify(
            pk.clone(),
            hex_of(&disclosure, "bbsProof"),
            header.clone(),
            ph.clone(),
            length,
            disclosed.clone(),
            selected.clone()
        ));

        let proof = bbs_blind_proof_gen(
            pk.clone(),
            signature,
            header.clone(),
            ph.clone(),
            messages.clone(),
            vec![holder_secret],
            selected.clone(),
            blind,
        )
        .unwrap();
        assert!(bbs_blind_proof_verify(
            pk.clone(),
            proof.clone(),
            header.clone(),
            ph.clone(),
            length,
            disclosed.clone(),
            selected.clone()
        ));
        // The holder-bound proof does not verify as a baseline proof.
        assert!(!bbs_proof_verify(
            pk, proof, header, ph, disclosed, selected
        ));

        let fresh = bbs_commit(vec![vec![9u8; 32]]).unwrap();
        assert_eq!(fresh.secret_prover_blind.len(), 32);
    }

    #[test]
    fn pseudonym_vectors() {
        let (sk, pk) = keys();
        let messages = non_mandatory(&vector("HolderBinding/addBaseTransform.json"));
        let header = header(&vector("HolderBinding/addHashData.json"));
        let prover_nym = hex_of(&vector("FeatureInputs/proverNym.json"), "proverNymHex");
        let entropy = hex_of(
            &vector("FeatureInputs/signerNymEntropy.json"),
            "signerNymEntropyHex",
        );
        let holder_secret = hex_of(
            &vector("FeatureInputs/holderSecret.json"),
            "holderSecretHex",
        );
        let domain = vector("FeatureInputs/verifierInfo.json")["verifierId"]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec();
        for (dir, committed) in [
            ("Pseudonym/", Vec::new()),
            ("PseudonymHB/", vec![holder_secret.clone()]),
        ] {
            let commitment = vector(&format!("{dir}commitmentInfo.json"));
            let blind = hex_of(&commitment, "secretProverBlind");
            let signature = bbs_nym_sign(
                sk.clone(),
                pk.clone(),
                hex_of(&commitment, "commitmentWithProof"),
                header.clone(),
                entropy.clone(),
                messages.clone(),
            )
            .unwrap();
            assert_eq!(
                signature,
                hex_of(
                    &vector(&format!("{dir}addRawBaseSignatureInfo.json")),
                    "bbsSignature"
                )
            );
            let nym_secret = bbs_nym_finalize(
                pk.clone(),
                signature.clone(),
                header.clone(),
                messages.clone(),
                committed.clone(),
                prover_nym.clone(),
                entropy.clone(),
                blind.clone(),
            )
            .unwrap();
            let expected = vector(&format!("{dir}nymSecret.json"))["nymSecretHex"]
                .as_str()
                .unwrap()
                .to_string();
            assert_eq!(hex::encode(&nym_secret), format!("{expected:0>64}"));

            let disclosure = vector(&format!("{dir}derivedDisclosureData.json"));
            let selected = selective(&disclosure);
            let disclosed: Vec<Vec<u8>> = selected
                .iter()
                .map(|i| messages[*i as usize].clone())
                .collect();
            let ph = presentation_header(&disclosure);
            let length = disclosure["lengthBBSMessages"].as_u64().unwrap();
            let pseudonym = hex_of(&disclosure, "pseudonym");
            assert!(bbs_nym_proof_verify(
                pk.clone(),
                hex_of(&disclosure, "bbsProof"),
                header.clone(),
                ph.clone(),
                pseudonym.clone(),
                domain.clone(),
                length,
                disclosed.clone(),
                selected.clone()
            ));
            assert!(!bbs_nym_proof_verify(
                pk.clone(),
                hex_of(&disclosure, "bbsProof"),
                header.clone(),
                ph.clone(),
                pseudonym.clone(),
                b"https://other.example/".to_vec(),
                length,
                disclosed.clone(),
                selected.clone()
            ));

            let generated = bbs_nym_proof_gen(
                pk.clone(),
                signature,
                header.clone(),
                ph.clone(),
                nym_secret,
                domain.clone(),
                messages.clone(),
                committed,
                selected.clone(),
                blind,
            )
            .unwrap();
            // The pseudonym depends only on the nym secret and the domain.
            assert_eq!(generated.pseudonym, pseudonym);
            assert!(bbs_nym_proof_verify(
                pk.clone(),
                generated.proof,
                header.clone(),
                ph,
                generated.pseudonym,
                domain.clone(),
                length,
                disclosed,
                selected
            ));
        }
        let fresh = bbs_nym_commit(Vec::new(), bbs_random_scalar()).unwrap();
        assert!(!fresh.commitment_with_proof.is_empty());
    }

    #[test]
    fn malformed_input_is_rejected() {
        let (_, pk) = keys();
        assert!(matches!(
            bbs_sign(vec![1; 31], pk.clone(), Vec::new(), Vec::new()),
            Err(ZkError::InvalidInput { .. })
        ));
        assert!(!bbs_verify(pk.clone(), vec![0; 79], Vec::new(), Vec::new()));
        assert!(!bbs_proof_verify(
            pk.clone(),
            vec![0; 10],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new()
        ));
        assert!(!bbs_proof_verify(
            vec![0; 96],
            vec![0; 272],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new()
        ));
        assert!(bbs_proof_gen(
            pk,
            vec![0; 80],
            Vec::new(),
            Vec::new(),
            vec![vec![1]],
            vec![1, 0]
        )
        .is_err());
    }
}
