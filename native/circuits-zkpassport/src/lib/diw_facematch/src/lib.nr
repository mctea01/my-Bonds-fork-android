// FaceMatch evidence for platforms where zkPassport's own circuits cannot be used.
//
// zkPassport's FaceMatch circuits prove that an attested app signed a statement
// (mode, DG2 hash). On Android they also need a Play Integrity token. The circuits
// built on this library keep zkPassport's public interface and client data, and
// replace the token with checks on the Android key attestation itself (keyattest),
// or drop the attestation entirely (self).
pub mod keyattest;
mod tests;

use facematch::param_commit::calculate_param_commitment;

// Values of the committed environment. 0 and 1 mean what they mean in zkPassport's
// circuits; 2 is specific to the key attestation circuits.
pub global ENV_UNTRUSTED: u8 = 0;
pub global ENV_VERIFIED: u8 = 1;
pub global ENV_SELF_SIGNED: u8 = 2;

/// Parameter commitment of the key attestation circuits. Same formula as zkPassport's
/// FaceMatch circuits; the slot that holds the Play Integrity key hash there holds the
/// hash of the app's signing certificate digest here.
pub fn keyattest_param_commitment(
    root_key_leaf: Field,
    environment: u8,
    app_id_hash: Field,
    signer_hash: Field,
    facematch_mode: u8,
) -> Field {
    calculate_param_commitment(root_key_leaf, environment, app_id_hash, signer_hash, facematch_mode)
}

/// Parameter commitment of the self-declared circuit: no attestation root, untrusted
/// environment, no signer. A verifier that recomputes it with these zeros knows the
/// statement is the wallet's own claim.
pub fn self_param_commitment(app_id_hash: Field, facematch_mode: u8) -> Field {
    calculate_param_commitment(0, ENV_UNTRUSTED, app_id_hash, 0, facematch_mode)
}
