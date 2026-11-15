// Self-declared FaceMatch: the wallet's own statement that it compared the holder's
// face with the photo of this document. Nothing attests the app or the device, so the
// proof adds no assurance of its own; it ties the statement to the document, the scope
// and the nullifier of the other proofs, and commits to "no attestation" so a verifier
// can tell it apart. For platforms that have no app attestation at all.
use commitment::nullify;
use data_check_expiry::check_expiry_from_date;
use diw_facematch::self_param_commitment;
use facematch::constants::{APP_ID_MAX_LEN, FACEMATCH_MODE_REGULAR, FACEMATCH_MODE_STRICT};
use utils::{check_zero_padding, poseidon2_hash_packed, types::{DG1Data, MRZExpiryDate, SaltedValue}};
mod tests;

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salted_private_nullifier: SaltedValue<Field>,
    salted_expiry_date: SaltedValue<MRZExpiryDate>,
    salted_dg1: SaltedValue<DG1Data>,
    salted_dg2_hash: SaltedValue<Field>,
    salted_dg2_hash_type: SaltedValue<u32>,
    // @committed
    // The app id the wallet declares, zero padded. Not verified by anything.
    app_id: [u8; APP_ID_MAX_LEN],
    app_id_length: u32,
    // @committed
    facematch_mode: u8, // FACEMATCH_MODE_REGULAR (1) or FACEMATCH_MODE_STRICT (2)
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field, Field) {
    check_expiry_from_date(salted_expiry_date.value, current_date);

    assert(
        (facematch_mode == FACEMATCH_MODE_REGULAR) | (facematch_mode == FACEMATCH_MODE_STRICT),
        "Invalid facematch_mode",
    );
    assert((app_id_length != 0) & (app_id_length <= APP_ID_MAX_LEN), "Invalid app_id length");
    check_zero_padding(app_id, app_id_length);

    // No OPRF proof here, as in zkPassport's FaceMatch circuits.
    let zero_oprf_proof = commitment::OPRFProof {
        pk: commitment::BabyJubJubPoint { x: 0, y: 0 },
        dlog_e: 0,
        dlog_s: 0,
        response_blinded: commitment::BabyJubJubPoint { x: 0, y: 0 },
        response: commitment::BabyJubJubPoint { x: 0, y: 0 },
        beta: 0,
    };
    let (nullifier, nullifier_type, oprf_pk_hash) = nullify(
        comm_in,
        salted_dg1,
        salted_expiry_date,
        salted_dg2_hash,
        salted_dg2_hash_type,
        salted_private_nullifier,
        service_scope,
        service_subscope,
        nullifier_secret,
        zero_oprf_proof,
    );

    let app_id_hash = poseidon2_hash_packed(app_id, app_id_length);
    (self_param_commitment(app_id_hash, facematch_mode), nullifier_type, nullifier, oprf_pk_hash)
}
