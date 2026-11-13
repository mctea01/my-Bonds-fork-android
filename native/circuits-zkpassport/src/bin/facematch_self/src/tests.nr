use commitment_common::hash_salt_dg1_dg2_hash_private_nullifier;
use diw_facematch::self_param_commitment;
use facematch::constants::{APP_ID_MAX_LEN, FACEMATCH_MODE_STRICT};
use utils::{
    constants::NON_SALTED_NULLIFIER, get_expiry_date_from_mrz, poseidon2_hash_packed,
    types::{DG1Data, SaltedValue},
};

// zkPassport's fictional specimen (P<AUSSILVERHAND<<JOHNNY).
global DG1: DG1Data = [
    97, 91, 95, 31, 88, 80, 60, 65, 85, 83, 83, 73, 76, 86, 69, 82, 72, 65, 78, 68, 60, 60, 74, 79,
    72, 78, 78, 89, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
    60, 80, 65, 49, 50, 51, 52, 53, 54, 55, 95, 65, 85, 83, 56, 56, 49, 49, 49, 50, 95, 77, 51, 48,
    48, 49, 48, 49, 95, 60, 67, 89, 66, 69, 82, 67, 73, 84, 89, 60, 60, 60, 60, 60, 60, 0, 0,
];
global SALT: Field = 3;
global PRIVATE_NULLIFIER: Field = 0x1be38799f1a15b187efcc4054f77363511b4ddbeffbf1923c49205a5e069f832;
global DG2_HASH: Field = 0x2a;
global DATE: u64 = 1719859200;

fn app_id() -> [u8; APP_ID_MAX_LEN] {
    let name = "diw.wallet".as_bytes();
    let mut app_id = [0; APP_ID_MAX_LEN];
    for i in 0..10 {
        app_id[i] = name[i];
    }
    app_id
}

fn run(comm_in: Field, date: u64, mode: u8, scope: Field) -> (Field, Field, Field, Field) {
    crate::main(
        comm_in,
        date,
        SaltedValue::from_value(SALT, PRIVATE_NULLIFIER),
        SaltedValue::from_value(SALT, get_expiry_date_from_mrz(DG1)),
        SaltedValue::from_value(SALT, DG1),
        SaltedValue::from_value(SALT, DG2_HASH),
        SaltedValue::from_value(SALT, 3),
        app_id(),
        10,
        mode,
        0,
        scope,
        0,
    )
}

fn commitment() -> Field {
    hash_salt_dg1_dg2_hash_private_nullifier(
        SaltedValue::from_value(SALT, DG1),
        SaltedValue::from_value(SALT, get_expiry_date_from_mrz(DG1)),
        SaltedValue::from_value(SALT, DG2_HASH),
        SaltedValue::from_value(SALT, 3),
        SaltedValue::from_value(SALT, PRIVATE_NULLIFIER),
    )
}

#[test]
fn commits_to_no_attestation() {
    let (param_commitment, nullifier_type, nullifier, oprf_pk_hash) =
        run(commitment(), DATE, FACEMATCH_MODE_STRICT, 7);
    assert(
        param_commitment
            == self_param_commitment(poseidon2_hash_packed(app_id(), 10), FACEMATCH_MODE_STRICT),
    );
    assert(nullifier_type == NON_SALTED_NULLIFIER);
    assert(nullifier != 0);
    assert(oprf_pk_hash == 0);
    // The nullifier is scoped like the one of the other proofs.
    let (_, _, other, _) = run(commitment(), DATE, FACEMATCH_MODE_STRICT, 8);
    assert(other != nullifier);
}

#[test(should_fail_with = "Commitment from 3rd subproof doesn't match")]
fn rejects_another_document() {
    let _ = run(commitment() + 1, DATE, FACEMATCH_MODE_STRICT, 7);
}

#[test(should_fail_with = "Invalid facematch_mode")]
fn rejects_an_unknown_mode() {
    let _ = run(commitment(), DATE, 3, 7);
}

#[test(should_fail)]
fn rejects_an_expired_document() {
    // 2040-01-01; the specimen expires in 2030.
    let _ = run(commitment(), 2208988800, FACEMATCH_MODE_STRICT, 7);
}
