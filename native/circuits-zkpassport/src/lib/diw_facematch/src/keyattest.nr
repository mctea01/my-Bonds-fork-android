// Reads the Android Key Attestation extension (OID 1.3.6.1.4.1.11129.2.1.17) of the
// credential certificate. The certificate is signed by the attestation chain, so every
// value read here is a statement of the device's keystore, not of the prover.
//
// KeyDescription ::= SEQUENCE {
//     attestationVersion INTEGER, attestationSecurityLevel ENUMERATED,
//     keyMintVersion INTEGER, keyMintSecurityLevel ENUMERATED,
//     attestationChallenge OCTET STRING, uniqueId OCTET STRING,
//     softwareEnforced AuthorizationList, hardwareEnforced AuthorizationList }
use crate::{ENV_SELF_SIGNED, ENV_UNTRUSTED, ENV_VERIFIED};
use facematch::android::constants::OID_ANDROID_KEY_ATTESTATION;
use utils::{find_subarray_index_strict, read_der_length};

pub global SECURITY_LEVEL_SOFTWARE: u8 = 0;
pub global KEY_ORIGIN_GENERATED: u8 = 0;
pub global BOOT_STATE_VERIFIED: u8 = 0;
pub global BOOT_STATE_SELF_SIGNED: u8 = 1;

// Authorization list tags in their DER high-tag form.
global TAG_ORIGIN: [u8; 3] = [0xBF, 0x85, 0x3E]; // [702]
global TAG_ROOT_OF_TRUST: [u8; 3] = [0xBF, 0x85, 0x40]; // [704]
global TAG_APPLICATION_ID: [u8; 3] = [0xBF, 0x85, 0x45]; // [709]

// An authorization list holds a few dozen entries at most; the cap bounds the walk.
global MAX_ENTRIES: u32 = 48;

pub struct KeyAttestation {
    pub attestation_level: u8,
    pub keymint_level: u8,
    pub origin: u8,
    pub device_locked: bool,
    pub boot_state: u8,
    pub signer_digest: [u8; 32],
}

/// Start of the content of the single-byte-tag element at `pos`, which must carry `tag`.
fn enter<let N: u32>(tbs: [u8; N], pos: u32, tag: u8) -> u32 {
    assert(tbs[pos] == tag, "unexpected DER tag in the key attestation");
    let (_, consumed) = read_der_length(tbs, pos + 1);
    pos + 1 + consumed
}

/// Position after the single-byte-tag element at `pos`.
fn skip<let N: u32>(tbs: [u8; N], pos: u32) -> u32 {
    let (len, consumed) = read_der_length(tbs, pos + 1);
    pos + 1 + consumed + len
}

/// Position after the element at `pos`, whose tag may be in the high-tag form.
fn skip_tagged<let N: u32>(tbs: [u8; N], pos: u32) -> u32 {
    let mut tag_len: u32 = 1;
    if (tbs[pos] & 0x1F) == 0x1F {
        let mut done = false;
        for i in 0..4 {
            if !done {
                tag_len += 1;
                done = (tbs[pos + 1 + i] & 0x80) == 0;
            }
        }
        assert(done, "tag too long in the key attestation");
    }
    let (len, consumed) = read_der_length(tbs, pos + tag_len);
    pos + tag_len + consumed + len
}

/// Value of an ENUMERATED of one byte at `pos`.
fn enumerated<let N: u32>(tbs: [u8; N], pos: u32) -> u8 {
    assert((tbs[pos] == 0x0A) & (tbs[pos + 1] == 0x01), "expected a one-byte ENUMERATED");
    tbs[pos + 2]
}

/// Bounds of the content of the authorization list (a SEQUENCE) at `pos`.
fn list_bounds<let N: u32>(tbs: [u8; N], pos: u32) -> (u32, u32) {
    assert(tbs[pos] == 0x30, "authorization list not found");
    let (len, consumed) = read_der_length(tbs, pos + 1);
    let start = pos + 1 + consumed;
    let end = start + len;
    assert(end <= N, "authorization list exceeds the certificate");
    (start, end)
}

/// Start of the content of the entry tagged `tag` in the list [start, end). Only tag
/// positions are compared, so bytes inside another entry's value cannot be taken for it.
fn entry<let N: u32>(tbs: [u8; N], start: u32, end: u32, tag: [u8; 3]) -> u32 {
    let mut p = start;
    let mut found = false;
    for _ in 0..MAX_ENTRIES {
        if !found & (p + 3 <= end) {
            if (tbs[p] == tag[0]) & (tbs[p + 1] == tag[1]) & (tbs[p + 2] == tag[2]) {
                found = true;
            } else {
                p = skip_tagged(tbs, p);
            }
        }
    }
    assert(found, "entry not found in the authorization list");
    let (len, consumed) = read_der_length(tbs, p + 3);
    assert(p + 3 + consumed + len <= end, "entry exceeds the authorization list");
    p + 3 + consumed
}

pub fn parse_key_attestation<let N: u32>(tbs: [u8; N]) -> KeyAttestation {
    // First occurrence only, as in zkPassport's reader: the extension cannot be replaced
    // by a copy planted in bytes the prover controls further on.
    let oid = find_subarray_index_strict(OID_ANDROID_KEY_ATTESTATION, tbs);
    assert(oid < N, "key attestation extension not found");
    let mut p = enter(tbs, oid + OID_ANDROID_KEY_ATTESTATION.len(), 0x04);
    p = enter(tbs, p, 0x30);
    p = skip(tbs, p); // attestationVersion
    let attestation_level = enumerated(tbs, p);
    p = skip(tbs, p);
    p = skip(tbs, p); // keyMintVersion
    let keymint_level = enumerated(tbs, p);
    p = skip(tbs, p);
    p = skip(tbs, p); // attestationChallenge, chosen by the prover
    p = skip(tbs, p); // uniqueId
    let (sw_start, sw_end) = list_bounds(tbs, p);
    let (hw_start, hw_end) = list_bounds(tbs, sw_end);

    // origin [702] EXPLICIT INTEGER, in the hardware-enforced list only.
    let mut q = entry(tbs, hw_start, hw_end, TAG_ORIGIN);
    assert((tbs[q] == 0x02) & (tbs[q + 1] == 0x01), "expected a one-byte key origin");
    let origin = tbs[q + 2];

    // rootOfTrust [704] EXPLICIT SEQUENCE { verifiedBootKey OCTET STRING,
    // deviceLocked BOOLEAN, verifiedBootState ENUMERATED, verifiedBootHash OCTET STRING }
    q = entry(tbs, hw_start, hw_end, TAG_ROOT_OF_TRUST);
    q = enter(tbs, q, 0x30);
    assert(tbs[q] == 0x04, "verifiedBootKey not found");
    q = skip(tbs, q);
    assert((tbs[q] == 0x01) & (tbs[q + 1] == 0x01), "deviceLocked not found");
    let device_locked = tbs[q + 2] != 0;
    let boot_state = enumerated(tbs, q + 3);

    // attestationApplicationId [709] EXPLICIT OCTET STRING holding SEQUENCE {
    // SET OF AttestationPackageInfo, SET OF OCTET STRING (signing certificate digests) },
    // in the software-enforced list: the operating system states which app holds the key.
    q = entry(tbs, sw_start, sw_end, TAG_APPLICATION_ID);
    q = enter(tbs, q, 0x04);
    q = enter(tbs, q, 0x30);
    assert(tbs[q] == 0x31, "package list not found");
    q = skip(tbs, q);
    q = enter(tbs, q, 0x31);
    assert((tbs[q] == 0x04) & (tbs[q + 1] == 0x20), "expected a SHA-256 signing certificate digest");
    let mut signer_digest = [0; 32];
    for i in 0..32 {
        signer_digest[i] = tbs[q + 2 + i];
    }

    KeyAttestation { attestation_level, keymint_level, origin, device_locked, boot_state, signer_digest }
}

/// What every key attestation circuit requires: the attestation and the key are held in
/// a TEE or StrongBox, and the key was generated there (not imported).
pub fn assert_hardware_key(attestation: KeyAttestation) {
    assert(attestation.attestation_level != SECURITY_LEVEL_SOFTWARE, "software attestation");
    assert(attestation.attestation_level <= 2, "unknown attestation security level");
    assert(attestation.keymint_level != SECURITY_LEVEL_SOFTWARE, "software key");
    assert(attestation.keymint_level <= 2, "unknown key security level");
    assert(attestation.origin == KEY_ORIGIN_GENERATED, "the key was not generated in the keystore");
}

/// The committed environment. The app id and signing certificate come from the operating
/// system, so they mean something only when the boot chain is locked: to the
/// manufacturer's key (verified) or to a key the owner installed (self-signed).
pub fn environment(attestation: KeyAttestation) -> u8 {
    if attestation.device_locked & (attestation.boot_state == BOOT_STATE_VERIFIED) {
        ENV_VERIFIED
    } else if attestation.device_locked & (attestation.boot_state == BOOT_STATE_SELF_SIGNED) {
        ENV_SELF_SIGNED
    } else {
        ENV_UNTRUSTED
    }
}
