#!/usr/bin/env python3
"""Key attestation FaceMatch circuits: generator and checks.

The circuits differ only in the shape of the attestation chain (kind of root key, number
of intermediates, curve and hash of each), exactly like zkPassport's Android FaceMatch
circuits, so they are generated from one template:

    python3 -I tools/keyattest.py gen                 # writes gen/ (ignored by git)
    python3 -I tools/keyattest.py libtests            # rewrites src/lib/diw_facematch/src/tests.nr
    python3 -I tools/keyattest.py check --nargo NARGO [--bb BB --crs DIR] [SHAPE ...]

`check` builds a synthetic chain for each shape (fresh keys, a fictional app and the
specimen document of zkPassport's own tests), executes the circuit on it and on tampered
copies, and with --bb also proves and verifies. The root of a synthetic chain is not
Google's: the circuit commits to the root key and the verifier compares it, outside.
"""
import argparse
import hashlib
import itertools
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GEN = ROOT / 'gen'
VENDOR = '../vendor/zkpassport-circuits/src/noir/lib'
IK_KINDS = [('p256', 'sha256'), ('p384', 'sha256'), ('p384', 'sha384')]
KEY_BYTES = {'p256': 64, 'p384': 96}
TBS_MAX = 700
CREDENTIAL_TBS_MAX = 1000
CLIENT_DATA_MAX = 169
APP_ID_MAX = 100
OID_KEY_ATTESTATION = '1.3.6.1.4.1.11129.2.1.17'

# The specimen of zkPassport's tests (P<AUSSILVERHAND<<JOHNNY), not a real document.
DG1 = [97, 91, 95, 31, 88, 80, 60, 65, 85, 83, 83, 73, 76, 86, 69, 82, 72, 65, 78, 68, 60, 60,
       74, 79, 72, 78, 78, 89, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
       60, 60, 60, 60, 60, 80, 65, 49, 50, 51, 52, 53, 54, 55, 95, 65, 85, 83, 56, 56, 49, 49,
       49, 50, 95, 77, 51, 48, 48, 49, 48, 49, 95, 60, 67, 89, 66, 69, 82, 67, 73, 84, 89, 60,
       60, 60, 60, 60, 60, 0, 0]
EXPIRY = [51, 48, 48, 49, 48, 49]  # 300101, from the specimen's MRZ
SALT = 3
PRIVATE_NULLIFIER = 0x1be38799f1a15b187efcc4054f77363511b4ddbeffbf1923c49205a5e069f832
DG2_DIGEST = bytes([0x11]) * 32
DATE = 1719859200
PACKAGE = b'diw.wallet.fixture'
SIGNER = hashlib.sha256(b'fixture signing certificate').digest()


def shapes():
    out = []
    for root in ('ecdsa', 'rsa'):
        for count in (1, 2, 3):
            for iks in itertools.product(IK_KINDS, repeat=count):
                out.append((root, list(iks)))
    return out


def shape_name(shape):
    root, iks = shape
    return 'rk_' + root + ''.join('_ik_%s_%s' % ik for ik in iks)


def package_name(shape):
    return 'diw_facematch_keyattest_' + shape_name(shape)


def sig_bytes(signer):
    """Size of a signature made by `signer`: 'ecdsa'/'rsa' for a root, or an ik kind."""
    if signer == 'rsa':
        return 512
    if signer == 'ecdsa':
        return 96
    return KEY_BYTES[signer[0]]


def verify_block(signer, signer_name, tbs, sig, what):
    """Noir statements that check `sig` over `tbs` under the signer's key."""
    if signer == 'rsa':
        return f'''    let {tbs}_len = unsafe {{ unsafe_get_asn1_element_length({tbs}) }};
    assert(
        verify_signature::<_, 0, _, 32>(root_key, {sig}, root_key_redc_param, 65537, {tbs}, {tbs}_len, 0),
        "Failed to verify {what}",
    );
'''
    curve, digest = ('p384', 'sha384') if signer == 'ecdsa' else signer
    return f'''    let ({sig}_r, {sig}_s) = split_array({sig});
    assert(
        verify_nist_{curve}({signer_name}_x, {signer_name}_y, {sig}_r, {sig}_s, get_tbs_hash_{digest}({tbs})),
        "Failed to verify {what}",
    );
'''


def main_nr(shape):
    root, iks = shape
    rsa = root == 'rsa'
    inputs = []
    if rsa:
        inputs += ['root_key: [u8; 512]', 'root_key_redc_param: [u8; 513]']
    else:
        inputs += ['root_key: [u8; 96]']
    signer = root
    for i, ik in enumerate(iks, 1):
        inputs += [f'intermediate_{i}_key: [u8; {KEY_BYTES[ik[0]]}]',
                   f'intermediate_{i}_tbs: [u8; {TBS_MAX}]',
                   f'intermediate_{i}_sig: [u8; {sig_bytes(signer)}]']
        signer = ik
    inputs += ['credential_key: [u8; 64]', 'credential_tbs: [u8; CREDENTIAL_TBS_MAX_LEN]',
               f'credential_sig: [u8; {sig_bytes(signer)}]',
               'client_data: [u8; CLIENT_DATA_MAX_LEN]', 'client_data_sig: [u8; 64]']
    body = ''
    if not rsa:
        body += '    let (root_key_x, root_key_y) = split_array(root_key);\n'
    signer, signer_name = root, 'root_key'
    for i, ik in enumerate(iks, 1):
        key = f'intermediate_{i}_key'
        body += f'''    let ({key}_x, {key}_y) = split_array({key});
    verify_ecdsa_pubkey_in_tbs({key}_x, {key}_y, intermediate_{i}_tbs);
'''
        body += verify_block(signer, signer_name, f'intermediate_{i}_tbs', f'intermediate_{i}_sig',
                             f'intermediate certificate {i}')
        signer, signer_name = ik, key
    body += '''    let (credential_key_x, credential_key_y) = split_array(credential_key);
    verify_ecdsa_pubkey_in_tbs(credential_key_x, credential_key_y, credential_tbs);
'''
    body += verify_block(signer, signer_name, 'credential_tbs', 'credential_sig', 'credential certificate')
    used = {'p384'} if not rsa else set()
    used |= {ik[0] for ik in iks}
    digests = ({'sha384'} if not rsa else set()) | {ik[1] for ik in iks}
    ecdsa_imports = ['verify_nist_p256_blackbox as verify_nist_p256']
    if 'p384' in used:
        ecdsa_imports.append('verify_nist_p384')
    facematch_imports = ['android::get_app_id_from_credential_tbs', 'calculate_attestation_registry_leaf',
                         'get_client_data_hash', 'get_facematch_mode_from_client_data']
    facematch_imports += [f'get_tbs_hash_{d}' for d in sorted(digests)]
    facematch_imports += ['prepare_client_data_hash_for_signature', 'verify_dg2_hash_in_client_data']
    lines = ',\n    '.join(inputs)
    return f'''// Generated by tools/keyattest.py: edit the generator, not this file.
//
// FaceMatch on an Android key attestation alone, for devices where a Play Integrity token
// cannot be had. Chain: {root.upper()} root, {len(iks)} intermediate(s) ({', '.join('%s/%s' % ik for ik in iks)}).
// Same public interface and client data as zkPassport's Android FaceMatch circuits; what the
// token gave there is read from the attestation here (see src/lib/diw_facematch).
use commitment::nullify;
use data_check_expiry::check_expiry_from_date;
use data_check_tbs_pubkey::verify_ecdsa_pubkey_in_tbs;
use diw_facematch::{{
    keyattest::{{assert_hardware_key, environment, parse_key_attestation}},
    keyattest_param_commitment,
}};
use facematch::{{
    {(',' + chr(10) + '    ').join(facematch_imports)},
}};
use facematch::constants::{{
    APP_ID_MAX_LEN, ATTESTATION_KEY_TYPE_GOOGLE, CLIENT_DATA_MAX_LEN, CREDENTIAL_TBS_MAX_LEN,
}};
use sig_check_ecdsa::{{{', '.join(ecdsa_imports)}}};
{'use sig_check_rsa::verify_signature;' + chr(10) if rsa else ''}use utils::{{
    poseidon2_hash_packed, split_array,
    types::{{DG1Data, MRZExpiryDate, SaltedValue}},
    unsafe_get_asn1_element_length,
}};

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salted_private_nullifier: SaltedValue<Field>,
    salted_expiry_date: SaltedValue<MRZExpiryDate>,
    salted_dg1: SaltedValue<DG1Data>,
    salted_dg2_hash: SaltedValue<Field>,
    salted_dg2_hash_type: SaltedValue<u32>,
    // @committed
    // The attestation root; its registry leaf is committed and compared outside.
    {lines},
    // @committed
    facematch_mode: u8, // FACEMATCH_MODE_REGULAR (1) or FACEMATCH_MODE_STRICT (2)
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field, Field) {{
    check_expiry_from_date(salted_expiry_date.value, current_date);

    // The chain, from the root down to the credential certificate of the keystore key.
    let root_key_leaf = calculate_attestation_registry_leaf(ATTESTATION_KEY_TYPE_GOOGLE, root_key);
{body}
    // The keystore key signed the client data.
    let (client_data_sig_r, client_data_sig_s) = split_array(client_data_sig);
    // Safety: a wrong length gives another hash, which the signature does not cover.
    let client_data_len = unsafe {{ unsafe_get_asn1_element_length(client_data) }};
    let client_data_hash = get_client_data_hash(client_data, client_data_len);
    assert(
        verify_nist_p256(
            credential_key_x,
            credential_key_y,
            client_data_sig_r,
            client_data_sig_s,
            prepare_client_data_hash_for_signature(client_data_hash),
        ),
        "Failed to verify client data hash",
    );
    assert(
        get_facematch_mode_from_client_data(client_data) == facematch_mode,
        "Failed to verify facematch_mode in client_data",
    );
    assert(
        verify_dg2_hash_in_client_data(salted_dg2_hash.value, client_data),
        "Failed to verify dg2_hash in client_data",
    );

    // In place of the Play Integrity token: a hardware key, the state of the boot chain,
    // and the app (package name and signing certificate) the system says holds the key.
    let attestation = parse_key_attestation(credential_tbs);
    assert_hardware_key(attestation);
    let (app_id, app_id_length): ([u8; APP_ID_MAX_LEN], u32) =
        get_app_id_from_credential_tbs(credential_tbs);

    // No OPRF proof here, as in zkPassport's FaceMatch circuits.
    let zero_oprf_proof = commitment::OPRFProof {{
        pk: commitment::BabyJubJubPoint {{ x: 0, y: 0 }},
        dlog_e: 0,
        dlog_s: 0,
        response_blinded: commitment::BabyJubJubPoint {{ x: 0, y: 0 }},
        response: commitment::BabyJubJubPoint {{ x: 0, y: 0 }},
        beta: 0,
    }};
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

    let param_commitment = keyattest_param_commitment(
        root_key_leaf,
        environment(attestation),
        poseidon2_hash_packed(app_id, app_id_length),
        poseidon2_hash_packed(attestation.signer_digest, 32),
        facematch_mode,
    );
    (param_commitment, nullifier_type, nullifier, oprf_pk_hash)
}}
'''


def nargo_toml(name, rsa, up):
    lib = up + '/' + VENDOR
    deps = [f'diw_facematch = {{ path = "{up}/src/lib/diw_facematch" }}',
            f'facematch = {{ path = "{lib}/facematch" }}',
            f'sig_check_ecdsa = {{ path = "{lib}/sig-check/ecdsa" }}']
    if rsa:
        deps.append(f'sig_check_rsa = {{ path = "{lib}/sig-check/rsa" }}')
    deps += [f'data_check_tbs_pubkey = {{ path = "{lib}/data-check/tbs-pubkey" }}',
             f'data_check_expiry = {{ path = "{lib}/data-check/expiry" }}',
             f'commitment = {{ path = "{lib}/commitment/scoped-nullifier" }}',
             f'commitment_common = {{ path = "{lib}/commitment/common" }}',
             f'utils = {{ path = "{lib}/utils" }}']
    return (f'[package]\nname = "{name}"\ntype = "bin"\nauthors = ["DIW MY WALLET"]\n'
            f'compiler_version = ">=1.0.0"\n\n[dependencies]\n' + '\n'.join(deps) + '\n')


def generate():
    members = []
    for shape in shapes():
        directory = GEN / 'keyattest' / shape_name(shape)
        (directory / 'src').mkdir(parents=True, exist_ok=True)
        (directory / 'Nargo.toml').write_text(nargo_toml(package_name(shape), shape[0] == 'rsa', '../../..'))
        (directory / 'src/main.nr').write_text(main_nr(shape))
        members.append('keyattest/' + shape_name(shape))
    (GEN / 'probe/src').mkdir(parents=True, exist_ok=True)
    members.append('probe')
    (GEN / 'Nargo.toml').write_text('[workspace]\nmembers = [' + ', '.join(json.dumps(m) for m in members) + ']\n')
    return len(members) - 1


# --- DER -------------------------------------------------------------------------------

def der_len(n):
    if n < 128:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag, content):
    return bytes(tag) + der_len(len(content)) + content


def integer(n):
    raw = n.to_bytes(n.bit_length() // 8 + 1, 'big')
    return tlv([0x02], raw)


def explicit(number, content):
    if number < 31:
        return tlv([0xA0 | number], content)
    return tlv([0xBF, 0x80 | (number >> 7), number & 0x7F], content)


def key_description(level=1, keymint_level=1, origin=0, locked=True, boot_state=0, hardware_root=True,
                    challenge=b'\x07' * 32):
    """An Android KeyDescription. `challenge` is the prover's to choose; the others are not."""
    application_id = tlv([0x30], tlv([0x31], tlv([0x30], tlv([0x04], PACKAGE) + integer(42)))
                         + tlv([0x31], tlv([0x04], SIGNER)))
    software = explicit(701, integer(1700000000000)) + explicit(709, tlv([0x04], application_id))
    root_of_trust = explicit(704, tlv([0x30], tlv([0x04], b'\x21' * 32)
                                       + bytes([0x01, 0x01, 0xFF if locked else 0x00])
                                       + bytes([0x0A, 0x01, boot_state]) + tlv([0x04], b'\x22' * 32)))
    hardware = (explicit(1, tlv([0x31], integer(2))) + explicit(2, integer(3)) + explicit(3, integer(256))
                + explicit(5, tlv([0x31], integer(4))) + explicit(10, integer(1)) + explicit(503, b'\x05\x00')
                + explicit(702, integer(origin)))
    if hardware_root:
        hardware += root_of_trust
    else:
        software += root_of_trust
    hardware += explicit(705, integer(150000)) + explicit(706, integer(202611))
    return tlv([0x30], integer(300) + bytes([0x0A, 0x01, level]) + integer(300)
               + bytes([0x0A, 0x01, keymint_level]) + tlv([0x04], challenge) + tlv([0x04], b'')
               + tlv([0x30], software) + tlv([0x30], hardware))


def client_data(mode=1, digest=DG2_DIGEST):
    """zkPassport's ZKPassportAppAttest, with only the fields the circuits read."""
    digest_info = tlv([0x30], tlv([0x30], bytes.fromhex('0609608648016503040201')) + tlv([0x04], digest))
    attestation = tlv([0x30], bytes([0x0A, 0x01, mode]) + digest_info)
    return tlv([0x30], integer(1) + tlv([0x0C], b'1.0.0') + bytes([0x0A, 0x01, 0x01]) + tlv([0xA1], attestation))


# --- Synthetic chains ------------------------------------------------------------------

def crypto():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils
    return x509, hashes, ec, rsa, utils


def point(key, size):
    numbers = key.public_key().public_numbers()
    return numbers.x.to_bytes(size // 2, 'big') + numbers.y.to_bytes(size // 2, 'big')


def raw_signature(der, key_kind):
    """r || s with s in the lower half of the order, as the circuits' ECDSA expects."""
    _, _, ec, _, utils = crypto()
    r, s = utils.decode_dss_signature(der)
    order = {64: 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
             96: int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF'
                     '581A0DB248B0A77AECEC196ACCC52973', 16)}[key_kind]
    if s > order // 2:
        s = order - s
    half = key_kind // 2
    return r.to_bytes(half, 'big') + s.to_bytes(half, 'big')


def pad(data, size):
    if len(data) > size:
        raise SystemExit('fixture exceeds %d bytes' % size)
    return list(data) + [0] * (size - len(data))


def certificate(subject, key, issuer, issuer_key, digest, extension=None, ca=True):
    x509, hashes, _, _, _ = crypto()
    name = lambda cn: x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
    builder = (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer))
               .public_key(key.public_key()).serial_number(0x1001)
               .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
               .not_valid_after(datetime(2036, 1, 1, tzinfo=timezone.utc)))
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    if extension is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(OID_KEY_ATTESTATION), extension), critical=False)
    return builder.sign(issuer_key, {'sha256': hashes.SHA256(), 'sha384': hashes.SHA384()}[digest])


def chain(shape, description):
    """Inputs of the chain for `shape`, and the credential key."""
    _, hashes, ec, rsa, _ = crypto()
    root, iks = shape
    curves = {'p256': ec.SECP256R1(), 'p384': ec.SECP384R1()}
    values = {}
    if root == 'rsa':
        signer_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        modulus = signer_key.public_key().public_numbers().n
        values['root_key'] = list(modulus.to_bytes(512, 'big'))
        values['root_key_redc_param'] = list(((1 << (2 * 4096 + 6)) // modulus).to_bytes(513, 'big'))
        signer_digest, signer_size = 'sha256', None
    else:
        signer_key = ec.generate_private_key(ec.SECP384R1())
        values['root_key'] = list(point(signer_key, 96))
        signer_digest, signer_size = 'sha384', 96
    issuer = 'Fixture root'
    for i, (curve, digest) in enumerate(iks, 1):
        key = ec.generate_private_key(curves[curve])
        cert = certificate('Fixture intermediate %d' % i, key, issuer, signer_key, signer_digest)
        values['intermediate_%d_key' % i] = list(point(key, KEY_BYTES[curve]))
        values['intermediate_%d_tbs' % i] = pad(cert.tbs_certificate_bytes, TBS_MAX)
        values['intermediate_%d_sig' % i] = list(
            cert.signature if signer_size is None else raw_signature(cert.signature, signer_size))
        signer_key, signer_digest, signer_size = key, digest, KEY_BYTES[curve]
        issuer = 'Fixture intermediate %d' % i
    credential = ec.generate_private_key(ec.SECP256R1())
    cert = certificate('Android Keystore Key', credential, issuer, signer_key, signer_digest,
                       extension=description, ca=False)
    values['credential_key'] = list(point(credential, 64))
    values['credential_tbs'] = pad(cert.tbs_certificate_bytes, CREDENTIAL_TBS_MAX)
    values['credential_sig'] = list(
        cert.signature if signer_size is None else raw_signature(cert.signature, signer_size))
    return values, credential


# --- Running nargo ---------------------------------------------------------------------

def toml(values):
    plain, tables = [], []
    for key, value in values.items():
        if isinstance(value, dict):
            tables.append('[%s]\n' % key + ''.join('%s = %s\n' % (k, json.dumps(v)) for k, v in value.items()))
        else:
            plain.append('%s = %s\n' % (key, json.dumps(value)))
    return ''.join(plain) + '\n' + '\n'.join(tables)


def execute(nargo, package, values):
    directory = next(p.parent for p in GEN.rglob('Nargo.toml') if ('name = "%s"' % package) in p.read_text())
    (directory / 'Prover.toml').write_text(toml(values))
    result = subprocess.run([nargo, 'execute', '--package', package], cwd=GEN, capture_output=True, text=True)
    text = result.stdout + result.stderr
    outputs = None
    if result.returncode == 0:
        line = next(l for l in text.splitlines() if 'Circuit output' in l)
        outputs = [int(v, 0) for v in re.findall(r'0x[0-9a-f]+|\d+', line.split('Circuit output:')[1])]
    return outputs, text


def probe_source(root_bytes):
    return f'''// Generated by tools/keyattest.py: values the fixtures need from the circuits' own code.
use commitment_common::hash_salt_dg1_dg2_hash_private_nullifier;
use diw_facematch::keyattest_param_commitment;
use facematch::{{calculate_attestation_registry_leaf, constants::ATTESTATION_KEY_TYPE_GOOGLE, get_client_data_hash}};
use utils::{{poseidon2_hash_packed, types::{{DG1Data, MRZExpiryDate, SaltedValue}}}};

fn main(
    client_data: [u8; {CLIENT_DATA_MAX}],
    client_data_len: u32,
    root_key: [u8; {root_bytes}],
    app_id: [u8; {APP_ID_MAX}],
    app_id_len: u32,
    signer: [u8; 32],
    dg2_digest: [u8; 64],
    dg1: DG1Data,
    expiry: MRZExpiryDate,
    salt: Field,
    private_nullifier: Field,
    environment: u8,
    mode: u8,
) -> pub ([u8; 32], Field, Field, Field) {{
    let dg2_hash = poseidon2_hash_packed(dg2_digest, 32);
    let comm_in = hash_salt_dg1_dg2_hash_private_nullifier(
        SaltedValue::from_value(salt, dg1),
        SaltedValue::from_value(salt, expiry),
        SaltedValue::from_value(salt, dg2_hash),
        SaltedValue::from_value(salt, 3),
        SaltedValue::from_value(salt, private_nullifier),
    );
    let commitment = keyattest_param_commitment(
        calculate_attestation_registry_leaf(ATTESTATION_KEY_TYPE_GOOGLE, root_key),
        environment,
        poseidon2_hash_packed(app_id, app_id_len),
        poseidon2_hash_packed(signer, 32),
        mode,
    );
    (get_client_data_hash(client_data, client_data_len), dg2_hash, comm_in, commitment)
}}
'''


def probe(nargo, root_key, data, environment, mode):
    (GEN / 'probe/Nargo.toml').write_text(nargo_toml('diw_facematch_probe', False, '../..'))
    (GEN / 'probe/src/main.nr').write_text(probe_source(len(root_key)))
    outputs, text = execute(nargo, 'diw_facematch_probe', {
        'client_data': pad(data, CLIENT_DATA_MAX), 'client_data_len': len(data), 'root_key': root_key,
        'app_id': pad(PACKAGE, APP_ID_MAX), 'app_id_len': len(PACKAGE), 'signer': list(SIGNER),
        'dg2_digest': pad(DG2_DIGEST, 64), 'dg1': DG1, 'expiry': EXPIRY, 'salt': hex(SALT),
        'private_nullifier': hex(PRIVATE_NULLIFIER), 'environment': environment, 'mode': mode})
    if outputs is None:
        raise SystemExit('probe failed:\n' + text)
    return bytes(outputs[:32]), outputs[32], outputs[33], outputs[34]


def fixture(nargo, shape, description, mode=1, environment=1):
    """Inputs of the circuit for `shape`, and the parameter commitment it must return."""
    _, hashes, ec, _, _ = crypto()
    values, credential = chain(shape, description)
    data = client_data(mode)
    data_hash, dg2_hash, comm_in, commitment = probe(nargo, values['root_key'], data, environment, mode)
    signature = credential.sign(data_hash, ec.ECDSA(hashes.SHA256()))
    salted = lambda value: {'salt': hex(SALT), 'value': value, 'hash': '0'}
    inputs = {'comm_in': hex(comm_in), 'current_date': DATE}
    inputs.update(values)
    inputs.update({
        'client_data': pad(data, CLIENT_DATA_MAX), 'client_data_sig': list(raw_signature(signature, 64)),
        'facematch_mode': mode, 'nullifier_secret': '0', 'service_scope': '7', 'service_subscope': '0',
        'salted_private_nullifier': salted(hex(PRIVATE_NULLIFIER)), 'salted_expiry_date': salted(EXPIRY),
        'salted_dg1': salted(DG1), 'salted_dg2_hash': salted(hex(dg2_hash)), 'salted_dg2_hash_type': salted(3)})
    return inputs, commitment


def check_shape(nargo, shape, bb=None, crs=None):
    package = package_name(shape)
    failures = []

    def expect(label, outputs, text, commitment=None, error=None):
        if error is None:
            ok = outputs is not None and outputs[0] == commitment
        else:
            ok = outputs is None and error in text
        print('  %-44s %s' % (label, 'ok' if ok else 'FAILED'))
        if not ok:
            failures.append(label)
            print('\n'.join(text.splitlines()[-6:]))

    # Environments: verified and locked, owner-installed key and locked, anything else.
    for label, kwargs, environment in (
            ('verified boot, locked', {}, 1),
            ('self-signed boot, locked', {'boot_state': 1}, 2),
            ('verified boot, unlocked', {'locked': False}, 0),
            ('unverified boot', {'boot_state': 2}, 0)):
        inputs, commitment = fixture(nargo, shape, key_description(**kwargs), environment=environment)
        outputs, text = execute(nargo, package, inputs)
        expect(label, outputs, text, commitment=commitment)
    good = inputs

    for label, kwargs, error in (
            ('software attestation', {'level': 0}, 'software attestation'),
            ('software key', {'keymint_level': 0}, 'software key'),
            ('imported key', {'origin': 2}, 'not generated in the keystore'),
            ('root of trust only in the software list', {'hardware_root': False}, 'entry not found')):
        inputs, _ = fixture(nargo, shape, key_description(**kwargs))
        outputs, text = execute(nargo, package, inputs)
        expect(label, outputs, text, error=error)

    # A root-of-trust entry planted in the challenge must not be read in place of the real one.
    planted = explicit(704, tlv([0x30], tlv([0x04], b'\x21' * 32) + bytes([0x01, 0x01, 0xFF, 0x0A, 0x01, 0x00])
                               + tlv([0x04], b'\x22' * 32)))
    inputs, commitment = fixture(nargo, shape, key_description(boot_state=2, challenge=planted), environment=0)
    outputs, text = execute(nargo, package, inputs)
    expect('planted root of trust in the challenge', outputs, text, commitment=commitment)

    tampered = dict(good)
    tampered['client_data_sig'] = [b ^ 1 if i == 5 else b for i, b in enumerate(good['client_data_sig'])]
    outputs, text = execute(nargo, package, tampered)
    expect('client data signature of another key', outputs, text, error='Failed to verify client data hash')
    tampered = dict(good)
    tampered['credential_tbs'] = [b ^ 1 if i == 40 else b for i, b in enumerate(good['credential_tbs'])]
    outputs, text = execute(nargo, package, tampered)
    expect('altered credential certificate', outputs, text, error='Failed to verify')
    tampered = dict(good)
    tampered['facematch_mode'] = 2
    outputs, text = execute(nargo, package, tampered)
    expect('another mode than the signed one', outputs, text, error='facematch_mode')
    tampered = dict(good)
    tampered['salted_dg2_hash'] = {'salt': hex(SALT), 'value': '0x2a', 'hash': '0'}
    outputs, text = execute(nargo, package, tampered)
    expect('photo of another document', outputs, text, error='dg2_hash')

    if bb and not failures:
        outputs, text = execute(nargo, package, good)
        target = GEN / 'target'
        proof = target / ('proof_' + shape_name(shape))
        proof.mkdir(exist_ok=True)
        gates = json.loads(subprocess.run([bb, 'gates', '-b', str(target / (package + '.json'))],
                                          capture_output=True, text=True, check=True).stdout)
        size = gates['functions'][0]['circuit_size']
        common = ['-s', 'ultra_honk', '--oracle_hash', 'poseidon2', '-c', str(crs)]
        proved = subprocess.run([bb, 'prove', *common, '-b', str(target / (package + '.json')),
                                 '-w', str(target / (package + '.gz')), '-o', str(proof), '--write_vk'],
                                capture_output=True, text=True)
        verified = proved.returncode == 0 and subprocess.run(
            [bb, 'verify', *common, '-k', str(proof / 'vk'), '-p', str(proof / 'proof'),
             '-i', str(proof / 'public_inputs')], capture_output=True, text=True).returncode == 0
        print('  %-44s %s (%d gates)' % ('prove and verify', 'ok' if verified else 'FAILED', size))
        if not verified:
            failures.append('prove')
            print(proved.stderr[-600:])
    return failures


# --- Library tests ---------------------------------------------------------------------

def noir_bytes(data, size):
    values = pad(data, size)
    rows = [', '.join(str(b) for b in values[i:i + 24]) for i in range(0, size, 24)]
    return '[\n    ' + ',\n    '.join(rows) + ',\n]'


def lib_tests():
    prefix = bytes.fromhex('3082010ca003020102') + b'\x30\x0a' + bytes.fromhex('06082a8648ce3d040302')
    oid = bytes.fromhex('060a2b06010401d679020111')

    def tbs(**kwargs):
        value = key_description(**kwargs)
        return prefix + tlv([0x30], oid + tlv([0x04], value))

    planted = explicit(704, tlv([0x30], tlv([0x04], b'\x21' * 32) + bytes([0x01, 0x01, 0xFF, 0x0A, 0x01, 0x00])
                               + tlv([0x04], b'\x22' * 32)))
    cases = [('VERIFIED', {}), ('SELF_SIGNED', {'boot_state': 1}), ('UNLOCKED', {'locked': False}),
             ('STRONGBOX', {'level': 2, 'keymint_level': 2}), ('SOFTWARE', {'level': 0}),
             ('SOFTWARE_KEY', {'keymint_level': 0}), ('IMPORTED', {'origin': 2}),
             ('SOFTWARE_ROOT', {'hardware_root': False}),
             ('PLANTED', {'boot_state': 2, 'locked': False, 'challenge': planted})]
    out = ['// Generated by `tools/keyattest.py libtests`: synthetic key attestation extensions of a\n'
           '// fictional app, not taken from any device.\n'
           'use crate::{ENV_SELF_SIGNED, ENV_UNTRUSTED, ENV_VERIFIED};\n'
           'use crate::keyattest::{assert_hardware_key, environment, parse_key_attestation};\n']
    for name, kwargs in cases:
        out.append('global %s: [u8; 600] = %s;\n' % (name, noir_bytes(tbs(**kwargs), 600)))
    out.append('global SIGNER: [u8; 32] = %s;\n' % noir_bytes(SIGNER, 32))
    out.append('''#[test]
fn reads_a_verified_locked_device() {
    let attestation = parse_key_attestation(VERIFIED);
    assert_hardware_key(attestation);
    assert(attestation.attestation_level == 1);
    assert(attestation.device_locked);
    assert(attestation.boot_state == 0);
    assert(attestation.signer_digest == SIGNER);
    assert(environment(attestation) == ENV_VERIFIED);
}

#[test]
fn tells_the_boot_states_apart() {
    assert(environment(parse_key_attestation(SELF_SIGNED)) == ENV_SELF_SIGNED);
    assert(environment(parse_key_attestation(UNLOCKED)) == ENV_UNTRUSTED);
}

#[test]
fn accepts_strongbox() {
    let attestation = parse_key_attestation(STRONGBOX);
    assert_hardware_key(attestation);
    assert(attestation.keymint_level == 2);
}

#[test(should_fail_with = "software attestation")]
fn rejects_a_software_attestation() {
    assert_hardware_key(parse_key_attestation(SOFTWARE));
}

#[test(should_fail_with = "software key")]
fn rejects_a_software_key() {
    assert_hardware_key(parse_key_attestation(SOFTWARE_KEY));
}

#[test(should_fail_with = "not generated in the keystore")]
fn rejects_an_imported_key() {
    assert_hardware_key(parse_key_attestation(IMPORTED));
}

#[test(should_fail_with = "entry not found")]
fn wants_the_root_of_trust_in_the_hardware_list() {
    let _ = parse_key_attestation(SOFTWARE_ROOT);
}

#[test]
fn ignores_a_root_of_trust_planted_in_the_challenge() {
    let attestation = parse_key_attestation(PLANTED);
    assert(!attestation.device_locked);
    assert(attestation.boot_state == 2);
    assert(environment(attestation) == ENV_UNTRUSTED);
}
''')
    (ROOT / 'src/lib/diw_facematch/src/tests.nr').write_text('\n'.join(out))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('gen')
    sub.add_parser('libtests')
    sub.add_parser('list')
    check = sub.add_parser('check')
    check.add_argument('--nargo', default='nargo')
    check.add_argument('--bb')
    check.add_argument('--crs', type=Path)
    check.add_argument('shapes', nargs='*', help='shape names (default: one per kind of root)')
    args = parser.parse_args()
    if args.command == 'gen':
        print('%d circuits in %s' % (generate(), GEN))
    elif args.command == 'libtests':
        lib_tests()
    elif args.command == 'list':
        print('\n'.join(shape_name(s) for s in shapes()))
    else:
        if args.bb and not args.crs:
            parser.error('--bb requires --crs')
        generate()
        by_name = {shape_name(s): s for s in shapes()}
        names = args.shapes or ['rk_ecdsa_ik_p384_sha384', 'rk_rsa_ik_p256_sha256_ik_p384_sha384']
        failed = False
        for name in names:
            if name not in by_name:
                parser.error('unknown shape ' + name)
            print(name)
            failed |= bool(check_shape(args.nargo, by_name[name], args.bb, args.crs))
        sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
