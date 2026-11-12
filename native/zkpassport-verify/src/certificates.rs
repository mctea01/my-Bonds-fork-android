//! zkPassport's packaged certificates (@zkpassport/utils `calculatePackagedCertificatesRoot`): the certificate
//! registry root a package hashes to, and its CSCA keys by country. The circuits bind the CSCA leaf's country to
//! the issuing state of DG1, so a disclosed issuing country tells which of these keys can have signed.

use crate::zk::{merkle_root, pack_be_bytes, poseidon2_hash};
use crate::{field, hex32};
use num_bigint::BigUint;
use serde_json::{json, Value};

pub const CERTIFICATE_TREE_HEIGHT: usize = 16;
pub const REVOCATION_TREE_HEIGHT: usize = 14;
pub const MASTERLIST_TREE_HEIGHT: usize = 8;
const CSCA: u8 = 1;
const TAG_LIMB_BITS: usize = 253;

fn bytes(hex: &str) -> Result<Vec<u8>, String> {
    let h = hex.strip_prefix("0x").ok_or("certificates")?;
    let h = if h.len() % 2 == 1 { format!("0{h}") } else { h.to_string() };
    hex::decode(h).map_err(|_| "certificates".to_string())
}

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v.get(key).and_then(Value::as_str).ok_or_else(|| "certificates".to_string())
}

/// `tagsArrayToBitsFlag`: one bit per two-letter tag over three 253-bit limbs.
fn tags(cert: &Value) -> Result<Vec<BigUint>, String> {
    let mut limbs = vec![BigUint::from(0u8); 3];
    for tag in cert.get("tags").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
        let t = tag.as_str().map(str::as_bytes).ok_or("certificates")?;
        if t.len() != 2 || !t.iter().all(u8::is_ascii_uppercase) {
            return Err("certificates".into());
        }
        let bit = (t[0] - b'A') as usize * 26 + (t[1] - b'A') as usize;
        limbs[bit / TAG_LIMB_BITS] |= BigUint::from(1u8) << (bit % TAG_LIMB_BITS);
    }
    Ok(limbs)
}

/// `publicKeyToBytes`: the RSA modulus, or the EC point's x then y.
fn public_key(cert: &Value) -> Result<Vec<u8>, String> {
    let key = cert.get("public_key").ok_or("certificates")?;
    match text(key, "type")? {
        "RSA" => bytes(text(key, "modulus")?),
        "EC" => Ok([bytes(text(key, "public_key_x")?)?, bytes(text(key, "public_key_y")?)?].concat()),
        _ => Err("certificates".into()),
    }
}

/// `getCertificateLeafHash` for schema versions 0 and 1.
fn leaf(cert: &Value, version: u64) -> Result<BigUint, String> {
    let country = text(cert, "country")?.as_bytes();
    if country.len() != 3 {
        return Err("certificates".into());
    }
    let mut meta = vec![CSCA, country[0], country[1], country[2]];
    let mut inputs = tags(cert)?;
    if version == 1 {
        let expiry = cert.pointer("/validity/not_after").and_then(Value::as_u64).filter(|e| *e <= u32::MAX as u64).ok_or("certificates")?;
        meta.extend_from_slice(&(expiry as u32).to_be_bytes());
        inputs.push(pack_be_bytes(&meta, 31).remove(0));
        inputs.push(text(cert, "fingerprint").ok().and_then(field).ok_or("certificates")?);
    } else {
        inputs.push(pack_be_bytes(&meta, 31).remove(0));
    }
    inputs.extend(pack_be_bytes(&public_key(cert)?, 31));
    Ok(poseidon2_hash(&inputs))
}

fn tree(height: usize, mut leaves: Vec<BigUint>) -> Result<BigUint, String> {
    if leaves.len() > 1 << height {
        return Err("certificates".into());
    }
    leaves.sort();
    if leaves.windows(2).any(|w| w[0] == w[1]) {
        return Err("certificates".into());
    }
    Ok(merkle_root(height, &leaves))
}

/// The certificate registry root of a package (v0: the certificate tree root; v1: bound with the revocation and
/// masterlist trees, the schema version and the timestamp).
pub fn root(package: &Value) -> Result<BigUint, String> {
    let version = package.get("version").and_then(Value::as_u64).unwrap_or(0);
    if version > 1 {
        return Err("certificates_version".into());
    }
    let certs = package.get("certificates").and_then(Value::as_array).ok_or("certificates")?;
    let cert_root = tree(CERTIFICATE_TREE_HEIGHT, certs.iter().map(|c| leaf(c, version)).collect::<Result<_, _>>()?)?;
    if version == 0 {
        return Ok(cert_root);
    }
    let revocations = package.get("revocations").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let revocation_leaves = revocations
        .iter()
        .map(|r| {
            let fingerprint = text(r, "fingerprint").ok().and_then(field).ok_or("certificates")?;
            let serial = poseidon2_hash(&pack_be_bytes(&bytes(text(r, "serial")?)?, 31));
            Ok(poseidon2_hash(&[fingerprint, serial]))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let masterlists = package.get("masterlists").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let masterlist_leaves = masterlists.iter().map(|m| m.as_str().and_then(field).ok_or("certificates".to_string())).collect::<Result<Vec<_>, _>>()?;
    let state = poseidon2_hash(&[cert_root, tree(REVOCATION_TREE_HEIGHT, revocation_leaves)?, tree(MASTERLIST_TREE_HEIGHT, masterlist_leaves)?]);
    let timestamp = package.get("timestamp").and_then(Value::as_u64).filter(|t| *t <= u32::MAX as u64).ok_or("certificates")?;
    let mut meta = (version as u16).to_be_bytes().to_vec();
    meta.extend_from_slice(&(timestamp as u32).to_be_bytes());
    Ok(poseidon2_hash(&[pack_be_bytes(&meta, 31).remove(0), state]))
}

/// The root a package hashes to and its CSCA keys: country, key bytes (hex), fingerprint and validity.
pub fn package_json(package: &str) -> Result<String, String> {
    let package: Value = serde_json::from_str(package).map_err(|_| "json".to_string())?;
    let root = root(&package)?;
    let certs = package.get("certificates").and_then(Value::as_array).ok_or("certificates")?;
    let keys = certs
        .iter()
        .map(|c| {
            Ok(json!({
                "country": text(c, "country")?,
                "publicKey": hex::encode(public_key(c)?),
                "fingerprint": c.get("fingerprint").cloned().unwrap_or(Value::Null),
                "notBefore": c.pointer("/validity/not_before").cloned().unwrap_or(Value::Null),
                "notAfter": c.pointer("/validity/not_after").cloned().unwrap_or(Value::Null),
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(json!({ "root": hex32(&root), "certificates": keys }).to_string())
}
