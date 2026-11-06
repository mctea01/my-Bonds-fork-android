//! Checks a zkPassport proof bundle (fast mode) for the wallet's verifier role.
//!
//! It follows the zkPassport SDK's public-input checker and is stricter in three ways: only values the
//! proofs commit to are reported (never the plaintext result the holder's app sends alongside), the circuit
//! manifest must hash to a root the circuit registry accepted at the proofs' date (the SDK only checks the
//! manifest against itself), and every condition of the verifier's own query must be backed by a proof.
//! Barretenberg verification is passed in, so this crate stays free of native code.

use base64::Engine;
use num_bigint::BigUint;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
mod zk;
use zk::{merkle_root, num_public_inputs, pack_be_bits, pack_be_bytes, poseidon2_hash, vkey_fields, CIRCUIT_REGISTRY_HEIGHT};

/// The SDK's default validity of the proven current date, in seconds.
pub const DEFAULT_VALIDITY: u64 = 7 * 24 * 60 * 60;
const FUTURE_TOLERANCE: i64 = 24 * 60 * 60;
const CHAIN: [&str; 3] = ["sig_check_dsc", "sig_check_id_data", "data_check_integrity"];
/// The disclosure circuits this verifier asks for, in the SDK's order.
const DISCLOSURES: [&str; 7] = [
    "disclose_bytes",
    "compare_age",
    "exclusion_check_nationality",
    "inclusion_check_nationality",
    "exclusion_check_issuing_country",
    "inclusion_check_issuing_country",
    "bind",
];
const DISCLOSABLE: [&str; 10] = [
    "firstname", "lastname", "fullname", "birthdate", "document_number", "nationality", "document_type",
    "expiry_date", "gender", "issuing_country",
];

/// One proof as the holder's app sends it in a `proof` message.
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProofResult {
    pub proof: String,
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub vkey_hash: Option<String>,
    #[serde(default)]
    pub committed_inputs: Option<Value>,
}

struct Proof {
    name: String,
    rank: usize,
    public: Vec<BigUint>,
    public_bytes: Vec<u8>,
    body: Vec<u8>,
    committed: Value,
    vkey_hash: Option<String>,
}

impl Proof {
    fn disclosure(&self) -> bool {
        self.rank >= CHAIN.len()
    }
    fn input(&self, i: usize) -> &BigUint {
        &self.public[i]
    }
    fn tail(&self, back: usize) -> &BigUint {
        &self.public[self.public.len() - back]
    }
}

fn rank(name: &str) -> Option<usize> {
    CHAIN
        .iter()
        .position(|p| name.starts_with(p))
        .or_else(|| DISCLOSURES.iter().position(|d| *d == name).map(|i| i + CHAIN.len()))
}

fn parse(p: &ProofResult) -> Result<Proof, String> {
    let rank = rank(&p.name).ok_or_else(|| format!("unsupported:{}", p.name))?;
    let bytes = hex::decode(p.proof.strip_prefix("0x").unwrap_or(&p.proof)).map_err(|_| format!("encoding:{}", p.name))?;
    let n = num_public_inputs(&p.name);
    if bytes.len() % 32 != 0 || bytes.len() <= n * 32 {
        return Err(format!("encoding:{}", p.name));
    }
    let (head, body) = bytes.split_at(n * 32);
    Ok(Proof {
        name: p.name.clone(),
        rank,
        public: head.chunks(32).map(BigUint::from_bytes_be).collect(),
        public_bytes: head.to_vec(),
        body: body.to_vec(),
        committed: p.committed_inputs.as_ref().and_then(|c| c.get(&p.name)).cloned().unwrap_or(Value::Null),
        vkey_hash: p.vkey_hash.clone(),
    })
}

struct Bundle {
    version: String,
    proofs: Vec<Proof>,
    date: u64,
}

impl Bundle {
    fn new(results: &[ProofResult]) -> Result<Self, String> {
        let mut proofs = results.iter().map(parse).collect::<Result<Vec<_>, _>>()?;
        proofs.sort_by_key(|p| p.rank);
        for rank in 0..CHAIN.len() {
            if proofs.iter().filter(|p| p.rank == rank).count() != 1 {
                return Err(format!("missing:{}", CHAIN[rank]));
            }
        }
        if proofs.windows(2).any(|w| w[0].rank == w[1].rank) {
            return Err("duplicate".into());
        }
        let first = proofs.iter().find(|p| p.disclosure()).ok_or("missing:disclosure")?;
        let date = u64::try_from(first.input(1)).map_err(|_| "date".to_string())?;
        let mut versions = results.iter().map(|r| r.version.clone().unwrap_or_default());
        let version = versions.next().unwrap_or_default();
        if version.is_empty() || versions.any(|v| v != version) {
            return Err("version".into());
        }
        Ok(Self { version, proofs, date })
    }
}

fn field(s: &str) -> Option<BigUint> {
    let h = s.strip_prefix("0x").unwrap_or(s);
    if h.is_empty() || h.len() > 64 {
        return None;
    }
    BigUint::parse_bytes(h.as_bytes(), 16)
}

fn hex32(x: &BigUint) -> String {
    format!("0x{:0>64}", x.to_str_radix(16))
}

fn big(n: u64) -> BigUint {
    BigUint::from(n)
}

/// `getScopeHash`: the first 31 bytes of SHA-256 of the text, or 0 without one.
pub fn scope_hash(value: Option<&str>) -> BigUint {
    match value.filter(|v| !v.is_empty()) {
        None => big(0),
        Some(v) => BigUint::from_bytes_be(&Sha256::digest(v.as_bytes())[..31]),
    }
}

/// The registry leaf of a packaged circuit: Poseidon2 over its verification key's 32-byte fields.
pub fn vkey_hash(vkey: &[u8]) -> BigUint {
    poseidon2_hash(&vkey_fields(vkey))
}

/// The circuit registry root of a manifest: a height-12 Poseidon2 tree over its sorted key hashes. It must
/// equal the root the manifest declares.
pub fn circuit_root(manifest: &Value) -> Result<String, String> {
    let circuits = manifest.get("circuits").and_then(Value::as_object).ok_or("manifest")?;
    let mut leaves = circuits
        .values()
        .map(|c| c.get("hash").and_then(Value::as_str).and_then(field))
        .collect::<Option<Vec<_>>>()
        .ok_or("manifest")?;
    if leaves.is_empty() || leaves.len() > 1 << CIRCUIT_REGISTRY_HEIGHT {
        return Err("manifest".into());
    }
    leaves.sort();
    let root = merkle_root(CIRCUIT_REGISTRY_HEIGHT, &leaves);
    match manifest.get("root").and_then(Value::as_str).map(field) {
        Some(Some(declared)) if declared == root => Ok(hex32(&root)),
        _ => Err("manifest_root".into()),
    }
}

/// The version, circuit names, certificate registry root and proof date of a bundle: what the caller needs
/// to fetch the circuit manifest and ask the registry before [verify].
pub fn inspect(results: &[ProofResult]) -> Result<Value, String> {
    let bundle = Bundle::new(results)?;
    let names: Vec<&str> = bundle.proofs.iter().map(|p| p.name.as_str()).collect();
    Ok(json!({
        "version": bundle.version,
        "names": names,
        "certificateRoot": hex32(bundle.proofs[0].input(0)),
        "timestamp": bundle.date,
    }))
}

// ---- Parameter commitments ------------------------------------------------------------------------------

fn u8_list(v: Option<&Value>, len: usize) -> Option<Vec<u8>> {
    let list = v?.as_array()?;
    if list.len() != len {
        return None;
    }
    list.iter().map(|x| x.as_u64().filter(|n| *n <= 255).map(|n| n as u8)).collect()
}

fn country_sum(code: &str) -> Option<u64> {
    let b = code.as_bytes();
    let ok = b.len() == 3 && (b.iter().all(u8::is_ascii_uppercase) || code == "D<<");
    ok.then(|| (b[0] as u64) * 0x10000 + (b[1] as u64) * 0x100 + b[2] as u64)
}

fn countries(committed: &Value) -> Option<Vec<String>> {
    let list = committed.get("countries")?.as_array()?;
    if list.is_empty() || list.len() > 200 {
        return None;
    }
    list.iter().map(|c| c.as_str().filter(|s| country_sum(s).is_some()).map(String::from)).collect()
}

/// The bound data a bind proof commits to: user address and custom data (chains are not asked for).
fn format_bound(data: &Value) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    if let Some(addr) = data.get("user_address").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        let h = addr.strip_prefix("0x").unwrap_or(addr);
        let bytes = hex::decode(if h.len() % 2 == 1 { format!("0{h}") } else { h.to_string() }).ok()?;
        out.push(1);
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(&bytes);
    }
    if data.get("chain").is_some_and(|c| !c.is_null()) {
        return None;
    }
    if let Some(custom) = data.get("custom_data").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        out.push(3);
        out.extend_from_slice(&(custom.len() as u16).to_be_bytes());
        out.extend_from_slice(custom.as_bytes());
    }
    (out.len() <= 509).then_some(out)
}

fn commitment(kind: u64, length: u64, values: Vec<BigUint>) -> BigUint {
    let mut inputs = vec![big(kind), big(length)];
    inputs.extend(values);
    poseidon2_hash(&inputs)
}

/// The parameter commitment a disclosure proof must carry for its committed inputs.
fn parameters(p: &Proof) -> Option<BigUint> {
    let c = &p.committed;
    Some(match p.name.as_str() {
        "disclose_bytes" => {
            let mask = u8_list(c.get("discloseMask"), 90)?;
            let bytes = u8_list(c.get("disclosedBytes"), 90)?;
            if mask.iter().any(|m| *m > 1) || mask.iter().zip(&bytes).any(|(m, b)| *m == 0 && *b != 0) {
                return None;
            }
            let mut values = vec![pack_be_bits(&mask, 253)];
            values.extend(pack_be_bytes(&bytes, 31));
            commitment(0, 4, values)
        }
        "compare_age" => {
            let min = c.get("minAge")?.as_u64().filter(|n| *n <= 255)?;
            let max = c.get("maxAge")?.as_u64().filter(|n| *n <= 255)?;
            commitment(1, 2, vec![big(min), big(max)])
        }
        "bind" => {
            let mut data = format_bound(c.get("data")?)?;
            data.resize(509, 0);
            commitment(8, 17, pack_be_bytes(&data, 31))
        }
        name => {
            let kind = match name {
                "inclusion_check_nationality" => 4,
                "exclusion_check_nationality" => 5,
                "inclusion_check_issuing_country" => 6,
                "exclusion_check_issuing_country" => 7,
                _ => return None,
            };
            let mut sums: Vec<u64> = countries(c)?.iter().filter_map(|s| country_sum(s)).collect();
            if kind % 2 == 1 {
                // An exclusion proof is only sound over an ascending list.
                if sums.windows(2).any(|w| w[0] >= w[1]) {
                    return None;
                }
            }
            sums.resize(200, 0);
            commitment(kind, 200, sums.into_iter().map(big).collect())
        }
    })
}

// ---- Disclosed data -------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Layout {
    Td3,
    Td1,
}

fn range(layout: Option<Layout>, field: &str) -> Option<(usize, usize)> {
    match (field, layout) {
        ("document_type", _) => Some((0, 2)),
        ("issuing_country", _) => Some((2, 5)),
        (_, None) => None,
        ("firstname" | "lastname" | "fullname", Some(Layout::Td3)) => Some((5, 44)),
        ("document_number", Some(Layout::Td3)) => Some((44, 53)),
        ("nationality", Some(Layout::Td3)) => Some((54, 57)),
        ("birthdate", Some(Layout::Td3)) => Some((57, 63)),
        ("gender", Some(Layout::Td3)) => Some((64, 65)),
        ("expiry_date", Some(Layout::Td3)) => Some((65, 71)),
        ("firstname" | "lastname" | "fullname", Some(Layout::Td1)) => Some((60, 90)),
        ("document_number", Some(Layout::Td1)) => Some((5, 14)),
        ("birthdate", Some(Layout::Td1)) => Some((30, 36)),
        ("gender", Some(Layout::Td1)) => Some((37, 38)),
        ("expiry_date", Some(Layout::Td1)) => Some((38, 44)),
        ("nationality", Some(Layout::Td1)) => Some((45, 48)),
        _ => None,
    }
}

struct Disclosed {
    mask: Vec<u8>,
    bytes: Vec<u8>,
    layout: Option<Layout>,
}

impl Disclosed {
    fn new(committed: &Value) -> Option<Self> {
        let mask = u8_list(committed.get("discloseMask"), 90)?;
        let bytes = u8_list(committed.get("disclosedBytes"), 90)?;
        let layout = (mask[0] == 1 && mask[1] == 1).then(|| match bytes[0] {
            b'P' => Some(Layout::Td3),
            b'I' | b'A' | b'C' => Some(Layout::Td1),
            _ => None,
        });
        Some(Self { mask, bytes, layout: layout.flatten() })
    }
    fn covers(&self, field: &str) -> bool {
        range(self.layout, field).is_some_and(|(a, b)| self.mask[a..b].iter().all(|m| *m == 1))
    }
    fn text(&self, field: &str) -> Option<String> {
        if !self.covers(field) {
            return None;
        }
        let (a, b) = range(self.layout, field)?;
        Some(String::from_utf8_lossy(&self.bytes[a..b]).replace('\0', ""))
    }
    fn values(&self) -> Value {
        let mut out = Map::new();
        if let Some(t) = self.text("document_type") {
            out.insert("documentCode".into(), json!(t.trim_end_matches('<')));
        }
        for (field, key) in [("issuing_country", "issuingCountry"), ("nationality", "nationality")] {
            if let Some(t) = self.text(field) {
                out.insert(key.into(), json!(if t == "D<<" { "DEU".to_string() } else { t.trim_end_matches('<').to_string() }));
            }
        }
        for (field, key) in [("document_number", "documentNumber"), ("birthdate", "birthdate"), ("expiry_date", "expiryDate"), ("gender", "gender")] {
            if let Some(t) = self.text(field) {
                out.insert(key.into(), json!(t.trim_end_matches('<')));
            }
        }
        if let Some(raw) = self.text("fullname") {
            // Every given name is kept: the zone separates them with single fillers.
            let (last, given) = raw.split_once("<<").unwrap_or((raw.as_str(), ""));
            let words = |s: &str| s.split('<').filter(|w| !w.is_empty()).collect::<Vec<_>>().join(" ");
            out.insert("lastName".into(), json!(words(last)));
            out.insert("givenNames".into(), json!(words(given)));
        }
        out.insert("layout".into(), json!(match self.layout {
            Some(Layout::Td3) => "td3",
            Some(Layout::Td1) => "td1",
            None => "unknown",
        }));
        Value::Object(out)
    }
}

// ---- Query --------------------------------------------------------------------------------------------

/// `minAge`/`maxAge` the app derives from an age condition (0 means unbounded).
fn age_bounds(q: &Value) -> Option<(u64, u64)> {
    let get = |k: &str| q.get(k).and_then(Value::as_u64);
    let (mut min, mut max) = (0, 0);
    if let Some(gt) = get("gt") {
        min = gt + 1;
    } else if let Some(gte) = get("gte") {
        min = gte;
    } else if let Some(r) = q.get("range").and_then(Value::as_array) {
        min = r.first()?.as_u64()?;
        max = r.get(1)?.as_u64()?;
    } else if let Some(eq) = get("eq") {
        min = eq;
        max = eq;
    }
    if let Some(lt) = get("lt") {
        max = lt.checked_sub(1)?;
    } else if let Some(lte) = get("lte") {
        max = lte;
    }
    Some((min, max))
}

fn same_set(a: &[String], b: &[String]) -> bool {
    let (mut a, mut b) = (a.to_vec(), b.to_vec());
    a.sort();
    b.sort();
    a == b
}

fn query_list(q: &Value, field: &str, op: &str) -> Option<Vec<String>> {
    let list = q.get(field)?.get(op)?.as_array()?;
    Some(list.iter().filter_map(|c| c.as_str().map(String::from)).collect())
}

fn bind_matches(asked: &Value, proven: &Value) -> bool {
    let text = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let address = |v: &Value| text(v, "user_address").trim_start_matches("0x").to_ascii_lowercase();
    address(asked) == address(proven)
        && text(asked, "custom_data") == text(proven, "custom_data")
        && asked.get("chain").is_none_or(Value::is_null)
}

/// Every condition of the verifier's own query must be backed by a proof with exactly those parameters.
fn check_query(query: &Value, proofs: &[Proof], errors: &mut Vec<String>) {
    let find = |name: &str| proofs.iter().find(|p| p.name == name);
    let Some(q) = query.as_object() else {
        errors.push("query".into());
        return;
    };
    let disclosed = find("disclose_bytes").and_then(|p| Disclosed::new(&p.committed));
    for (field, ops) in q {
        let Some(ops) = ops.as_object() else { continue };
        let known = match field.as_str() {
            "age" => vec!["gt", "gte", "lt", "lte", "range", "eq"],
            "nationality" | "issuing_country" => vec!["in", "out", "disclose"],
            "bind" => vec!["user_address", "custom_data", "chain"],
            f if DISCLOSABLE.contains(&f) => vec!["disclose"],
            _ => vec![],
        };
        if ops.keys().any(|k| !known.contains(&k.as_str())) {
            errors.push(format!("query_unsupported:{field}"));
        }
        if ops.get("disclose").and_then(Value::as_bool) == Some(true)
            && !disclosed.as_ref().is_some_and(|d| d.covers(field))
        {
            errors.push(format!("query:{field}"));
        }
    }
    if let Some(age) = q.get("age").filter(|a| a.as_object().is_some_and(|o| !o.is_empty())) {
        let proven = find("compare_age").map(|p| (p.committed.get("minAge").and_then(Value::as_u64), p.committed.get("maxAge").and_then(Value::as_u64)));
        let asked = age_bounds(age);
        if asked.is_none() || proven != asked.map(|(a, b)| (Some(a), Some(b))) {
            errors.push("query:age".into());
        }
    }
    for field in ["nationality", "issuing_country"] {
        for (op, circuit) in [("in", "inclusion_check"), ("out", "exclusion_check")] {
            if let Some(asked) = query_list(query, field, op) {
                let proven = find(&format!("{circuit}_{field}")).and_then(|p| countries(&p.committed));
                if !proven.is_some_and(|p| same_set(&p, &asked)) {
                    errors.push(format!("query:{field}"));
                }
            }
        }
    }
    if let Some(asked) = q.get("bind").filter(|b| b.is_object()) {
        let proven = find("bind").and_then(|p| p.committed.get("data").cloned());
        if !proven.is_some_and(|p| bind_matches(asked, &p)) {
            errors.push("query:bind".into());
        }
    }
}

// ---- Verification -----------------------------------------------------------------------------------------

/// What [verify] needs besides the proofs: the verifier's query and service, the manifest and verification
/// keys the caller fetched for the bundle's version, and the registry's answers at the proofs' date.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    pub proofs: Vec<ProofResult>,
    pub query: Value,
    pub domain: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub dev_mode: bool,
    #[serde(default)]
    pub validity: Option<u64>,
    /// Local midnight today, in Unix seconds.
    pub today: i64,
    pub manifest: Value,
    /// Circuit name to base64 verification key, from the packaged circuits.
    pub vkeys: HashMap<String, String>,
    pub certificate_root: String,
    pub certificate_root_valid: bool,
    pub circuit_root: String,
    pub circuit_root_valid: bool,
    /// Poseidon2 hash of the accepted OPRF public key, for salted identifiers.
    #[serde(default)]
    pub oprf_public_key_hash: Option<String>,
}

fn nullifier_type(n: &BigUint) -> &'static str {
    match u64::try_from(n).unwrap_or(u64::MAX) {
        0 => "NON_SALTED",
        1 => "SALTED",
        2 => "NON_SALTED_MOCK",
        3 => "SALTED_MOCK",
        4 => "NONE",
        _ => "INVALID",
    }
}

fn distinct<T: PartialEq + Clone>(values: impl Iterator<Item = T>, none: &T) -> Vec<T> {
    let mut out: Vec<T> = Vec::new();
    for v in values {
        if &v != none && !out.contains(&v) {
            out.push(v);
        }
    }
    out
}

fn failure(error: String) -> Value {
    json!({ "verified": false, "errors": [error] })
}

/// Checks the bundle in [Request]; `bb` verifies one UltraHonk proof from its verification key, proof body
/// and public inputs. Proofs are only handed to `bb` once every other check passed.
pub fn verify(req: &Request, mut bb: impl FnMut(&[u8], &[u8], &[u8]) -> Result<(), String>) -> Value {
    let bundle = match Bundle::new(&req.proofs) {
        Ok(b) => b,
        Err(e) => return failure(e),
    };
    let mut errors: Vec<String> = Vec::new();
    let proofs = &bundle.proofs;

    // Registries: the certificate root the document chains to, and the circuits the keys come from.
    if field(&req.certificate_root).as_ref() != Some(proofs[0].input(0)) {
        errors.push("certificate_root_mismatch".into());
    } else if !req.certificate_root_valid {
        errors.push("certificate_root".into());
    }
    match circuit_root(&req.manifest) {
        Ok(root) if field(&root) == field(&req.circuit_root) => {
            if !req.circuit_root_valid {
                errors.push("circuit_root".into());
            }
        }
        Ok(_) => errors.push("circuit_root_mismatch".into()),
        Err(e) => errors.push(e),
    }
    if req.manifest.get("version").and_then(Value::as_str) != Some(bundle.version.as_str()) {
        errors.push("manifest_version".into());
    }

    // The commitment chain: certificate -> document signature -> integrity -> every disclosure.
    let mut out = proofs[0].input(1).clone();
    for p in &proofs[1..] {
        if p.input(0) != &out {
            errors.push(format!("commitment:{}", p.name));
        }
        if !p.disclosure() {
            out = p.input(1).clone();
        }
    }

    // Each disclosure: service scope, proven date and parameters.
    let validity = req.validity.unwrap_or(DEFAULT_VALIDITY) as i64;
    let (scope, subscope) = (scope_hash(Some(&req.domain)), scope_hash(req.scope.as_deref()));
    for p in proofs.iter().filter(|p| p.disclosure()) {
        if p.input(2) != &scope || p.input(3) != &subscope {
            errors.push(format!("scope:{}", p.name));
        }
        let date = i64::try_from(p.input(1)).unwrap_or(i64::MAX);
        if req.today.saturating_sub(date) >= validity {
            errors.push(format!("date_expired:{}", p.name));
        } else if date.saturating_sub(req.today) > FUTURE_TOLERANCE {
            errors.push(format!("date_future:{}", p.name));
        }
        if parameters(p).as_ref() != Some(p.input(4)) {
            errors.push(format!("parameters:{}", p.name));
        }
    }

    // One identifier for the whole bundle.
    let disclosures: Vec<&Proof> = proofs.iter().filter(|p| p.disclosure()).collect();
    let nullifiers = distinct(disclosures.iter().map(|p| p.tail(2).clone()), &big(0));
    let types = distinct(disclosures.iter().map(|p| nullifier_type(p.tail(3))), &"NONE");
    let oprf = distinct(disclosures.iter().map(|p| p.tail(1).clone()), &big(0));
    if nullifiers.len() > 1 || types.len() > 1 || oprf.len() > 1 {
        errors.push("nullifier_mismatch".into());
    }
    let id_type = types.first().copied().unwrap_or("NONE");
    let mut identifier = nullifiers.first().map(|n| n.to_str_radix(10));
    match id_type {
        "INVALID" => errors.push("nullifier_type".into()),
        "NON_SALTED_MOCK" | "SALTED_MOCK" if !req.dev_mode => errors.push("mock".into()),
        "NONE" => {
            if identifier.is_some() {
                errors.push("nullifier_type".into());
            }
            identifier = None;
        }
        _ => {}
    }
    let accepted = req.oprf_public_key_hash.as_deref().and_then(field);
    if id_type.starts_with("SALTED") && (accepted.is_none() || accepted.as_ref() != oprf.first()) {
        errors.push("oprf_key".into());
    }

    check_query(&req.query, proofs, &mut errors);

    // Keys: each must be the one the (registry-checked) manifest lists for that circuit.
    let mut keys = Vec::new();
    for p in proofs {
        let listed = req.manifest.get("circuits").and_then(|c| c.get(&p.name)).and_then(|c| c.get("hash")).and_then(Value::as_str).and_then(field);
        let vkey = req.vkeys.get(&p.name).and_then(|v| base64::engine::general_purpose::STANDARD.decode(v).ok());
        let claimed_ok = p.vkey_hash.as_deref().is_none_or(|h| field(h) == listed);
        match (vkey, listed) {
            (Some(k), Some(l)) if vkey_hash(&k) == l && claimed_ok => keys.push(k),
            _ => errors.push(format!("vkey:{}", p.name)),
        }
    }

    if errors.is_empty() {
        for (p, k) in proofs.iter().zip(&keys) {
            if let Err(e) = bb(k, &p.body, &p.public_bytes) {
                errors.push(format!("proof:{}:{e}", p.name));
                break;
            }
        }
    }

    let committed = |name: &str| proofs.iter().find(|p| p.name == name).map(|p| p.committed.clone());
    let mut conditions = Map::new();
    for name in DISCLOSURES.iter().skip(1) {
        if let Some(c) = committed(name) {
            conditions.insert((*name).into(), c);
        }
    }
    json!({
        "verified": errors.is_empty(),
        "errors": errors,
        "version": bundle.version,
        "names": proofs.iter().map(|p| p.name.clone()).collect::<Vec<_>>(),
        "date": bundle.date,
        "uniqueIdentifier": if errors.is_empty() { identifier.map(Value::from).unwrap_or(Value::Null) } else { Value::Null },
        "uniqueIdentifierType": id_type,
        "disclosed": committed("disclose_bytes").and_then(|c| Disclosed::new(&c)).map(|d| d.values()).unwrap_or(Value::Null),
        "conditions": Value::Object(conditions),
        "certificateRoot": hex32(proofs[0].input(0)),
        "circuitRoot": req.circuit_root,
        "devMode": req.dev_mode,
    })
}

// ---- JSON entry points for the FFI ------------------------------------------------------------------------

/// [inspect] over the JSON array of the holder's `proof` messages.
pub fn inspect_json(proofs: &str) -> Result<String, String> {
    let proofs: Vec<ProofResult> = serde_json::from_str(proofs).map_err(|_| "json".to_string())?;
    inspect(&proofs).map(|v| v.to_string())
}

/// [circuit_root] over a manifest's JSON.
pub fn circuit_root_json(manifest: &str) -> Result<String, String> {
    circuit_root(&serde_json::from_str(manifest).map_err(|_| "json".to_string())?)
}

/// [verify] over a [Request]'s JSON; the result is JSON as well.
pub fn verify_json(request: &str, bb: impl FnMut(&[u8], &[u8], &[u8]) -> Result<(), String>) -> Result<String, String> {
    let request: Request = serde_json::from_str(request).map_err(|_| "json".to_string())?;
    Ok(verify(&request, bb).to_string())
}

#[cfg(test)]
mod tests;
