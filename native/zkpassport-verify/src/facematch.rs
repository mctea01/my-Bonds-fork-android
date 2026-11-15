//! FaceMatch proofs. zkPassport's own prove that its attested app signed the statement (mode, photo hash); this
//! project's alternatives (native/circuits-zkpassport) prove the same statement signed under an Android key
//! attestation without Play Integrity, or carry it as the wallet's own unattested claim. All share one public
//! interface and one commitment formula; what the committed values mean and who vouches for them differs, so
//! [check] reports the `kind` and a verifier accepts only the kinds its policy lists.

use crate::zk::{hash_packed, poseidon2_hash};
use crate::{big, field, hex32};
use num_bigint::BigUint;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::OnceLock;

/// The key under which a FaceMatch proof's committed inputs travel, whatever the circuit's name.
pub(crate) const COMMITTED_KEY: &str = "facematch";
const SELF: &str = "diw_facematch_self";
const KEY_ATTESTATION: &str = "diw_facematch_keyattest_";
const PROOF_TYPE: u64 = 10;

// zkPassport SDK constants (zkpassport-sdk/src/constants.ts, zkpassport-utils/src/circuits/facematch.ts): the
// registry leaves of the attestation roots, the hashes of the official app ids and of Play Integrity's key.
const APPLE_ROOT: &str = "0x2532418a107c5306fa8308c22255792cf77e4a290cbce8a840a642a3e591340b";
const GOOGLE_RSA_ROOT: &str = "0x16700a2d9168a194fc85f237af5829b5a2be05b8ae8ac4879ada34cf54a9c211";
const GOOGLE_P384_ROOT: &str = "0x0e1889bec6c1d686abcf08360ff404f803ab345881ea8cba6aad33b7f7f7ffe0";
const OFFICIAL_IOS_APP: &str = "0x1fa73686cf510f8f85757b0602de0dd72a13e68ae2092462be8b72662e7f179b";
const OFFICIAL_ANDROID_APP: &str = "0x24d9929b248be7eeecaa98e105c034a50539610f3fdd4cb9c8983ef4100d615d";
const PLAY_INTEGRITY_KEY: &str = "8544227306600425492560068004835614964118871262589609739238120993689090208159";

#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum Kind {
    /// zkPassport's circuits: App Attest or key attestation with Play Integrity, of the official app.
    Official,
    /// This project's key attestation circuits: a hardware key of a named app, without Play Integrity.
    KeyAttestation,
    /// This project's self-declared circuit: nothing attests the app or the device.
    SelfDeclared,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Official => "official",
            Kind::KeyAttestation => "keyattest",
            Kind::SelfDeclared => "self",
        }
    }
}

pub(crate) fn kind(name: &str) -> Option<Kind> {
    if name == SELF {
        Some(Kind::SelfDeclared)
    } else if name.starts_with(KEY_ATTESTATION) {
        Some(Kind::KeyAttestation)
    } else if name.starts_with("facematch") && !name.ends_with("_evm") {
        Some(Kind::Official)
    } else {
        None
    }
}

/// The verification key hashes of this project's FaceMatch circuits, as built from native/circuits-zkpassport:
/// `{"version": 1, "circuits": {name: hash}}`. They are not in zkPassport's manifest, so this list pins them.
pub fn diw_circuits_json() -> &'static str {
    include_str!("../../circuits-zkpassport/circuits.json")
}

pub(crate) fn diw_hash(name: &str) -> Option<BigUint> {
    static CIRCUITS: OnceLock<Value> = OnceLock::new();
    let circuits = CIRCUITS.get_or_init(|| serde_json::from_str(diw_circuits_json()).unwrap_or(Value::Null));
    circuits.get("circuits")?.get(name)?.as_str().and_then(field)
}

/// An app a verifier trusts to have made the comparison: its package name and the SHA-256 digests (hex) of the
/// certificates that may sign it.
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FaceMatchApp {
    pub app_id: String,
    #[serde(default)]
    pub signers: Vec<String>,
}

/// What a verifier accepts as FaceMatch. Without a policy only zkPassport's own proofs are accepted.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct FaceMatchPolicy {
    /// Accepted kinds: `official`, `keyattest`, `self`.
    pub accept: Vec<String>,
    /// The apps accepted for `keyattest`; a proof of any other app is refused.
    pub apps: Vec<FaceMatchApp>,
    /// Accept a locked device whose system is signed with the owner's key (no Google-verified boot).
    pub allow_self_signed: bool,
    /// Attestation roots (registry leaves) accepted besides Google's, for test devices.
    pub roots: Vec<String>,
}

fn commitment(root: &BigUint, environment: u64, app: &BigUint, fourth: &BigUint, mode: u64) -> BigUint {
    poseidon2_hash(&[big(PROOF_TYPE), big(5), root.clone(), big(environment), app.clone(), fourth.clone(), big(mode)])
}

fn among(value: Option<&BigUint>, list: &[&str]) -> bool {
    value.is_some_and(|v| list.iter().any(|l| field(l).as_ref() == Some(v)))
}

/// What a FaceMatch proof's committed inputs say, in the forms the commitment and the policy take them.
struct Stated<'a> {
    mode: Option<u64>,
    environment: Option<u64>,
    root: Option<BigUint>,
    app_id: Option<&'a str>,
    app: Option<BigUint>,
    signer: Option<Vec<u8>>,
    fourth: Option<BigUint>,
}

impl<'a> Stated<'a> {
    fn read(kind: Kind, committed: &'a Value) -> Self {
        let text = |key: &str| committed.get(key).and_then(Value::as_str);
        let mode = match text("mode") {
            Some("regular") => Some(1),
            Some("strict") => Some(2),
            _ => None,
        };
        let environment = match (kind, text("environment")) {
            (Kind::SelfDeclared, _) => Some(0),
            (_, Some("development")) => Some(0),
            (_, Some("production")) => Some(1),
            (Kind::KeyAttestation, Some("self_signed")) => Some(2),
            _ => None,
        };
        let root = match kind {
            Kind::SelfDeclared => Some(big(0)),
            _ => text("rootKeyLeaf").and_then(field),
        };
        let app_id = text("appId").filter(|a| !a.is_empty() && a.len() <= 100);
        let app = match kind {
            Kind::Official => text("appIdHash").and_then(field),
            _ => app_id.map(|a| hash_packed(a.as_bytes())),
        };
        let signer = text("signerDigest").and_then(|d| hex::decode(d).ok()).filter(|d| d.len() == 32);
        let fourth = match kind {
            // As the SDK does: Android proofs of the official app commit to Play Integrity's key.
            Kind::Official if among(app.as_ref(), &[OFFICIAL_ANDROID_APP]) => PLAY_INTEGRITY_KEY.parse().ok(),
            Kind::KeyAttestation => signer.as_deref().map(hash_packed),
            _ => Some(big(0)),
        };
        Stated { mode, environment, root, app_id, app, signer, fourth }
    }

    fn commitment(&self) -> Option<BigUint> {
        match (&self.root, self.environment, &self.app, &self.fourth, self.mode) {
            (Some(r), Some(e), Some(a), Some(f), Some(m)) => Some(commitment(r, e, a, f, m)),
            _ => None,
        }
    }
}

/// The parameter commitment a proof of circuit `name` must return for [check] to accept these committed inputs
/// (0x and 64 hex digits), or None when they are incomplete: what a holder compares its own proof with.
pub fn expected_commitment(name: &str, committed: &Value) -> Option<String> {
    Stated::read(kind(name)?, committed).commitment().map(|c| hex32(&c))
}

/// Checks a FaceMatch proof's committed inputs against its parameter commitment and the verifier's policy,
/// adding error codes, and returns what the proof states. `committed` is the proof's `facematch` object:
/// `mode`, `environment`, and for zkPassport's circuits `rootKeyLeaf` and `appIdHash`; this project's circuits
/// carry the app id itself (`appId`), and the key attestation ones `rootKeyLeaf` and `signerDigest`.
pub(crate) fn check(
    name: &str,
    kind: Kind,
    committed: &Value,
    proven: &BigUint,
    policy: Option<&FaceMatchPolicy>,
    dev_mode: bool,
    errors: &mut Vec<String>,
) -> Value {
    let text = |key: &str| committed.get(key).and_then(Value::as_str);
    let Stated { environment, root, app_id, app, signer, .. } = Stated::read(kind, committed);
    if Stated::read(kind, committed).commitment().as_ref() != Some(proven) {
        errors.push(format!("parameters:{name}"));
    }

    let fallback = FaceMatchPolicy { accept: vec![Kind::Official.label().into()], ..Default::default() };
    let policy = policy.unwrap_or(&fallback);
    if !policy.accept.iter().any(|a| a == kind.label()) {
        errors.push(format!("facematch_level:{}", kind.label()));
    }
    match kind {
        Kind::Official => {
            if !among(root.as_ref(), &[APPLE_ROOT, GOOGLE_RSA_ROOT, GOOGLE_P384_ROOT]) {
                errors.push("facematch_root".into());
            }
            if !among(app.as_ref(), &[OFFICIAL_IOS_APP, OFFICIAL_ANDROID_APP]) {
                errors.push("facematch_app".into());
            }
            if environment != Some(1) && !dev_mode {
                errors.push("facematch_environment".into());
            }
        }
        Kind::KeyAttestation => {
            let extra: Vec<&str> = policy.roots.iter().map(String::as_str).collect();
            if !among(root.as_ref(), &[GOOGLE_RSA_ROOT, GOOGLE_P384_ROOT]) && !among(root.as_ref(), &extra) {
                errors.push("facematch_root".into());
            }
            let trusted = policy.apps.iter().any(|a| {
                Some(a.app_id.as_str()) == app_id
                    && a.signers.iter().any(|s| hex::decode(s).ok().as_deref() == signer.as_deref() && signer.is_some())
            });
            if !trusted {
                errors.push("facematch_app".into());
            }
            let accepted = match environment {
                Some(1) => true,
                Some(2) => policy.allow_self_signed,
                _ => dev_mode,
            };
            if !accepted {
                errors.push("facematch_environment".into());
            }
        }
        Kind::SelfDeclared => {}
    }

    let mut report = json!({
        "kind": kind.label(),
        "circuit": name,
        "mode": text("mode"),
        "environment": match environment {
            Some(1) => "production",
            Some(2) => "self_signed",
            _ => "development",
        },
    });
    if let Some(a) = &app {
        report["appIdHash"] = json!(hex32(a));
    }
    match kind {
        Kind::Official => {
            let platform = if among(root.as_ref(), &[APPLE_ROOT]) { "ios" } else { "android" };
            report["platform"] = json!(platform);
        }
        _ => {
            report["appId"] = json!(app_id);
            if kind == Kind::KeyAttestation {
                report["signerDigest"] = json!(signer.map(hex::encode));
            }
        }
    }
    if let (Some(r), true) = (&root, kind != Kind::SelfDeclared) {
        report["rootKeyLeaf"] = json!(hex32(r));
    }
    report
}

/// `mode` a query asks FaceMatch for, when it asks.
pub(crate) fn asked_mode(query: &Value) -> Option<&str> {
    query.get(COMMITTED_KEY)?.get("mode")?.as_str()
}
