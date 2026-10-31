//! WP3b transport records. Private records intentionally do not implement Debug.
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkPdfWindowInput {
    pub role: String,
    pub mid_in: Vec<u8>,
    pub head: Vec<u8>,
    pub private_data: Vec<u8>,
    pub tail: Vec<u8>,
    pub key_stream: Option<Vec<u8>>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkPdfRecord {
    pub font: Vec<u8>,
    pub kind: u8,
    pub strings: Vec<Vec<u8>>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkPdfAnchorInput {
    pub record: ZkPdfRecord,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkPdfSlotInput {
    pub slot: u32,
    pub before_anchor: u32,
    pub after_anchor: u32,
    pub salt: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkPdfDigitTable {
    pub font: Vec<u8>,
    pub width: u8,
    pub codes: Vec<u32>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkPdfPredicateInput {
    pub kind: u8,
    pub slot: u32,
    pub format: u8,
    pub cutoff: u32,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkPdfProveInput {
    pub composition: String,
    pub binding: Vec<u8>,
    pub windows: Vec<ZkPdfWindowInput>,
    pub anchors: Vec<ZkPdfAnchorInput>,
    pub slots: Vec<ZkPdfSlotInput>,
    pub digit_tables: Vec<ZkPdfDigitTable>,
    pub predicates: Vec<ZkPdfPredicateInput>,
    pub assets_dir: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkPdfSegmentProof {
    pub kind: String,
    pub index: u32,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkPdfBundle {
    pub composition: String,
    pub segments: Vec<ZkPdfSegmentProof>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkPdfProveOutput {
    pub bundle: ZkPdfBundle,
    pub mid_outs: Vec<Vec<u8>>,
    pub anchor_ordinals: Vec<u32>,
    pub anchor_totals: Vec<u32>,
    pub claim_records: Vec<Vec<u8>>,
    pub claim_digests: Vec<Vec<u8>>,
    pub prove_ms: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkPdfWindowPublic {
    pub role: String,
    pub mid_in: Vec<u8>,
    pub blocks: u32,
    pub head: Vec<u8>,
    pub tail: Vec<u8>,
    pub key_stream: Option<Vec<u8>>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkPdfAnchorPublic {
    pub record: ZkPdfRecord,
    pub ordinal: u32,
    pub total: u32,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkPdfSlotPublic {
    pub slot: u32,
    pub before_anchor: u32,
    pub after_anchor: u32,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkPdfVerifierSpec {
    pub composition: String,
    pub binding: Vec<u8>,
    pub windows: Vec<ZkPdfWindowPublic>,
    pub anchors: Vec<ZkPdfAnchorPublic>,
    pub slots: Vec<ZkPdfSlotPublic>,
    pub digit_tables: Vec<ZkPdfDigitTable>,
    pub predicates: Vec<ZkPdfPredicateInput>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ZkPdfVerified {
    pub mid_outs: Vec<Vec<u8>>,
    pub claim_digests: Vec<Vec<u8>>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ZkPdfPlan {
    pub composition: String,
    pub total_segments: u32,
    pub sha_segments: u32,
    pub inflate_segments: u32,
    pub lex_segments: u32,
    pub claim_segments: u32,
    pub predicate_segments: u32,
    pub estimated_proof_bytes: u64,
    pub public_input_bytes: u64,
}
