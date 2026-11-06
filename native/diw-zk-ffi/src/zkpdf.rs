//! WP3b exports. All work containing private data runs on the protected worker.
use crate::{run_worker, ZkCancelToken, ZkError};
use std::sync::Arc;

#[derive(uniffi::Record)]
pub struct ZkPdfWindowInput {
    pub role: String,
    pub mid_in: Vec<u8>,
    pub head: Vec<u8>,
    pub private_data: Vec<u8>,
    pub tail: Vec<u8>,
    pub key_stream: Option<Vec<u8>>,
}

#[cfg(feature = "zkpdf")]
impl From<ZkPdfWindowInput> for zkpdf_prover::ZkPdfWindowInput {
    fn from(value: ZkPdfWindowInput) -> Self {
        Self {
            role: value.role,
            mid_in: value.mid_in,
            head: value.head,
            private_data: value.private_data,
            tail: value.tail,
            key_stream: value.key_stream,
        }
    }
}

#[cfg(feature = "zkpdf")]
impl From<zkpdf_prover::ZkPdfWindowInput> for ZkPdfWindowInput {
    fn from(value: zkpdf_prover::ZkPdfWindowInput) -> Self {
        Self {
            role: value.role,
            mid_in: value.mid_in,
            head: value.head,
            private_data: value.private_data,
            tail: value.tail,
            key_stream: value.key_stream,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ZkPdfRecord {
    pub font: Vec<u8>,
    pub kind: u8,
    pub strings: Vec<Vec<u8>>,
}

#[cfg(feature = "zkpdf")]
impl From<ZkPdfRecord> for zkpdf_prover::ZkPdfRecord {
    fn from(value: ZkPdfRecord) -> Self {
        Self {
            font: value.font,
            kind: value.kind,
            strings: value.strings,
        }
    }
}

#[cfg(feature = "zkpdf")]
impl From<zkpdf_prover::ZkPdfRecord> for ZkPdfRecord {
    fn from(value: zkpdf_prover::ZkPdfRecord) -> Self {
        Self {
            font: value.font,
            kind: value.kind,
            strings: value.strings,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ZkPdfAnchorInput {
    pub record: ZkPdfRecord,
    pub ordinal: u32,
}

#[cfg(feature = "zkpdf")]
impl From<ZkPdfAnchorInput> for zkpdf_prover::ZkPdfAnchorInput {
    fn from(value: ZkPdfAnchorInput) -> Self {
        Self {
            record: value.record.into(),
            ordinal: value.ordinal,
        }
    }
}

#[cfg(feature = "zkpdf")]
impl From<zkpdf_prover::ZkPdfAnchorInput> for ZkPdfAnchorInput {
    fn from(value: zkpdf_prover::ZkPdfAnchorInput) -> Self {
        Self {
            record: value.record.into(),
            ordinal: value.ordinal,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ZkPdfSlotInput {
    pub slot: u32,
    pub before_anchor: u32,
    pub after_anchor: u32,
    pub salt: Vec<u8>,
}

#[cfg(feature = "zkpdf")]
impl From<ZkPdfSlotInput> for zkpdf_prover::ZkPdfSlotInput {
    fn from(value: ZkPdfSlotInput) -> Self {
        Self {
            slot: value.slot,
            before_anchor: value.before_anchor,
            after_anchor: value.after_anchor,
            salt: value.salt,
        }
    }
}

#[cfg(feature = "zkpdf")]
impl From<zkpdf_prover::ZkPdfSlotInput> for ZkPdfSlotInput {
    fn from(value: zkpdf_prover::ZkPdfSlotInput) -> Self {
        Self {
            slot: value.slot,
            before_anchor: value.before_anchor,
            after_anchor: value.after_anchor,
            salt: value.salt,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ZkPdfDigitTable {
    pub font: Vec<u8>,
    pub width: u8,
    pub codes: Vec<u32>,
}

#[cfg(feature = "zkpdf")]
impl From<ZkPdfDigitTable> for zkpdf_prover::ZkPdfDigitTable {
    fn from(value: ZkPdfDigitTable) -> Self {
        Self {
            font: value.font,
            width: value.width,
            codes: value.codes,
        }
    }
}

#[cfg(feature = "zkpdf")]
impl From<zkpdf_prover::ZkPdfDigitTable> for ZkPdfDigitTable {
    fn from(value: zkpdf_prover::ZkPdfDigitTable) -> Self {
        Self {
            font: value.font,
            width: value.width,
            codes: value.codes,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ZkPdfPredicateInput {
    pub kind: u8,
    pub slot: u32,
    pub format: u8,
    pub cutoff: u32,
}

#[cfg(feature = "zkpdf")]
impl From<ZkPdfPredicateInput> for zkpdf_prover::ZkPdfPredicateInput {
    fn from(value: ZkPdfPredicateInput) -> Self {
        Self {
            kind: value.kind,
            slot: value.slot,
            format: value.format,
            cutoff: value.cutoff,
        }
    }
}

#[cfg(feature = "zkpdf")]
impl From<zkpdf_prover::ZkPdfPredicateInput> for ZkPdfPredicateInput {
    fn from(value: zkpdf_prover::ZkPdfPredicateInput) -> Self {
        Self {
            kind: value.kind,
            slot: value.slot,
            format: value.format,
            cutoff: value.cutoff,
        }
    }
}

#[derive(uniffi::Record)]
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

#[cfg(feature = "zkpdf")]
impl From<ZkPdfProveInput> for zkpdf_prover::ZkPdfProveInput {
    fn from(value: ZkPdfProveInput) -> Self {
        Self {
            composition: value.composition,
            binding: value.binding,
            windows: value.windows.into_iter().map(Into::into).collect(),
            anchors: value.anchors.into_iter().map(Into::into).collect(),
            slots: value.slots.into_iter().map(Into::into).collect(),
            digit_tables: value.digit_tables.into_iter().map(Into::into).collect(),
            predicates: value.predicates.into_iter().map(Into::into).collect(),
            assets_dir: value.assets_dir,
        }
    }
}

#[cfg(feature = "zkpdf")]
impl From<zkpdf_prover::ZkPdfProveInput> for ZkPdfProveInput {
    fn from(value: zkpdf_prover::ZkPdfProveInput) -> Self {
        Self {
            composition: value.composition,
            binding: value.binding,
            windows: value.windows.into_iter().map(Into::into).collect(),
            anchors: value.anchors.into_iter().map(Into::into).collect(),
            slots: value.slots.into_iter().map(Into::into).collect(),
            digit_tables: value.digit_tables.into_iter().map(Into::into).collect(),
            predicates: value.predicates.into_iter().map(Into::into).collect(),
            assets_dir: value.assets_dir,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ZkPdfSegmentProof {
    pub kind: String,
    pub index: u32,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
}

#[cfg(feature = "zkpdf")]
impl From<ZkPdfSegmentProof> for zkpdf_prover::ZkPdfSegmentProof {
    fn from(value: ZkPdfSegmentProof) -> Self {
        Self {
            kind: value.kind,
            index: value.index,
            proof: value.proof,
            public_inputs: value.public_inputs,
        }
    }
}

#[cfg(feature = "zkpdf")]
impl From<zkpdf_prover::ZkPdfSegmentProof> for ZkPdfSegmentProof {
    fn from(value: zkpdf_prover::ZkPdfSegmentProof) -> Self {
        Self {
            kind: value.kind,
            index: value.index,
            proof: value.proof,
            public_inputs: value.public_inputs,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ZkPdfBundle {
    pub composition: String,
    pub segments: Vec<ZkPdfSegmentProof>,
}

#[cfg(feature = "zkpdf")]
impl From<ZkPdfBundle> for zkpdf_prover::ZkPdfBundle {
    fn from(value: ZkPdfBundle) -> Self {
        Self {
            composition: value.composition,
            segments: value.segments.into_iter().map(Into::into).collect(),
        }
    }
}

#[cfg(feature = "zkpdf")]
impl From<zkpdf_prover::ZkPdfBundle> for ZkPdfBundle {
    fn from(value: zkpdf_prover::ZkPdfBundle) -> Self {
        Self {
            composition: value.composition,
            segments: value.segments.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(uniffi::Record)]
pub struct ZkPdfProveOutput {
    pub bundle: ZkPdfBundle,
    pub mid_outs: Vec<Vec<u8>>,
    pub anchor_ordinals: Vec<u32>,
    pub anchor_totals: Vec<u32>,
    pub claim_records: Vec<Vec<u8>>,
    pub claim_digests: Vec<Vec<u8>>,
    pub prove_ms: u64,
}

#[cfg(feature = "zkpdf")]
impl From<ZkPdfProveOutput> for zkpdf_prover::ZkPdfProveOutput {
    fn from(value: ZkPdfProveOutput) -> Self {
        Self {
            bundle: value.bundle.into(),
            mid_outs: value.mid_outs,
            anchor_ordinals: value.anchor_ordinals,
            anchor_totals: value.anchor_totals,
            claim_records: value.claim_records,
            claim_digests: value.claim_digests,
            prove_ms: value.prove_ms,
        }
    }
}

#[cfg(feature = "zkpdf")]
impl From<zkpdf_prover::ZkPdfProveOutput> for ZkPdfProveOutput {
    fn from(value: zkpdf_prover::ZkPdfProveOutput) -> Self {
        Self {
            bundle: value.bundle.into(),
            mid_outs: value.mid_outs,
            anchor_ordinals: value.anchor_ordinals,
            anchor_totals: value.anchor_totals,
            claim_records: value.claim_records,
            claim_digests: value.claim_digests,
            prove_ms: value.prove_ms,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ZkPdfWindowPublic {
    pub role: String,
    pub mid_in: Vec<u8>,
    pub blocks: u32,
    pub head: Vec<u8>,
    pub tail: Vec<u8>,
    pub key_stream: Option<Vec<u8>>,
}

#[cfg(feature = "zkpdf")]
impl From<ZkPdfWindowPublic> for zkpdf_prover::ZkPdfWindowPublic {
    fn from(value: ZkPdfWindowPublic) -> Self {
        Self {
            role: value.role,
            mid_in: value.mid_in,
            blocks: value.blocks,
            head: value.head,
            tail: value.tail,
            key_stream: value.key_stream,
        }
    }
}

#[cfg(feature = "zkpdf")]
impl From<zkpdf_prover::ZkPdfWindowPublic> for ZkPdfWindowPublic {
    fn from(value: zkpdf_prover::ZkPdfWindowPublic) -> Self {
        Self {
            role: value.role,
            mid_in: value.mid_in,
            blocks: value.blocks,
            head: value.head,
            tail: value.tail,
            key_stream: value.key_stream,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ZkPdfAnchorPublic {
    pub record: ZkPdfRecord,
    pub ordinal: u32,
    pub total: u32,
}

#[cfg(feature = "zkpdf")]
impl From<ZkPdfAnchorPublic> for zkpdf_prover::ZkPdfAnchorPublic {
    fn from(value: ZkPdfAnchorPublic) -> Self {
        Self {
            record: value.record.into(),
            ordinal: value.ordinal,
            total: value.total,
        }
    }
}

#[cfg(feature = "zkpdf")]
impl From<zkpdf_prover::ZkPdfAnchorPublic> for ZkPdfAnchorPublic {
    fn from(value: zkpdf_prover::ZkPdfAnchorPublic) -> Self {
        Self {
            record: value.record.into(),
            ordinal: value.ordinal,
            total: value.total,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ZkPdfSlotPublic {
    pub slot: u32,
    pub before_anchor: u32,
    pub after_anchor: u32,
}

#[cfg(feature = "zkpdf")]
impl From<ZkPdfSlotPublic> for zkpdf_prover::ZkPdfSlotPublic {
    fn from(value: ZkPdfSlotPublic) -> Self {
        Self {
            slot: value.slot,
            before_anchor: value.before_anchor,
            after_anchor: value.after_anchor,
        }
    }
}

#[cfg(feature = "zkpdf")]
impl From<zkpdf_prover::ZkPdfSlotPublic> for ZkPdfSlotPublic {
    fn from(value: zkpdf_prover::ZkPdfSlotPublic) -> Self {
        Self {
            slot: value.slot,
            before_anchor: value.before_anchor,
            after_anchor: value.after_anchor,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ZkPdfVerifierSpec {
    pub composition: String,
    pub binding: Vec<u8>,
    pub windows: Vec<ZkPdfWindowPublic>,
    pub anchors: Vec<ZkPdfAnchorPublic>,
    pub slots: Vec<ZkPdfSlotPublic>,
    pub digit_tables: Vec<ZkPdfDigitTable>,
    pub predicates: Vec<ZkPdfPredicateInput>,
}

#[cfg(feature = "zkpdf")]
impl From<ZkPdfVerifierSpec> for zkpdf_prover::ZkPdfVerifierSpec {
    fn from(value: ZkPdfVerifierSpec) -> Self {
        Self {
            composition: value.composition,
            binding: value.binding,
            windows: value.windows.into_iter().map(Into::into).collect(),
            anchors: value.anchors.into_iter().map(Into::into).collect(),
            slots: value.slots.into_iter().map(Into::into).collect(),
            digit_tables: value.digit_tables.into_iter().map(Into::into).collect(),
            predicates: value.predicates.into_iter().map(Into::into).collect(),
        }
    }
}

#[cfg(feature = "zkpdf")]
impl From<zkpdf_prover::ZkPdfVerifierSpec> for ZkPdfVerifierSpec {
    fn from(value: zkpdf_prover::ZkPdfVerifierSpec) -> Self {
        Self {
            composition: value.composition,
            binding: value.binding,
            windows: value.windows.into_iter().map(Into::into).collect(),
            anchors: value.anchors.into_iter().map(Into::into).collect(),
            slots: value.slots.into_iter().map(Into::into).collect(),
            digit_tables: value.digit_tables.into_iter().map(Into::into).collect(),
            predicates: value.predicates.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(uniffi::Record)]
pub struct ZkPdfVerified {
    pub mid_outs: Vec<Vec<u8>>,
    pub claim_digests: Vec<Vec<u8>>,
}

#[cfg(feature = "zkpdf")]
impl From<ZkPdfVerified> for zkpdf_prover::ZkPdfVerified {
    fn from(value: ZkPdfVerified) -> Self {
        Self {
            mid_outs: value.mid_outs,
            claim_digests: value.claim_digests,
        }
    }
}

#[cfg(feature = "zkpdf")]
impl From<zkpdf_prover::ZkPdfVerified> for ZkPdfVerified {
    fn from(value: zkpdf_prover::ZkPdfVerified) -> Self {
        Self {
            mid_outs: value.mid_outs,
            claim_digests: value.claim_digests,
        }
    }
}

#[derive(uniffi::Record)]
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

#[cfg(feature = "zkpdf")]
impl From<ZkPdfPlan> for zkpdf_prover::ZkPdfPlan {
    fn from(value: ZkPdfPlan) -> Self {
        Self {
            composition: value.composition,
            total_segments: value.total_segments,
            sha_segments: value.sha_segments,
            inflate_segments: value.inflate_segments,
            lex_segments: value.lex_segments,
            claim_segments: value.claim_segments,
            predicate_segments: value.predicate_segments,
            estimated_proof_bytes: value.estimated_proof_bytes,
            public_input_bytes: value.public_input_bytes,
        }
    }
}

#[cfg(feature = "zkpdf")]
impl From<zkpdf_prover::ZkPdfPlan> for ZkPdfPlan {
    fn from(value: zkpdf_prover::ZkPdfPlan) -> Self {
        Self {
            composition: value.composition,
            total_segments: value.total_segments,
            sha_segments: value.sha_segments,
            inflate_segments: value.inflate_segments,
            lex_segments: value.lex_segments,
            claim_segments: value.claim_segments,
            predicate_segments: value.predicate_segments,
            estimated_proof_bytes: value.estimated_proof_bytes,
            public_input_bytes: value.public_input_bytes,
        }
    }
}

#[uniffi::export(callback_interface)]
pub trait ZkProgress: Send + Sync {
    /// One-based position in the complete composition, emitted before the segment.
    fn on_progress(&self, kind: String, index: u32, total: u32);
}
#[cfg(feature = "zkpdf")]
fn error(value: zkpdf_prover::Error) -> ZkError {
    if value.0 == "cancelled" {
        ZkError::Cancelled
    } else {
        ZkError::InvalidInput {
            reason: value.0.into(),
        }
    }
}
#[uniffi::export]
pub fn zkpdf_check(input: ZkPdfProveInput) -> Result<ZkPdfPlan, ZkError> {
    run_worker(64 * 1024 * 1024, ZkCancelToken::new(), move |_| {
        #[cfg(feature = "zkpdf")]
        {
            zkpdf_prover::check(&input.into())
                .map(Into::into)
                .map_err(error)
        }
        #[cfg(not(feature = "zkpdf"))]
        {
            let _ = input;
            Err(ZkError::Unsupported {
                reason: "zkpdf_disabled".into(),
            })
        }
    })
}
#[uniffi::export]
pub fn zkpdf_prove(
    input: ZkPdfProveInput,
    cancel: Arc<ZkCancelToken>,
    progress: Box<dyn ZkProgress>,
) -> Result<ZkPdfProveOutput, ZkError> {
    run_worker(64 * 1024 * 1024, cancel, move |token| {
        #[cfg(feature = "zkpdf")]
        {
            zkpdf_prover::prove(
                &input.into(),
                || token.check().is_err(),
                |kind, index, total| progress.on_progress(kind.into(), index, total),
            )
            .map(Into::into)
            .map_err(error)
        }
        #[cfg(not(feature = "zkpdf"))]
        {
            let _ = (input, token, progress);
            Err(ZkError::Unsupported {
                reason: "zkpdf_disabled".into(),
            })
        }
    })
}
#[uniffi::export]
pub fn zkpdf_verify(
    spec: ZkPdfVerifierSpec,
    bundle: ZkPdfBundle,
    assets_dir: String,
) -> Result<ZkPdfVerified, ZkError> {
    run_worker(64 * 1024 * 1024, ZkCancelToken::new(), move |_| {
        #[cfg(feature = "zkpdf")]
        {
            zkpdf_prover::verify(&spec.into(), &bundle.into(), &assets_dir)
                .map(Into::into)
                .map_err(error)
        }
        #[cfg(not(feature = "zkpdf"))]
        {
            let _ = (spec, bundle, assets_dir);
            Err(ZkError::Unsupported {
                reason: "zkpdf_disabled".into(),
            })
        }
    })
}
