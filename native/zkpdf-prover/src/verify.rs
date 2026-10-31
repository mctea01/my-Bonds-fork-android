//! Reconstruct verifier-owned fields and enforce every frozen composition join.
use crate::{
    field::{self, F},
    prepare, public, Error, Result, *,
};
use acvm::AcirField;
use serde_json::{json, Value};
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error("public_mismatch"))
    }
}
fn bounded(f: F, maximum: u128) -> Result<u128> {
    let bytes = f.to_be_bytes();
    require(bytes[..16].iter().all(|x| *x == 0))?;
    let value = f.to_u128();
    require(value <= maximum)?;
    Ok(value)
}
fn base(circuit: &str) -> Value {
    json!({"domain":field::json(field::ascii("diw-zkpdf-v1")),"circuit":field::json(field::ascii(circuit))})
}
fn compare(segment: &ZkPdfSegmentProof, kind: &str, index: u32, expected: &Value) -> Result<()> {
    require(segment.kind == kind && segment.index == index)?;
    require(segment.public_inputs == public::encode(kind, expected)?)
}
/// This validates transport and policy only. Callers must additionally verify
/// every proof against the pinned key before returning the result.
pub fn policy(spec: &ZkPdfVerifierSpec, bundle: &ZkPdfBundle) -> Result<ZkPdfVerified> {
    let (p, _, _, _) = prepare::parameters(&spec.composition)?;
    require(bundle.composition == spec.composition && spec.binding.len() == 32)?;
    require(
        !spec.windows.is_empty()
            && spec.windows.len() <= 2
            && spec.windows.iter().filter(|x| x.role == "content").count() == 1,
    )?;
    require(bundle.segments.len() <= 45)?;
    let pred = (!spec.predicates.is_empty()) as usize;
    let paired = bundle
        .segments
        .len()
        .checked_sub(spec.windows.len() + 1 + pred)
        .ok_or(Error("segment_count"))?;
    require(paired >= 2 && paired % 2 == 0)?;
    let k = paired / 2;
    require(k <= 40960 / p)?;
    for segment in &bundle.segments {
        require(segment.proof.len() == 16256)?;
        // Reject encodings that a field parser could otherwise reduce modulo p.
        public::decode(&segment.proof, 508)?;
    }
    let anchor_inputs: Vec<_> = spec
        .anchors
        .iter()
        .map(|a| ZkPdfAnchorInput {
            record: a.record.clone(),
        })
        .collect();
    let mut anchors = prepare::anchors(&anchor_inputs)?;
    for (i, a) in spec.anchors.iter().enumerate() {
        require(a.ordinal > 0 && a.ordinal <= a.total && a.total <= 512)?;
        anchors[i]["ordinal"] = json!(a.ordinal);
        anchors[i]["total"] = json!(a.total);
    }
    let slots = prepare::slot_values(&spec.slots, spec.anchors.len())?;
    let fonts = prepare::fonts(&spec.digit_tables)?;
    let predicates = prepare::predicates(&spec.predicates, &slots)?;
    let mut cz = field::number(0);
    let mut mid_outs = Vec::new();
    for (i, window) in spec.windows.iter().enumerate() {
        let content = window.role == "content";
        let kind = if content { "sha_content" } else { "sha_opaque" };
        let segment = &bundle.segments[i];
        let fields = public::decode(&segment.public_inputs, if content { 294 } else { 27 })?;
        let mut mid_out = Vec::new();
        for f in &fields[10..18] {
            mid_out.extend((bounded(*f, u32::MAX as u128)? as u32).to_be_bytes());
        }
        if content {
            cz = fields[293];
        }
        let expected = prepare::sha_public(
            window,
            &mid_out,
            if content {
                fields[293]
            } else {
                field::number(0)
            },
        )?;
        compare(segment, kind, i as u32, &expected)?;
        mid_outs.push(mid_out);
    }
    let mut position = spec.windows.len();
    let mut state = field::number(0);
    let mut cps = Vec::new();
    let w = 32768 / p;
    for i in 0..k {
        let kind = if i == 0 { "inflate0" } else { "inflate" };
        let segment = &bundle.segments[position];
        position += 1;
        let fields = public::decode(&segment.public_inputs, if i == 0 { 9 } else { 9 + w })?;
        let mut expected = base(if i == 0 {
            "pdf_inflate_seg0_v1"
        } else {
            "pdf_inflate_seg_v1"
        });
        expected["index"] = json!(i);
        expected["first"] = json!(i == 0);
        expected["last"] = json!(i + 1 == k);
        expected["cz"] = field::json(cz);
        expected["sin"] = field::json(state);
        expected["sout"] = field::json(fields[7]);
        expected["cp"] = field::json(fields[8]);
        if i > 0 {
            expected["previous"] = json!((0..w)
                .map(|j| field::json(if i + j < w {
                    field::number(0)
                } else {
                    cps[i + j - w]
                }))
                .collect::<Vec<_>>());
        }
        compare(segment, kind, i as u32, &expected)?;
        state = fields[7];
        cps.push(fields[8]);
    }
    let mut state = field::number(0);
    let mut cg = field::number(0);
    for (i, cp) in cps.iter().enumerate() {
        let segment = &bundle.segments[position];
        position += 1;
        let fields = public::decode(&segment.public_inputs, 1646)?;
        let mut expected = base("pdf_lex_seg_v1");
        let last = i + 1 == k;
        let mut segment_anchors = anchors.clone();
        if !last {
            for a in &mut segment_anchors {
                a["ordinal"] = json!(0);
                a["total"] = json!(0);
            }
        } else {
            cg = fields[1645];
        }
        expected["index"] = json!(i);
        expected["first"] = json!(i == 0);
        expected["last"] = json!(last);
        expected["cz"] = field::json(cz);
        expected["lin"] = field::json(state);
        expected["lout"] = field::json(fields[7]);
        expected["cp"] = json!([field::json(*cp)]);
        expected["anchors"] = json!(segment_anchors);
        expected["slots"] = json!(slots);
        expected["cg"] = field::json(if last { cg } else { field::number(0) });
        compare(segment, "lex", i as u32, &expected)?;
        state = fields[7];
    }
    let segment = &bundle.segments[position];
    position += 1;
    let fields = public::decode(&segment.public_inputs, 2058)?;
    let mut digests = Vec::new();
    for (c, slot) in slots.iter().enumerate() {
        let digest = fields[1674 + c * 32..1674 + (c + 1) * 32]
            .iter()
            .map(|f| bounded(*f, 255).map(|b| b as u8))
            .collect::<Result<Vec<_>>>()?;
        if slot["enabled"] == false {
            require(digest.iter().all(|b| *b == 0))?;
        }
        digests.push(digest);
    }
    let mut expected = base("pdf_claim_v1");
    expected["beta"] = json!(spec.binding);
    expected["start"] = json!(0);
    expected["count"] = json!(12);
    expected["cz"] = field::json(cz);
    expected["anchors"] = json!(anchors);
    expected["slots"] = json!(slots);
    expected["cg"] = field::json(cg);
    expected["digests"] = json!(digests);
    compare(segment, "claim", 0, &expected)?;
    if pred != 0 {
        let segment = &bundle.segments[position];
        position += 1;
        public::decode(&segment.public_inputs, 1798)?;
        expected["circuit"] = field::json(field::ascii("pdf_pred_v1"));
        expected["fonts"] = json!(fonts);
        expected["predicates"] = json!(predicates);
        compare(segment, "pred", 0, &expected)?;
    }
    require(position == bundle.segments.len())?;
    Ok(ZkPdfVerified {
        mid_outs,
        claim_digests: digests,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (ZkPdfVerifierSpec, ZkPdfBundle) {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../test-servers/src/test/resources/zkpdf/student.json"
        ))
        .unwrap();
        let input = serde_json::from_value(fixture["input"].clone()).unwrap();
        let prepared = prepare::prepare(&input, field::number(42)).unwrap();
        let bundle = ZkPdfBundle {
            composition: input.composition,
            segments: prepared
                .stages
                .into_iter()
                .map(|(kind, index, values)| {
                    ZkPdfSegmentProof {
                        public_inputs: public::encode(&kind, &values).unwrap(),
                        kind,
                        index,
                        // Deliberately invalid proofs: these tests exercise policy
                        // reconstruction only, never cryptographic acceptance.
                        proof: vec![0; 16256],
                    }
                })
                .collect(),
        };
        (
            serde_json::from_value(fixture["spec"].clone()).unwrap(),
            bundle,
        )
    }
    #[test]
    fn policy_reconstructs_and_rejects_changed_spec_and_joins() {
        let (spec, bundle) = fixture();
        assert!(policy(&spec, &bundle).is_ok());
        let mut changed = spec.clone();
        changed.anchors[0].ordinal = 2;
        assert!(policy(&changed, &bundle).is_err());
        let mut changed = spec.clone();
        changed.binding[0] ^= 1;
        assert!(policy(&changed, &bundle).is_err());
        let mut changed = spec.clone();
        changed.predicates[0].cutoff -= 1;
        assert!(policy(&changed, &bundle).is_err());
        let mut changed = bundle.clone();
        changed.segments.swap(0, 1);
        assert!(policy(&spec, &changed).is_err());
        let mut changed = bundle.clone();
        changed.segments.remove(2);
        assert!(policy(&spec, &changed).is_err());
        let mut changed = bundle.clone();
        changed.segments[3].public_inputs[8 * 32 + 31] ^= 1;
        assert!(policy(&spec, &changed).is_err());
        let mut changed = bundle.clone();
        changed.segments[0].public_inputs[31] ^= 1;
        assert!(policy(&spec, &changed).is_err());
        let mut changed = bundle.clone();
        changed.composition = "zkpdf-v1-desktop".into();
        assert!(policy(&spec, &changed).is_err());
        let mut changed = bundle;
        changed.segments[0].proof[0] = 255;
        assert!(policy(&spec, &changed).is_err());
    }
}
