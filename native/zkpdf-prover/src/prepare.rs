//! Deterministic v1 segmentation and ABI advice; PDF parsing stays in Kotlin.
use crate::{
    field::{self, F},
    inflate, lex, Error, Result, *,
};
use acvm::AcirField;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub struct Prepared {
    pub plan: ZkPdfPlan,
    pub stages: Vec<(String, u32, Value)>,
    pub mid_outs: Vec<Vec<u8>>,
    pub ordinals: Vec<u32>,
    pub totals: Vec<u32>,
    pub records: Vec<Vec<u8>>,
    pub digests: Vec<Vec<u8>>,
}
pub fn parameters(composition: &str) -> Result<(usize, usize, usize, usize)> {
    match composition {
        "zkpdf-v1-phone" => Ok((2048, 1024, 352, 64)),
        "zkpdf-v1-desktop" => Ok((4096, 1536, 576, 128)),
        _ => Err(Error("composition")),
    }
}
fn require(ok: bool, code: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error(code))
    }
}
pub fn record_bytes(record: &ZkPdfRecord) -> Result<Vec<u8>> {
    lex::record(&record.font, record.kind, &record.strings)
}
pub fn anchors(input: &[ZkPdfAnchorInput]) -> Result<Vec<Value>> {
    require(input.len() <= 16, "max_anchors")?;
    let mut anchors = Vec::new();
    for a in input {
        let mut bytes = record_bytes(&a.record)?;
        let len = bytes.len();
        require(len <= 96, "max_anchor_length")?;
        bytes.resize(96, 0);
        anchors.push(json!({"enabled":true,"len":len,"raw":bytes,"ordinal":0,"total":0}));
    }
    anchors.resize_with(
        16,
        || json!({"enabled":false,"len":0,"raw":vec![0;96],"ordinal":0,"total":0}),
    );
    Ok(anchors)
}
pub fn slot_values(input: &[ZkPdfSlotPublic], anchor_count: usize) -> Result<Vec<Value>> {
    require(input.len() <= 12, "max_slots")?;
    let mut slots = vec![json!({"enabled":false,"before":0,"after":0}); 12];
    for s in input {
        require(
            s.slot < 12
                && (s.before_anchor as usize) < anchor_count
                && (s.after_anchor as usize) < anchor_count,
            "slot_range",
        )?;
        require(slots[s.slot as usize]["enabled"] == false, "duplicate_slot")?;
        slots[s.slot as usize] =
            json!({"enabled":true,"before":s.before_anchor,"after":s.after_anchor});
    }
    Ok(slots)
}
pub fn fonts(input: &[ZkPdfDigitTable]) -> Result<Vec<Value>> {
    require(input.len() <= 4, "max_digit_fonts")?;
    let mut result = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for f in input {
        require(
            !f.font.is_empty()
                && f.font.len() <= 16
                && [1, 2].contains(&f.width)
                && f.codes.len() == 10,
            "digit_font",
        )?;
        require(
            names.insert(&f.font)
                && f.codes
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == 10,
            "digit_font_duplicate",
        )?;
        require(
            f.codes
                .iter()
                .all(|v| *v < if f.width == 1 { 256 } else { 65536 }),
            "digit_code",
        )?;
        let mut name = f.font.clone();
        name.resize(16, 0);
        result.push(
            json!({"enabled":true,"len":f.font.len(),"name":name,"width":f.width,"digits":f.codes}),
        );
    }
    result.resize_with(
        4,
        || json!({"enabled":false,"len":0,"name":vec![0;16],"width":0,"digits":vec![0;10]}),
    );
    Ok(result)
}
pub fn predicates(input: &[ZkPdfPredicateInput], slots: &[Value]) -> Result<Vec<Value>> {
    require(input.len() <= 2, "max_predicates")?;
    let mut values = Vec::new();
    for p in input {
        require(
            p.kind <= 1
                && p.format == 0
                && p.slot < 12
                && slots[p.slot as usize]["enabled"] == true,
            "predicate",
        )?;
        values.push(
            json!({"enabled":true,"kind":p.kind,"slot":p.slot,"format":p.format,"cutoff":p.cutoff}),
        );
    }
    values.resize_with(
        2,
        || json!({"enabled":false,"kind":0,"slot":0,"format":0,"cutoff":0}),
    );
    Ok(values)
}
pub fn sha_public(window: &ZkPdfWindowPublic, mid_out: &[u8], cz: F) -> Result<Value> {
    let content = window.role == "content";
    require(content || window.role == "opaque", "window_role")?;
    require(
        window.mid_in.len() == 32
            && mid_out.len() == 32
            && window.head.len() < 64
            && window.tail.len() < 64,
        "sha_boundary",
    )?;
    require(
        window.blocks > 0 && window.blocks <= if content { 130 } else { 128 },
        "sha_blocks",
    )?;
    let size = window.blocks as usize * 64;
    require(
        window.head.len() + window.tail.len() < size,
        "window_length",
    )?;
    let length = size - window.head.len() - window.tail.len();
    require(length <= 8192, "compressed_length")?;
    let words = |b: &[u8]| {
        b.chunks_exact(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect::<Vec<_>>()
    };
    let pack = |b: &[u8]| {
        let mut x = b.to_vec();
        x.resize(63, 0);
        field::pack(&x)
            .into_iter()
            .map(field::json)
            .collect::<Vec<_>>()
    };
    let mut value = json!({"domain":field::json(field::ascii("diw-zkpdf-v1")),"circuit":field::json(field::ascii(if content {"pdf_sha_content_v1"}else{"pdf_sha_opaque_v1"})),"mid_in":words(&window.mid_in),"mid_out":words(mid_out),"blocks":window.blocks,"head_len":window.head.len(),"head":pack(&window.head),"tail_len":window.tail.len(),"tail":pack(&window.tail)});
    if content {
        let mut key = if let Some(key) = &window.key_stream {
            require(key.len() == length, "keystream_length")?;
            key.clone()
        } else {
            vec![0; length]
        };
        key.resize(8192, 0);
        value["encrypted"] = json!(window.key_stream.is_some());
        value["keystream"] = json!(field::pack(&key)
            .into_iter()
            .map(field::json)
            .collect::<Vec<_>>());
        value["cz"] = field::json(cz);
    } else {
        require(window.key_stream.is_none(), "opaque_keystream")?;
    }
    Ok(value)
}
pub fn prepare(input: &ZkPdfProveInput, salt: F) -> Result<Prepared> {
    let (p, t0, t, o) = parameters(&input.composition)?;
    require(input.binding.len() == 32, "binding_length")?;
    require(
        !input.windows.is_empty()
            && input.windows.len() <= 2
            && input.windows.iter().filter(|w| w.role == "content").count() == 1,
        "windows",
    )?;
    let mut anchors = anchors(&input.anchors)?;
    let public_slots: Vec<_> = input
        .slots
        .iter()
        .map(|s| ZkPdfSlotPublic {
            slot: s.slot,
            before_anchor: s.before_anchor,
            after_anchor: s.after_anchor,
        })
        .collect();
    let slots = slot_values(&public_slots, input.anchors.len())?;
    let fonts = fonts(&input.digit_tables)?;
    let predicates = predicates(&input.predicates, &slots)?;
    require(
        input.slots.iter().all(|s| s.salt.len() == 16),
        "claim_salt_length",
    )?;
    let content = input
        .windows
        .iter()
        .find(|w| w.role == "content")
        .ok_or(Error("windows"))?;
    require(
        !content.private_data.is_empty() && content.private_data.len() <= 8192,
        "compressed_length",
    )?;
    if let Some(key) = &content.key_stream {
        require(key.len() == content.private_data.len(), "keystream_length")?;
    }
    let z: Vec<u8> = content
        .private_data
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ content.key_stream.as_ref().map_or(0, |key| key[i]))
        .collect();
    let full = inflate::decode(&z)?;
    let records = lex::Scanner::collect(&full.plain)?;
    let mut anchor_ops = vec![0; 16];
    let mut ordinals = Vec::new();
    let mut totals = Vec::new();
    for (i, a) in input.anchors.iter().enumerate() {
        let bytes = record_bytes(&a.record)?;
        let matches: Vec<_> = records
            .iter()
            .enumerate()
            .filter(|(_, r)| **r == bytes)
            .map(|(j, _)| j)
            .collect();
        // WP3b supplies record content only. Select its first exact occurrence;
        // the verifier still enforces its independent ordinal/total policy.
        let index = matches.first().copied().ok_or(Error("anchor_missing"))?;
        anchor_ops[i] = index;
        anchors[i]["ordinal"] = json!(1);
        anchors[i]["total"] = json!(matches.len());
        ordinals.push(1);
        totals.push(matches.len() as u32);
    }
    let mut claim_records = vec![vec![0u8; 384]; 12];
    let mut claim_lengths = vec![0usize; 12];
    let mut last_end = 0;
    for c in 0..12 {
        if slots[c]["enabled"] == true {
            let begin = anchor_ops[lex::integer(&slots[c], "before")];
            let end = anchor_ops[lex::integer(&slots[c], "after")];
            require(begin < end && begin >= last_end, "claim_intervals")?;
            last_end = end;
            let bytes: Vec<u8> = records[begin + 1..end].iter().flatten().copied().collect();
            require(bytes.len() <= 384, "max_claim_length")?;
            claim_lengths[c] = bytes.len();
            claim_records[c][..bytes.len()].copy_from_slice(&bytes);
        }
    }
    let plan = json!({"anchor_ops":anchor_ops,"lengths":claim_lengths,"records":claim_records});
    let inflate = inflate::segments(&z, &full, p, t0, t, salt)?;
    let cz = lex::scalar(&inflate[0]["cz"]);
    let pi = lex::plan_commit(salt, &plan)?;
    let r = lex::challenge(cz, pi, &anchors, &slots)?;
    let mut stages = Vec::new();
    let mut mid_outs = Vec::new();
    for (index, w) in input.windows.iter().enumerate() {
        require(
            w.head.len() < 64
                && w.tail.len() < 64
                && !w.private_data.is_empty()
                && w.private_data.len() <= 8192
                && w.mid_in.len() == 32,
            "sha_boundary",
        )?;
        let mut bytes = w.head.clone();
        bytes.extend(&w.private_data);
        bytes.extend(&w.tail);
        require(bytes.len() % 64 == 0, "window_alignment")?;
        let public = ZkPdfWindowPublic {
            role: w.role.clone(),
            mid_in: w.mid_in.clone(),
            blocks: (bytes.len() / 64) as u32,
            head: w.head.clone(),
            tail: w.tail.clone(),
            key_stream: w.key_stream.clone(),
        };
        let mut words = [0u32; 8];
        for (i, chunk) in w.mid_in.chunks_exact(4).enumerate() {
            words[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for chunk in bytes.chunks_exact(64) {
            sha2::compress256(
                &mut words,
                std::slice::from_ref(sha2::digest::generic_array::GenericArray::from_slice(chunk)),
            );
        }
        let mid_out: Vec<u8> = words.iter().flat_map(|x| x.to_be_bytes()).collect();
        let mut witness = sha_public(&public, &mid_out, cz)?;
        let capacity = if w.role == "content" { 130 } else { 128 };
        bytes.resize(capacity * 64, 0);
        witness["bytes"] = json!(bytes);
        if w.role == "content" {
            witness["salt"] = field::json(salt);
        }
        stages.push((format!("sha_{}", w.role), index as u32, witness));
        mid_outs.push(mid_out);
    }
    for (i, w) in inflate.iter().enumerate() {
        stages.push((
            if i == 0 { "inflate0" } else { "inflate" }.into(),
            i as u32,
            w.clone(),
        ));
    }
    let mut scan = lex::Scanner::new(pi, r, anchors.clone(), slots.clone(), plan.clone());
    let mut lin = field::number(0);
    let mut cg = field::number(0);
    for (i, w) in inflate.iter().enumerate() {
        let incoming = scan.s.clone();
        let start = scan.records.len();
        let mut positions = Vec::new();
        let length = lex::integer(w, "plain_len");
        for (j, b) in full.plain[i * p..i * p + length].iter().enumerate() {
            let before = scan.records.len();
            scan.step(*b)?;
            scan.s["pos"] = json!(lex::integer(&scan.s, "pos") + 1);
            if scan.records.len() != before {
                positions.push(j);
            }
        }
        let last = i + 1 == inflate.len();
        if last {
            scan.eof()?;
        }
        require(positions.len() <= o, "segment_ops")?;
        scan.aggregate(start)?;
        let used = positions.len();
        positions.resize(o, 0);
        let lout = lex::state_commit(salt, &scan.s)?;
        let mut segment_anchors = anchors.clone();
        if last {
            cg = lex::result_commit(salt, &scan.s)?;
            require(scan.s["lengths"] == plan["lengths"], "claim_records")?;
        } else {
            for a in &mut segment_anchors {
                a["ordinal"] = json!(0);
                a["total"] = json!(0);
            }
        }
        let value = json!({"domain":field::json(field::ascii("diw-zkpdf-v1")),"circuit":field::json(field::ascii("pdf_lex_seg_v1")),"index":i,"first":i==0,"last":last,"cz":field::json(cz),"lin":field::json(lin),"lout":field::json(lout),"cp":[w["cp"].clone()],"anchors":segment_anchors,"slots":slots,"cg":field::json(if last{cg}else{field::number(0)}),"salt":field::json(salt),"plain":[w["plain"].clone()],"lengths":[length],"incoming":incoming,"plan":plan,"positions":positions,"used":used});
        stages.push(("lex".into(), i as u32, value));
        lin = lout;
    }
    let mut salts = vec![vec![0u8; 16]; 12];
    for s in &input.slots {
        salts[s.slot as usize] = s.salt.clone();
    }
    let mut digests = vec![vec![0u8; 32]; 12];
    for c in 0..12 {
        if slots[c]["enabled"] == true {
            let mut hash = Sha256::new();
            hash.update(b"diw-zkpdf-claim-v1");
            hash.update([c as u8]);
            hash.update(&salts[c]);
            hash.update((claim_lengths[c] as u16).to_be_bytes());
            hash.update(&claim_records[c]);
            digests[c] = hash.finalize().to_vec();
        }
    }
    let mut claim = json!({"domain":field::json(field::ascii("diw-zkpdf-v1")),"circuit":field::json(field::ascii("pdf_claim_v1")),"beta":input.binding,"start":0,"count":12,"cz":field::json(cz),"anchors":anchors,"slots":slots,"cg":field::json(cg),"digests":digests,"salt":field::json(salt),"plan":plan,"claim_salts":salts});
    stages.push(("claim".into(), 0, claim.clone()));
    if !input.predicates.is_empty() {
        let object = claim.as_object_mut().ok_or(Error("claim_schema"))?;
        for key in ["start", "count", "digests", "claim_salts"] {
            object.remove(key);
        }
        claim["circuit"] = field::json(field::ascii("pdf_pred_v1"));
        claim["fonts"] = json!(fonts);
        claim["predicates"] = json!(predicates);
        stages.push(("pred".into(), 0, claim));
    }
    let public_input_bytes = stages
        .iter()
        .map(|(kind, _, _)| match kind.as_str() {
            "sha_content" => 9408,
            "sha_opaque" => 864,
            "inflate0" => 288,
            "inflate" => {
                if p == 2048 {
                    800
                } else {
                    544
                }
            }
            "lex" => 52672,
            "claim" => 65856,
            _ => 57536,
        })
        .sum();
    let plan = ZkPdfPlan {
        composition: input.composition.clone(),
        total_segments: stages.len() as u32,
        sha_segments: input.windows.len() as u32,
        inflate_segments: inflate.len() as u32,
        lex_segments: inflate.len() as u32,
        claim_segments: 1,
        predicate_segments: (!input.predicates.is_empty()) as u32,
        estimated_proof_bytes: stages.len() as u64 * 16256,
        public_input_bytes,
    };
    let records = claim_records
        .iter()
        .enumerate()
        .map(|(c, r)| r[..claim_lengths[c]].to_vec())
        .collect();
    Ok(Prepared {
        plan,
        stages,
        mid_outs,
        ordinals,
        totals,
        records,
        digests,
    })
}
pub fn check(input: &ZkPdfProveInput) -> Result<ZkPdfPlan> {
    Ok(prepare(input, field::number(0))?.plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_segment_public_inputs_match_python() {
        for source in [
            include_str!("../../../test-servers/src/test/resources/zkpdf/student.json"),
            include_str!("../../../test-servers/src/test/resources/zkpdf/travel-rc4.json"),
        ] {
            let fixture: Value = serde_json::from_str(source).unwrap();
            let input: ZkPdfProveInput = serde_json::from_value(fixture["input"].clone()).unwrap();
            let generated = prepare(&input, field::number(42)).unwrap();
            let expected = fixture["reference_public_inputs"].as_array().unwrap();
            assert!(generated.stages.len() == expected.len());
            for ((kind, index, witness), reference) in generated.stages.iter().zip(expected) {
                assert!(reference["kind"] == *kind && reference["index"] == *index);
                let public = crate::public::encode(kind, witness).unwrap();
                assert!(public.len() == reference["bytes"].as_u64().unwrap() as usize);
                assert!(
                    format!("{:x}", Sha256::digest(&public))
                        == reference["sha256"].as_str().unwrap(),
                    "public_reference_mismatch"
                );
            }
        }
    }
    #[test]
    fn forbidden_profile_content_is_rejected() {
        assert!(lex::Scanner::collect(b"BI /W 1 /H 1 ID x EI").is_err());
        assert!(lex::Scanner::collect(b"BT /Span << /ActualText (hidden) >> BDC ET").is_err());
    }

    #[test]
    #[ignore = "requires authenticated circuit assets; runs all synthetic ACVM witnesses"]
    fn execute_synthetic_acvm() {
        use std::{fs, path::PathBuf, time::Instant};
        let assets = PathBuf::from(std::env::var_os("ZKPDF_ASSETS_DIR").expect("assets_directory"));
        let output = std::env::var_os("ZKPDF_SYNTHETIC_OUTPUT").map(PathBuf::from);
        for (name, source) in [
            (
                "student",
                include_str!("../../../test-servers/src/test/resources/zkpdf/student.json"),
            ),
            (
                "travel-rc4",
                include_str!("../../../test-servers/src/test/resources/zkpdf/travel-rc4.json"),
            ),
        ] {
            let fixture: Value = serde_json::from_str(source).unwrap();
            let input: ZkPdfProveInput = serde_json::from_value(fixture["input"].clone()).unwrap();
            let prepared = prepare(&input, field::number(42)).unwrap();
            for (kind, index, witness) in &prepared.stages {
                let artifact =
                    crate::assets::circuit(&assets, &input.composition, kind, false).unwrap();
                let start = Instant::now();
                let result = crate::acir::execute(&artifact, witness).unwrap();
                assert!(result.public_inputs == crate::public::encode(kind, witness).unwrap());
                println!(
                    "synthetic={name} kind={kind} index={index} witness_ms={}",
                    start.elapsed().as_millis()
                );
                if let Some(output) = &output {
                    let dir = output.join(name).join(format!("{kind}-{index}"));
                    fs::create_dir_all(&dir).unwrap();
                    fs::write(dir.join("bytecode.gz"), result.bytecode).unwrap();
                    fs::write(dir.join("witness.gz"), result.witness).unwrap();
                    fs::write(dir.join("public_inputs"), result.public_inputs).unwrap();
                }
            }
        }
    }
}
