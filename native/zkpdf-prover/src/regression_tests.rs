//! Synthetic content streams only; assertion failures never print private data.
use crate::{field, prepare, public, verify, *};
use flate2::{write::ZlibEncoder, Compression};
use std::io::Write;

fn input(plain: &[u8], composition: &str) -> ZkPdfProveInput {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(plain).unwrap();
    let compressed = encoder.finish().unwrap();
    let tail = vec![0; (64 - compressed.len() % 64) % 64];
    ZkPdfProveInput {
        composition: composition.into(),
        binding: vec![7; 32],
        windows: vec![ZkPdfWindowInput {
            role: "content".into(),
            mid_in: vec![0; 32],
            head: vec![],
            private_data: compressed,
            tail,
            key_stream: None,
        }],
        anchors: vec![],
        slots: vec![],
        digit_tables: vec![],
        predicates: vec![],
        assets_dir: String::new(),
    }
}
fn spec(input: &ZkPdfProveInput, totals: &[u32]) -> ZkPdfVerifierSpec {
    ZkPdfVerifierSpec {
        composition: input.composition.clone(),
        binding: input.binding.clone(),
        windows: input
            .windows
            .iter()
            .map(|w| ZkPdfWindowPublic {
                role: w.role.clone(),
                mid_in: w.mid_in.clone(),
                blocks: ((w.head.len() + w.private_data.len() + w.tail.len()) / 64) as u32,
                head: w.head.clone(),
                tail: w.tail.clone(),
                key_stream: w.key_stream.clone(),
            })
            .collect(),
        anchors: input
            .anchors
            .iter()
            .zip(totals)
            .map(|(a, total)| ZkPdfAnchorPublic {
                record: a.record.clone(),
                ordinal: a.ordinal,
                total: *total,
            })
            .collect(),
        slots: input
            .slots
            .iter()
            .map(|s| ZkPdfSlotPublic {
                slot: s.slot,
                before_anchor: s.before_anchor,
                after_anchor: s.after_anchor,
            })
            .collect(),
        digit_tables: input.digit_tables.clone(),
        predicates: input.predicates.clone(),
    }
}
fn bundle(input: &ZkPdfProveInput, prepared: &prepare::Prepared) -> ZkPdfBundle {
    ZkPdfBundle {
        composition: input.composition.clone(),
        segments: prepared
            .stages
            .iter()
            .map(|(kind, index, witness)| ZkPdfSegmentProof {
                kind: kind.clone(),
                index: *index,
                public_inputs: public::encode(kind, witness).unwrap(),
                // Invalid placeholder proofs: exercise only public-input policy.
                proof: vec![0; crate::PROOF_BYTES],
            })
            .collect(),
    }
}
fn repeated_record_input() -> ZkPdfProveInput {
    let mut input = input(
        b"BT /F1 12 Tf (A) Tj (first) Tj (A) Tj (second) Tj (Z) Tj ET\n",
        "zkpdf-v1-phone",
    );
    let record = |text: &[u8]| ZkPdfRecord {
        font: b"F1".to_vec(),
        kind: 0,
        strings: vec![text.to_vec()],
    };
    input.anchors = vec![
        ZkPdfAnchorInput {
            record: record(b"A"),
            ordinal: 2,
        },
        ZkPdfAnchorInput {
            record: record(b"Z"),
            ordinal: 1,
        },
    ];
    input.slots = vec![ZkPdfSlotInput {
        slot: 0,
        before_anchor: 0,
        after_anchor: 1,
        salt: vec![3; 16],
    }];
    input
}
#[test]
fn second_occurrence_selects_the_second_slot_boundary() {
    let input = repeated_record_input();
    let prepared = prepare::prepare(&input, field::number(42)).unwrap();
    let selected = prepare::record_bytes(&ZkPdfRecord {
        font: b"F1".to_vec(),
        kind: 0,
        strings: vec![b"second".to_vec()],
    })
    .unwrap();
    assert!(prepared.records[0] == selected);
    assert!(prepared.ordinals == [2, 1] && prepared.totals == [2, 1]);
    let lex = &prepared
        .stages
        .iter()
        .find(|(kind, _, _)| kind == "lex")
        .unwrap()
        .2;
    assert!(lex["plan"]["anchor_ops"][0] == 2);
    let mut spec = spec(&input, &[2, 1]);
    let bundle = bundle(&input, &prepared);
    assert!(verify::policy(&spec, &bundle).is_ok());
    spec.anchors[0].ordinal = 1;
    assert!(verify::policy(&spec, &bundle).err() == Some(Error("public_mismatch")));
}
#[test]
fn invalid_occurrences_fail_before_assets_or_progress() {
    for ordinal in [0, 3, u32::MAX] {
        let mut input = repeated_record_input();
        input.anchors[0].ordinal = ordinal;
        assert!(check(&input).err() == Some(Error("anchor_ordinal")));
        #[cfg(feature = "bb")]
        assert!(
            prove(&input, || false, |_, _, _| panic!("unexpected_progress")).err()
                == Some(Error("anchor_ordinal"))
        );
    }
}
#[test]
fn exact_plain_boundaries_omit_empty_tail_but_policy_accepts_it() {
    for (composition, p) in [("zkpdf-v1-phone", 2048), ("zkpdf-v1-desktop", 4096)] {
        for length in [p, p * 2, 40960] {
            let input = input(&vec![b' '; length], composition);
            let canonical = prepare::prepare(&input, field::number(42)).unwrap();
            let deferred =
                prepare::prepare_with_boundary::<true>(&input, field::number(42)).unwrap();
            let count = (length / p) as u32;
            assert!(canonical.plan.inflate_segments == count);
            assert!(canonical.plan.lex_segments == count);
            let checked = check(&input).unwrap();
            assert!(checked.inflate_segments == count && checked.lex_segments == count);
            assert!(checked.total_segments == 2 * count + 2);
            assert!(deferred.plan.inflate_segments == count + 1);
            assert!(deferred.plan.lex_segments == count + 1);
            let tail = &deferred
                .stages
                .iter()
                .rev()
                .find(|(kind, _, _)| kind == "inflate")
                .unwrap()
                .2;
            assert!(tail["plain_len"] == 0 && tail["last"] == true);
            assert!(canonical.records == deferred.records && canonical.digests == deferred.digests);
            let spec = spec(&input, &[]);
            assert!(verify::policy(&spec, &bundle(&input, &canonical)).is_ok());
            assert!(verify::policy(&spec, &bundle(&input, &deferred)).is_ok());
            let mut broken = bundle(&input, &deferred);
            let tail_index = broken
                .segments
                .iter()
                .rposition(|s| s.kind == "lex")
                .unwrap();
            broken.segments[tail_index].public_inputs[6 * 32 + 31] ^= 1;
            assert!(verify::policy(&spec, &broken).is_err());
        }
    }
}

#[test]
#[ignore = "requires authenticated circuit assets"]
fn second_occurrence_executes_frozen_acvm() {
    let directory =
        std::path::PathBuf::from(std::env::var_os("ZKPDF_ASSETS_DIR").expect("assets_directory"));
    let input = repeated_record_input();
    let prepared = prepare::prepare(&input, field::number(42)).unwrap();
    for (kind, _, witness) in prepared.stages {
        let artifact =
            crate::assets::circuit(&directory, &input.composition, &kind, false).unwrap();
        let executed = crate::acir::execute(&artifact, &witness).unwrap();
        assert!(executed.public_inputs == public::encode(&kind, &witness).unwrap());
    }
}
