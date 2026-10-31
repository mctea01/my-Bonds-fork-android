//! Exact PUBLIC_SPEC field ordering, shared by planning and verification.
use crate::{field::F, Error, Result};
use acvm::AcirField;
use serde_json::Value;
fn append(out: &mut Vec<u8>, v: &Value) -> Result<()> {
    if let Some(array) = v.as_array() {
        for item in array {
            append(out, item)?;
        }
        return Ok(());
    }
    let field = if let Some(s) = v.as_str() {
        F::from_hex(s).ok_or(Error("public_field"))?
    } else if let Some(n) = v.as_u64() {
        F::from(n as u128)
    } else if let Some(b) = v.as_bool() {
        F::from(b)
    } else {
        return Err(Error("public_schema"));
    };
    out.extend(field.to_be_bytes());
    Ok(())
}
fn keys(out: &mut Vec<u8>, v: &Value, names: &[&str]) -> Result<()> {
    for key in names {
        append(out, &v[*key])?;
    }
    Ok(())
}
pub fn encode(kind: &str, w: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    keys(&mut out, w, &["domain", "circuit"])?;
    match kind {
        "sha_content" | "sha_opaque" => {
            keys(
                &mut out,
                w,
                &[
                    "mid_in", "mid_out", "blocks", "head_len", "head", "tail_len", "tail",
                ],
            )?;
            if kind == "sha_content" {
                keys(&mut out, w, &["encrypted", "keystream", "cz"])?;
            }
        }
        "inflate0" | "inflate" => {
            keys(
                &mut out,
                w,
                &["index", "first", "last", "cz", "sin", "sout", "cp"],
            )?;
            if kind == "inflate" {
                keys(&mut out, w, &["previous"])?;
            }
        }
        "lex" | "claim" | "pred" => {
            match kind {
                "lex" => keys(
                    &mut out,
                    w,
                    &["index", "first", "last", "cz", "lin", "lout", "cp"],
                )?,
                "claim" => keys(&mut out, w, &["beta", "start", "count", "cz"])?,
                _ => keys(&mut out, w, &["beta", "cz"])?,
            }
            for anchor in w["anchors"].as_array().ok_or(Error("public_schema"))? {
                keys(
                    &mut out,
                    anchor,
                    &["enabled", "len", "raw", "ordinal", "total"],
                )?;
            }
            for slot in w["slots"].as_array().ok_or(Error("public_schema"))? {
                keys(&mut out, slot, &["enabled", "before", "after"])?;
            }
            keys(&mut out, w, &["cg"])?;
            if kind == "claim" {
                keys(&mut out, w, &["digests"])?;
            }
            if kind == "pred" {
                for font in w["fonts"].as_array().ok_or(Error("public_schema"))? {
                    keys(
                        &mut out,
                        font,
                        &["enabled", "len", "name", "width", "digits"],
                    )?;
                }
                for predicate in w["predicates"].as_array().ok_or(Error("public_schema"))? {
                    keys(
                        &mut out,
                        predicate,
                        &["enabled", "kind", "slot", "format", "cutoff"],
                    )?;
                }
            }
        }
        _ => return Err(Error("segment_kind")),
    }
    Ok(out)
}
pub fn decode(bytes: &[u8], count: usize) -> Result<Vec<F>> {
    if bytes.len() != count * 32 {
        return Err(Error("public_length"));
    }
    bytes
        .chunks_exact(32)
        .map(|b| {
            let f = F::from_be_bytes_reduce(b);
            if f.to_be_bytes() != b {
                return Err(Error("public_noncanonical"));
            }
            Ok(f)
        })
        .collect()
}
