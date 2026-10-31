//! Authenticate exact bytes before handing any asset to native code.
use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};
const VERSIONS: &str = include_str!("../../circuits/VERSIONS");
pub const CRS: [(&str, usize, &str); 2] = [
    (
        "bn254_g1.dat",
        134217792,
        "ea6069e3563ad79f186d1c0088499309cbdaeb54254346760ffec7fe15ae49cd",
    ),
    (
        "bn254_g2.dat",
        128,
        "01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f",
    ),
];
fn pin(key: &str) -> Result<&'static str> {
    VERSIONS
        .lines()
        .filter_map(|line| line.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
        .ok_or(Error("asset_pin"))
}
pub fn package(composition: &str, kind: &str) -> Result<String> {
    crate::prepare::parameters(composition)?;
    let circuit = match kind {
        "sha_content" => "pdf_sha_content_v1",
        "sha_opaque" => "pdf_sha_opaque_v1",
        "inflate0" => "pdf_inflate_seg0_v1",
        "inflate" => "pdf_inflate_seg_v1",
        "lex" => "pdf_lex_seg_v1",
        "claim" => "pdf_claim_v1",
        "pred" => "pdf_pred_v1",
        _ => return Err(Error("segment_kind")),
    };
    Ok(pin(&format!("{composition}.{circuit}.package"))?.to_string())
}
fn read(path: &Path, limit: usize, digest: &str) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|_| Error("asset_missing"))?;
    if file.metadata().map_err(|_| Error("asset_read"))?.len() > limit as u64 {
        return Err(Error("asset_size"));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("asset_read"))?;
    if bytes.len() > limit || format!("{:x}", Sha256::digest(&bytes)) != digest {
        return Err(Error("asset_integrity"));
    }
    Ok(bytes)
}
pub fn circuit(directory: &Path, composition: &str, kind: &str, vk: bool) -> Result<Vec<u8>> {
    let package = package(composition, kind)?;
    let canonical = package.strip_suffix("_desktop").unwrap_or(&package);
    let extension = if vk { "vk" } else { "json" };
    let pin_kind = if vk { "vk" } else { "acir" };
    read(
        &directory.join(format!("{package}.{extension}")),
        if vk { 16384 } else { 256 * 1024 * 1024 },
        pin(&format!("{composition}.{canonical}.{pin_kind}_sha256"))?,
    )
}
pub fn crs(directory: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let load = |(name, size, hash): (&str, usize, &str)| -> Result<Vec<u8>> {
        let bytes = read(&directory.join("crs").join(name), size, hash)?;
        if bytes.len() != size {
            return Err(Error("crs_size"));
        }
        Ok(bytes)
    };
    Ok((load(CRS[0])?, load(CRS[1])?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_compositions_have_exact_frozen_assets() {
        for composition in ["zkpdf-v1-phone", "zkpdf-v1-desktop"] {
            for kind in [
                "sha_content",
                "sha_opaque",
                "inflate0",
                "inflate",
                "lex",
                "claim",
                "pred",
            ] {
                assert!(package(composition, kind).is_ok());
            }
        }
        assert!(package("other", "claim").is_err());
        assert!(package("zkpdf-v1-phone", "../claim").is_err());
        assert!(pin("noirc_commit").unwrap() == "83245db91dcf63420ef4bcbbd85b98f397fee663");
    }
}
