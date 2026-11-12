//! Image formats the platforms cannot decode themselves: JPEG 2000 portraits of electronic travel documents.

use crate::{run_worker, ZkCancelToken, ZkError};
use hayro_jpeg2000::{ColorSpace, DecodeSettings, DecoderContext, Image};

/// Largest encoded image accepted (a chip portrait is a few tens of kilobytes).
const MAX_BYTES: usize = 16 * 1024 * 1024;
/// Largest decoded image accepted, in pixels.
const MAX_PIXELS: u64 = 64 * 1024 * 1024;

/// A decoded picture as 8-bit RGBA rows, top to bottom.
#[derive(uniffi::Record)]
pub struct RgbaImage {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

fn invalid(reason: &str) -> ZkError {
    ZkError::InvalidInput {
        reason: reason.into(),
    }
}

/// Decodes a JPEG 2000 file (JP2) or bare codestream (J2K) into RGBA.
#[uniffi::export]
pub fn jpeg2000_decode(data: Vec<u8>) -> Result<RgbaImage, ZkError> {
    if data.is_empty() || data.len() > MAX_BYTES {
        return Err(invalid("image_size"));
    }
    run_worker(16 * 1024 * 1024, ZkCancelToken::new(), move |_| {
        decode(&data)
    })
}

fn decode(data: &[u8]) -> Result<RgbaImage, ZkError> {
    let image = Image::new(data, &DecodeSettings::default()).map_err(|_| invalid("jpeg2000"))?;
    let (width, height) = (image.width(), image.height());
    if width == 0 || height == 0 || u64::from(width) * u64::from(height) > MAX_PIXELS {
        return Err(invalid("image_size"));
    }
    let alpha = image.has_alpha();
    let colors = image.color_space().num_channels() as usize;
    let cmyk = matches!(image.color_space(), ColorSpace::CMYK);
    let mut context = DecoderContext::default();
    let decoded = image
        .decode(&mut context)
        .map_err(|_| invalid("jpeg2000"))?;
    let samples = decoded.data_u8();
    let channels = colors + usize::from(alpha);
    let pixels = (width as usize) * (height as usize);
    if channels == 0 || samples.len() < pixels * channels {
        return Err(invalid("jpeg2000"));
    }
    let mut rgba = Vec::with_capacity(pixels * 4);
    for p in samples.chunks_exact(channels).take(pixels) {
        let a = if alpha { p[colors] } else { 255 };
        let (r, g, b) = match colors {
            1 | 2 => (p[0], p[0], p[0]),
            4 if cmyk => {
                let k = 255 - u16::from(p[3]);
                let c = |v: u8| ((255 - u16::from(v)) * k / 255) as u8;
                (c(p[0]), c(p[1]), c(p[2]))
            }
            _ => (p[0], p[1], p[2]),
        };
        rgba.extend_from_slice(&[r, g, b, a]);
    }
    Ok(RgbaImage {
        width,
        height,
        rgba,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_what_is_not_jpeg2000() {
        assert!(matches!(
            jpeg2000_decode(vec![0xFF, 0xD8, 0xFF, 0xE0]),
            Err(ZkError::InvalidInput { .. })
        ));
        assert!(matches!(
            jpeg2000_decode(Vec::new()),
            Err(ZkError::InvalidInput { .. })
        ));
    }
}
