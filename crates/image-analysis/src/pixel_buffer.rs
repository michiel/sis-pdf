use sis_pdf_pdf::graph::ObjectGraph;
use sis_pdf_pdf::object::PdfDict;

use crate::colour_space::{resolve_colour_space, ResolvedColourSpace};
use crate::util::{dict_f64_array, dict_u32};

/// Maximum pixel buffer size for preview (16 megapixels * 4 = 64 MB).
pub const MAX_PREVIEW_BUFFER_BYTES: u64 = 64 * 1024 * 1024;

/// Result of pixel reconstruction from decoded image stream bytes.
#[derive(Debug, Clone)]
pub struct PixelBuffer {
    pub width: u32,
    pub height: u32,
    /// RGBA pixels, row-major, 4 bytes per pixel.
    pub rgba: Vec<u8>,
}

/// Errors during pixel reconstruction.
#[derive(Debug, Clone, PartialEq)]
pub enum PixelError {
    /// Missing required dictionary key.
    MissingKey(&'static str),
    /// Colour space cannot be resolved or is unsupported.
    UnsupportedColourSpace(String),
    /// Calculated buffer size exceeds safety limit.
    BufferSizeExceeded { expected: u64, limit: u64 },
    /// Decoded stream is shorter than expected for the declared dimensions.
    InsufficientData { expected: usize, actual: usize },
    /// BitsPerComponent value is not 1, 2, 4, or 8.
    UnsupportedBitsPerComponent(u32),
    /// Arithmetic overflow in row/buffer calculations.
    ArithmeticOverflow(String),
    /// Indexed palette is too short for the declared hival.
    PaletteTooShort { expected: usize, actual: usize },
    /// Decode array has invalid length or values.
    InvalidDecodeArray(String),
}

impl std::fmt::Display for PixelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingKey(k) => write!(f, "missing key: {}", k),
            Self::UnsupportedColourSpace(s) => write!(f, "unsupported colour space: {}", s),
            Self::BufferSizeExceeded { expected, limit } => {
                write!(f, "buffer {} bytes exceeds limit {} bytes", expected, limit)
            }
            Self::InsufficientData { expected, actual } => {
                write!(f, "need {} bytes, got {}", expected, actual)
            }
            Self::UnsupportedBitsPerComponent(v) => write!(f, "unsupported BPC: {}", v),
            Self::ArithmeticOverflow(s) => write!(f, "arithmetic overflow: {}", s),
            Self::PaletteTooShort { expected, actual } => {
                write!(f, "palette needs {} bytes, got {}", expected, actual)
            }
            Self::InvalidDecodeArray(s) => write!(f, "invalid /Decode: {}", s),
        }
    }
}

/// Reconstruct RGBA pixel data from decoded image stream bytes.
///
/// `decoded` is the stream bytes after all filter decoding (FlateDecode etc.).
/// For images using DCTDecode/JPXDecode/JBIG2Decode, use the format-specific
/// decoders instead (those produce complete images, not raw pixel samples).
pub fn reconstruct_pixels(
    decoded: &[u8],
    dict: &PdfDict<'_>,
    graph: &ObjectGraph<'_>,
) -> Result<PixelBuffer, PixelError> {
    let width = dict_u32(dict, b"/Width").ok_or(PixelError::MissingKey("/Width"))?;
    let height = dict_u32(dict, b"/Height").ok_or(PixelError::MissingKey("/Height"))?;

    if width == 0 {
        return Err(PixelError::MissingKey("/Width (zero)"));
    }
    if height == 0 {
        return Err(PixelError::MissingKey("/Height (zero)"));
    }

    let cs = resolve_colour_space(dict, graph)
        .ok_or_else(|| PixelError::UnsupportedColourSpace("none".to_string()))?;

    if !cs.supports_preview() {
        return Err(PixelError::UnsupportedColourSpace(format!("{:?}", cs)));
    }

    let channels = cs.channels().ok_or_else(|| {
        PixelError::UnsupportedColourSpace("unknown channel count".to_string())
    })? as u64;

    // For Indexed colour spaces, each sample is a single palette index
    // and the number of source channels is 1 regardless of base
    let source_channels: u64 = if matches!(cs, ResolvedColourSpace::Indexed { .. }) {
        1
    } else {
        channels
    };

    let bpc = dict_u32(dict, b"/BitsPerComponent").unwrap_or(8);
    if !matches!(bpc, 1 | 2 | 4 | 8) {
        return Err(PixelError::UnsupportedBitsPerComponent(bpc));
    }

    // Calculate expected byte count with checked arithmetic
    let bits_per_row = (width as u64)
        .checked_mul(source_channels)
        .and_then(|v| v.checked_mul(bpc as u64))
        .ok_or_else(|| PixelError::ArithmeticOverflow("bits_per_row".to_string()))?;

    let bytes_per_row = (bits_per_row + 7) / 8;

    let expected_bytes = bytes_per_row
        .checked_mul(height as u64)
        .ok_or_else(|| PixelError::ArithmeticOverflow("total_bytes".to_string()))?;

    if expected_bytes > MAX_PREVIEW_BUFFER_BYTES {
        return Err(PixelError::BufferSizeExceeded {
            expected: expected_bytes,
            limit: MAX_PREVIEW_BUFFER_BYTES,
        });
    }

    let expected_bytes = expected_bytes as usize;
    if decoded.len() < expected_bytes {
        return Err(PixelError::InsufficientData {
            expected: expected_bytes,
            actual: decoded.len(),
        });
    }

    // Check output RGBA buffer size
    let rgba_size = (width as u64)
        .checked_mul(height as u64)
        .and_then(|v| v.checked_mul(4))
        .ok_or_else(|| PixelError::ArithmeticOverflow("rgba_size".to_string()))?;

    if rgba_size > MAX_PREVIEW_BUFFER_BYTES {
        return Err(PixelError::BufferSizeExceeded {
            expected: rgba_size,
            limit: MAX_PREVIEW_BUFFER_BYTES,
        });
    }

    // Extract and validate /Decode array if present
    let decode_array = extract_decode_array(dict, source_channels as usize)?;

    // Unpack samples from stream data
    let samples = unpack_samples(
        decoded,
        width,
        height,
        source_channels as u32,
        bpc,
        bytes_per_row as usize,
    );

    // Apply /Decode array remapping if present
    let samples = if let Some(ref decode) = decode_array {
        apply_decode_array(&samples, decode, bpc)
    } else {
        samples
    };

    // Convert samples to RGBA
    let rgba = convert_to_rgba(&samples, width, height, &cs)?;

    Ok(PixelBuffer { width, height, rgba })
}

/// Extract and validate the /Decode array from the image dictionary.
fn extract_decode_array(
    dict: &PdfDict<'_>,
    source_channels: usize,
) -> Result<Option<Vec<f64>>, PixelError> {
    let Some(arr) = dict_f64_array(dict, b"/Decode") else {
        return Ok(None);
    };

    let expected_len = source_channels * 2;
    if arr.len() != expected_len {
        return Err(PixelError::InvalidDecodeArray(format!(
            "length {} but expected {}",
            arr.len(),
            expected_len
        )));
    }

    // Validate values are finite
    for (i, v) in arr.iter().enumerate() {
        if !v.is_finite() {
            return Err(PixelError::InvalidDecodeArray(format!(
                "non-finite value at index {}",
                i
            )));
        }
    }

    Ok(Some(arr))
}

/// Unpack pixel samples from raw stream bytes, handling sub-byte BPC.
fn unpack_samples(
    data: &[u8],
    width: u32,
    height: u32,
    channels: u32,
    bpc: u32,
    bytes_per_row: usize,
) -> Vec<u8> {
    if bpc == 8 {
        // Fast path: samples are already byte-aligned
        let samples_per_row = (width * channels) as usize;
        let mut out = Vec::with_capacity(samples_per_row * height as usize);
        for row in 0..height as usize {
            let row_start = row * bytes_per_row;
            let row_end = row_start + samples_per_row;
            if row_end <= data.len() {
                out.extend_from_slice(&data[row_start..row_end]);
            }
        }
        return out;
    }

    // Sub-byte unpacking for BPC 1, 2, 4
    let samples_per_row = (width * channels) as usize;
    let max_sample = (1u16 << bpc) - 1;
    let mut out = Vec::with_capacity(samples_per_row * height as usize);

    for row in 0..height as usize {
        let row_start = row * bytes_per_row;
        let mut bit_offset = 0u32;

        for _ in 0..samples_per_row {
            let byte_idx = row_start + (bit_offset / 8) as usize;
            let bit_pos = 8 - bpc - (bit_offset % 8);

            let sample = if byte_idx < data.len() {
                (data[byte_idx] >> bit_pos) & (max_sample as u8)
            } else {
                0
            };

            // Scale to 0-255 range
            let scaled = match bpc {
                1 => sample * 255,
                2 => sample * 85, // 255/3
                4 => sample * 17, // 255/15
                _ => sample,
            };

            out.push(scaled);
            bit_offset += bpc;
        }
    }

    out
}

/// Apply /Decode array to remap sample values.
///
/// In the PDF spec, /Decode maps the sample range [0..2^bpc-1] to [D_min..D_max].
/// The D_min/D_max values are normalised to the colour component range (typically 0-1).
/// Since we've already scaled sub-byte samples to 0-255, we treat the input as [0..255]
/// and scale the /Decode output back to [0..255].
fn apply_decode_array(samples: &[u8], decode: &[f64], _bpc: u32) -> Vec<u8> {
    let num_channels = decode.len() / 2;

    samples
        .iter()
        .enumerate()
        .map(|(i, &s)| {
            let ch = i % num_channels;
            let d_min = decode[ch * 2];
            let d_max = decode[ch * 2 + 1];
            // Interpolate: t is normalised sample position [0..1]
            let t = s as f64 / 255.0;
            // Result is in /Decode output range (typically 0-1)
            let result = d_min + t * (d_max - d_min);
            // Scale from [0..1] to [0..255]
            (result * 255.0).clamp(0.0, 255.0) as u8
        })
        .collect()
}

/// Convert unpacked samples to RGBA based on colour space.
fn convert_to_rgba(
    samples: &[u8],
    width: u32,
    height: u32,
    cs: &ResolvedColourSpace,
) -> Result<Vec<u8>, PixelError> {
    let pixel_count = (width as usize) * (height as usize);
    let mut rgba = Vec::with_capacity(pixel_count * 4);

    match cs {
        ResolvedColourSpace::DeviceGray
        | ResolvedColourSpace::ICCBased { n: 1 }
        | ResolvedColourSpace::Calibrated { channels: 1 } => {
            for i in 0..pixel_count {
                let v = samples.get(i).copied().unwrap_or(0);
                rgba.extend_from_slice(&[v, v, v, 255]);
            }
        }
        ResolvedColourSpace::DeviceRGB
        | ResolvedColourSpace::ICCBased { n: 3 }
        | ResolvedColourSpace::Calibrated { channels: 3 } => {
            for i in 0..pixel_count {
                let base = i * 3;
                let r = samples.get(base).copied().unwrap_or(0);
                let g = samples.get(base + 1).copied().unwrap_or(0);
                let b = samples.get(base + 2).copied().unwrap_or(0);
                rgba.extend_from_slice(&[r, g, b, 255]);
            }
        }
        ResolvedColourSpace::DeviceCMYK | ResolvedColourSpace::ICCBased { n: 4 } => {
            for i in 0..pixel_count {
                let base = i * 4;
                let c = samples.get(base).copied().unwrap_or(0) as f64 / 255.0;
                let m = samples.get(base + 1).copied().unwrap_or(0) as f64 / 255.0;
                let y = samples.get(base + 2).copied().unwrap_or(0) as f64 / 255.0;
                let k = samples.get(base + 3).copied().unwrap_or(0) as f64 / 255.0;
                let r = ((1.0 - c) * (1.0 - k) * 255.0).clamp(0.0, 255.0) as u8;
                let g = ((1.0 - m) * (1.0 - k) * 255.0).clamp(0.0, 255.0) as u8;
                let b = ((1.0 - y) * (1.0 - k) * 255.0).clamp(0.0, 255.0) as u8;
                rgba.extend_from_slice(&[r, g, b, 255]);
            }
        }
        ResolvedColourSpace::Indexed { base, hival, palette } => {
            let base_channels = base.channels().unwrap_or(3) as usize;
            let palette_entry_size = base_channels;
            let expected_palette_bytes = (*hival as usize + 1) * palette_entry_size;

            if palette.len() < expected_palette_bytes {
                return Err(PixelError::PaletteTooShort {
                    expected: expected_palette_bytes,
                    actual: palette.len(),
                });
            }

            for i in 0..pixel_count {
                let idx = samples.get(i).copied().unwrap_or(0);
                // Clamp index to hival
                let idx = idx.min(*hival) as usize;
                let palette_offset = idx * palette_entry_size;

                match base.as_ref() {
                    ResolvedColourSpace::DeviceGray
                    | ResolvedColourSpace::ICCBased { n: 1 }
                    | ResolvedColourSpace::Calibrated { channels: 1 } => {
                        let v = palette.get(palette_offset).copied().unwrap_or(0);
                        rgba.extend_from_slice(&[v, v, v, 255]);
                    }
                    ResolvedColourSpace::DeviceRGB
                    | ResolvedColourSpace::ICCBased { n: 3 }
                    | ResolvedColourSpace::Calibrated { channels: 3 } => {
                        let r = palette.get(palette_offset).copied().unwrap_or(0);
                        let g = palette.get(palette_offset + 1).copied().unwrap_or(0);
                        let b = palette.get(palette_offset + 2).copied().unwrap_or(0);
                        rgba.extend_from_slice(&[r, g, b, 255]);
                    }
                    ResolvedColourSpace::DeviceCMYK | ResolvedColourSpace::ICCBased { n: 4 } => {
                        let c = palette.get(palette_offset).copied().unwrap_or(0) as f64 / 255.0;
                        let m =
                            palette.get(palette_offset + 1).copied().unwrap_or(0) as f64 / 255.0;
                        let y =
                            palette.get(palette_offset + 2).copied().unwrap_or(0) as f64 / 255.0;
                        let k =
                            palette.get(palette_offset + 3).copied().unwrap_or(0) as f64 / 255.0;
                        let r = ((1.0 - c) * (1.0 - k) * 255.0).clamp(0.0, 255.0) as u8;
                        let g = ((1.0 - m) * (1.0 - k) * 255.0).clamp(0.0, 255.0) as u8;
                        let b = ((1.0 - y) * (1.0 - k) * 255.0).clamp(0.0, 255.0) as u8;
                        rgba.extend_from_slice(&[r, g, b, 255]);
                    }
                    _ => {
                        return Err(PixelError::UnsupportedColourSpace(format!(
                            "Indexed base: {:?}",
                            base
                        )));
                    }
                }
            }
        }
        _ => {
            return Err(PixelError::UnsupportedColourSpace(format!("{:?}", cs)));
        }
    }

    Ok(rgba)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::collections::HashMap;

    use sis_pdf_pdf::object::{PdfAtom, PdfName, PdfObj, PdfStr};
    use sis_pdf_pdf::span::Span;

    fn zero_span() -> Span {
        Span { start: 0, end: 0 }
    }

    fn pdf_name(name: &'static str) -> PdfName<'static> {
        PdfName {
            span: zero_span(),
            raw: Cow::Owned(name.as_bytes().to_vec()),
            decoded: name.as_bytes().to_vec(),
        }
    }

    fn pdf_obj_name(name: &'static str) -> PdfObj<'static> {
        PdfObj { span: zero_span(), atom: PdfAtom::Name(pdf_name(name)) }
    }

    fn pdf_obj_int(value: i64) -> PdfObj<'static> {
        PdfObj { span: zero_span(), atom: PdfAtom::Int(value) }
    }

    fn make_dict(entries: Vec<(PdfName<'static>, PdfObj<'static>)>) -> PdfDict<'static> {
        PdfDict { span: zero_span(), entries }
    }

    fn empty_graph() -> ObjectGraph<'static> {
        ObjectGraph {
            bytes: &[],
            objects: Vec::new(),
            index: HashMap::new(),
            trailers: Vec::new(),
            startxrefs: Vec::new(),
            xref_sections: Vec::new(),
            deviations: Vec::new(),
            telemetry_events: Vec::new(),
        }
    }

    fn image_dict(
        width: u32,
        height: u32,
        bpc: u32,
        cs_name: &'static str,
    ) -> PdfDict<'static> {
        make_dict(vec![
            (pdf_name("/Width"), pdf_obj_int(width as i64)),
            (pdf_name("/Height"), pdf_obj_int(height as i64)),
            (pdf_name("/BitsPerComponent"), pdf_obj_int(bpc as i64)),
            (pdf_name("/ColorSpace"), pdf_obj_name(cs_name)),
        ])
    }

    #[test]
    fn gray_8bpc_2x2() {
        let dict = image_dict(2, 2, 8, "/DeviceGray");
        let graph = empty_graph();
        let data = vec![0, 128, 255, 64];
        let result = reconstruct_pixels(&data, &dict, &graph).expect("should succeed");
        assert_eq!(result.width, 2);
        assert_eq!(result.height, 2);
        assert_eq!(result.rgba.len(), 16);
        assert_eq!(&result.rgba[0..4], &[0, 0, 0, 255]);
        assert_eq!(&result.rgba[4..8], &[128, 128, 128, 255]);
        assert_eq!(&result.rgba[8..12], &[255, 255, 255, 255]);
        assert_eq!(&result.rgba[12..16], &[64, 64, 64, 255]);
    }

    #[test]
    fn rgb_8bpc_1x1() {
        let dict = image_dict(1, 1, 8, "/DeviceRGB");
        let graph = empty_graph();
        let data = vec![255, 128, 0];
        let result = reconstruct_pixels(&data, &dict, &graph).expect("should succeed");
        assert_eq!(result.rgba, vec![255, 128, 0, 255]);
    }

    #[test]
    fn cmyk_8bpc_1x1() {
        let dict = image_dict(1, 1, 8, "/DeviceCMYK");
        let graph = empty_graph();
        // C=0, M=0, Y=0, K=0 -> white
        let data = vec![0, 0, 0, 0];
        let result = reconstruct_pixels(&data, &dict, &graph).expect("should succeed");
        assert_eq!(&result.rgba[0..3], &[255, 255, 255]);

        // C=255, M=255, Y=255, K=255 -> black
        let data = vec![255, 255, 255, 255];
        let result = reconstruct_pixels(&data, &dict, &graph).expect("should succeed");
        assert_eq!(&result.rgba[0..3], &[0, 0, 0]);
    }

    #[test]
    fn gray_1bpc_8x1() {
        let dict = image_dict(8, 1, 1, "/DeviceGray");
        let graph = empty_graph();
        // 8 pixels in 1 byte: 0b10101010 = alternating black/white
        let data = vec![0b10101010];
        let result = reconstruct_pixels(&data, &dict, &graph).expect("should succeed");
        assert_eq!(result.rgba.len(), 32); // 8 pixels * 4 bytes
        // First pixel: bit 7 = 1 -> 255
        assert_eq!(&result.rgba[0..4], &[255, 255, 255, 255]);
        // Second pixel: bit 6 = 0 -> 0
        assert_eq!(&result.rgba[4..8], &[0, 0, 0, 255]);
    }

    #[test]
    fn gray_4bpc_2x1() {
        let dict = image_dict(2, 1, 4, "/DeviceGray");
        let graph = empty_graph();
        // 2 pixels in 1 byte: high nibble = 15 (0xF), low nibble = 0
        let data = vec![0xF0];
        let result = reconstruct_pixels(&data, &dict, &graph).expect("should succeed");
        assert_eq!(result.rgba.len(), 8);
        // First pixel: 15 * 17 = 255
        assert_eq!(&result.rgba[0..4], &[255, 255, 255, 255]);
        // Second pixel: 0 * 17 = 0
        assert_eq!(&result.rgba[4..8], &[0, 0, 0, 255]);
    }

    #[test]
    fn indexed_rgb_palette() {
        let graph = empty_graph();

        // Palette: index 0 = red, index 1 = green
        let palette_bytes = vec![255, 0, 0, 0, 255, 0];
        let palette_str = PdfObj {
            span: zero_span(),
            atom: PdfAtom::Str(PdfStr::Literal {
                span: zero_span(),
                raw: Cow::Owned(palette_bytes.clone()),
                decoded: palette_bytes,
            }),
        };

        let cs_array = PdfObj {
            span: zero_span(),
            atom: PdfAtom::Array(vec![
                pdf_obj_name("/Indexed"),
                pdf_obj_name("/DeviceRGB"),
                pdf_obj_int(1),
                palette_str,
            ]),
        };

        let dict = make_dict(vec![
            (pdf_name("/Width"), pdf_obj_int(2)),
            (pdf_name("/Height"), pdf_obj_int(1)),
            (pdf_name("/BitsPerComponent"), pdf_obj_int(8)),
            (pdf_name("/ColorSpace"), cs_array),
        ]);

        // Two pixels: index 0 (red) and index 1 (green)
        let data = vec![0, 1];
        let result = reconstruct_pixels(&data, &dict, &graph).expect("should succeed");
        assert_eq!(&result.rgba[0..4], &[255, 0, 0, 255]); // red
        assert_eq!(&result.rgba[4..8], &[0, 255, 0, 255]); // green
    }

    #[test]
    fn decode_array_remaps_values() {
        let graph = empty_graph();

        // /Decode [1 0] inverts grayscale
        let decode_arr = PdfObj {
            span: zero_span(),
            atom: PdfAtom::Array(vec![
                PdfObj { span: zero_span(), atom: PdfAtom::Real(1.0) },
                PdfObj { span: zero_span(), atom: PdfAtom::Real(0.0) },
            ]),
        };

        let dict = make_dict(vec![
            (pdf_name("/Width"), pdf_obj_int(1)),
            (pdf_name("/Height"), pdf_obj_int(1)),
            (pdf_name("/BitsPerComponent"), pdf_obj_int(8)),
            (pdf_name("/ColorSpace"), pdf_obj_name("/DeviceGray")),
            (pdf_name("/Decode"), decode_arr),
        ]);

        // Input 0 with /Decode [1 0] should map to 255 (inverted)
        let data = vec![0];
        let result = reconstruct_pixels(&data, &dict, &graph).expect("should succeed");
        assert_eq!(&result.rgba[0..4], &[255, 255, 255, 255]);

        // Input 255 should map to 0
        let data = vec![255];
        let result = reconstruct_pixels(&data, &dict, &graph).expect("should succeed");
        assert_eq!(&result.rgba[0..4], &[0, 0, 0, 255]);
    }

    #[test]
    fn insufficient_data_error() {
        let dict = image_dict(2, 2, 8, "/DeviceRGB");
        let graph = empty_graph();
        // Need 2*2*3 = 12 bytes, provide 6
        let data = vec![0; 6];
        let result = reconstruct_pixels(&data, &dict, &graph);
        assert!(matches!(result, Err(PixelError::InsufficientData { expected: 12, actual: 6 })));
    }

    #[test]
    fn buffer_size_overflow_rejected() {
        let dict = image_dict(100_000, 100_000, 8, "/DeviceRGB");
        let graph = empty_graph();
        let data = vec![0; 100];
        let result = reconstruct_pixels(&data, &dict, &graph);
        assert!(matches!(result, Err(PixelError::BufferSizeExceeded { .. })));
    }

    #[test]
    fn zero_width_rejected() {
        let dict = image_dict(0, 10, 8, "/DeviceGray");
        let graph = empty_graph();
        let result = reconstruct_pixels(&[], &dict, &graph);
        assert!(matches!(result, Err(PixelError::MissingKey("/Width (zero)"))));
    }

    #[test]
    fn zero_height_rejected() {
        let dict = image_dict(10, 0, 8, "/DeviceGray");
        let graph = empty_graph();
        let result = reconstruct_pixels(&[], &dict, &graph);
        assert!(matches!(result, Err(PixelError::MissingKey("/Height (zero)"))));
    }

    #[test]
    fn unsupported_bpc_rejected() {
        let dict = image_dict(1, 1, 7, "/DeviceGray");
        let graph = empty_graph();
        let data = vec![0];
        let result = reconstruct_pixels(&data, &dict, &graph);
        assert!(matches!(result, Err(PixelError::UnsupportedBitsPerComponent(7))));
    }

    #[test]
    fn palette_too_short_error() {
        let graph = empty_graph();

        // Palette has only 3 bytes but hival=1 requires 6 (2 entries * 3 channels)
        let palette_bytes = vec![255, 0, 0]; // only 1 entry
        let palette_str = PdfObj {
            span: zero_span(),
            atom: PdfAtom::Str(PdfStr::Literal {
                span: zero_span(),
                raw: Cow::Owned(palette_bytes.clone()),
                decoded: palette_bytes,
            }),
        };

        let cs_array = PdfObj {
            span: zero_span(),
            atom: PdfAtom::Array(vec![
                pdf_obj_name("/Indexed"),
                pdf_obj_name("/DeviceRGB"),
                pdf_obj_int(1),
                palette_str,
            ]),
        };

        let dict = make_dict(vec![
            (pdf_name("/Width"), pdf_obj_int(1)),
            (pdf_name("/Height"), pdf_obj_int(1)),
            (pdf_name("/BitsPerComponent"), pdf_obj_int(8)),
            (pdf_name("/ColorSpace"), cs_array),
        ]);

        let data = vec![0];
        let result = reconstruct_pixels(&data, &dict, &graph);
        assert!(matches!(result, Err(PixelError::PaletteTooShort { expected: 6, actual: 3 })));
    }
}
