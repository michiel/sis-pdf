/// Variable font analysis for detecting anomalous variation tables
///
/// This module analyzes variable font tables (gvar, avar, HVAR, MVAR) for
/// suspicious patterns that could indicate exploits or malformed fonts.
#[cfg(feature = "dynamic")]
use std::collections::HashMap;
#[cfg(feature = "dynamic")]
use std::convert::TryInto;
#[cfg(feature = "dynamic")]
use tracing::{debug, instrument, warn};
#[cfg(feature = "dynamic")]
use ttf_parser::Tag;

use crate::model::FontFinding;
#[cfg(feature = "dynamic")]
use crate::model::{Confidence, Severity};

/// Maximum safe size for gvar table (10MB)
#[cfg(feature = "dynamic")]
const MAX_GVAR_SIZE: usize = 10 * 1024 * 1024;

/// Maximum safe size for HVAR table (5MB)
#[cfg(feature = "dynamic")]
const MAX_HVAR_SIZE: usize = 5 * 1024 * 1024;

/// Maximum safe size for MVAR table (1MB)
#[cfg(feature = "dynamic")]
const MAX_MVAR_SIZE: usize = 1024 * 1024;

/// Analyze variable font tables for anomalies
#[cfg(feature = "dynamic")]
#[instrument(skip(font_data), fields(data_len = font_data.len()))]
pub fn analyze_variable_font(font_data: &[u8]) -> Vec<FontFinding> {
    let mut findings = Vec::new();

    // Parse font with ttf-parser
    let font = match ttf_parser::Face::parse(font_data, 0) {
        Ok(f) => f,
        Err(e) => {
            debug!(error = ?e, "Failed to parse font for variable font analysis");
            return findings;
        }
    };

    // Check if this is actually a variable font
    if !font.is_variable() {
        debug!("Font is not a variable font, skipping variable font analysis");
        return findings;
    }

    debug!("Analyzing variable font");

    if let Some(gvar_data) = font.raw_face().table(Tag::from_bytes(b"gvar")) {
        if let Some(header) = parse_gvar_header(gvar_data) {
            let glyph_count = header.glyph_count as u32;
            let font_glyphs = font.number_of_glyphs() as u32;
            if glyph_count > font_glyphs {
                let mut meta = HashMap::new();
                meta.insert("cve".into(), "CVE-2025-27363".into());
                meta.insert(
                    "attack_surface".into(),
                    "Font parsing / variable fonts".into(),
                );
                meta.insert("gvar.glyph_count".into(), glyph_count.to_string());
                meta.insert("font.glyph_count".into(), font_glyphs.to_string());
                meta.insert(
                    "gvar.last_offset".into(),
                    header
                        .offsets
                        .last()
                        .map(|v| v.to_string())
                        .unwrap_or_default(),
                );
                meta.insert("gvar.data_length".into(), header.glyph_data_len.to_string());
                findings.push(FontFinding {
                    kind: "font.gvar_glyph_count_mismatch".into(),
                    severity: Severity::High,
                    confidence: Confidence::Strong,
                    title: "Gvar glyph count exceeds maxp glyph count".into(),
                    description: "The gvar table advertises more glyphs than the face actually defines, which can trigger subglyph parsing issues (CVE-2025-27363).".into(),
                    meta,
                });
            }
            if header
                .offsets
                .windows(2)
                .any(|window| window[0] > window[1])
            {
                let mut meta = HashMap::new();
                meta.insert("cve".into(), "CVE-2025-27363".into());
                meta.insert(
                    "attack_surface".into(),
                    "Font parsing / variable fonts".into(),
                );
                meta.insert("gvar.ordering".into(), "nonstrict".into());
                meta.insert(
                    "gvar.last_offset".into(),
                    header
                        .offsets
                        .last()
                        .map(|v| v.to_string())
                        .unwrap_or_default(),
                );
                meta.insert("gvar.data_length".into(), header.glyph_data_len.to_string());
                findings.push(FontFinding {
                    kind: "font.gvar_offsets_disorder".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    title: "Gvar offsets appear out of order".into(),
                    description: "Offset entries inside the gvar variation data are not monotonically increasing, which matches erroneous subglyph parsing primitives.".into(),
                    meta,
                });
            }
        }
    }

    // Check gvar table size
    if let Some(gvar_size) = get_table_size(font_data, b"gvar") {
        if gvar_size > MAX_GVAR_SIZE {
            warn!(
                gvar_size = gvar_size,
                max_size = MAX_GVAR_SIZE,
                "Anomalously large gvar table detected"
            );

            let mut meta = HashMap::new();
            meta.insert("table".to_string(), "gvar".to_string());
            meta.insert("size".to_string(), gvar_size.to_string());
            meta.insert("max_safe_size".to_string(), MAX_GVAR_SIZE.to_string());
            meta.insert(
                "attack_surface".into(),
                "Font parsing / variable fonts".into(),
            );

            findings.push(FontFinding {
                kind: "font.anomalous_variation_table".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                title: "Anomalous gvar table size".to_string(),
                description: format!(
                    "Variable font gvar table size ({} bytes) exceeds safe limit ({} bytes)",
                    gvar_size, MAX_GVAR_SIZE
                ),
                meta,
            });
        }
    }

    // Check HVAR table size
    if let Some(hvar_size) = get_table_size(font_data, b"HVAR") {
        if hvar_size > MAX_HVAR_SIZE {
            warn!(
                hvar_size = hvar_size,
                max_size = MAX_HVAR_SIZE,
                "Anomalously large HVAR table detected"
            );

            let mut meta = HashMap::new();
            meta.insert("table".to_string(), "HVAR".to_string());
            meta.insert("size".to_string(), hvar_size.to_string());
            meta.insert("max_safe_size".to_string(), MAX_HVAR_SIZE.to_string());

            findings.push(FontFinding {
                kind: "font.anomalous_variation_table".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                title: "Anomalous HVAR table size".to_string(),
                description: format!(
                    "Variable font HVAR table size ({} bytes) exceeds safe limit ({} bytes)",
                    hvar_size, MAX_HVAR_SIZE
                ),
                meta,
            });
        }
    }

    // Check MVAR table size
    if let Some(mvar_size) = get_table_size(font_data, b"MVAR") {
        if mvar_size > MAX_MVAR_SIZE {
            warn!(
                mvar_size = mvar_size,
                max_size = MAX_MVAR_SIZE,
                "Anomalously large MVAR table detected"
            );

            let mut meta = HashMap::new();
            meta.insert("table".to_string(), "MVAR".to_string());
            meta.insert("size".to_string(), mvar_size.to_string());
            meta.insert("max_safe_size".to_string(), MAX_MVAR_SIZE.to_string());

            findings.push(FontFinding {
                kind: "font.anomalous_variation_table".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                title: "Anomalous MVAR table size".to_string(),
                description: format!(
                    "Variable font MVAR table size ({} bytes) exceeds safe limit ({} bytes)",
                    mvar_size, MAX_MVAR_SIZE
                ),
                meta,
            });
        }
    }

    // Check for excessive number of axes
    let axes = font.variation_axes();
    let axis_count = axes.into_iter().count();
    if axis_count > 16 {
        warn!(axis_count = axis_count, "Excessive variation axes");

        let mut meta = HashMap::new();
        meta.insert("axis_count".to_string(), axis_count.to_string());
        meta.insert("max_safe_count".to_string(), "16".to_string());

        findings.push(FontFinding {
            kind: "font.anomalous_variation_table".to_string(),
            severity: Severity::Low,
            confidence: Confidence::Heuristic,
            title: "Excessive variation axes".to_string(),
            description: format!(
                "Variable font has {} variation axes, which exceeds typical usage (16 max)",
                axis_count
            ),
            meta,
        });
    }

    findings
}

#[cfg(not(feature = "dynamic"))]
pub fn analyze_variable_font(_font_data: &[u8]) -> Vec<FontFinding> {
    Vec::new()
}

/// Get the size of a TrueType table
#[cfg(any(test, feature = "dynamic"))]
fn get_table_size(font_data: &[u8], tag: &[u8; 4]) -> Option<usize> {
    // Parse table directory
    if font_data.len() < 12 {
        return None;
    }

    // Skip to table directory (offset 12)
    let num_tables = u16::from_be_bytes([font_data[4], font_data[5]]) as usize;

    // Each table record is 16 bytes: tag (4), checksum (4), offset (4), length (4)
    for i in 0..num_tables {
        let record_offset = 12 + (i * 16);
        if record_offset + 16 > font_data.len() {
            break;
        }

        let table_tag = &font_data[record_offset..record_offset + 4];
        if table_tag == tag {
            let length_offset = record_offset + 12;
            let length = u32::from_be_bytes([
                font_data[length_offset],
                font_data[length_offset + 1],
                font_data[length_offset + 2],
                font_data[length_offset + 3],
            ]) as usize;
            return Some(length);
        }
    }

    None
}

#[cfg(feature = "dynamic")]
struct GvarHeader {
    glyph_count: u16,
    offsets: Vec<u32>,
    glyph_data_len: usize,
}

#[cfg(feature = "dynamic")]
fn parse_gvar_header(data: &[u8]) -> Option<GvarHeader> {
    if data.len() < 20 {
        return None;
    }
    let version = u32::from_be_bytes(data[0..4].try_into().ok()?);
    if version != 0x00010000 {
        return None;
    }
    let axis_count = u16::from_be_bytes(data[4..6].try_into().ok()?);
    if axis_count == 0 {
        return None;
    }
    let glyph_count = u16::from_be_bytes(data[12..14].try_into().ok()?);
    let flags = u16::from_be_bytes(data[14..16].try_into().ok()?);
    let glyph_data_offset = u32::from_be_bytes(data[16..20].try_into().ok()?) as usize;
    let offsets_count = glyph_count as usize + 1;
    let entry_size: usize = if flags & 1 == 1 { 4 } else { 2 };
    let offsets_start: usize = 20;
    let offsets_end = offsets_start.checked_add(offsets_count.checked_mul(entry_size)?)?;
    if offsets_end > data.len() {
        return None;
    }
    let offsets_slice = &data[offsets_start..offsets_end];
    let offsets = parse_gvar_offsets(offsets_slice, entry_size == 4)?;
    let glyph_data_len = data.len().checked_sub(glyph_data_offset)?;
    Some(GvarHeader {
        glyph_count,
        offsets,
        glyph_data_len,
    })
}

#[cfg(feature = "dynamic")]
fn parse_gvar_offsets(slice: &[u8], long_format: bool) -> Option<Vec<u32>> {
    if long_format {
        if !slice.len().is_multiple_of(4) {
            return None;
        }
        let mut out = Vec::with_capacity(slice.len() / 4);
        for chunk in slice.chunks_exact(4) {
            let arr: [u8; 4] = chunk.try_into().ok()?;
            out.push(u32::from_be_bytes(arr));
        }
        Some(out)
    } else {
        if !slice.len().is_multiple_of(2) {
            return None;
        }
        let mut out = Vec::with_capacity(slice.len() / 2);
        for chunk in slice.chunks_exact(2) {
            let arr: [u8; 2] = chunk.try_into().ok()?;
            let val = u16::from_be_bytes(arr);
            out.push((val as u32) * 2);
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "dynamic")]
    fn test_non_variable_font() {
        // Minimal TrueType font header (not a variable font)
        let font_data = vec![
            0x00, 0x01, 0x00, 0x00, // version
            0x00, 0x00, // num tables
            0x00, 0x00, // search range
            0x00, 0x00, // entry selector
            0x00, 0x00, // range shift
        ];

        let findings = analyze_variable_font(&font_data);
        // Should return empty for non-variable fonts or parsing errors
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_get_table_size() {
        // Create minimal font with gvar table
        let font_data = vec![
            0x00, 0x01, 0x00, 0x00, // version
            0x00, 0x01, // num tables = 1
            0x00, 0x00, // search range
            0x00, 0x00, // entry selector
            0x00, 0x00, // range shift
            // Table record for 'gvar'
            b'g', b'v', b'a', b'r', // tag
            0x00, 0x00, 0x00, 0x00, // checksum
            0x00, 0x00, 0x00, 0x20, // offset = 32
            0x00, 0x00, 0x10, 0x00, // length = 4096
        ];

        let size = get_table_size(&font_data, b"gvar");
        assert_eq!(size, Some(4096));

        let missing = get_table_size(&font_data, b"HVAR");
        assert_eq!(missing, None);
    }
}
