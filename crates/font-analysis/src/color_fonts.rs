/// Color font analysis for COLR/CPAL table validation
///
/// This module analyzes color font tables (COLR, CPAL) for consistency
/// and potential security issues.
use crate::model::FontFinding;

#[cfg(feature = "dynamic")]
use std::collections::HashMap;
#[cfg(feature = "dynamic")]
use tracing::{debug, instrument, warn};

#[cfg(feature = "dynamic")]
use crate::model::{Confidence, Severity};

/// Maximum safe number of palettes
#[cfg(feature = "dynamic")]
const MAX_SAFE_PALETTES: usize = 256;

/// Analyze color font tables for inconsistencies
#[cfg(feature = "dynamic")]
#[instrument(skip(font_data), fields(data_len = font_data.len()))]
pub fn analyze_color_font(font_data: &[u8]) -> Vec<FontFinding> {
    let mut findings = Vec::new();

    // Parse font with ttf-parser
    let font = match ttf_parser::Face::parse(font_data, 0) {
        Ok(f) => f,
        Err(e) => {
            debug!(error = ?e, "Failed to parse font for color font analysis");
            return findings;
        }
    };

    // Check if font has color tables
    let has_colr = has_table(font_data, b"COLR");
    let has_cpal = has_table(font_data, b"CPAL");

    if !has_colr && !has_cpal {
        debug!("Font does not have color tables, skipping color font analysis");
        return findings;
    }

    debug!(
        has_colr = has_colr,
        has_cpal = has_cpal,
        "Analyzing color font"
    );

    // COLR without CPAL or vice versa is suspicious
    if has_colr != has_cpal {
        warn!(
            has_colr = has_colr,
            has_cpal = has_cpal,
            "Inconsistent color tables: COLR and CPAL should both be present or both absent"
        );

        let mut meta = HashMap::new();
        meta.insert("has_colr".to_string(), has_colr.to_string());
        meta.insert("has_cpal".to_string(), has_cpal.to_string());

        findings.push(FontFinding {
            kind: "font.color_table_inconsistent".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            title: "Inconsistent color tables".to_string(),
            description: "Font has COLR or CPAL table but not both, which is inconsistent"
                .to_string(),
            meta,
        });
    }

    // Validate CPAL table if present
    if has_cpal {
        if let Some(palette_findings) = validate_cpal_table(font_data) {
            findings.extend(palette_findings);
        }
    }

    // Validate COLR table if present
    if has_colr {
        let num_glyphs = font.number_of_glyphs();
        if let Some(colr_findings) = validate_colr_table(font_data, num_glyphs) {
            findings.extend(colr_findings);
        }
    }

    findings
}

#[cfg(not(feature = "dynamic"))]
pub fn analyze_color_font(_font_data: &[u8]) -> Vec<FontFinding> {
    Vec::new()
}

/// Validate CPAL (Color Palette) table
#[cfg(feature = "dynamic")]
fn validate_cpal_table(font_data: &[u8]) -> Option<Vec<FontFinding>> {
    let mut findings = Vec::new();

    // Find CPAL table
    let (offset, length) = find_table(font_data, b"CPAL")?;

    if offset + length > font_data.len() {
        warn!("CPAL table extends beyond font data");
        let mut meta = HashMap::new();
        meta.insert("table".to_string(), "CPAL".to_string());
        meta.insert("offset".to_string(), offset.to_string());
        meta.insert("length".to_string(), length.to_string());
        meta.insert("font_size".to_string(), font_data.len().to_string());

        findings.push(FontFinding {
            kind: "font.color_table_inconsistent".to_string(),
            severity: Severity::High,
            confidence: Confidence::Probable,
            title: "CPAL table out of bounds".to_string(),
            description: "CPAL table extends beyond font data boundaries".to_string(),
            meta,
        });
        return Some(findings);
    }

    // Basic CPAL structure validation (version 0)
    if length < 12 {
        warn!(length = length, "CPAL table too small");
        let mut meta = HashMap::new();
        meta.insert("table".to_string(), "CPAL".to_string());
        meta.insert("size".to_string(), length.to_string());
        meta.insert("min_size".to_string(), "12".to_string());

        findings.push(FontFinding {
            kind: "font.color_table_inconsistent".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            title: "CPAL table too small".to_string(),
            description: format!(
                "CPAL table size ({} bytes) is smaller than minimum (12 bytes)",
                length
            ),
            meta,
        });
        return Some(findings);
    }

    let table_data = &font_data[offset..offset + length];

    // Read number of palettes (offset 4, u16)
    let num_palettes = u16::from_be_bytes([table_data[4], table_data[5]]) as usize;

    if num_palettes > MAX_SAFE_PALETTES {
        warn!(
            num_palettes = num_palettes,
            "Excessive number of color palettes"
        );

        let mut meta = HashMap::new();
        meta.insert("num_palettes".to_string(), num_palettes.to_string());
        meta.insert("max_safe".to_string(), MAX_SAFE_PALETTES.to_string());

        findings.push(FontFinding {
            kind: "font.color_table_inconsistent".to_string(),
            severity: Severity::Low,
            confidence: Confidence::Heuristic,
            title: "Excessive color palettes".to_string(),
            description: format!(
                "Font has {} color palettes, which exceeds typical usage ({} max)",
                num_palettes, MAX_SAFE_PALETTES
            ),
            meta,
        });
    }

    if findings.is_empty() {
        None
    } else {
        Some(findings)
    }
}

/// Validate COLR (Color Layer) table
#[cfg(feature = "dynamic")]
fn validate_colr_table(font_data: &[u8], font_num_glyphs: u16) -> Option<Vec<FontFinding>> {
    let mut findings = Vec::new();

    // Find COLR table
    let (offset, length) = find_table(font_data, b"COLR")?;

    if offset + length > font_data.len() {
        warn!("COLR table extends beyond font data");
        let mut meta = HashMap::new();
        meta.insert("table".to_string(), "COLR".to_string());
        meta.insert("offset".to_string(), offset.to_string());
        meta.insert("length".to_string(), length.to_string());

        findings.push(FontFinding {
            kind: "font.color_table_inconsistent".to_string(),
            severity: Severity::High,
            confidence: Confidence::Probable,
            title: "COLR table out of bounds".to_string(),
            description: "COLR table extends beyond font data boundaries".to_string(),
            meta,
        });
        return Some(findings);
    }

    // Basic COLR structure validation
    if length < 14 {
        warn!(length = length, "COLR table too small");
        let mut meta = HashMap::new();
        meta.insert("table".to_string(), "COLR".to_string());
        meta.insert("size".to_string(), length.to_string());
        meta.insert("min_size".to_string(), "14".to_string());

        findings.push(FontFinding {
            kind: "font.color_table_inconsistent".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            title: "COLR table too small".to_string(),
            description: format!(
                "COLR table size ({} bytes) is smaller than minimum (14 bytes)",
                length
            ),
            meta,
        });
        return Some(findings);
    }

    let table_data = &font_data[offset..offset + length];

    // Read number of base glyph records (offset 2, u16)
    let num_base_glyphs = u16::from_be_bytes([table_data[2], table_data[3]]) as usize;

    // Sanity check: number of colored glyphs shouldn't exceed total glyphs
    if num_base_glyphs > font_num_glyphs as usize {
        warn!(
            num_base_glyphs = num_base_glyphs,
            num_glyphs = font_num_glyphs,
            "COLR base glyph count exceeds total glyph count"
        );

        let mut meta = HashMap::new();
        meta.insert("num_base_glyphs".to_string(), num_base_glyphs.to_string());
        meta.insert("num_glyphs".to_string(), font_num_glyphs.to_string());

        findings.push(FontFinding {
            kind: "font.color_table_inconsistent".to_string(),
            severity: Severity::High,
            confidence: Confidence::Probable,
            title: "COLR glyph count mismatch".to_string(),
            description: format!(
                "COLR table has {} base glyphs but font only has {} total glyphs",
                num_base_glyphs, font_num_glyphs
            ),
            meta,
        });
    }

    if findings.is_empty() {
        None
    } else {
        Some(findings)
    }
}

/// Check if a table exists in the font
#[cfg(feature = "dynamic")]
fn has_table(font_data: &[u8], tag: &[u8; 4]) -> bool {
    find_table(font_data, tag).is_some()
}

/// Find a table in the font and return (offset, length)
#[cfg(feature = "dynamic")]
fn find_table(font_data: &[u8], tag: &[u8; 4]) -> Option<(usize, usize)> {
    if font_data.len() < 12 {
        return None;
    }

    let num_tables = u16::from_be_bytes([font_data[4], font_data[5]]) as usize;

    for i in 0..num_tables {
        let record_offset = 12 + (i * 16);
        if record_offset + 16 > font_data.len() {
            break;
        }

        let table_tag = &font_data[record_offset..record_offset + 4];
        if table_tag == tag {
            let offset_offset = record_offset + 8;
            let length_offset = record_offset + 12;

            let offset = u32::from_be_bytes([
                font_data[offset_offset],
                font_data[offset_offset + 1],
                font_data[offset_offset + 2],
                font_data[offset_offset + 3],
            ]) as usize;

            let length = u32::from_be_bytes([
                font_data[length_offset],
                font_data[length_offset + 1],
                font_data[length_offset + 2],
                font_data[length_offset + 3],
            ]) as usize;

            return Some((offset, length));
        }
    }

    None
}

#[cfg(all(test, feature = "dynamic"))]
mod tests {
    use super::*;

    #[test]
    fn test_has_table() {
        // Minimal font with COLR table
        let font_data = vec![
            0x00, 0x01, 0x00, 0x00, // version
            0x00, 0x01, // num tables = 1
            0x00, 0x00, // search range
            0x00, 0x00, // entry selector
            0x00, 0x00, // range shift
            // Table record for 'COLR'
            b'C', b'O', b'L', b'R', // tag
            0x00, 0x00, 0x00, 0x00, // checksum
            0x00, 0x00, 0x00, 0x20, // offset = 32
            0x00, 0x00, 0x00, 0x10, // length = 16
        ];

        assert!(has_table(&font_data, b"COLR"));
        assert!(!has_table(&font_data, b"CPAL"));
    }

    #[test]
    fn test_find_table() {
        let font_data = vec![
            0x00, 0x01, 0x00, 0x00, // version
            0x00, 0x01, // num tables = 1
            0x00, 0x00, // search range
            0x00, 0x00, // entry selector
            0x00, 0x00, // range shift
            // Table record for 'CPAL'
            b'C', b'P', b'A', b'L', // tag
            0x00, 0x00, 0x00, 0x00, // checksum
            0x00, 0x00, 0x00, 0x30, // offset = 48
            0x00, 0x00, 0x00, 0x20, // length = 32
        ];

        let result = find_table(&font_data, b"CPAL");
        assert_eq!(result, Some((48, 32)));

        let missing = find_table(&font_data, b"gvar");
        assert_eq!(missing, None);
    }
}
