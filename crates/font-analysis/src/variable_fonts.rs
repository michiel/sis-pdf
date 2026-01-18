/// Variable font analysis for detecting anomalous variation tables
///
/// This module analyzes variable font tables (gvar, avar, HVAR, MVAR) for
/// suspicious patterns that could indicate exploits or malformed fonts.

use std::collections::HashMap;
use tracing::{debug, instrument, warn};

use crate::model::{Confidence, FontFinding, Severity};

/// Maximum safe size for gvar table (10MB)
const MAX_GVAR_SIZE: usize = 10 * 1024 * 1024;

/// Maximum safe size for HVAR table (5MB)
const MAX_HVAR_SIZE: usize = 5 * 1024 * 1024;

/// Maximum safe size for MVAR table (1MB)
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
        let mut font_data = vec![
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
