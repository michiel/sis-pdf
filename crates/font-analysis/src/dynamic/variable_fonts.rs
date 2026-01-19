/// Variable font validation and CVE checks

use crate::model::FontFinding;
#[cfg(feature = "dynamic")]
use crate::model::{Confidence, Severity};
use super::parser::FontContext;
#[cfg(feature = "dynamic")]
use std::collections::HashMap;

/// Check for CVE-2025-27163: hmtx/hhea mismatch
#[cfg(feature = "dynamic")]
///
/// The hmtx table must have at least 4 * hhea.numberOfHMetrics bytes.
/// A mismatch can lead to out-of-bounds reads.
pub fn check_cve_2025_27163(context: &FontContext, findings: &mut Vec<FontFinding>) {
    if let (Some(num_h_metrics), Some(hmtx_length)) = (context.num_h_metrics, context.hmtx_length) {
        let required_length = (num_h_metrics as usize) * 4;

        if hmtx_length < required_length {
            let mut meta = HashMap::new();
            meta.insert("num_h_metrics".to_string(), num_h_metrics.to_string());
            meta.insert("hmtx_length".to_string(), hmtx_length.to_string());
            meta.insert("required_length".to_string(), required_length.to_string());
            meta.insert("cve".to_string(), "CVE-2025-27163".to_string());

            findings.push(FontFinding {
                kind: "font.cve_2025_27163".to_string(),
                severity: Severity::High,
                confidence: Confidence::Strong,
                title: "CVE-2025-27163: hmtx/hhea table mismatch".to_string(),
                description: format!(
                    "Font has hmtx table length ({}) smaller than required ({}) based on hhea.numberOfHMetrics ({}). This can lead to out-of-bounds reads.",
                    hmtx_length, required_length, num_h_metrics
                ),
                meta,
            });
        }
    }
}

/// Check for CVE-2025-27164: CFF2/maxp mismatch
#[cfg(feature = "dynamic")]
///
/// In fonts with CFF2 outlines, maxp.num_glyphs must not exceed the number of charstrings.
/// A mismatch can lead to buffer overflows when accessing glyph data.
pub fn check_cve_2025_27164(context: &FontContext, findings: &mut Vec<FontFinding>) {
    // Only applicable to CFF2 fonts
    if !context.has_cff2 {
        return;
    }

    if let (Some(glyph_count_maxp), Some(glyph_count_cff)) =
        (context.glyph_count_maxp, context.glyph_count_cff) {

        if glyph_count_maxp as usize > glyph_count_cff {
            let mut meta = HashMap::new();
            meta.insert("maxp_glyph_count".to_string(), glyph_count_maxp.to_string());
            meta.insert("cff2_charstring_count".to_string(), glyph_count_cff.to_string());
            meta.insert("cve".to_string(), "CVE-2025-27164".to_string());

            findings.push(FontFinding {
                kind: "font.cve_2025_27164".to_string(),
                severity: Severity::High,
                confidence: Confidence::Strong,
                title: "CVE-2025-27164: CFF2/maxp glyph count mismatch".to_string(),
                description: format!(
                    "Font has maxp.num_glyphs ({}) exceeding CFF2 charstring count ({}). This can lead to buffer overflow when accessing glyph data.",
                    glyph_count_maxp, glyph_count_cff
                ),
                meta,
            });
        }
    }
}

/// Validate gvar table structure for anomalies
#[cfg(feature = "dynamic")]
pub fn check_gvar_anomalies(context: &FontContext, findings: &mut Vec<FontFinding>) {
    if !context.has_gvar {
        return;
    }

    // Find gvar table
    if let Some(gvar_table) = context.tables.iter().find(|t| t.tag == "gvar") {
        // Check for excessively large gvar table (>10MB as per plan)
        const MAX_GVAR_SIZE: usize = 10 * 1024 * 1024;

        if gvar_table.length > MAX_GVAR_SIZE {
            let mut meta = HashMap::new();
            meta.insert("gvar_length".to_string(), gvar_table.length.to_string());
            meta.insert("max_allowed".to_string(), MAX_GVAR_SIZE.to_string());

            findings.push(FontFinding {
                kind: "font.anomalous_variation_table".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Heuristic,
                title: "Anomalous gvar table size".to_string(),
                description: format!(
                    "Font has excessively large gvar table ({} bytes), which may indicate malformed data or exploit attempt.",
                    gvar_table.length
                ),
                meta,
            });
        }
    }
}

/// Check for EBSC out-of-bounds (CVE-2023-26369)
#[cfg(feature = "dynamic")]
pub fn check_ebsc_oob(context: &FontContext, findings: &mut Vec<FontFinding>) {
    if !context.has_ebsc {
        return;
    }

    // Find EBSC table
    if let Some(ebsc_table) = context.tables.iter().find(|t| t.tag == "EBSC") {
        // EBSC table should be at least 8 bytes (version + numSizes)
        if ebsc_table.length < 8 {
            let mut meta = HashMap::new();
            meta.insert("ebsc_length".to_string(), ebsc_table.length.to_string());
            meta.insert("cve".to_string(), "CVE-2023-26369".to_string());

            findings.push(FontFinding {
                kind: "font.cve_2023_26369".to_string(),
                severity: Severity::High,
                confidence: Confidence::Probable,
                title: "CVE-2023-26369: EBSC table too small".to_string(),
                description: format!(
                    "Font has EBSC table with length {} bytes, which is too small and may lead to out-of-bounds reads.",
                    ebsc_table.length
                ),
                meta,
            });
        }
    }
}

// NOTE: Tests for hardcoded CVE checks have been removed.
// CVE detection is now handled by the signature system in signatures.rs.
// See crates/font-analysis/tests/integration_tests.rs for signature-based CVE detection tests.

#[cfg(test)]
mod tests {
    // Tests will be added here as needed for variable font-specific functionality
}
