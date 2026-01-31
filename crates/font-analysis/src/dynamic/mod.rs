mod parser;
#[cfg(feature = "dynamic")]
mod ttf_vm;
#[cfg(feature = "dynamic")]
mod variable_fonts;

pub use parser::{parse_font, FontContext, InstructionIssue, InvalidMagic, TableInfo};

use crate::model::FontFinding;
#[cfg(feature = "dynamic")]
use crate::model::{Confidence, Severity};
#[cfg(feature = "dynamic")]
use std::collections::HashMap;

#[cfg(feature = "dynamic")]
pub fn analyse(data: &[u8]) -> Result<(), String> {
    // Try parsing with skrifa first (original behavior)
    use skrifa::FontRef;
    FontRef::new(data)
        .map(|_| ())
        .map_err(|err| err.to_string())?;

    // Also try ttf-parser for more detailed analysis
    let _context = parser::parse_font(data)?;

    Ok(())
}

#[cfg(not(feature = "dynamic"))]
pub fn analyse(_data: &[u8]) -> Result<(), String> {
    Err("dynamic analysis not compiled".into())
}

#[cfg(feature = "dynamic")]
pub fn available() -> bool {
    true
}

#[cfg(not(feature = "dynamic"))]
pub fn available() -> bool {
    false
}

/// Perform comprehensive dynamic analysis and return findings
#[cfg(feature = "dynamic")]
pub fn analyze_with_findings(data: &[u8]) -> Vec<FontFinding> {
    analyze_with_findings_and_config(data, &crate::model::FontAnalysisConfig::default())
}

/// Perform comprehensive dynamic analysis with configuration
#[cfg(feature = "dynamic")]
pub fn analyze_with_findings_and_config(
    data: &[u8],
    config: &crate::model::FontAnalysisConfig,
) -> Vec<FontFinding> {
    let mut findings = Vec::new();

    // Parse font and extract context
    let context = match parser::parse_font(data) {
        Ok(ctx) => ctx,
        Err(err) => {
            let mut meta = HashMap::new();
            meta.insert("parse_error".to_string(), err);
            findings.push(FontFinding {
                kind: "font.dynamic_parse_failure".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                title: "Font parsing failed".to_string(),
                description: "Dynamic font parsing encountered an error".to_string(),
                meta,
            });
            return findings;
        }
    };

    // Check for CVE-specific issues (legacy hardcoded checks)
    variable_fonts::check_cve_2025_27163(&context, &mut findings);
    variable_fonts::check_cve_2025_27164(&context, &mut findings);
    variable_fonts::check_ebsc_oob(&context, &mut findings);
    variable_fonts::check_gvar_anomalies(&context, &mut findings);

    // Analyze TrueType hinting programs (fpgm, prep, cvt)
    analyze_hinting_tables(data, config, &mut findings);

    // Run signature-based CVE matching if enabled
    if config.signature_matching_enabled {
        match config.load_signatures() {
            Ok(signatures) => {
                if !signatures.is_empty() {
                    let mut registry = crate::signatures::SignatureRegistry::new();
                    for sig in signatures {
                        // Registry expects owned signatures
                        registry.add(sig);
                    }
                    let signature_findings = registry.match_signatures(&context);
                    findings.extend(signature_findings);
                }
            }
            Err(err) => {
                // Log error but don't fail the entire analysis
                let mut meta = HashMap::new();
                meta.insert("signature_error".to_string(), err);
                findings.push(FontFinding {
                    kind: "font.signature_load_failed".to_string(),
                    severity: Severity::Info,
                    confidence: Confidence::Probable,
                    title: "Signature loading failed".to_string(),
                    description: "Failed to load CVE signatures for matching".to_string(),
                    meta,
                });
            }
        }
    }

    findings
}

/// Analyze TrueType hinting tables for suspicious patterns
#[cfg(feature = "dynamic")]
fn analyze_hinting_tables(
    data: &[u8],
    config: &crate::model::FontAnalysisConfig,
    findings: &mut Vec<FontFinding>,
) {
    let limits = ttf_vm::VmLimits::from_config(config);
    // Extract hinting tables (fpgm, prep)
    if let Some(fpgm) = extract_table(data, b"fpgm") {
        findings.extend(ttf_vm::analyze_hinting_program(&fpgm, &limits));
    }

    if let Some(prep) = extract_table(data, b"prep") {
        findings.extend(ttf_vm::analyze_hinting_program(&prep, &limits));
    }
}

/// Extract a specific table from TrueType font data
#[cfg(feature = "dynamic")]
fn extract_table(data: &[u8], tag: &[u8; 4]) -> Option<Vec<u8>> {
    if data.len() < 12 {
        return None;
    }

    // Read number of tables
    let num_tables = u16::from_be_bytes([data[4], data[5]]);
    let table_dir_offset = 12;

    for i in 0..num_tables as usize {
        let offset = table_dir_offset + i * 16;
        if offset + 16 > data.len() {
            break;
        }

        let table_tag = &data[offset..offset + 4];
        if table_tag == tag {
            // Found the table - extract it
            let table_offset = u32::from_be_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
            ]) as usize;

            let table_length = u32::from_be_bytes([
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]) as usize;

            if table_offset + table_length <= data.len() {
                return Some(data[table_offset..table_offset + table_length].to_vec());
            }
        }
    }

    None
}

#[cfg(not(feature = "dynamic"))]
pub fn analyze_with_findings(_data: &[u8]) -> Vec<FontFinding> {
    Vec::new()
}
