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
use tracing::warn;

#[cfg(feature = "dynamic")]
const RENDERER_FONT_MARKER: &[u8] = b"CairoFont";

#[cfg(feature = "dynamic")]
fn matches_renderer_font_marker(data: &[u8]) -> bool {
    if data.len() < RENDERER_FONT_MARKER.len() + 8 {
        return false;
    }
    if data[0] != 0x01 {
        return false;
    }
    data.windows(RENDERER_FONT_MARKER.len()).any(|window| window == RENDERER_FONT_MARKER)
}

#[cfg(feature = "dynamic")]
pub fn analyse(data: &[u8]) -> Result<(), String> {
    // Try parsing with skrifa first (original behavior)
    use skrifa::FontRef;
    FontRef::new(data).map(|_| ()).map_err(|err| err.to_string())?;

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

    if matches_renderer_font_marker(data) {
        let mut meta = HashMap::new();
        meta.insert("renderer_font".to_string(), "cairo".to_string());
        meta.insert(
            "marker".to_string(),
            String::from_utf8_lossy(RENDERER_FONT_MARKER).to_string(),
        );
        findings.push(FontFinding {
            kind: "font.dynamic_renderer_font".to_string(),
            severity: Severity::Info,
            confidence: Confidence::Probable,
            title: "Renderer font skipped".to_string(),
            description: "Detected renderer-generated Cairo Type1/CFF blob; dynamic parsing is skipped because the dedicated Type 1 analyzer already covers this format."
                .to_string(),
            meta,
        });
        return findings;
    }

    // Parse font and extract context
    let context = match parser::parse_font(data) {
        Ok(ctx) => ctx,
        Err(err) => {
            let mut meta = HashMap::new();
            meta.insert("parse_error".to_string(), err.clone());
            let mut severity = Severity::Medium;
            if err.contains("UnknownMagic") {
                severity = Severity::Low;
                meta.insert("parse_error_class".to_string(), "unknown_magic".to_string());
            }
            findings.push(FontFinding {
                kind: "font.dynamic_parse_failure".to_string(),
                severity,
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
    let mut stats = HintingStats::default();
    // Extract hinting tables (fpgm, prep)
    if let Some(fpgm) = extract_table(data, b"fpgm") {
        if stats.should_skip() {
            stats.log_stack_guard();
        } else if !stats.warning_limit_reached() {
            let table_findings = ttf_vm::analyze_hinting_program(&fpgm, &limits);
            stats.record(&table_findings);
            findings.extend(table_findings);
            if stats.warning_limit_reached() {
                stats.log_limit();
            }
            if stats.stack_guard_reached() {
                stats.log_stack_guard();
            }
        }
    }

    if let Some(prep) = extract_table(data, b"prep") {
        if stats.should_skip() {
            stats.log_stack_guard();
        } else if !stats.warning_limit_reached() {
            let table_findings = ttf_vm::analyze_hinting_program(&prep, &limits);
            stats.record(&table_findings);
            findings.extend(table_findings);
            if stats.warning_limit_reached() {
                stats.log_limit();
            }
            if stats.stack_guard_reached() {
                stats.log_stack_guard();
            }
        }
    }

    stats.emit(&limits, findings);
}

const HINTING_TORTURE_THRESHOLD: usize = 3;
const HINTING_WARNING_LIMIT: usize = 200;
const HINTING_STACK_ERROR_GUARD: usize = 32;

#[derive(Default)]
pub(super) struct HintingStats {
    warnings: usize,
    tables_scanned: usize,
    highest_stack_depth: usize,
    highest_instruction_count: usize,
    highest_control_depth: usize,
    highest_push_loop_length: usize,
    instruction_history: Option<String>,
    limit_logged: bool,
    stack_errors: usize,
    guard_logged: bool,
}

impl HintingStats {
    fn record(&mut self, table_findings: &[FontFinding]) {
        self.tables_scanned += 1;
        for finding in table_findings {
            if finding.kind != "font.ttf_hinting_suspicious"
                && finding.kind != "font.ttf_hinting_push_loop"
            {
                continue;
            }
            self.warnings += 1;
            if let Some(error_kind) = finding.meta.get("error_kind") {
                if error_kind == "stack_overflow" || error_kind == "stack_underflow" {
                    self.stack_errors += 1;
                }
            }
            if let Some(stack_depth) =
                finding.meta.get("max_stack_depth").and_then(|value| value.parse::<usize>().ok())
            {
                self.highest_stack_depth = self.highest_stack_depth.max(stack_depth);
            }
            if let Some(instr_count) =
                finding.meta.get("instruction_count").and_then(|value| value.parse::<usize>().ok())
            {
                self.highest_instruction_count = self.highest_instruction_count.max(instr_count);
            }
            if let Some(control_depth) =
                finding.meta.get("control_depth").and_then(|value| value.parse::<usize>().ok())
            {
                self.highest_control_depth = self.highest_control_depth.max(control_depth);
            }
            if let Some(push_loop_length) =
                finding.meta.get("push_loop_length").and_then(|value| value.parse::<usize>().ok())
            {
                self.highest_push_loop_length = self.highest_push_loop_length.max(push_loop_length);
            }
            if self.instruction_history.is_none() {
                if let Some(history) = finding.meta.get("instruction_history") {
                    self.instruction_history = Some(history.clone());
                }
            }
        }
    }

    fn warning_limit_reached(&self) -> bool {
        self.warnings >= HINTING_WARNING_LIMIT
    }

    fn stack_guard_reached(&self) -> bool {
        self.stack_errors >= HINTING_STACK_ERROR_GUARD
    }

    fn should_skip(&self) -> bool {
        self.stack_guard_reached()
    }

    fn log_stack_guard(&mut self) {
        if !self.stack_guard_reached() || self.guard_logged {
            return;
        }
        self.guard_logged = true;
        warn!(
            "Hinting stack guard triggered ({} stack errors); skipping remaining tables",
            self.stack_errors
        );
    }

    fn log_limit(&mut self) {
        if self.limit_logged {
            return;
        }
        self.limit_logged = true;
        warn!(
            "Hinting warning limit reached ({} warnings); skipping remaining hinting tables",
            self.warnings
        );
    }

    fn should_emit(&self, limits: &ttf_vm::VmLimits) -> bool {
        if self.warnings == 0 {
            return false;
        }
        self.warnings >= HINTING_TORTURE_THRESHOLD
            || self.highest_stack_depth >= limits.max_stack_depth()
            || self.highest_instruction_count >= limits.max_instructions_per_glyph()
    }

    fn emit(self, limits: &ttf_vm::VmLimits, findings: &mut Vec<FontFinding>) {
        if self.should_skip() {
            return;
        }
        if !self.should_emit(limits) {
            return;
        }
        let mut meta = HashMap::new();
        meta.insert("hinting_warnings".to_string(), self.warnings.to_string());
        meta.insert("tables_scanned".to_string(), self.tables_scanned.to_string());
        meta.insert("max_stack_depth".to_string(), self.highest_stack_depth.to_string());
        meta.insert("instruction_count".to_string(), self.highest_instruction_count.to_string());
        meta.insert("control_depth".to_string(), self.highest_control_depth.to_string());
        if self.highest_push_loop_length > 0 {
            meta.insert("push_loop_length".to_string(), self.highest_push_loop_length.to_string());
        }
        if let Some(history) = &self.instruction_history {
            meta.insert("instruction_history".to_string(), history.clone());
        }
        findings.push(FontFinding {
            kind: "font.ttf_hinting_torture".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            title: "Hinting program torture detected".to_string(),
            description: "Multiple hinting programs exhaust the interpreter or stack budgets."
                .to_string(),
            meta,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, Severity};

    fn suspicious_hinting_finding(
        stack_depth: usize,
        instruction_count: usize,
        control_depth: usize,
        push_loop_length: Option<usize>,
    ) -> FontFinding {
        let mut meta = HashMap::new();
        meta.insert("max_stack_depth".to_string(), stack_depth.to_string());
        meta.insert("instruction_count".to_string(), instruction_count.to_string());
        meta.insert("control_depth".to_string(), control_depth.to_string());
        if let Some(length) = push_loop_length {
            meta.insert("push_loop_length".to_string(), length.to_string());
        }
        FontFinding {
            kind: "font.ttf_hinting_suspicious".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            title: "suspicious hinting".to_string(),
            description: "test".to_string(),
            meta,
        }
    }

    fn stack_error_finding(error_kind: &'static str) -> FontFinding {
        let mut finding = suspicious_hinting_finding(0, 0, 0, None);
        finding.meta.insert("error_kind".to_string(), error_kind.to_string());
        finding
    }

    #[test]
    fn hinting_torture_triggers_on_warning_count() {
        let limits = ttf_vm::VmLimits::default();
        let mut stats = HintingStats::default();
        let findings = vec![
            suspicious_hinting_finding(10, 50, 2, None),
            suspicious_hinting_finding(12, 60, 0, None),
            suspicious_hinting_finding(14, 70, 0, None),
        ];
        stats.record(&findings);
        let mut collected = Vec::new();
        stats.emit(&limits, &mut collected);
        assert!(
            collected.iter().any(|f| f.kind == "font.ttf_hinting_torture"),
            "Expected aggregate finding when warnings exceed threshold"
        );
    }

    #[test]
    fn hinting_torture_triggers_on_stack_limit() {
        let limits = ttf_vm::VmLimits::default();
        let mut stats = HintingStats::default();
        let findings = vec![suspicious_hinting_finding(limits.max_stack_depth(), 5, 3, None)];
        stats.record(&findings);
        let mut collected = Vec::new();
        stats.emit(&limits, &mut collected);
        assert!(
            collected.iter().any(|f| f.kind == "font.ttf_hinting_torture"),
            "Expected aggregate finding when stack limit is met"
        );
    }

    #[test]
    fn hinting_torture_not_triggered_for_single_safe_warning() {
        let limits = ttf_vm::VmLimits::default();
        let mut stats = HintingStats::default();
        let findings = vec![suspicious_hinting_finding(5, 5, 0, None)];
        stats.record(&findings);
        let mut collected = Vec::new();
        stats.emit(&limits, &mut collected);
        assert!(
            collected.is_empty(),
            "Should not emit aggregate finding for safe hinting programs"
        );
    }

    #[test]
    fn stack_guard_triggers_after_anomalies() {
        let mut stats = HintingStats::default();
        for _ in 0..HINTING_STACK_ERROR_GUARD {
            stats.record(&[stack_error_finding("stack_overflow")]);
        }
        assert!(stats.stack_guard_reached());
        assert!(stats.should_skip());
        assert!(!stats.guard_logged);
        stats.log_stack_guard();
        assert!(stats.guard_logged);
        let mut findings = Vec::new();
        stats.emit(&ttf_vm::VmLimits::default(), &mut findings);
        assert!(findings.is_empty(), "Guard should prevent aggregate finding emit");
    }

    #[test]
    fn hinting_stats_capture_control_depth_and_history() {
        let limits = ttf_vm::VmLimits::default();
        let mut stats = HintingStats::default();
        let mut first = suspicious_hinting_finding(6, 20, 5, None);
        first.meta.insert("instruction_history".to_string(), "0xB0@0,0xB1@1".to_string());
        let findings = vec![
            first,
            suspicious_hinting_finding(7, 21, 0, None),
            suspicious_hinting_finding(8, 22, 0, None),
        ];
        stats.record(&findings);
        let mut collected = Vec::new();
        stats.emit(&limits, &mut collected);
        assert!(
            collected.iter().any(|f| {
                if f.kind != "font.ttf_hinting_torture" {
                    return false;
                }
                f.meta.get("control_depth") == Some(&"5".to_string())
                    && f.meta.get("instruction_history") == Some(&"0xB0@0,0xB1@1".to_string())
            }),
            "Aggregate finding should include control depth and instruction history"
        );
    }

    #[test]
    fn hinting_stats_capture_push_loop_length() {
        let limits = ttf_vm::VmLimits::default();
        let mut stats = HintingStats::default();
        let findings = vec![
            suspicious_hinting_finding(6, 20, 0, Some(48)),
            suspicious_hinting_finding(6, 20, 0, None),
            suspicious_hinting_finding(6, 20, 0, None),
        ];
        stats.record(&findings);
        let mut collected = Vec::new();
        stats.emit(&limits, &mut collected);
        assert!(
            collected.iter().any(|f| {
                if f.kind != "font.ttf_hinting_torture" {
                    return false;
                }
                f.meta.get("push_loop_length") == Some(&"48".to_string())
            }),
            "Aggregate finding should include push loop length"
        );
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
