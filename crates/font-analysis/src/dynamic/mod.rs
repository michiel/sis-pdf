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
struct ParseFailureTriage {
    class: &'static str,
    severity: Severity,
    confidence: Confidence,
    exploit_relevance: &'static str,
    triage_bucket: &'static str,
    remediation: &'static str,
}

#[cfg(feature = "dynamic")]
fn classify_dynamic_parse_failure(err: &str, data_len: usize) -> ParseFailureTriage {
    let lower = err.to_ascii_lowercase();
    if lower.contains("unknownmagic")
        || lower.contains("unknown magic")
        || lower.contains("faceindexoutofbounds")
    {
        return ParseFailureTriage {
            class: "unknown_magic_or_face_index",
            severity: Severity::Low,
            confidence: Confidence::Weak,
            exploit_relevance: "low",
            triage_bucket: "noise_likely",
            remediation: "Confirm the object is an actual font stream before deep dynamic parsing.",
        };
    }

    if data_len < 64 && (lower.contains("font data too short") || lower.contains("eof")) {
        return ParseFailureTriage {
            class: "truncated_tiny_font",
            severity: Severity::Low,
            confidence: Confidence::Tentative,
            exploit_relevance: "low",
            triage_bucket: "noise_likely",
            remediation: "Treat as malformed/truncated input unless corroborating findings indicate active abuse.",
        };
    }

    if lower.contains("overflow")
        || lower.contains("underflow")
        || lower.contains("recursion")
        || lower.contains("stack")
    {
        return ParseFailureTriage {
            class: "parser_stress_signal",
            severity: Severity::High,
            confidence: Confidence::Strong,
            exploit_relevance: "high",
            triage_bucket: "exploit_relevant",
            remediation: "Correlate with structural anomalies and sandbox findings; treat as likely parser-targeting behaviour.",
        };
    }

    if lower.contains("malformedfont")
        || lower.contains("invalid")
        || lower.contains("outofbounds")
        || lower.contains("offset")
        || lower.contains("eof")
        || lower.contains("table")
    {
        return ParseFailureTriage {
            class: "malformed_structure",
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            exploit_relevance: "medium",
            triage_bucket: "needs_correlation",
            remediation: "Correlate malformed font layout with action/script/context findings to determine exploit relevance.",
        };
    }

    ParseFailureTriage {
        class: "dynamic_runtime_failure",
        severity: Severity::Medium,
        confidence: Confidence::Tentative,
        exploit_relevance: "medium",
        triage_bucket: "needs_correlation",
        remediation: "Capture additional parser/runtime context before escalating.",
    }
}

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
            let triage = classify_dynamic_parse_failure(&err, data.len());
            let mut meta = HashMap::new();
            meta.insert("parse_error".to_string(), err.clone());
            meta.insert("parse_error_class".to_string(), triage.class.to_string());
            meta.insert(
                "parse_error_exploit_relevance".to_string(),
                triage.exploit_relevance.to_string(),
            );
            meta.insert("parse_error_triage_bucket".to_string(), triage.triage_bucket.to_string());
            meta.insert("parse_error_remediation".to_string(), triage.remediation.to_string());
            meta.insert("font.dynamic_data_len".to_string(), data.len().to_string());
            findings.push(FontFinding {
                kind: "font.dynamic_parse_failure".to_string(),
                severity: triage.severity,
                confidence: triage.confidence,
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

#[cfg(all(test, feature = "dynamic"))]
mod parse_failure_tests {
    use super::{classify_dynamic_parse_failure, Confidence, Severity};

    #[test]
    fn classify_dynamic_parse_failure_marks_unknown_magic_as_noise() {
        let triage = classify_dynamic_parse_failure("Failed to parse font: UnknownMagic", 120);
        assert_eq!(triage.class, "unknown_magic_or_face_index");
        assert_eq!(triage.severity, Severity::Low);
        assert_eq!(triage.confidence, Confidence::Weak);
        assert_eq!(triage.triage_bucket, "noise_likely");
    }

    #[test]
    fn classify_dynamic_parse_failure_marks_malformed_font_as_medium() {
        let triage = classify_dynamic_parse_failure("Failed to parse font: MalformedFont", 2048);
        assert_eq!(triage.class, "malformed_structure");
        assert_eq!(triage.severity, Severity::Medium);
        assert_eq!(triage.confidence, Confidence::Probable);
        assert_eq!(triage.triage_bucket, "needs_correlation");
    }

    #[test]
    fn classify_dynamic_parse_failure_marks_parser_stress_as_high() {
        let triage = classify_dynamic_parse_failure("parser stack overflow while decoding", 4096);
        assert_eq!(triage.class, "parser_stress_signal");
        assert_eq!(triage.severity, Severity::High);
        assert_eq!(triage.confidence, Confidence::Strong);
        assert_eq!(triage.triage_bucket, "exploit_relevant");
    }
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
    // Check limits BEFORE calling analyze_hinting_program to avoid unnecessary work
    if let Some(fpgm) = extract_table(data, b"fpgm") {
        if stats.should_skip() {
            stats.mark_truncated("stack_error_guard");
        } else {
            let table_findings =
                ttf_vm::analyze_hinting_program(&fpgm, &limits, stats.should_skip());
            stats.record_and_limit(&table_findings, findings);
        }
    }

    if let Some(prep) = extract_table(data, b"prep") {
        if stats.should_skip() {
            stats.mark_truncated("stack_error_guard");
        } else {
            let table_findings =
                ttf_vm::analyze_hinting_program(&prep, &limits, stats.should_skip());
            stats.record_and_limit(&table_findings, findings);
        }
    }

    stats.emit(&limits, findings);
}

const HINTING_TORTURE_THRESHOLD: usize = 3;
const HINTING_TORTURE_STRONG_THRESHOLD: usize = 6;
/// Maximum hinting warnings before truncating analysis for this font
const HINTING_WARNING_LIMIT: usize = 50;
/// Maximum stack errors before aborting hinting analysis for this font
const HINTING_STACK_ERROR_GUARD: usize = 10;

#[derive(Default)]
pub(super) struct HintingStats {
    warnings: usize,
    tables_scanned: usize,
    kind_counts: HashMap<String, usize>,
    error_kind_counts: HashMap<String, usize>,
    sample_instruction_histories: Vec<String>,
    highest_stack_depth: usize,
    highest_instruction_count: usize,
    highest_control_depth: usize,
    highest_push_loop_length: usize,
    instruction_history: Option<String>,
    stack_errors: usize,
    /// Set when analysis was truncated due to limits
    truncated: bool,
    truncation_reason: Option<&'static str>,
}

impl HintingStats {
    /// Record findings and add to output, respecting limits
    fn record_and_limit(&mut self, table_findings: &[FontFinding], output: &mut Vec<FontFinding>) {
        self.tables_scanned += 1;
        for finding in table_findings {
            // Check limits before adding each finding
            if self.truncated {
                break;
            }

            // Track stats for relevant finding types
            if finding.kind == "font.ttf_hinting_suspicious"
                || finding.kind == "font.ttf_hinting_push_loop"
                || finding.kind == "font.ttf_hinting_control_flow_storm"
                || finding.kind == "font.ttf_hinting_call_storm"
            {
                self.warnings += 1;
                let kind_entry = self.kind_counts.entry(finding.kind.clone()).or_insert(0);
                *kind_entry = kind_entry.saturating_add(1);
                if let Some(error_kind) = finding.meta.get("error_kind") {
                    let error_entry = self.error_kind_counts.entry(error_kind.clone()).or_insert(0);
                    *error_entry = error_entry.saturating_add(1);
                    if error_kind == "stack_overflow" || error_kind == "stack_underflow" {
                        self.stack_errors += 1;
                    }
                }
                self.update_high_water_marks(finding);

                // Check limits after updating counters
                if self.stack_guard_reached() {
                    self.mark_truncated("stack_error_guard");
                    break;
                }
                if self.warning_limit_reached() {
                    self.mark_truncated("warning_limit");
                    break;
                }
            }

            // Only add finding to output if not truncated
            if !self.truncated {
                output.push(finding.clone());
            }
        }
    }

    fn update_high_water_marks(&mut self, finding: &FontFinding) {
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
        if let Some(history) = finding.meta.get("instruction_history") {
            if self.sample_instruction_histories.len() < 3
                && !self.sample_instruction_histories.iter().any(|sample| sample == history)
            {
                self.sample_instruction_histories.push(history.clone());
            }
        }
    }

    fn mark_truncated(&mut self, reason: &'static str) {
        if self.truncated {
            return;
        }
        self.truncated = true;
        self.truncation_reason = Some(reason);
        warn!(
            security = true,
            domain = "font.hinting",
            kind = "hinting_analysis_truncated",
            reason = reason,
            warnings = self.warnings,
            stack_errors = self.stack_errors,
            "[NON-FATAL][finding:hinting_analysis_truncated] Font hinting analysis truncated due to excessive anomalies"
        );
    }

    fn warning_limit_reached(&self) -> bool {
        self.warnings >= HINTING_WARNING_LIMIT
    }

    fn stack_guard_reached(&self) -> bool {
        self.stack_errors >= HINTING_STACK_ERROR_GUARD
    }

    fn should_skip(&self) -> bool {
        self.stack_guard_reached() || self.warning_limit_reached()
    }

    fn should_emit(&self, limits: &ttf_vm::VmLimits) -> bool {
        // Always emit if truncated
        if self.truncated {
            return true;
        }
        if self.warnings == 0 {
            return false;
        }
        let push_loop_count =
            self.kind_counts.get("font.ttf_hinting_push_loop").copied().unwrap_or(0);
        let has_control_storm =
            self.kind_counts.contains_key("font.ttf_hinting_control_flow_storm");
        let has_call_storm = self.kind_counts.contains_key("font.ttf_hinting_call_storm");

        let strong_warning_density = self.warnings >= HINTING_TORTURE_STRONG_THRESHOLD;
        let repeated_push_loops = push_loop_count >= 2 && self.highest_push_loop_length >= 32;
        let heavy_stack_pressure = self.stack_errors >= 3;
        let stack_budget_exceeded = self.highest_stack_depth >= limits.max_stack_depth();
        let instruction_budget_exceeded =
            self.highest_instruction_count >= limits.max_instructions_per_glyph();

        has_control_storm
            || has_call_storm
            || repeated_push_loops
            || heavy_stack_pressure
            || stack_budget_exceeded
            || instruction_budget_exceeded
            || strong_warning_density
    }

    fn emit(self, limits: &ttf_vm::VmLimits, findings: &mut Vec<FontFinding>) {
        if !self.should_emit(limits) {
            return;
        }

        let mut meta = HashMap::new();
        meta.insert("hinting_warnings".to_string(), self.warnings.to_string());
        meta.insert("tables_scanned".to_string(), self.tables_scanned.to_string());
        meta.insert("max_stack_depth".to_string(), self.highest_stack_depth.to_string());
        meta.insert("instruction_count".to_string(), self.highest_instruction_count.to_string());
        meta.insert("control_depth".to_string(), self.highest_control_depth.to_string());
        meta.insert("stack_errors".to_string(), self.stack_errors.to_string());
        let warnings_per_table = if self.tables_scanned == 0 {
            0.0
        } else {
            self.warnings as f64 / self.tables_scanned as f64
        };
        let stack_error_ratio =
            if self.warnings == 0 { 0.0 } else { self.stack_errors as f64 / self.warnings as f64 };
        meta.insert("warning_density".to_string(), format!("{warnings_per_table:.2}"));
        meta.insert("stack_error_ratio".to_string(), format!("{stack_error_ratio:.2}"));
        meta.insert("warning_threshold".to_string(), HINTING_TORTURE_THRESHOLD.to_string());
        meta.insert(
            "strong_warning_threshold".to_string(),
            HINTING_TORTURE_STRONG_THRESHOLD.to_string(),
        );
        if !self.kind_counts.is_empty() {
            meta.insert("kind_counts".to_string(), format_count_pairs(&self.kind_counts, 8));
        }
        if !self.error_kind_counts.is_empty() {
            meta.insert(
                "error_kind_counts".to_string(),
                format_count_pairs(&self.error_kind_counts, 8),
            );
        }

        if self.highest_push_loop_length > 0 {
            meta.insert("push_loop_length".to_string(), self.highest_push_loop_length.to_string());
        }
        if let Some(history) = &self.instruction_history {
            meta.insert("instruction_history".to_string(), history.clone());
        }
        if !self.sample_instruction_histories.is_empty() {
            meta.insert(
                "sample_instruction_histories".to_string(),
                self.sample_instruction_histories.join(" || "),
            );
        }

        // Add truncation metadata if analysis was limited
        if self.truncated {
            meta.insert("analysis_truncated".to_string(), "true".to_string());
            if let Some(reason) = self.truncation_reason {
                meta.insert("truncation_reason".to_string(), reason.to_string());
            }
            meta.insert("warning_limit".to_string(), HINTING_WARNING_LIMIT.to_string());
            meta.insert("stack_error_limit".to_string(), HINTING_STACK_ERROR_GUARD.to_string());
        }

        let (title, description) = if self.truncated {
            (
                "Font hinting analysis truncated".to_string(),
                format!(
                    "Hinting analysis was truncated after {} warnings ({} stack errors). \
                    This font contains excessive hinting anomalies that may indicate \
                    malformed or malicious font data designed to exhaust parser resources.",
                    self.warnings, self.stack_errors
                ),
            )
        } else {
            (
                "Hinting program torture detected".to_string(),
                "Multiple hinting programs exhaust the interpreter or stack budgets.".to_string(),
            )
        };

        warn!(
            security = true,
            domain = "font.hinting",
            kind = "hinting_program_anomaly_aggregate",
            warnings = self.warnings,
            tables_scanned = self.tables_scanned,
            stack_errors = self.stack_errors,
            kind_counts = %format_count_pairs(&self.kind_counts, 8),
            error_kind_counts = %format_count_pairs(&self.error_kind_counts, 8),
            sample_instruction_histories = %self.sample_instruction_histories.join(" || "),
            "[NON-FATAL][finding:font.ttf_hinting_torture] Aggregated hinting anomalies"
        );

        findings.push(FontFinding {
            kind: "font.ttf_hinting_torture".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Strong,
            title,
            description,
            meta,
        });
    }
}

fn format_count_pairs(counts: &HashMap<String, usize>, limit: usize) -> String {
    let mut pairs: Vec<(String, usize)> =
        counts.iter().map(|(kind, count)| (kind.clone(), *count)).collect();
    pairs.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    pairs
        .into_iter()
        .take(limit)
        .map(|(kind, count)| format!("{kind}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
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
    fn hinting_torture_triggers_on_strong_warning_density() {
        let limits = ttf_vm::VmLimits::default();
        let mut stats = HintingStats::default();
        let findings = vec![
            suspicious_hinting_finding(10, 50, 2, None),
            suspicious_hinting_finding(12, 60, 0, None),
            suspicious_hinting_finding(14, 70, 0, None),
            suspicious_hinting_finding(16, 80, 0, None),
            suspicious_hinting_finding(18, 90, 0, None),
            suspicious_hinting_finding(20, 100, 0, None),
        ];
        let mut output = Vec::new();
        stats.record_and_limit(&findings, &mut output);
        let mut collected = Vec::new();
        stats.emit(&limits, &mut collected);
        assert!(
            collected.iter().any(|f| f.kind == "font.ttf_hinting_torture"),
            "Expected aggregate finding when warnings exceed threshold"
        );
    }

    #[test]
    fn hinting_torture_not_triggered_for_sparse_push_loop_profile() {
        let limits = ttf_vm::VmLimits::default();
        let mut stats = HintingStats::default();
        let mut push_loop = suspicious_hinting_finding(12, 80, 1, Some(40));
        push_loop.kind = "font.ttf_hinting_push_loop".to_string();
        let findings = vec![
            suspicious_hinting_finding(10, 50, 1, None),
            suspicious_hinting_finding(11, 60, 1, None),
            push_loop,
        ];
        let mut output = Vec::new();
        stats.record_and_limit(&findings, &mut output);
        let mut collected = Vec::new();
        stats.emit(&limits, &mut collected);
        assert!(
            collected.iter().all(|f| f.kind != "font.ttf_hinting_torture"),
            "Sparse push-loop profile should not emit aggregate hinting torture finding"
        );
    }

    #[test]
    fn hinting_torture_triggers_on_stack_limit() {
        let limits = ttf_vm::VmLimits::default();
        let mut stats = HintingStats::default();
        let findings = vec![suspicious_hinting_finding(limits.max_stack_depth(), 5, 3, None)];
        let mut output = Vec::new();
        stats.record_and_limit(&findings, &mut output);
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
        let mut output = Vec::new();
        stats.record_and_limit(&findings, &mut output);
        let mut collected = Vec::new();
        stats.emit(&limits, &mut collected);
        assert!(
            collected.is_empty(),
            "Should not emit aggregate finding for safe hinting programs"
        );
    }

    #[test]
    fn stack_guard_triggers_and_emits_truncated_finding() {
        let mut stats = HintingStats::default();
        let mut output = Vec::new();
        // Generate enough stack errors to trigger the guard
        for _ in 0..HINTING_STACK_ERROR_GUARD {
            stats.record_and_limit(&[stack_error_finding("stack_overflow")], &mut output);
        }
        assert!(stats.stack_guard_reached());
        assert!(stats.should_skip());
        assert!(stats.truncated);

        let mut findings = Vec::new();
        stats.emit(&ttf_vm::VmLimits::default(), &mut findings);
        assert!(
            findings.iter().any(|f| {
                f.kind == "font.ttf_hinting_torture"
                    && f.meta.get("analysis_truncated") == Some(&"true".to_string())
                    && f.meta.get("truncation_reason") == Some(&"stack_error_guard".to_string())
            }),
            "Should emit truncated finding with metadata: {:?}",
            findings
        );
    }

    #[test]
    fn warning_limit_triggers_and_emits_truncated_finding() {
        let mut stats = HintingStats::default();
        let mut output = Vec::new();
        // Generate enough warnings to trigger the limit
        for _ in 0..HINTING_WARNING_LIMIT {
            stats.record_and_limit(&[suspicious_hinting_finding(5, 5, 0, None)], &mut output);
        }
        assert!(stats.warning_limit_reached());
        assert!(stats.should_skip());
        assert!(stats.truncated);

        let mut findings = Vec::new();
        stats.emit(&ttf_vm::VmLimits::default(), &mut findings);
        assert!(
            findings.iter().any(|f| {
                f.kind == "font.ttf_hinting_torture"
                    && f.meta.get("analysis_truncated") == Some(&"true".to_string())
                    && f.meta.get("truncation_reason") == Some(&"warning_limit".to_string())
            }),
            "Should emit truncated finding with metadata: {:?}",
            findings
        );
    }

    #[test]
    fn emitted_hinting_torture_includes_aggregated_counts() {
        let limits = ttf_vm::VmLimits::default();
        let mut stats = HintingStats::default();
        let mut output = Vec::new();
        let mut stack_overflow = suspicious_hinting_finding(12, 60, 2, None);
        stack_overflow.meta.insert("error_kind".to_string(), "stack_overflow".to_string());
        let mut push_loop = suspicious_hinting_finding(14, 80, 2, Some(16));
        push_loop.kind = "font.ttf_hinting_push_loop".to_string();
        push_loop.meta.insert("error_kind".to_string(), "push_loop_detected".to_string());
        let mut control_flow = suspicious_hinting_finding(18, 90, 4, None);
        control_flow.kind = "font.ttf_hinting_control_flow_storm".to_string();
        control_flow.meta.insert("error_kind".to_string(), "control_flow_storm".to_string());
        stats.record_and_limit(&[stack_overflow, push_loop, control_flow], &mut output);
        let mut collected = Vec::new();
        stats.emit(&limits, &mut collected);
        let finding = collected
            .iter()
            .find(|f| f.kind == "font.ttf_hinting_torture")
            .expect("expected aggregate finding");
        assert_eq!(
            finding.meta.get("kind_counts").map(|value| value.as_str()),
            Some(
                "font.ttf_hinting_control_flow_storm=1, font.ttf_hinting_push_loop=1, font.ttf_hinting_suspicious=1"
            )
        );
        assert_eq!(
            finding.meta.get("error_kind_counts").map(|value| value.as_str()),
            Some("control_flow_storm=1, push_loop_detected=1, stack_overflow=1")
        );
    }

    #[test]
    fn output_limited_when_warning_limit_reached() {
        let mut stats = HintingStats::default();
        let mut output = Vec::new();
        // Try to add more findings than the limit
        for _ in 0..(HINTING_WARNING_LIMIT + 20) {
            stats.record_and_limit(&[suspicious_hinting_finding(5, 5, 0, None)], &mut output);
        }
        // Output should be capped at the limit
        assert!(
            output.len() <= HINTING_WARNING_LIMIT,
            "Output should be limited to {} findings, got {}",
            HINTING_WARNING_LIMIT,
            output.len()
        );
        assert!(stats.truncated, "Should be marked as truncated");
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
            suspicious_hinting_finding(9, 23, 0, None),
            suspicious_hinting_finding(10, 24, 0, None),
            suspicious_hinting_finding(11, 25, 0, None),
        ];
        let mut output = Vec::new();
        stats.record_and_limit(&findings, &mut output);
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
            suspicious_hinting_finding(6, 20, 0, None),
            suspicious_hinting_finding(6, 20, 0, None),
            suspicious_hinting_finding(6, 20, 0, None),
        ];
        let mut output = Vec::new();
        stats.record_and_limit(&findings, &mut output);
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
