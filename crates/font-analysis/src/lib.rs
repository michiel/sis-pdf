#![forbid(unsafe_code)]

pub mod color_fonts;
pub mod context;
pub mod dynamic;
pub mod model;
pub mod signatures;
pub mod static_scan;
pub mod type1;
pub mod variable_fonts;
pub mod woff;

pub use context::AnalysisContext;
pub use model::FontAnalysisConfig;
pub use signatures::{Signature, SignatureRegistry};

use std::collections::HashMap;
#[cfg(all(feature = "dynamic", not(target_arch = "wasm32")))]
use std::sync::mpsc;
#[cfg(all(feature = "dynamic", not(target_arch = "wasm32")))]
use std::time::Duration;

use model::{Confidence, DynamicAnalysisOutcome, FontFinding, Severity};
use static_scan::analyse_static;
use std::collections::HashSet;

/// Threshold for flagging fonts with multiple vulnerability signals
const DYNAMIC_RISK_THRESHOLD: usize = 2;
const HINTING_ONLY_MEDIUM_THRESHOLD: usize = 3;

pub fn analyse_font(data: &[u8], config: &FontAnalysisConfig) -> DynamicAnalysisOutcome {
    if !config.enabled {
        return DynamicAnalysisOutcome::default();
    }

    let mut outcome = DynamicAnalysisOutcome::default();

    // Handle WOFF/WOFF2 decompression
    let font_data = if woff::is_woff(data) || woff::is_woff2(data) {
        // Validate WOFF for decompression bombs before decompressing
        outcome.findings.extend(woff::validate_woff_decompression(data));

        // Attempt decompression if dynamic features enabled
        #[cfg(feature = "dynamic")]
        {
            match woff::decompress_woff(data) {
                Ok(decompressed) => decompressed,
                Err(e) => {
                    let mut meta = HashMap::new();
                    meta.insert("error".to_string(), e);
                    outcome.findings.push(FontFinding {
                        kind: "font.woff_decompression_failed".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Probable,
                        title: "WOFF decompression failed".into(),
                        description: "Failed to decompress WOFF/WOFF2 font".into(),
                        meta,
                    });
                    data.to_vec()
                }
            }
        }
        #[cfg(not(feature = "dynamic"))]
        {
            data.to_vec()
        }
    } else {
        data.to_vec()
    };

    // Check if this is a Type 1 font
    let is_type1 = type1::is_type1_font(&font_data);
    if is_type1 {
        let type1_findings = type1::analyze_type1(&font_data);
        outcome.findings.extend(type1_findings);
    }

    let static_outcome = analyse_static(&font_data);
    let mut findings = outcome.findings;
    findings.extend(static_outcome.findings);

    // Run variable font analysis
    findings.extend(variable_fonts::analyze_variable_font(&font_data));

    // Run color font analysis
    findings.extend(color_fonts::analyze_color_font(&font_data));

    // Run dynamic analysis if enabled (Type 1 fonts are handled by the Type 1 pipeline)
    #[cfg(feature = "dynamic")]
    if !is_type1 && config.dynamic_enabled && dynamic::available() {
        match run_dynamic_with_timeout(&font_data, config.dynamic_timeout_ms, config) {
            Ok(dynamic_findings) => {
                findings.extend(dynamic_findings);
            }
            Err(DynamicError::Timeout) => {
                let mut meta = HashMap::new();
                meta.insert(
                    "font.dynamic_timeout_ms".into(),
                    config.dynamic_timeout_ms.to_string(),
                );
                findings.push(FontFinding {
                    kind: "font.dynamic_timeout".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    title: "Font analysis timeout".into(),
                    description: "Dynamic font analysis exceeded the configured timeout.".into(),
                    meta,
                });
                outcome.timed_out = true;
            }
            Err(DynamicError::Failure(err)) => {
                findings.push(dynamic_worker_failure_finding(&err));
            }
        }
    }

    if let Some(finding) = aggregate_multiple_vuln_signals(&findings) {
        findings.push(finding);
    }

    outcome.findings = findings;
    outcome
}

fn is_hinting_kind(kind: &str) -> bool {
    matches!(
        kind,
        "font.ttf_hinting_torture"
            | "font.ttf_hinting_push_loop"
            | "font.ttf_hinting_control_flow_storm"
            | "font.ttf_hinting_call_storm"
            | "font.ttf_hinting_suspicious"
            | "font.suspicious_hinting"
    )
}

fn aggregate_multiple_vuln_signals(findings: &[FontFinding]) -> Option<FontFinding> {
    let risk_findings: Vec<&FontFinding> = findings
        .iter()
        .filter(|finding| matches!(finding.severity, Severity::Medium | Severity::High))
        .collect();
    if risk_findings.len() < DYNAMIC_RISK_THRESHOLD {
        return None;
    }

    let hinting_risk_count =
        risk_findings.iter().filter(|finding| is_hinting_kind(&finding.kind)).count();
    let non_hinting_risk_count = risk_findings.len().saturating_sub(hinting_risk_count);
    let high_signal_kinds: HashSet<&str> =
        risk_findings.iter().map(|finding| finding.kind.as_str()).collect();
    let has_control_flow_storm = high_signal_kinds.contains("font.ttf_hinting_control_flow_storm");
    let has_call_storm = high_signal_kinds.contains("font.ttf_hinting_call_storm");

    let (severity, confidence, profile) = if non_hinting_risk_count >= 2 {
        (Severity::High, Confidence::Probable, "correlated_multi_surface")
    } else if non_hinting_risk_count == 1 {
        (Severity::Medium, Confidence::Probable, "partially_correlated")
    } else if has_control_flow_storm || has_call_storm {
        (Severity::Medium, Confidence::Probable, "hinting_storm")
    } else if hinting_risk_count >= HINTING_ONLY_MEDIUM_THRESHOLD {
        (Severity::Medium, Confidence::Tentative, "hinting_only_dense")
    } else {
        (Severity::Low, Confidence::Tentative, "hinting_only_sparse")
    };

    let mut meta = HashMap::new();
    meta.insert("aggregate.risk_count".into(), risk_findings.len().to_string());
    meta.insert("aggregate.hinting_risk_count".into(), hinting_risk_count.to_string());
    meta.insert("aggregate.non_hinting_risk_count".into(), non_hinting_risk_count.to_string());
    meta.insert("aggregate.profile".into(), profile.to_string());

    Some(FontFinding {
        kind: "font.multiple_vuln_signals".into(),
        severity,
        confidence,
        title: "Multiple font anomalies".into(),
        description: format!(
            "Font exhibits {} medium/high anomaly signals (threshold: {}).",
            risk_findings.len(),
            DYNAMIC_RISK_THRESHOLD
        ),
        meta,
    })
}

#[cfg(feature = "dynamic")]
#[derive(Debug)]
enum DynamicError {
    Timeout,
    Failure(String),
}

#[cfg(feature = "dynamic")]
fn dynamic_worker_failure_finding(err: &str) -> FontFinding {
    let mut meta = HashMap::new();
    meta.insert("font.dynamic_error".into(), err.to_string());
    meta.insert("parse_error_class".into(), "dynamic_worker_failure".into());
    meta.insert("parse_error_exploit_relevance".into(), "low".into());
    meta.insert("parse_error_triage_bucket".into(), "runtime_infrastructure".into());
    meta.insert(
        "parse_error_remediation".into(),
        "Retry with runtime telemetry enabled; escalate only when corroborating font/structure findings exist."
            .into(),
    );
    FontFinding {
        kind: "font.dynamic_parse_failure".into(),
        severity: Severity::Low,
        confidence: Confidence::Tentative,
        title: "Font parsing failed".into(),
        description: "Dynamic font parsing failed in the runtime engine.".into(),
        meta,
    }
}

#[cfg(feature = "dynamic")]
fn run_dynamic_with_timeout(
    data: &[u8],
    timeout_ms: u64,
    config: &FontAnalysisConfig,
) -> Result<Vec<FontFinding>, DynamicError> {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = timeout_ms;
        return Ok(dynamic::analyze_with_findings_and_config(data, config));
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
    let (tx, rx) = mpsc::channel();
    let payload = data.to_vec();
    let config_clone = config.clone();
    std::thread::spawn(move || {
        let findings = dynamic::analyze_with_findings_and_config(&payload, &config_clone);
        let _ = tx.send(findings);
    });

    match rx.recv_timeout(Duration::from_millis(timeout_ms)) {
        Ok(findings) => Ok(findings),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(DynamicError::Timeout),
        Err(_) => Err(DynamicError::Failure("dynamic worker error".into())),
    }
    }
}

#[cfg(all(test, feature = "dynamic"))]
mod tests {
    use super::{
        aggregate_multiple_vuln_signals, dynamic_worker_failure_finding, Confidence, FontFinding,
        Severity,
    };
    use std::collections::HashMap;

    #[test]
    fn dynamic_worker_failure_finding_sets_low_relevance_metadata() {
        let finding = dynamic_worker_failure_finding("dynamic worker error");
        assert_eq!(finding.kind, "font.dynamic_parse_failure");
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.confidence, Confidence::Tentative);
        assert_eq!(
            finding.meta.get("parse_error_class"),
            Some(&"dynamic_worker_failure".to_string())
        );
        assert_eq!(
            finding.meta.get("parse_error_triage_bucket"),
            Some(&"runtime_infrastructure".to_string())
        );
    }

    fn finding(kind: &str, severity: Severity) -> FontFinding {
        FontFinding {
            kind: kind.to_string(),
            severity,
            confidence: Confidence::Probable,
            title: "test".to_string(),
            description: "test".to_string(),
            meta: HashMap::new(),
        }
    }

    #[test]
    fn aggregate_multiple_vuln_signals_downgrades_hinting_only_profiles() {
        let findings = vec![
            finding("font.ttf_hinting_push_loop", Severity::Medium),
            finding("font.ttf_hinting_torture", Severity::Medium),
        ];
        let aggregate = aggregate_multiple_vuln_signals(&findings).expect("aggregate finding");
        assert_eq!(aggregate.severity, Severity::Low);
        assert_eq!(aggregate.confidence, Confidence::Tentative);
        assert_eq!(
            aggregate.meta.get("aggregate.profile"),
            Some(&"hinting_only_sparse".to_string())
        );
    }

    #[test]
    fn aggregate_multiple_vuln_signals_keeps_high_for_correlated_non_hinting_profiles() {
        let findings = vec![
            finding("font.invalid_structure", Severity::High),
            finding("font.inconsistent_table_layout", Severity::Medium),
            finding("font.ttf_hinting_push_loop", Severity::Medium),
        ];
        let aggregate = aggregate_multiple_vuln_signals(&findings).expect("aggregate finding");
        assert_eq!(aggregate.severity, Severity::High);
        assert_eq!(aggregate.confidence, Confidence::Probable);
        assert_eq!(
            aggregate.meta.get("aggregate.profile"),
            Some(&"correlated_multi_surface".to_string())
        );
    }
}

#[cfg(test)]
mod aggregate_tests {
    use super::{aggregate_multiple_vuln_signals, Confidence, FontFinding, Severity};
    use std::collections::HashMap;

    fn finding(kind: &str, severity: Severity) -> FontFinding {
        FontFinding {
            kind: kind.to_string(),
            severity,
            confidence: Confidence::Probable,
            title: "test".to_string(),
            description: "test".to_string(),
            meta: HashMap::new(),
        }
    }

    #[test]
    fn aggregate_multiple_vuln_signals_downgrades_hinting_only_profiles() {
        let findings = vec![
            finding("font.ttf_hinting_push_loop", Severity::Medium),
            finding("font.ttf_hinting_torture", Severity::Medium),
        ];
        let aggregate = aggregate_multiple_vuln_signals(&findings).expect("aggregate finding");
        assert_eq!(aggregate.severity, Severity::Low);
        assert_eq!(aggregate.confidence, Confidence::Tentative);
        assert_eq!(
            aggregate.meta.get("aggregate.profile"),
            Some(&"hinting_only_sparse".to_string())
        );
    }

    #[test]
    fn aggregate_multiple_vuln_signals_keeps_high_for_correlated_non_hinting_profiles() {
        let findings = vec![
            finding("font.invalid_structure", Severity::High),
            finding("font.inconsistent_table_layout", Severity::Medium),
            finding("font.ttf_hinting_push_loop", Severity::Medium),
        ];
        let aggregate = aggregate_multiple_vuln_signals(&findings).expect("aggregate finding");
        assert_eq!(aggregate.severity, Severity::High);
        assert_eq!(aggregate.confidence, Confidence::Probable);
        assert_eq!(
            aggregate.meta.get("aggregate.profile"),
            Some(&"correlated_multi_surface".to_string())
        );
    }
}
