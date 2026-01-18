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
use std::sync::mpsc;
use std::time::Duration;

use model::{Confidence, DynamicAnalysisOutcome, FontFinding, Severity};
use static_scan::analyse_static;

const DYNAMIC_RISK_THRESHOLD: u32 = 2;

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
    if type1::is_type1_font(&font_data) {
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

    // Run dynamic analysis if enabled
    #[cfg(feature = "dynamic")]
    if config.dynamic_enabled && dynamic::available() {
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
                let mut meta = HashMap::new();
                meta.insert("font.dynamic_error".into(), err);
                findings.push(FontFinding {
                    kind: "font.dynamic_parse_failure".into(),
                    severity: Severity::High,
                    confidence: Confidence::Probable,
                    title: "Font parsing failed".into(),
                    description: "Dynamic font parsing failed in the runtime engine.".into(),
                    meta,
                });
            }
        }
    }

    if findings.len() >= 2 {
        findings.push(FontFinding {
            kind: "font.multiple_vuln_signals".into(),
            severity: Severity::High,
            confidence: Confidence::Probable,
            title: "Multiple font anomalies".into(),
            description: "Font exhibits multiple anomalous signals.".into(),
            meta: HashMap::new(),
        });
    }

    outcome.findings = findings;
    outcome
}

#[cfg(feature = "dynamic")]
#[derive(Debug)]
enum DynamicError {
    Timeout,
    Failure(String),
}

#[cfg(feature = "dynamic")]
fn run_dynamic_with_timeout(
    data: &[u8],
    timeout_ms: u64,
    config: &FontAnalysisConfig,
) -> Result<Vec<FontFinding>, DynamicError> {
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
