pub mod dynamic;
pub mod model;
pub mod static_scan;

pub use model::FontAnalysisConfig;

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
    let static_outcome = analyse_static(data);
    let mut findings = static_outcome.findings;

    let should_run_dynamic =
        config.dynamic_enabled && static_outcome.risk_score >= DYNAMIC_RISK_THRESHOLD;

    if should_run_dynamic && dynamic::available() {
        match run_dynamic_with_timeout(data, config.dynamic_timeout_ms) {
            Ok(()) => {}
            Err(DynamicError::Timeout) => {
                let mut meta = HashMap::new();
                meta.insert("font.dynamic_timeout_ms".into(), config.dynamic_timeout_ms.to_string());
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

#[derive(Debug)]
enum DynamicError {
    Timeout,
    Failure(String),
}

fn run_dynamic_with_timeout(data: &[u8], timeout_ms: u64) -> Result<(), DynamicError> {
    let (tx, rx) = mpsc::channel();
    let payload = data.to_vec();
    std::thread::spawn(move || {
        let result = dynamic::analyse(&payload);
        let _ = tx.send(result);
    });

    match rx.recv_timeout(Duration::from_millis(timeout_ms)) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(DynamicError::Failure(err)),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(DynamicError::Timeout),
        Err(_) => Err(DynamicError::Failure("dynamic worker error".into())),
    }
}
