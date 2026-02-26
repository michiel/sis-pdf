use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_core::scan::span_to_evidence;

use crate::js_payload_candidates_from_entry;

pub struct TimingEvasionDetector;

impl Detector for TimingEvasionDetector {
    fn id(&self) -> &'static str {
        "js_time_evasion"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::JavaScript
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Cheap
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            let candidates = js_payload_candidates_from_entry(ctx, entry);
            if candidates.is_empty() {
                continue;
            }
            for candidate in candidates {
                if !has_time_evasion(&candidate.payload.bytes) {
                    continue;
                }
                let mut evidence = candidate.evidence;
                if evidence.is_empty() {
                    evidence.push(span_to_evidence(entry.full_span, "JavaScript object"));
                }
                let mut meta = std::collections::HashMap::new();
                if let Some(label) = candidate.source.meta_value() {
                    meta.insert("js.source".into(), label.into());
                }
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "js_time_evasion".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    impact: Impact::Unknown,
                    title: "Time-based evasion in JavaScript".into(),
                    description: "JavaScript references timing APIs that can delay execution."
                        .into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence,
                    remediation: Some("Inspect for delayed or staged execution logic.".into()),
                    meta,
                    yara: None,
                    positions: Vec::new(),
                    ..Finding::default()
                });
            }
        }
        Ok(findings)
    }
}

fn has_time_evasion(data: &[u8]) -> bool {
    contains_any(
        data,
        &[b"setTimeout", b"setInterval", b"Date(", b"performance.now", b"app.setTimeOut"],
    )
}

fn contains_any(data: &[u8], needles: &[&[u8]]) -> bool {
    needles.iter().any(|n| data.windows(n.len()).any(|w| w == *n))
}
