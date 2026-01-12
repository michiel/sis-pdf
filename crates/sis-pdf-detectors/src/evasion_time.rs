use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;

use crate::{entry_dict, resolve_payload};

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
            let Some(dict) = entry_dict(entry) else {
                continue;
            };
            if !dict.has_name(b"/S", b"/JavaScript") && dict.get_first(b"/JS").is_none() {
                continue;
            }
            let Some((_, obj)) = dict.get_first(b"/JS") else {
                continue;
            };
            let payload = resolve_payload(ctx, obj);
            let Some(info) = payload.payload else {
                continue;
            };
            if has_time_evasion(&info.bytes) {
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "js_time_evasion".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    title: "Time-based evasion in JavaScript".into(),
                    description: "JavaScript references timing APIs that can delay execution."
                        .into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                    remediation: Some("Inspect for delayed or staged execution logic.".into()),
                    meta: Default::default(),
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                });
            }
        }
        Ok(findings)
    }
}

fn has_time_evasion(data: &[u8]) -> bool {
    contains_any(
        data,
        &[
            b"setTimeout",
            b"setInterval",
            b"Date(",
            b"performance.now",
            b"app.setTimeOut",
        ],
    )
}

fn contains_any(data: &[u8], needles: &[&[u8]]) -> bool {
    needles
        .iter()
        .any(|n| data.windows(n.len()).any(|w| w == *n))
}
