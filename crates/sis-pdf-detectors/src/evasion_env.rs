use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;

use crate::{entry_dict, resolve_payload};

pub struct EnvProbeDetector;

impl Detector for EnvProbeDetector {
    fn id(&self) -> &'static str {
        "js_env_probe"
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
            let Some(dict) = entry_dict(entry) else { continue };
            if !dict.has_name(b"/S", b"/JavaScript") && dict.get_first(b"/JS").is_none() {
                continue;
            }
            let Some((_, obj)) = dict.get_first(b"/JS") else { continue };
            let payload = resolve_payload(ctx, obj);
            let Some(info) = payload.payload else { continue };
            if has_env_probes(&info.bytes) {
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "js_env_probe".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    title: "Environment probe in JavaScript".into(),
                    description: "JavaScript queries viewer or environment properties.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                    remediation: Some("Inspect conditional logic based on environment probes.".into()),
                    meta: Default::default(),
                    yara: None,
                });
            }
        }
        Ok(findings)
    }
}

fn has_env_probes(data: &[u8]) -> bool {
    contains_any(
        data,
        &[
            b"app.viewerType",
            b"app.viewerVersion",
            b"app.platform",
            b"app.language",
            b"navigator.userAgent",
            b"screen.height",
            b"screen.width",
        ],
    )
}

fn contains_any(data: &[u8], needles: &[&[u8]]) -> bool {
    needles.iter().any(|n| data.windows(n.len()).any(|w| w == *n))
}
