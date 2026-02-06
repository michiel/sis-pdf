use anyhow::Result;
use std::collections::HashMap;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_core::scan::span_to_evidence;

pub struct XrefTrailerSearchDetector;

impl Detector for XrefTrailerSearchDetector {
    fn id(&self) -> &'static str {
        "xref_trailer_search_invalid"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::XRefTrailer
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Cheap
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for dev in &ctx.graph.deviations {
            if dev.kind != "xref_trailer_search_invalid" {
                continue;
            }
            let mut meta = HashMap::new();
            if let Some(note) = &dev.note {
                meta.insert("trailer.search.note".into(), note.clone());
            }

            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "xref.trailer_search_invalid".into(),
                severity: Severity::Medium,
                confidence: Confidence::Strong,
                impact: Some(Impact::Medium),
                title: "Xref trailer search invalid".into(),
                description:
                    "Unable to locate the trailer keyword while scanning the XRef table.".into(),
                objects: vec!["xref".into()],
                evidence: vec![span_to_evidence(dev.span, "Xref trailer scan")],
                remediation: Some(
                    "Guard startxref/trailer offsets and verify the trailer dictionary before parsing."
                        .into(),
                ),
                meta,
                reader_impacts: Vec::new(),
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
            });
        }
        Ok(findings)
    }
}
