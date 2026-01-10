use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::decode::stream_filters;
use sis_pdf_pdf::object::PdfAtom;

pub struct FilterChainDepthDetector;

impl Detector for FilterChainDepthDetector {
    fn id(&self) -> &'static str {
        "filter_chain_depth_high"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::StreamsAndFilters
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Moderate
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            if let PdfAtom::Stream(st) = &entry.atom {
                let filters = stream_filters(&st.dict);
                if filters.len() >= 3 {
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("filters.count".into(), filters.len().to_string());
                    meta.insert("filters.list".into(), filters.join(", "));
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "filter_chain_depth_high".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Probable,
                        title: "Deep filter chain".into(),
                        description: format!(
                            "Stream uses {} filters: {}.",
                            meta["filters.count"], meta["filters.list"]
                        ),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(st.dict.span, "Stream dict")],
                        remediation: Some(
                            "Inspect nested filter chains for obfuscation or decoder abuse.".into(),
                        ),
                        meta,
                        yara: None,
        position: None,
        positions: Vec::new(),
                    });
                }
            }
        }
        Ok(findings)
    }
}
