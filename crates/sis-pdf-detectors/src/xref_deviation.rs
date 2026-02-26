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
            meta.insert("xref.startxref.count".into(), ctx.graph.startxrefs.len().to_string());
            if let Some(last) = ctx.graph.startxrefs.last() {
                meta.insert("xref.startxref.last".into(), last.to_string());
            }
            meta.insert("xref.section.count".into(), ctx.graph.xref_sections.len().to_string());
            meta.insert("xref.trailer_scan.offset".into(), dev.span.start.to_string());
            meta.insert("xref.trailer_scan.length".into(), dev.span.len().to_string());
            if let Some(section) = ctx
                .graph
                .xref_sections
                .iter()
                .min_by_key(|section| section.offset.abs_diff(dev.span.start))
            {
                meta.insert("xref.section.kind".into(), section.kind.clone());
                meta.insert("xref.section.offset".into(), section.offset.to_string());
                meta.insert("xref.section.has_trailer".into(), section.has_trailer.to_string());
                if let Some(prev) = section.prev {
                    meta.insert("xref.section.prev".into(), prev.to_string());
                }
            }
            if let Some(note) = &dev.note {
                meta.insert("trailer.search.note".into(), note.clone());
            }
            meta.insert("query.next".into(), "xref.sections --verbose".into());

            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "xref.trailer_search_invalid".into(),
                severity: Severity::Medium,
                confidence: Confidence::Strong,
                impact: Impact::Medium,
                title: "Xref trailer search invalid".into(),
                description: format!(
                    "Trailer keyword search failed near offset {} (section kind: {}).",
                    dev.span.start,
                    meta.get("xref.section.kind").cloned().unwrap_or_else(|| "unknown".into())
                ),
                objects: vec!["xref".into()],
                evidence: vec![span_to_evidence(dev.span, "Xref trailer scan")],
                remediation: Some(
                    "Validate startxref offsets, inspect the matching xref section, and walk the /Prev chain for hidden updates."
                        .into(),
                ),
                meta,
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                positions: Vec::new(),
            });
        }
        Ok(findings)
    }
}
