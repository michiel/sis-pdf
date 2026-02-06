use anyhow::Result;
use std::collections::HashMap;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{
    AttackSurface, Confidence, EvidenceSource, EvidenceSpan, Finding, Impact, Severity,
};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::PdfAtom;

pub struct StructuralAnomaliesDetector;

impl Detector for StructuralAnomaliesDetector {
    fn id(&self) -> &'static str {
        "structural_anomalies"
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
        let actual_objects = ctx.graph.objects.len() as u64;

        for (idx, trailer) in ctx.graph.trailers.iter().enumerate() {
            if let Some((_, size_obj)) = trailer.get_first(b"/Size") {
                if let PdfAtom::Int(declared) = size_obj.atom {
                    if declared as u64 != actual_objects {
                        let mut meta = HashMap::new();
                        meta.insert("trailer.index".into(), idx.to_string());
                        meta.insert("trailer.declared_size".into(), declared.to_string());
                        meta.insert("parser.object_count".into(), actual_objects.to_string());
                        meta.insert(
                            "trailer.size_diff".into(),
                            (declared as i64 - actual_objects as i64).abs().to_string(),
                        );

                        findings.push(Finding {
                            id: String::new(),
                            surface: self.surface(),
                            kind: "pdf.trailer_inconsistent".into(),
                            severity: Severity::Medium,
                            confidence: Confidence::Strong,
                            impact: Some(Impact::Medium),
                            title: "Trailer /Size disagrees with parsed objects".into(),
                            description: format!(
                                "Trailer {} declares /Size {} but parser saw {} objects.",
                                idx, declared, actual_objects
                            ),
                            objects: vec![format!("trailer.{}", idx)],
                            evidence: vec![span_to_evidence(trailer.span, "Trailer dictionary")],
                            remediation: Some(
                                "Inspect xref/trailer sections for tampering.".into(),
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
                }
            }
        }

        let file_len = ctx.bytes.len() as u64;
        for (idx, offset) in ctx.graph.startxrefs.iter().enumerate() {
            if *offset > file_len {
                let mut meta = HashMap::new();
                meta.insert("xref.index".into(), idx.to_string());
                meta.insert("xref.offset".into(), offset.to_string());
                meta.insert("file.length".into(), file_len.to_string());

                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::FileStructure,
                    kind: "xref_start_offset_oob".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    impact: Some(Impact::Medium),
                    title: "Startxref offset out of file bounds".into(),
                    description: format!(
                        "startxref[{}] = {} is beyond file length {}.",
                        idx, offset, file_len
                    ),
                    objects: vec![format!("startxref.{}", idx)],
                    evidence: vec![EvidenceSpan {
                        source: EvidenceSource::File,
                        offset: *offset,
                        length: 4,
                        origin: None,
                        note: Some("startxref pointer".into()),
                    }],
                    remediation: Some("Validate xref offsets before parsing.".into()),
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
        }

        Ok(findings)
    }
}
