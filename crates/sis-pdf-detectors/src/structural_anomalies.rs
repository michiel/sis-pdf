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
        let null_object_count =
            ctx.graph.objects.iter().filter(|entry| matches!(entry.atom, PdfAtom::Null)).count()
                as u64;
        let canonical_trailer_size = ctx
            .graph
            .objects
            .iter()
            .map(|entry| entry.obj as u64)
            .max()
            .map(|max_obj_id| max_obj_id + 1)
            .unwrap_or(0);

        for (idx, trailer) in ctx.graph.trailers.iter().enumerate() {
            if let Some((_, size_obj)) = trailer.get_first(b"/Size") {
                if let PdfAtom::Int(declared) = size_obj.atom {
                    let declared_u64 = declared as u64;
                    if declared as u64 != actual_objects {
                        let mut meta = HashMap::new();
                        meta.insert("trailer.index".into(), idx.to_string());
                        meta.insert("trailer.declared_size".into(), declared.to_string());
                        meta.insert("parser.object_count".into(), actual_objects.to_string());
                        meta.insert(
                            "parser.max_object_id_plus_one".into(),
                            canonical_trailer_size.to_string(),
                        );
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
                    if declared_u64 != canonical_trailer_size {
                        let mut meta = HashMap::new();
                        meta.insert("trailer.index".into(), idx.to_string());
                        meta.insert("trailer.declared_size".into(), declared.to_string());
                        meta.insert(
                            "trailer.canonical_size".into(),
                            canonical_trailer_size.to_string(),
                        );
                        meta.insert("parser.object_count".into(), actual_objects.to_string());

                        findings.push(Finding {
                            id: String::new(),
                            surface: self.surface(),
                            kind: "pdf.trailer_size_noncanonical".into(),
                            severity: Severity::Low,
                            confidence: Confidence::Strong,
                            impact: Some(Impact::Low),
                            title: "Trailer /Size is non-canonical".into(),
                            description: format!(
                                "Trailer {} declares /Size {}, but canonical value from highest object id is {}.",
                                idx, declared, canonical_trailer_size
                            ),
                            objects: vec![format!("trailer.{}", idx)],
                            evidence: vec![span_to_evidence(trailer.span, "Trailer dictionary")],
                            remediation: Some(
                                "Validate trailer /Size against object numbering and xref sections."
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

        let phantom_deviations = ctx
            .graph
            .deviations
            .iter()
            .filter(|deviation| {
                deviation.kind == "xref_offset_oob"
                    || deviation.kind == "xref_trailer_search_invalid"
                    || deviation.kind.contains("xref_phantom")
            })
            .collect::<Vec<_>>();
        if !phantom_deviations.is_empty() {
            let mut meta = HashMap::new();
            let mut kinds = phantom_deviations
                .iter()
                .map(|deviation| deviation.kind.clone())
                .collect::<Vec<_>>();
            kinds.sort();
            kinds.dedup();
            meta.insert(
                "xref.phantom_deviation_count".into(),
                phantom_deviations.len().to_string(),
            );
            meta.insert("xref.phantom_deviation_kinds".into(), kinds.join(","));
            meta.insert("evasion.indicator".into(), "xref_phantom_entries".into());
            meta.insert("evasion.xref_phantom_entries".into(), "true".into());

            let mut evidence = phantom_deviations
                .iter()
                .take(3)
                .map(|deviation| span_to_evidence(deviation.span, "Xref deviation"))
                .collect::<Vec<_>>();
            if evidence.is_empty() {
                evidence.push(span_to_evidence(
                    sis_pdf_pdf::span::Span { start: 0, end: ctx.bytes.len() as u64 },
                    "Xref chain",
                ));
            }

            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::XRefTrailer,
                kind: "xref_phantom_entries".into(),
                severity: Severity::Low,
                confidence: Confidence::Probable,
                impact: Some(Impact::Low),
                title: "Xref phantom entries detected".into(),
                description:
                    "Xref deviations indicate offsets or trailer references that do not resolve cleanly."
                        .into(),
                objects: vec!["xref".into()],
                evidence,
                remediation: Some(
                    "Inspect xref sections and trailer chain consistency for evasive structure use."
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

        let mut trailer_roots = ctx
            .graph
            .xref_sections
            .iter()
            .filter_map(|section| section.trailer_root.as_ref())
            .cloned()
            .collect::<Vec<_>>();
        trailer_roots.sort();
        trailer_roots.dedup();
        if trailer_roots.len() > 1 {
            let mut meta = HashMap::new();
            meta.insert("trailer.root_conflict_count".into(), trailer_roots.len().to_string());
            meta.insert("trailer.root_values".into(), trailer_roots.join(", "));
            meta.insert("evasion.indicator".into(), "trailer_root_conflict".into());
            meta.insert("evasion.trailer_root_conflict".into(), "true".into());

            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::XRefTrailer,
                kind: "trailer_root_conflict".into(),
                severity: Severity::Low,
                confidence: Confidence::Strong,
                impact: Some(Impact::Low),
                title: "Conflicting trailer /Root references".into(),
                description: "Multiple xref sections declare different trailer /Root references."
                    .into(),
                objects: vec!["xref".into()],
                evidence: keyword_evidence(ctx.bytes, b"/Root", "Trailer /Root", 3),
                remediation: Some(
                    "Validate incremental update chain and determine authoritative trailer root."
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

        if actual_objects >= 8 {
            let null_ratio = null_object_count as f64 / actual_objects as f64;
            if null_object_count >= 6 && null_ratio >= 0.20 {
                let mut meta = HashMap::new();
                meta.insert("evasion.indicator".into(), "null_object_density".into());
                meta.insert("evasion.null_object_density".into(), "true".into());
                meta.insert("evasion.null_object_count".into(), null_object_count.to_string());
                meta.insert("evasion.total_object_count".into(), actual_objects.to_string());
                meta.insert("evasion.null_object_ratio".into(), format!("{null_ratio:.3}"));

                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::FileStructure,
                    kind: "null_object_density".into(),
                    severity: Severity::Low,
                    confidence: Confidence::Probable,
                    impact: Some(Impact::Low),
                    title: "High null object density".into(),
                    description:
                        "Object graph contains an unusually high density of null placeholder objects."
                            .into(),
                    objects: vec!["object_graph".into()],
                    evidence: vec![span_to_evidence(
                        sis_pdf_pdf::span::Span { start: 0, end: ctx.bytes.len() as u64 },
                        "Object graph summary",
                    )],
                    remediation: Some(
                        "Review unreferenced and null-heavy object regions for structural evasion."
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
        }

        Ok(findings)
    }
}

fn keyword_evidence(
    bytes: &[u8],
    needle: &[u8],
    label: &str,
    max_hits: usize,
) -> Vec<EvidenceSpan> {
    if needle.is_empty() || bytes.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + needle.len() <= bytes.len() && out.len() < max_hits {
        if &bytes[i..i + needle.len()] == needle {
            out.push(EvidenceSpan {
                source: EvidenceSource::File,
                offset: i as u64,
                length: needle.len() as u32,
                origin: None,
                note: Some(label.to_string()),
            });
            i += needle.len();
        } else {
            i += 1;
        }
    }
    out
}
