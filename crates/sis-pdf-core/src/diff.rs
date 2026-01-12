use crate::model::{AttackSurface, Confidence, EvidenceSource, EvidenceSpan, Finding, Severity};
use sis_pdf_pdf::ObjectGraph;
use std::io::Cursor;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffSummary {
    pub primary_objects: usize,
    pub secondary_objects: usize,
    pub primary_trailers: usize,
    pub secondary_trailers: usize,
    pub missing_in_secondary: usize,
    pub missing_in_primary: usize,
}

#[derive(Debug, Clone)]
pub struct DiffResult {
    pub findings: Vec<Finding>,
    pub summary: Option<DiffSummary>,
    pub error: Option<String>,
}

pub fn diff_summary(bytes: &[u8], primary: &ObjectGraph<'_>) -> Result<DiffSummary, lopdf::Error> {
    let doc = lopdf::Document::load_from(Cursor::new(bytes))?;
    let primary_ids: std::collections::HashSet<(u32, u16)> =
        primary.index.keys().cloned().collect();
    let secondary_ids: std::collections::HashSet<(u32, u16)> =
        doc.objects.keys().cloned().collect();
    let missing_in_secondary = primary_ids.difference(&secondary_ids).count();
    let missing_in_primary = secondary_ids.difference(&primary_ids).count();
    Ok(DiffSummary {
        primary_objects: primary.objects.len(),
        secondary_objects: doc.objects.len(),
        primary_trailers: primary.trailers.len(),
        secondary_trailers: doc.trailer.len(),
        missing_in_secondary,
        missing_in_primary,
    })
}

pub fn diff_with_lopdf(bytes: &[u8], primary: &ObjectGraph<'_>) -> DiffResult {
    let evidence = keyword_evidence(bytes, b"startxref", "startxref marker", 3);
    let mut findings = Vec::new();
    let summary = match diff_summary(bytes, primary) {
        Ok(v) => v,
        Err(err) => {
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::FileStructure,
                kind: "secondary_parser_failure".into(),
                severity: Severity::Low,
                confidence: Confidence::Probable,
                title: "Secondary parser failed".into(),
                description: format!("lopdf failed to parse the document: {}", err),
                objects: vec!["parser".into()],
                evidence,
                remediation: Some(
                    "Compare with a stricter parser or inspect file integrity.".into(),
                ),
                meta: Default::default(),
                yara: None,
                position: None,
                positions: Vec::new(),
            });
            return DiffResult {
                findings,
                summary: None,
                error: Some(err.to_string()),
            };
        }
    };
    if summary.primary_objects != summary.secondary_objects {
        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::FileStructure,
            kind: "parser_object_count_diff".into(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            title: "Parser object count mismatch".into(),
            description: format!(
                "Primary parser saw {} objects; lopdf saw {} objects.",
                summary.primary_objects, summary.secondary_objects
            ),
            objects: vec!["object_graph".into()],
            evidence: evidence.clone(),
            remediation: Some("Investigate parser differential artifacts.".into()),
            meta: Default::default(),
            yara: None,
            position: None,
            positions: Vec::new(),
        });
    }
    if summary.primary_trailers != summary.secondary_trailers {
        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::XRefTrailer,
            kind: "parser_trailer_count_diff".into(),
            severity: Severity::Low,
            confidence: Confidence::Probable,
            title: "Parser trailer count mismatch".into(),
            description: format!(
                "Primary parser saw {} trailers; lopdf saw {} trailer entries.",
                summary.primary_trailers, summary.secondary_trailers
            ),
            objects: vec!["xref".into()],
            evidence: evidence.clone(),
            remediation: Some("Inspect xref and trailer sections.".into()),
            meta: Default::default(),
            yara: None,
            position: None,
            positions: Vec::new(),
        });
    }
    if summary.missing_in_secondary > 0 || summary.missing_in_primary > 0 {
        let mut meta = std::collections::HashMap::new();
        meta.insert(
            "diff.missing_in_secondary".into(),
            summary.missing_in_secondary.to_string(),
        );
        meta.insert(
            "diff.missing_in_primary".into(),
            summary.missing_in_primary.to_string(),
        );
        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::FileStructure,
            kind: "parser_diff_structural".into(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            title: "Structural parser differential".into(),
            description: format!(
                "Primary parser missing in lopdf: {}; lopdf-only objects: {}.",
                summary.missing_in_secondary, summary.missing_in_primary
            ),
            objects: vec!["object_graph".into()],
            evidence: evidence.clone(),
            remediation: Some("Inspect missing objects and xref consistency.".into()),
            meta,
            yara: None,
            position: None,
            positions: Vec::new(),
        });
        let mut meta = std::collections::HashMap::new();
        meta.insert(
            "shadow.missing_in_secondary".into(),
            summary.missing_in_secondary.to_string(),
        );
        meta.insert(
            "shadow.missing_in_primary".into(),
            summary.missing_in_primary.to_string(),
        );
        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::FileStructure,
            kind: "object_shadow_mismatch".into(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            title: "Object shadow mismatch".into(),
            description: format!(
                "Object sets differ between primary scan and xref-based parse (missing_in_secondary={}, missing_in_primary={}).",
                summary.missing_in_secondary, summary.missing_in_primary
            ),
            objects: vec!["object_graph".into()],
            evidence: evidence.clone(),
            remediation: Some("Compare recovered objects to xref entries for hidden revisions.".into()),
            meta,
            yara: None,
        position: None,
        positions: Vec::new(),
        });
    }
    DiffResult {
        findings,
        summary: Some(summary),
        error: None,
    }
}

fn keyword_evidence(bytes: &[u8], keyword: &[u8], note: &str, limit: usize) -> Vec<EvidenceSpan> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + keyword.len() <= bytes.len() {
        if &bytes[i..i + keyword.len()] == keyword {
            out.push(EvidenceSpan {
                source: EvidenceSource::File,
                offset: i as u64,
                length: keyword.len() as u32,
                origin: None,
                note: Some(note.into()),
            });
            if out.len() >= limit {
                break;
            }
            i += keyword.len();
        } else {
            i += 1;
        }
    }
    out
}
