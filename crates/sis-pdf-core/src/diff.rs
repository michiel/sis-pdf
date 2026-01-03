use crate::model::{AttackSurface, Confidence, EvidenceSource, EvidenceSpan, Finding, Severity};
use std::io::Cursor;
use sis_pdf_pdf::ObjectGraph;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffSummary {
    pub primary_objects: usize,
    pub secondary_objects: usize,
    pub primary_trailers: usize,
    pub secondary_trailers: usize,
}

pub fn diff_summary(
    bytes: &[u8],
    primary: &ObjectGraph<'_>,
) -> Result<DiffSummary, lopdf::Error> {
    let doc = lopdf::Document::load_from(Cursor::new(bytes))?;
    Ok(DiffSummary {
        primary_objects: primary.objects.len(),
        secondary_objects: doc.objects.len(),
        primary_trailers: primary.trailers.len(),
        secondary_trailers: doc.trailer.len(),
    })
}

pub fn diff_with_lopdf(bytes: &[u8], primary: &ObjectGraph<'_>) -> Vec<Finding> {
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
                remediation: Some("Compare with a stricter parser or inspect file integrity.".into()),
                meta: Default::default(),
                yara: None,
            });
            return findings;
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
                summary.primary_objects,
                summary.secondary_objects
            ),
            objects: vec!["object_graph".into()],
            evidence: evidence.clone(),
            remediation: Some("Investigate parser differential artifacts.".into()),
            meta: Default::default(),
            yara: None,
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
                summary.primary_trailers,
                summary.secondary_trailers
            ),
            objects: vec!["xref".into()],
            evidence: evidence.clone(),
            remediation: Some("Inspect xref and trailer sections.".into()),
            meta: Default::default(),
            yara: None,
        });
    }
    findings
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
