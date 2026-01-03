use crate::model::{AttackSurface, Confidence, EvidenceSource, EvidenceSpan, Finding, Severity};
use std::io::Cursor;
use ysnp_pdf::ObjectGraph;

pub fn diff_with_lopdf(bytes: &[u8], primary: &ObjectGraph<'_>) -> Vec<Finding> {
    let evidence = keyword_evidence(bytes, b"startxref", "startxref marker", 3);
    let mut findings = Vec::new();
    let doc = match lopdf::Document::load_from(Cursor::new(bytes)) {
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
    let secondary_object_count = doc.objects.len();
    if primary.objects.len() != secondary_object_count {
        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::FileStructure,
            kind: "parser_object_count_diff".into(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            title: "Parser object count mismatch".into(),
            description: format!(
                "Primary parser saw {} objects; lopdf saw {} objects.",
                primary.objects.len(),
                secondary_object_count
            ),
            objects: vec!["object_graph".into()],
            evidence: evidence.clone(),
            remediation: Some("Investigate parser differential artifacts.".into()),
            meta: Default::default(),
            yara: None,
        });
    }
    let secondary_trailer_count = doc.trailer.len();
    if primary.trailers.len() != secondary_trailer_count {
        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::XRefTrailer,
            kind: "parser_trailer_count_diff".into(),
            severity: Severity::Low,
            confidence: Confidence::Probable,
            title: "Parser trailer count mismatch".into(),
            description: format!(
                "Primary parser saw {} trailers; lopdf saw {} trailer entries.",
                primary.trailers.len(),
                secondary_trailer_count
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
