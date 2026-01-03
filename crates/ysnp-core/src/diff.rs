use crate::model::{AttackSurface, Confidence, EvidenceSource, EvidenceSpan, Finding, Severity};
use ysnp_pdf::ObjectGraph;

pub fn diff_graphs(
    bytes: &[u8],
    primary: &ObjectGraph<'_>,
    secondary: &ObjectGraph<'_>,
) -> Vec<Finding> {
    let evidence = keyword_evidence(bytes, b"startxref", "startxref marker", 3);
    let mut findings = Vec::new();
    if primary.objects.len() != secondary.objects.len() {
        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::FileStructure,
            kind: "parser_object_count_diff".into(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            title: "Parser object count mismatch".into(),
            description: format!(
                "Primary parser saw {} objects; secondary parser saw {} objects.",
                primary.objects.len(),
                secondary.objects.len()
            ),
            objects: vec!["object_graph".into()],
            evidence: evidence.clone(),
            remediation: Some("Investigate parser differential artifacts.".into()),
            meta: Default::default(),
        });
    }
    if primary.trailers.len() != secondary.trailers.len() {
        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::XRefTrailer,
            kind: "parser_trailer_count_diff".into(),
            severity: Severity::Low,
            confidence: Confidence::Probable,
            title: "Parser trailer count mismatch".into(),
            description: format!(
                "Primary parser saw {} trailers; secondary parser saw {} trailers.",
                primary.trailers.len(),
                secondary.trailers.len()
            ),
            objects: vec!["xref".into()],
            evidence: evidence.clone(),
            remediation: Some("Inspect xref and trailer sections.".into()),
            meta: Default::default(),
        });
    }
    if primary.startxrefs.len() != secondary.startxrefs.len() {
        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::XRefTrailer,
            kind: "parser_startxref_count_diff".into(),
            severity: Severity::Low,
            confidence: Confidence::Probable,
            title: "Parser startxref mismatch".into(),
            description: format!(
                "Primary parser found {} startxref markers; secondary parser found {}.",
                primary.startxrefs.len(),
                secondary.startxrefs.len()
            ),
            objects: vec!["startxref".into()],
            evidence,
            remediation: Some("Inspect incremental updates and xref offsets.".into()),
            meta: Default::default(),
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
