use crate::model::{AttackSurface, Confidence, EvidenceSource, EvidenceSpan, Finding, Severity};
use sis_pdf_pdf::ObjectGraph;
use std::io::Cursor;

const DIFF_SAMPLE_LIMIT: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffSummary {
    pub primary_objects: usize,
    pub secondary_objects: usize,
    pub primary_trailers: usize,
    pub secondary_trailers: usize,
    pub missing_in_secondary: usize,
    pub missing_in_primary: usize,
    pub missing_in_secondary_ids: Vec<(u32, u16)>,
    pub missing_in_primary_ids: Vec<(u32, u16)>,
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
    let mut missing_in_secondary_ids: Vec<(u32, u16)> =
        primary_ids.difference(&secondary_ids).copied().collect();
    let mut missing_in_primary_ids: Vec<(u32, u16)> =
        secondary_ids.difference(&primary_ids).copied().collect();
    missing_in_secondary_ids.sort_unstable();
    missing_in_primary_ids.sort_unstable();
    let missing_in_secondary = missing_in_secondary_ids.len();
    let missing_in_primary = missing_in_primary_ids.len();
    Ok(DiffSummary {
        primary_objects: primary.objects.len(),
        secondary_objects: doc.objects.len(),
        primary_trailers: primary.trailers.len(),
        secondary_trailers: doc.trailer.len(),
        missing_in_secondary,
        missing_in_primary,
        missing_in_secondary_ids,
        missing_in_primary_ids,
    })
}

pub fn diff_with_lopdf(bytes: &[u8], primary: &ObjectGraph<'_>) -> DiffResult {
    let evidence = keyword_evidence(bytes, b"startxref", "startxref marker", 3);
    let mut findings = Vec::new();
    let summary = match diff_summary(bytes, primary) {
        Ok(v) => v,
        Err(err) => {
            let mut finding = Finding::template(
                AttackSurface::FileStructure,
                "secondary_parser_failure",
                Severity::Low,
                Confidence::Probable,
                "Secondary parser failed",
                format!("lopdf failed to parse the document: {}", err),
            );
            finding.objects = vec!["parser".into()];
            finding.evidence = evidence;
            finding.remediation =
                Some("Compare with a stricter parser or inspect file integrity.".into());
            finding.meta.insert(
                "secondary_parser.error_class".into(),
                secondary_parser_error_class(&err).into(),
            );
            finding.meta.insert("secondary_parser.error_message".into(), err.to_string());
            findings.push(finding);
            return DiffResult { findings, summary: None, error: Some(err.to_string()) };
        }
    };
    if summary.primary_objects != summary.secondary_objects {
        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::FileStructure,
            kind: "parser_object_count_diff".into(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            impact: None,
            title: "Parser object count mismatch".into(),
            description: format!(
                "Primary parser saw {} objects; lopdf saw {} objects.",
                summary.primary_objects, summary.secondary_objects
            ),
            objects: vec!["object_graph".into()],
            evidence: evidence.clone(),
            remediation: Some("Investigate parser differential artifacts.".into()),
            meta: Default::default(),
            reader_impacts: Vec::new(),
            action_type: None,
            action_target: None,
            action_initiation: None,
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
            impact: None,
            title: "Parser trailer count mismatch".into(),
            description: format!(
                "Primary parser saw {} trailers; lopdf saw {} trailer entries.",
                summary.primary_trailers, summary.secondary_trailers
            ),
            objects: vec!["xref".into()],
            evidence: evidence.clone(),
            remediation: Some("Inspect xref and trailer sections.".into()),
            meta: Default::default(),
            reader_impacts: Vec::new(),
            action_type: None,
            action_target: None,
            action_initiation: None,
            yara: None,
            position: None,
            positions: Vec::new(),
        });
    }
    if summary.missing_in_secondary > 0 || summary.missing_in_primary > 0 {
        let secondary_id_samples = summary
            .missing_in_secondary_ids
            .iter()
            .take(DIFF_SAMPLE_LIMIT)
            .copied()
            .collect::<Vec<_>>();
        let primary_id_samples = summary
            .missing_in_primary_ids
            .iter()
            .take(DIFF_SAMPLE_LIMIT)
            .copied()
            .collect::<Vec<_>>();
        let secondary_offsets = sample_missing_offsets(primary, &secondary_id_samples);
        let secondary_hazards =
            sample_secondary_parse_hazards(primary, bytes, &secondary_id_samples);
        let primary_offsets = sample_missing_offsets(primary, &primary_id_samples);
        let mut meta = std::collections::HashMap::new();
        meta.insert("diff.missing_in_secondary".into(), summary.missing_in_secondary.to_string());
        meta.insert("diff.missing_in_primary".into(), summary.missing_in_primary.to_string());
        if !secondary_id_samples.is_empty() {
            meta.insert(
                "diff.missing_in_secondary_ids".into(),
                format_id_list(&secondary_id_samples),
            );
        }
        if !secondary_offsets.is_empty() {
            meta.insert("diff.missing_in_secondary_offsets".into(), secondary_offsets.join(", "));
        }
        if !secondary_hazards.is_empty() {
            meta.insert("diff.missing_in_secondary_hazards".into(), secondary_hazards.join(", "));
        }
        if !primary_id_samples.is_empty() {
            meta.insert("diff.missing_in_primary_ids".into(), format_id_list(&primary_id_samples));
        }
        if !primary_offsets.is_empty() {
            meta.insert("diff.missing_in_primary_offsets".into(), primary_offsets.join(", "));
        }
        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::FileStructure,
            kind: "parser_diff_structural".into(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            impact: None,
            title: "Structural parser differential".into(),
            description: format!(
                "Primary parser missing in lopdf: {}; lopdf-only objects: {}.",
                summary.missing_in_secondary, summary.missing_in_primary
            ),
            objects: vec!["object_graph".into()],
            evidence: evidence.clone(),
            remediation: Some("Inspect missing objects and xref consistency.".into()),
            meta,
            reader_impacts: Vec::new(),
            action_type: None,
            action_target: None,
            action_initiation: None,
            yara: None,
            position: None,
            positions: Vec::new(),
        });
        let mut meta = std::collections::HashMap::new();
        meta.insert("shadow.missing_in_secondary".into(), summary.missing_in_secondary.to_string());
        meta.insert("shadow.missing_in_primary".into(), summary.missing_in_primary.to_string());
        if !secondary_id_samples.is_empty() {
            meta.insert(
                "diff.missing_in_secondary_ids".into(),
                format_id_list(&secondary_id_samples),
            );
        }
        if !secondary_offsets.is_empty() {
            meta.insert("diff.missing_in_secondary_offsets".into(), secondary_offsets.join(", "));
        }
        if !secondary_hazards.is_empty() {
            meta.insert("diff.missing_in_secondary_hazards".into(), secondary_hazards.join(", "));
        }
        if !primary_id_samples.is_empty() {
            meta.insert("diff.missing_in_primary_ids".into(), format_id_list(&primary_id_samples));
        }
        if !primary_offsets.is_empty() {
            meta.insert("diff.missing_in_primary_offsets".into(), primary_offsets.join(", "));
        }
        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::FileStructure,
            kind: "object_shadow_mismatch".into(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            impact: None,
            title: "Object shadow mismatch".into(),
            description: format!(
                "Object sets differ between primary scan and xref-based parse (missing_in_secondary={}, missing_in_primary={}).",
                summary.missing_in_secondary, summary.missing_in_primary
            ),
            objects: vec!["object_graph".into()],
            evidence: evidence.clone(),
            remediation: Some("Compare recovered objects to xref entries for hidden revisions.".into()),
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
    DiffResult { findings, summary: Some(summary), error: None }
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

fn format_id_list(ids: &[(u32, u16)]) -> String {
    ids.iter().map(|(obj, generation)| format!("{obj} {generation}")).collect::<Vec<_>>().join(", ")
}

fn sample_missing_offsets(primary: &ObjectGraph<'_>, ids: &[(u32, u16)]) -> Vec<String> {
    ids.iter()
        .filter_map(|(obj, generation)| {
            primary
                .get_object(*obj, *generation)
                .map(|entry| format!("{} {}@{}", obj, generation, entry.full_span.start))
        })
        .collect()
}

fn sample_secondary_parse_hazards(
    primary: &ObjectGraph<'_>,
    bytes: &[u8],
    ids: &[(u32, u16)],
) -> Vec<String> {
    ids.iter()
        .filter_map(|(obj, generation)| {
            let entry = primary.get_object(*obj, *generation)?;
            let start = entry.full_span.start as usize;
            let end = entry.full_span.end as usize;
            if start >= end || end > bytes.len() {
                return None;
            }
            classify_secondary_parse_hazard(&bytes[start..end])
                .map(|hazard| format!("{obj} {generation}={hazard}"))
        })
        .collect()
}

fn classify_secondary_parse_hazard(raw_obj: &[u8]) -> Option<&'static str> {
    if raw_obj.windows(13).any(|w| w == b"/CreationDate") && raw_obj.windows(3).any(|w| w == b")Z)")
    {
        return Some("creation_date_trailing_timezone_token");
    }
    if has_unbalanced_literal_parentheses(raw_obj) {
        return Some("unbalanced_literal_string_parentheses");
    }
    None
}

fn has_unbalanced_literal_parentheses(raw_obj: &[u8]) -> bool {
    let mut depth = 0i32;
    let mut escaped = false;
    for byte in raw_obj {
        if escaped {
            escaped = false;
            continue;
        }
        if *byte == b'\\' {
            escaped = true;
            continue;
        }
        if *byte == b'(' {
            depth += 1;
        } else if *byte == b')' {
            depth -= 1;
            if depth < 0 {
                return true;
            }
        }
    }
    depth != 0
}

fn secondary_parser_error_class(err: &lopdf::Error) -> &'static str {
    let rendered = err.to_string();
    if rendered.contains("invalid file trailer") {
        "invalid_file_trailer"
    } else if rendered.contains("IndirectObject") {
        "invalid_indirect_object"
    } else if rendered.contains("Xref") || rendered.contains("xref") {
        "xref_parse_error"
    } else if rendered.contains("trailer") {
        "trailer_parse_error"
    } else {
        "parse_error"
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_secondary_parse_hazard, has_unbalanced_literal_parentheses};

    #[test]
    fn detects_creation_date_trailing_timezone_token_hazard() {
        let payload = b"1 0 obj\n<< /CreationDate (D:20250712160849)Z) >>\nendobj\n";
        assert_eq!(
            classify_secondary_parse_hazard(payload),
            Some("creation_date_trailing_timezone_token")
        );
    }

    #[test]
    fn detects_unbalanced_literal_parentheses_hazard() {
        let payload = b"2 0 obj\n<< /Producer (abc(def) >>\nendobj\n";
        assert!(has_unbalanced_literal_parentheses(payload));
        assert_eq!(
            classify_secondary_parse_hazard(payload),
            Some("unbalanced_literal_string_parentheses")
        );
    }
}
