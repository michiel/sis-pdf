/// Finding correlation for content stream analysis (Stage 5).
///
/// Correlates scan report findings to a specific content stream by matching object
/// references, decoded evidence offsets, and finding kinds. Used by both the CLI
/// (`--with-findings`) and the GUI content stream panel.
use crate::model::{Confidence, EvidenceSource, Finding, Severity};

/// Finding from the scan report correlated to a content stream.
#[derive(Debug, Clone)]
pub struct CorrelatedStreamFinding {
    /// Finding ID for navigating to the findings panel.
    pub finding_id: String,
    /// Finding kind string (e.g. `"content_invisible_text"`).
    pub kind: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    /// Which anomaly variant this finding correlates to (e.g. `"InvisibleRenderingMode"`).
    pub anomaly_hint: Option<String>,
    /// Decoded stream byte offset of the matching evidence span, if any.
    pub decoded_offset: Option<u64>,
}

/// Finding kinds that can be correlated to individual content streams.
pub const STREAM_FINDING_KINDS: &[&str] = &[
    "stream_high_entropy",
    "stream_zlib_bomb",
    "content_invisible_text",
    "content_image_only_page",
    "content_overlay_link",
];

/// Map from content anomaly variant names to the corresponding finding kinds.
const ANOMALY_TO_FINDING: &[(&str, &str)] = &[
    ("InvisibleRenderingMode", "content_invisible_text"),
    ("ExcessiveKernOffset", "content_invisible_text"),
    ("ZeroScaleText", "content_invisible_text"),
];

/// Collect findings from `findings` correlated to stream `stream_ref` / page `page_ref`.
///
/// Correlation rules (all matching findings are included):
/// 1. Finding's `objects` list contains `"N G obj"` for `stream_ref` or `page_ref`.
/// 2. Finding has at least one `EvidenceSource::Decoded` evidence span whose `offset`
///    falls within `[raw_stream_offset, raw_stream_offset + decoded_stream_len]`.
/// 3. Finding kind is in `STREAM_FINDING_KINDS` and finding's `objects` contains `stream_ref`.
///
/// Deduplicates by finding ID. Returns findings sorted by severity (highest first).
pub fn correlate_content_stream_findings(
    findings: &[Finding],
    stream_ref: (u32, u16),
    page_ref: Option<(u32, u16)>,
    raw_stream_offset: u64,
    decoded_stream_len: u64,
) -> Vec<CorrelatedStreamFinding> {
    let stream_obj_str = format!("{} {} obj", stream_ref.0, stream_ref.1);
    let page_obj_str = page_ref.map(|(o, g)| format!("{} {} obj", o, g));

    let mut seen_ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut results: Vec<CorrelatedStreamFinding> = Vec::new();

    for finding in findings {
        // Check if already seen.
        if seen_ids.contains(finding.id.as_str()) {
            continue;
        }

        let matches_stream = finding.objects.iter().any(|o| o == &stream_obj_str);
        let matches_page = page_obj_str
            .as_deref()
            .map(|p| finding.objects.iter().any(|o| o == p))
            .unwrap_or(false);

        // Rule 1: direct object ref match.
        let matches_ref = matches_stream || matches_page;

        // Rule 2: decoded evidence span falls within stream range.
        let decoded_offset = finding.evidence.iter().find_map(|e| {
            if matches!(e.source, EvidenceSource::Decoded) {
                let offset = e.offset;
                if offset >= raw_stream_offset
                    && offset < raw_stream_offset.saturating_add(decoded_stream_len)
                {
                    return Some(offset);
                }
            }
            None
        });
        let matches_evidence = decoded_offset.is_some();

        // Rule 3: stream-level finding kind + stream ref.
        let matches_stream_kind =
            STREAM_FINDING_KINDS.contains(&finding.kind.as_str()) && matches_stream;

        if !matches_ref && !matches_evidence && !matches_stream_kind {
            continue;
        }

        // Determine anomaly hint from finding kind.
        let anomaly_hint = ANOMALY_TO_FINDING.iter().find_map(|(anomaly, kind)| {
            if *kind == finding.kind.as_str() {
                Some((*anomaly).to_string())
            } else {
                None
            }
        });

        seen_ids.insert(&finding.id);
        results.push(CorrelatedStreamFinding {
            finding_id: finding.id.clone(),
            kind: finding.kind.clone(),
            severity: finding.severity,
            confidence: finding.confidence,
            title: finding.title.clone(),
            anomaly_hint,
            decoded_offset,
        });
    }

    // Sort by severity descending (Critical > High > Medium > Low > Info).
    results.sort_by(|a, b| b.severity.cmp(&a.severity));
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AttackSurface, Confidence, EvidenceSource, EvidenceSpan, Finding, Severity,
    };

    fn make_finding(
        id: &str,
        kind: &str,
        severity: Severity,
        objects: Vec<String>,
        evidence: Vec<EvidenceSpan>,
    ) -> Finding {
        Finding {
            id: id.to_string(),
            surface: AttackSurface::ContentPhishing,
            kind: kind.to_string(),
            severity,
            confidence: Confidence::Probable,
            title: format!("Test finding {}", id),
            objects,
            evidence,
            ..Finding::default()
        }
    }

    fn decoded_span(offset: u64) -> EvidenceSpan {
        EvidenceSpan {
            source: EvidenceSource::Decoded,
            offset,
            length: 10,
            origin: None,
            note: None,
        }
    }

    #[test]
    fn correlate_finds_content_invisible_text_by_page_ref() {
        let page_ref = (7, 0u16);
        let finding = make_finding(
            "abc123",
            "content_invisible_text",
            Severity::Low,
            vec!["7 0 obj".to_string()],
            vec![],
        );
        let results =
            correlate_content_stream_findings(&[finding], (15, 0), Some(page_ref), 4096, 1024);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].finding_id, "abc123");
        assert_eq!(results[0].kind, "content_invisible_text");
    }

    #[test]
    fn correlate_finds_stream_high_entropy_by_stream_ref() {
        let finding = make_finding(
            "ent001",
            "stream_high_entropy",
            Severity::Medium,
            vec!["15 0 obj".to_string()],
            vec![],
        );
        let results = correlate_content_stream_findings(&[finding], (15, 0), None, 4096, 1024);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].kind, "stream_high_entropy");
    }

    #[test]
    fn correlate_deduplicates_same_finding() {
        // Finding matches both stream_ref and page_ref — should appear exactly once.
        let finding = make_finding(
            "dup001",
            "content_invisible_text",
            Severity::Low,
            vec!["15 0 obj".to_string(), "7 0 obj".to_string()],
            vec![],
        );
        let results =
            correlate_content_stream_findings(&[finding], (15, 0), Some((7, 0)), 4096, 1024);
        assert_eq!(results.len(), 1, "duplicate should be deduplicated");
    }

    #[test]
    fn correlate_returns_empty_for_unrelated_findings() {
        let finding = make_finding(
            "unrelated",
            "some_other_finding",
            Severity::High,
            vec!["99 0 obj".to_string()],
            vec![],
        );
        let results = correlate_content_stream_findings(&[finding], (15, 0), None, 4096, 1024);
        assert!(results.is_empty());
    }

    #[test]
    fn correlate_matches_decoded_evidence_offset() {
        let finding = make_finding(
            "ev001",
            "content_invisible_text",
            Severity::Low,
            vec!["99 0 obj".to_string()], // does not match by ref
            vec![decoded_span(5000)],     // but evidence falls within stream range
        );
        // Stream at raw_stream_offset=4096, decoded_len=2048 → range [4096, 6143]
        let results = correlate_content_stream_findings(&[finding], (15, 0), None, 4096, 2048);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded_offset, Some(5000));
    }

    #[test]
    fn correlate_evidence_outside_range_not_matched() {
        let finding = make_finding(
            "ev002",
            "content_invisible_text",
            Severity::Low,
            vec!["99 0 obj".to_string()],
            vec![decoded_span(10000)], // outside stream range
        );
        let results = correlate_content_stream_findings(&[finding], (15, 0), None, 4096, 1024);
        assert!(results.is_empty());
    }

    #[test]
    fn correlate_sorted_by_severity_descending() {
        let f1 = make_finding(
            "low",
            "content_invisible_text",
            Severity::Low,
            vec!["15 0 obj".to_string()],
            vec![],
        );
        let f2 = make_finding(
            "high",
            "stream_high_entropy",
            Severity::High,
            vec!["15 0 obj".to_string()],
            vec![],
        );
        let f3 = make_finding(
            "med",
            "stream_zlib_bomb",
            Severity::Medium,
            vec!["15 0 obj".to_string()],
            vec![],
        );
        let results = correlate_content_stream_findings(&[f1, f2, f3], (15, 0), None, 0, 0);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].severity, Severity::High);
        assert_eq!(results[1].severity, Severity::Medium);
        assert_eq!(results[2].severity, Severity::Low);
    }
}
