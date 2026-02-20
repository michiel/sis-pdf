use crate::model::Finding;

#[derive(Debug, Clone)]
pub struct Taint {
    pub flagged: bool,
    pub reasons: Vec<String>,
    pub taint_sources: Vec<(u32, u16)>,
    pub taint_propagation: Vec<((u32, u16), (u32, u16))>,
}

pub fn taint_from_findings(findings: &[Finding]) -> Taint {
    let mut reasons = Vec::new();
    let mut taint_sources = Vec::new();
    let mut taint_propagation = Vec::new();
    for f in findings {
        if is_taint_finding_kind(&f.kind) {
            match f.kind.as_str() {
                "js_present" => reasons.push(js_taint_reason(f)),
                "embedded_file_present" => reasons.push("Embedded file present".into()),
                "decoder_risk_present" => reasons.push("High-risk decoder present".into()),
                "stream_length_mismatch" => reasons.push("Stream length mismatch".into()),
                "xref_conflict" => reasons.push("XRef conflict".into()),
                "image.jbig2_present" | "image.jpx_present" | "image.ccitt_present" => {
                    reasons.push("Risky image decoder present".into())
                }
                "image.jbig2_malformed"
                | "image.jpx_malformed"
                | "image.jpeg_malformed"
                | "image.ccitt_malformed"
                | "image.decode_failed"
                | "image.xfa_decode_failed" => reasons.push("Image decode failure observed".into()),
                "image.extreme_dimensions"
                | "image.pixel_count_excessive"
                | "image.suspect_strip_dimensions" => {
                    reasons.push("Suspicious image dimensions".into())
                }
                _ => {}
            }
            for obj in &f.objects {
                if let Some(obj_ref) = parse_object_ref(obj) {
                    taint_sources.push(obj_ref);
                }
            }
            collect_propagation_edges(f, &mut taint_propagation);
        }
    }
    reasons.sort();
    reasons.dedup();
    taint_sources.sort_unstable();
    taint_sources.dedup();
    taint_propagation.sort_unstable();
    taint_propagation.dedup();
    Taint { flagged: !reasons.is_empty(), reasons, taint_sources, taint_propagation }
}

fn js_taint_reason(f: &Finding) -> String {
    let mut details = Vec::new();
    if f.meta.get("js.ast_parsed").map(|v| v == "true").unwrap_or(false) {
        details.push("AST");
    }
    if f.meta.get("js.contains_eval").map(|v| v == "true").unwrap_or(false) {
        details.push("eval");
    }
    if f.meta.get("js.suspicious_apis").map(|v| v == "true").unwrap_or(false) {
        details.push("suspicious APIs");
    }
    if f.meta.get("js.obfuscation_suspected").map(|v| v == "true").unwrap_or(false) {
        details.push("obfuscation");
    }
    if details.is_empty() {
        "JavaScript present (no extra signals)".into()
    } else {
        format!("JavaScript present ({})", details.join(", "))
    }
}

fn is_taint_finding_kind(kind: &str) -> bool {
    matches!(
        kind,
        "js_present"
            | "embedded_file_present"
            | "decoder_risk_present"
            | "stream_length_mismatch"
            | "xref_conflict"
            | "image.jbig2_present"
            | "image.jpx_present"
            | "image.ccitt_present"
            | "image.jbig2_malformed"
            | "image.jpx_malformed"
            | "image.jpeg_malformed"
            | "image.ccitt_malformed"
            | "image.decode_failed"
            | "image.xfa_decode_failed"
            | "image.extreme_dimensions"
            | "image.pixel_count_excessive"
            | "image.suspect_strip_dimensions"
    )
}

fn collect_propagation_edges(finding: &Finding, out: &mut Vec<((u32, u16), (u32, u16))>) {
    let from = finding.meta.get("edge.from").and_then(|value| parse_object_ref(value));
    let to = finding.meta.get("edge.to").and_then(|value| parse_object_ref(value));
    if let (Some(from_ref), Some(to_ref)) = (from, to) {
        out.push((from_ref, to_ref));
        return;
    }

    let object_refs: Vec<(u32, u16)> =
        finding.objects.iter().filter_map(|obj| parse_object_ref(obj)).collect();
    for pair in object_refs.windows(2) {
        if let [from_ref, to_ref] = pair {
            out.push((*from_ref, *to_ref));
        }
    }
}

fn parse_object_ref(value: &str) -> Option<(u32, u16)> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    for idx in 0..parts.len().saturating_sub(1) {
        let obj = parts[idx].parse::<u32>().ok();
        let gen = parts[idx + 1].parse::<u16>().ok();
        if let (Some(obj), Some(gen)) = (obj, gen) {
            return Some((obj, gen));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AttackSurface, Confidence, Finding, Severity};
    use std::collections::HashMap;

    #[test]
    fn tracks_taint_sources_from_flagged_findings() {
        let mut finding = Finding::template(
            AttackSurface::JavaScript,
            "js_present",
            Severity::High,
            Confidence::Strong,
            "js",
            "present",
        );
        finding.objects = vec!["6 0 obj".into()];
        let taint = taint_from_findings(&[finding]);
        assert!(taint.flagged);
        assert_eq!(taint.taint_sources, vec![(6, 0)]);
    }

    #[test]
    fn prefers_edge_meta_for_taint_propagation() {
        let mut finding = Finding::template(
            AttackSurface::Actions,
            "stream_length_mismatch",
            Severity::Medium,
            Confidence::Strong,
            "mismatch",
            "stream",
        );
        finding.meta = HashMap::from([
            ("edge.from".to_string(), "obj 7 0".to_string()),
            ("edge.to".to_string(), "obj 8 0".to_string()),
        ]);
        let taint = taint_from_findings(&[finding]);
        assert_eq!(taint.taint_propagation, vec![((7, 0), (8, 0))]);
    }
}
