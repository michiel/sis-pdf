use crate::model::Finding;

#[derive(Debug, Clone)]
pub struct Taint {
    pub flagged: bool,
    pub reasons: Vec<String>,
}

pub fn taint_from_findings(findings: &[Finding]) -> Taint {
    let mut reasons = Vec::new();
    for f in findings {
        match f.kind.as_str() {
            "js_present" => reasons.push(js_taint_reason(f)),
            "embedded_file_present" => reasons.push("Embedded file present".into()),
            "decoder_risk_present" => reasons.push("High-risk decoder present".into()),
            "stream_length_mismatch" => reasons.push("Stream length mismatch".into()),
            "xref_conflict" => reasons.push("XRef conflict".into()),
            _ => {}
        }
    }
    reasons.sort();
    reasons.dedup();
    Taint {
        flagged: !reasons.is_empty(),
        reasons,
    }
}

fn js_taint_reason(f: &Finding) -> String {
    let mut details = Vec::new();
    if f.meta
        .get("js.ast_parsed")
        .map(|v| v == "true")
        .unwrap_or(false)
    {
        details.push("AST");
    }
    if f.meta
        .get("js.contains_eval")
        .map(|v| v == "true")
        .unwrap_or(false)
    {
        details.push("eval");
    }
    if f.meta
        .get("js.suspicious_apis")
        .map(|v| v == "true")
        .unwrap_or(false)
    {
        details.push("suspicious APIs");
    }
    if f.meta
        .get("js.obfuscation_suspected")
        .map(|v| v == "true")
        .unwrap_or(false)
    {
        details.push("obfuscation");
    }
    if details.is_empty() {
        "JavaScript present (no extra signals)".into()
    } else {
        format!("JavaScript present ({})", details.join(", "))
    }
}
