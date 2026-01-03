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
            "js_present" => reasons.push("JavaScript present".into()),
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
