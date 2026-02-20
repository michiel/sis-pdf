use crate::chain::ExploitChain;
use std::fmt::Write;

fn findings_hint(chain: &ExploitChain) -> String {
    format!("unknown (findings: {})", chain.findings.len())
}

pub fn chain_trigger_label(chain: &ExploitChain) -> String {
    chain
        .notes
        .get("trigger.label")
        .map(String::as_str)
        .or(chain.trigger.as_deref())
        .map(str::to_string)
        .or_else(|| chain.notes.get("correlation.object").map(|obj| format!("Object {}", obj)))
        .unwrap_or_else(|| findings_hint(chain))
}

pub fn chain_action_label(chain: &ExploitChain) -> String {
    let hint = findings_hint(chain);
    let mut action = chain
        .notes
        .get("action.label")
        .or_else(|| chain.notes.get("action.type"))
        .map(String::as_str)
        .or(chain.action.as_deref())
        .map(str::to_string)
        .unwrap_or_else(|| hint.clone());
    if let Some(target) = chain.notes.get("action.target") {
        if !target.is_empty() {
            action = format!("{} [target: {}]", action, target);
        }
    }
    action
}

pub fn chain_payload_label(chain: &ExploitChain) -> String {
    let hint = findings_hint(chain);
    let mut payload = chain
        .notes
        .get("payload.label")
        .or_else(|| chain.notes.get("payload.type"))
        .map(String::as_str)
        .or(chain.payload.as_deref())
        .map(str::to_string)
        .unwrap_or_else(|| hint.clone());
    if let Some(ref_chain) = chain.notes.get("payload.ref_chain") {
        payload = format!("{} [ref: {}]", payload, ref_chain);
    }
    if let Some(len) = chain.notes.get("payload.decoded_len") {
        if !len.is_empty() {
            payload = format!("{} [len: {}]", payload, len);
        }
    }
    if let Some(summary) = chain.notes.get("payload.summary") {
        if !summary.is_empty() {
            payload = format!("{} [{}]", payload, summary);
        }
    }
    payload
}

pub fn render_path(chain: &ExploitChain) -> String {
    format!(
        "Trigger:{} -> Action:{} -> Payload:{}",
        chain_trigger_label(chain),
        chain_action_label(chain),
        chain_payload_label(chain)
    )
}

fn split_delimited(value: &str) -> Vec<String> {
    value
        .split([',', ';'])
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn compose_chain_narrative(chain: &ExploitChain) -> String {
    let trigger = chain_trigger_label(chain);
    let action = chain_action_label(chain);
    let payload = chain_payload_label(chain);
    let mut parts = vec![format!("{trigger} drives {action}, delivering {payload}.")];

    if !chain.confirmed_stages.is_empty() {
        parts.push(format!("Confirmed stages: {}.", chain.confirmed_stages.join(" -> ")));
    }
    if !chain.inferred_stages.is_empty() {
        parts.push(format!("Inferred stages: {}.", chain.inferred_stages.join(" -> ")));
    }

    let completeness = (chain.chain_completeness * 100.0).round();
    if completeness > 0.0 {
        parts.push(format!("Chain completeness: {:.0}%.", completeness));
    }

    if let Some(raw_outcomes) = chain.notes.get("exploit.outcomes") {
        let outcomes = split_delimited(raw_outcomes);
        if !outcomes.is_empty() {
            parts.push(format!("Likely outcomes: {}.", outcomes.join(", ")));
        }
    }

    if let Some(fragment_count) = chain.notes.get("scatter.fragment_count") {
        if !fragment_count.trim().is_empty() {
            parts.push(format!("Payload scatter evidence: {} fragments.", fragment_count.trim()));
        }
    }

    if !chain.active_mitigations.is_empty() {
        parts.push(format!("Active mitigations: {}.", chain.active_mitigations.join(", ")));
    }
    if !chain.unmet_conditions.is_empty() {
        parts.push(format!("Unmet preconditions: {}.", chain.unmet_conditions.join(", ")));
    }

    if !chain.reader_risk.is_empty() {
        let mut reader_risks = chain
            .reader_risk
            .iter()
            .map(|(reader, severity)| (reader.as_str(), severity.as_str()))
            .collect::<Vec<_>>();
        reader_risks.sort_by_key(|(reader, _)| *reader);
        let mut line = String::new();
        for (index, (reader, severity)) in reader_risks.iter().enumerate() {
            if index > 0 {
                line.push_str(", ");
            }
            let _ = write!(line, "{reader}={severity}");
        }
        if !line.is_empty() {
            parts.push(format!("Reader risk: {line}."));
        }
    }

    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::compose_chain_narrative;
    use crate::chain::ExploitChain;
    use std::collections::HashMap;

    fn base_chain() -> ExploitChain {
        ExploitChain {
            id: "chain-1".into(),
            group_id: None,
            group_count: 1,
            group_members: Vec::new(),
            trigger: Some("open_action_present".into()),
            action: Some("js_present".into()),
            payload: Some("javascript".into()),
            findings: vec!["f1".into()],
            score: 0.0,
            reasons: Vec::new(),
            path: String::new(),
            nodes: Vec::new(),
            edges: Vec::new(),
            confirmed_stages: vec!["input".into(), "execute".into()],
            inferred_stages: vec!["egress".into()],
            chain_completeness: 0.6,
            reader_risk: HashMap::new(),
            narrative: String::new(),
            finding_criticality: HashMap::new(),
            active_mitigations: Vec::new(),
            required_conditions: Vec::new(),
            unmet_conditions: Vec::new(),
            notes: HashMap::new(),
        }
    }

    #[test]
    fn compose_chain_narrative_includes_context_sections() {
        let mut chain = base_chain();
        chain.notes.insert("exploit.outcomes".into(), "script_execution; data_exfiltration".into());
        chain.notes.insert("scatter.fragment_count".into(), "4".into());
        chain.reader_risk.insert("acrobat".into(), "Critical".into());
        chain.reader_risk.insert("pdfjs".into(), "High".into());
        chain.active_mitigations = vec!["sandbox_enabled".into()];
        chain.unmet_conditions = vec!["egress_allowed".into()];

        let narrative = compose_chain_narrative(&chain);
        assert!(narrative.contains("open_action_present drives js_present"));
        assert!(narrative.contains("Confirmed stages: input -> execute."));
        assert!(narrative.contains("Inferred stages: egress."));
        assert!(narrative.contains("Chain completeness: 60%."));
        assert!(narrative.contains("Likely outcomes: script_execution, data_exfiltration."));
        assert!(narrative.contains("Payload scatter evidence: 4 fragments."));
        assert!(narrative.contains("Active mitigations: sandbox_enabled."));
        assert!(narrative.contains("Unmet preconditions: egress_allowed."));
        assert!(narrative.contains("Reader risk: acrobat=Critical, pdfjs=High."));
    }

    #[test]
    fn compose_chain_narrative_is_stable_without_optional_fields() {
        let chain = base_chain();
        let narrative = compose_chain_narrative(&chain);
        assert!(narrative.contains("open_action_present drives js_present"));
        assert!(narrative.contains("Chain completeness: 60%."));
        assert!(!narrative.contains("Likely outcomes:"));
        assert!(!narrative.contains("Payload scatter evidence:"));
        assert!(!narrative.contains("Active mitigations:"));
        assert!(!narrative.contains("Unmet preconditions:"));
    }
}
