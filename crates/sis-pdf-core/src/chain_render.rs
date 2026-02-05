use crate::chain::ExploitChain;

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
