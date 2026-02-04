use crate::chain::ExploitChain;

pub fn render_path(chain: &ExploitChain) -> String {
    let findings_hint = format!("unknown (findings: {})", chain.findings.len());
    let trigger = chain
        .notes
        .get("trigger.label")
        .map(String::as_str)
        .or(chain.trigger.as_deref())
        .map(str::to_string)
        .or_else(|| chain.notes.get("correlation.object").map(|obj| format!("Object {}", obj)))
        .unwrap_or_else(|| findings_hint.clone());
    let mut action = chain
        .notes
        .get("action.label")
        .or_else(|| chain.notes.get("action.type"))
        .map(String::as_str)
        .or(chain.action.as_deref())
        .map(str::to_string)
        .unwrap_or_else(|| findings_hint.clone());
    if let Some(target) = chain.notes.get("action.target") {
        action = format!("{} [target: {}]", action, target);
    }
    let mut payload = chain
        .notes
        .get("payload.label")
        .or_else(|| chain.notes.get("payload.type"))
        .map(String::as_str)
        .or(chain.payload.as_deref())
        .map(str::to_string)
        .unwrap_or_else(|| findings_hint);
    if let Some(ref_chain) = chain.notes.get("payload.ref_chain") {
        payload = format!("{} [ref: {}]", payload, ref_chain);
    }
    if let Some(len) = chain.notes.get("payload.decoded_len") {
        payload = format!("{} [len: {}]", payload, len);
    }
    if let Some(summary) = chain.notes.get("payload.summary") {
        payload = format!("{} [{}]", payload, summary);
    }
    format!("Trigger:{} -> Action:{} -> Payload:{}", trigger, action, payload)
}
