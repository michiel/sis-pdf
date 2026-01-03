use crate::chain::ExploitChain;

pub fn render_path(chain: &ExploitChain) -> String {
    let trigger = chain.trigger.as_deref().unwrap_or("-");
    let action = chain
        .notes
        .get("action.type")
        .map(String::as_str)
        .or(chain.action.as_deref())
        .unwrap_or("-");
    let payload = chain
        .notes
        .get("payload.type")
        .map(String::as_str)
        .or(chain.payload.as_deref())
        .unwrap_or("-");
    format!("Trigger:{} -> Action:{} -> Payload:{}", trigger, action, payload)
}
