use crate::chain::ExploitChain;

pub enum GraphFormat {
    Dot,
    Json,
}

pub fn export_chain_dot(chain: &ExploitChain) -> String {
    let trigger = chain.trigger.as_deref().unwrap_or("-");
    let action = chain.action.as_deref().unwrap_or("-");
    let payload = chain.payload.as_deref().unwrap_or("-");
    format!(
        "digraph chain {{\n  trigger [label=\"Trigger: {trigger}\"];\n  action [label=\"Action: {action}\"];\n  payload [label=\"Payload: {payload}\"];\n  trigger -> action;\n  action -> payload;\n}}\n"
    )
}

pub fn export_chain_json(chain: &ExploitChain) -> serde_json::Value {
    serde_json::json!({
        "id": chain.id,
        "nodes": [
            { "id": "trigger", "label": chain.trigger.as_deref().unwrap_or("-") },
            { "id": "action", "label": chain.action.as_deref().unwrap_or("-") },
            { "id": "payload", "label": chain.payload.as_deref().unwrap_or("-") }
        ],
        "edges": [
            { "from": "trigger", "to": "action" },
            { "from": "action", "to": "payload" }
        ]
    })
}
