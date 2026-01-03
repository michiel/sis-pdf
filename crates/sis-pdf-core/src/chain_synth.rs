use std::collections::HashMap;

use crate::chain::{ChainTemplate, ExploitChain};
use crate::chain_render::render_path;
use crate::chain_score::score_chain;
use crate::model::Finding;
use crate::taint::taint_from_findings;

pub fn synthesise_chains(findings: &[Finding]) -> (Vec<ExploitChain>, Vec<ChainTemplate>) {
    let structural_count = findings
        .iter()
        .filter(|f| {
            matches!(
                f.kind.as_str(),
                "xref_conflict"
                    | "incremental_update_chain"
                    | "object_id_shadowing"
                    | "objstm_density_high"
            )
        })
        .count();
    let taint = taint_from_findings(findings);
    let mut chains = Vec::new();
    for f in findings {
        let trigger = trigger_from_kind(&f.kind);
        let action = f
            .meta
            .get("action.s")
            .cloned()
            .or_else(|| action_from_kind(&f.kind));
        let payload = payload_from_finding(f);
        let mut notes = HashMap::new();
        if let Some(action_type) = f.meta.get("action.s") {
            notes.insert("action.type".into(), action_type.clone());
        }
        if let Some(action_target) = f.meta.get("action.target") {
            notes.insert("action.target".into(), action_target.clone());
        }
        if let Some(payload_type) = f.meta.get("payload.type") {
            notes.insert("payload.type".into(), payload_type.clone());
        }
        for (k, v) in &f.meta {
            if k.starts_with("js.") || k.starts_with("payload.") {
                notes.insert(k.clone(), v.clone());
            }
        }
        if structural_count > 0 {
            notes.insert("structural.suspicious_count".into(), structural_count.to_string());
        }
        if taint.flagged {
            notes.insert("taint.flagged".into(), "true".into());
            notes.insert("taint.reasons".into(), taint.reasons.join("; "));
        }
        let mut chain = ExploitChain {
            id: String::new(),
            trigger,
            action,
            payload,
            findings: vec![f.id.clone()],
            score: 0.0,
            reasons: Vec::new(),
            path: String::new(),
            notes,
        };
        chain.path = render_path(&chain);
        let (score, reasons) = score_chain(&chain);
        chain.score = score;
        chain.reasons = reasons;
        chain.id = chain_id(&chain);
        chains.push(chain);
    }

    let mut templates: HashMap<String, ChainTemplate> = HashMap::new();
    for c in &chains {
        let key = format!(
            "{}|{}|{}",
            c.trigger.as_deref().unwrap_or("-"),
            c.action.as_deref().unwrap_or("-"),
            c.payload.as_deref().unwrap_or("-")
        );
        let entry = templates.entry(key.clone()).or_insert_with(|| ChainTemplate {
            id: template_id(&key),
            trigger: c.trigger.clone(),
            action: c.action.clone(),
            payload: c.payload.clone(),
            instances: Vec::new(),
        });
        entry.instances.push(c.id.clone());
    }

    (chains, templates.into_values().collect())
}

fn trigger_from_kind(kind: &str) -> Option<String> {
    match kind {
        "open_action_present" | "aa_present" | "aa_event_present" => Some(kind.into()),
        _ => None,
    }
}

fn action_from_kind(kind: &str) -> Option<String> {
    match kind {
        "launch_action_present"
        | "uri_present"
        | "submitform_present"
        | "gotor_present"
        | "js_present"
        | "open_action_present"
        | "aa_present"
        | "aa_event_present" => Some(kind.into()),
        _ => None,
    }
}

fn payload_from_finding(f: &Finding) -> Option<String> {
    if let Some(v) = f.meta.get("payload.type") {
        return Some(v.clone());
    }
    match f.kind.as_str() {
        "js_present" => Some("javascript".into()),
        "embedded_file_present" => Some("embedded_file".into()),
        _ => None,
    }
}

fn chain_id(chain: &ExploitChain) -> String {
    let mut hasher = blake3::Hasher::new();
    if let Some(t) = &chain.trigger {
        hasher.update(t.as_bytes());
    }
    if let Some(a) = &chain.action {
        hasher.update(a.as_bytes());
    }
    if let Some(p) = &chain.payload {
        hasher.update(p.as_bytes());
    }
    for f in &chain.findings {
        hasher.update(f.as_bytes());
    }
    format!("chain-{}", hasher.finalize().to_hex())
}

fn template_id(key: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(key.as_bytes());
    format!("template-{}", hasher.finalize().to_hex())
}
