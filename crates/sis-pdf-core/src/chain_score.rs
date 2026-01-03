use crate::chain::ExploitChain;

pub fn score_chain(chain: &ExploitChain) -> (f64, Vec<String>) {
    let mut score: f64 = 0.2;
    let mut reasons = Vec::new();

    if let Some(trigger) = &chain.trigger {
        if trigger == "open_action_present" || trigger == "aa_event_present" {
            score = score.max(0.7);
            reasons.push("Auto-trigger: document or event action".into());
        }
    }

    if let Some(action) = &chain.action {
        match action.as_str() {
            "launch_action_present" => {
                score = score.max(0.85);
                reasons.push("Action severity: Launch".into());
            }
            "js_present" => {
                score = score.max(0.75);
                reasons.push("Action severity: JavaScript".into());
            }
            "submitform_present" => {
                score = score.max(0.6);
                reasons.push("Action severity: SubmitForm".into());
            }
            "uri_present" => {
                score = score.max(0.5);
                reasons.push("Action severity: URI".into());
            }
            _ => {}
        }
    }

    if let Some(payload) = &chain.payload {
        if payload.contains("stream") {
            score = score.max(0.65);
            reasons.push("Payload: stream-based data".into());
        }
    }

    if chain
        .notes
        .get("js.obfuscation_suspected")
        .map(|v| v == "true")
        .unwrap_or(false)
    {
        score = score.max(0.85);
        reasons.push("Payload: JS obfuscation suspected".into());
    }

    let concat_density = chain
        .notes
        .get("js.string_concat_density")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);
    if concat_density > 0.03 {
        score = score.max(0.7);
        reasons.push(format!(
            "Payload: string concat density {:.3}",
            concat_density
        ));
    }

    let escape_density = chain
        .notes
        .get("js.escape_density")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);
    if escape_density > 0.05 {
        score = score.max(0.7);
        reasons.push(format!("Payload: escape density {:.3}", escape_density));
    }

    if chain
        .notes
        .get("js.regex_packing")
        .map(|v| v == "true")
        .unwrap_or(false)
    {
        score = score.max(0.75);
        reasons.push("Payload: regex packing patterns".into());
    }

    if chain
        .notes
        .get("js.suspicious_apis")
        .map(|v| v == "true")
        .unwrap_or(false)
    {
        score = score.max(0.8);
        reasons.push("Payload: suspicious JavaScript APIs".into());
    }

    let structural = chain
        .notes
        .get("structural.suspicious_count")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    if structural > 0 {
        score = score.max(0.7);
        reasons.push(format!("Structure: {} suspicious finding(s)", structural));
    }

    if chain
        .notes
        .get("taint.flagged")
        .map(|v| v == "true")
        .unwrap_or(false)
    {
        score = score.max(0.8);
        reasons.push("Taint: suspicious constructs present".into());
    }

    (score.clamp(0.0, 1.0), reasons)
}
