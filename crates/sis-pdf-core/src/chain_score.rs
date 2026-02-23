use crate::chain::ExploitChain;

pub fn score_chain(chain: &ExploitChain) -> (f64, Vec<String>) {
    let mut score: f64 = 0.2;
    let mut reasons = Vec::new();

    let trigger_key =
        chain.notes.get("trigger.key").map(String::as_str).or(chain.trigger.as_deref());
    if let Some(trigger) = trigger_key {
        if trigger == "open_action_present" || trigger == "aa_event_present" {
            score = score.max(0.7);
            reasons.push("Auto-trigger: document or event action".into());
        }
    }

    let action_key = chain.notes.get("action.key").map(String::as_str).or(chain.action.as_deref());
    if let Some(action) = action_key {
        match action {
            "launch_action_present" => {
                score = score.max(0.85);
                reasons.push("Action severity: High (Launch)".into());
            }
            "uri_javascript_scheme" | "uri_file_scheme" | "uri_data_html_scheme" => {
                score = score.max(0.85);
                reasons.push("Action severity: High (Dangerous URI scheme — code execution vector)".into());
            }
            "uri_command_injection" => {
                score = score.max(0.8);
                reasons.push("Action severity: High (Command injection URI pattern)".into());
            }
            "js_present" => {
                score = score.max(0.75);
                reasons.push("Action severity: Medium (JavaScript)".into());
            }
            "submitform_present" => {
                score = score.max(0.6);
                reasons.push("Action severity: Medium (SubmitForm)".into());
            }
            "uri_content_analysis" => {
                score = score.max(0.5);
                reasons.push("Action severity: Low (URI)".into());
            }
            _ => {}
        }
    }
    if let Some(uri_risk_score) =
        chain.notes.get("uri.risk_score").and_then(|value| value.parse::<u32>().ok())
    {
        if uri_risk_score >= 100 {
            score = score.max(0.8);
            reasons.push(format!("URI risk score: {}", uri_risk_score));
        } else if uri_risk_score >= 70 {
            score = score.max(0.65);
            reasons.push(format!("URI risk score: {}", uri_risk_score));
        }
    }

    let payload_key =
        chain.notes.get("payload.key").map(String::as_str).or(chain.payload.as_deref());
    if let Some(payload) = payload_key {
        if payload.contains("stream") {
            score = score.max(0.65);
            reasons.push("Payload: stream-based data".into());
        }
        if payload.contains("image") {
            score = score.max(0.55);
            reasons.push("Payload: image data".into());
        }
    }
    if chain.notes.get("payload.risky").map(|v| v == "true").unwrap_or(false) {
        score = score.max(0.7);
        reasons.push("Payload: risky image format".into());
    }

    if chain.notes.get("js.obfuscation_suspected").map(|v| v == "true").unwrap_or(false) {
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
        reasons.push(format!("Payload: string concat density {:.3}", concat_density));
    }

    let escape_density =
        chain.notes.get("js.escape_density").and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
    if escape_density > 0.05 {
        score = score.max(0.7);
        reasons.push(format!("Payload: escape density {:.3}", escape_density));
    }

    if chain.notes.get("js.regex_packing").map(|v| v == "true").unwrap_or(false) {
        score = score.max(0.75);
        reasons.push("Payload: regex packing patterns".into());
    }

    if chain.notes.get("js.suspicious_apis").map(|v| v == "true").unwrap_or(false) {
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

    if chain.notes.get("taint.flagged").map(|v| v == "true").unwrap_or(false) {
        score = score.max(0.8);
        reasons.push("Taint: suspicious constructs present".into());
    }

    (score.clamp(0.0, 1.0), reasons)
}
