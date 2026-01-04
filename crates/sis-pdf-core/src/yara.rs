use crate::model::{Finding, Severity, YaraAnnotation};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct YaraRule {
    pub name: String,
    pub tags: Vec<String>,
    pub strings: Vec<(String, String)>,
    pub condition: String,
    pub namespace: Option<String>,
    pub meta: Vec<(String, String)>,
}

pub fn annotate_findings(findings: &mut [Finding], scope: Option<&str>) -> Vec<YaraRule> {
    let threshold = scope.unwrap_or("high").to_lowercase();
    let mut rules = Vec::new();
    for f in findings.iter_mut() {
        if !meets_scope(f, &threshold) {
            continue;
        }
        if let Some(rule) = rule_for_finding(f) {
            f.yara = Some(YaraAnnotation {
                rule_name: rule.name.clone(),
                tags: rule.tags.clone(),
                strings: rule.strings.iter().map(|(id, _)| id.clone()).collect(),
                namespace: rule.namespace.clone(),
            });
            rules.push(rule);
        }
    }
    rules
}

pub fn render_rules(rules: &[YaraRule]) -> String {
    let mut out = String::new();
    for rule in rules {
        let tags = if rule.tags.is_empty() {
            String::new()
        } else {
            format!(" : {}", rule.tags.join(" "))
        };
        out.push_str(&format!("rule {}{} {{\n", rule.name, tags));
        if !rule.meta.is_empty() {
            out.push_str("  meta:\n");
            for (k, v) in &rule.meta {
                out.push_str(&format!("    {} = \"{}\"\n", k, escape_yara_string(v)));
            }
        }
        if !rule.strings.is_empty() {
            out.push_str("  strings:\n");
            for (id, val) in &rule.strings {
                out.push_str(&format!("    {} = \"{}\" ascii nocase\n", id, val));
            }
        }
        out.push_str(&format!("  condition:\n    {}\n", rule.condition));
        out.push_str("}\n\n");
    }
    out
}

fn meets_scope(f: &Finding, scope: &str) -> bool {
    match scope {
        "all" => true,
        "medium" => matches!(f.severity, Severity::Medium | Severity::High | Severity::Critical),
        "low" => true,
        _ => matches!(f.severity, Severity::High | Severity::Critical),
    }
}

fn rule_for_finding(f: &Finding) -> Option<YaraRule> {
    if !matches!(
        f.kind.as_str(),
        "js_present"
            | "embedded_file_present"
            | "decoder_risk_present"
            | "decompression_ratio_suspicious"
            | "launch_action_present"
            | "uri_present"
            | "submitform_present"
            | "gotor_present"
    ) {
        return None;
    }
    let name = format!(
        "SISPDF_{}_{}",
        sanitize_tag(&f.kind),
        f.id.chars().take(8).collect::<String>()
    );
    let mut tags = vec![
        format!("surface_{}", sanitize_tag(&format!("{:?}", f.surface))),
        sanitize_tag(&f.kind),
    ];
    tags.sort();
    tags.dedup();
    let strings = build_strings(f);
    if strings.is_empty() {
        return None;
    }
    Some(YaraRule {
        name,
        tags,
        strings,
        condition: "any of them".into(),
        namespace: Some("sis_pdf".into()),
        meta: build_meta(f),
    })
}

fn build_strings(f: &Finding) -> Vec<(String, String)> {
    let mut vals = Vec::new();
    if let Some(p) = f.meta.get("payload.preview") {
        vals.push(p.clone());
    }
    if let Some(t) = f.meta.get("action.target") {
        vals.push(t.clone());
    }
    if let Some(m) = f.meta.get("embedded.magic") {
        vals.push(m.clone());
    }
    if f.meta.get("js.contains_eval").map(|v| v == "true").unwrap_or(false) {
        vals.push("eval".into());
    }
    if f.meta.get("js.contains_fromcharcode").map(|v| v == "true").unwrap_or(false) {
        vals.push("fromCharCode".into());
    }
    if f.meta.get("js.suspicious_apis").map(|v| v == "true").unwrap_or(false) {
        vals.push("app.launchURL".into());
    }
    let mut out = Vec::new();
    for (idx, v) in vals.into_iter().enumerate().take(6) {
        let id = format!("$s{}", idx + 1);
        out.push((id, escape_yara_string(&v)));
    }
    out
}

fn build_meta(f: &Finding) -> Vec<(String, String)> {
    let mut out = Vec::new();
    out.push(("surface".into(), format!("{:?}", f.surface)));
    out.push(("confidence".into(), format!("{:?}", f.confidence)));
    if let Some(bucket) = f.meta.get("intent.bucket") {
        out.push(("intent_bucket".into(), bucket.clone()));
    }
    if let Some(conf) = f.meta.get("intent.confidence") {
        out.push(("intent_confidence".into(), conf.clone()));
    }
    if let Some(action) = f.meta.get("action.s") {
        out.push(("action_type".into(), action.clone()));
    }
    if let Some(payload) = f.meta.get("payload.type") {
        out.push(("payload_type".into(), payload.clone()));
    }
    out
}

pub(crate) fn escape_yara_string(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars().take(128) {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

fn sanitize_tag(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .to_lowercase()
}
