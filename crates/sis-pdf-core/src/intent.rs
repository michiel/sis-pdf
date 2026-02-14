use crate::model::{Confidence, Finding};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntentSummary {
    pub buckets: Vec<IntentBucketSummary>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntentBucketSummary {
    pub bucket: IntentBucket,
    pub score: u32,
    pub confidence: Confidence,
    pub findings: Vec<String>,
    pub signals: Vec<IntentSignalSummary>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntentSignalSummary {
    pub label: String,
    pub weight: u32,
}

#[derive(
    Debug, Clone, Copy, serde::Serialize, serde::Deserialize, Eq, PartialEq, Hash, Ord, PartialOrd,
)]
pub enum IntentBucket {
    DataExfiltration,
    SandboxEscape,
    Phishing,
    Persistence,
    Obfuscation,
    ExploitPrimitive,
}

#[derive(Debug, Clone)]
pub struct IntentSignal {
    pub bucket: IntentBucket,
    pub weight: u32,
    pub label: String,
    pub finding_id: Option<String>,
}

pub fn apply_intent(findings: &mut [Finding]) -> IntentSummary {
    let mut signals = Vec::new();
    let mut has_js = false;
    let mut has_action = false;
    let mut has_uri = false;
    let mut has_submit = false;
    let mut has_launch = false;
    let mut has_embedded = false;
    let mut has_open_action = false;
    for f in findings.iter() {
        signals.extend(signals_from_finding(f));
        match f.kind.as_str() {
            "js_present" => has_js = true,
            "uri_listing" | "uri_content_analysis" => has_uri = true,
            "submitform_present" => has_submit = true,
            "launch_action_present" => has_launch = true,
            "embedded_file_present" => has_embedded = true,
            "open_action_present" | "aa_present" | "aa_event_present" => has_open_action = true,
            _ => {}
        }
        if f.meta.contains_key("action.s") {
            has_action = true;
        }
    }
    if has_js && (has_uri || has_submit) {
        signals.push(signal(IntentBucket::DataExfiltration, 2, "JS with external action", None));
    }
    if has_js && has_launch {
        signals.push(signal(IntentBucket::SandboxEscape, 2, "JS with Launch action", None));
    }
    if has_open_action && has_js {
        signals.push(signal(IntentBucket::SandboxEscape, 1, "Auto-run trigger with JS", None));
    }
    if has_embedded && has_action {
        signals.push(signal(IntentBucket::Persistence, 2, "Embedded payload with action", None));
    }

    let mut buckets: std::collections::BTreeMap<IntentBucket, IntentBucketSummary> =
        std::collections::BTreeMap::new();
    for sig in signals {
        let entry = buckets.entry(sig.bucket).or_insert_with(|| IntentBucketSummary {
            bucket: sig.bucket,
            score: 0,
            confidence: Confidence::Heuristic,
            findings: Vec::new(),
            signals: Vec::new(),
        });
        entry.score = entry.score.saturating_add(sig.weight);
        if let Some(fid) = sig.finding_id {
            if !entry.findings.contains(&fid) {
                entry.findings.push(fid);
            }
        }
        entry.signals.push(IntentSignalSummary { label: sig.label, weight: sig.weight });
    }
    for bucket in buckets.values_mut() {
        let only_structural = bucket.signals.iter().all(|s| s.label == "Structural anomaly");
        if only_structural {
            bucket.score = bucket.score.saturating_sub(1);
        }
        bucket.confidence = score_confidence(bucket.score);
    }

    let mut summary = IntentSummary { buckets: buckets.into_values().collect() };
    summary.buckets.sort_by(|a, b| b.score.cmp(&a.score));

    for f in findings.iter_mut() {
        let mut best_bucket: Option<(IntentBucket, u32)> = None;
        for bucket in &summary.buckets {
            if bucket.findings.iter().any(|id| id == &f.id)
                && best_bucket.map(|(_, s)| bucket.score > s).unwrap_or(true)
            {
                best_bucket = Some((bucket.bucket, bucket.score));
            }
        }
        if let Some((bucket, score)) = best_bucket {
            f.meta.insert("intent.bucket".into(), bucket_name(bucket));
            f.meta.insert("intent.confidence".into(), format!("{:?}", score_confidence(score)));
        }
    }

    summary
}

fn signals_from_finding(f: &Finding) -> Vec<IntentSignal> {
    let mut out = Vec::new();
    let fid = if f.id.is_empty() { None } else { Some(f.id.clone()) };
    match f.kind.as_str() {
        "submitform_present" => {
            out.push(signal(IntentBucket::DataExfiltration, 3, "SubmitForm action", fid.clone()))
        }
        "uri_content_analysis" | "uri_listing" => {
            out.push(signal(IntentBucket::DataExfiltration, 2, "URI action", fid.clone()))
        }
        "gotor_present" => {
            out.push(signal(IntentBucket::DataExfiltration, 2, "GoToR action", fid.clone()))
        }
        "launch_action_present" => {
            out.push(signal(IntentBucket::SandboxEscape, 3, "Launch action", fid.clone()))
        }
        "open_action_present" => {
            out.push(signal(IntentBucket::SandboxEscape, 1, "OpenAction trigger", fid.clone()))
        }
        "embedded_file_present" | "filespec_present" => {
            out.push(signal(IntentBucket::Persistence, 3, "Embedded file", fid.clone()));
        }
        "content_phishing"
        | "content_overlay_link"
        | "content_invisible_text"
        | "content_image_only_page"
        | "content_html_payload" => {
            out.push(signal(IntentBucket::Phishing, 2, "Content deception", fid.clone()));
        }
        "fontmatrix_payload_present" => {
            out.push(signal(
                IntentBucket::ExploitPrimitive,
                3,
                "FontMatrix injection",
                fid.clone(),
            ));
        }
        "decoder_risk_present" | "decompression_ratio_suspicious" | "huge_image_dimensions" => {
            out.push(signal(IntentBucket::ExploitPrimitive, 2, "Decoder risk", fid.clone()));
        }
        "parser_object_count_diff" | "parser_trailer_count_diff" => {
            out.push(signal(IntentBucket::ExploitPrimitive, 2, "Parser differential", fid.clone()));
        }
        "xref_conflict"
        | "incremental_update_chain"
        | "object_id_shadowing"
        | "objstm_density_high" => {
            out.push(signal(IntentBucket::Obfuscation, 1, "Structural anomaly", fid.clone()));
        }
        _ => {}
    }

    if let Some(v) = f.meta.get("js.contains_eval") {
        if v == "true" {
            out.push(signal(IntentBucket::Obfuscation, 2, "eval() usage", fid.clone()));
        }
    }
    if let Some(v) = f.meta.get("js.contains_unescape") {
        if v == "true" {
            out.push(signal(IntentBucket::Obfuscation, 2, "unescape() usage", fid.clone()));
        }
    }
    if let Some(v) = f.meta.get("js.contains_fromcharcode") {
        if v == "true" {
            out.push(signal(IntentBucket::Obfuscation, 2, "fromCharCode() usage", fid.clone()));
        }
    }
    if let Some(v) = f.meta.get("js.obfuscation_suspected") {
        if v == "true" {
            out.push(signal(IntentBucket::Obfuscation, 3, "Obfuscation suspected", fid.clone()));
        }
    }
    if let Some(v) = f.meta.get("js.suspicious_apis") {
        if v == "true" {
            out.push(signal(
                IntentBucket::SandboxEscape,
                2,
                "Suspicious Acrobat APIs",
                fid.clone(),
            ));
        }
    }
    if let Some(v) = f.meta.get("js.ast_domains") {
        if !v.is_empty() {
            out.push(signal(IntentBucket::DataExfiltration, 2, "AST domains present", fid.clone()));
        }
    }
    if let Some(v) = f.meta.get("js.ast_urls") {
        if !v.is_empty() {
            out.push(signal(IntentBucket::DataExfiltration, 2, "AST URLs present", fid.clone()));
        }
    }
    if let Some(v) = f.meta.get("js.ast_call_args") {
        let lower = v.to_ascii_lowercase();
        if lower.contains("geturl(")
            || lower.contains("submitform(")
            || lower.contains("launchurl(")
        {
            out.push(signal(
                IntentBucket::DataExfiltration,
                2,
                "JS network call arguments",
                fid.clone(),
            ));
        }
    }
    if let Some(target) = f.meta.get("action.target") {
        let t = target.to_ascii_lowercase();
        if t.contains("http") || t.contains("mailto:") || t.contains("data:") {
            out.push(signal(IntentBucket::DataExfiltration, 2, "External target", fid.clone()));
        }
        if t.contains("file://")
            || t.contains("cmd.exe")
            || t.contains("powershell")
            || t.contains(".exe")
        {
            out.push(signal(IntentBucket::SandboxEscape, 2, "Local execution target", fid.clone()));
        }
    }
    if let Some(preview) = f.meta.get("payload.preview") {
        let p = preview.to_ascii_lowercase();
        if p.contains("http") || p.contains("mailto:") || p.contains("data:") {
            out.push(signal(
                IntentBucket::DataExfiltration,
                1,
                "External payload string",
                fid.clone(),
            ));
        }
        if p.contains("<script") || p.contains("javascript:") {
            out.push(signal(IntentBucket::Phishing, 1, "HTML-like payload", fid.clone()));
        }
    }
    if let Some(preview) = f.meta.get("payload.decoded_preview") {
        let p = preview.to_ascii_lowercase();
        if p.contains("http") || p.contains("mailto:") || p.contains("data:") {
            out.push(signal(
                IntentBucket::DataExfiltration,
                1,
                "External decoded payload",
                fid.clone(),
            ));
        }
    }

    out
}

fn signal(bucket: IntentBucket, weight: u32, label: &str, fid: Option<String>) -> IntentSignal {
    IntentSignal { bucket, weight, label: label.into(), finding_id: fid }
}

fn score_confidence(score: u32) -> Confidence {
    if score >= 6 {
        Confidence::Strong
    } else if score >= 3 {
        Confidence::Probable
    } else {
        Confidence::Heuristic
    }
}

fn bucket_name(bucket: IntentBucket) -> String {
    match bucket {
        IntentBucket::DataExfiltration => "data_exfiltration",
        IntentBucket::SandboxEscape => "sandbox_escape",
        IntentBucket::Phishing => "phishing",
        IntentBucket::Persistence => "persistence",
        IntentBucket::Obfuscation => "obfuscation",
        IntentBucket::ExploitPrimitive => "exploit_primitive",
    }
    .into()
}
