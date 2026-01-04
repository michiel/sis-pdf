use std::collections::BTreeMap;

use anyhow::Result;

use crate::chain::{ChainTemplate, ExploitChain};
use crate::intent::IntentSummary;
use crate::model::{AttackSurface, Finding, Severity};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Summary {
    pub total: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Report {
    pub summary: Summary,
    pub findings: Vec<Finding>,
    pub grouped: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    pub chains: Vec<ExploitChain>,
    pub chain_templates: Vec<ChainTemplate>,
    pub yara_rules: Vec<crate::yara::YaraRule>,
    pub input_path: Option<String>,
    pub intent_summary: Option<IntentSummary>,
    #[serde(default)]
    pub behavior_summary: Option<crate::behavior::BehaviorSummary>,
    #[serde(default)]
    pub future_threats: Vec<crate::predictor::FutureThreat>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BatchEntry {
    pub path: String,
    pub summary: Summary,
    pub duration_ms: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BatchTiming {
    pub total_ms: u64,
    pub avg_ms: u64,
    pub max_ms: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BatchReport {
    pub summary: Summary,
    pub entries: Vec<BatchEntry>,
    pub timing: BatchTiming,
}

impl Report {
    pub fn from_findings(
        findings: Vec<Finding>,
        chains: Vec<ExploitChain>,
        chain_templates: Vec<ChainTemplate>,
        yara_rules: Vec<crate::yara::YaraRule>,
        intent_summary: Option<IntentSummary>,
        behavior_summary: Option<crate::behavior::BehaviorSummary>,
        future_threats: Vec<crate::predictor::FutureThreat>,
    ) -> Self {
        let mut grouped: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
        for f in &findings {
            let surface = attack_surface_name(f.surface);
            grouped
                .entry(surface)
                .or_default()
                .entry(f.kind.clone())
                .or_default()
                .push(f.id.clone());
        }
        let summary = summary_from_findings(&findings);
        Self {
            summary,
            findings,
            grouped,
            chains,
            chain_templates,
            yara_rules,
            input_path: None,
            intent_summary,
            behavior_summary,
            future_threats,
        }
    }

    pub fn with_input_path(mut self, input_path: Option<String>) -> Self {
        self.input_path = input_path;
        self
    }
}

pub fn print_human(report: &Report) {
    println!("Findings: {}", report.summary.total);
    println!(
        "High: {}  Medium: {}  Low: {}  Info: {}",
        report.summary.high, report.summary.medium, report.summary.low, report.summary.info
    );
    println!();
    for (surface, kinds) in &report.grouped {
        println!("{}", surface);
        for (kind, ids) in kinds {
            println!("  {} ({})", kind, ids.len());
            for id in ids {
                println!("    - {}", id);
            }
        }
    }
    let mut printed = false;
    for f in &report.findings {
        if let Some(payload) = f
            .meta
            .get("payload.decoded_preview")
            .or_else(|| f.meta.get("payload.preview"))
        {
            if !printed {
                println!();
                println!("Payload previews");
                printed = true;
            }
            println!();
            println!("{} — {}", f.id, f.title);
            println!("```");
            println!("{}", payload);
            println!("```");
        }
    }
}

pub fn print_jsonl(report: &Report) -> Result<()> {
    for f in &report.findings {
        println!("{}", serde_json::to_string(f)?);
    }
    Ok(())
}

pub use crate::sarif::sarif_rule_count;

fn render_action_chain(f: &Finding) -> Option<String> {
    let mut parts = Vec::new();
    let trigger = match f.kind.as_str() {
        "open_action_present" => "OpenAction",
        "aa_present" | "aa_event_present" => "AdditionalActions",
        _ => "Finding",
    };
    parts.push(format!("Trigger: {}", trigger));
    if let Some(action) = f.meta.get("action.s") {
        parts.push(format!("Action: {}", action));
    } else if f.kind == "js_present" {
        parts.push("Action: /JavaScript".into());
    }
    if let Some(kind) = f.meta.get("payload.type") {
        parts.push(format!("Payload: {}", kind));
    } else if f
        .meta
        .get("payload.decoded_preview")
        .or_else(|| f.meta.get("payload.preview"))
        .is_some()
    {
        parts.push("Payload: preview".into());
    }
    if parts.len() <= 1 {
        return None;
    }
    Some(parts.join(" -> "))
}

fn render_payload_behaviour(f: &Finding) -> Option<String> {
    if !f.meta.keys().any(|k| k.starts_with("js.")) {
        return None;
    }
    let mut notes = Vec::new();
    if f.meta.get("js.contains_eval").map(|v| v == "true").unwrap_or(false) {
        notes.push("Uses eval()".into());
    }
    if f.meta.get("js.has_base64_like").map(|v| v == "true").unwrap_or(false) {
        notes.push("Contains base64-like runs".into());
    }
    if f.meta.get("js.contains_unescape").map(|v| v == "true").unwrap_or(false) {
        notes.push("Uses unescape()".into());
    }
    if f.meta.get("js.contains_fromcharcode").map(|v| v == "true").unwrap_or(false) {
        notes.push("Uses fromCharCode()".into());
    }
    if f.meta.get("js.suspicious_apis").map(|v| v == "true").unwrap_or(false) {
        notes.push("Calls suspicious Acrobat APIs".into());
    }
    if f.meta.get("js.obfuscation_suspected").map(|v| v == "true").unwrap_or(false) {
        notes.push("Obfuscation suspected".into());
    }
    if let Some(summary) = f.meta.get("js.behaviour_summary") {
        notes.push(format!("Behaviour summary: {}", summary));
    }
    let ent = f.meta.get("js.entropy").cloned();
    if let Some(ent) = ent {
        notes.push(format!("Entropy {}", ent));
    }
    if notes.is_empty() {
        return None;
    }
    Some(notes.join("; "))
}

pub(crate) fn impact_for_finding(f: &Finding) -> String {
    match f.kind.as_str() {
        "open_action_present" => {
            "OpenAction triggers automatically when the document opens, enabling automatic execution of its action target."
                .into()
        }
        "aa_present" | "aa_event_present" => {
            "Additional Actions can execute on viewer events, enabling scripted or external behaviour during user interaction."
                .into()
        }
        "js_present" => {
            "JavaScript can execute in the viewer context, access APIs, and influence user actions or data."
                .into()
        }
        "launch_action_present" => {
            "Launch actions can invoke external applications or files, increasing the risk of user compromise."
                .into()
        }
        "uri_present" => {
            "URI actions can direct users to external resources, enabling phishing or data exfiltration."
                .into()
        }
        "submitform_present" => {
            "SubmitForm can transmit form data to external endpoints, enabling data leakage."
                .into()
        }
        "gotor_present" => {
            "GoToR can open remote documents or resources, which may lead to untrusted content."
                .into()
        }
        "embedded_file_present" | "filespec_present" => {
            "Embedded files and file specifications can deliver secondary payloads or hidden content."
                .into()
        }
        "signature_present" => {
            "Digital signatures embed cryptographic structures that can carry additional objects or trust anchors."
                .into()
        }
        "encryption_present" => {
            "Encrypted documents obscure content and can limit visibility for security tooling."
                .into()
        }
        "dss_present" => {
            "DSS structures add validation data that may include embedded streams or certificates."
                .into()
        }
        "richmedia_present" | "3d_present" | "sound_movie_present" => {
            "Rich media content expands the parser and renderer attack surface, potentially triggering vulnerable code paths."
                .into()
        }
        "xfa_present" | "acroform_present" => {
            "Interactive form technologies increase scriptable surface and can be abused for malicious interaction."
                .into()
        }
        "decoder_risk_present" | "decompression_ratio_suspicious" | "huge_image_dimensions" => {
            "Decoder-heavy content can trigger parser vulnerabilities or resource exhaustion."
                .into()
        }
        "xref_conflict"
        | "incremental_update_chain"
        | "object_id_shadowing"
        | "objstm_density_high"
        | "stream_length_mismatch"
        | "missing_pdf_header"
        | "missing_eof_marker" => {
            "Structural anomalies can cause parser differentials and enable evasion or exploitation."
                .into()
        }
        "content_phishing" => {
            "Content cues suggest possible phishing or social-engineering intent."
                .into()
        }
        "content_html_payload" => {
            "HTML-like content may indicate an embedded script or spoofed UI presented to the user."
                .into()
        }
        "fontmatrix_payload_present" => {
            "Injected FontMatrix entries can trigger script execution in vulnerable PDF renderers."
                .into()
        }
        "parser_object_count_diff"
        | "parser_trailer_count_diff"
        | "parser_startxref_count_diff" => {
            "Parser disagreement indicates malformed structure, which can be exploited for differential parsing."
                .into()
        }
        "object_count_exceeded" => {
            "Very large object graphs can be used to hide content or exhaust parser resources."
                .into()
        }
        "linearization_invalid"
        | "linearization_multiple"
        | "linearization_hint_anomaly" => {
            "Linearization anomalies can be used to confuse parsers and hide content or offsets."
                .into()
        }
        "font_payload_present" | "font_table_anomaly" => {
            "Suspicious embedded fonts can exploit font parsing vulnerabilities."
                .into()
        }
        "icc_profile_anomaly" | "icc_profile_oversized" => {
            "Malformed ICC profiles can trigger vulnerable color management code paths."
                .into()
        }
        "annotation_hidden" | "annotation_action_chain" => {
            "Annotation manipulation can hide actions or trigger unexpected viewer behavior."
                .into()
        }
        "page_tree_cycle" | "page_tree_mismatch" => {
            "Page tree inconsistencies can hide pages or confuse rendering traversal."
                .into()
        }
        "js_polymorphic" | "js_multi_stage_decode" | "js_obfuscation_deep" => {
            "Obfuscated JavaScript indicates potential attempts to evade static analysis."
                .into()
        }
        "js_time_evasion" | "js_env_probe" => {
            "Evasion-oriented JavaScript can delay or gate malicious behavior based on environment."
                .into()
        }
        "supply_chain_staged_payload"
        | "supply_chain_update_vector"
        | "supply_chain_persistence" => {
            "Supply-chain style indicators suggest staged payload delivery or update abuse."
                .into()
        }
        "crypto_weak_algo" | "crypto_cert_anomaly" | "crypto_mining_js" => {
            "Cryptographic anomalies or mining indicators can signal malicious behavior."
                .into()
        }
        "multi_stage_attack_chain" => {
            "Multiple attack stages detected, indicating coordinated execution paths."
                .into()
        }
        "quantum_vulnerable_crypto" => {
            "Legacy cryptography may be vulnerable to future quantum attacks."
                .into()
        }
        "ml_adversarial_suspected" => {
            "ML features suggest possible adversarial manipulation."
                .into()
        }
        "js_runtime_network_intent" => {
            "Runtime JavaScript calls indicate network-capable behavior during execution."
                .into()
        }
        "js_runtime_file_probe" => {
            "Runtime JavaScript calls indicate file or export behavior during execution."
                .into()
        }
        "parser_diff_structural" => {
            "Structural parser differentials indicate malformed structure and possible parser confusion."
                .into()
        }
        "ml_malware_score_high" => {
            "Machine-learning classifier indicates the file resembles known malicious PDFs."
                .into()
        }
        "ml_model_error" => {
            "ML classification was requested but the model failed to load."
                .into()
        }
        _ => "This construct increases attack surface or indicates a potentially unsafe PDF feature."
            .into(),
    }
}

pub fn render_markdown(report: &Report, input_path: Option<&str>) -> String {
    let mut out = String::new();
    out.push_str("# sis-pdf Report\n\n");
    out.push_str("## Summary\n\n");
    out.push_str(&format!(
        "- Total findings: {}\n- High: {}\n- Medium: {}\n- Low: {}\n- Info: {}\n\n",
        report.summary.total,
        report.summary.high,
        report.summary.medium,
        report.summary.low,
        report.summary.info
    ));

    if let Some(path) = input_path {
        out.push_str(&format!("- Input: `{}`\n\n", path));
    }

    if let Some(summary) = &report.intent_summary {
        if !summary.buckets.is_empty() {
            out.push_str("## Intent Summary\n\n");
            for bucket in &summary.buckets {
                out.push_str(&format!(
                    "- {}: score={} confidence={:?} findings={}\n",
                    format!("{:?}", bucket.bucket),
                    bucket.score,
                    bucket.confidence,
                    bucket.findings.len()
                ));
            }
            out.push('\n');
            out.push_str("## Intent Details\n\n");
            for bucket in &summary.buckets {
                out.push_str(&format!(
                    "### {:?} — score={} confidence={:?}\n\n",
                    bucket.bucket, bucket.score, bucket.confidence
                ));
                if !bucket.signals.is_empty() {
                    let mut weights: std::collections::BTreeMap<String, u32> =
                        std::collections::BTreeMap::new();
                    for sig in &bucket.signals {
                        *weights.entry(sig.label.clone()).or_insert(0) += sig.weight;
                    }
                    let mut ranked: Vec<(String, u32)> = weights.into_iter().collect();
                    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                    out.push_str("**Classification signals**\n\n");
                    for (label, weight) in ranked.into_iter().take(8) {
                        out.push_str(&format!("- {} (weight {})\n", label, weight));
                    }
                    out.push('\n');
                }
                out.push_str("**Sequence of events**\n\n");
                let mut shown = 0usize;
                for fid in &bucket.findings {
                    if shown >= 3 {
                        break;
                    }
                    if let Some(f) = report.findings.iter().find(|f| &f.id == fid) {
                        if let Some(chain) = render_action_chain(f) {
                            out.push_str(&format!("- {}: {}\n", f.id, chain));
                        } else {
                            out.push_str(&format!("- {}: {}\n", f.id, f.title));
                        }
                        shown += 1;
                    }
                }
                if shown == 0 {
                    out.push_str("- No sequence available\n");
                }
                out.push('\n');
                out.push_str("**Supporting evidence**\n\n");
                let mut ev_count = 0usize;
                for fid in &bucket.findings {
                    if ev_count >= 3 {
                        break;
                    }
                    if let Some(f) = report.findings.iter().find(|f| &f.id == fid) {
                        for ev in &f.evidence {
                            if ev_count >= 3 {
                                break;
                            }
                            let origin = ev
                                .origin
                                .map(|o| format!("origin={}..{}", o.start, o.end))
                                .unwrap_or_else(|| "origin=-".into());
                            out.push_str(&format!(
                                "- {} source={:?} offset={} length={} {}\n",
                                f.id, ev.source, ev.offset, ev.length, origin
                            ));
                            ev_count += 1;
                        }
                    }
                }
                if ev_count == 0 {
                    out.push_str("- No evidence captured\n");
                }
                out.push('\n');
            }
        }
    }

    if let Some(summary) = &report.behavior_summary {
        if !summary.patterns.is_empty() {
            out.push_str("## Behavior Correlation\n\n");
            for pattern in &summary.patterns {
                out.push_str(&format!(
                    "- {} (severity {:?}) kinds=[{}] objects=[{}]\n",
                    pattern.summary,
                    pattern.severity,
                    pattern.kinds.join(", "),
                    pattern.objects.join(", ")
                ));
            }
            out.push('\n');
        }
    }

    if !report.future_threats.is_empty() {
        out.push_str("## Predicted Threat Evolution\n\n");
        for threat in &report.future_threats {
            out.push_str(&format!(
                "- {} (confidence {:.2})\n",
                threat.label, threat.confidence
            ));
        }
        out.push('\n');
    }

    let strict_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.kind == "strict_parse_deviation")
        .collect();
    if !strict_findings.is_empty() {
        out.push_str("## Strict Parse Deviations\n\n");
        out.push_str(&format!(
            "- Count: {}\n\n",
            strict_findings.len()
        ));
        for f in &strict_findings {
            out.push_str(&format!("- {}: {}\n", f.id, f.title));
        }
        out.push('\n');
    }

    out.push_str("## SARIF\n\n");
    out.push_str(&format!(
        "- Rules: {}\n- Results: {}\n- Generate with: `sis scan --sarif`\n\n",
        sarif_rule_count(report),
        report.findings.len()
    ));

    if !report.yara_rules.is_empty() {
        out.push_str("## YARA\n\n");
        out.push_str(&format!("- Rules: {}\n\n", report.yara_rules.len()));
        for rule in &report.yara_rules {
            let tags = if rule.tags.is_empty() {
                "-".into()
            } else {
                rule.tags.join(", ")
            };
            out.push_str(&format!("- {} (tags: {})\n", rule.name, tags));
        }
        out.push('\n');
    }

    out.push_str("## Findings\n\n");
    for f in &report.findings {
        out.push_str(&format!("### {} — {}\n\n", f.id, f.title));
        out.push_str(&format!("- Surface: `{:?}`\n", f.surface));
        out.push_str(&format!("- Kind: `{}`\n", f.kind));
        out.push_str(&format!("- Severity: `{:?}`\n", f.severity));
        out.push_str(&format!("- Confidence: `{:?}`\n", f.confidence));
        if !f.objects.is_empty() {
            out.push_str(&format!("- Objects: {}\n", f.objects.join(", ")));
        }
        if let Some(page) = f.meta.get("page.number") {
            out.push_str(&format!("- Page: {}\n", page));
        }
        if let Some(coord) = f.meta.get("content.coord") {
            out.push_str(&format!("- Coord: {}\n", coord));
        }
        out.push_str("\n**Description**\n\n");
        out.push_str(&format!("{}\n\n", f.description));
        if let Some(s) = f.meta.get("action.s") {
            out.push_str("**Action Details**\n\n");
            out.push_str(&format!("- Action type: `{}`\n", s));
            if let Some(t) = f.meta.get("action.target") {
                out.push_str(&format!("- Target: {}\n", t));
            }
            out.push('\n');
        }
        if let Some(payload) = f
            .meta
            .get("payload.decoded_preview")
            .or_else(|| f.meta.get("payload.preview"))
        {
            out.push_str("**Payload**\n\n");
            out.push_str("```\n");
            out.push_str(payload);
            out.push_str("\n```\n\n");
        }
        if let Some(chain) = render_action_chain(f) {
            out.push_str("**Action Chain**\n\n");
            out.push_str(&format!("{}\n\n", chain));
        }
        if let Some(behaviour) = render_payload_behaviour(f) {
            out.push_str("**Payload Behaviour**\n\n");
            out.push_str(&format!("{}\n\n", behaviour));
        }
        let impact = f
            .meta
            .get("impact")
            .cloned()
            .unwrap_or_else(|| impact_for_finding(f));
        out.push_str("**Impact**\n\n");
        out.push_str(&format!("{}\n\n", impact));
        if let Some(y) = &f.yara {
            out.push_str("**YARA**\n\n");
            out.push_str(&format!("- Rule: `{}`\n", y.rule_name));
            if !y.tags.is_empty() {
                out.push_str(&format!("- Tags: {}\n", y.tags.join(", ")));
            }
            if !y.strings.is_empty() {
                out.push_str(&format!("- Strings: {}\n", y.strings.join(", ")));
            }
            if let Some(ns) = &y.namespace {
                out.push_str(&format!("- Namespace: {}\n", ns));
            }
            out.push('\n');
        }
        if let Some(rem) = &f.remediation {
            out.push_str("**Remediation**\n\n");
            out.push_str(&format!("{}\n\n", rem));
        }
        if !f.evidence.is_empty() {
            out.push_str("**Evidence**\n\n");
            for ev in &f.evidence {
                let origin = ev
                    .origin
                    .map(|o| format!("origin={}..{}", o.start, o.end))
                    .unwrap_or_else(|| "origin=-".into());
                out.push_str(&format!(
                    "- source={:?} offset={} length={} {}",
                    ev.source, ev.offset, ev.length, origin
                ));
                if let Some(note) = &ev.note {
                    out.push_str(&format!(" note={}", note));
                }
                out.push('\n');
            }
            out.push('\n');
        }
        if !f.meta.is_empty() {
            let mut js_meta: Vec<(&String, &String)> = f
                .meta
                .iter()
                .filter(|(k, _)| k.starts_with("js."))
                .collect();
            js_meta.sort_by(|a, b| a.0.cmp(b.0));
            let mut other_meta: Vec<(&String, &String)> = f
                .meta
                .iter()
                .filter(|(k, _)| !k.starts_with("js."))
                .collect();
            other_meta.sort_by(|a, b| a.0.cmp(b.0));

            if !other_meta.is_empty() {
                out.push_str("**Metadata**\n\n");
                out.push_str("| Key | Value |\n");
                out.push_str("| --- | ----- |\n");
                for (k, v) in other_meta {
                    out.push_str(&format!("| {} | {} |\n", k, v));
                }
                out.push('\n');
            }
            if !js_meta.is_empty() {
                out.push_str("**JavaScript Metadata**\n\n");
                out.push_str("| Key | Value |\n");
                out.push_str("| --- | ----- |\n");
                for (k, v) in js_meta {
                    out.push_str(&format!("| {} | {} |\n", k, v));
                }
                out.push('\n');
            }
        }
    }
    out
}

pub fn render_batch_markdown(report: &BatchReport) -> String {
    let mut out = String::new();
    out.push_str("# sis-pdf Batch Report\n\n");
    out.push_str("## Summary\n\n");
    out.push_str(&format!(
        "- Files: {}\n- Total findings: {}\n- High: {}\n- Medium: {}\n- Low: {}\n- Info: {}\n- Timing: total={}ms avg={}ms max={}ms\n\n",
        report.entries.len(),
        report.summary.total,
        report.summary.high,
        report.summary.medium,
        report.summary.low,
        report.summary.info,
        report.timing.total_ms,
        report.timing.avg_ms,
        report.timing.max_ms
    ));
    out.push_str("## Per-File Totals\n\n");
    for entry in &report.entries {
        out.push_str(&format!(
            "- {}: total={} high={} medium={} low={} info={} duration={}ms\n",
            entry.path,
            entry.summary.total,
            entry.summary.high,
            entry.summary.medium,
            entry.summary.low,
            entry.summary.info,
            entry.duration_ms
        ));
    }
    out
}

fn summary_from_findings(findings: &[Finding]) -> Summary {
    let mut summary = Summary {
        total: findings.len(),
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
    };
    for f in findings {
        match f.severity {
            Severity::High | Severity::Critical => summary.high += 1,
            Severity::Medium => summary.medium += 1,
            Severity::Low => summary.low += 1,
            Severity::Info => summary.info += 1,
        }
    }
    summary
}

pub fn attack_surface_name(surface: AttackSurface) -> String {
    format!("{:?}", surface)
}
