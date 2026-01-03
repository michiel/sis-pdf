use std::collections::BTreeMap;

use anyhow::Result;

use crate::chain::{ChainTemplate, ExploitChain};
use crate::model::{AttackSurface, Finding, Severity};

#[derive(Debug, serde::Serialize)]
pub struct Summary {
    pub total: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug, serde::Serialize)]
pub struct Report {
    pub summary: Summary,
    pub findings: Vec<Finding>,
    pub grouped: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    pub chains: Vec<ExploitChain>,
    pub chain_templates: Vec<ChainTemplate>,
    pub yara_rules: Vec<crate::yara::YaraRule>,
    pub input_path: Option<String>,
}

impl Report {
    pub fn from_findings(
        findings: Vec<Finding>,
        chains: Vec<ExploitChain>,
        chain_templates: Vec<ChainTemplate>,
        yara_rules: Vec<crate::yara::YaraRule>,
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
}

pub fn print_jsonl(report: &Report) -> Result<()> {
    for f in &report.findings {
        println!("{}", serde_json::to_string(f)?);
    }
    Ok(())
}

pub fn to_sarif(report: &Report, input_path: Option<&str>) -> serde_json::Value {
    let mut rules = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for f in &report.findings {
        if seen.insert(f.kind.clone()) {
            rules.push(serde_json::json!({
                "id": f.kind,
                "name": f.title,
                "shortDescription": { "text": f.title },
                "fullDescription": { "text": f.description },
                "helpUri": format!("https://example.invalid/ysnp/rules/{}", f.kind),
                "defaultConfiguration": {
                    "level": match f.severity {
                        Severity::Critical | Severity::High => "error",
                        Severity::Medium => "warning",
                        _ => "note",
                    }
                },
                "properties": {
                    "surface": format!("{:?}", f.surface),
                    "confidence": format!("{:?}", f.confidence),
                    "tags": [format!("{:?}", f.surface), f.kind],
                }
            }));
        }
    }
    let results: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low | Severity::Info => "note",
            };
            let locations = sarif_locations(f, input_path);
            serde_json::json!({
                "ruleId": f.kind,
                "level": level,
                "message": { "text": f.title },
                "locations": locations,
                "fingerprints": {
                    "ysnp": f.id
                },
                "properties": {
                    "confidence": format!("{:?}", f.confidence),
                    "objects": f.objects,
                    "surface": format!("{:?}", f.surface),
                    "impact": f.meta.get("impact").cloned().unwrap_or_else(|| impact_for_finding(f)),
                    "meta": f.meta,
                    "yara": f.yara.as_ref().map(|y| {
                        serde_json::json!({
                            "rule_name": y.rule_name,
                            "tags": y.tags,
                            "strings": y.strings,
                            "namespace": y.namespace
                        })
                    }),
                    "evidence": f.evidence.iter().map(|ev| {
                        serde_json::json!({
                            "source": format!("{:?}", ev.source),
                            "offset": ev.offset,
                            "length": ev.length,
                            "origin": ev.origin.map(|o| serde_json::json!({"start": o.start, "end": o.end})),
                            "note": ev.note
                        })
                    }).collect::<Vec<_>>(),
                }
            })
        })
        .collect();

    let artifacts = input_path.map(|p| {
        serde_json::json!([{
            "location": { "uri": p },
            "roles": ["analysisTarget"]
        }])
    });
    serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ysnp",
                    "rules": rules
                }
            },
            "artifacts": artifacts,
            "invocations": [{
                "executionSuccessful": true,
                "properties": {
                    "input_path": input_path
                }
            }],
            "results": results
        }]
    })
}

fn sarif_locations(f: &Finding, input_path: Option<&str>) -> Vec<serde_json::Value> {
    let uri = input_path.unwrap_or("input");
    let mut out = Vec::new();
    for ev in &f.evidence {
        match ev.source {
            crate::model::EvidenceSource::File => {
                out.push(serde_json::json!({
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri },
                        "region": {
                            "byteOffset": ev.offset,
                            "byteLength": ev.length
                        }
                    },
                    "properties": {
                        "source": "File",
                        "note": ev.note,
                    }
                }));
            }
            crate::model::EvidenceSource::Decoded => {
                if let Some(origin) = ev.origin {
                    out.push(serde_json::json!({
                        "physicalLocation": {
                            "artifactLocation": { "uri": uri },
                            "region": {
                                "byteOffset": origin.start,
                                "byteLength": (origin.end - origin.start) as u64
                            }
                        },
                        "properties": {
                            "source": "Decoded",
                            "decoded_offset": ev.offset,
                            "decoded_length": ev.length,
                            "note": ev.note,
                        }
                    }));
                }
            }
        }
    }
    out
}

fn sarif_rule_count(report: &Report) -> usize {
    let mut seen = std::collections::HashSet::new();
    for f in &report.findings {
        seen.insert(f.kind.clone());
    }
    seen.len()
}

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
    if let Some(payload) = f.meta.get("payload.preview") {
        parts.push(format!("Payload: {}", payload));
    } else if let Some(kind) = f.meta.get("payload.type") {
        parts.push(format!("Payload: {}", kind));
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

fn impact_for_finding(f: &Finding) -> String {
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
        _ => "This construct increases attack surface or indicates a potentially unsafe PDF feature."
            .into(),
    }
}

pub fn render_markdown(report: &Report, input_path: Option<&str>) -> String {
    let mut out = String::new();
    out.push_str("# ysnp Report\n\n");
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

    out.push_str("## SARIF\n\n");
    out.push_str(&format!(
        "- Rules: {}\n- Results: {}\n- Generate with: `ysnp scan --sarif`\n\n",
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
            out.push_str("**Metadata**\n\n");
            for (k, v) in &f.meta {
                out.push_str(&format!("- {}: {}\n", k, v));
            }
            out.push('\n');
        }
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
