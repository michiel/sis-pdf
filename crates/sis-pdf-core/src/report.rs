use std::collections::{BTreeMap, BTreeSet};

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
    #[serde(default)]
    pub network_intents: Vec<crate::campaign::NetworkIntent>,
    #[serde(default)]
    pub response_rules: Vec<crate::yara::YaraRule>,
    #[serde(default)]
    pub structural_summary: Option<StructuralSummary>,
    #[serde(default)]
    pub ml_summary: Option<MlSummary>,
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
        network_intents: Vec<crate::campaign::NetworkIntent>,
        response_rules: Vec<crate::yara::YaraRule>,
        structural_summary: Option<StructuralSummary>,
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
        let ml_summary = ml_summary_from_findings(&findings);
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
            network_intents,
            response_rules,
            structural_summary,
            ml_summary,
        }
    }

    pub fn with_input_path(mut self, input_path: Option<String>) -> Self {
        self.input_path = input_path;
        self
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct StructuralSummary {
    pub startxref_count: usize,
    pub trailer_count: usize,
    pub object_count: usize,
    pub objstm_count: usize,
    pub objstm_ratio: f64,
    pub recover_xref: bool,
    pub deep_scan: bool,
    pub header_offset: Option<u64>,
    pub eof_offset: Option<u64>,
    pub eof_distance_to_end: Option<u64>,
    pub polyglot_risk: bool,
    pub polyglot_signatures: Vec<String>,
    pub secondary_parser: Option<SecondaryParserSummary>,
    pub secondary_parser_error: Option<String>,
    pub ir_summary: Option<IrSummary>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SecondaryParserSummary {
    pub parser: String,
    pub object_count: usize,
    pub trailer_count: usize,
    pub missing_in_secondary: usize,
    pub missing_in_primary: usize,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct MlSummary {
    pub graph: Option<MlRunSummary>,
    pub traditional: Option<MlRunSummary>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct MlRunSummary {
    pub score: f32,
    pub threshold: f32,
    pub label: bool,
    pub kind: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct IrSummary {
    pub object_count: usize,
    pub line_count: usize,
    pub action_object_count: usize,
    pub payload_object_count: usize,
    pub edge_count: usize,
}

pub fn print_human(report: &Report) {
    println!("Findings: {}", report.summary.total);
    println!(
        "High: {}  Medium: {}  Low: {}  Info: {}",
        report.summary.high, report.summary.medium, report.summary.low, report.summary.info
    );
    if let Some((risk, sigs)) = polyglot_summary(&report.findings) {
        let line = if sigs.is_empty() {
            risk
        } else {
            format!("{} ({})", risk, sigs.join(", "))
        };
        println!("Polyglot risk: {}", line);
    }
    if let Some(summary) = &report.structural_summary {
        println!();
        println!("Structural reconciliation");
        println!(
            "  Objects: {}  ObjStm: {} (ratio {:.3})",
            summary.object_count, summary.objstm_count, summary.objstm_ratio
        );
        println!(
            "  startxref: {}  trailers: {}",
            summary.startxref_count, summary.trailer_count
        );
        println!(
            "  Recover xref: {}  Deep scan: {}",
            summary.recover_xref, summary.deep_scan
        );
        match summary.header_offset {
            Some(offset) => println!("  Header offset: {}", offset),
            None => println!("  Header offset: not found"),
        }
        match summary.eof_offset {
            Some(offset) => {
                let distance = summary.eof_distance_to_end.unwrap_or(0);
                println!("  EOF offset: {} (distance to end {})", offset, distance);
            }
            None => println!("  EOF offset: not found"),
        }
        if summary.polyglot_risk {
            let sigs = if summary.polyglot_signatures.is_empty() {
                "-".into()
            } else {
                summary.polyglot_signatures.join(", ")
            };
            println!("  Polyglot risk: yes ({})", sigs);
        } else {
            println!("  Polyglot risk: no");
        }
        if let Some(ir) = &summary.ir_summary {
            println!(
                "  IR/ORG: objects={} lines={} actions={} payloads={} edges={}",
                ir.object_count,
                ir.line_count,
                ir.action_object_count,
                ir.payload_object_count,
                ir.edge_count
            );
        }
        if let Some(sec) = &summary.secondary_parser {
            println!(
                "  Secondary parser: {} objects={} trailers={} missing_in_secondary={} missing_in_primary={}",
                sec.parser,
                sec.object_count,
                sec.trailer_count,
                sec.missing_in_secondary,
                sec.missing_in_primary
            );
        } else if let Some(err) = &summary.secondary_parser_error {
            println!("  Secondary parser: failed ({})", err);
        } else {
            println!("  Secondary parser: not run");
        }
    }
    if let Some(ml) = &report.ml_summary {
        println!();
        println!("ML summary");
        if let Some(run) = &ml.graph {
            println!(
                "  Graph: score {:.4} threshold {:.4} label {}",
                run.score, run.threshold, run.label
            );
        }
        if let Some(run) = &ml.traditional {
            println!(
                "  Traditional: score {:.4} threshold {:.4} label {}",
                run.score, run.threshold, run.label
            );
        }
    }
    if let Some(resource) = resource_risk_summary(&report.findings) {
        println!();
        println!("Resource risks");
        println!(
            "  Embedded files: {}  File specs: {}  Rich media: {}  3D: {}  Sound/Movie: {}",
            resource.embedded_files,
            resource.filespecs,
            resource.richmedia,
            resource.three_d,
            resource.sound_movie
        );
    }
    println!();
    for (surface, kinds) in &report.grouped {
        println!("{}", escape_control(surface));
        for (kind, ids) in kinds {
            println!("  {} ({})", escape_control(kind), ids.len());
            for id in ids {
                println!("    - {}", escape_control(id));
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
            println!("{} — {}", escape_control(&f.id), escape_control(&f.title));
            println!("```");
            println!("{}", escape_control(payload));
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

fn escape_control(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_control() && ch != '\n' && ch != '\t' {
            out.push_str(&format!("\\x{:02X}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
}

fn escape_markdown(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '(' | ')' | '#' | '+' | '-' | '.'
            | '!' | '|' | '>' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

fn polyglot_summary(findings: &[Finding]) -> Option<(String, Vec<String>)> {
    let mut sigs = Vec::new();
    let mut found = false;
    for f in findings {
        if f.kind == "polyglot_signature_conflict" {
            found = true;
            if let Some(list) = f.meta.get("polyglot.signatures") {
                sigs.extend(
                    list.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty()),
                );
            }
        }
    }
    if found {
        sigs.sort();
        sigs.dedup();
        Some(("yes".into(), sigs))
    } else {
        Some(("no".into(), Vec::new()))
    }
}

struct ResourceRiskSummary {
    embedded_files: usize,
    filespecs: usize,
    richmedia: usize,
    three_d: usize,
    sound_movie: usize,
}

fn resource_risk_summary(findings: &[Finding]) -> Option<ResourceRiskSummary> {
    let mut summary = ResourceRiskSummary {
        embedded_files: 0,
        filespecs: 0,
        richmedia: 0,
        three_d: 0,
        sound_movie: 0,
    };
    for f in findings {
        match f.kind.as_str() {
            "embedded_file_present" => summary.embedded_files += 1,
            "filespec_present" => summary.filespecs += 1,
            "richmedia_present" => summary.richmedia += 1,
            "3d_present" => summary.three_d += 1,
            "sound_movie_present" => summary.sound_movie += 1,
            _ => {}
        }
    }
    if summary.embedded_files == 0
        && summary.filespecs == 0
        && summary.richmedia == 0
        && summary.three_d == 0
        && summary.sound_movie == 0
    {
        None
    } else {
        Some(summary)
    }
}

fn ml_summary_from_findings(findings: &[Finding]) -> Option<MlSummary> {
    let mut graph = None;
    let mut traditional = None;
    for f in findings {
        if f.kind == "ml_graph_score_high" {
            let score = f
                .meta
                .get("ml.graph.score")
                .and_then(|v| v.parse::<f32>().ok())
                .unwrap_or(0.0);
            let threshold = f
                .meta
                .get("ml.graph.threshold")
                .and_then(|v| v.parse::<f32>().ok())
                .unwrap_or(0.0);
            graph = Some(MlRunSummary {
                score,
                threshold,
                label: true,
                kind: f.kind.clone(),
            });
        } else if f.kind == "ml_malware_score_high" {
            let score = f
                .meta
                .get("ml.score")
                .and_then(|v| v.parse::<f32>().ok())
                .unwrap_or(0.0);
            let threshold = f
                .meta
                .get("ml.threshold")
                .and_then(|v| v.parse::<f32>().ok())
                .unwrap_or(0.0);
            traditional = Some(MlRunSummary {
                score,
                threshold,
                label: true,
                kind: f.kind.clone(),
            });
        }
    }
    if graph.is_none() && traditional.is_none() {
        None
    } else {
        Some(MlSummary { graph, traditional })
    }
}

struct LinkEdge {
    from: String,
    to: String,
    reason: String,
}

fn build_link_edges(report: &Report) -> Vec<LinkEdge> {
    let mut keys: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for f in &report.findings {
        for obj in &f.objects {
            add_link_key(&mut keys, "object", obj, &f.id);
        }
        if let Some(target) = f.meta.get("action.target") {
            for token in split_values(target) {
                add_link_key(&mut keys, "action_target", &token, &f.id);
            }
        }
        if let Some(targets) = f.meta.get("supply_chain.action_targets") {
            for token in split_values(targets) {
                add_link_key(&mut keys, "action_target", &token, &f.id);
            }
        }
        if let Some(urls) = f.meta.get("js.ast_urls") {
            for token in split_values(urls) {
                add_link_key(&mut keys, "url", &token, &f.id);
            }
        }
        if let Some(payload_type) = f.meta.get("payload.type") {
            add_link_key(&mut keys, "payload", payload_type, &f.id);
        }
        if let Some(names) = f.meta.get("supply_chain.embedded_names") {
            for token in split_values(names) {
                add_link_key(&mut keys, "embedded_name", &token, &f.id);
            }
        }
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for ((kind, value), ids) in keys {
        if ids.len() < 2 {
            continue;
        }
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                let (a, b) = if ids[i] <= ids[j] {
                    (ids[i].clone(), ids[j].clone())
                } else {
                    (ids[j].clone(), ids[i].clone())
                };
                let reason = match kind.as_str() {
                    "object" => format!("shared object {}", value),
                    "action_target" => format!("shared action target {}", value),
                    "url" => format!("shared url {}", value),
                    "payload" => format!("shared payload {}", value),
                    "embedded_name" => format!("shared embedded filename {}", value),
                    _ => format!("shared {}", value),
                };
                if seen.insert((a.clone(), b.clone(), reason.clone())) {
                    out.push(LinkEdge {
                        from: a,
                        to: b,
                        reason,
                    });
                }
            }
        }
    }
    out
}

fn add_link_key(
    keys: &mut BTreeMap<(String, String), Vec<String>>,
    kind: &str,
    value: &str,
    finding_id: &str,
) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    keys.entry((kind.to_string(), value.to_string()))
        .or_default()
        .push(finding_id.to_string());
}

fn split_values(input: &str) -> Vec<String> {
    input
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_matches(['"', '\'']).to_string())
        .collect()
}

fn render_chain_notes(chain: &ExploitChain) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = chain
        .notes
        .iter()
        .filter(|(k, _)| {
            k.starts_with("action.")
                || k.starts_with("payload.")
                || k.starts_with("js.")
                || k.starts_with("supply_chain.")
                || k.starts_with("taint.")
                || k.starts_with("structural.")
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn render_finding_context(f: &Finding) -> String {
    let mut parts = Vec::new();
    parts.push(format!("kind `{}`", f.kind));
    parts.push(format!("severity {:?}", f.severity));
    parts.push(format!("impact {}", impact_rating_for_finding(f)));
    if let Some(target) = f.meta.get("action.target") {
        parts.push(format!("action_target {}", target));
    }
    if let Some(urls) = f.meta.get("js.ast_urls") {
        parts.push(format!("urls {}", urls));
    }
    if let Some(payload) = f.meta.get("payload.type") {
        parts.push(format!("payload {}", payload));
    }
    if !f.objects.is_empty() {
        parts.push(format!("objects {}", f.objects.join(", ")));
    }
    parts.join("; ")
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

fn impact_rating_for_finding(f: &Finding) -> &'static str {
    if let Some(r) = f.meta.get("impact.rating") {
        return if r.eq_ignore_ascii_case("high") {
            "High"
        } else if r.eq_ignore_ascii_case("medium") {
            "Medium"
        } else if r.eq_ignore_ascii_case("low") {
            "Low"
        } else {
            "Low"
        };
    }
    match f.severity {
        Severity::Critical | Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low | Severity::Info => "Low",
    }
}

fn runtime_effect_for_finding(f: &Finding) -> String {
    if let Some(action) = f.meta.get("action.s") {
        if action == "/JavaScript" {
            return "Viewer executes JavaScript in the document context; may access APIs, user data, or trigger further actions.".into();
        }
        if action == "/URI" {
            return "Viewer can open an external URL or prompt the user to navigate to a remote resource.".into();
        }
        if action == "/Launch" {
            return "Viewer may launch an external application or file, which can lead to user compromise.".into();
        }
        if action == "/SubmitForm" {
            return "Form submission can transmit data to external endpoints.".into();
        }
    }
    match f.kind.as_str() {
        "open_action_present" => "Automatic execution occurs on document open; downstream actions may run without user intent.".into(),
        "aa_present" | "aa_event_present" => "Event-driven actions can fire during viewing or interaction, enabling automatic execution.".into(),
        "js_present" => "JavaScript runs in the viewer context and can influence document behavior or user actions.".into(),
        "uri_present" => "User may be redirected to external resources, enabling phishing or data exfiltration.".into(),
        "launch_action_present" => "External application launch is possible, increasing risk of system compromise.".into(),
        "submitform_present" => "Form data may be transmitted to remote endpoints.".into(),
        "embedded_file_present" | "filespec_present" => "Embedded files can be extracted or opened by the user or viewer.".into(),
        "decoder_risk_present" | "decompression_ratio_suspicious" | "huge_image_dimensions" => {
            "Decoding may trigger resource exhaustion or vulnerable parser paths during rendering.".into()
        }
        "xref_conflict"
        | "incremental_update_chain"
        | "object_id_shadowing"
        | "objstm_density_high"
        | "stream_length_mismatch"
        | "missing_pdf_header"
        | "missing_eof_marker"
        | "parser_diff_structural" => {
            "No direct runtime behavior inferred; structural anomalies can alter how viewers parse and execute content.".into()
        }
        _ => "No direct runtime behavior inferred; increases attack surface or analysis risk.".into(),
    }
}

fn chain_effect_summary(chain: &ExploitChain) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(trigger) = &chain.trigger {
        if trigger.contains("OpenAction") {
            parts.push("Document open triggers execution".into());
        } else if trigger.contains("AA") {
            parts.push("Viewer event triggers execution".into());
        }
    }
    if let Some(action) = &chain.action {
        if action.contains("JavaScript") {
            parts.push("JavaScript executes in viewer context".into());
        } else if action.contains("URI") {
            parts.push("External navigation or fetch occurs".into());
        } else if action.contains("Launch") {
            parts.push("External application launch possible".into());
        }
    }
    if let Some(payload) = &chain.payload {
        if payload.contains("JS") || payload.contains("JavaScript") {
            parts.push("Script payload involved".into());
        } else if payload.contains("URI") {
            parts.push("External URL payload involved".into());
        } else if payload.contains("Embedded") {
            parts.push("Embedded payload involved".into());
        }
    }
    if parts.is_empty() {
        "Execution path inferred from linked findings; review trigger and payload details.".into()
    } else {
        parts.join("; ")
    }
}

fn chain_execution_narrative(chain: &ExploitChain, findings: &[Finding]) -> String {
    let mut lines: Vec<String> = Vec::new();
    if let Some(trigger) = &chain.trigger {
        if trigger.contains("OpenAction") {
            lines.push("Execution starts automatically when the document opens.".into());
        } else if trigger.contains("AA") {
            lines.push("Execution is tied to viewer events (Additional Actions).".into());
        }
    }
    if let Some(action) = &chain.action {
        if action.contains("JavaScript") {
            lines.push("JavaScript runs in the viewer context and can access document APIs.".into());
        } else if action.contains("URI") {
            lines.push("Viewer may navigate to an external URL or fetch remote content.".into());
        } else if action.contains("Launch") {
            lines.push("Viewer may launch an external application or file.".into());
        } else if action.contains("SubmitForm") {
            lines.push("Form data can be transmitted to external endpoints.".into());
        }
    }
    if let Some(payload) = &chain.payload {
        if payload.contains("JS") || payload.contains("JavaScript") {
            lines.push("Chain contains a script payload that can alter viewer behavior.".into());
        } else if payload.contains("URI") {
            lines.push("Chain references external URL payloads.".into());
        } else if payload.contains("Embedded") {
            lines.push("Chain involves embedded file payloads.".into());
        }
    }
    if let Some(target) = chain.notes.get("action.target") {
        lines.push(format!("Action target: {}.", target));
    }
    let mut js_notes: Vec<String> = Vec::new();
    for fid in &chain.findings {
        if let Some(f) = findings.iter().find(|f| &f.id == fid) {
            if let Some(summary) = f.meta.get("js.behaviour_summary") {
                js_notes.push(summary.clone());
            }
            if f.meta.get("js.obfuscation_suspected").map(|v| v == "true").unwrap_or(false) {
                js_notes.push("Obfuscation suspected in script payloads.".into());
            }
            if f.kind == "uri_present" {
                if let Some(url) = f.meta.get("uri.value") {
                    js_notes.push(format!("External URL observed: {}", url));
                }
            }
        }
    }
    if !js_notes.is_empty() {
        let mut uniq = js_notes;
        uniq.sort();
        uniq.dedup();
        lines.push(format!("Observed behavior signals: {}.", uniq.join("; ")));
    }
    if lines.is_empty() {
        "Insufficient context for a detailed narrative; review chain findings and payload details.".into()
    } else {
        lines.join(" ")
    }
}

fn runtime_behavior_summary(findings: &[Finding]) -> Vec<String> {
    let mut auto_exec = false;
    let mut js = false;
    let mut external = false;
    let mut launch = false;
    let mut submit = false;
    let mut embedded = false;
    let mut decoder = false;
    for f in findings {
        match f.kind.as_str() {
            "open_action_present" | "aa_present" | "aa_event_present" => auto_exec = true,
            "js_present" => js = true,
            "uri_present" | "gotor_present" => external = true,
            "launch_action_present" => launch = true,
            "submitform_present" => submit = true,
            "embedded_file_present" | "filespec_present" => embedded = true,
            "decoder_risk_present" | "decompression_ratio_suspicious" => decoder = true,
            _ => {}
        }
    }
    let mut out = Vec::new();
    if auto_exec {
        out.push("Automatic execution triggers detected (OpenAction/AA).".into());
    }
    if js {
        out.push("JavaScript execution likely in viewer context.".into());
    }
    if external {
        out.push("External navigation or remote resource access possible.".into());
    }
    if launch {
        out.push("External application or file launch possible.".into());
    }
    if submit {
        out.push("Form submission can transmit data externally.".into());
    }
    if embedded {
        out.push("Embedded files present; secondary payload delivery possible.".into());
    }
    if decoder {
        out.push("Decoder-heavy streams may trigger vulnerable code paths or resource exhaustion.".into());
    }
    out
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
    if let Some((risk, sigs)) = polyglot_summary(&report.findings) {
        let line = if sigs.is_empty() {
            risk
        } else {
            format!("{} ({})", risk, sigs.join(", "))
        };
        out.push_str(&format!(
            "- Polyglot risk: {}\n\n",
            escape_markdown(&line)
        ));
    }

    if let Some(path) = input_path {
        out.push_str(&format!("- Input: `{}`\n\n", escape_markdown(path)));
    }

    if let Some(summary) = &report.structural_summary {
        out.push_str("## Structural Reconciliation\n\n");
        out.push_str(&format!(
            "- Objects: {} (ObjStm: {}, ratio {:.3})\n",
            summary.object_count, summary.objstm_count, summary.objstm_ratio
        ));
        out.push_str(&format!(
            "- startxref markers: {} trailers: {}\n",
            summary.startxref_count, summary.trailer_count
        ));
        out.push_str(&format!(
            "- Recover xref: {} Deep scan: {}\n",
            summary.recover_xref, summary.deep_scan
        ));
        if let Some(offset) = summary.header_offset {
            out.push_str(&format!("- Header offset: {}\n", offset));
        } else {
            out.push_str("- Header offset: not found\n");
        }
        if let Some(offset) = summary.eof_offset {
            let distance = summary.eof_distance_to_end.unwrap_or(0);
            out.push_str(&format!(
                "- EOF offset: {} (distance to end {})\n",
                offset, distance
            ));
        } else {
            out.push_str("- EOF offset: not found\n");
        }
        if summary.polyglot_risk {
            let sigs = if summary.polyglot_signatures.is_empty() {
                "-".into()
            } else {
                summary.polyglot_signatures.join(", ")
            };
            out.push_str(&format!("- Polyglot risk: yes ({})\n", escape_markdown(&sigs)));
        } else {
            out.push_str("- Polyglot risk: no\n");
        }
        if let Some(ir) = &summary.ir_summary {
            out.push_str(&format!(
                "- IR/ORG: objects={} lines={} actions={} payloads={} edges={}\n",
                ir.object_count,
                ir.line_count,
                ir.action_object_count,
                ir.payload_object_count,
                ir.edge_count
            ));
        }
        if let Some(sec) = &summary.secondary_parser {
            out.push_str(&format!(
                "- Secondary parser: {} objects={} trailers={} missing_in_secondary={} missing_in_primary={}\n",
                escape_markdown(&sec.parser),
                sec.object_count,
                sec.trailer_count,
                sec.missing_in_secondary,
                sec.missing_in_primary
            ));
        } else if let Some(err) = &summary.secondary_parser_error {
            out.push_str(&format!(
                "- Secondary parser: failed ({})\n",
                escape_markdown(err)
            ));
        } else {
            out.push_str("- Secondary parser: not run\n");
        }
        out.push('\n');
    }

    if let Some(ml) = &report.ml_summary {
        out.push_str("## ML Summary\n\n");
        if let Some(run) = &ml.graph {
            out.push_str(&format!(
                "- Graph: score {:.4} threshold {:.4} label {}\n",
                run.score, run.threshold, run.label
            ));
        }
        if let Some(run) = &ml.traditional {
            out.push_str(&format!(
                "- Traditional: score {:.4} threshold {:.4} label {}\n",
                run.score, run.threshold, run.label
            ));
        }
        out.push('\n');
    }

    if let Some(resource) = resource_risk_summary(&report.findings) {
        out.push_str("## Resource Risks\n\n");
        out.push_str(&format!(
            "- Embedded files: {}\n- File specs: {}\n- Rich media: {}\n- 3D: {}\n- Sound/Movie: {}\n\n",
            resource.embedded_files,
            resource.filespecs,
            resource.richmedia,
            resource.three_d,
            resource.sound_movie
        ));
    }

    let runtime_summary = runtime_behavior_summary(&report.findings);
    if !runtime_summary.is_empty() {
        out.push_str("## Static Runtime Behavior\n\n");
        for line in runtime_summary {
            out.push_str(&format!("- {}\n", escape_markdown(&line)));
        }
        out.push('\n');
    }

    if let Some(summary) = &report.intent_summary {
        if !summary.buckets.is_empty() {
            out.push_str("## Intent Summary\n\n");
            for bucket in &summary.buckets {
                out.push_str(&format!(
                    "- {}: score={} confidence={:?} findings={}\n",
                    escape_markdown(&format!("{:?}", bucket.bucket)),
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
                        out.push_str(&format!(
                            "- {} (weight {})\n",
                            escape_markdown(&label),
                            weight
                        ));
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
                            out.push_str(&format!(
                                "- {}: {}\n",
                                escape_markdown(&f.id),
                                escape_markdown(&chain)
                            ));
                        } else {
                            out.push_str(&format!(
                                "- {}: {}\n",
                                escape_markdown(&f.id),
                                escape_markdown(&f.title)
                            ));
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
                                escape_markdown(&f.id),
                                ev.source,
                                ev.offset,
                                ev.length,
                                escape_markdown(&origin)
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
                    escape_markdown(&pattern.summary),
                    pattern.severity,
                    escape_markdown(&pattern.kinds.join(", ")),
                    escape_markdown(&pattern.objects.join(", "))
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
                escape_markdown(&threat.label),
                threat.confidence
            ));
        }
        out.push('\n');
    }

    if !report.network_intents.is_empty() {
        out.push_str("## Network Intents\n\n");
        for intent in &report.network_intents {
            let domain = intent.domain.as_deref().unwrap_or("-");
            out.push_str(&format!(
                "- {} (domain {})\n",
                escape_markdown(&intent.url),
                escape_markdown(domain)
            ));
        }
        out.push('\n');
    }

    if !report.response_rules.is_empty() {
        out.push_str("## Response Rules\n\n");
        for rule in &report.response_rules {
            out.push_str(&format!(
                "- {} (tags: {})\n",
                escape_markdown(&rule.name),
                escape_markdown(&rule.tags.join(", "))
            ));
        }
        out.push('\n');
    }

    if !report.chains.is_empty() {
        let link_edges = build_link_edges(report);
        out.push_str("## Exploit Chain Reconstruction\n\n");
        for chain in &report.chains {
            out.push_str(&format!(
                "### {} (score {:.2})\n\n",
                escape_markdown(&chain.id),
                chain.score
            ));
            out.push_str(&format!(
                "- Path: {}\n",
                escape_markdown(&chain.path)
            ));
            if let Some(trigger) = &chain.trigger {
                out.push_str(&format!("- Trigger: `{}`\n", escape_markdown(trigger)));
            }
            if let Some(action) = &chain.action {
                out.push_str(&format!("- Action: `{}`\n", escape_markdown(action)));
            }
            if let Some(payload) = &chain.payload {
                out.push_str(&format!("- Payload: `{}`\n", escape_markdown(payload)));
            }
            out.push_str(&format!(
                "- Effect: {}\n",
                escape_markdown(&chain_effect_summary(chain))
            ));
            out.push_str(&format!(
                "- Narrative: {}\n",
                escape_markdown(&chain_execution_narrative(chain, &report.findings))
            ));
            if let Some(target) = chain.notes.get("action.target") {
                out.push_str(&format!(
                    "- Action target: {}\n",
                    escape_markdown(target)
                ));
            }
            if !chain.reasons.is_empty() {
                out.push_str(&format!(
                    "- Score reasons: {}\n",
                    escape_markdown(&chain.reasons.join("; "))
                ));
            }
            out.push('\n');
            out.push_str("**Findings in chain**\n\n");
            if chain.findings.is_empty() {
                out.push_str("- No findings recorded\n\n");
            } else {
                for fid in &chain.findings {
                    if let Some(f) = report.findings.iter().find(|f| &f.id == fid) {
                        out.push_str(&format!(
                            "- {}: {} (surface `{:?}`) [{}]\n",
                            escape_markdown(&f.id),
                            escape_markdown(&f.title),
                            f.surface,
                            escape_markdown(&render_finding_context(f))
                        ));
                    } else {
                        out.push_str(&format!(
                            "- {}: (missing finding)\n",
                            escape_markdown(fid)
                        ));
                    }
                }
                out.push('\n');
            }
            let notes = render_chain_notes(chain);
            if !notes.is_empty() {
                out.push_str("**Chain notes**\n\n");
                for (k, v) in notes.into_iter().take(12) {
                    out.push_str(&format!(
                        "- {}: {}\n",
                        escape_markdown(&k),
                        escape_markdown(&v)
                    ));
                }
                out.push('\n');
            }
            out.push_str("**Link details**\n\n");
            let mut links = Vec::new();
            for edge in &link_edges {
                if chain.findings.iter().any(|fid| fid == &edge.from || fid == &edge.to) {
                    links.push(edge);
                }
            }
            if links.is_empty() {
                out.push_str("- No linked findings\n\n");
            } else {
                for edge in links.iter().take(12) {
                    let from_f = report.findings.iter().find(|f| f.id == edge.from);
                    let to_f = report.findings.iter().find(|f| f.id == edge.to);
                    let from_title = from_f.map(|f| f.title.as_str()).unwrap_or("unknown");
                    let to_title = to_f.map(|f| f.title.as_str()).unwrap_or("unknown");
                    let from_ctx = from_f
                        .map(render_finding_context)
                        .unwrap_or_else(|| "-".into());
                    let to_ctx = to_f
                        .map(render_finding_context)
                        .unwrap_or_else(|| "-".into());
                    out.push_str(&format!(
                        "- {} ({}) -> {} ({}) via {}\n",
                        escape_markdown(&edge.from),
                        escape_markdown(from_title),
                        escape_markdown(&edge.to),
                        escape_markdown(to_title),
                        escape_markdown(&edge.reason)
                    ));
                    out.push_str(&format!(
                        "  - left: {}\n",
                        escape_markdown(&from_ctx)
                    ));
                    out.push_str(&format!(
                        "  - right: {}\n",
                        escape_markdown(&to_ctx)
                    ));
                }
                out.push('\n');
            }
        }
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
            out.push_str(&format!(
                "- {}: {}\n",
                escape_markdown(&f.id),
                escape_markdown(&f.title)
            ));
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
            out.push_str(&format!(
                "- {} (tags: {})\n",
                escape_markdown(&rule.name),
                escape_markdown(&tags)
            ));
        }
        out.push('\n');
    }

    out.push_str("## Findings\n\n");
    for f in &report.findings {
        out.push_str(&format!(
            "### {} — {}\n\n",
            escape_markdown(&f.id),
            escape_markdown(&f.title)
        ));
        out.push_str(&format!("- Surface: `{:?}`\n", f.surface));
        out.push_str(&format!("- Kind: `{}`\n", escape_markdown(&f.kind)));
        out.push_str(&format!("- Severity: `{:?}`\n", f.severity));
        out.push_str(&format!(
            "- Impact rating: `{}`\n",
            impact_rating_for_finding(f)
        ));
        out.push_str(&format!("- Confidence: `{:?}`\n", f.confidence));
        if !f.objects.is_empty() {
            out.push_str(&format!(
                "- Objects: {}\n",
                escape_markdown(&f.objects.join(", "))
            ));
        }
        if let Some(page) = f.meta.get("page.number") {
            out.push_str(&format!("- Page: {}\n", escape_markdown(page)));
        }
        if let Some(coord) = f.meta.get("content.coord") {
            out.push_str(&format!("- Coord: {}\n", escape_markdown(coord)));
        }
        out.push_str("\n**Description**\n\n");
        out.push_str(&format!("{}\n\n", escape_markdown(&f.description)));
        out.push_str("**Runtime Effect**\n\n");
        out.push_str(&format!(
            "{}\n\n",
            escape_markdown(&runtime_effect_for_finding(f))
        ));
        if let Some(s) = f.meta.get("action.s") {
            out.push_str("**Action Details**\n\n");
            out.push_str(&format!(
                "- Action type: `{}`\n",
                escape_markdown(s)
            ));
            if let Some(t) = f.meta.get("action.target") {
                out.push_str(&format!("- Target: {}\n", escape_markdown(t)));
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
            out.push_str(&escape_control(payload));
            out.push_str("\n```\n\n");
        }
        if let Some(chain) = render_action_chain(f) {
            out.push_str("**Action Chain**\n\n");
            out.push_str(&format!("{}\n\n", escape_markdown(&chain)));
        }
        if let Some(behaviour) = render_payload_behaviour(f) {
            out.push_str("**Payload Behaviour**\n\n");
            out.push_str(&format!("{}\n\n", escape_markdown(&behaviour)));
        }
        let impact = f
            .meta
            .get("impact")
            .cloned()
            .unwrap_or_else(|| impact_for_finding(f));
        out.push_str("**Impact**\n\n");
        out.push_str(&format!("{}\n\n", escape_markdown(&impact)));
        if let Some(y) = &f.yara {
            out.push_str("**YARA**\n\n");
            out.push_str(&format!(
                "- Rule: `{}`\n",
                escape_markdown(&y.rule_name)
            ));
            if !y.tags.is_empty() {
                out.push_str(&format!(
                    "- Tags: {}\n",
                    escape_markdown(&y.tags.join(", "))
                ));
            }
            if !y.strings.is_empty() {
                out.push_str(&format!(
                    "- Strings: {}\n",
                    escape_markdown(&y.strings.join(", "))
                ));
            }
            if let Some(ns) = &y.namespace {
                out.push_str(&format!("- Namespace: {}\n", escape_markdown(ns)));
            }
            out.push('\n');
        }
        if let Some(rem) = &f.remediation {
            out.push_str("**Remediation**\n\n");
            out.push_str(&format!("{}\n\n", escape_markdown(rem)));
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
                    ev.source,
                    ev.offset,
                    ev.length,
                    escape_markdown(&origin)
                ));
                if let Some(note) = &ev.note {
                    out.push_str(&format!(" note={}", escape_markdown(note)));
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
                    out.push_str(&format!(
                        "| {} | {} |\n",
                        escape_markdown(k),
                        escape_markdown(&escape_control(v))
                    ));
                }
                out.push('\n');
            }
            if !js_meta.is_empty() {
                out.push_str("**JavaScript Metadata**\n\n");
                out.push_str("| Key | Value |\n");
                out.push_str("| --- | ----- |\n");
                for (k, v) in js_meta {
                    out.push_str(&format!(
                        "| {} | {} |\n",
                        escape_markdown(k),
                        escape_markdown(&escape_control(v))
                    ));
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
            escape_markdown(&entry.path),
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

#[cfg(test)]
mod tests {
    use super::escape_control;

    #[test]
    fn escapes_control_chars() {
        let input = "ok\x1b[31mred";
        let escaped = escape_control(input);
        assert!(escaped.contains("\\x1B"));
        assert!(!escaped.contains('\x1b'));
    }
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
