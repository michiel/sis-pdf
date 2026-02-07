use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;

use anyhow::Result;

use crate::chain::{ChainTemplate, ExploitChain};
use crate::chain_render::{chain_action_label, chain_payload_label, chain_trigger_label};
use crate::intent::IntentSummary;
use crate::model::{AttackSurface, Finding, Severity};
use crate::reader_context;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Summary {
    pub total: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug)]
struct ChainSummaryEntry {
    path: String,
    trigger_label: String,
    action_label: String,
    payload_label: String,
    outcome: Option<String>,
    narrative: Option<String>,
    instances: usize,
    score: f64,
    reasons: Vec<String>,
    node_preview: Option<String>,
    finding_kinds: Vec<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct SandboxSummary {
    pub enabled: bool,
    pub disabled_reason: Option<String>,
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
    #[serde(default)]
    pub ml_inference: Option<crate::ml_inference::MlInferenceResult>,
    #[serde(default)]
    pub temporal_signals: Option<TemporalSignalSummary>,
    #[serde(default)]
    pub temporal_snapshots: Option<Vec<crate::explainability::TemporalSnapshot>>,
    #[serde(default)]
    pub sandbox_summary: Option<SandboxSummary>,
    #[serde(default)]
    pub detection_duration_ms: Option<u64>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BatchEntry {
    pub path: String,
    pub summary: Summary,
    pub duration_ms: u64,
    pub detection_duration_ms: Option<u64>,
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

fn chain_note<'a>(chain: &'a ExploitChain, key: &str) -> Option<&'a str> {
    chain.notes.get(key).map(String::as_str)
}

impl Report {
    #[allow(clippy::too_many_arguments)]
    pub fn from_findings(
        mut findings: Vec<Finding>,
        chains: Vec<ExploitChain>,
        chain_templates: Vec<ChainTemplate>,
        yara_rules: Vec<crate::yara::YaraRule>,
        intent_summary: Option<IntentSummary>,
        behavior_summary: Option<crate::behavior::BehaviorSummary>,
        future_threats: Vec<crate::predictor::FutureThreat>,
        network_intents: Vec<crate::campaign::NetworkIntent>,
        response_rules: Vec<crate::yara::YaraRule>,
        structural_summary: Option<StructuralSummary>,
        ml_summary_override: Option<MlSummary>,
    ) -> Self {
        for finding in &mut findings {
            reader_context::annotate_reader_context(finding);
        }

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
        let ml_summary = ml_summary_override.or_else(|| ml_summary_from_findings(&findings));
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
            ml_inference: None,
            temporal_signals: None,
            temporal_snapshots: None,
            sandbox_summary: None,
            detection_duration_ms: None,
        }
    }

    pub fn with_input_path(mut self, input_path: Option<String>) -> Self {
        self.input_path = input_path;
        self
    }

    pub fn with_sandbox_summary(mut self, summary: SandboxSummary) -> Self {
        self.sandbox_summary = Some(summary);
        self
    }

    pub fn with_ml_inference(
        mut self,
        ml_inference: Option<crate::ml_inference::MlInferenceResult>,
    ) -> Self {
        self.ml_inference = ml_inference;
        self
    }

    pub fn with_temporal_signals(
        mut self,
        temporal_signals: Option<TemporalSignalSummary>,
    ) -> Self {
        self.temporal_signals = temporal_signals;
        self
    }

    pub fn with_temporal_snapshots(
        mut self,
        temporal_snapshots: Option<Vec<crate::explainability::TemporalSnapshot>>,
    ) -> Self {
        self.temporal_snapshots = temporal_snapshots;
        self
    }

    pub fn with_detection_duration(mut self, detection_duration_ms: Option<u64>) -> Self {
        self.detection_duration_ms = detection_duration_ms;
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
    #[serde(default)]
    pub canonical_object_count: usize,
    #[serde(default)]
    pub incremental_updates_removed: usize,
    #[serde(default)]
    pub normalized_name_changes: usize,
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
    #[serde(default)]
    pub mode: Option<String>,
    pub graph: Option<MlRunSummary>,
    pub traditional: Option<MlRunSummary>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TemporalSignalSummary {
    pub revisions: usize,
    pub new_high_severity: usize,
    pub new_attack_surfaces: Vec<String>,
    pub removed_findings: Vec<String>,
    pub new_findings: Vec<String>,
    pub structural_deltas: Vec<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct MlNodeAttribution {
    pub obj_ref: String,
    pub summary: String,
    pub score: f32,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct MlRunSummary {
    pub score: f32,
    pub threshold: f32,
    pub label: bool,
    pub kind: String,
    #[serde(default)]
    pub top_nodes: Option<Vec<MlNodeAttribution>>,
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
        let line = if sigs.is_empty() { risk } else { format!("{} ({})", risk, sigs.join(", ")) };
        println!("Polyglot risk: {}", line);
    }
    if let Some(summary) = &report.structural_summary {
        println!();
        println!("Structural reconciliation");
        println!(
            "  Objects: {}  ObjStm: {} (ratio {:.3})",
            summary.object_count, summary.objstm_count, summary.objstm_ratio
        );
        println!("  startxref: {}  trailers: {}", summary.startxref_count, summary.trailer_count);
        println!("  Recover xref: {}  Deep scan: {}", summary.recover_xref, summary.deep_scan);
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
        println!("ML findings");
        println!("  ML summary");
        if let Some(mode) = ml_mode_label(ml) {
            println!("    Mode: {}", mode);
            if ml_mode_includes_graph(mode) {
                if let Some(run) = &ml.graph {
                    println!(
                        "    Graph: score {:.4} threshold {:.4} label {} ({})",
                        run.score,
                        run.threshold,
                        run.label,
                        ml_assessment(run.label)
                    );
                } else if has_ml_error(&report.findings) {
                    println!("    Graph: error (see ml_model_error findings)");
                }
            }
            if ml_mode_includes_traditional(mode) {
                if let Some(run) = &ml.traditional {
                    println!(
                        "    Traditional: score {:.4} threshold {:.4} label {} ({})",
                        run.score,
                        run.threshold,
                        run.label,
                        ml_assessment(run.label)
                    );
                } else if has_ml_error(&report.findings) {
                    println!("    Traditional: error (see ml_model_error findings)");
                }
            }
        } else if has_ml_error(&report.findings) {
            println!("    Status: error (see ml_model_error findings)");
        }
        println!();
        println!("  ML details");
        if let Some(mode) = ml_mode_label(ml) {
            if ml_mode_includes_graph(mode) {
                if let Some(run) = &ml.graph {
                    println!(
                        "    Graph: kind={} score {:.4} threshold {:.4} label {} ({})",
                        run.kind,
                        run.score,
                        run.threshold,
                        run.label,
                        ml_assessment(run.label)
                    );
                    if let Some(nodes) = &run.top_nodes {
                        println!("    Graph top nodes:");
                        for node in nodes {
                            println!(
                                "      - {} score {:.4} ({})",
                                node.obj_ref, node.score, node.summary
                            );
                        }
                    }
                } else if has_ml_error(&report.findings) {
                    println!("    Graph: error (see ml_model_error findings)");
                }
            }
            if ml_mode_includes_traditional(mode) {
                if let Some(run) = &ml.traditional {
                    println!(
                        "    Traditional: kind={} score {:.4} threshold {:.4} label {} ({})",
                        run.kind,
                        run.score,
                        run.threshold,
                        run.label,
                        ml_assessment(run.label)
                    );
                    if let Some(nodes) = &run.top_nodes {
                        println!("    Traditional top nodes:");
                        for node in nodes {
                            println!(
                                "      - {} score {:.4} ({})",
                                node.obj_ref, node.score, node.summary
                            );
                        }
                    }
                } else if has_ml_error(&report.findings) {
                    println!("    Traditional: error (see ml_model_error findings)");
                }
            }
        } else if has_ml_error(&report.findings) {
            println!("    Status: error (see ml_model_error findings)");
        }
    }
    if let Some(ml) = &report.ml_inference {
        println!();
        println!("ML inference");
        println!(
            "  Score: {:.4} threshold {:.4} label {} ({})",
            ml.prediction.calibrated_score,
            ml.prediction.threshold,
            ml.prediction.label,
            ml_assessment(ml.prediction.label)
        );
        println!(
            "  Raw: {:.4} calibration: {}",
            ml.prediction.raw_score, ml.prediction.calibration_method
        );
        if let Some((low, high)) = ml.prediction.confidence_interval {
            println!("  Confidence interval (95%): {:.4}-{:.4}", low, high);
        }
        if let Some(explanation) = &ml.explanation {
            println!("  Summary: {}", escape_control(&explanation.summary));
            if !explanation.decision_factors.is_empty() {
                println!("  Decision factors:");
                for factor in explanation.decision_factors.iter().take(5) {
                    println!("    - {}", escape_control(factor));
                }
            }
        }
    }
    if let Some(signals) = &report.temporal_signals {
        println!();
        println!("Temporal signals");
        println!("  Revisions: {}", signals.revisions);
        if signals.new_high_severity > 0 {
            println!("  New high-severity findings: {}", signals.new_high_severity);
        }
        if !signals.new_attack_surfaces.is_empty() {
            println!("  New attack surfaces: {}", signals.new_attack_surfaces.join(", "));
        }
        if !signals.new_findings.is_empty() {
            println!("  New findings: {}", signals.new_findings.len());
        }
        if !signals.removed_findings.is_empty() {
            println!("  Removed findings: {}", signals.removed_findings.len());
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
        if let Some(payload) =
            f.meta.get("payload.decoded_preview").or_else(|| f.meta.get("payload.preview"))
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
    if let Some(ml) = &report.ml_inference {
        let record = serde_json::json!({
            "type": "ml_inference",
            "prediction": ml.prediction,
            "explanation": ml.explanation,
        });
        println!("{}", serde_json::to_string(&record)?);
    }
    if let Some(signals) = &report.temporal_signals {
        let record = serde_json::json!({
            "type": "temporal_signal_summary",
            "summary": signals,
        });
        println!("{}", serde_json::to_string(&record)?);
    }
    if let Some(snapshots) = &report.temporal_snapshots {
        for snapshot in snapshots {
            let record = serde_json::json!({
                "type": "ml_temporal_snapshot",
                "snapshot": snapshot,
            });
            println!("{}", serde_json::to_string(&record)?);
        }
    }
    Ok(())
}

pub fn write_jsonl_findings(report: &Report, writer: &mut dyn Write) -> Result<()> {
    let path = report.input_path.as_deref().unwrap_or("-");
    for f in &report.findings {
        let record = serde_json::json!({
            "path": path,
            "finding": f,
        });
        writer.write_all(serde_json::to_string(&record)?.as_bytes())?;
        writer.write_all(b"\n")?;
    }
    if let Some(ml) = &report.ml_inference {
        let record = serde_json::json!({
            "type": "ml_inference",
            "path": path,
            "prediction": ml.prediction,
            "explanation": ml.explanation,
        });
        writer.write_all(serde_json::to_string(&record)?.as_bytes())?;
        writer.write_all(b"\n")?;
    }
    if let Some(signals) = &report.temporal_signals {
        let record = serde_json::json!({
            "type": "temporal_signal_summary",
            "path": path,
            "summary": signals,
        });
        writer.write_all(serde_json::to_string(&record)?.as_bytes())?;
        writer.write_all(b"\n")?;
    }
    if let Some(snapshots) = &report.temporal_snapshots {
        for snapshot in snapshots {
            let record = serde_json::json!({
                "type": "ml_temporal_snapshot",
                "path": path,
                "snapshot": snapshot,
            });
            writer.write_all(serde_json::to_string(&record)?.as_bytes())?;
            writer.write_all(b"\n")?;
        }
    }
    Ok(())
}

pub fn print_jsonl_findings(report: &Report) -> Result<()> {
    let mut writer = std::io::stdout();
    write_jsonl_findings(report, &mut writer)
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
                    list.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
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

fn finding_context(kind: &str) -> Option<&'static str> {
    match kind {
        "icc_profile_anomaly" => Some("Malformed ICC profiles often trigger color-management bugs (e.g., Adobe CVE reports) and can conceal malicious imagery or metadata."),
        "annotation_action_chain" => Some("Annotation chains frequently wrap multiple URI/action steps, allowing attackers to hide phishing redirects behind layered annotations."),
        "uri_present" => Some("URIs often ferry phishing destinations or downloader links; attackers hide them in actions, JavaScript, or annotations to evade static filters."),
        "launch_action_present" => Some("Launch actions invoke external executables and have been abused to stage binaries via malicious PDFs in targeted campaigns."),
        "js_present" => Some("JavaScript actions enable heap sprays, obfuscation, and chained payload delivery; attackers rely on them for staged compromise."),
        "polyglot_signature_conflict" => Some("PDFs that also match ZIP/HTML/Image signatures are classic polyglots used to sneak payloads past scanners that only look at headers."),
        "invalid_pdf_header" => Some("Tampered headers signal evasion or corruption and have featured in parser-differential attacks where attackers append other formats to the PDF."),
        _ => None,
    }
}

fn doc_link_for_finding(f: &Finding) -> Option<&'static str> {
    const FILTER_FLATE_DOC: &str = "docs/filter-flatedecode.md";
    const OBJSTM_DOC: &str = "docs/findings.md#objstm_embedded_summary";

    if f.kind == "objstm_embedded_summary" {
        return Some(OBJSTM_DOC);
    }
    if f.kind == "declared_filter_invalid" {
        if let Some(mismatch) = f.meta.get("decode.mismatch") {
            if mismatch.contains("/FlateDecode") {
                return Some(FILTER_FLATE_DOC);
            }
        }
        if let Some(filters) = f.meta.get("stream.filters") {
            if filters.contains("/FlateDecode") {
                return Some(FILTER_FLATE_DOC);
            }
        }
    }
    None
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
            let score =
                f.meta.get("ml.graph.score").and_then(|v| v.parse::<f32>().ok()).unwrap_or(0.0);
            let threshold =
                f.meta.get("ml.graph.threshold").and_then(|v| v.parse::<f32>().ok()).unwrap_or(0.0);
            graph = Some(MlRunSummary {
                score,
                threshold,
                label: true,
                kind: f.kind.clone(),
                top_nodes: None,
            });
        } else if f.kind == "ml_malware_score_high" {
            let score = f.meta.get("ml.score").and_then(|v| v.parse::<f32>().ok()).unwrap_or(0.0);
            let threshold =
                f.meta.get("ml.threshold").and_then(|v| v.parse::<f32>().ok()).unwrap_or(0.0);
            traditional = Some(MlRunSummary {
                score,
                threshold,
                label: true,
                kind: f.kind.clone(),
                top_nodes: None,
            });
        }
    }
    if graph.is_none() && traditional.is_none() {
        None
    } else {
        let mode = if graph.is_some() && traditional.is_some() {
            Some("graph+traditional".to_string())
        } else if graph.is_some() {
            Some("graph".to_string())
        } else if traditional.is_some() {
            Some("traditional".to_string())
        } else {
            None
        };
        Some(MlSummary { mode, graph, traditional })
    }
}

fn has_ml_error(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.kind == "ml_model_error")
}

fn ml_mode_label(summary: &MlSummary) -> Option<&str> {
    if let Some(mode) = summary.mode.as_deref() {
        return Some(mode);
    }
    if summary.graph.is_some() && summary.traditional.is_some() {
        Some("graph+traditional")
    } else if summary.graph.is_some() {
        Some("graph")
    } else if summary.traditional.is_some() {
        Some("traditional")
    } else {
        None
    }
}

fn ml_mode_includes_graph(mode: &str) -> bool {
    mode == "graph" || mode == "graph+traditional"
}

fn ml_mode_includes_traditional(mode: &str) -> bool {
    mode == "traditional" || mode == "graph+traditional"
}

fn ml_assessment(label: bool) -> &'static str {
    if label {
        "above threshold (flagged)"
    } else {
        "below threshold (not flagged)"
    }
}

fn build_position_preview_map(findings: &[Finding]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for f in findings {
        let mut positions = Vec::new();
        if let Some(position) = &f.position {
            positions.push(position.clone());
        }
        positions.extend(f.positions.iter().cloned());
        positions.sort();
        positions.dedup();
        for position in positions {
            let preview = position_preview_for_finding(f, &position)
                .or_else(|| select_position_preview(f))
                .unwrap_or_else(|| f.title.clone());
            if preview.trim().is_empty() {
                continue;
            }
            out.entry(position).or_insert(preview);
        }
    }
    out
}

fn position_preview_for_finding(f: &Finding, position: &str) -> Option<String> {
    let (obj, gen) = parse_position_obj_ref(position)?;
    let key = format!("position.preview.{}:{}", obj, gen);
    f.meta.get(&key).cloned()
}

fn parse_position_obj_ref(position: &str) -> Option<(u32, u16)> {
    let (_, obj_ref) = position.split_once('@')?;
    let (obj, gen) = obj_ref.split_once(':')?;
    let obj_id = obj.parse::<u32>().ok()?;
    let gen_id = gen.parse::<u16>().ok()?;
    Some((obj_id, gen_id))
}

fn select_position_preview(f: &Finding) -> Option<String> {
    let keys = [
        "position.preview",
        "payload.decoded_preview",
        "payload.deobfuscated_preview",
        "payload.preview",
        "embedded.decoded_preview",
        "action.target",
        "uri.url",
        "js.behaviour_summary",
    ];
    for key in keys {
        if let Some(value) = f.meta.get(key) {
            if !value.trim().is_empty() {
                return Some(value.clone());
            }
        }
    }
    None
}

#[allow(dead_code)]
fn render_aligned_preview_lines(entries: &[(String, String)], preview_len: usize) -> Vec<String> {
    let width = entries.iter().map(|(pos, _)| pos.len()).max().unwrap_or(0);
    entries
        .iter()
        .map(|(pos, preview)| {
            let preview = sanitise_preview(preview, preview_len);
            format!("{:<width$} | \"{}\"", pos, preview, width = width)
        })
        .collect()
}

#[allow(dead_code)]
fn node_summary(
    node: &str,
    position_previews: &BTreeMap<String, String>,
    findings: &[Finding],
    chain: &ExploitChain,
) -> String {
    if let Some(preview) = position_previews.get(node) {
        return preview.clone();
    }
    let mut summaries = Vec::new();
    for fid in &chain.findings {
        if summaries.len() >= 3 {
            break;
        }
        if let Some(f) = findings.iter().find(|f| &f.id == fid) {
            if f.position.as_deref() == Some(node) || f.positions.iter().any(|pos| pos == node) {
                summaries.push(summary_for_finding(f));
            }
        }
    }
    if summaries.is_empty() {
        node.to_string()
    } else {
        summaries.join(" | ")
    }
}

#[allow(dead_code)]
fn summary_for_finding(f: &Finding) -> String {
    let mut summary = if !f.title.is_empty() { f.title.clone() } else { f.kind.clone() };
    if let Some(target) = f.meta.get("action.target") {
        if !target.trim().is_empty() {
            summary = format!("{summary} -> {}", target.trim());
        }
    }
    summary
}

#[allow(dead_code)]
fn chain_finding_reasons(
    chain: &ExploitChain,
    findings: &[Finding],
    id_map: &BTreeMap<String, String>,
    limit: usize,
) -> Vec<String> {
    let mut reasons = Vec::new();
    for fid in &chain.findings {
        if reasons.len() >= limit {
            break;
        }
        if let Some(f) = findings.iter().find(|f| &f.id == fid) {
            let mut text = format!("{}: {}", display_id(&f.id, id_map), f.title);
            if let Some(target) = f.meta.get("action.target") {
                if !target.trim().is_empty() {
                    text = format!("{text} -> {}", target.trim());
                }
            }
            reasons.push(text);
        }
    }
    reasons
}

#[allow(dead_code)]
fn sanitise_preview(preview: &str, max_len: usize) -> String {
    let mut cleaned = String::with_capacity(preview.len());
    for ch in preview.chars() {
        if ch.is_ascii() {
            if ch.is_ascii_control() {
                cleaned.push(' ');
            } else {
                cleaned.push(ch);
            }
        } else {
            cleaned.push('?');
        }
    }
    let mut out =
        cleaned.split_whitespace().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ");
    if max_len == 0 {
        return String::new();
    }
    if out.len() > max_len {
        if max_len > 3 {
            out.truncate(max_len - 3);
            out.push_str("...");
        } else {
            out.truncate(max_len);
        }
    }
    out
}

#[allow(dead_code)]
struct ParsedPositionEntry {
    revision: String,
    path_segments: Vec<String>,
    obj_ref: String,
    preview: String,
}

#[allow(dead_code)]
fn parse_canonical_position(position: &str, preview: &str) -> Option<ParsedPositionEntry> {
    let trimmed = position.trim();
    let after_doc = trimmed.strip_prefix("doc:")?;
    let (rev_and_path, obj_ref) = after_doc.split_once('@')?;
    let mut parts = rev_and_path.splitn(2, '/');
    let revision = parts.next()?.to_string();
    let path = parts.next().unwrap_or("?").trim();
    let path_segments = if path.is_empty() {
        vec!["?".to_string()]
    } else {
        path.split('.').map(|s| s.to_string()).collect()
    };
    Some(ParsedPositionEntry {
        revision,
        path_segments,
        obj_ref: obj_ref.to_string(),
        preview: preview.to_string(),
    })
}

#[derive(Default)]
#[allow(dead_code)]
struct PositionTreeNode {
    label: String,
    obj_ref: Option<String>,
    preview: Option<String>,
    children: BTreeMap<String, PositionTreeNode>,
}

#[allow(dead_code)]
impl PositionTreeNode {
    fn insert(&mut self, segments: &[String], obj_ref: String, preview: String) {
        if segments.is_empty() {
            return;
        }
        let mut node = self;
        for segment in segments {
            node = node.children.entry(segment.clone()).or_insert_with(|| PositionTreeNode {
                label: segment.clone(),
                obj_ref: None,
                preview: None,
                children: BTreeMap::new(),
            });
        }
        if node.obj_ref.is_none() {
            node.obj_ref = Some(obj_ref);
        }
        if node.preview.is_none() {
            node.preview = Some(preview);
        }
    }

    fn render(&self, depth: usize, out: &mut Vec<(String, String)>) {
        for child in self.children.values() {
            let indent = "  ".repeat(depth);
            let label = match &child.obj_ref {
                Some(obj_ref) => format!("{}{}@{}", indent, child.label, obj_ref),
                None => format!("{}{}@?", indent, child.label),
            };
            let preview = child.preview.clone().unwrap_or_else(|| segment_preview(&child.label));
            out.push((label, preview));
            child.render(depth + 1, out);
        }
    }
}

#[allow(dead_code)]
fn segment_preview(segment: &str) -> String {
    let trimmed = segment.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.chars().any(|c| c.is_ascii_digit() || c == '[') {
        return trimmed.to_string();
    }
    let lower = trimmed.to_ascii_lowercase();
    let mapped = match lower.as_str() {
        "catalog" => "Catalog",
        "pages" => "Pages",
        "page" => "Page",
        "kids" => "kids",
        "annots" => "Annots",
        "openaction" => "OpenAction",
        "aa" => "AA",
        "action" => "Action",
        "js" => "JS",
        "uri" => "URI",
        "embedded" => "Embedded",
        "filespec" => "FileSpec",
        "objstm" => "ObjStm",
        "stream" => "Stream",
        "names" => "Names",
        _ => trimmed,
    };
    if mapped == trimmed {
        let mut chars = trimmed.chars();
        let Some(first) = chars.next() else {
            return String::new();
        };
        let mut out = String::new();
        out.push(first.to_ascii_uppercase());
        out.push_str(chars.as_str());
        out
    } else {
        mapped.to_string()
    }
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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
        "vbscript_payload_present"
        | "powershell_payload_present"
        | "bash_payload_present"
        | "cmd_payload_present"
        | "applescript_payload_present"
        | "xfa_script_present"
        | "actionscript_present"
        | "swf_url_iocs" => {
            "Script payload indicators suggest executable content that may run in viewer or host contexts.".into()
        }
        "decoder_risk_present" | "decompression_ratio_suspicious" | "huge_image_dimensions" => {
            "Decoding may trigger resource exhaustion or vulnerable parser paths during rendering.".into()
        }
        "xref_conflict"
        | "incremental_update_chain"
        | "object_id_shadowing"
        | "objstm_density_high"
        | "label_mismatch_stream_type"
        | "declared_filter_invalid"
        | "undeclared_compression_present"
        | "content_validation_failed"
        | "embedded_payload_carved"
        | "nested_container_chain"
        | "shadow_object_payload_divergence"
        | "parse_disagreement"
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
    let trigger_key = chain_note(chain, "trigger.key").or(chain.trigger.as_deref());
    let action_key = chain_note(chain, "action.key").or(chain.action.as_deref());
    let action_type = chain_note(chain, "action.type");
    let payload_key = chain_note(chain, "payload.key").or(chain.payload.as_deref());
    let payload_type = chain_note(chain, "payload.type");
    if let Some(trigger) = trigger_key {
        if matches!(trigger, "open_action_present") {
            parts.push("Document open triggers execution".into());
        } else if matches!(trigger, "aa_present" | "aa_event_present") {
            parts.push("Viewer event triggers execution".into());
        }
    }
    if let Some(action) = action_type.or(action_key) {
        if action.contains("JavaScript") || matches!(action, "js_present") {
            parts.push("JavaScript executes in viewer context".into());
        } else if action.contains("URI") || matches!(action, "uri_present") {
            parts.push("External navigation or fetch occurs".into());
        } else if action.contains("Launch") || matches!(action, "launch_action_present") {
            parts.push("External application launch possible".into());
        } else if action.contains("SubmitForm") || matches!(action, "submitform_present") {
            parts.push("Form submission can transmit data.".into());
        }
    }
    if let Some(payload) = payload_type.or(payload_key) {
        let payload_lower = payload.to_ascii_lowercase();
        if payload_lower.contains("javascript") || payload_lower.contains("js") {
            parts.push("Script payload involved".into());
        } else if payload_lower.contains("uri") {
            parts.push("External URL payload involved".into());
        } else if payload_lower.contains("embedded") {
            parts.push("Embedded payload involved".into());
        } else if payload_lower.contains("stream") {
            parts.push("Stream payload involved".into());
        }
    }
    if parts.is_empty() {
        "Execution path inferred from linked findings; review trigger and payload details.".into()
    } else {
        parts.join("; ")
    }
}

#[allow(dead_code)]
fn chain_sandbox_observations(
    chain: &ExploitChain,
    findings: &[Finding],
    sandbox_summary: Option<&SandboxSummary>,
    linked_ids: &BTreeSet<String>,
) -> String {
    let mut calls: Vec<String> = Vec::new();
    let mut executed = false;
    let mut js_present = false;
    let mut skipped: Vec<String> = Vec::new();
    let mut timed_out = false;
    if let Some(summary) = sandbox_summary {
        if !summary.enabled {
            let reason = summary.disabled_reason.as_deref().unwrap_or("disabled");
            return format!("Not executed: {}.", reason);
        }
    }
    let mut ids: BTreeSet<String> = chain.findings.iter().cloned().collect();
    ids.extend(linked_ids.iter().cloned());
    for fid in &ids {
        if let Some(f) = findings.iter().find(|f| &f.id == fid) {
            if f.kind == "js_runtime_network_intent" || f.kind == "js_runtime_file_probe" {
                executed = true;
            }
            if f.kind == "js_present" {
                js_present = true;
            }
            if f.kind == "js_sandbox_skipped" {
                if let Some(reason) = f.meta.get("js.sandbox_skip_reason") {
                    skipped.push(reason.clone());
                } else {
                    skipped.push("skipped".into());
                }
            }
            if f.kind == "js_sandbox_timeout" {
                executed = true;
                timed_out = true;
            }
            if f.kind == "js_sandbox_exec" {
                executed = true;
            }
            if let Some(value) = f.meta.get("js.sandbox_exec") {
                if value == "true" {
                    executed = true;
                }
            }
            if let Some(value) = f.meta.get("js.runtime.calls") {
                executed = true;
                calls.push(value.clone());
            }
        }
    }
    if !calls.is_empty() {
        calls.sort();
        calls.dedup();
        return format!("Executed; calls: {}", calls.join("; "));
    }
    if timed_out {
        return "Executed; sandbox timed out.".into();
    }
    if executed {
        "Executed; no monitored API calls observed.".into()
    } else if !skipped.is_empty() {
        skipped.sort();
        skipped.dedup();
        let reasons = skipped
            .into_iter()
            .map(|r| match r.as_str() {
                "payload_too_large" => "payload exceeds size limit".to_string(),
                other => other.to_string(),
            })
            .collect::<Vec<_>>()
            .join("; ");
        format!("Not executed: {}.", reasons)
    } else if js_present {
        "Not executed: no sandbox execution recorded.".into()
    } else {
        "Not executed (no JavaScript finding for this chain).".into()
    }
}

fn chain_execution_narrative(chain: &ExploitChain, findings: &[Finding]) -> String {
    let mut lines = Vec::new();
    if let Some(trigger_label) = chain.notes.get("trigger.label") {
        lines.push(format!("Trigger: {}.", trigger_label));
    }
    if let Some(action_label) = chain.notes.get("action.label") {
        lines.push(format!("Action: {}.", action_label));
    }
    if let Some(payload_label) = chain.notes.get("payload.label") {
        lines.push(format!("Payload: {}.", payload_label));
    }
    if let Some(summary) = chain.notes.get("payload.summary") {
        lines.push(format!("Payload summary: {}.", summary));
    }
    if let Some(preview) = chain.notes.get("payload.preview") {
        lines.push(format!("Payload preview: {}.", preview));
    }
    if !lines.is_empty() {
        return lines.join(" ");
    }
    let mut fallback_lines: Vec<String> = Vec::new();
    let trigger_key = chain_note(chain, "trigger.key").or(chain.trigger.as_deref());
    let action_key = chain_note(chain, "action.key").or(chain.action.as_deref());
    let action_type = chain_note(chain, "action.type");
    let payload_key = chain_note(chain, "payload.key").or(chain.payload.as_deref());
    let payload_type = chain_note(chain, "payload.type");
    if let Some(trigger) = trigger_key {
        if matches!(trigger, "open_action_present") {
            fallback_lines.push("Execution starts automatically when the document opens.".into());
        } else if matches!(trigger, "aa_present" | "aa_event_present") {
            fallback_lines.push("Execution is tied to viewer events (Additional Actions).".into());
        }
    }
    if let Some(action) = action_type.or(action_key) {
        if action.contains("JavaScript") || matches!(action, "js_present") {
            fallback_lines
                .push("JavaScript runs in the viewer context and can access document APIs.".into());
        } else if action.contains("URI") || matches!(action, "uri_present") {
            fallback_lines
                .push("Viewer may navigate to an external URL or fetch remote content.".into());
        } else if action.contains("Launch") || matches!(action, "launch_action_present") {
            fallback_lines.push("Viewer may launch an external application or file.".into());
        } else if action.contains("SubmitForm") || matches!(action, "submitform_present") {
            fallback_lines.push("Form data can be transmitted to external endpoints.".into());
        }
    }
    if let Some(payload) = payload_type.or(payload_key) {
        let payload_lower = payload.to_ascii_lowercase();
        if payload_lower.contains("javascript") || payload_lower.contains("js") {
            fallback_lines
                .push("Chain contains a script payload that can alter viewer behavior.".into());
        } else if payload_lower.contains("uri") {
            fallback_lines.push("Chain references external URL payloads.".into());
        } else if payload_lower.contains("embedded") {
            fallback_lines.push("Chain involves embedded file payloads.".into());
        } else if payload_lower.contains("stream") {
            fallback_lines.push("Chain involves stream payloads.".into());
        }
    }
    if let Some(target) = chain.notes.get("action.target") {
        fallback_lines.push(format!("Action target: {}.", target));
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
        fallback_lines.push(format!("Observed behavior signals: {}.", uniq.join("; ")));
    }
    if fallback_lines.is_empty() {
        "Insufficient context for a detailed narrative; review chain findings and payload details."
            .into()
    } else {
        fallback_lines.join(" ")
    }
}

#[cfg(test)]
mod narrative_tests {
    use super::*;
    use crate::chain::ExploitChain;
    use crate::model::Finding;
    use std::collections::HashMap;

    #[test]
    fn custom_notes_drive_narrative() {
        let mut notes = HashMap::new();
        notes.insert("trigger.label".into(), "TriggerLabel -> https://example.com".into());
        notes.insert("action.label".into(), "ActionLabel".into());
        notes.insert("payload.label".into(), "PayloadLabel".into());
        notes.insert("payload.summary".into(), "filters=/DCTDecode decode=deferred".into());
        notes.insert("payload.preview".into(), "PreviewText".into());
        let chain = ExploitChain {
            id: "chain-test".into(),
            group_id: None,
            group_count: 1,
            group_members: Vec::new(),
            trigger: None,
            action: None,
            payload: None,
            findings: Vec::new(),
            score: 0.0,
            reasons: Vec::new(),
            path: String::new(),
            nodes: Vec::new(),
            edges: Vec::new(),
            notes,
        };
        let narrative = chain_execution_narrative(&chain, &[] as &[Finding]);
        assert!(narrative.contains("Trigger: TriggerLabel -> https://example.com."));
        assert!(narrative.contains("Action: ActionLabel."));
        assert!(narrative.contains("Payload: PayloadLabel."));
        assert!(narrative.contains("Payload summary: filters=/DCTDecode decode=deferred."));
        assert!(narrative.contains("Payload preview: PreviewText."));
    }

    #[test]
    fn fallback_narrative_hits_default_when_notes_missing() {
        let chain = ExploitChain {
            id: "chain-fallback".into(),
            group_id: None,
            group_count: 1,
            group_members: Vec::new(),
            trigger: Some("open_action_present".into()),
            action: Some("uri_present".into()),
            payload: Some("stream".into()),
            findings: Vec::new(),
            score: 0.0,
            reasons: Vec::new(),
            path: String::new(),
            nodes: Vec::new(),
            edges: Vec::new(),
            notes: HashMap::new(),
        };
        let narrative = chain_execution_narrative(&chain, &[] as &[Finding]);
        assert!(narrative.starts_with("Execution starts automatically when the document opens."));
        assert!(narrative.contains("Viewer may navigate to an external URL"));
    }
}

fn sandbox_summary_line(report: &Report) -> Option<String> {
    if let Some(summary) = report.sandbox_summary.as_ref() {
        if !summary.enabled {
            let reason = summary.disabled_reason.as_deref().unwrap_or("disabled");
            return Some(format!("Not executed: {}.", reason));
        }
    }
    let js_present = report.findings.iter().any(|f| f.kind == "js_present");
    let mut calls: Vec<String> = Vec::new();
    let mut executed = false;
    let mut skipped: Vec<String> = Vec::new();
    let mut timed_out = false;
    for f in &report.findings {
        if f.kind == "js_runtime_network_intent" || f.kind == "js_runtime_file_probe" {
            executed = true;
        }
        if f.kind == "js_sandbox_timeout" {
            executed = true;
            timed_out = true;
        }
        if f.kind == "js_sandbox_exec" {
            executed = true;
        }
        if f.kind == "js_sandbox_skipped" {
            if let Some(reason) = f.meta.get("js.sandbox_skip_reason") {
                skipped.push(reason.clone());
            } else {
                skipped.push("skipped".into());
            }
        }
        if let Some(value) = f.meta.get("js.sandbox_exec") {
            if value == "true" {
                executed = true;
            }
        }
        if let Some(value) = f.meta.get("js.runtime.calls") {
            executed = true;
            calls.push(value.clone());
        }
    }
    if !js_present && !executed && skipped.is_empty() {
        return None;
    }
    if !calls.is_empty() {
        calls.sort();
        calls.dedup();
        return Some(format!("Executed; calls: {}", calls.join("; ")));
    }
    if timed_out {
        return Some("Executed; sandbox timed out.".into());
    }
    if executed {
        Some("Executed; no monitored API calls observed.".into())
    } else if !skipped.is_empty() {
        skipped.sort();
        skipped.dedup();
        let reasons = skipped
            .into_iter()
            .map(|r| match r.as_str() {
                "payload_too_large" => "payload exceeds size limit".to_string(),
                other => other.to_string(),
            })
            .collect::<Vec<_>>()
            .join("; ");
        Some(format!("Not executed: {}.", reasons))
    } else if js_present {
        Some("Not executed: no sandbox execution recorded.".into())
    } else {
        Some("Not executed (no JavaScript findings).".into())
    }
}

#[allow(dead_code)]
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
        out.push(
            "Decoder-heavy streams may trigger vulnerable code paths or resource exhaustion."
                .into(),
        );
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
        "label_mismatch_stream_type" => {
            "Declared stream subtype does not match observed bytes, indicating potential payload disguise."
                .into()
        }
        "declared_filter_invalid" => {
            "Declared filters fail or do not match stream data, which may indicate obfuscation or corrupted content."
                .into()
        }
        "undeclared_compression_present" => {
            "Stream appears compressed without declaring filters, suggesting hidden content or evasion."
                .into()
        }
        "content_validation_failed" => {
            "Lightweight validation failed despite a matching signature, indicating malformed or evasive content."
                .into()
        }
        "embedded_payload_carved" => {
            "Embedded payload signatures were found within another object, indicating possible polyglot or hidden content."
                .into()
        }
        "nested_container_chain" => {
            "Archive entries contain nested file signatures, indicating staged or hidden payload delivery."
                .into()
        }
        "shadow_object_payload_divergence" => {
            "Shadowed object revisions differ in payload signatures, suggesting hidden or conflicting content."
                .into()
        }
        "parse_disagreement" => {
            "Carved objects disagree with parsed revisions, indicating parsing ambiguity or hidden content."
                .into()
        }
        "vbscript_payload_present" => {
            "VBScript indicators suggest embedded script content that may execute in viewer contexts.".into()
        }
        "powershell_payload_present" => {
            "PowerShell indicators suggest a potential external script payload or dropper.".into()
        }
        "bash_payload_present" => {
            "Shell script indicators suggest command execution content.".into()
        }
        "cmd_payload_present" => {
            "Command shell indicators suggest direct command execution content.".into()
        }
        "applescript_payload_present" => {
            "AppleScript indicators suggest macOS automation or execution content.".into()
        }
        "xfa_script_present" => {
            "XFA/XML script tags increase executable surface inside form content.".into()
        }
        "actionscript_present" => {
            "SWF ActionScript bytecode indicates executable content embedded in the document.".into()
        }
        "swf_url_iocs" => {
            "SWF payloads contain URLs, suggesting external references or staged delivery.".into()
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

fn severity_score(sev: Severity) -> u8 {
    match sev {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
    }
}

fn confidence_score(conf: crate::model::Confidence) -> u8 {
    match conf {
        crate::model::Confidence::Certain | crate::model::Confidence::Strong => 3,
        crate::model::Confidence::Probable => 2,
        crate::model::Confidence::Tentative => 1,
        crate::model::Confidence::Weak => 1,
        crate::model::Confidence::Heuristic => 1,
    }
}

fn attack_surface_label(surface: AttackSurface) -> &'static str {
    match surface {
        AttackSurface::FileStructure => "File structure",
        AttackSurface::XRefTrailer => "XRef and trailers",
        AttackSurface::ObjectStreams => "Object streams",
        AttackSurface::StreamsAndFilters => "Streams and filters",
        AttackSurface::Actions => "Actions",
        AttackSurface::JavaScript => "JavaScript",
        AttackSurface::Forms => "Forms",
        AttackSurface::EmbeddedFiles => "Embedded files",
        AttackSurface::RichMedia3D => "Rich media and 3D",
        AttackSurface::Images => "Images",
        AttackSurface::CryptoSignatures => "Cryptographic signatures",
        AttackSurface::Metadata => "Metadata",
        AttackSurface::ContentPhishing => "Content and phishing",
    }
}

fn join_list(items: &[String]) -> String {
    match items.len() {
        0 => "-".into(),
        1 => items[0].clone(),
        _ => items.join(", "),
    }
}

fn keyword_match(f: &Finding, keywords: &[&str]) -> bool {
    let text = format!("{} {} {}", f.kind, f.title, f.description).to_lowercase();
    keywords.iter().any(|kw| text.contains(kw))
}

fn top_findings(findings: &[Finding], limit: usize) -> Vec<&Finding> {
    let mut ranked: Vec<&Finding> = findings.iter().collect();
    ranked.sort_by(|a, b| {
        severity_score(b.severity)
            .cmp(&severity_score(a.severity))
            .then_with(|| confidence_score(b.confidence).cmp(&confidence_score(a.confidence)))
            .then_with(|| a.title.cmp(&b.title))
    });
    ranked.truncate(limit);
    ranked
}

fn verdict_label(report: &Report) -> (String, String) {
    let mut verdict = "Benign".to_string();
    let mut confidence = "low".to_string();

    let ml_signal = report
        .ml_inference
        .as_ref()
        .map(|ml| (ml.prediction.label, ml.prediction.calibrated_score, ml.prediction.threshold))
        .or_else(|| {
            report.ml_summary.as_ref().and_then(|ml| {
                ml.graph.as_ref().map(|run| (run.label, run.score, run.threshold)).or_else(|| {
                    ml.traditional.as_ref().map(|run| (run.label, run.score, run.threshold))
                })
            })
        });

    if let Some((label, score, threshold)) = ml_signal {
        if label {
            verdict = "Malicious".to_string();
            confidence =
                if score - threshold >= 0.15 { "high".to_string() } else { "medium".to_string() };
            return (verdict, confidence);
        }
    }

    if report.summary.high > 0 {
        verdict = "Suspicious".to_string();
        confidence = "high".to_string();
    } else if report.summary.medium > 0 {
        verdict = "Suspicious".to_string();
        confidence = "medium".to_string();
    } else if report.summary.low > 0 || report.summary.info > 0 {
        verdict = "Benign".to_string();
        confidence = "low".to_string();
    }

    (verdict, confidence)
}

fn build_recommendations(report: &Report) -> Vec<String> {
    let mut steps = Vec::new();
    let has_js = report.findings.iter().any(|f| f.surface == AttackSurface::JavaScript);
    let has_images = report.findings.iter().any(|f| f.surface == AttackSurface::Images);
    let has_embedded = report.findings.iter().any(|f| {
        f.surface == AttackSurface::EmbeddedFiles || f.surface == AttackSurface::RichMedia3D
    });
    let polyglot_flag =
        report.structural_summary.as_ref().map(|s| s.polyglot_risk).unwrap_or(false)
            || report.findings.iter().any(|f| keyword_match(f, &["polyglot"]));

    if has_js {
        if let Some(summary) = report.sandbox_summary.as_ref() {
            if !summary.enabled {
                steps.push(
                    "Enable the JavaScript sandbox and re-run to capture dynamic behaviour."
                        .to_string(),
                );
            } else {
                steps.push(
                    "Review extracted JavaScript payloads with static and dynamic analysis."
                        .to_string(),
                );
            }
        } else {
            steps.push(
                "Review extracted JavaScript payloads with static and dynamic analysis."
                    .to_string(),
            );
        }
    }
    if has_embedded {
        steps.push("Extract embedded files and scan them separately.".to_string());
    }
    if has_images {
        steps.push("Review image payloads and decoder findings for malformed content.".to_string());
    }
    if report.structural_summary.as_ref().map(|s| !s.deep_scan).unwrap_or(false) {
        steps.push("Re-run with `sis scan --deep` to reconcile object structure.".to_string());
    }
    if polyglot_flag {
        steps.push(
            "Validate file type integrity and strip trailing data before distribution.".to_string(),
        );
    }
    if !report.chains.is_empty() {
        steps.push("Review chain analysis for likely execution paths.".to_string());
    }
    if report.summary.high > 0 {
        steps.push("Quarantine the file until the findings are cleared.".to_string());
    }

    steps.truncate(4);
    steps
}

pub fn build_short_id_map_from_findings(findings: &[Finding]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let mut used = BTreeSet::new();
    for f in findings {
        let long = f.id.clone();
        let short = shorten_id(&long, &mut used);
        map.insert(long, short);
    }
    map
}

fn build_id_map(report: &Report) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let mut used = BTreeSet::new();
    for f in &report.findings {
        let long = f.id.clone();
        let short = shorten_id(&long, &mut used);
        map.insert(long, short);
    }
    for chain in &report.chains {
        let long = chain.id.clone();
        let short = shorten_id(&long, &mut used);
        map.insert(long, short);
    }
    map
}

fn shorten_id(long: &str, used: &mut BTreeSet<String>) -> String {
    if long.len() <= 14 {
        used.insert(long.to_string());
        return long.to_string();
    }
    if let Some(rest) = long.strip_prefix("sis-") {
        for len in [8usize, 12, 16, rest.len()] {
            let slice_len = len.min(rest.len());
            let candidate = format!("sis-{}", &rest[..slice_len]);
            if used.insert(candidate.clone()) {
                return candidate;
            }
        }
    } else {
        for len in [8usize, 12, 16, long.len()] {
            let slice_len = len.min(long.len());
            let candidate = long[..slice_len].to_string();
            if used.insert(candidate.clone()) {
                return candidate;
            }
        }
    }
    long.to_string()
}

fn display_id(id: &str, id_map: &BTreeMap<String, String>) -> String {
    id_map.get(id).cloned().unwrap_or_else(|| id.to_string())
}

fn replace_ids(text: &str, id_map: &BTreeMap<String, String>) -> String {
    let mut out = text.to_string();
    for (long, short) in id_map {
        if long != short {
            out = out.replace(long, short);
        }
    }
    out
}

fn render_finding_list(
    out: &mut String,
    findings: &[&Finding],
    limit: usize,
    id_map: &BTreeMap<String, String>,
) {
    if findings.is_empty() {
        out.push_str("- No findings recorded.\n\n");
        return;
    }
    out.push_str(&format!("- Findings: {}\n", findings.len()));
    for f in findings.iter().take(limit) {
        out.push_str(&format!(
            "- {}: {} (severity {:?}, confidence {:?})\n",
            escape_markdown(&display_id(&f.id, id_map)),
            escape_markdown(&f.title),
            f.severity,
            f.confidence
        ));
    }
    if findings.len() > limit {
        out.push_str(&format!(
            "- Additional findings: {} more (see Appendix)\n",
            findings.len() - limit
        ));
    }
    out.push('\n');
}

pub fn render_markdown(report: &Report, input_path: Option<&str>) -> String {
    let mut out = String::new();
    let id_map = build_id_map(report);
    out.push_str("# Summary\n\n");
    let (verdict, verdict_confidence) = verdict_label(report);
    out.push_str(&format!("- Verdict: {} (confidence {})\n", verdict, verdict_confidence));
    if report.summary.total > 0 {
        let mut domains = BTreeSet::new();
        for f in &report.findings {
            domains.insert(attack_surface_label(f.surface).to_string());
        }
        let domain_list: Vec<String> = domains.into_iter().collect();
        out.push_str(&format!(
            "- Findings: {} total (high {}, medium {}, low {}, info {}) across {}\n",
            report.summary.total,
            report.summary.high,
            report.summary.medium,
            report.summary.low,
            report.summary.info,
            join_list(&domain_list)
        ));
        let key_findings = top_findings(&report.findings, 3);
        if !key_findings.is_empty() {
            out.push_str("- Key findings:\n");
            for f in &key_findings {
                out.push_str(&format!(
                    "  - {} ({})\n",
                    escape_markdown(&f.title),
                    display_id(&f.id, &id_map)
                ));
            }
        }
        let mut validation_reasons = Vec::new();
        for f in &report.findings {
            if f.kind == "content_validation_failed" {
                if let Some(reason) = f.meta.get("validation.reason") {
                    if !validation_reasons.contains(reason) {
                        validation_reasons.push(reason.clone());
                    }
                }
            }
        }
        if !validation_reasons.is_empty() {
            out.push_str(&format!(
                "- Validation issues: {}\n",
                escape_markdown(&validation_reasons.join("; "))
            ));
        }
        let mut origins = Vec::new();
        for f in &report.findings {
            if let Some(origin) = f.meta.get("blob.origin") {
                let origin_lower = origin.to_ascii_lowercase();
                let is_embedded =
                    origin_lower.starts_with("embedded") || origin_lower == "xfa_package";
                if is_embedded && !origins.contains(origin) {
                    origins.push(origin.clone());
                }
            }
        }
        if !origins.is_empty() {
            out.push_str(&format!(
                "- Embedded origins: {}\n",
                escape_markdown(&origins.join(", "))
            ));
        }
        let mut impacts = Vec::new();
        for f in &key_findings {
            let impact = f.meta.get("impact").cloned().unwrap_or_else(|| impact_for_finding(f));
            if !impacts.contains(&impact) {
                impacts.push(impact);
            }
        }
        if !impacts.is_empty() {
            out.push_str(&format!("- Impact: {}\n", escape_markdown(&impacts.join("; "))));
        }
    } else {
        out.push_str("- Findings: no findings recorded\n");
    }
    let recommendations = build_recommendations(report);
    if !recommendations.is_empty() {
        out.push_str("- Recommended next steps:\n");
        for step in recommendations {
            out.push_str(&format!("  - {}\n", escape_markdown(&step)));
        }
    }
    if let Some(path) = input_path {
        out.push_str(&format!("- Input: `{}`\n", escape_markdown(path)));
    }
    if let Some(line) = sandbox_summary_line(report) {
        out.push_str(&format!("- Sandbox observations: {}\n", escape_markdown(&line)));
    }
    out.push('\n');

    out.push_str("# Findings by scan domain\n\n");
    out.push_str("## Surface\n\n");
    let surface_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.surface,
                AttackSurface::FileStructure
                    | AttackSurface::XRefTrailer
                    | AttackSurface::ObjectStreams
                    | AttackSurface::StreamsAndFilters
            )
        })
        .collect();
    let sizing_keywords = ["size", "length", "truncat", "overlap", "gap", "boundary", "offset"];
    let sizing_findings: Vec<&Finding> =
        surface_findings.iter().copied().filter(|f| keyword_match(f, &sizing_keywords)).collect();
    let polyglot_findings: Vec<&Finding> =
        surface_findings.iter().copied().filter(|f| keyword_match(f, &["polyglot"])).collect();
    let sizing_ids: BTreeSet<String> = sizing_findings.iter().map(|f| f.id.clone()).collect();
    let polyglot_ids: BTreeSet<String> = polyglot_findings.iter().map(|f| f.id.clone()).collect();
    let other_surface: Vec<&Finding> = surface_findings
        .iter()
        .copied()
        .filter(|f| !sizing_ids.contains(&f.id) && !polyglot_ids.contains(&f.id))
        .collect();

    out.push_str("### Sizing\n\n");
    render_finding_list(&mut out, &sizing_findings, 6, &id_map);

    out.push_str("### Polyglot\n\n");
    if let Some(summary) = &report.structural_summary {
        if summary.polyglot_risk {
            let sigs = if summary.polyglot_signatures.is_empty() {
                "no signatures recorded".to_string()
            } else {
                summary.polyglot_signatures.join(", ")
            };
            out.push_str(&format!(
                "- Structural summary indicates polyglot risk ({})\n",
                escape_markdown(&sigs)
            ));
        } else {
            out.push_str("- Structural summary does not indicate polyglot risk\n");
        }
    }
    render_finding_list(&mut out, &polyglot_findings, 6, &id_map);

    out.push_str("### Other surface findings\n\n");
    render_finding_list(&mut out, &other_surface, 8, &id_map);

    out.push_str("## Structure\n\n");
    out.push_str("### Found contents\n\n");
    if let Some(summary) = &report.structural_summary {
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
        }
        if let Some(offset) = summary.eof_offset {
            let distance = summary.eof_distance_to_end.unwrap_or(0);
            out.push_str(&format!("- EOF offset: {} (distance to end {})\n", offset, distance));
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
            out.push_str(&format!("- Secondary parser: failed ({})\n", escape_markdown(err)));
        } else {
            out.push_str("- Secondary parser: not run\n");
        }
    } else {
        out.push_str("- Structural summary not available\n");
    }
    out.push('\n');

    out.push_str("### Content inventory\n\n");
    let mut inventory: BTreeMap<&'static str, usize> = BTreeMap::new();
    for f in &report.findings {
        *inventory.entry(attack_surface_label(f.surface)).or_insert(0) += 1;
    }
    if inventory.is_empty() {
        out.push_str("- No content inventory findings recorded\n\n");
    } else {
        for (label, count) in inventory {
            out.push_str(&format!("- {}: {}\n", label, count));
        }
        out.push('\n');
    }

    out.push_str("## Content details and analysis\n\n");
    out.push_str("### JavaScript analysis\n\n");
    let js_findings: Vec<&Finding> =
        report.findings.iter().filter(|f| f.surface == AttackSurface::JavaScript).collect();
    if js_findings.is_empty() {
        out.push_str("- No JavaScript findings recorded\n\n");
    } else {
        out.push_str(&format!("- Findings: {}\n", js_findings.len()));
        let severity_summary = js_findings.iter().fold(
            Summary { total: 0, high: 0, medium: 0, low: 0, info: 0 },
            |mut acc, f| {
                acc.total += 1;
                match f.severity {
                    Severity::High | Severity::Critical => acc.high += 1,
                    Severity::Medium => acc.medium += 1,
                    Severity::Low => acc.low += 1,
                    Severity::Info => acc.info += 1,
                }
                acc
            },
        );
        out.push_str(&format!(
            "- Severity breakdown: high {} medium {} low {} info {}\n",
            severity_summary.high,
            severity_summary.medium,
            severity_summary.low,
            severity_summary.info
        ));
        out.push('\n');
        out.push_str("#### Static analysis\n\n");
        render_finding_list(&mut out, &js_findings, 6, &id_map);
        out.push_str("#### Dynamic analysis\n\n");
        let dynamic_findings: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.kind.starts_with("js_runtime_") || f.kind.starts_with("js_sandbox_"))
            .collect();
        if dynamic_findings.is_empty() {
            out.push_str("- No dynamic analysis findings recorded\n");
        } else {
            render_finding_list(&mut out, &dynamic_findings, 6, &id_map);
        }
        let mut calls: Vec<String> = Vec::new();
        let mut exec_ms: Vec<String> = Vec::new();
        let mut timeout_ms: Vec<String> = Vec::new();
        let mut skip_reasons: Vec<String> = Vec::new();
        let mut risky_calls: Vec<String> = Vec::new();
        for f in &dynamic_findings {
            if let Some(value) = f.meta.get("js.runtime.calls") {
                calls.push(value.clone());
            }
            if let Some(value) = f.meta.get("js.sandbox_exec_ms") {
                exec_ms.push(value.clone());
            }
            if let Some(value) = f.meta.get("js.sandbox_timeout_ms") {
                timeout_ms.push(value.clone());
            }
            if let Some(value) = f.meta.get("js.sandbox_skip_reason") {
                skip_reasons.push(value.clone());
            }
            if let Some(value) = f.meta.get("js.runtime.risky_calls") {
                risky_calls.push(value.clone());
            }
        }
        if !calls.is_empty() {
            calls.sort();
            calls.dedup();
            out.push_str(&format!(
                "- Observed runtime calls: {}\n",
                escape_markdown(&calls.join("; "))
            ));
        }
        if !risky_calls.is_empty() {
            risky_calls.sort();
            risky_calls.dedup();
            out.push_str(&format!(
                "- Runtime risky calls: {}\n",
                escape_markdown(&risky_calls.join(", "))
            ));
        }
        if !exec_ms.is_empty() {
            exec_ms.sort();
            exec_ms.dedup();
            out.push_str(&format!(
                "- Sandbox execution time (ms): {}\n",
                escape_markdown(&exec_ms.join(", "))
            ));
        }
        if !timeout_ms.is_empty() {
            timeout_ms.sort();
            timeout_ms.dedup();
            out.push_str(&format!(
                "- Sandbox timeout (ms): {}\n",
                escape_markdown(&timeout_ms.join(", "))
            ));
        }
        if !skip_reasons.is_empty() {
            skip_reasons.sort();
            skip_reasons.dedup();
            out.push_str(&format!(
                "- Sandbox skip reasons: {}\n",
                escape_markdown(&skip_reasons.join(", "))
            ));
        }
        if let Some(line) = sandbox_summary_line(report) {
            out.push_str(&format!("- Sandbox status: {}\n", escape_markdown(&line)));
        }
        out.push('\n');
    }

    out.push_str("### Fonts\n\n");
    let font_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| keyword_match(f, &["font", "cff", "truetype", "opentype"]))
        .collect();
    render_finding_list(&mut out, &font_findings, 6, &id_map);

    out.push_str("### Images\n\n");
    let image_findings: Vec<&Finding> =
        report.findings.iter().filter(|f| f.surface == AttackSurface::Images).collect();
    render_finding_list(&mut out, &image_findings, 6, &id_map);

    out.push_str("### Embedded media\n\n");
    let embedded_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| matches!(f.surface, AttackSurface::EmbeddedFiles | AttackSurface::RichMedia3D))
        .collect();
    render_finding_list(&mut out, &embedded_findings, 6, &id_map);

    out.push_str("### Other content analysis\n\n");
    let other_content: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.surface,
                AttackSurface::Actions
                    | AttackSurface::Forms
                    | AttackSurface::Metadata
                    | AttackSurface::ContentPhishing
                    | AttackSurface::CryptoSignatures
            )
        })
        .collect();
    render_finding_list(&mut out, &other_content, 8, &id_map);

    out.push_str("## Interactions\n\n");
    let mut interactions = Vec::new();
    if let Some(summary) = &report.behavior_summary {
        for pattern in summary.patterns.iter().take(5) {
            interactions.push(format!(
                "Behaviour pattern: {} (severity {:?}) kinds=[{}]",
                pattern.summary,
                pattern.severity,
                pattern.kinds.join(", ")
            ));
        }
    }
    if !report.chains.is_empty() {
        for chain in report.chains.iter().take(5) {
            let mut line = format!(
                "Chain {} links {} findings with path {}",
                display_id(&chain.id, &id_map),
                chain.findings.len(),
                replace_ids(&chain.path, &id_map)
            );
            if chain.group_count > 1 {
                line.push_str(&format!(" (instances {})", chain.group_count));
            }
            interactions.push(line);
        }
    }
    if !report.network_intents.is_empty() {
        interactions.push(format!("Network intents observed: {}", report.network_intents.len()));
    }
    if let Some(signals) = &report.temporal_signals {
        interactions.push(format!(
            "Temporal signals: revisions {} new high-severity {} new findings {} removed {}",
            signals.revisions,
            signals.new_high_severity,
            signals.new_findings.len(),
            signals.removed_findings.len()
        ));
    }
    if let Some(summary) = &report.intent_summary {
        if !summary.buckets.is_empty() {
            let mut buckets = summary.buckets.clone();
            buckets.sort_by(|a, b| b.score.cmp(&a.score));
            if let Some(top) = buckets.first() {
                interactions.push(format!(
                    "Intent signal: {:?} score {} confidence {:?}",
                    top.bucket, top.score, top.confidence
                ));
            }
        }
    }
    if !report.future_threats.is_empty() {
        let labels =
            report.future_threats.iter().take(3).map(|t| t.label.clone()).collect::<Vec<_>>();
        interactions.push(format!("Predicted threat evolution: {}", labels.join(", ")));
    }
    if interactions.is_empty() {
        out.push_str("- No cross-domain interactions recorded\n\n");
    } else {
        for line in interactions {
            out.push_str(&format!("- {}\n", escape_markdown(&line)));
        }
        out.push('\n');
    }

    out.push_str("# ML Analysis\n\n");
    out.push_str("## ML summary\n\n");
    if let Some(ml) = &report.ml_summary {
        if let Some(mode) = ml_mode_label(ml) {
            out.push_str(&format!("- Mode: `{}`\n", escape_markdown(mode)));
            if ml_mode_includes_graph(mode) {
                if let Some(run) = &ml.graph {
                    out.push_str(&format!(
                        "- Graph: score {:.4} threshold {:.4} label {} ({})\n",
                        run.score,
                        run.threshold,
                        run.label,
                        ml_assessment(run.label)
                    ));
                } else if has_ml_error(&report.findings) {
                    out.push_str("- Graph: error (see ml_model_error findings)\n");
                }
            }
            if ml_mode_includes_traditional(mode) {
                if let Some(run) = &ml.traditional {
                    out.push_str(&format!(
                        "- Traditional: score {:.4} threshold {:.4} label {} ({})\n",
                        run.score,
                        run.threshold,
                        run.label,
                        ml_assessment(run.label)
                    ));
                } else if has_ml_error(&report.findings) {
                    out.push_str("- Traditional: error (see ml_model_error findings)\n");
                }
            }
        } else if has_ml_error(&report.findings) {
            out.push_str("- Status: error (see ml_model_error findings)\n");
        }
    } else if has_ml_error(&report.findings) {
        out.push_str("- Status: error (see ml_model_error findings)\n");
    } else {
        out.push_str("- ML summary not available\n");
    }
    out.push('\n');

    out.push_str("## ML details\n\n");
    if let Some(ml) = &report.ml_summary {
        if let Some(mode) = ml_mode_label(ml) {
            if ml_mode_includes_graph(mode) {
                if let Some(run) = &ml.graph {
                    out.push_str(&format!(
                        "**Graph ML**\n\n- Kind: `{}`\n- Score: {:.4}\n- Threshold: {:.4}\n- Label: {} ({})\n\n",
                        escape_markdown(&run.kind),
                        run.score,
                        run.threshold,
                        run.label,
                        ml_assessment(run.label)
                    ));
                    if let Some(nodes) = &run.top_nodes {
                        out.push_str("**Top contributing nodes**\n\n");
                        for node in nodes {
                            out.push_str(&format!(
                                "- `{}` score {:.4} — {}\n",
                                escape_markdown(&node.obj_ref),
                                node.score,
                                escape_markdown(&node.summary)
                            ));
                        }
                        out.push('\n');
                    }
                } else if has_ml_error(&report.findings) {
                    out.push_str(
                        "**Graph ML**\n\n- Status: error (see ml_model_error findings)\n\n",
                    );
                }
            }
            if ml_mode_includes_traditional(mode) {
                if let Some(run) = &ml.traditional {
                    out.push_str(&format!(
                        "**Traditional ML**\n\n- Kind: `{}`\n- Score: {:.4}\n- Threshold: {:.4}\n- Label: {} ({})\n\n",
                        escape_markdown(&run.kind),
                        run.score,
                        run.threshold,
                        run.label,
                        ml_assessment(run.label)
                    ));
                    if let Some(nodes) = &run.top_nodes {
                        out.push_str("**Top contributing nodes**\n\n");
                        for node in nodes {
                            out.push_str(&format!(
                                "- `{}` score {:.4} — {}\n",
                                escape_markdown(&node.obj_ref),
                                node.score,
                                escape_markdown(&node.summary)
                            ));
                        }
                        out.push('\n');
                    }
                } else if has_ml_error(&report.findings) {
                    out.push_str(
                        "**Traditional ML**\n\n- Status: error (see ml_model_error findings)\n\n",
                    );
                }
            }
        } else if has_ml_error(&report.findings) {
            out.push_str("- Status: error (see ml_model_error findings)\n\n");
        }
    }
    if let Some(ml) = &report.ml_inference {
        out.push_str(&format_ml_explanation_for_report(ml.explanation.as_ref(), &ml.prediction));
    } else if report.ml_summary.is_none() {
        out.push_str("- No ML details recorded\n\n");
    }

    out.push_str("# Chain analysis\n\n");
    let position_previews = build_position_preview_map(&report.findings);
    let chain_summary = build_chain_summary(report, &position_previews, &id_map);
    if chain_summary.is_empty() {
        out.push_str("- No chain analysis recorded\n\n");
    } else {
        let total_instances: usize = chain_summary.iter().map(|entry| entry.instances).sum();
        out.push_str(&format!(
            "- {} chain signature(s) covering {} correlated occurrence(s).\n",
            chain_summary.len(),
            total_instances
        ));
        for (idx, entry) in chain_summary.iter().take(5).enumerate() {
            out.push_str(&format!(
                "- Signature {} (score {:.2}, {} instance(s))\n",
                idx + 1,
                entry.score,
                entry.instances
            ));
            out.push_str(&format!("  - Path: `{}`\n", escape_markdown(&entry.path)));
            if let Some(outcome) = &entry.outcome {
                out.push_str(&format!("  - Outcome: `{}`\n", escape_markdown(outcome)));
            }
            if let Some(narrative) = &entry.narrative {
                out.push_str(&format!("  - Narrative: `{}`\n", escape_markdown(narrative)));
            }
            out.push_str(&format!("  - Trigger: `{}`\n", escape_markdown(&entry.trigger_label)));
            out.push_str(&format!("  - Action: `{}`\n", escape_markdown(&entry.action_label)));
            out.push_str(&format!("  - Payload: `{}`\n", escape_markdown(&entry.payload_label)));
            if let Some(preview) = &entry.node_preview {
                out.push_str(&format!("  - Node preview: `{}`\n", escape_markdown(preview)));
            }
            let reasons_text = if entry.reasons.is_empty() {
                "none".into()
            } else {
                entry.reasons.iter().take(3).cloned().collect::<Vec<_>>().join("; ")
            };
            out.push_str(&format!("  - Reasons: {}\n", escape_markdown(&reasons_text)));
            if !entry.finding_kinds.is_empty() {
                out.push_str(&format!(
                    "  - Finding kinds: {}\n",
                    escape_markdown(&entry.finding_kinds.join(", "))
                ));
            }
        }
        if chain_summary.len() > 5 {
            out.push_str(&format!(
                "- Additional {} signature(s) omitted for brevity.\n",
                chain_summary.len() - 5
            ));
        }
        out.push('\n');
    }

    out.push_str("# Appendix\n\n");
    out.push_str("## List of findings and details\n\n");
    if report.findings.is_empty() {
        out.push_str("- No findings recorded\n\n");
    } else {
        for f in &report.findings {
            out.push_str(&format!(
                "### {} — {}\n\n",
                escape_markdown(&display_id(&f.id, &id_map)),
                escape_markdown(&f.title)
            ));
            out.push_str(&format!("- Surface: `{:?}`\n", f.surface));
            out.push_str(&format!("- Kind: `{}`\n", escape_markdown(&f.kind)));
            out.push_str(&format!("- Severity: `{:?}`\n", f.severity));
            out.push_str(&format!("- Impact rating: `{}`\n", impact_rating_for_finding(f)));
            out.push_str(&format!("- Confidence: `{:?}`\n", f.confidence));
            if !f.objects.is_empty() {
                out.push_str(&format!("- Objects: {}\n", escape_markdown(&f.objects.join(", "))));
            }
            if let Some(position) = &f.position {
                out.push_str(&format!("- Position: `{}`\n", escape_markdown(position)));
            }
            if f.positions.len() > 1 {
                out.push_str(&format!(
                    "- Positions: {}\n",
                    escape_markdown(&f.positions.join(", "))
                ));
            }
            if f.meta.get("page_tree.orphaned_has_payload").map(|v| v == "true").unwrap_or(false) {
                out.push_str("- Orphaned page contains suspicious content; likely concealment.\n");
                if let Some(ids) = f.meta.get("page_tree.orphaned_payload_findings") {
                    out.push_str(&format!(
                        "- Related findings: {}\n",
                        escape_markdown(&replace_ids(ids, &id_map))
                    ));
                }
            }
            if let Some(page) = f.meta.get("page.number") {
                out.push_str(&format!("- Page: {}\n", escape_markdown(page)));
            }
            if let Some(coord) = f.meta.get("content.coord") {
                out.push_str(&format!("- Coord: {}\n", escape_markdown(coord)));
            }
            if let Some(s) = f.meta.get("action.s") {
                out.push_str("**Action details**\n\n");
                out.push_str(&format!("- Action type: `{}`\n", escape_markdown(s)));
                if let Some(t) = f.meta.get("action.target") {
                    out.push_str(&format!("- Target: {}\n", escape_markdown(t)));
                }
                out.push('\n');
            }
            if let Some(payload) =
                f.meta.get("payload.decoded_preview").or_else(|| f.meta.get("payload.preview"))
            {
                out.push_str("**Payload**\n\n");
                out.push_str("```\n");
                out.push_str(&escape_control(payload));
                out.push_str("\n```\n\n");
            }
            if let Some(chain) = render_action_chain(f) {
                out.push_str("**Action chain**\n\n");
                out.push_str(&format!("{}\n\n", escape_markdown(&replace_ids(&chain, &id_map))));
            }
            if let Some(behaviour) = render_payload_behaviour(f) {
                out.push_str("**Payload behaviour**\n\n");
                out.push_str(&format!(
                    "{}\n\n",
                    escape_markdown(&replace_ids(&behaviour, &id_map))
                ));
            }
            let impact = f.meta.get("impact").cloned().unwrap_or_else(|| impact_for_finding(f));
            let runtime = runtime_effect_for_finding(f);
            let mut description_lines = Vec::new();
            if !f.description.is_empty() {
                description_lines.push(f.description.clone());
            }
            description_lines.push(format!("Runtime effect: {}", runtime));
            description_lines.push(format!("Impact: {}", impact));
            if let Some(mismatch) = f.meta.get("decode.mismatch") {
                description_lines.push(format!("Filter mismatch: {}", mismatch));
            }
            if let Some(filters) = f.meta.get("stream.filters") {
                description_lines.push(format!("Declared filters: {}", filters));
            }
            if let Some(outcome) = f.meta.get("decode.outcome") {
                description_lines.push(format!("Decode outcome: {}", outcome));
            }
            if let Some(context) = finding_context(&f.kind) {
                description_lines.push(format!("Context: {}", context));
            }
            if let Some(link) = doc_link_for_finding(f) {
                description_lines.push(format!("More info: {}", link));
            }
            out.push_str("**Description**\n\n");
            out.push_str(&format!("{}\n\n", escape_markdown(&description_lines.join("\n\n"))));
            if let Some(y) = &f.yara {
                out.push_str("**YARA**\n\n");
                out.push_str(&format!("- Rule: `{}`\n", escape_markdown(&y.rule_name)));
                if !y.tags.is_empty() {
                    out.push_str(&format!("- Tags: {}\n", escape_markdown(&y.tags.join(", "))));
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
                let mut js_meta: Vec<(&String, &String)> =
                    f.meta.iter().filter(|(k, _)| k.starts_with("js.")).collect();
                js_meta.sort_by(|a, b| a.0.cmp(b.0));
                let mut other_meta: Vec<(&String, &String)> =
                    f.meta.iter().filter(|(k, _)| !k.starts_with("js.")).collect();
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
                    let js_meta: Vec<(&String, &String)> =
                        js_meta.into_iter().filter(|(_, v)| v.trim() != "false").collect();
                    if !js_meta.is_empty() {
                        out.push_str("**JavaScript metadata**\n\n");
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
        }
    }

    out.push_str("## Identifier lookup\n\n");
    let mut id_pairs: Vec<(&String, &String)> =
        id_map.iter().filter(|(long, short)| long != short).collect();
    id_pairs.sort_by(|a, b| a.1.cmp(b.1).then_with(|| a.0.cmp(b.0)));
    if id_pairs.is_empty() {
        out.push_str("- No identifiers were shortened\n\n");
    } else {
        out.push_str("| Short | Long |\n");
        out.push_str("| --- | --- |\n");
        for (long, short) in id_pairs {
            out.push_str(&format!("| {} | {} |\n", escape_markdown(short), escape_markdown(long)));
        }
        out.push('\n');
    }

    let strict_findings: Vec<&Finding> =
        report.findings.iter().filter(|f| f.kind == "strict_parse_deviation").collect();
    if !strict_findings.is_empty() {
        out.push_str("## Strict parse deviations\n\n");
        out.push_str(&format!("- Count: {}\n\n", strict_findings.len()));
        for f in &strict_findings {
            out.push_str(&format!(
                "- {}: {}\n",
                escape_markdown(&display_id(&f.id, &id_map)),
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
            let tags = if rule.tags.is_empty() { "-".into() } else { rule.tags.join(", ") };
            out.push_str(&format!(
                "- {} (tags: {})\n",
                escape_markdown(&rule.name),
                escape_markdown(&tags)
            ));
        }
        out.push('\n');
    }

    out.push_str("## Sis scanner details\n\n");
    out.push_str(&format!("- sis-pdf-core version: {}\n", env!("CARGO_PKG_VERSION")));
    out.push_str(&format!(
        "- ML graph feature enabled: {}\n",
        if cfg!(feature = "ml-graph") { "yes" } else { "no" }
    ));
    if let Some(summary) = &report.structural_summary {
        out.push_str(&format!(
            "- Scan profile: {}\n",
            if summary.deep_scan { "deep" } else { "triage" }
        ));
    }
    if let Some(line) = sandbox_summary_line(report) {
        out.push_str(&format!("- Sandbox status: {}\n", escape_markdown(&line)));
    }
    out.push('\n');

    out.push_str("## Metadata and timestamps\n\n");
    if let Some(path) = input_path {
        out.push_str(&format!("- Input path: `{}`\n", escape_markdown(path)));
    } else {
        out.push_str("- Input path: not captured\n");
    }
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    out.push_str(&format!("- Timestamp (UTC, unix seconds): {}\n", timestamp));
    out.push_str("- File metadata: not captured in report output\n");
    out
}

fn format_ml_explanation_for_report(
    explanation: Option<&crate::ml_inference::ComprehensiveExplanation>,
    prediction: &crate::ml_inference::CalibratedPrediction,
) -> String {
    let mut report = String::new();
    report.push_str("### ML inference\n\n");
    report.push_str(&format!(
        "- Score: {:.4}\n- Threshold: {:.4}\n- Label: {} ({})\n- Calibration: `{}`\n",
        prediction.calibrated_score,
        prediction.threshold,
        prediction.label,
        ml_assessment(prediction.label),
        escape_markdown(&prediction.calibration_method)
    ));
    if let Some((low, high)) = prediction.confidence_interval {
        report.push_str(&format!("- Confidence interval (95%): {:.4}-{:.4}\n", low, high));
    }
    report.push('\n');

    let Some(explanation) = explanation else {
        return report;
    };

    report.push_str("#### Summary\n\n");
    report.push_str(&format!("{}\n\n", escape_markdown(&explanation.summary)));

    if !explanation.decision_factors.is_empty() {
        report.push_str("#### Decision factors\n\n");
        for factor in explanation.decision_factors.iter().take(10) {
            report.push_str(&format!("- {}\n", escape_markdown(factor)));
        }
        report.push('\n');
    }

    if !explanation.feature_attribution.is_empty() {
        report.push_str("#### Top contributing features\n\n");
        report.push_str("| Feature | Value | Contribution | Baseline |\n");
        report.push_str("| --- | --- | --- | --- |\n");
        for attr in explanation.feature_attribution.iter().take(10) {
            report.push_str(&format!(
                "| {} | {:.2} | {:+.2} | {:.2} |\n",
                escape_markdown(&crate::explainability::humanize_feature_name(&attr.feature_name)),
                attr.value,
                attr.contribution,
                attr.baseline
            ));
        }
        report.push('\n');
    }

    if !explanation.comparative_analysis.is_empty() {
        report.push_str("#### Comparison with benign baseline\n\n");
        for comp in explanation.comparative_analysis.iter().take(5) {
            report.push_str(&format!(
                "- **{}**: {:.2} (benign mean {:.2}, z-score {:.1}) — {}\n",
                escape_markdown(&crate::explainability::humanize_feature_name(&comp.feature_name)),
                comp.value,
                comp.benign_mean,
                comp.z_score,
                escape_markdown(&comp.interpretation)
            ));
        }
        report.push('\n');
    }

    if !explanation.evidence_chains.is_empty() {
        report.push_str("#### Evidence chains\n\n");
        for chain in explanation.evidence_chains.iter().take(5) {
            report.push_str(&format!(
                "- **{}** -> findings [{}] (spans {})\n",
                escape_markdown(&crate::explainability::humanize_feature_name(&chain.feature_name)),
                escape_markdown(&chain.derived_from_findings.join(", ")),
                chain.evidence_spans.len()
            ));
        }
        report.push('\n');
    }

    if let Some(counterfactual) = &explanation.counterfactual {
        report.push_str("#### Counterfactual changes\n\n");
        report.push_str(&format!(
            "- Target score: {:.2}\n- Achieved score: {:.2}\n",
            counterfactual.target_score, counterfactual.achieved_score
        ));
        if counterfactual.changes.is_empty() {
            report.push_str("- No changes suggested\n");
        } else {
            for change in counterfactual.changes.iter().take(6) {
                report.push_str(&format!(
                    "- {}: {:.2} -> {:.2} (delta {:+.2})\n",
                    escape_markdown(&crate::explainability::humanize_feature_name(
                        &change.feature_name
                    )),
                    change.from_value,
                    change.to_value,
                    change.delta
                ));
            }
        }
        if !counterfactual.notes.is_empty() {
            for note in counterfactual.notes.iter().take(3) {
                report.push_str(&format!("- Note: {}\n", escape_markdown(note)));
            }
        }
        report.push('\n');
    }

    if !explanation.feature_interactions.is_empty() {
        report.push_str("#### Feature interactions\n\n");
        for interaction in explanation.feature_interactions.iter().take(5) {
            report.push_str(&format!(
                "- {} (score {:.2})\n",
                escape_markdown(&interaction.summary),
                interaction.interaction_score
            ));
        }
        report.push('\n');
    }

    if let Some(temporal) = &explanation.temporal_analysis {
        report.push_str("#### Temporal analysis\n\n");
        report.push_str(&format!(
            "- Trend: {}\n- Score delta: {:.2}\n",
            escape_markdown(&temporal.trend),
            temporal.score_delta
        ));
        if !temporal.notable_changes.is_empty() {
            for change in temporal.notable_changes.iter().take(5) {
                report.push_str(&format!("- {}\n", escape_markdown(change)));
            }
        }
        report.push('\n');
    }

    report
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
        let detection_duration = entry
            .detection_duration_ms
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "n/a".to_string());
        out.push_str(&format!(
            "- {}: total={} high={} medium={} low={} info={} duration={}ms detection={}\n",
            escape_markdown(&entry.path),
            entry.summary.total,
            entry.summary.high,
            entry.summary.medium,
            entry.summary.low,
            entry.summary.info,
            entry.duration_ms,
            detection_duration
        ));
    }
    out
}

fn build_chain_summary(
    report: &Report,
    position_previews: &BTreeMap<String, String>,
    id_map: &BTreeMap<String, String>,
) -> Vec<ChainSummaryEntry> {
    let mut findings_by_id: HashMap<&str, &Finding> = HashMap::new();
    for finding in &report.findings {
        findings_by_id.insert(finding.id.as_str(), finding);
    }

    let mut entries = Vec::new();
    for chain in &report.chains {
        let path = replace_ids(&chain.path, id_map);
        let trigger_label = chain_trigger_label(chain);
        let action_label = chain_action_label(chain);
        let payload_label = chain_payload_label(chain);
        let outcome = {
            let summary = chain_effect_summary(chain);
            if summary == "Execution path inferred from linked findings; review trigger and payload details."
            {
                None
            } else {
                Some(summary)
            }
        };
        let narrative = {
            let story = chain_execution_narrative(chain, &report.findings);
            if story == "Insufficient context for a detailed narrative; review chain findings and payload details."
            {
                None
            } else {
                Some(story)
            }
        };

        let instances = chain.group_count.max(1);
        let node_preview =
            chain.nodes.iter().find_map(|node| format_node_preview(node, position_previews));

        let mut finding_kinds = BTreeSet::new();
        for fid in &chain.findings {
            if let Some(finding) = findings_by_id.get(fid.as_str()) {
                finding_kinds.insert(finding.kind.clone());
            }
        }

        let mut reasons = Vec::new();
        for reason in &chain.reasons {
            if !reason.trim().is_empty() && !reasons.contains(reason) {
                reasons.push(reason.clone());
            }
        }

        entries.push(ChainSummaryEntry {
            path,
            trigger_label,
            action_label,
            payload_label,
            outcome,
            narrative,
            instances,
            score: chain.score,
            reasons,
            node_preview,
            finding_kinds: finding_kinds.into_iter().collect(),
        });
    }

    entries.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| b.instances.cmp(&a.instances))
            .then_with(|| a.trigger_label.cmp(&b.trigger_label))
            .then_with(|| a.action_label.cmp(&b.action_label))
            .then_with(|| a.payload_label.cmp(&b.payload_label))
    });
    entries
}

fn format_node_preview(node: &str, position_previews: &BTreeMap<String, String>) -> Option<String> {
    let preview = position_previews.get(node);
    let obj_label = parse_position_obj_ref(node).map(|(obj, gen)| format!("obj[{obj} {gen}]"));
    match (obj_label, preview) {
        (Some(obj), Some(text)) => Some(format!("{} {}", obj, text)),
        (Some(obj), None) => Some(obj),
        (None, Some(text)) => Some(text.clone()),
        (None, None) => None,
    }
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
    let mut summary = Summary { total: findings.len(), high: 0, medium: 0, low: 0, info: 0 };
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
