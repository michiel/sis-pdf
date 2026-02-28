use crate::event_graph::{EventGraph, EventNodeKind, OutcomeType};
use crate::model::{Confidence, Finding};
use std::collections::{HashMap, HashSet, VecDeque};

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
    DenialOfService,
}

#[derive(Debug, Clone)]
pub struct IntentSignal {
    pub bucket: IntentBucket,
    pub weight: u32,
    pub label: String,
    pub finding_id: Option<String>,
}

pub fn apply_intent(findings: &mut [Finding]) -> IntentSummary {
    apply_intent_with_event_graph(findings, None)
}

pub fn apply_intent_with_event_graph(
    findings: &mut [Finding],
    event_graph: Option<&EventGraph>,
) -> IntentSummary {
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
        if f.meta.contains_key("action.s")
            || f.meta.contains_key("action.type")
            || f.action_type.is_some()
        {
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
    if let Some(graph) = event_graph {
        let has_network_path = has_event_path_to_outcome(
            graph,
            &[OutcomeType::NetworkEgress, OutcomeType::FormSubmission],
        );
        if has_js && (has_uri || has_submit) && has_network_path {
            signals.push(signal(
                IntentBucket::DataExfiltration,
                1,
                "Connected event-to-network outcome path",
                None,
            ));
        }
        let has_launch_path = has_event_path_to_outcome(graph, &[OutcomeType::ExternalLaunch]);
        if has_js && has_launch && has_launch_path {
            signals.push(signal(
                IntentBucket::SandboxEscape,
                1,
                "Connected event-to-launch outcome path",
                None,
            ));
        }
        let has_execution_path = has_event_path_to_outcome(graph, &[OutcomeType::CodeExecution]);
        if has_open_action && has_js && has_execution_path {
            signals.push(signal(
                IntentBucket::SandboxEscape,
                1,
                "Connected open trigger to executable outcome",
                None,
            ));
        }
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
    // Confidence promotion: if a bucket has score ≥ 4 AND any contributing finding
    // has Strong/Certain confidence, promote the bucket one confidence tier.
    let findings_by_id: HashMap<&str, &Finding> =
        findings.iter().map(|f| (f.id.as_str(), f)).collect();
    for bucket in buckets.values_mut() {
        if bucket.score < 4 {
            continue;
        }
        let has_strong_finding = bucket
            .findings
            .iter()
            .filter_map(|fid| findings_by_id.get(fid.as_str()))
            .any(|f| matches!(f.confidence, Confidence::Certain | Confidence::Strong));
        if has_strong_finding {
            bucket.confidence = match bucket.confidence {
                Confidence::Heuristic => Confidence::Probable,
                Confidence::Probable => Confidence::Strong,
                other => other,
            };
        }
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

fn has_event_path_to_outcome(event_graph: &EventGraph, outcomes: &[OutcomeType]) -> bool {
    let mut queue = VecDeque::<String>::new();
    let mut seen = HashSet::<String>::new();
    let wanted = outcomes.iter().copied().collect::<HashSet<_>>();

    for node in &event_graph.nodes {
        if let EventNodeKind::Event { .. } = node.kind {
            queue.push_back(node.id.clone());
            seen.insert(node.id.clone());
        }
    }

    while let Some(node_id) = queue.pop_front() {
        if let Some(indices) = event_graph.forward_index.get(&node_id) {
            for edge_idx in indices {
                let Some(edge) = event_graph.edges.get(*edge_idx) else {
                    continue;
                };
                let Some(next_idx) = event_graph.node_index.get(&edge.to) else {
                    continue;
                };
                let Some(next_node) = event_graph.nodes.get(*next_idx) else {
                    continue;
                };
                if let EventNodeKind::Outcome { outcome_type, .. } = next_node.kind {
                    if wanted.contains(&outcome_type) {
                        return true;
                    }
                }
                if seen.insert(edge.to.clone()) {
                    queue.push_back(edge.to.clone());
                }
            }
        }
    }
    false
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
        "decoder_risk_present" | "huge_image_dimensions" => {
            out.push(signal(IntentBucket::ExploitPrimitive, 2, "Decoder risk", fid.clone()));
        }
        "decompression_ratio_suspicious" => {
            // Weight by ratio severity for DoS intent.
            // DecompressionRatioDetector uses "decode.ratio"; "decompression.ratio" is a legacy key.
            let ratio: f64 = f
                .meta
                .get("decode.ratio")
                .or_else(|| f.meta.get("decompression.ratio"))
                .or_else(|| f.meta.get("ratio"))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0.0);
            let dos_weight = if ratio >= 100.0 {
                4
            } else if ratio >= 20.0 {
                2
            } else {
                1
            };
            out.push(signal(
                IntentBucket::DenialOfService,
                dos_weight,
                "Decompression bomb",
                fid.clone(),
            ));
            out.push(signal(IntentBucket::ExploitPrimitive, 2, "Decoder risk", fid.clone()));
        }
        "parser_resource_exhaustion" => {
            out.push(signal(
                IntentBucket::DenialOfService,
                4,
                "Parser resource exhaustion",
                fid.clone(),
            ));
        }
        "object_reference_depth_high" => {
            out.push(signal(
                IntentBucket::DenialOfService,
                2,
                "Object graph exhaustion",
                fid.clone(),
            ));
        }
        "polyglot_signature_conflict" => {
            out.push(signal(
                IntentBucket::ExploitPrimitive,
                4,
                "Polyglot signature conflict",
                fid.clone(),
            ));
        }
        "nested_container_chain" => {
            let nested_kind = f.meta.get("nested.kind").map(|s| s.as_str()).unwrap_or("");
            if nested_kind == "mz" {
                out.push(signal(
                    IntentBucket::ExploitPrimitive,
                    4,
                    "Nested PE executable",
                    fid.clone(),
                ));
                out.push(signal(
                    IntentBucket::SandboxEscape,
                    2,
                    "PE dropper in container",
                    fid.clone(),
                ));
            } else {
                out.push(signal(
                    IntentBucket::ExploitPrimitive,
                    2,
                    "Nested container",
                    fid.clone(),
                ));
            }
        }
        "embedded_payload_carved" => {
            let carve_kind = f.meta.get("carve.kind").map(|s| s.as_str()).unwrap_or("");
            let weight = if carve_kind == "zip" || carve_kind == "mz" { 3 } else { 2 };
            out.push(signal(IntentBucket::ExploitPrimitive, weight, "Carved payload", fid.clone()));
        }
        "font_exploitation_cluster" => {
            out.push(signal(
                IntentBucket::ExploitPrimitive,
                3,
                "Font exploitation cluster",
                fid.clone(),
            ));
        }
        "polyglot_pe_dropper" | "polyglot_dropper_chain" => {
            out.push(signal(IntentBucket::ExploitPrimitive, 4, "Polyglot PE dropper", fid.clone()));
            out.push(signal(IntentBucket::SandboxEscape, 3, "PE dropper chain", fid.clone()));
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
        IntentBucket::DenialOfService => "denial_of_service",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_graph::{EdgeProvenance, EventEdge, EventEdgeKind, EventGraph, EventNode};
    use std::collections::HashMap;

    fn make_finding(id: &str, kind: &str) -> Finding {
        Finding { id: id.to_string(), kind: kind.to_string(), ..Finding::default() }
    }

    fn minimal_event_graph_with_network_outcome() -> EventGraph {
        let event = EventNode {
            id: "ev:1:0:DocumentOpen:0".to_string(),
            mitre_techniques: Vec::new(),
            kind: EventNodeKind::Event {
                event_type: crate::event_graph::EventType::DocumentOpen,
                trigger: crate::event_graph::TriggerClass::Automatic,
                label: "/OpenAction".to_string(),
                source_obj: Some((1, 0)),
            },
        };
        let outcome = EventNode {
            id: "out:1:0:NetworkEgress:0".to_string(),
            mitre_techniques: Vec::new(),
            kind: EventNodeKind::Outcome {
                outcome_type: OutcomeType::NetworkEgress,
                label: "Network egress".to_string(),
                target: Some("example.test".to_string()),
                source_obj: Some((1, 0)),
                evidence: vec!["f2".to_string()],
                confidence_source: Some("finding".to_string()),
                confidence_score: Some(70),
                severity_hint: Some("medium".to_string()),
            },
        };
        let edge = EventEdge {
            from: event.id.clone(),
            to: outcome.id.clone(),
            kind: EventEdgeKind::ProducesOutcome,
            provenance: EdgeProvenance::Finding { finding_id: "f2".to_string() },
            metadata: None,
        };
        let nodes = vec![event, outcome];
        let edges = vec![edge];
        let mut node_index = HashMap::new();
        node_index.insert(nodes[0].id.clone(), 0);
        node_index.insert(nodes[1].id.clone(), 1);
        let mut forward_index = HashMap::new();
        forward_index.insert(nodes[0].id.clone(), vec![0]);
        let mut reverse_index = HashMap::new();
        reverse_index.insert(nodes[1].id.clone(), vec![0]);
        EventGraph {
            schema_version: "1.0",
            nodes,
            edges,
            node_index,
            forward_index,
            reverse_index,
            truncation: None,
        }
    }

    #[test]
    fn intent_connectivity_boost_adds_signal_weight_for_connected_network_path() {
        let mut findings =
            vec![make_finding("f1", "js_present"), make_finding("f2", "uri_listing")];
        let mut baseline_findings = findings.clone();
        let baseline = apply_intent(&mut baseline_findings);
        let connected = apply_intent_with_event_graph(
            &mut findings,
            Some(&minimal_event_graph_with_network_outcome()),
        );

        let baseline_score = baseline
            .buckets
            .iter()
            .find(|bucket| bucket.bucket == IntentBucket::DataExfiltration)
            .map(|bucket| bucket.score)
            .unwrap_or(0);
        let connected_score = connected
            .buckets
            .iter()
            .find(|bucket| bucket.bucket == IntentBucket::DataExfiltration)
            .map(|bucket| bucket.score)
            .unwrap_or(0);
        assert!(connected_score > baseline_score);
    }
}
