use std::collections::HashMap;

use sis_pdf_core::chain_synth::synthesise_chains;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};

fn base_finding(id: &str, kind: &str, object_ref: &str) -> Finding {
    Finding {
        id: id.to_string(),
        surface: AttackSurface::StreamsAndFilters,
        kind: kind.to_string(),
        severity: Severity::Low,
        confidence: Confidence::Strong,
        impact: Impact::Unknown,
        title: "test".to_string(),
        description: "test".to_string(),
        objects: vec![object_ref.to_string()],
        evidence: Vec::new(),
        remediation: None,
        positions: Vec::new(),
        meta: HashMap::new(),
        action_type: None,
        action_target: None,
        action_initiation: None,
        yara: None,
    }
}

#[test]
fn groups_identical_chains() {
    let findings = vec![
        base_finding("f1", "xref_conflict", "1 0 obj"),
        base_finding("f2", "xref_conflict", "1 0 obj"),
    ];
    let (chains, _) = synthesise_chains(&findings, true);
    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0].group_count, 2);
    assert_eq!(chains[0].group_members.len(), 2);
    assert!(chains[0].group_id.is_some());
}

#[test]
fn adds_payload_summary_from_decode_meta() {
    let mut finding = base_finding("f1", "declared_filter_invalid", "7 0 obj");
    finding.meta.insert("stream.filters".into(), "/FlateDecode".into());
    finding.meta.insert("decode.outcome".into(), "error".into());
    let findings = vec![finding];
    let (chains, _) = synthesise_chains(&findings, true);
    let chain =
        chains.iter().find(|c| c.notes.contains_key("payload.summary")).expect("payload summary");
    let summary = chain.notes.get("payload.summary").unwrap();
    assert!(summary.contains("filters=/FlateDecode"));
    assert!(summary.contains("decode=error"));
}

#[test]
fn classifies_action_and_payload_labels() {
    let findings = vec![base_finding("f1", "js_present", "4 0 obj")];
    let (chains, _) = synthesise_chains(&findings, true);
    let chain = chains.iter().find(|c| c.notes.contains_key("action.label")).expect("action label");
    assert_eq!(chain.notes.get("action.label").map(String::as_str), Some("JavaScript action"));
    let payload_label = chain.notes.get("payload.label").expect("payload label").clone();
    assert!(payload_label.contains("JavaScript payload"));
}

#[test]
fn preserves_custom_action_labels() {
    let mut finding = base_finding("f1", "uri_content_analysis", "4 0 obj");
    finding.meta.insert("action.target".into(), "https://example.com".into());
    finding.meta.insert("payload.type".into(), "stream".into());
    finding.title = "URI present".into();
    let companion = base_finding("f2", "uri_content_analysis", "4 0 obj");
    let (chains, _) = synthesise_chains(&[finding, companion], true);
    let chain = chains.iter().find(|c| c.notes.contains_key("action.label")).expect("action label");
    let label = chain.notes.get("action.label").map(String::as_str);
    assert!(matches!(label, Some("URI action") | Some("URI present -> https://example.com")));
}

#[test]
fn records_recovered_payload_summary() {
    let mut finding = base_finding("f1", "decode_recovery_used", "9 0 obj");
    finding.meta.insert("decode.recovered_filters".into(), "/FlateDecode".into());
    let findings = vec![finding];
    let (chains, _) = synthesise_chains(&findings, true);
    let chain =
        chains.iter().find(|c| c.notes.contains_key("payload.summary")).expect("payload summary");
    let summary = chain.notes.get("payload.summary").unwrap();
    assert!(summary.contains("recovered=/FlateDecode"));
}

#[test]
fn propagates_edge_and_exploit_notes_into_chain_output() {
    let mut finding = base_finding("f1", "composite.injection_edge_bridge", "10 0 obj");
    finding.meta.insert("edge.reason".into(), "scatter_to_injection".into());
    finding.meta.insert("edge.confidence".into(), "Strong".into());
    finding.meta.insert("edge.shared_objects".into(), "10 0 obj".into());
    finding.meta.insert("exploit.preconditions".into(), "fragment_assembly_path_reachable".into());
    finding.meta.insert("exploit.blockers".into(), "fragment_validation".into());
    finding.meta.insert("exploit.outcomes".into(), "payload_staging".into());
    finding.meta.insert("chain.stage".into(), "decode".into());
    finding.meta.insert("chain.severity".into(), "Medium".into());
    finding.meta.insert("chain.confidence".into(), "Strong".into());

    let (chains, _) = synthesise_chains(&[finding], true);
    let chain = chains.first().expect("single chain");
    assert_eq!(chain.notes.get("edge.reason").map(String::as_str), Some("scatter_to_injection"));
    assert_eq!(chain.notes.get("edge.confidence").map(String::as_str), Some("Strong"));
    assert_eq!(chain.notes.get("exploit.outcomes").map(String::as_str), Some("payload_staging"));
    assert_eq!(chain.notes.get("chain.severity").map(String::as_str), Some("Medium"));
    assert!(chain.narrative.contains("Likely outcomes: payload_staging."));
}

#[test]
fn computes_stage_completeness_without_reader_risk() {
    let mut input = base_finding("f1", "form_html_injection", "20 0 obj");
    input.meta.insert("chain.stage".into(), "input".into());
    input.confidence = Confidence::Probable;

    let mut execute = base_finding("f2", "js_present", "20 0 obj");
    execute.meta.insert("chain.stage".into(), "execute".into());
    execute.confidence = Confidence::Strong;

    let mut egress = base_finding("f3", "submitform_present", "20 0 obj");
    egress.meta.insert("chain.stage".into(), "egress".into());
    egress.confidence = Confidence::Probable;

    let (chains, _) = synthesise_chains(&[input, execute, egress], true);
    let chain = chains.iter().max_by_key(|chain| chain.confirmed_stages.len()).expect("chain");
    assert_eq!(chain.confirmed_stages, vec!["input", "execute", "egress"]);
    // Blended formula: ≥0.6 (3 confirmed) and ≤1.0; exact value depends on inferred stages
    assert!(
        chain.chain_completeness >= 0.6 && chain.chain_completeness <= 1.0,
        "completeness out of expected range: {}",
        chain.chain_completeness
    );
    assert!(chain.reader_risk.is_empty());
}

#[test]
fn maps_mitigations_and_required_conditions() {
    let mut finding = base_finding("f1", "composite.injection_edge_bridge", "33 0 obj");
    finding.meta.insert("exploit.blockers".into(), "sandbox_enabled".into());
    finding.meta.insert("exploit.mitigations".into(), "url_filtering".into());
    finding.meta.insert("exploit.preconditions".into(), "egress_allowed, js_enabled".into());
    finding.meta.insert("exploit.conditions_met".into(), "js_enabled".into());

    let (chains, _) = synthesise_chains(&[finding], true);
    let chain = chains.first().expect("single chain");
    assert_eq!(
        chain.active_mitigations,
        vec!["sandbox_enabled".to_string(), "url_filtering".to_string()]
    );
    assert_eq!(
        chain.required_conditions,
        vec!["egress_allowed".to_string(), "js_enabled".to_string()]
    );
    assert_eq!(chain.unmet_conditions, vec!["egress_allowed".to_string()]);
    assert!(chain.narrative.contains("Active mitigations: sandbox_enabled, url_filtering."));
    assert!(chain.narrative.contains("Unmet preconditions: egress_allowed."));
}

#[test]
fn captures_scatter_fragment_context_in_narrative() {
    let mut finding = base_finding("f1", "scattered_payload_assembly", "40 0 obj");
    finding.meta.insert("scatter.fragment_count".into(), "5".into());
    finding.meta.insert("chain.stage".into(), "decode".into());

    let (chains, _) = synthesise_chains(&[finding], true);
    let chain = chains.first().expect("single chain");
    assert_eq!(chain.notes.get("scatter.fragment_count").map(String::as_str), Some("5"));
    assert!(chain.narrative.contains("Payload scatter evidence: 5 fragments."));
}

#[test]
fn populates_finding_roles_for_named_chain_roles() {
    let trigger = base_finding("f1", "open_action_present", "50 0 obj");
    let action = base_finding("f2", "js_present", "50 0 obj");
    let payload = base_finding("f3", "embedded_file_present", "50 0 obj");

    let (chains, _) = synthesise_chains(&[trigger, action, payload], true);
    let chain = chains
        .iter()
        .find(|chain| chain.findings.len() >= 2 && chain.finding_roles.contains_key("f1"))
        .expect("multi-finding chain with trigger role");
    assert_eq!(chain.finding_roles.get("f1").map(String::as_str), Some("trigger"));
    assert!(chain.finding_roles.values().any(|role| role == "trigger"));
    assert!(chain.finding_roles.values().any(|role| role == "payload"));
}

#[test]
fn leaves_non_role_findings_out_of_finding_roles() {
    let mut non_role = base_finding("f1", "xref_conflict", "60 0 obj");
    non_role.meta.insert("chain.stage".into(), "decode".into());
    let (chains, _) = synthesise_chains(&[non_role], true);
    let chain = chains.first().expect("single chain");
    assert!(!chain.finding_roles.contains_key("f1"));
}

// --- EXT-01: URI dangerous scheme findings in chain scoring ---

#[test]
fn uri_javascript_scheme_finding_scores_high_in_chain() {
    let finding = base_finding("f1", "uri_javascript_scheme", "4 0 obj");
    let (chains, _) = synthesise_chains(&[finding], true);
    let chain = chains.first().expect("chain");
    assert!(chain.score >= 0.85, "uri_javascript_scheme should score >= 0.85, got {}", chain.score);
    assert!(
        chain.reasons.iter().any(|r| r.contains("Dangerous URI scheme")),
        "chain reasons should mention dangerous URI scheme"
    );
}

#[test]
fn uri_file_scheme_finding_scores_high_in_chain() {
    let finding = base_finding("f1", "uri_file_scheme", "4 0 obj");
    let (chains, _) = synthesise_chains(&[finding], true);
    let chain = chains.first().expect("chain");
    assert!(chain.score >= 0.85, "uri_file_scheme should score >= 0.85, got {}", chain.score);
}

#[test]
fn uri_data_html_scheme_finding_scores_high_in_chain() {
    let finding = base_finding("f1", "uri_data_html_scheme", "4 0 obj");
    let (chains, _) = synthesise_chains(&[finding], true);
    let chain = chains.first().expect("chain");
    assert!(chain.score >= 0.85, "uri_data_html_scheme should score >= 0.85, got {}", chain.score);
}

#[test]
fn uri_command_injection_finding_scores_high_in_chain() {
    let finding = base_finding("f1", "uri_command_injection", "4 0 obj");
    let (chains, _) = synthesise_chains(&[finding], true);
    let chain = chains.first().expect("chain");
    assert!(chain.score >= 0.8, "uri_command_injection should score >= 0.8, got {}", chain.score);
}

#[test]
fn uri_scheme_finding_assigned_as_action_key_in_chain() {
    let finding = base_finding("f1", "uri_javascript_scheme", "4 0 obj");
    let (chains, _) = synthesise_chains(&[finding], true);
    let chain = chains.first().expect("chain");
    assert_eq!(
        chain.notes.get("action.key").map(String::as_str),
        Some("uri_javascript_scheme"),
        "uri_javascript_scheme finding should be assigned as action.key"
    );
}

#[test]
fn launch_url_chain_assigns_trigger_action_payload_and_edges() {
    let trigger = base_finding("f1", "action_automatic_trigger", "70 0 obj");
    let action = base_finding("f2", "launch_action_present", "70 0 obj");
    let payload = base_finding("f3", "launch_win_embedded_url", "70 0 obj");

    let (chains, _) = synthesise_chains(&[trigger, action, payload], true);
    let chain = chains
        .iter()
        .find(|chain| chain.findings.len() >= 3 && chain.findings.contains(&"f3".to_string()))
        .expect("expected merged launch chain with embedded URL payload");

    assert_eq!(chain.trigger.as_deref(), Some("action_automatic_trigger"));
    assert_eq!(chain.action.as_deref(), Some("launch_action_present"));
    assert_eq!(chain.payload.as_deref(), Some("uri"));
    assert!(!chain.edges.is_empty(), "expected synthesized edges for trigger/action/payload chain");
    assert!(
        chain.chain_completeness >= 0.4,
        "expected non-trivial completeness for launch chain, got {}",
        chain.chain_completeness
    );
}
