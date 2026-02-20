use std::collections::HashMap;

use sis_pdf_core::chain_synth::synthesise_chains;
use sis_pdf_core::model::{
    AttackSurface, Confidence, Finding, Impact, ReaderImpact, ReaderProfile, Severity,
};

fn base_finding(id: &str, kind: &str, object_ref: &str) -> Finding {
    Finding {
        id: id.to_string(),
        surface: AttackSurface::StreamsAndFilters,
        kind: kind.to_string(),
        severity: Severity::Low,
        confidence: Confidence::Strong,
        impact: None,
        title: "test".to_string(),
        description: "test".to_string(),
        objects: vec![object_ref.to_string()],
        evidence: Vec::new(),
        remediation: None,
        position: None,
        positions: Vec::new(),
        meta: HashMap::new(),
        reader_impacts: Vec::new(),
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
}

#[test]
fn computes_stage_completeness_and_reader_risk() {
    let mut input = base_finding("f1", "form_html_injection", "20 0 obj");
    input.meta.insert("chain.stage".into(), "input".into());
    input.confidence = Confidence::Probable;
    input.reader_impacts.push(ReaderImpact {
        profile: ReaderProfile::Acrobat,
        surface: AttackSurface::Forms,
        severity: Severity::Medium,
        impact: Impact::Medium,
        note: None,
    });

    let mut execute = base_finding("f2", "js_present", "20 0 obj");
    execute.meta.insert("chain.stage".into(), "execute".into());
    execute.confidence = Confidence::Strong;
    execute.reader_impacts.push(ReaderImpact {
        profile: ReaderProfile::Acrobat,
        surface: AttackSurface::JavaScript,
        severity: Severity::Critical,
        impact: Impact::Critical,
        note: None,
    });

    let mut egress = base_finding("f3", "submitform_present", "20 0 obj");
    egress.meta.insert("chain.stage".into(), "egress".into());
    egress.confidence = Confidence::Probable;

    let (chains, _) = synthesise_chains(&[input, execute, egress], true);
    let chain = chains.iter().max_by_key(|chain| chain.confirmed_stages.len()).expect("chain");
    assert_eq!(chain.confirmed_stages, vec!["input", "execute", "egress"]);
    assert!((chain.chain_completeness - 0.6).abs() < f64::EPSILON);
    assert_eq!(chain.reader_risk.get("acrobat").map(String::as_str), Some("Critical"));
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
}
