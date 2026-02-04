use std::collections::HashMap;

use sis_pdf_core::chain_synth::synthesise_chains;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};

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
    let mut finding = base_finding("f1", "uri_present", "4 0 obj");
    finding.meta.insert("action.target".into(), "https://example.com".into());
    finding.title = "URI present".into();
    let (chains, _) = synthesise_chains(&[finding], true);
    let chain = chains.iter().find(|c| c.notes.contains_key("action.label")).expect("action label");
    assert_eq!(
        chain.notes.get("action.label").map(String::as_str),
        Some("URI present -> https://example.com")
    );
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
