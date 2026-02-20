use std::collections::HashMap;
use std::time::{Duration, Instant};

use sis_pdf_core::chain::ExploitChain;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::object_context::{
    build_object_context_index, get_object_context, has_context, ObjectChainRole,
};
use sis_pdf_core::report::Report;
use sis_pdf_core::taint::Taint;

fn finding(
    id: &str,
    kind: &str,
    severity: Severity,
    confidence: Confidence,
    objects: &[&str],
) -> Finding {
    let mut finding =
        Finding::template(AttackSurface::Actions, kind, severity, confidence, kind, kind);
    finding.id = id.to_string();
    finding.objects = objects.iter().map(|value| (*value).to_string()).collect();
    finding
}

fn test_chain(id: &str, findings: &[&str], score: f64) -> ExploitChain {
    ExploitChain {
        id: id.to_string(),
        group_id: None,
        group_count: 1,
        group_members: vec![id.to_string()],
        trigger: Some("open_action_present".into()),
        action: Some("js_present".into()),
        payload: Some("javascript".into()),
        findings: findings.iter().map(|value| (*value).to_string()).collect(),
        score,
        reasons: Vec::new(),
        path: format!("path:{id}"),
        nodes: Vec::new(),
        edges: Vec::new(),
        confirmed_stages: Vec::new(),
        inferred_stages: Vec::new(),
        chain_completeness: 0.0,
        reader_risk: HashMap::new(),
        narrative: String::new(),
        finding_criticality: HashMap::new(),
        active_mitigations: Vec::new(),
        required_conditions: Vec::new(),
        unmet_conditions: Vec::new(),
        finding_roles: HashMap::new(),
        notes: HashMap::new(),
    }
}

fn report_with(findings: Vec<Finding>, chains: Vec<ExploitChain>) -> Report {
    Report::from_findings(
        findings,
        chains,
        Vec::new(),
        Vec::new(),
        None,
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        None,
    )
}

#[test]
fn object_context_marks_taint_source_and_payload_role() {
    let finding = finding("f1", "js_present", Severity::High, Confidence::Strong, &["5 0 obj"]);
    let mut chain = test_chain("chain-1", &["f1"], 0.9);
    chain.finding_roles.insert("f1".into(), "payload".into());
    let report = report_with(vec![finding], vec![chain]);
    let taint = Taint {
        flagged: true,
        reasons: vec!["JavaScript present (no extra signals)".into()],
        taint_sources: vec![(5, 0)],
        taint_propagation: Vec::new(),
    };

    let index = build_object_context_index(&report, &taint);
    let context = get_object_context(&index, 5, 0);
    assert!(context.tainted);
    assert!(context.taint_source);
    assert_eq!(context.chains.len(), 1);
    assert_eq!(context.chains[0].role, ObjectChainRole::Payload);
}

#[test]
fn object_context_marks_propagation_target_as_tainted_but_not_source() {
    let finding =
        finding("f1", "stream_length_mismatch", Severity::Medium, Confidence::Strong, &["7 0 obj"]);
    let report = report_with(vec![finding], Vec::new());
    let taint = Taint {
        flagged: true,
        reasons: vec!["Stream length mismatch".into()],
        taint_sources: vec![(7, 0)],
        taint_propagation: vec![((7, 0), (8, 0))],
    };

    let index = build_object_context_index(&report, &taint);
    let source = get_object_context(&index, 7, 0);
    let propagated = get_object_context(&index, 8, 0);
    assert!(source.taint_source);
    assert!(propagated.tainted);
    assert!(!propagated.taint_source);
    assert_eq!(propagated.taint_incoming, vec![(7, 0)]);
}

#[test]
fn object_context_distinguishes_participant_and_path_node_roles() {
    let finding = finding("f1", "js_present", Severity::High, Confidence::Strong, &["5 0 obj"]);
    let mut chain = test_chain("chain-1", &["f1"], 0.9);
    chain.nodes.push("doc:r0/catalog.openaction@9:0".into());
    let report = report_with(vec![finding], vec![chain]);
    let taint = Taint::default();

    let index = build_object_context_index(&report, &taint);
    let participant = get_object_context(&index, 5, 0);
    let path_only = get_object_context(&index, 9, 0);
    assert_eq!(participant.chains[0].role, ObjectChainRole::Participant);
    assert_eq!(path_only.chains[0].role, ObjectChainRole::PathNode);
}

#[test]
fn object_context_is_empty_for_unknown_object() {
    let report = report_with(Vec::new(), Vec::new());
    let taint = Taint::default();

    let index = build_object_context_index(&report, &taint);
    assert!(!has_context(&index, 42, 0));
    let context = get_object_context(&index, 42, 0);
    assert_eq!((context.obj, context.gen), (42, 0));
    assert_eq!(context.finding_count, 0);
    assert!(!context.tainted);
    assert!(context.chains.is_empty());
}

#[test]
fn object_context_build_budget() {
    let mut findings = Vec::new();
    for idx in 0..10_000usize {
        let object_ref = format!("{} 0 obj", (idx % 2_000) + 1);
        findings.push(finding(
            &format!("f-{idx}"),
            if idx % 2 == 0 { "js_present" } else { "stream_length_mismatch" },
            Severity::Medium,
            Confidence::Probable,
            &[&object_ref],
        ));
    }
    let mut chains = Vec::new();
    for idx in 0..2_000usize {
        let finding_id = format!("f-{idx}");
        let mut chain = test_chain(&format!("chain-{idx}"), &[&finding_id], 0.5);
        chain.finding_roles.insert(finding_id, "action".into());
        chains.push(chain);
    }
    let report = report_with(findings, chains);
    let taint = Taint {
        flagged: true,
        reasons: vec!["JavaScript present (no extra signals)".into()],
        taint_sources: vec![(1, 0)],
        taint_propagation: vec![((1, 0), (2, 0))],
    };

    let start = Instant::now();
    let index = build_object_context_index(&report, &taint);
    let elapsed = start.elapsed();
    assert!(has_context(&index, 1, 0));
    assert!(
        elapsed <= Duration::from_millis(500),
        "object context build exceeded budget: {:?}",
        elapsed
    );
}
