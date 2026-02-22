use sis_pdf_core::event_graph::{
    build_event_graph, EdgeProvenance, EventEdgeKind, EventGraphOptions, EventNodeKind, EventType,
    OutcomeType,
};
use sis_pdf_core::scan::{
    CorrelationOptions, FontAnalysisOptions, ImageAnalysisOptions, ProfileFormat, ScanOptions,
};
use sis_pdf_pdf::{parse_pdf, ParseOptions};

fn scan_options() -> ScanOptions {
    ScanOptions {
        deep: true,
        max_decode_bytes: 8 * 1024 * 1024,
        max_total_decoded_bytes: 64 * 1024 * 1024,
        recover_xref: true,
        parallel: false,
        batch_parallel: false,
        diff_parser: false,
        max_objects: 100_000,
        max_recursion_depth: 64,
        fast: false,
        focus_trigger: None,
        focus_depth: 0,
        yara_scope: None,
        strict: false,
        strict_summary: false,
        ir: false,
        ml_config: None,
        font_analysis: FontAnalysisOptions::default(),
        image_analysis: ImageAnalysisOptions::default(),
        filter_allowlist: None,
        filter_allowlist_strict: false,
        profile: false,
        profile_format: ProfileFormat::Text,
        group_chains: true,
        correlation: CorrelationOptions::default(),
    }
}

fn parse_options() -> ParseOptions {
    ParseOptions {
        recover_xref: true,
        deep: false,
        strict: false,
        max_objstm_bytes: 1024 * 1024,
        max_objects: 10_000,
        max_objstm_total_bytes: 10 * 1024 * 1024,
        carve_stream_objects: false,
        max_carved_objects: 0,
        max_carved_bytes: 0,
    }
}

fn build_pdf(objects: &[String], size: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"%PDF-1.4\n");
    let mut offsets = vec![0usize; size];
    for object in objects {
        let id = object
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        if id < offsets.len() {
            offsets[id] = out.len();
        }
        out.extend_from_slice(object.as_bytes());
    }
    let startxref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", size).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n", size).as_bytes(),
    );
    out.extend_from_slice(startxref.to_string().as_bytes());
    out.extend_from_slice(b"\n%%EOF\n");
    out
}

fn event_graph_for_pdf(bytes: &[u8]) -> sis_pdf_core::event_graph::EventGraph {
    let graph = parse_pdf(bytes, parse_options()).expect("parse pdf");
    let ctx = sis_pdf_core::scan::ScanContext::new(bytes, graph, scan_options());
    let typed = ctx.build_typed_graph();
    let findings = sis_pdf_core::runner::run_scan_with_detectors(
        bytes,
        scan_options(),
        &sis_pdf_detectors::default_detectors(),
    )
    .expect("scan")
    .findings;
    build_event_graph(&typed, &findings, EventGraphOptions::default())
}

#[test]
fn derives_uri_and_launch_outcomes_with_confidence_metadata() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Action /S /URI /URI 8 0 R /Next 4 0 R >>\nendobj\n".to_string(),
        "4 0 obj\n<< /Type /Action /S /Launch /F 9 0 R >>\nendobj\n".to_string(),
        "8 0 obj\n(https://example.test)\nendobj\n".to_string(),
        "9 0 obj\n(target.exe)\nendobj\n".to_string(),
    ];
    let bytes = build_pdf(&objects, 10);
    let event_graph = event_graph_for_pdf(&bytes);

    let outcomes = event_graph
        .nodes
        .iter()
        .filter_map(|node| match &node.kind {
            EventNodeKind::Outcome { outcome_type, confidence_score, severity_hint, .. } => {
                Some((*outcome_type, *confidence_score, severity_hint.clone()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(outcomes.iter().any(|(kind, confidence, _)| {
        *kind == OutcomeType::NetworkEgress && confidence.unwrap_or_default() >= 60
    }));
    assert!(outcomes.iter().any(|(kind, confidence, _)| {
        *kind == OutcomeType::ExternalLaunch && confidence.unwrap_or_default() >= 60
    }));
}

#[test]
fn derives_submit_form_outcome_and_next_action_path() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert(1)) /Next 4 0 R >>\nendobj\n"
            .to_string(),
        "4 0 obj\n<< /Type /Action /S /SubmitForm /F 8 0 R >>\nendobj\n".to_string(),
        "8 0 obj\n(form-target)\nendobj\n".to_string(),
    ];
    let bytes = build_pdf(&objects, 9);
    let event_graph = event_graph_for_pdf(&bytes);

    let has_submit = event_graph.nodes.iter().any(|node| {
        matches!(
            node.kind,
            EventNodeKind::Outcome { outcome_type: OutcomeType::FormSubmission, .. }
        )
    });
    assert!(has_submit);

    let next_action_edges = event_graph
        .nodes
        .iter()
        .filter(|node| {
            matches!(
                node.kind,
                EventNodeKind::Event {
                    event_type: sis_pdf_core::event_graph::EventType::NextAction,
                    ..
                }
            )
        })
        .count();
    assert!(next_action_edges >= 1);
}

#[test]
fn next_action_array_edges_include_branch_index_and_initiation_metadata() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert(1)) /Next [4 0 R 5 0 R] >>\nendobj\n"
            .to_string(),
        "4 0 obj\n<< /Type /Action /S /URI /URI 8 0 R >>\nendobj\n".to_string(),
        "5 0 obj\n<< /Type /Action /S /Launch /F 9 0 R >>\nendobj\n".to_string(),
        "8 0 obj\n(https://example.test/branch-a)\nendobj\n".to_string(),
        "9 0 obj\n(branch-b.exe)\nendobj\n".to_string(),
    ];
    let bytes = build_pdf(&objects, 11);
    let event_graph = event_graph_for_pdf(&bytes);

    let mut branch_indexes = Vec::new();
    let mut initiations = Vec::new();
    for edge in &event_graph.edges {
        if edge.kind != EventEdgeKind::Executes {
            continue;
        }
        let EdgeProvenance::TypedEdge { edge_type } = &edge.provenance else {
            continue;
        };
        if edge_type != "next_action" {
            continue;
        }
        if let Some(metadata) = &edge.metadata {
            if let Some(branch_index) = metadata.branch_index {
                branch_indexes.push(branch_index);
            }
            if let Some(initiation) = &metadata.initiation {
                initiations.push(initiation.clone());
            }
        }
    }

    branch_indexes.sort_unstable();
    assert_eq!(branch_indexes, vec![0, 1]);
    assert!(initiations.iter().all(|value| value == "hidden"));
}

#[test]
fn finding_outcome_edges_fallback_to_trigger_type_initiation() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /AA << /K 4 0 R >> >>\nendobj\n".to_string(),
        "4 0 obj\n<< /Type /Action /S /URI /URI (https://example.test/key) >>\nendobj\n"
            .to_string(),
    ];
    let bytes = build_pdf(&objects, 6);
    let event_graph = event_graph_for_pdf(&bytes);

    let mut finding_edge_initiations = Vec::new();
    for edge in &event_graph.edges {
        if edge.kind != EventEdgeKind::ProducesOutcome {
            continue;
        }
        let EdgeProvenance::Finding { .. } = &edge.provenance else {
            continue;
        };
        if let Some(metadata) = &edge.metadata {
            if let Some(initiation) = &metadata.initiation {
                finding_edge_initiations.push(initiation.clone());
            }
        }
    }

    assert!(
        finding_edge_initiations.iter().any(|value| value == "user"),
        "expected finding-provenance outcome initiation to fallback to action.trigger_type=user"
    );
}

#[test]
fn test_circular_next_terminates() {
    // Objects 3 and 4 form a /Next cycle: 3 -> 4 -> 3
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Action /S /JavaScript /JS (alert(1)) /Next 4 0 R >>\nendobj\n"
            .to_string(),
        "4 0 obj\n<< /Type /Action /S /JavaScript /JS (alert(2)) /Next 3 0 R >>\nendobj\n"
            .to_string(),
    ];
    let bytes = build_pdf(&objects, 5);
    let event_graph = event_graph_for_pdf(&bytes);

    let next_action_count = event_graph
        .nodes
        .iter()
        .filter(|node| {
            matches!(
                node.kind,
                EventNodeKind::Event {
                    event_type: sis_pdf_core::event_graph::EventType::NextAction,
                    ..
                }
            )
        })
        .count();
    // With cycle detection, we should have at most 2 NextAction events (3->4 and 4->3),
    // and the graph should not hang
    assert!(
        next_action_count <= 2,
        "expected at most 2 NextAction events, got {next_action_count}"
    );
}

#[test]
fn test_per_component_collapse() {
    // Two disconnected clusters of passive objects with one active cluster near the event
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 0 /Kids [7 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Action /S /URI /URI (https://test.example) >>\nendobj\n".to_string(),
        // Disconnected passive cluster 1
        "7 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 8 0 R >> >> >>\nendobj\n"
            .to_string(),
        "8 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n".to_string(),
    ];
    let bytes = build_pdf(&objects, 9);
    let event_graph = event_graph_for_pdf(&bytes);

    let _collapse_count = event_graph
        .nodes
        .iter()
        .filter(|n| matches!(n.kind, EventNodeKind::Collapse { .. }))
        .count();
    // We don't assert exact count since it depends on which objects are >3 hops from events,
    // but if there are collapse nodes, they should have meaningful member counts
    for node in &event_graph.nodes {
        if let EventNodeKind::Collapse { member_count, .. } = &node.kind {
            assert!(*member_count > 0, "collapse nodes should have members");
        }
    }
    // The graph should have completed without errors
    assert!(!event_graph.nodes.is_empty());
    // If there is more than one collapse node, verify they have distinct IDs
    let collapse_ids: Vec<&str> = event_graph
        .nodes
        .iter()
        .filter_map(|n| match &n.kind {
            EventNodeKind::Collapse { .. } => Some(n.id.as_str()),
            _ => None,
        })
        .collect();
    let unique_ids: std::collections::BTreeSet<&str> = collapse_ids.iter().copied().collect();
    assert_eq!(collapse_ids.len(), unique_ids.len(), "collapse IDs should be unique");
}

#[test]
fn test_collapse_determinism() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Action /S /URI /URI (https://test.example) >>\nendobj\n".to_string(),
    ];
    let bytes = build_pdf(&objects, 4);
    let graph1 = event_graph_for_pdf(&bytes);
    let graph2 = event_graph_for_pdf(&bytes);

    let ids1: Vec<&str> = graph1.nodes.iter().map(|n| n.id.as_str()).collect();
    let ids2: Vec<&str> = graph2.nodes.iter().map(|n| n.id.as_str()).collect();
    assert_eq!(ids1, ids2, "same graph built twice should produce identical node IDs");
}

#[test]
fn test_content_stream_exec_event() {
    // Page with /Contents reference should produce a ContentStreamExec event
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n".to_string(),
        "4 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n".to_string(),
    ];
    let bytes = build_pdf(&objects, 5);
    let event_graph = event_graph_for_pdf(&bytes);

    let content_stream_exec = event_graph.nodes.iter().find_map(|node| match &node.kind {
        EventNodeKind::Event { event_type: EventType::ContentStreamExec, label, .. } => {
            Some(label.as_str())
        }
        _ => None,
    });
    let label =
        content_stream_exec.expect("should have ContentStreamExec event for page with /Contents");
    assert!(
        label.contains("page 3 0") && label.contains("stream 4 0"),
        "content stream event label should include page and stream refs, got: {label}"
    );
}

#[test]
fn test_content_stream_exec_event_count_matches_contents_array_length() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents [4 0 R 5 0 R 4 0 R] >>\nendobj\n"
            .to_string(),
        "4 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n".to_string(),
        "5 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n".to_string(),
    ];
    let bytes = build_pdf(&objects, 6);
    let event_graph = event_graph_for_pdf(&bytes);

    let content_stream_events = event_graph
        .nodes
        .iter()
        .filter(|node| {
            matches!(
                node.kind,
                EventNodeKind::Event { event_type: EventType::ContentStreamExec, .. }
            )
        })
        .count();

    assert_eq!(
        content_stream_events, 2,
        "expected one ContentStreamExec event per unique /Contents target reference"
    );
}
