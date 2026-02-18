use sis_pdf_core::event_graph::{
    build_event_graph, EdgeProvenance, EventEdgeKind, EventGraphOptions, EventNodeKind, OutcomeType,
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
