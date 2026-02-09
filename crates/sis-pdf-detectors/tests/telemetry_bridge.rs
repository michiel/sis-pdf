mod common;

use std::collections::HashMap;

use common::default_scan_opts;
use sis_pdf_core::detect::Detector;
use sis_pdf_core::model::Severity;
use sis_pdf_core::scan::ScanContext;
use sis_pdf_detectors::telemetry_bridge::TelemetryBridgeDetector;
use sis_pdf_pdf::graph::{ObjectGraph, TelemetryEvent, TelemetryLevel};
use sis_pdf_pdf::span::Span;

fn build_context(
    bytes: &'static [u8],
    telemetry_events: Vec<TelemetryEvent>,
) -> ScanContext<'static> {
    let graph = ObjectGraph {
        bytes,
        objects: Vec::new(),
        index: HashMap::new(),
        trailers: Vec::new(),
        startxrefs: Vec::new(),
        xref_sections: Vec::new(),
        deviations: Vec::new(),
        telemetry_events,
    };
    ScanContext::new(bytes, graph, default_scan_opts())
}

#[test]
fn emits_xref_loop_finding_from_telemetry_event() {
    let bytes: &'static [u8] = b"%PDF-1.7\n";
    let event = TelemetryEvent {
        level: TelemetryLevel::Warn,
        domain: "pdf.xref".into(),
        kind: "xref_loop_detected".into(),
        message: "Detected xref loop".into(),
        span: Some(Span { start: 42, end: 42 }),
        object_ref: Some("xref_chain".into()),
        meta: HashMap::from([("offset".into(), "42".into())]),
    };
    let ctx = build_context(bytes, vec![event]);
    let detector = TelemetryBridgeDetector;
    let findings = detector.run(&ctx).expect("telemetry bridge should run");
    let finding = findings
        .iter()
        .find(|finding| finding.kind == "xref_loop_detected")
        .expect("xref loop finding should exist");
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.meta.get("telemetry.count"), Some(&"1".to_string()));
    assert_eq!(finding.meta.get("telemetry.offset"), Some(&"42".to_string()));
}

#[test]
fn aggregates_objstm_budget_events() {
    let bytes: &'static [u8] = b"%PDF-1.7\n";
    let events = vec![
        TelemetryEvent {
            level: TelemetryLevel::Warn,
            domain: "pdf.object_stream".into(),
            kind: "objstm_decode_budget_reached".into(),
            message: "ObjStm expansion halted due to decode budget".into(),
            span: Some(Span { start: 100, end: 120 }),
            object_ref: Some("10 0 obj".into()),
            meta: HashMap::from([("max_total_decoded_bytes".into(), "1000".into())]),
        },
        TelemetryEvent {
            level: TelemetryLevel::Warn,
            domain: "pdf.object_stream".into(),
            kind: "objstm_decode_budget_exceeded".into(),
            message: "ObjStm expansion halted due to budget overflow".into(),
            span: Some(Span { start: 100, end: 120 }),
            object_ref: Some("10 0 obj".into()),
            meta: HashMap::from([("decoded_total".into(), "1200".into())]),
        },
    ];
    let ctx = build_context(bytes, events);
    let detector = TelemetryBridgeDetector;
    let findings = detector.run(&ctx).expect("telemetry bridge should run");
    let finding = findings
        .iter()
        .find(|finding| finding.kind == "objstm_processing_limited")
        .expect("aggregated objstm finding should exist");
    assert_eq!(finding.meta.get("telemetry.count"), Some(&"2".to_string()));
    assert_eq!(
        finding.meta.get("telemetry.kinds"),
        Some(&"objstm_decode_budget_exceeded,objstm_decode_budget_reached".to_string())
    );
}
