mod common;

use common::default_scan_opts;
use sis_pdf_core::model::Severity;
use sis_pdf_detectors::default_detectors;

#[test]
fn detects_external_entity_as_backend_xxe_pattern() {
    let bytes = include_bytes!("fixtures/xfa_entity_external.pdf");
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let entity_risk = report
        .findings
        .iter()
        .find(|finding| finding.kind == "xfa_entity_resolution_risk")
        .expect("xfa_entity_resolution_risk");
    assert_eq!(entity_risk.severity, Severity::High);
    assert_eq!(
        entity_risk.meta.get("xfa.dtd_present").map(std::string::String::as_str),
        Some("true")
    );
    assert_eq!(
        entity_risk.meta.get("xfa.xml_entity_count").map(std::string::String::as_str),
        Some("1")
    );
    assert_eq!(
        entity_risk.meta.get("xfa.external_entity_refs").map(std::string::String::as_str),
        Some("1")
    );
    assert_eq!(
        entity_risk.meta.get("backend.ingest_risk").map(std::string::String::as_str),
        Some("high")
    );

    let backend_pattern = report
        .findings
        .iter()
        .find(|finding| finding.kind == "xfa_backend_xxe_pattern")
        .expect("xfa_backend_xxe_pattern");
    assert_eq!(backend_pattern.severity, Severity::High);
}

#[test]
fn detects_internal_entity_without_external_xxe_pattern() {
    let bytes = include_bytes!("fixtures/xfa_entity_internal.pdf");
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let entity_risk = report
        .findings
        .iter()
        .find(|finding| finding.kind == "xfa_entity_resolution_risk")
        .expect("xfa_entity_resolution_risk");
    assert_eq!(entity_risk.severity, Severity::Medium);
    assert_eq!(
        entity_risk.meta.get("xfa.external_entity_refs").map(std::string::String::as_str),
        Some("0")
    );
    assert_eq!(
        entity_risk.meta.get("backend.ingest_risk").map(std::string::String::as_str),
        Some("medium")
    );

    assert!(
        report.findings.iter().all(|finding| finding.kind != "xfa_backend_xxe_pattern"),
        "internal entities should not emit backend XXE pattern finding"
    );
}

#[test]
fn benign_xfa_without_entities_does_not_emit_entity_findings() {
    let bytes = include_bytes!("fixtures/xfa_entity_benign.pdf");
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    assert!(
        report.findings.iter().all(|finding| {
            finding.kind != "xfa_entity_resolution_risk"
                && finding.kind != "xfa_backend_xxe_pattern"
        }),
        "benign XFA should not emit entity resolution findings"
    );
}

#[test]
fn detects_external_reference_tokens_without_doctype() {
    let bytes = include_bytes!("fixtures/xfa_entity_xinclude.pdf");
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let entity_risk = report
        .findings
        .iter()
        .find(|finding| finding.kind == "xfa_entity_resolution_risk")
        .expect("xfa_entity_resolution_risk");
    assert_eq!(entity_risk.severity, Severity::Medium);
    assert_eq!(
        entity_risk.meta.get("xfa.dtd_present").map(std::string::String::as_str),
        Some("false")
    );
    assert_eq!(
        entity_risk.meta.get("xfa.external_entity_refs").map(std::string::String::as_str),
        Some("0")
    );
    let token_count = entity_risk
        .meta
        .get("xfa.external_reference_tokens")
        .and_then(|value| value.parse::<usize>().ok())
        .expect("xfa.external_reference_tokens");
    assert!(token_count >= 1, "expected at least one external reference token");
    assert_eq!(
        entity_risk.meta.get("backend.ingest_risk").map(std::string::String::as_str),
        Some("medium")
    );

    assert!(
        report.findings.iter().all(|finding| finding.kind != "xfa_backend_xxe_pattern"),
        "external reference token should not emit backend XXE pattern without external entity declaration"
    );
}
