mod common;

use common::default_scan_opts;
use sis_pdf_core::model::Severity;
use sis_pdf_detectors::default_detectors;

#[test]
fn detects_packetised_payload_with_execution_bridge() {
    let bytes = include_bytes!("fixtures/packetised_payload_obfuscation.pdf");
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == "packetised_payload_obfuscation")
        .expect("packetised_payload_obfuscation");
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(
        finding.meta.get("packet.correlation.execution_bridge").map(std::string::String::as_str),
        Some("true")
    );
    assert!(
        finding
            .meta
            .get("packet.block_count")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0)
            >= 16
    );
}

#[test]
fn suppresses_packetised_finding_without_execution_bridge() {
    let bytes = include_bytes!("fixtures/packetised_payload_no_bridge.pdf");
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    assert!(
        report.findings.iter().all(|finding| finding.kind != "packetised_payload_obfuscation"),
        "packetised signal should be gated when execution bridge is absent"
    );
}
