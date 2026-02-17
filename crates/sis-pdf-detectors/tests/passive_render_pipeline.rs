mod common;

use common::default_scan_opts;
use sis_pdf_core::model::Severity;
use sis_pdf_detectors::default_detectors;

#[test]
fn detects_passive_credential_leak_with_automatic_trigger() {
    let bytes = include_bytes!("fixtures/passive_openaction_unc.pdf");
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let fetch = report
        .findings
        .iter()
        .find(|finding| finding.kind == "passive_external_resource_fetch")
        .expect("passive_external_resource_fetch");
    assert_eq!(fetch.severity, Severity::High);
    assert_eq!(
        fetch.meta.get("passive.trigger_mode").map(std::string::String::as_str),
        Some("automatic_or_aa")
    );
    assert_eq!(
        fetch.meta.get("passive.indexer_trigger_likelihood").map(std::string::String::as_str),
        Some("elevated")
    );
    assert_eq!(
        fetch.meta.get("passive.credential_leak_risk").map(std::string::String::as_str),
        Some("true")
    );
    assert_eq!(
        fetch.meta.get("passive.ntlm_hash_leak_likelihood").map(std::string::String::as_str),
        Some("high")
    );
    assert_eq!(
        fetch.meta.get("passive.protocol_risk_class").map(std::string::String::as_str),
        Some("high")
    );
    assert_eq!(
        fetch.meta.get("passive.ntlm_hosts").map(std::string::String::as_str),
        Some("corp-fs")
    );
    assert_eq!(
        fetch.meta.get("passive.ntlm_shares").map(std::string::String::as_str),
        Some("finance")
    );

    let credential = report
        .findings
        .iter()
        .find(|finding| finding.kind == "passive_credential_leak_risk")
        .expect("passive_credential_leak_risk");
    assert_eq!(credential.severity, Severity::High);
    assert!(
        credential.objects.iter().any(|value| value == "2 0 obj"),
        "expected object reference for manual follow-up"
    );
}

#[test]
fn emits_composite_when_auto_trigger_and_preview_prone_surface_cooccur() {
    let bytes = include_bytes!("fixtures/passive_composite_font_http.pdf");
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let fetch = report
        .findings
        .iter()
        .find(|finding| finding.kind == "passive_external_resource_fetch")
        .expect("passive_external_resource_fetch");
    assert_eq!(fetch.severity, Severity::Medium);
    assert_eq!(
        fetch.meta.get("passive.preview_prone_surface").map(std::string::String::as_str),
        Some("true")
    );

    let composite = report
        .findings
        .iter()
        .find(|finding| finding.kind == "passive_render_pipeline_risk_composite")
        .expect("passive_render_pipeline_risk_composite");
    assert_eq!(composite.severity, Severity::High);
    assert_eq!(
        composite.meta.get("passive.composite_rule").map(std::string::String::as_str),
        Some("auto_trigger+preview_context+external_targets")
    );
}

#[test]
fn ignores_relative_targets_without_supported_external_protocol() {
    let bytes = include_bytes!("fixtures/passive_benign_relative_uri.pdf");
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(
        report.findings.iter().all(|finding| !finding.kind.starts_with("passive_")),
        "relative path should not trigger passive external target findings"
    );
}

#[test]
fn classifies_passive_render_only_context_without_automatic_trigger() {
    let bytes = include_bytes!("fixtures/passive_font_only_http.pdf");
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let fetch = report
        .findings
        .iter()
        .find(|finding| finding.kind == "passive_external_resource_fetch")
        .expect("passive_external_resource_fetch");
    assert_eq!(fetch.severity, Severity::Low);
    assert_eq!(
        fetch.meta.get("passive.trigger_mode").map(std::string::String::as_str),
        Some("passive_render_or_indexer")
    );
    assert_eq!(
        fetch.meta.get("passive.indexer_trigger_likelihood").map(std::string::String::as_str),
        Some("elevated")
    );
    assert_eq!(
        fetch.meta.get("passive.protocol_risk_class").map(std::string::String::as_str),
        Some("low")
    );
    assert!(
        report.findings.iter().all(|finding| finding.kind != "passive_credential_leak_risk"),
        "http-only passive target should not trigger credential leak finding"
    );
}

#[test]
fn detects_ntlm_risk_for_passive_render_without_automatic_trigger() {
    let bytes = include_bytes!("fixtures/passive_font_only_unc.pdf");
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let fetch = report
        .findings
        .iter()
        .find(|finding| finding.kind == "passive_external_resource_fetch")
        .expect("passive_external_resource_fetch");
    assert_eq!(fetch.severity, Severity::Medium);
    assert_eq!(
        fetch.meta.get("passive.trigger_mode").map(std::string::String::as_str),
        Some("passive_render_or_indexer")
    );
    assert_eq!(
        fetch.meta.get("passive.ntlm_hash_leak_likelihood").map(std::string::String::as_str),
        Some("elevated")
    );
    assert_eq!(
        fetch.meta.get("passive.ntlm_hosts").map(std::string::String::as_str),
        Some("corp-fs.local")
    );
    assert_eq!(
        fetch.meta.get("passive.ntlm_shares").map(std::string::String::as_str),
        Some("fonts")
    );

    let credential = report
        .findings
        .iter()
        .find(|finding| finding.kind == "passive_credential_leak_risk")
        .expect("passive_credential_leak_risk");
    assert_eq!(credential.severity, Severity::Medium);
    let high_risk = report
        .findings
        .iter()
        .find(|finding| finding.kind == "resource.external_reference_high_risk_scheme")
        .expect("resource.external_reference_high_risk_scheme");
    assert_eq!(high_risk.severity, Severity::High);
}

#[test]
fn detects_obfuscated_external_targets() {
    let bytes = include_bytes!("fixtures/passive_obfuscated_http_uri.pdf");
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let obfuscated = report
        .findings
        .iter()
        .find(|finding| finding.kind == "resource.external_reference_obfuscated")
        .expect("resource.external_reference_obfuscated");
    assert_eq!(obfuscated.severity, Severity::Medium);
    assert_eq!(
        obfuscated.meta.get("resource.obfuscated_target_count").map(std::string::String::as_str),
        Some("1")
    );
}
