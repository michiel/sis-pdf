use sis_pdf_core::scan::{CorrelationOptions, FontAnalysisOptions, ProfileFormat, ScanOptions};

fn opts() -> ScanOptions {
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
        image_analysis: sis_pdf_core::scan::ImageAnalysisOptions::default(),
        filter_allowlist: None,
        filter_allowlist_strict: false,
        profile: false,
        profile_format: ProfileFormat::Text,
        group_chains: true,
        correlation: CorrelationOptions::default(),
    }
}

#[test]
fn detects_xfa_submit_and_sensitive_fields() {
    let bytes = include_bytes!("fixtures/xfa/xfa_submit_sensitive.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains("xfa_submit"));
    assert!(kinds.contains("xfa_sensitive_field"));
    assert!(kinds.contains("xfa_script_count_high"));
}

#[test]
fn detects_xfa_too_large() {
    let bytes = include_bytes!("fixtures/xfa/xfa_large.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains("xfa_too_large"));
}

#[test]
fn rejects_xfa_doctype_payloads() {
    let bytes = include_bytes!("fixtures/xfa/xfa_doctype_submit.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(!kinds.contains("xfa_submit"));
    assert!(!kinds.contains("xfa_sensitive_field"));
    assert!(!kinds.contains("xfa_script_count_high"));
}

#[test]
fn detects_xfa_execute_tags_as_scripts() {
    let bytes = include_bytes!("fixtures/xfa/xfa_execute_high.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains("xfa_script_count_high"));
}

#[test]
fn xfa_submit_finding_reports_metadata() {
    let bytes = include_bytes!("fixtures/xfa/xfa_submit_sensitive.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let finding =
        report.findings.iter().find(|f| f.kind == "xfa_submit").expect("xfa_submit finding");

    let script_count = finding
        .meta
        .get("xfa.script_count")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    assert!(script_count >= 1, "expected script count metadata");
    assert_eq!(
        finding.meta.get("xfa.submit.url").map(String::as_str),
        Some("https://example.com/submit")
    );
    let sensitive = finding.meta.get("xfa.sensitive_fields").expect("sensitive field metadata");
    assert!(sensitive.contains("user.password"), "expected password field in {}", sensitive);
}

#[test]
fn xfa_cve_2013_2729_reports_script_presence() {
    let bytes = include_bytes!("fixtures/xfa/xfa_cve_2013_2729.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    assert!(
        report.findings.iter().any(|f| f.kind == "xfa_script_present"),
        "expected xfa_script_present finding"
    );
}
