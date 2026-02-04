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
fn detects_action_chain_complexity_and_automatic_trigger() {
    let bytes = include_bytes!("fixtures/action_chain_complex.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains("action_chain_complex"));
    assert!(kinds.contains("action_automatic_trigger"));
}

#[test]
fn detects_hidden_action_trigger() {
    let bytes = include_bytes!("fixtures/action_hidden_trigger.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains("action_hidden_trigger"));
}

#[test]
fn canonical_incremental_action_prefers_latest_definition() {
    let bytes = include_bytes!("fixtures/filters/action_incremental.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "action_automatic_trigger")
        .expect("action automatic trigger");
    assert_eq!(finding.meta.get("action.type"), Some(&"/GoToR".to_string()));
    assert_eq!(finding.meta.get("action.target"), Some(&"OpenAction -> action (7 0)".to_string()));
    assert_eq!(finding.meta.get("action.initiation"), Some(&"automatic".to_string()));
}
