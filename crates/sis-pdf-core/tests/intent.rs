use sis_pdf_core::scan::{CorrelationOptions, FontAnalysisOptions, ProfileFormat, ScanOptions};

fn base_opts() -> ScanOptions {
    ScanOptions {
        deep: false,
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

fn bucket_names(report: &sis_pdf_core::report::Report) -> Vec<String> {
    report
        .intent_summary
        .as_ref()
        .map(|s| s.buckets.iter().map(|b| format!("{:?}", b.bucket)).collect())
        .unwrap_or_default()
}

#[test]
fn intent_exfiltration_bucket() {
    let bytes = include_bytes!("fixtures/intent_exfil.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, base_opts(), &detectors)
        .expect("scan should succeed");
    let buckets = bucket_names(&report);
    assert!(buckets.iter().any(|b| b == "DataExfiltration"));
}

#[test]
fn intent_escape_bucket() {
    let bytes = include_bytes!("fixtures/intent_escape.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, base_opts(), &detectors)
        .expect("scan should succeed");
    let buckets = bucket_names(&report);
    assert!(buckets.iter().any(|b| b == "SandboxEscape"));
}

#[test]
fn intent_obfuscation_bucket() {
    let bytes = include_bytes!("fixtures/intent_obfuscation.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, base_opts(), &detectors)
        .expect("scan should succeed");
    let buckets = bucket_names(&report);
    assert!(buckets.iter().any(|b| b == "Obfuscation"));
}

#[test]
fn intent_phishing_bucket() {
    let bytes = include_bytes!("fixtures/html_text.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, base_opts(), &detectors)
        .expect("scan should succeed");
    let buckets = bucket_names(&report);
    assert!(buckets.iter().any(|b| b == "Phishing"));
}
