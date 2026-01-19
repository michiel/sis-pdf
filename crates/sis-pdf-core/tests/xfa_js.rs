use sis_pdf_core::scan::{FontAnalysisOptions, ProfileFormat, ScanOptions};

fn opts() -> ScanOptions {
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
        profile: false,
        profile_format: ProfileFormat::Text,
        group_chains: true,
    }
}

#[test]
fn detects_xfa_script_as_javascript_payload() {
    let bytes = include_bytes!("fixtures/xfa_script.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");
    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();

    assert!(kinds.contains("xfa_present"));
    assert!(kinds.contains("js_present"));

    let js_present = report.findings.iter().find(|f| f.kind == "js_present");
    assert!(js_present.is_some());
    assert_eq!(
        js_present
            .unwrap()
            .meta
            .get("js.source")
            .map(String::as_str),
        Some("xfa")
    );
}
