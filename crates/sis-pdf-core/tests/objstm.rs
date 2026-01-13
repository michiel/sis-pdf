use sis_pdf_core::scan::{FontAnalysisOptions, ProfileFormat, ScanOptions};

#[test]
fn deep_objstm_surfaces_js() {
    let bytes = include_bytes!("fixtures/objstm_js.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let opts = ScanOptions {
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
        profile: false,
        profile_format: ProfileFormat::Text,
    };
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts, &detectors)
        .expect("scan should succeed");
    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains("js_present"));
}
