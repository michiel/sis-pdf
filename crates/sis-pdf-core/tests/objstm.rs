use sis_pdf_core::report::Report;
use sis_pdf_core::runner::run_scan_with_detectors;
use sis_pdf_core::scan::{CorrelationOptions, FontAnalysisOptions, ProfileFormat, ScanOptions};

fn objstm_scan_opts(deep: bool) -> ScanOptions {
    ScanOptions {
        deep,
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

fn run_objstm_scan(deep: bool) -> Report {
    let bytes = include_bytes!("fixtures/objstm_js.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let opts = objstm_scan_opts(deep);
    run_scan_with_detectors(bytes, opts, &detectors).expect("scan should succeed")
}

#[test]
fn deep_objstm_surfaces_js() {
    let report = run_objstm_scan(true);
    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains("js_present"));
    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "objstm_embedded_summary")
        .expect("ObjStm summary finding expected");
    assert!(
        !finding.description.contains("Run the scan with `--deep`"),
        "Deep scans should not reiterate the deep-scan note"
    );
}

#[test]
fn objstm_summary_prompts_deep_for_shallow_scans() {
    let report = run_objstm_scan(false);
    let kinds: Vec<_> = report.findings.iter().map(|f| f.kind.as_str()).collect();
    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "objstm_embedded_summary")
        .unwrap_or_else(|| panic!("ObjStm summary finding expected; got {:?}", kinds));
    assert!(
        finding.description.contains("Run the scan with `--deep`"),
        "Shallow scans should include the deep-scan guidance note"
    );
}
