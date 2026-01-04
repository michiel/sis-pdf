use std::path::Path;
use sis_pdf_core::scan::ScanOptions;

fn base_opts() -> ScanOptions {
    ScanOptions {
        deep: false,
        max_decode_bytes: 8 * 1024 * 1024,
        max_total_decoded_bytes: 64 * 1024 * 1024,
        recover_xref: true,
        parallel: false,
        diff_parser: false,
        max_objects: 100_000,
        max_recursion_depth: 64,
        fast: false,
        focus_trigger: None,
        focus_depth: 0,
        yara_scope: None,
        strict: false,
        ml_config: None,
    }
}

#[test]
fn external_payload_sets_basic_coverage() {
    let payloads = Path::new("tmp/PayloadsAllThePDFs/pdf-payloads/payload1.pdf");
    let pentest = Path::new("tmp/pentest-pdf-collection/pdf_files/20250820_120506_js_annot.pdf");
    if !payloads.exists() || !pentest.exists() {
        return;
    }
    let detectors = sis_pdf_detectors::default_detectors();

    let bytes = std::fs::read(payloads).expect("read payload1");
    let report = sis_pdf_core::runner::run_scan_with_detectors(&bytes, base_opts(), &detectors)
        .expect("scan should succeed");
    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains("js_present"));

    let bytes = std::fs::read(pentest).expect("read js_annot");
    let report = sis_pdf_core::runner::run_scan_with_detectors(&bytes, base_opts(), &detectors)
        .expect("scan should succeed");
    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains("js_present"));
}
