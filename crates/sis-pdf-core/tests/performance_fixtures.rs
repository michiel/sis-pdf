use sis_pdf_core::runner::run_scan_with_detectors;
use sis_pdf_core::scan::{ScanOptions, FontAnalysisOptions, ImageAnalysisOptions, ProfileFormat};
use sis_pdf_detectors::default_detectors;
use std::path::PathBuf;

fn scan_fixture(name: &str) -> sis_pdf_core::report::Report {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures");
    path.push(name);
    let bytes = std::fs::read(&path).expect("fixture exists");
    let opts = ScanOptions {
        deep: true,
        max_decode_bytes: 32 * 1024 * 1024,
        max_total_decoded_bytes: 256 * 1024 * 1024,
        recover_xref: true,
        parallel: false,
        batch_parallel: false,
        diff_parser: true,
        max_objects: 500_000,
        max_recursion_depth: 64,
        fast: false,
        focus_trigger: None,
        focus_depth: 0,
        strict: false,
        strict_summary: false,
        ir: false,
        ml_config: None,
        font_analysis: FontAnalysisOptions::default(),
        image_analysis: ImageAnalysisOptions::default(),
        filter_allowlist: None,
        filter_allowlist_strict: false,
        profile: false,
        profile_format: ProfileFormat::Text,
        group_chains: true,
        correlation: Default::default(),
        yara_scope: None,
        no_js_ast: false,
        no_js_sandbox: false,
    };
    run_scan_with_detectors(&bytes, opts, &default_detectors()).expect("scan succeeds")
}

#[test]
fn vera_pdf_metadata_trailer_findings() {
    let report = scan_fixture("veraPDF-6-6-2-3-1-t01-fail-r.pdf");
    let kinds: Vec<&str> = report.findings.iter().map(|f| f.kind.as_str()).collect();
    for expected in [
        "parser_trailer_count_diff",
        "pdf.trailer_inconsistent",
        "label_mismatch_stream_type",
        "content_image_only_page",
    ] {
        assert!(kinds.contains(&expected), "{} missing", expected);
    }
}

#[test]
fn unknown_filter_bundle() {
    let report = scan_fixture("unknown-filter-4387ba48.pdf");
    let kinds: Vec<&str> = report.findings.iter().map(|f| f.kind.as_str()).collect();
    for expected in [
        "declared_filter_invalid",
        "embedded_payload_carved",
        "parser_trailer_count_diff",
        "pdf.trailer_inconsistent",
    ] {
        assert!(kinds.contains(&expected), "{} missing", expected);
    }
}

#[test]
fn qpdf_bad30_findings() {
    let report = scan_fixture("qpdf-bad30.pdf");
    let kinds: Vec<&str> = report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains(&"parser_trailer_count_diff"));
    assert!(kinds.contains(&"pdf.trailer_inconsistent"));
    assert!(kinds.contains(&"undeclared_compression_present"));
}
