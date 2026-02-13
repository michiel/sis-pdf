use sis_pdf_core::scan::{CorrelationOptions, FontAnalysisOptions, ProfileFormat, ScanOptions};

fn opts() -> ScanOptions {
    ScanOptions {
        deep: true,
        max_decode_bytes: 8 * 1024 * 1024,
        max_total_decoded_bytes: 64 * 1024 * 1024,
        recover_xref: true,
        parallel: false,
        batch_parallel: false,
        diff_parser: true,
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

fn assert_hazard_presence(bytes: &[u8], expected_hazard: &str) {
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    assert!(
        report.findings.iter().any(|finding| finding.kind == "parser_diff_structural"),
        "expected parser_diff_structural finding"
    );
    assert!(
        report.findings.iter().all(|finding| finding.kind != "secondary_parser_failure"),
        "unexpected secondary_parser_failure for deterministic hazard fixture"
    );

    let parser_diff = report
        .findings
        .iter()
        .find(|finding| finding.kind == "parser_diff_structural")
        .expect("parser_diff_structural should be present");
    let hazards = parser_diff
        .meta
        .get("diff.missing_in_secondary_hazards")
        .expect("hazard summary should be present on parser diff");
    assert!(
        hazards.contains(expected_hazard),
        "expected hazard {expected_hazard} in parser diff metadata, got: {hazards}"
    );

    let baseline = report
        .findings
        .iter()
        .find(|finding| finding.kind == "secondary_parser_prevalence_baseline")
        .expect("secondary_parser_prevalence_baseline should be present");
    let hazard_counts = baseline
        .meta
        .get("secondary_parser.hazard_counts")
        .expect("hazard counts should be present");
    assert!(
        hazard_counts.contains(expected_hazard),
        "expected hazard {expected_hazard} in prevalence baseline, got: {hazard_counts}"
    );
}

#[test]
fn parser_diff_hazard_creation_date_trailing_timezone_token_is_detected() {
    let bytes =
        include_bytes!("fixtures/parser_diff_hazards/creation-date-trailing-timezone.pdf");
    assert_hazard_presence(bytes, "creation_date_trailing_timezone_token");
}

#[test]
fn parser_diff_hazard_unbalanced_literal_parentheses_is_detected() {
    let bytes = include_bytes!("fixtures/parser_diff_hazards/unbalanced-literal-parentheses.pdf");
    assert_hazard_presence(bytes, "unbalanced_literal_string_parentheses");
}
