use sis_pdf_core::scan::{
    CorrelationOptions, FontAnalysisOptions, ImageAnalysisOptions, ProfileFormat, ScanOptions,
};

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
        image_analysis: ImageAnalysisOptions::default(),
        filter_allowlist: None,
        filter_allowlist_strict: false,
        profile: false,
        profile_format: ProfileFormat::Text,
        group_chains: true,
        correlation: CorrelationOptions::default(),
    }
}

#[test]
fn canonical_summary_counts_incremental_versions() {
    let bytes = include_bytes!("fixtures/filters/action_incremental.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan succeeds");
    let summary = report.structural_summary.expect("should include structural summary");
    assert_eq!(
        summary.canonical_object_count + summary.incremental_updates_removed,
        summary.object_count
    );
}

#[test]
fn emits_structural_complexity_summary_finding() {
    let bytes = include_bytes!("fixtures/filters/action_incremental.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan succeeds");
    let finding = report
        .findings
        .iter()
        .find(|item| item.kind == "structural_complexity_summary")
        .expect("structural complexity summary finding");
    assert_eq!(finding.severity, sis_pdf_core::model::Severity::Info);
    assert_eq!(finding.confidence, sis_pdf_core::model::Confidence::Certain);
    assert_eq!(finding.impact, sis_pdf_core::model::Impact::None);
    assert!(finding.meta.contains_key("trailer_count"));
    assert!(finding.meta.contains_key("startxref_count"));
    assert!(finding.meta.contains_key("revision_count"));
    assert!(finding.meta.contains_key("detached_objects"));
}
