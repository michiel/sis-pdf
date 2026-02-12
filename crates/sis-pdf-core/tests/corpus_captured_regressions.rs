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
fn corpus_captured_noisy_likely_noise_bucket_stays_stable() {
    let bytes = include_bytes!("fixtures/corpus_captured/noisy-likely-noise-693ea.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == "content_stream_anomaly")
        .expect("content_stream_anomaly should be present");
    assert_eq!(finding.severity, sis_pdf_core::model::Severity::Low);
    assert_eq!(finding.confidence, sis_pdf_core::model::Confidence::Tentative);
    assert_eq!(finding.meta.get("triage.noisy_class_bucket"), Some(&"likely_noise".to_string()));
    assert_eq!(finding.meta.get("triage.context_signals"), Some(&"none".to_string()));
}

#[test]
fn corpus_captured_noisy_correlated_high_risk_bucket_stays_stable() {
    let bytes = include_bytes!("fixtures/corpus_captured/noisy-correlated-highrisk-11606.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    assert!(
        report.findings.iter().any(|finding| {
            finding.kind == "label_mismatch_stream_type"
                && finding.severity == sis_pdf_core::model::Severity::High
                && finding.confidence == sis_pdf_core::model::Confidence::Strong
                && finding.meta.get("triage.noisy_class_bucket")
                    == Some(&"correlated_high_risk".to_string())
        }),
        "expected at least one high/strong correlated_high_risk label mismatch finding"
    );
    assert!(
        report.findings.iter().any(|finding| {
            finding.kind == "image.decode_skipped"
                && finding.severity == sis_pdf_core::model::Severity::Low
                && finding.confidence == sis_pdf_core::model::Confidence::Strong
                && finding.meta.get("triage.noisy_class_bucket")
                    == Some(&"correlated_high_risk".to_string())
        }),
        "expected at least one low/strong correlated_high_risk image decode skipped finding"
    );
}

#[test]
fn corpus_captured_secondary_parser_baseline_stays_stable() {
    let bytes = include_bytes!("fixtures/corpus_captured/secondary-invalid-trailer-6eb8.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let mut options = opts();
    options.diff_parser = true;
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, options, &detectors)
        .expect("scan should succeed");

    let secondary_failure = report
        .findings
        .iter()
        .find(|finding| finding.kind == "secondary_parser_failure")
        .expect("secondary_parser_failure should be present");
    assert_eq!(
        secondary_failure.meta.get("secondary_parser.error_class"),
        Some(&"invalid_file_trailer".to_string())
    );

    let baseline = report
        .findings
        .iter()
        .find(|finding| finding.kind == "secondary_parser_prevalence_baseline")
        .expect("secondary_parser_prevalence_baseline should be present");
    assert_eq!(baseline.severity, sis_pdf_core::model::Severity::Info);
    assert_eq!(baseline.confidence, sis_pdf_core::model::Confidence::Strong);
    assert_eq!(
        baseline.meta.get("secondary_parser.error_class_counts"),
        Some(&"invalid_file_trailer=1".to_string())
    );
    let candidates = baseline
        .meta
        .get("secondary_parser.remediation_candidates")
        .expect("remediation candidates should be present");
    assert!(candidates.contains("xref_trailer_recovery_guardrails"));
}
