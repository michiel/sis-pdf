use sha2::{Digest, Sha256};
use sis_pdf_core::scan::{CorrelationOptions, FontAnalysisOptions, ProfileFormat, ScanOptions};
use std::fs;
use std::path::PathBuf;

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

fn finding_by_kind<'a>(
    report: &'a sis_pdf_core::report::Report,
    kind: &str,
) -> &'a sis_pdf_core::model::Finding {
    report
        .findings
        .iter()
        .find(|finding| finding.kind == kind)
        .unwrap_or_else(|| panic!("{kind} should be present"))
}

fn meta_as_u32(finding: &sis_pdf_core::model::Finding, key: &str) -> u32 {
    finding
        .meta
        .get(key)
        .unwrap_or_else(|| panic!("missing metadata key: {key}"))
        .parse::<u32>()
        .unwrap_or_else(|_| panic!("metadata key {key} should be numeric"))
}

fn corpus_captured_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/corpus_captured")
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

#[test]
fn corpus_captured_modern_openaction_staged_baseline_stays_stable() {
    let bytes = include_bytes!("fixtures/corpus_captured/modern-openaction-staged-38851573.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let renderer_divergence = finding_by_kind(&report, "renderer_behavior_divergence_known_path");
    assert_eq!(renderer_divergence.severity, sis_pdf_core::model::Severity::High);
    assert_eq!(
        renderer_divergence.confidence,
        sis_pdf_core::model::Confidence::Strong
    );

    let renderer_chain = finding_by_kind(&report, "renderer_behavior_exploitation_chain");
    assert_eq!(renderer_chain.severity, sis_pdf_core::model::Severity::High);
    assert_eq!(renderer_chain.confidence, sis_pdf_core::model::Confidence::Strong);

    let staged_payload = finding_by_kind(&report, "supply_chain_staged_payload");
    assert_eq!(staged_payload.severity, sis_pdf_core::model::Severity::High);
    assert_eq!(staged_payload.confidence, sis_pdf_core::model::Confidence::Probable);

    let file_probe = finding_by_kind(&report, "js_runtime_file_probe");
    assert_eq!(file_probe.severity, sis_pdf_core::model::Severity::High);
    assert_eq!(file_probe.confidence, sis_pdf_core::model::Confidence::Strong);
    assert_eq!(
        file_probe.meta.get("js.runtime.calls"),
        Some(&"exportDataObject".to_string())
    );

    let pdfjs = finding_by_kind(&report, "pdfjs_eval_path_risk");
    assert_eq!(pdfjs.severity, sis_pdf_core::model::Severity::Info);
    assert_eq!(pdfjs.confidence, sis_pdf_core::model::Confidence::Strong);
}

#[test]
fn corpus_captured_modern_renderer_revision_baseline_stays_stable() {
    let bytes = include_bytes!("fixtures/corpus_captured/modern-renderer-revision-8d42d425.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let renderer_divergence = finding_by_kind(&report, "renderer_behavior_divergence_known_path");
    assert_eq!(renderer_divergence.severity, sis_pdf_core::model::Severity::High);
    assert_eq!(
        renderer_divergence.confidence,
        sis_pdf_core::model::Confidence::Strong
    );

    let renderer_chain = finding_by_kind(&report, "renderer_behavior_exploitation_chain");
    assert_eq!(renderer_chain.severity, sis_pdf_core::model::Severity::High);
    assert_eq!(renderer_chain.confidence, sis_pdf_core::model::Confidence::Strong);

    let revision = finding_by_kind(&report, "revision_annotations_changed");
    assert_eq!(revision.severity, sis_pdf_core::model::Severity::Medium);
    assert_eq!(revision.confidence, sis_pdf_core::model::Confidence::Probable);
    assert!(meta_as_u32(revision, "revision.annotations_added_count") >= 20);

    let revision_score = finding_by_kind(&report, "revision_anomaly_scoring");
    assert_eq!(revision_score.severity, sis_pdf_core::model::Severity::Low);
    assert_eq!(
        revision_score.confidence,
        sis_pdf_core::model::Confidence::Tentative
    );
    assert!(meta_as_u32(revision_score, "revision.anomaly.max_score") >= 5);

    let pdfjs = finding_by_kind(&report, "pdfjs_eval_path_risk");
    assert_eq!(pdfjs.severity, sis_pdf_core::model::Severity::Info);
    assert_eq!(pdfjs.confidence, sis_pdf_core::model::Confidence::Strong);
}

#[test]
fn corpus_captured_modern_gated_supply_chain_baseline_stays_stable() {
    let bytes = include_bytes!("fixtures/corpus_captured/modern-gated-supplychain-9ff24c46.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let supply_chain = finding_by_kind(&report, "supply_chain_update_vector");
    assert_eq!(supply_chain.severity, sis_pdf_core::model::Severity::Medium);
    assert_eq!(
        supply_chain.confidence,
        sis_pdf_core::model::Confidence::Heuristic
    );

    let dormant = finding_by_kind(&report, "js_runtime_dormant_or_gated_execution");
    assert_eq!(dormant.severity, sis_pdf_core::model::Severity::Low);
    assert_eq!(dormant.confidence, sis_pdf_core::model::Confidence::Tentative);
    assert_eq!(
        dormant.meta.get("js.runtime.behavior.name"),
        Some(&"dormant_or_gated_execution".to_string())
    );
    assert_eq!(
        dormant.meta.get("js.runtime.profile_calls_ratio"),
        Some(&"0.00".to_string())
    );

    let pdfjs = finding_by_kind(&report, "pdfjs_eval_path_risk");
    assert_eq!(pdfjs.severity, sis_pdf_core::model::Severity::Info);
    assert_eq!(pdfjs.confidence, sis_pdf_core::model::Confidence::Strong);
}

#[test]
fn corpus_captured_manifest_integrity_stays_stable() {
    let manifest_path = corpus_captured_dir().join("manifest.json");
    let manifest_bytes =
        fs::read(&manifest_path).expect("corpus captured manifest should be readable");
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).expect("manifest should be valid JSON");
    let fixtures = manifest
        .get("fixtures")
        .and_then(serde_json::Value::as_array)
        .expect("manifest fixtures should be an array");

    for fixture in fixtures {
        let path = fixture
            .get("path")
            .and_then(serde_json::Value::as_str)
            .expect("fixture path should be present");
        let expected_sha = fixture
            .get("sha256")
            .and_then(serde_json::Value::as_str)
            .expect("fixture sha256 should be present");
        let fixture_path = corpus_captured_dir().join(path);
        let bytes = fs::read(&fixture_path)
            .unwrap_or_else(|_| panic!("fixture should be readable: {}", fixture_path.display()));
        let actual_sha = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(
            actual_sha, expected_sha,
            "fixture digest mismatch for {}",
            fixture_path.display()
        );
    }
}

#[test]
fn clean_google_docs_basic_does_not_raise_high_font_aggregate() {
    let bytes = include_bytes!("fixtures/clean-google-docs-basic.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    assert!(
        report.findings.iter().all(|finding| {
            !(finding.kind == "font.multiple_vuln_signals"
                && finding.severity == sis_pdf_core::model::Severity::High)
        }),
        "clean fixture should not emit high-severity font.multiple_vuln_signals"
    );
}

#[test]
fn corpus_captured_timeout_heavy_guardrail_metadata_stays_stable() {
    let bytes = include_bytes!("fixtures/corpus_captured/timeout-heavy-guardrail-c95a10a1.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let guardrail = finding_by_kind(&report, "content_first_guardrail_applied");
    assert_eq!(guardrail.severity, sis_pdf_core::model::Severity::Info);
    assert_eq!(guardrail.confidence, sis_pdf_core::model::Confidence::Strong);
    assert_eq!(
        guardrail.meta.get("content_first.guardrail_applied"),
        Some(&"true".to_string())
    );
    let guardrail_reasons = guardrail
        .meta
        .get("content_first.guardrail_reasons")
        .expect("guardrail reasons should be present");
    assert!(guardrail_reasons.contains("timeout_heavy_guardrail"));

    let truncated = finding_by_kind(&report, "content_first_analysis_truncated");
    assert_eq!(truncated.severity, sis_pdf_core::model::Severity::Medium);
    assert_eq!(truncated.confidence, sis_pdf_core::model::Confidence::Strong);
    let truncation_reason = truncated
        .meta
        .get("truncation_reason")
        .expect("truncation reason should be present");
    assert!(truncation_reason.contains("content_first_"));
    assert_eq!(
        truncated.meta.get("content_first.timeout_guardrail_applied"),
        Some(&"true".to_string())
    );
    let adaptive_reasons = truncated
        .meta
        .get("content_first.adaptive_budget_reasons")
        .expect("adaptive budget reasons should be present");
    assert!(adaptive_reasons.contains("timeout_heavy_guardrail"));
}
