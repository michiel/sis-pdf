use sha2::{Digest, Sha256};
use sis_pdf_core::object_context::{
    build_object_context_index, get_object_context, ObjectChainRole,
};
use sis_pdf_core::scan::{CorrelationOptions, FontAnalysisOptions, ProfileFormat, ScanOptions};
use sis_pdf_core::taint::taint_from_findings;
use std::collections::HashSet;
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
        per_file_timeout_ms: None,
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

fn stage_set(report: &sis_pdf_core::report::Report) -> HashSet<String> {
    report.findings.iter().filter_map(|finding| finding.meta.get("chain.stage").cloned()).collect()
}

fn assert_no_image_font_structural_followup_findings(
    report: &sis_pdf_core::report::Report,
    fixture_label: &str,
) {
    let followup_kinds = [
        "resource.declared_but_unused",
        "resource.hidden_invocation_pattern",
        "resource.operator_usage_anomalous",
        "resource.inheritance_conflict_font",
        "resource.inheritance_conflict_xobject",
        "resource.inheritance_override_suspicious",
        "resource.override_outside_signature_scope",
        "image.override_outside_signature_scope",
        "font.override_outside_signature_scope",
        "image.inline_structure_filter_chain_inconsistent",
        "image.inline_decode_array_invalid",
        "image.inline_mask_inconsistent",
        "font.type3_charproc_complexity_high",
        "font.type3_charproc_resource_abuse",
        "font.type3_charproc_recursion_like_pattern",
        "font.cmap_range_overlap",
        "font.cmap_cardinality_anomalous",
        "font.cmap_subtype_inconsistent",
        "composite.decode_amplification_chain",
        "composite.resource_overrides_with_decoder_pressure",
    ];

    for kind in followup_kinds {
        assert!(
            report.findings.iter().all(|finding| finding.kind != kind),
            "{fixture_label} unexpectedly emitted follow-up finding kind: {kind}"
        );
    }
}

fn object_context_for(
    report: &sis_pdf_core::report::Report,
    obj: u32,
    gen: u16,
) -> sis_pdf_core::object_context::ObjectSecurityContext {
    let taint = taint_from_findings(&report.findings);
    let index = build_object_context_index(report, &taint);
    get_object_context(&index, obj, gen)
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

    if let Some(finding) =
        report.findings.iter().find(|finding| finding.kind == "content_stream_anomaly")
    {
        assert_eq!(finding.severity, sis_pdf_core::model::Severity::Low);
        assert_eq!(finding.confidence, sis_pdf_core::model::Confidence::Tentative);
        assert_eq!(
            finding.meta.get("triage.noisy_class_bucket"),
            Some(&"likely_noise".to_string())
        );
        assert_eq!(finding.meta.get("triage.context_signals"), Some(&"none".to_string()));
    } else {
        let header = finding_by_kind(&report, "missing_pdf_header");
        assert_eq!(header.severity, sis_pdf_core::model::Severity::Low);
        assert_eq!(header.confidence, sis_pdf_core::model::Confidence::Probable);
    }
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
    assert_eq!(renderer_divergence.confidence, sis_pdf_core::model::Confidence::Strong);

    let renderer_chain = finding_by_kind(&report, "renderer_behavior_exploitation_chain");
    assert_eq!(renderer_chain.severity, sis_pdf_core::model::Severity::High);
    assert_eq!(renderer_chain.confidence, sis_pdf_core::model::Confidence::Strong);

    let staged_payload = finding_by_kind(&report, "supply_chain_staged_payload");
    assert_eq!(staged_payload.severity, sis_pdf_core::model::Severity::High);
    assert_eq!(staged_payload.confidence, sis_pdf_core::model::Confidence::Probable);

    let file_probe = finding_by_kind(&report, "js_runtime_file_probe");
    assert_eq!(file_probe.severity, sis_pdf_core::model::Severity::High);
    assert_eq!(file_probe.confidence, sis_pdf_core::model::Confidence::Strong);
    assert_eq!(file_probe.meta.get("js.runtime.calls"), Some(&"exportDataObject".to_string()));

    let pdfjs = finding_by_kind(&report, "pdfjs_eval_path_risk");
    assert_eq!(pdfjs.severity, sis_pdf_core::model::Severity::Info);
    assert_eq!(pdfjs.confidence, sis_pdf_core::model::Confidence::Strong);

    let stages = stage_set(&report);
    assert!(stages.contains("decode"), "expected decode stage");
    assert!(stages.contains("render"), "expected render stage");
    assert!(stages.contains("execute"), "expected execute stage");
    assert!(
        report.chains.iter().any(|chain| chain.nodes.len() >= 4),
        "expected at least one distributed chain with >=4 nodes"
    );
    assert!(
        report.chains.iter().any(|chain| chain.notes.contains_key("exploit.outcomes")
            && chain.narrative.contains("Likely outcomes:")),
        "expected outcome-linked chain narrative for staged exploit chain fixture"
    );

    let object_context = object_context_for(&report, 9, 0);
    assert!(object_context.tainted, "expected object 9 0 to be tainted");
    assert!(object_context.taint_source, "expected object 9 0 to be a taint source");
    assert!(
        object_context.finding_count >= 3,
        "expected object 9 0 to aggregate at least three findings"
    );
    assert!(
        object_context.chains.iter().any(|membership| membership.role == ObjectChainRole::Action),
        "expected object 9 0 to carry action chain role membership"
    );
    assert!(
        object_context
            .taint_reasons
            .iter()
            .any(|reason| reason.reason.contains("JavaScript present")),
        "expected object 9 0 taint reasons to include JavaScript provenance"
    );
    assert!(
        object_context.top_evidence_offset.is_some(),
        "expected object 9 0 to retain evidence jump metadata"
    );

    assert_no_image_font_structural_followup_findings(&report, "modern-openaction-staged");
}

#[test]
fn corpus_captured_modern_renderer_revision_baseline_stays_stable() {
    let bytes = include_bytes!("fixtures/corpus_captured/modern-renderer-revision-8d42d425.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let renderer_divergence = finding_by_kind(&report, "renderer_behavior_divergence_known_path");
    assert_eq!(renderer_divergence.severity, sis_pdf_core::model::Severity::High);
    assert_eq!(renderer_divergence.confidence, sis_pdf_core::model::Confidence::Strong);

    let renderer_chain = finding_by_kind(&report, "renderer_behavior_exploitation_chain");
    assert_eq!(renderer_chain.severity, sis_pdf_core::model::Severity::High);
    assert_eq!(renderer_chain.confidence, sis_pdf_core::model::Confidence::Strong);

    let revision = finding_by_kind(&report, "revision_annotations_changed");
    assert_eq!(revision.severity, sis_pdf_core::model::Severity::Medium);
    assert_eq!(revision.confidence, sis_pdf_core::model::Confidence::Probable);
    assert!(meta_as_u32(revision, "revision.annotations_added_count") >= 20);

    let revision_score = finding_by_kind(&report, "revision_anomaly_scoring");
    assert_eq!(revision_score.severity, sis_pdf_core::model::Severity::Low);
    assert_eq!(revision_score.confidence, sis_pdf_core::model::Confidence::Tentative);
    assert!(meta_as_u32(revision_score, "revision.anomaly.max_score") >= 5);

    let pdfjs = finding_by_kind(&report, "pdfjs_eval_path_risk");
    assert_eq!(pdfjs.severity, sis_pdf_core::model::Severity::Info);
    assert_eq!(pdfjs.confidence, sis_pdf_core::model::Confidence::Strong);

    let stages = stage_set(&report);
    assert!(stages.contains("decode"), "expected decode stage");
    assert!(stages.contains("render"), "expected render stage");
    assert!(stages.contains("execute"), "expected execute stage");
    assert!(
        report.chains.iter().filter(|chain| !chain.narrative.trim().is_empty()).count() > 0,
        "expected non-empty chain narratives for revision fixture"
    );
    assert!(
        report.findings.iter().any(|finding| {
            finding.kind == "revision_annotations_changed"
                && finding.meta.get("revision.total").map(String::as_str) == Some("2")
        }),
        "expected explicit revision count metadata for revision-shadow fixture"
    );
    let object_context = object_context_for(&report, 14, 0);
    assert!(
        object_context.finding_count >= 2,
        "expected revision-shadow object 14 0 to aggregate multiple findings"
    );
    assert!(
        object_context.chains.len() >= 3,
        "expected revision-shadow object 14 0 to remain connected across multiple chain memberships"
    );
    // Object 14 0 should have at least one substantive chain role (Action, Payload, Trigger,
    // or Participant — not just a path node). Chain-building improvements may upgrade
    // Participant to Action when the finding is recognized as an action in a multi-finding chain.
    assert!(
        object_context.chains.iter().any(|membership| {
            matches!(
                membership.role,
                ObjectChainRole::Trigger
                    | ObjectChainRole::Action
                    | ObjectChainRole::Payload
                    | ObjectChainRole::Participant
            )
        }),
        "expected revision-shadow object 14 0 to have a substantive chain role (not just PathNode)"
    );
    assert_eq!(
        object_context.max_severity,
        Some(sis_pdf_core::model::Severity::High),
        "expected revision-shadow object 14 0 to preserve high-severity exploit context"
    );
    assert!(
        object_context.top_evidence_offset.is_some(),
        "expected revision-shadow object 14 0 to preserve evidence jump metadata"
    );

    assert_no_image_font_structural_followup_findings(&report, "modern-renderer-revision");
}

#[test]
fn corpus_captured_modern_gated_supply_chain_baseline_stays_stable() {
    let bytes = include_bytes!("fixtures/corpus_captured/modern-gated-supplychain-9ff24c46.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    // Stage 4.3 fix: content starting with "<<" (PDF dict / PostScript) is now correctly
    // rejected from JS analysis. The embedded IEEE .joboptions file and the JS runtime
    // sandbox signals it triggered were false positives — neither finding is emitted.
    assert!(
        report.findings.iter().all(|f| f.kind != "supply_chain_update_vector"),
        "supply_chain_update_vector must not be emitted for a PDF-dict embedded file"
    );
    assert!(
        report.findings.iter().all(|f| f.kind != "js_runtime_dormant_or_gated_execution"),
        "js_runtime_dormant_or_gated_execution must not be emitted for a PDF-dict embedded file"
    );

    // pdfjs_eval_path_risk is static-analysis only and is still correctly emitted
    let pdfjs = finding_by_kind(&report, "pdfjs_eval_path_risk");
    assert_eq!(pdfjs.severity, sis_pdf_core::model::Severity::Info);
    assert_eq!(pdfjs.confidence, sis_pdf_core::model::Confidence::Strong);

    // Object 76 0 is the embedded file container — still tainted via embedded_payload_carved
    // and similar findings, but without the (now-removed) JS false positives its chain
    // membership no longer includes an Action role and its max_confidence is Probable.
    let object_context = object_context_for(&report, 76, 0);
    assert!(object_context.tainted, "expected object 76 0 to be tainted");
    assert!(object_context.taint_source, "expected object 76 0 to be a taint source");
    assert_eq!(
        object_context.max_confidence,
        Some(sis_pdf_core::model::Confidence::Probable),
        "expected object 76 0 max_confidence to be Probable after JS false-positive removal"
    );
    assert!(
        object_context.chains.iter().any(|membership| membership.role == ObjectChainRole::Payload),
        "expected object 76 0 to preserve payload-role chain context"
    );
    assert!(!object_context.chains.is_empty(), "expected object 76 0 to have chain membership");
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
            actual_sha,
            expected_sha,
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
    assert_eq!(guardrail.meta.get("content_first.guardrail_applied"), Some(&"true".to_string()));
    let guardrail_reasons = guardrail
        .meta
        .get("content_first.guardrail_reasons")
        .expect("guardrail reasons should be present");
    assert!(guardrail_reasons.contains("timeout_heavy_guardrail"));

    let truncated = finding_by_kind(&report, "content_first_analysis_truncated");
    assert_eq!(truncated.severity, sis_pdf_core::model::Severity::Medium);
    assert_eq!(truncated.confidence, sis_pdf_core::model::Confidence::Strong);
    let truncation_reason =
        truncated.meta.get("truncation_reason").expect("truncation reason should be present");
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

#[test]
fn corpus_captured_structural_unused_resource_baseline_stays_stable() {
    let bytes = include_bytes!("fixtures/corpus_captured/structural-unused-resource-c4afbb69.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let finding = finding_by_kind(&report, "resource.declared_but_unused");
    assert_eq!(finding.severity, sis_pdf_core::model::Severity::Low);
    assert_eq!(finding.confidence, sis_pdf_core::model::Confidence::Probable);
    assert_eq!(finding.impact, sis_pdf_core::model::Impact::Low);
    assert_eq!(meta_as_u32(finding, "resource.unused_font_count"), 1);
    assert_eq!(meta_as_u32(finding, "resource.unused_xobject_count"), 0);
    assert_eq!(finding.meta.get("resource.unused_fonts"), Some(&"/F1".to_string()));
}

#[test]
fn corpus_captured_structural_inline_decode_invalid_baseline_stays_stable() {
    let bytes =
        include_bytes!("fixtures/corpus_captured/structural-inline-decode-invalid-eac2732d.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let finding = finding_by_kind(&report, "image.inline_decode_array_invalid");
    assert_eq!(finding.severity, sis_pdf_core::model::Severity::Low);
    assert_eq!(finding.confidence, sis_pdf_core::model::Confidence::Strong);
    assert_eq!(finding.impact, sis_pdf_core::model::Impact::Low);
    assert_eq!(meta_as_u32(finding, "inline_image.decode_count"), 3);
    assert_eq!(meta_as_u32(finding, "inline_image.filter_count"), 0);
}

#[test]
fn corpus_captured_structural_hidden_invocation_baseline_stays_stable() {
    let bytes =
        include_bytes!("fixtures/corpus_captured/structural-hidden-invocation-19004614.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let finding = finding_by_kind(&report, "resource.hidden_invocation_pattern");
    assert_eq!(finding.severity, sis_pdf_core::model::Severity::Medium);
    assert_eq!(finding.confidence, sis_pdf_core::model::Confidence::Probable);
    assert_eq!(finding.impact, sis_pdf_core::model::Impact::Medium);
    assert_eq!(meta_as_u32(finding, "resource.hidden_invocation_count"), 1);
}

#[test]
fn corpus_captured_structural_inheritance_conflict_font_baseline_stays_stable() {
    let bytes = include_bytes!(
        "fixtures/corpus_captured/structural-inheritance-conflict-font-4e033b8b.pdf"
    );
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let conflict = finding_by_kind(&report, "resource.inheritance_conflict_font");
    assert_eq!(conflict.severity, sis_pdf_core::model::Severity::Medium);
    assert_eq!(conflict.confidence, sis_pdf_core::model::Confidence::Strong);
    assert_eq!(conflict.impact, sis_pdf_core::model::Impact::Medium);
    assert_eq!(conflict.meta.get("resource.font_conflicts"), Some(&"/F1".to_string()));

    let override_finding = finding_by_kind(&report, "resource.inheritance_override_suspicious");
    assert_eq!(override_finding.severity, sis_pdf_core::model::Severity::Medium);
    assert_eq!(override_finding.confidence, sis_pdf_core::model::Confidence::Probable);
    assert_eq!(override_finding.impact, sis_pdf_core::model::Impact::Medium);
    assert_eq!(meta_as_u32(override_finding, "resource.override_conflict_count"), 1);
}

#[test]
fn corpus_captured_structural_type3_charproc_abuse_baseline_stays_stable() {
    let bytes =
        include_bytes!("fixtures/corpus_captured/structural-type3-charproc-abuse-f942b416.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let abuse = finding_by_kind(&report, "font.type3_charproc_resource_abuse");
    assert_eq!(abuse.severity, sis_pdf_core::model::Severity::High);
    assert_eq!(abuse.confidence, sis_pdf_core::model::Confidence::Probable);
    assert_eq!(abuse.impact, sis_pdf_core::model::Impact::High);
    assert_eq!(meta_as_u32(abuse, "font.type3.resource_ops"), 1);

    let recursion = finding_by_kind(&report, "font.type3_charproc_recursion_like_pattern");
    assert_eq!(recursion.severity, sis_pdf_core::model::Severity::Medium);
    assert_eq!(recursion.confidence, sis_pdf_core::model::Confidence::Tentative);
    assert_eq!(recursion.impact, sis_pdf_core::model::Impact::Medium);
    assert_eq!(meta_as_u32(recursion, "font.type3.q_depth_final"), 1);
}

#[test]
fn corpus_captured_structural_cmap_overlap_baseline_stays_stable() {
    let bytes = include_bytes!("fixtures/corpus_captured/structural-cmap-overlap-e51348dc.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let overlap = finding_by_kind(&report, "font.cmap_range_overlap");
    assert_eq!(overlap.severity, sis_pdf_core::model::Severity::Medium);
    assert_eq!(overlap.confidence, sis_pdf_core::model::Confidence::Strong);
    assert_eq!(overlap.impact, sis_pdf_core::model::Impact::Medium);
    assert_eq!(meta_as_u32(overlap, "font.cmap.range_count"), 2);

    let subtype = finding_by_kind(&report, "font.cmap_subtype_inconsistent");
    assert_eq!(subtype.severity, sis_pdf_core::model::Severity::Medium);
    assert_eq!(subtype.confidence, sis_pdf_core::model::Confidence::Strong);
    assert_eq!(subtype.impact, sis_pdf_core::model::Impact::Medium);
}

#[test]
fn corpus_captured_structural_inheritance_conflict_xobject_baseline_stays_stable() {
    let bytes = include_bytes!(
        "fixtures/corpus_captured/structural-inheritance-conflict-xobject-246bb53b.pdf"
    );
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let conflict = finding_by_kind(&report, "resource.inheritance_conflict_xobject");
    assert_eq!(conflict.severity, sis_pdf_core::model::Severity::Medium);
    assert_eq!(conflict.confidence, sis_pdf_core::model::Confidence::Strong);
    assert_eq!(conflict.impact, sis_pdf_core::model::Impact::Medium);
    assert_eq!(conflict.meta.get("resource.xobject_conflicts"), Some(&"/Im1".to_string()));
}

#[test]
fn corpus_captured_structural_inline_filter_mask_baseline_stays_stable() {
    let bytes =
        include_bytes!("fixtures/corpus_captured/structural-inline-filter-mask-97762d41.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let filter_chain = finding_by_kind(&report, "image.inline_structure_filter_chain_inconsistent");
    assert_eq!(filter_chain.severity, sis_pdf_core::model::Severity::Medium);
    assert_eq!(filter_chain.confidence, sis_pdf_core::model::Confidence::Strong);
    assert_eq!(filter_chain.impact, sis_pdf_core::model::Impact::Medium);
    assert_eq!(meta_as_u32(filter_chain, "inline_image.filter_count"), 2);
    assert_eq!(meta_as_u32(filter_chain, "inline_image.decode_parms_count"), 1);

    let mask = finding_by_kind(&report, "image.inline_mask_inconsistent");
    assert_eq!(mask.severity, sis_pdf_core::model::Severity::Medium);
    assert_eq!(mask.confidence, sis_pdf_core::model::Confidence::Probable);
    assert_eq!(mask.impact, sis_pdf_core::model::Impact::Medium);
}

#[test]
fn corpus_captured_structural_type3_complexity_baseline_stays_stable() {
    let bytes = include_bytes!("fixtures/corpus_captured/structural-type3-complexity-b4c499af.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let complexity = finding_by_kind(&report, "font.type3_charproc_complexity_high");
    assert_eq!(complexity.severity, sis_pdf_core::model::Severity::Medium);
    assert_eq!(complexity.confidence, sis_pdf_core::model::Confidence::Probable);
    assert_eq!(complexity.impact, sis_pdf_core::model::Impact::Medium);
    assert!(meta_as_u32(complexity, "font.type3.total_ops") >= 1200);
}

#[test]
fn corpus_captured_structural_cmap_cardinality_baseline_stays_stable() {
    let bytes = include_bytes!("fixtures/corpus_captured/structural-cmap-cardinality-53ab048f.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let cardinality = finding_by_kind(&report, "font.cmap_cardinality_anomalous");
    assert_eq!(cardinality.severity, sis_pdf_core::model::Severity::Medium);
    assert_eq!(cardinality.confidence, sis_pdf_core::model::Confidence::Probable);
    assert_eq!(cardinality.impact, sis_pdf_core::model::Impact::Medium);
    assert!(meta_as_u32(cardinality, "font.cmap.range_count") > 4096);
}

#[test]
fn corpus_captured_structural_signature_overrides_baseline_stays_stable() {
    let bytes =
        include_bytes!("fixtures/corpus_captured/structural-signature-overrides-5e736721.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let resource = finding_by_kind(&report, "resource.override_outside_signature_scope");
    assert_eq!(resource.severity, sis_pdf_core::model::Severity::High);
    assert_eq!(resource.confidence, sis_pdf_core::model::Confidence::Strong);
    assert_eq!(resource.impact, sis_pdf_core::model::Impact::High);
    assert_eq!(resource.meta.get("resource.signature_boundary"), Some(&"140".to_string()));

    let font = finding_by_kind(&report, "font.override_outside_signature_scope");
    assert_eq!(font.severity, sis_pdf_core::model::Severity::High);
    assert_eq!(font.confidence, sis_pdf_core::model::Confidence::Strong);
    assert_eq!(font.impact, sis_pdf_core::model::Impact::High);

    let image = finding_by_kind(&report, "image.override_outside_signature_scope");
    assert_eq!(image.severity, sis_pdf_core::model::Severity::High);
    assert_eq!(image.confidence, sis_pdf_core::model::Confidence::Strong);
    assert_eq!(image.impact, sis_pdf_core::model::Impact::High);
}

// ---------------------------------------------------------------------------
// Stage 5+7: New corpus fixture regression tests
// ---------------------------------------------------------------------------

fn scan_corpus_fixture(name: &str) -> sis_pdf_core::report::Report {
    let path = corpus_captured_dir().join(name);
    let bytes =
        fs::read(&path).unwrap_or_else(|_| panic!("corpus fixture not found: {}", path.display()));
    let detectors = sis_pdf_detectors::default_detectors();
    sis_pdf_core::runner::run_scan_with_detectors(&bytes, opts(), &detectors)
        .expect("scan should succeed")
}

fn assert_intent_bucket(report: &sis_pdf_core::report::Report, name: &str) {
    let buckets: Vec<String> = report
        .intent_summary
        .as_ref()
        .map(|s| s.buckets.iter().map(|b| format!("{:?}", b.bucket)).collect())
        .unwrap_or_default();
    assert!(
        buckets.iter().any(|b| b == name),
        "intent bucket {} not found in report; got: {:?}",
        name,
        buckets
    );
}

fn intent_bucket<'a>(
    report: &'a sis_pdf_core::report::Report,
    name: &str,
) -> &'a sis_pdf_core::intent::IntentBucketSummary {
    report
        .intent_summary
        .as_ref()
        .unwrap()
        .buckets
        .iter()
        .find(|b| format!("{:?}", b.bucket) == name)
        .unwrap_or_else(|| panic!("intent bucket {} not found", name))
}

fn assert_finding_kind_count(report: &sis_pdf_core::report::Report, kind: &str, expected: usize) {
    let count = report.findings.iter().filter(|f| f.kind == kind).count();
    assert_eq!(count, expected, "expected {} findings of kind {}, got {}", expected, kind, count);
}

fn assert_finding_kind_present(report: &sis_pdf_core::report::Report, kind: &str) {
    assert!(
        report.findings.iter().any(|f| f.kind == kind),
        "finding kind {} should be present; found: {:?}",
        kind,
        report.findings.iter().map(|f| f.kind.as_str()).collect::<Vec<_>>()
    );
}

#[test]
fn perf_hang_717_objects_completes_within_budget() {
    let start = std::time::Instant::now();
    let report = scan_corpus_fixture("perf-hang-717obj-fb87d8a7.pdf");
    let elapsed_ms = start.elapsed().as_millis();

    // Critical: was >292,000 ms before fix; must complete.
    // Budget is 120s (generous for debug+parallel). Release builds are <10s.
    assert!(
        elapsed_ms < 120_000,
        "drift_guard: 717-object PDF must scan in < 120,000 ms, took {} ms",
        elapsed_ms
    );
    assert!(!report.findings.is_empty(), "drift_guard: must produce findings");
}

#[test]
fn apt42_polyglot_core_detections_present() {
    let report = scan_corpus_fixture("apt42-polyglot-pdf-zip-pe-6648302d.pdf");

    assert_finding_kind_present(&report, "polyglot_signature_conflict");
    assert_finding_kind_present(&report, "embedded_payload_carved");

    let polyglot = finding_by_kind(&report, "polyglot_signature_conflict");
    assert_eq!(polyglot.severity, sis_pdf_core::model::Severity::High);
    assert_eq!(polyglot.confidence, sis_pdf_core::model::Confidence::Strong);

    // After stage 3 uplift: ExploitPrimitive intent should fire
    assert_intent_bucket(&report, "ExploitPrimitive");

    // After stage 4 uplift: verdict should be present
    let verdict = report.verdict.as_ref().expect("verdict must be present");
    assert!(
        verdict.label == "Malicious" || verdict.label == "Suspicious",
        "drift_guard: apt42 verdict must be Malicious or Suspicious, got: {}",
        verdict.label
    );

    // Chain singleton reduction: at least one multi-finding chain must exist
    assert!(
        report.chains.iter().any(|c| c.findings.len() > 1),
        "apt42 must have at least one multi-finding chain (embedded_payload_carved cluster)"
    );
    // At least one chain must have completeness > 0.0 and non-empty edges
    assert!(
        report.chains.iter().any(|c| c.chain_completeness > 0.0 && !c.edges.is_empty()),
        "apt42 must have at least one chain with chain_completeness > 0.0 and edges"
    );
}

#[test]
fn booking_js_phishing_core_detections_present() {
    let report = scan_corpus_fixture("booking-js-phishing-379b41e3.pdf");

    assert_finding_kind_present(&report, "js_present");

    // Verdict must be present
    let verdict = report.verdict.as_ref().expect("verdict must be present");
    assert!(
        verdict.label == "Malicious" || verdict.label == "Suspicious",
        "drift_guard: booking phishing verdict must be Suspicious or Malicious, got: {}",
        verdict.label
    );

    // At least one chain must have completeness > 0.0 and non-empty edges (the JS action chain)
    assert!(
        report.chains.iter().any(|c| c.chain_completeness > 0.0 && !c.edges.is_empty()),
        "booking phishing must have at least one chain with chain_completeness > 0.0 and edges"
    );
}

#[test]
fn romcom_embedded_payload_detections_present() {
    let report = scan_corpus_fixture("romcom-embedded-payload-a99903.pdf");

    assert_finding_kind_present(&report, "embedded_payload_carved");

    // Verdict must be present
    assert!(report.verdict.is_some(), "verdict must be present");
}

#[test]
fn font_heavy_objstm_has_font_findings() {
    let start = std::time::Instant::now();
    let report = scan_corpus_fixture("font-heavy-objstm-5bb77b57.pdf");
    let elapsed_ms = start.elapsed().as_millis();

    // Performance guard (debug build budget)
    assert!(
        elapsed_ms < 60_000,
        "drift_guard: font-heavy scan must complete in < 60s, took {}ms",
        elapsed_ms
    );

    // Font findings must be present
    let font_count = report.findings.iter().filter(|f| f.kind.starts_with("font.")).count();
    assert!(font_count >= 1, "drift_guard: font-heavy PDF must have font findings");

    // Verdict must be present
    assert!(report.verdict.is_some(), "verdict must be present");

    // Chain labels should be non-empty
    for chain in &report.chains {
        assert!(!chain.label.is_empty(), "all chains must have non-empty labels");
    }
}

#[test]
fn encoded_uri_payload_has_network_intents() {
    let report = scan_corpus_fixture("encoded-uri-payload-b710ae59.pdf");
    // After scanning, we should have some findings
    assert!(!report.findings.is_empty(), "encoded URI payload should have findings");
    // Verdict must be present
    assert!(report.verdict.is_some(), "verdict must be present");
}

#[test]
fn all_chains_have_label_and_severity() {
    // Test that the chain label/severity derivation works on a real fixture
    let report = scan_corpus_fixture("booking-js-phishing-379b41e3.pdf");
    for chain in &report.chains {
        assert!(!chain.label.is_empty(), "chain {} must have non-empty label", chain.id);
        assert!(!chain.severity.is_empty(), "chain {} must have non-empty severity", chain.id);
    }
}

#[test]
fn report_verdict_field_present_on_all_fixtures() {
    // Verify verdict is populated for a basic fixture
    let bytes = include_bytes!("fixtures/corpus_captured/noisy-likely-noise-693ea.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");
    assert!(report.verdict.is_some(), "verdict must be present on every scan");
    let verdict = report.verdict.unwrap();
    assert!(
        ["Malicious", "Suspicious", "Anomalous", "Clean"].contains(&verdict.label.as_str()),
        "unexpected verdict label: {}",
        verdict.label
    );
}

#[test]
fn cov1_colocated_decode_skipped_preserved_in_supply_chain_fixture() {
    // modern-gated-supplychain has 21 image.decode_skipped findings. Each is
    // co-located with an image.colour_space_invalid finding on the same object.
    // COV-1 suppression should KEEP these (they provide context for the anomaly)
    // and NOT emit a suppression summary.
    let bytes = include_bytes!("fixtures/corpus_captured/modern-gated-supplychain-9ff24c46.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    // No suppression summary should be emitted (all are co-located with anomalies).
    let suppressed_summaries: Vec<_> = report
        .findings
        .iter()
        .filter(|f| {
            f.kind == "image.decode_skipped" && f.meta.get("image.suppress_reason").is_some()
        })
        .collect();
    assert!(
        suppressed_summaries.is_empty(),
        "no suppression summary should be emitted when all decode_skipped are co-located"
    );

    // All co-located decode_skipped findings should be present.
    let decode_skipped_count =
        report.findings.iter().filter(|f| f.kind == "image.decode_skipped").count();
    assert!(
        decode_skipped_count >= 10,
        "expected >= 10 co-located decode_skipped to be preserved, got {}",
        decode_skipped_count
    );
}

#[test]
fn cov6_entropy_clustering_fires_on_apt42_polyglot_deep() {
    // apt42 is a PDF+ZIP polyglot with PE executables — many high-entropy stream objects.
    // With deep=true the entropy_clustering detector (Cost::Expensive) should fire.
    let report = scan_corpus_fixture("apt42-polyglot-pdf-zip-pe-6648302d.pdf");
    assert_finding_kind_present(&report, "entropy_high_object_ratio");
    let finding = finding_by_kind(&report, "entropy_high_object_ratio");
    assert_eq!(finding.severity, sis_pdf_core::model::Severity::Low);
    assert_eq!(finding.confidence, sis_pdf_core::model::Confidence::Probable);
    assert!(finding.meta.get("entropy.ratio").is_some(), "expected entropy.ratio metadata");
}

// ---------------------------------------------------------------------------
// Fog-netlify phishing + decompression-bomb DoS fixtures
// ---------------------------------------------------------------------------

#[test]
fn fog_netlify_phishing_detections_present() {
    // Fog campaign PDF: phishing lure linking to netlify-hosted ZIP with "/Pay" path.
    // Same file as secondary-invalid-trailer-6eb8.pdf (multi-purpose fixture).
    let bytes = include_bytes!("fixtures/corpus_captured/secondary-invalid-trailer-6eb8.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    // URI action targeting netlify /Pay path
    let uri_action = finding_by_kind(&report, "action_remote_target_suspicious");
    assert_eq!(uri_action.severity, sis_pdf_core::model::Severity::Low);
    assert_eq!(uri_action.confidence, sis_pdf_core::model::Confidence::Probable);
    let target = uri_action.meta.get("action.target").expect("action.target present");
    assert!(target.contains("netlify.app"), "expected netlify.app in action target, got: {target}");
    assert!(
        target.to_lowercase().contains("/pay"),
        "expected /Pay path in action target, got: {target}"
    );

    // Passive external resource fetch also detected
    assert_finding_kind_present(&report, "passive_external_resource_fetch");
    let passive = finding_by_kind(&report, "passive_external_resource_fetch");
    let passive_targets = passive
        .meta
        .get("passive.external_targets_normalised")
        .expect("passive.external_targets_normalised present");
    assert!(passive_targets.contains("netlify.app"), "expected netlify.app in passive targets");

    // URI classification summary flags suspicious extension (.zip)
    let uri_summary = finding_by_kind(&report, "uri_classification_summary");
    assert_eq!(
        uri_summary.meta.get("uri.has_suspicious_ext").map(String::as_str),
        Some("true"),
        "expected uri.has_suspicious_ext=true"
    );

    // Verdict must be Malicious or Suspicious
    let verdict = report.verdict.as_ref().expect("verdict present");
    assert!(
        verdict.label == "Malicious" || verdict.label == "Suspicious",
        "drift_guard: fog-netlify verdict must be Malicious or Suspicious, got: {}",
        verdict.label
    );
}

#[test]
fn decompression_bomb_dos_detections_present() {
    // Decompression bomb: 485:1 ratio stream, causes parser/memory exhaustion.
    // Same file as noisy-correlated-highrisk-11606.pdf (multi-purpose fixture).
    let bytes = include_bytes!("fixtures/corpus_captured/noisy-correlated-highrisk-11606.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    // Use 64MB per-stream limit so the full 485:1 bomb stream (~26MB output) can be
    // measured accurately. opts() caps at 8MB which would cap the ratio at ~128.
    // Also raise max_total_decoded_bytes: reserve_budget() reserves max_decode_bytes
    // upfront, so total must be >> max_decode_bytes or every second stream fails.
    let mut scan_opts = opts();
    scan_opts.max_decode_bytes = 64 * 1024 * 1024;
    scan_opts.max_total_decoded_bytes = 512 * 1024 * 1024;
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, scan_opts, &detectors)
        .expect("scan should succeed");

    // High-ratio decompression stream (485:1)
    let decomp = report
        .findings
        .iter()
        .find(|f| {
            f.kind == "decompression_ratio_suspicious"
                && f.meta
                    .get("decode.ratio")
                    .and_then(|v| v.parse::<f64>().ok())
                    .map(|r| r > 400.0)
                    .unwrap_or(false)
        })
        .expect("decompression_ratio_suspicious with ratio > 400 must be present");
    // Severity may be High (fast solo run) or Critical (slow parallel run: detection exceeds
    // 5s threshold which triggers parser_resource_exhaustion + decode_structural_exhaustion_chain
    // escalation). Both are valid high-severity outcomes for this decompression bomb.
    assert!(
        decomp.severity == sis_pdf_core::model::Severity::High
            || decomp.severity == sis_pdf_core::model::Severity::Critical,
        "expected High or Critical severity, got {:?}",
        decomp.severity
    );
    assert!(
        decomp.confidence == sis_pdf_core::model::Confidence::Probable
            || decomp.confidence == sis_pdf_core::model::Confidence::Strong,
        "expected Probable or Strong confidence, got {:?}",
        decomp.confidence
    );
    let ratio: f64 = decomp
        .meta
        .get("decode.ratio")
        .expect("decode.ratio present")
        .parse()
        .expect("decode.ratio numeric");
    assert!(ratio > 480.0, "expected ratio > 480, got {ratio}");

    // DenialOfService intent bucket must fire
    assert_intent_bucket(&report, "DenialOfService");
    let dos_bucket = intent_bucket(&report, "DenialOfService");
    assert!(dos_bucket.score > 0, "DenialOfService bucket score must be > 0");

    // Verdict must be Malicious or Suspicious
    let verdict = report.verdict.as_ref().expect("verdict present");
    assert!(
        verdict.label == "Malicious" || verdict.label == "Suspicious",
        "drift_guard: decompression bomb verdict must be Malicious or Suspicious, got: {}",
        verdict.label
    );
}

#[test]
fn cov6_entropy_clustering_absent_without_deep() {
    // With deep=false the entropy_clustering detector is Cost::Expensive and should be skipped.
    let bytes = fs::read(corpus_captured_dir().join("apt42-polyglot-pdf-zip-pe-6648302d.pdf"))
        .expect("fixture exists");
    let detectors = sis_pdf_detectors::default_detectors();
    let mut no_deep_opts = opts();
    no_deep_opts.deep = false;
    let report = sis_pdf_core::runner::run_scan_with_detectors(&bytes, no_deep_opts, &detectors)
        .expect("scan should succeed");
    assert!(
        report.findings.iter().all(|f| f.kind != "entropy_high_object_ratio"),
        "entropy_high_object_ratio must not fire when deep=false"
    );
}

#[test]
fn jbig2_zeroclick_cve2021_30860_detections_present() {
    // JBIG2 zero-click exploit (CVE-2021-30860 / FORCEDENTRY pattern).
    // Five JBIG2 XObject streams with extreme full-page strip dimensions targeting the image
    // codec decoder. Dual-use: invisible text overlays provide phishing context.
    let report = scan_corpus_fixture("jbig2-zeroclick-cve2021-30860-1c8abb3a.pdf");

    // CVE-2021-30860 pattern: extreme JBIG2 strip dimensions (zero-click trigger)
    let zero_click_count =
        report.findings.iter().filter(|f| f.kind == "image.zero_click_jbig2").count();
    assert!(
        zero_click_count >= 5,
        "drift_guard: expected >= 5 image.zero_click_jbig2 findings, got {zero_click_count}"
    );

    // All zero-click findings must be High/Strong
    for f in report.findings.iter().filter(|f| f.kind == "image.zero_click_jbig2") {
        assert_eq!(
            f.severity,
            sis_pdf_core::model::Severity::High,
            "drift_guard: image.zero_click_jbig2 must be High severity"
        );
        assert_eq!(
            f.confidence,
            sis_pdf_core::model::Confidence::Strong,
            "drift_guard: image.zero_click_jbig2 must be Strong confidence"
        );
        assert_eq!(
            f.meta.get("cve").map(String::as_str),
            Some("CVE-2021-30860"),
            "drift_guard: image.zero_click_jbig2 must carry CVE-2021-30860 tag"
        );
    }

    // Decoder risk findings (JBIG2Decode filter is High risk)
    let decoder_risk_count =
        report.findings.iter().filter(|f| f.kind == "decoder_risk_present").count();
    assert!(
        decoder_risk_count >= 5,
        "drift_guard: expected >= 5 decoder_risk_present findings, got {decoder_risk_count}"
    );

    // ExploitPrimitive intent must fire (decoder risks + carved payload)
    assert_intent_bucket(&report, "ExploitPrimitive");
    let exploit = intent_bucket(&report, "ExploitPrimitive");
    assert!(
        exploit.score >= 10,
        "drift_guard: ExploitPrimitive score must be >= 10, got {}",
        exploit.score
    );

    // Phishing intent must fire (invisible text overlays on exploit pages)
    assert_intent_bucket(&report, "Phishing");

    // Verdict must be Malicious
    let verdict = report.verdict.as_ref().expect("verdict present");
    assert_eq!(
        verdict.label, "Malicious",
        "drift_guard: JBIG2 zero-click verdict must be Malicious, got: {}",
        verdict.label
    );
}

#[test]
fn mshta_italian_sandbox_escape_detections_present() {
    // mshta-based sandbox escape with Italian-language social engineering lure.
    // Attack chain: PDF open -> Italian JS alert -> OpenAction -> Launch(mshta) ->
    // PowerShell -ep Bypass -> IEX(IrM blogspot.com C2 URL).
    let report = scan_corpus_fixture("mshta-italian-sandbox-escape-ef6dff9b.pdf");

    // Launch action targeting mshta (sandbox escape primitive)
    let launch = report
        .findings
        .iter()
        .find(|f| f.kind == "launch_action_present")
        .expect("drift_guard: launch_action_present must be present");
    assert_eq!(
        launch.severity,
        sis_pdf_core::model::Severity::High,
        "drift_guard: launch_action_present must be High severity"
    );
    assert_eq!(
        launch.meta.get("launch.target_path").map(String::as_str),
        Some("mshta"),
        "drift_guard: launch target must be mshta"
    );

    // External program launch (mshta with javascript: URL scheme)
    assert_finding_kind_present(&report, "launch_external_program");

    // PowerShell payload indicators embedded in the mshta parameter
    assert_finding_kind_present(&report, "powershell_payload_present");

    // Italian social engineering alert
    let js_lure = report
        .findings
        .iter()
        .find(|f| f.kind == "js_intent_user_interaction")
        .expect("drift_guard: js_intent_user_interaction must be present");
    assert_eq!(
        js_lure.severity,
        sis_pdf_core::model::Severity::High,
        "drift_guard: js_intent_user_interaction must be High severity"
    );

    // SandboxEscape intent must fire at meaningful score
    assert_intent_bucket(&report, "SandboxEscape");
    let escape = intent_bucket(&report, "SandboxEscape");
    assert!(
        escape.score >= 6,
        "drift_guard: SandboxEscape score must be >= 6, got {}",
        escape.score
    );

    // Verdict must be Malicious
    let verdict = report.verdict.as_ref().expect("verdict present");
    assert_eq!(
        verdict.label, "Malicious",
        "drift_guard: mshta sandbox escape verdict must be Malicious, got: {}",
        verdict.label
    );
}

#[test]
fn url_bombing_25_annotation_detections_present() {
    // URL bombing via mass annotation injection: 25 link annotations pointing to 25 distinct
    // external domains. Image-only content hides the annotation layer. DataExfiltration intent
    // fires at score=50 (25 URI findings x2 weight each).
    let report = scan_corpus_fixture("url-bombing-25-annotation-9f4e98d1.pdf");

    // Mass annotation injection: at least 20 annotation_action_chain findings
    let annotation_count =
        report.findings.iter().filter(|f| f.kind == "annotation_action_chain").count();
    assert!(
        annotation_count >= 20,
        "drift_guard: expected >= 20 annotation_action_chain findings (25 expected), got {annotation_count}"
    );

    // DataExfiltration intent must fire at high score (25 URIs * 2 = 50)
    assert_intent_bucket(&report, "DataExfiltration");
    let exfil = intent_bucket(&report, "DataExfiltration");
    assert!(
        exfil.score >= 40,
        "drift_guard: DataExfiltration score must be >= 40 (URL bomb), got {}",
        exfil.score
    );

    // Verdict must be Suspicious or Malicious
    let verdict = report.verdict.as_ref().expect("verdict present");
    assert!(
        verdict.label == "Suspicious" || verdict.label == "Malicious",
        "drift_guard: URL bombing verdict must be Suspicious or Malicious, got: {}",
        verdict.label
    );
}

#[test]
fn decode_budget_exhaustion_fixture_stays_stable() {
    let report = scan_corpus_fixture("decode-budget-exhaustion-c2d0d7e2.pdf");

    // decode_budget_exceeded currently appears as telemetry warnings rather than
    // a stable report finding; guard on durable high-volume structural/DoS signals.
    let mismatch_count =
        report.findings.iter().filter(|f| f.kind == "label_mismatch_stream_type").count();
    assert!(
        mismatch_count >= 20,
        "drift_guard: expected >= 20 label_mismatch_stream_type findings, got {}",
        mismatch_count
    );

    assert_finding_kind_present(&report, "object_reference_depth_high");
    assert_finding_kind_present(&report, "parser_resource_exhaustion");
    assert_intent_bucket(&report, "DenialOfService");

    let verdict = report.verdict.as_ref().expect("verdict present");
    assert!(
        verdict.label == "Malicious" || verdict.label == "Suspicious",
        "drift_guard: decode-budget fixture verdict must be Malicious or Suspicious, got: {}",
        verdict.label
    );
}

#[test]
fn decompression_bomb_font_flood_fixture_stays_stable() {
    let report = scan_corpus_fixture("decompression-bomb-font-flood-b509f6c9.pdf");

    let bomb_count =
        report.findings.iter().filter(|f| f.kind == "decompression_ratio_suspicious").count();
    assert!(
        bomb_count >= 4,
        "drift_guard: expected >= 4 decompression_ratio_suspicious findings, got {}",
        bomb_count
    );
    assert_finding_kind_present(&report, "parser_resource_exhaustion");
    assert_intent_bucket(&report, "DenialOfService");
    let dos = intent_bucket(&report, "DenialOfService");
    assert!(dos.score >= 20, "drift_guard: DenialOfService score must be >= 20, got {}", dos.score);
}

#[test]
fn connectwise_filter_obfuscation_fixture_stays_stable() {
    let report = scan_corpus_fixture("connectwise-filter-obfuscation-9ab20ec2.pdf");

    let annotation_count =
        report.findings.iter().filter(|f| f.kind == "annotation_action_chain").count();
    assert!(
        annotation_count >= 15,
        "drift_guard: expected >= 15 annotation_action_chain findings, got {}",
        annotation_count
    );

    let uri_summary_count =
        report.findings.iter().filter(|f| f.kind == "uri_classification_summary").count();
    assert!(
        uri_summary_count >= 15,
        "drift_guard: expected >= 15 uri_classification_summary findings, got {}",
        uri_summary_count
    );

    let cycle_count =
        report.findings.iter().filter(|f| f.kind == "object_reference_cycle").count();
    assert!(
        cycle_count >= 20,
        "drift_guard: expected >= 20 object_reference_cycle findings, got {}",
        cycle_count
    );

    assert_intent_bucket(&report, "DataExfiltration");
    let exfil = intent_bucket(&report, "DataExfiltration");
    assert!(
        exfil.score >= 30,
        "drift_guard: DataExfiltration score must be >= 30, got {}",
        exfil.score
    );
}
