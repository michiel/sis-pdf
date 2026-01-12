use sis_pdf_core::scan::{FontAnalysisOptions, ScanOptions};

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
    }
}

#[test]
fn detects_content_first_phase1_findings() {
    let bytes = include_bytes!("fixtures/content_first_phase1.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");
    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();

    assert!(kinds.contains("label_mismatch_stream_type"));
    assert!(kinds.contains("declared_filter_invalid"));
    assert!(kinds.contains("undeclared_compression_present"));
    assert!(kinds.contains("embedded_payload_carved"));
    assert!(kinds.contains("nested_container_chain"));
    assert!(kinds.contains("vbscript_payload_present"));
    assert!(kinds.contains("powershell_payload_present"));
    assert!(kinds.contains("bash_payload_present"));
    assert!(kinds.contains("cmd_payload_present"));
    assert!(kinds.contains("applescript_payload_present"));
    assert!(kinds.contains("xfa_script_present"));
    assert!(kinds.contains("actionscript_present"));
    assert!(kinds.contains("swf_url_iocs"));

    let validation = report
        .findings
        .iter()
        .find(|f| f.kind == "content_validation_failed");
    assert!(validation.is_some());
    assert!(validation.unwrap().meta.get("validation.reason").is_some());
    assert!(report.findings.iter().any(|f| {
        f.meta
            .get("blob.origin")
            .map(|v| v == "embedded_file_name_tree")
            .unwrap_or(false)
    }));
    assert!(report.findings.iter().any(|f| {
        f.meta
            .get("blob.origin")
            .map(|v| v == "xfa_package")
            .unwrap_or(false)
    }));
}

#[test]
fn detects_phase5_shadow_findings() {
    let bytes = include_bytes!("fixtures/content_first_phase1.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let mut options = opts();
    options.deep = true;
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, options, &detectors)
        .expect("scan should succeed");
    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();

    assert!(kinds.contains("shadow_object_payload_divergence"));
    assert!(kinds.contains("parse_disagreement"));
}
