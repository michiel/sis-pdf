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
fn detects_filter_order_invalid() {
    let bytes = include_bytes!("fixtures/filters/filter_invalid_order.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains("filter_order_invalid"));
}

#[test]
fn detects_filter_chain_unusual_and_duplicates() {
    let bytes = include_bytes!("fixtures/filters/filter_unusual_chain.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains("filter_chain_unusual"));
    assert!(kinds.contains("filter_combination_unusual"));
}

#[test]
fn allows_known_filter_chain() {
    let bytes = include_bytes!("fixtures/filters/filter_allowlisted.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(!kinds.contains("filter_chain_unusual"));
    assert!(!kinds.contains("filter_order_invalid"));
    assert!(!kinds.contains("filter_combination_unusual"));
}

#[test]
fn strict_mode_flags_allowlisted_chain() {
    let bytes = include_bytes!("fixtures/filters/filter_allowlisted.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let mut scan_opts = opts();
    scan_opts.filter_allowlist_strict = true;
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, scan_opts, &detectors)
        .expect("scan should succeed");

    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains("filter_chain_unusual"));
}

#[test]
fn detects_image_filter_with_compression() {
    let bytes = include_bytes!("fixtures/filters/filter_image_compression.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "filter_chain_unusual")
        .expect("filter_chain_unusual");
    assert_eq!(
        finding.meta.get("violation_type"),
        Some(&"image_with_compression".to_string())
    );
    assert_eq!(
        finding.meta.get("allowlist_match"),
        Some(&"true".to_string())
    );
}

#[test]
fn cve_2010_2883_filter_obfuscation_strict_mode() {
    let bytes = include_bytes!("fixtures/filters/filter_obfuscation_cve_2010_2883.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let mut scan_opts = opts();
    scan_opts.filter_allowlist_strict = true;
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, scan_opts, &detectors)
        .expect("scan should succeed");

    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains("filter_chain_unusual"));
}

#[test]
fn detects_jbig2_filter_chain_obfuscation() {
    let bytes = include_bytes!("fixtures/filters/jbig2_ascii_obfuscation.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "filter_chain_jbig2_obfuscation")
        .expect("filter_chain_jbig2_obfuscation");
    assert_eq!(
        finding.meta.get("jbig2.cves"),
        Some(&"CVE-2021-30860,CVE-2022-38171".to_string())
    );
    assert_eq!(
        finding.meta.get("violation_type"),
        Some(&"jbig2_obfuscation".to_string())
    );
}
