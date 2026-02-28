use std::collections::HashSet;

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
        per_file_timeout_ms: None,
    }
}

fn fixture_path(rel: &str) -> std::path::PathBuf {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    root.join("tests/fixtures").join(rel)
}

fn scan_kinds(rel: &str) -> HashSet<String> {
    let bytes = std::fs::read(fixture_path(rel)).expect("fixture read");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(&bytes, opts(), &detectors)
        .expect("scan should succeed");
    report.findings.iter().map(|f| f.kind.clone()).collect()
}

#[test]
fn cve_2010_1240_launch_actions() {
    let kinds = scan_kinds("actions/launch_cve_2010_1240.pdf");
    assert!(kinds.contains("launch_action_present"));
    assert!(kinds.contains("launch_external_program"));
}

#[test]
fn cve_2018_4990_embedded_executable() {
    let kinds = scan_kinds("embedded/embedded_exe_cve_2018_4990.pdf");
    assert!(kinds.contains("embedded_file_present"));
    assert!(kinds.contains("embedded_executable_present"));
}

#[test]
fn cve_2013_2729_xfa_script() {
    let kinds = scan_kinds("xfa/xfa_cve_2013_2729.pdf");
    assert!(kinds.contains("xfa_present"));
    assert!(kinds.contains("xfa_script") || kinds.contains("xfa_script_present"));
}

#[test]
fn cve_2011_0611_swf() {
    let kinds = scan_kinds("media/swf_cve_2011_0611.pdf");
    assert!(kinds.contains("swf_embedded"));
}

#[test]
fn cve_2019_7089_encryption() {
    let kinds = scan_kinds("encryption/weak_encryption_cve_2019_7089.pdf");
    assert!(kinds.contains("encryption_key_short"));
}

#[test]
fn cve_2010_2883_filter_obfuscation() {
    let kinds = scan_kinds("filters/filter_obfuscation_cve_2010_2883.pdf");
    assert!(kinds.contains("declared_filter_invalid"));
}
