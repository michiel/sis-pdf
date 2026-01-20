use sis_pdf_core::scan::{FontAnalysisOptions, ProfileFormat, ScanOptions};

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
        profile: false,
        profile_format: ProfileFormat::Text,
        group_chains: true,
    }
}

#[test]
fn embedded_exe_reports_magic_and_double_extension() {
    let bytes = include_bytes!("fixtures/embedded_exe_double_ext.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "embedded_file_present")
        .expect("embedded file finding");

    assert_eq!(
        finding.meta.get("embedded.filename").map(String::as_str),
        Some("invoice.pdf.exe")
    );
    assert_eq!(
        finding.meta.get("embedded.magic").map(String::as_str),
        Some("pe")
    );
    assert_eq!(
        finding
            .meta
            .get("embedded.double_extension")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        finding.meta.get("embedded.sha256").map(String::len),
        Some(64)
    );
}

#[test]
fn embedded_zip_reports_encrypted_container() {
    let bytes = include_bytes!("fixtures/embedded_zip_encrypted.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "embedded_file_present")
        .expect("embedded file finding");

    assert_eq!(
        finding.meta.get("embedded.magic").map(String::as_str),
        Some("zip")
    );
    assert_eq!(
        finding
            .meta
            .get("embedded.encrypted_container")
            .map(String::as_str),
        Some("true")
    );
}

#[test]
fn launch_action_reports_payload_target() {
    let bytes = include_bytes!("fixtures/launch_action.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "launch_action_present")
        .expect("launch action finding");

    assert_eq!(
        finding.meta.get("payload.key").map(String::as_str),
        Some("/F")
    );
    assert!(
        finding
            .meta
            .get("payload.preview")
            .map(|v| v.contains("calc.exe"))
            .unwrap_or(false),
        "expected payload preview to include launch target"
    );
}
