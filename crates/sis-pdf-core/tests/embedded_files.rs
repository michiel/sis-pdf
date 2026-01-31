use std::io::Write;

use sha2::{Digest, Sha256};
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
    assert_eq!(finding.meta.get("hash.sha256").map(String::len), Some(64));
    assert_eq!(
        finding.meta.get("filename").map(String::as_str),
        Some("invoice.pdf.exe")
    );
    assert!(finding
        .meta
        .get("size_bytes")
        .and_then(|v| v.parse::<usize>().ok())
        .is_some());
    assert_eq!(
        finding.meta.get("magic_type").map(String::as_str),
        Some("pe")
    );
    assert_eq!(
        finding.meta.get("encrypted").map(String::as_str),
        Some("false")
    );

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == "embedded_executable_present"),
        "expected embedded_executable_present finding"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == "embedded_double_extension"),
        "expected embedded_double_extension finding"
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

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == "embedded_archive_encrypted"),
        "expected embedded_archive_encrypted finding"
    );
    assert_eq!(finding.meta.get("hash.sha256").map(String::len), Some(64));
    assert_eq!(
        finding.meta.get("encrypted").map(String::as_str),
        Some("true")
    );
}

#[test]
fn embedded_script_reports_magic() {
    let bytes = include_bytes!("fixtures/embedded_script.pdf");
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
        Some("script")
    );
    assert_eq!(finding.meta.get("hash.sha256").map(String::len), Some(64));
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == "embedded_script_present"),
        "expected embedded_script_present finding"
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
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == "launch_external_program"),
        "expected launch_external_program finding"
    );
    assert_eq!(
        finding.meta.get("launch.target_path").map(String::as_str),
        Some("calc.exe")
    );
    assert_eq!(
        finding.meta.get("launch.target_type").map(String::as_str),
        Some("external")
    );

    let external = report
        .findings
        .iter()
        .find(|f| f.kind == "launch_external_program")
        .expect("launch external finding");
    assert_eq!(
        external.meta.get("launch.target_path").map(String::as_str),
        Some("calc.exe")
    );
}

const LAUNCH_EMBEDDED_PAYLOAD: &[u8] = b"SPWN";

#[test]
fn launch_embedded_reports_correlation() {
    let bytes = build_launch_embedded_pdf();
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(&bytes, opts(), &detectors)
        .expect("scan should succeed");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "launch_embedded_file")
        .expect("expected launch_embedded_file");

    assert_eq!(
        finding.meta.get("launch.target_path").map(String::as_str),
        Some("payload.exe")
    );
    assert_eq!(
        finding.meta.get("launch.target_type").map(String::as_str),
        Some("embedded")
    );
    let expected_hash = sha256_hex_bytes(LAUNCH_EMBEDDED_PAYLOAD);
    assert_eq!(
        finding
            .meta
            .get("launch.embedded_file_hash")
            .map(String::as_str),
        Some(expected_hash.as_str())
    );
}

fn build_launch_embedded_pdf() -> Vec<u8> {
    let objects = vec![
        "<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>",
        "<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        "<< /Type /Page /Parent 2 0 R >>",
        "<< /Type /Action /S /Launch /F 5 0 R >>",
        "<< /Type /Filespec /F (payload.exe) /EF << /F 6 0 R >> >>",
        "<< /Type /EmbeddedFile /Length 4 >>stream\nSPWN\nendstream",
    ];
    build_pdf(&objects)
}

fn build_pdf(objects: &[&str]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"%PDF-1.4\n");
    let mut offsets = Vec::new();
    for (idx, body) in objects.iter().enumerate() {
        offsets.push(bytes.len());
        write!(&mut bytes, "{} 0 obj\n{}\nendobj\n", idx + 1, body).expect("write object");
    }
    let xref_start = bytes.len();
    write!(&mut bytes, "xref\n0 {}\n", objects.len() + 1).expect("write xref header");
    write!(&mut bytes, "0000000000 65535 f \n").expect("write xref free entry");
    for offset in offsets {
        write!(&mut bytes, "{:010} 00000 n \n", offset).expect("write xref entry");
    }
    write!(
        &mut bytes,
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
        objects.len() + 1,
        xref_start
    )
    .expect("write trailer");
    bytes
}

fn sha256_hex_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
