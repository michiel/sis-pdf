mod common;
use common::default_scan_opts;

#[test]
fn detectors_flag_embedded_executable_magic() {
    let bytes =
        include_bytes!("../../sis-pdf-core/tests/fixtures/embedded/embedded_exe_cve_2018_4990.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(bytes, default_scan_opts(), &detectors)
            .expect("scan");

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == "embedded_executable_present"),
        "expected embedded_executable_present finding"
    );
    let embedded_file = report
        .findings
        .iter()
        .find(|f| f.kind == "embedded_file_present")
        .expect("embedded file finding");
    assert_eq!(
        embedded_file.meta.get("magic_type").map(String::as_str),
        Some("pe")
    );
}

#[test]
fn detectors_flag_embedded_double_extension() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/embedded_exe_double_ext.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(bytes, default_scan_opts(), &detectors)
            .expect("scan");

    let embedded_file = report
        .findings
        .iter()
        .find(|f| f.kind == "embedded_file_present")
        .expect("embedded file finding");
    assert_eq!(
        embedded_file
            .meta
            .get("embedded.double_extension")
            .map(String::as_str),
        Some("true")
    );
}

#[test]
fn detectors_flag_embedded_script_present() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/embedded_script.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(bytes, default_scan_opts(), &detectors)
            .expect("scan");

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == "embedded_script_present"),
        "expected embedded_script_present finding"
    );
}

#[test]
fn detectors_flag_embedded_encrypted_archive() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/embedded_zip_encrypted.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(bytes, default_scan_opts(), &detectors)
            .expect("scan");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "embedded_archive_encrypted")
        .expect("expected encrypted archive finding");
    assert_eq!(
        finding.meta.get("encrypted").map(String::as_str),
        Some("true")
    );
    assert!(
        finding
            .meta
            .get("hash.sha256")
            .map(|hash| hash.len())
            .unwrap_or(0)
            >= 64
    );
}
