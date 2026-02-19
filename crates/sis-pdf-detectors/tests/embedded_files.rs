mod common;
use common::default_scan_opts;

fn build_pdf_with_objects(objects: &[&str]) -> Vec<u8> {
    let mut pdf = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.4\n");
    let mut offsets = vec![0usize; objects.len() + 1];
    for object in objects {
        let obj_num = object
            .split_whitespace()
            .next()
            .and_then(|token| token.parse::<usize>().ok())
            .expect("object number");
        if obj_num < offsets.len() {
            offsets[obj_num] = pdf.len();
        }
        pdf.extend_from_slice(object.as_bytes());
    }
    let start_xref = pdf.len();
    let size = offsets.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n", size).as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        if *offset == 0 {
            pdf.extend_from_slice(b"0000000000 00000 f \n");
        } else {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
    }
    pdf.extend_from_slice(
        format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n", size).as_bytes(),
    );
    pdf.extend_from_slice(start_xref.to_string().as_bytes());
    pdf.extend_from_slice(b"\n%%EOF\n");
    pdf
}

#[test]
fn detectors_flag_embedded_executable_magic() {
    let bytes =
        include_bytes!("../../sis-pdf-core/tests/fixtures/embedded/embedded_exe_cve_2018_4990.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(bytes, default_scan_opts(), &detectors)
            .expect("scan");

    assert!(
        report.findings.iter().any(|f| f.kind == "embedded_executable_present"),
        "expected embedded_executable_present finding"
    );
    let embedded_file = report
        .findings
        .iter()
        .find(|f| f.kind == "embedded_file_present")
        .expect("embedded file finding");
    assert_eq!(embedded_file.meta.get("magic_type").map(String::as_str), Some("pe"));
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
        embedded_file.meta.get("embedded.double_extension").map(String::as_str),
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
        report.findings.iter().any(|f| f.kind == "embedded_script_present"),
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
    assert_eq!(finding.meta.get("encrypted").map(String::as_str), Some("true"));
    assert!(finding.meta.get("hash.sha256").map(|hash| hash.len()).unwrap_or(0) >= 64);
}

#[test]
fn embedded_findings_include_blake3_metadata() {
    let bytes =
        include_bytes!("../../sis-pdf-core/tests/fixtures/embedded/embedded_exe_cve_2018_4990.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(bytes, default_scan_opts(), &detectors)
            .expect("scan");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "embedded_file_present")
        .expect("embedded file finding");
    assert_eq!(finding.meta.get("hash.blake3").map(|hash| hash.len()).unwrap_or(0), 64);
}

#[test]
fn detectors_flag_embedded_type_mismatch_with_filespec_relationship_context() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 7 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "4 0 obj\n<< /Type /Filespec /F (invoice.pdf) /EF << /F 6 0 R >> >>\nendobj\n",
        "6 0 obj\n<< /Type /EmbeddedFile /Subtype /application#2Fpdf /Length 20 >>\nstream\nMZPAYLOAD-EXECUTABLE\nendstream\nendobj\n",
        "7 0 obj\n<< /S /Launch /F 4 0 R >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");

    let mismatch = report
        .findings
        .iter()
        .find(|f| f.kind == "embedded_type_mismatch")
        .expect("expected embedded_type_mismatch");
    assert_eq!(
        mismatch.meta.get("embedded.relationship.filespec_present").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        mismatch.meta.get("embedded.relationship.binding").map(String::as_str),
        Some("filespec")
    );
    assert_eq!(mismatch.meta.get("embedded.filename").map(String::as_str), Some("invoice.pdf"));
    assert_eq!(
        mismatch.meta.get("embedded.extension_family").map(String::as_str),
        Some("document")
    );
    assert_eq!(mismatch.meta.get("embedded.magic_family").map(String::as_str), Some("active"));
    assert_eq!(mismatch.meta.get("embedded.family_mismatch").map(String::as_str), Some("true"));
    assert_eq!(
        mismatch.meta.get("embedded.mismatch_axes").map(String::as_str),
        Some("extension_vs_magic,subtype_vs_magic")
    );
}
