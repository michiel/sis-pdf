use sis_pdf_gui::analysis::{analyze, AnalysisError};

#[test]
fn rejects_oversized_file() {
    let big = vec![0u8; 50 * 1024 * 1024 + 1];
    let result = analyze(&big, "too_big.pdf");
    assert!(result.is_err());
    match result.unwrap_err() {
        AnalysisError::FileTooLarge { size, limit } => {
            assert_eq!(size, 50 * 1024 * 1024 + 1);
            assert_eq!(limit, 50 * 1024 * 1024);
        }
        other => panic!("Expected FileTooLarge, got: {:?}", other),
    }
}

#[test]
fn analyzes_fixture_with_findings() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/launch_action.pdf");
    let result = analyze(bytes, "launch_action.pdf").expect("analysis should succeed");
    assert_eq!(result.file_name, "launch_action.pdf");
    assert_eq!(result.file_size, bytes.len());
    assert!(
        !result.report.findings.is_empty(),
        "launch_action.pdf should produce findings"
    );
}

#[test]
fn analyzes_clean_pdf() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/clean-google-docs-basic.pdf");
    let result = analyze(bytes, "clean.pdf").expect("analysis should succeed");
    assert_eq!(result.file_name, "clean.pdf");
    // Clean PDF should still produce a report (may have info-level findings)
    assert!(result.report.summary.total >= 0);
}

#[test]
fn analyzes_minimal_synthetic_pdf() {
    let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n58\n%%EOF";
    let result = analyze(pdf, "minimal.pdf").expect("analysis should succeed");
    assert_eq!(result.file_size, pdf.len());
}
