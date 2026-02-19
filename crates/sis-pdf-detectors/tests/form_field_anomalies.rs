mod common;

use common::default_scan_opts;
use sis_pdf_detectors::default_detectors;

fn build_pdf(objects: &[String], size: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"%PDF-1.4\n");
    let mut offsets = vec![0usize; size];
    for object in objects {
        let id = object
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        if id < offsets.len() {
            offsets[id] = out.len();
        }
        out.extend_from_slice(object.as_bytes());
    }
    let startxref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", size).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n", size).as_bytes(),
    );
    out.extend_from_slice(startxref.to_string().as_bytes());
    out.extend_from_slice(b"\n%%EOF\n");
    out
}

#[test]
fn detects_oversized_fragmented_form_field_value() {
    let chunk_a = "A".repeat(2500);
    let chunk_b = "B".repeat(2500);
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [6 0 R] >>\nendobj\n".to_string(),
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n".to_string(),
        "6 0 obj\n<< /Type /Annot /Subtype /Widget /FT /Tx /T (notes) /V [7 0 R 8 0 R] >>\nendobj\n"
            .to_string(),
        format!("7 0 obj\n({chunk_a})\nendobj\n"),
        format!("8 0 obj\n({chunk_b})\nendobj\n"),
    ];
    let bytes = build_pdf(&objects, 9);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == "form_field_oversized_value")
        .expect("oversized field value finding");
    assert_eq!(finding.meta.get("field.name").map(String::as_str), Some("notes"));
    assert_eq!(finding.meta.get("field.source").map(String::as_str), Some("/V"));
    let len = finding
        .meta
        .get("field.value_len")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    assert!(len > 4096, "expected payload length over threshold");
    assert_eq!(finding.meta.get("chain.stage").map(String::as_str), Some("input"));
}

#[test]
fn benign_small_form_field_value_does_not_trigger_oversized_finding() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [6 0 R] >>\nendobj\n".to_string(),
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n".to_string(),
        "6 0 obj\n<< /Type /Annot /Subtype /Widget /FT /Tx /T (notes) /V (short value) >>\nendobj\n"
            .to_string(),
    ];
    let bytes = build_pdf(&objects, 7);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    assert!(!report.findings.iter().any(|finding| finding.kind == "form_field_oversized_value"));
}
