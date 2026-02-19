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
fn detects_missing_object_termination_for_deep_security_ref_chain() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n".to_string(),
        "4 0 obj\n<< /S /JavaScript /JS 5 0 R >>\nendobj\n".to_string(),
        "5 0 obj\n6 0 R\nendobj\n".to_string(),
    ];
    let bytes = build_pdf(&objects, 7);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == "null_ref_chain_termination")
        .expect("expected null_ref_chain_termination finding");
    assert_eq!(finding.meta.get("context.key").map(String::as_str), Some("/OpenAction"));
    assert_eq!(finding.meta.get("termination.kind").map(String::as_str), Some("missing_object"));
    assert!(
        finding
            .meta
            .get("ref.chain")
            .map(|value| {
                value.contains("4 0 R") && value.contains("5 0 R") && value.contains("6 0 R")
            })
            .unwrap_or(false),
        "expected deep indirect chain in metadata"
    );
}

#[test]
fn detects_null_literal_termination_for_deep_form_value_chain() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [6 0 R] >>\nendobj\n".to_string(),
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n".to_string(),
        "6 0 obj\n<< /Subtype /Widget /FT /Tx /T (f) /V 7 0 R >>\nendobj\n".to_string(),
        "7 0 obj\n8 0 R\nendobj\n".to_string(),
        "8 0 obj\n9 0 R\nendobj\n".to_string(),
        "9 0 obj\nnull\nendobj\n".to_string(),
    ];
    let bytes = build_pdf(&objects, 10);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == "null_ref_chain_termination")
        .expect("expected null_ref_chain_termination finding");
    assert_eq!(finding.meta.get("context.key").map(String::as_str), Some("/V"));
    assert_eq!(finding.meta.get("termination.kind").map(String::as_str), Some("null_literal"));
    let depth =
        finding.meta.get("ref.depth").and_then(|value| value.parse::<usize>().ok()).unwrap_or(0);
    assert!(depth >= 3, "expected deep ref chain");
}

#[test]
fn short_missing_ref_chain_does_not_trigger_null_ref_chain_termination() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n".to_string(),
        "4 0 obj\n<< /S /JavaScript /JS 5 0 R >>\nendobj\n".to_string(),
    ];
    let bytes = build_pdf(&objects, 6);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(!report.findings.iter().any(|finding| finding.kind == "null_ref_chain_termination"));
}
