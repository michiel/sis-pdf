mod common;

use common::default_scan_opts;
use sis_pdf_core::model::{Confidence, Severity};
use sis_pdf_detectors::default_detectors;

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
fn emits_font_js_exploitation_bridge_for_dual_signal_document() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 200 200] >>\nendobj\n",
        "4 0 obj\n<< /Type /Font /Subtype /Type1 /FontMatrix [0 0 1 1 (evil) 0] /FontBBox [0 0 100 (bbox)] >>\nendobj\n",
        "6 0 obj\n<< /S /JavaScript /JS (eval('alert(1)')) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == "font_js_exploitation_bridge")
        .expect("expected font_js_exploitation_bridge");
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::Strong);
    assert_eq!(finding.meta.get("bridge.confidence_adjusted").map(String::as_str), Some("true"));
    assert_eq!(finding.meta.get("bridge.co_location").map(String::as_str), Some("document_level"));
    assert_eq!(finding.meta.get("renderer.profile").map(String::as_str), Some("pdfjs"));
    assert_eq!(
        finding.meta.get("renderer.precondition").map(String::as_str),
        Some("pdfjs_font_eval_and_js_execution_paths_reachable")
    );
}

#[test]
fn does_not_emit_bridge_without_javascript_signal() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 200 200] >>\nendobj\n",
        "4 0 obj\n<< /Type /Font /Subtype /Type1 /FontMatrix [0 0 1 1 (evil) 0] >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(!report.findings.iter().any(|finding| finding.kind == "font_js_exploitation_bridge"));
}

#[test]
fn does_not_emit_bridge_without_font_signal() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 200 200] >>\nendobj\n",
        "4 0 obj\n<< /Type /Font /Subtype /Type1 /FontMatrix [0.001 0 0 0.001 0 0] /FontBBox [0 0 500 700] /Encoding /WinAnsiEncoding >>\nendobj\n",
        "6 0 obj\n<< /S /JavaScript /JS (eval('alert(1)')) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(!report.findings.iter().any(|finding| finding.kind == "font_js_exploitation_bridge"));
}

#[test]
fn co_located_font_and_js_signals_raise_bridge_confidence() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 200 200] >>\nendobj\n",
        "4 0 obj\n<< /Type /Font /Subtype /Type1 /FontMatrix [0 0 1 1 (evil) 0] /FontBBox [0 0 100 (bbox)] /JS (eval('alert(1)')) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == "font_js_exploitation_bridge")
        .expect("expected font_js_exploitation_bridge");
    assert_eq!(finding.confidence, Confidence::Certain);
    assert_eq!(finding.meta.get("bridge.co_location").map(String::as_str), Some("shared_object"));
    assert_eq!(finding.meta.get("bridge.shared_object_count").map(String::as_str), Some("1"));
}
