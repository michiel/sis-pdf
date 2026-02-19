mod common;

use common::default_scan_opts;
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
fn detects_acroform_field_javascript_keystroke_action() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [6 0 R] >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /Type /Annot /Subtype /Widget /FT /Tx /T (cardNumber) /AA << /K 7 0 R >> >>\nendobj\n",
        "7 0 obj\n<< /S /JavaScript /JS (app.alert('k')) >>\nendobj\n",
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
        .find(|finding| finding.kind == "acroform_field_action")
        .expect("expected acroform field action finding");
    assert_eq!(finding.meta.get("action.field_name").map(String::as_str), Some("cardNumber"));
    assert_eq!(finding.meta.get("action.field_event").map(String::as_str), Some("/K"));
    assert_eq!(finding.meta.get("action.field_event_class").map(String::as_str), Some("keystroke"));
    assert_eq!(finding.meta.get("chain.trigger").map(String::as_str), Some("acroform_field_aa"));
    assert_eq!(finding.confidence, sis_pdf_core::model::Confidence::Strong);
}

#[test]
fn calculate_event_javascript_field_action_escalates_severity() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [6 0 R] >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /Type /Annot /Subtype /Widget /FT /Tx /T (amount) /AA << /C 7 0 R >> >>\nendobj\n",
        "7 0 obj\n<< /S /JavaScript /JS (event.value=0;) >>\nendobj\n",
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
        .find(|finding| finding.kind == "acroform_field_action")
        .expect("expected acroform field action finding");
    assert_eq!(finding.meta.get("action.field_event").map(String::as_str), Some("/C"));
    assert_eq!(finding.meta.get("action.field_event_class").map(String::as_str), Some("calculate"));
    assert_eq!(finding.severity, sis_pdf_core::model::Severity::High);
}

#[test]
fn non_javascript_field_event_does_not_emit_acroform_field_action() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [6 0 R] >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /Type /Annot /Subtype /Widget /FT /Tx /T (refDoc) /AA << /K 7 0 R >> >>\nendobj\n",
        "7 0 obj\n<< /S /GoToR /F (chapter2.pdf) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    assert!(!report.findings.iter().any(|finding| finding.kind == "acroform_field_action"));
}
