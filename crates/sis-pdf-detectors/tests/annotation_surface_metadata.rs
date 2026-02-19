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
fn annotation_payloads_emit_subtype_and_trigger_context_metadata() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [4 0 R] >>\nendobj\n",
        "4 0 obj\n<< /Type /Annot /Subtype /Link /Rect [0 0 120 40] /AP << /N 7 0 R >> /Contents (%61%70%70%2e%61%6c%65%72%74%281%29) /RC (<details ontoggle=confirm(1)>) /A 5 0 R /AA << /O 6 0 R >> >>\nendobj\n",
        "5 0 obj\n<< /S /URI /URI (https://collector.example/pixel) >>\nendobj\n",
        "6 0 obj\n<< /S /JavaScript /JS 8 0 R >>\nendobj\n",
        "7 0 obj\n<< /Length 13 >>\nstream\napp.alert(1)\nendstream\nendobj\n",
        "8 0 obj\n<< /Length 26 >>\nstream\napp.alert('annotation js')\nendstream\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let annotation_injection = report
        .findings
        .iter()
        .find(|finding| finding.kind == "pdfjs_annotation_injection")
        .expect("pdfjs annotation injection finding");
    assert_eq!(annotation_injection.severity, sis_pdf_core::model::Severity::Medium);
    assert_eq!(
        annotation_injection.meta.get("annot.subtype").map(String::as_str),
        Some("/Link")
    );
    assert_eq!(
        annotation_injection.meta.get("annot.trigger_context").map(String::as_str),
        Some("annotation_action")
    );
    assert_eq!(
        annotation_injection.meta.get("chain.stage").map(String::as_str),
        Some("render")
    );
    assert_eq!(
        annotation_injection.meta.get("chain.capability").map(String::as_str),
        Some("annotation_injection")
    );
    assert_eq!(
        annotation_injection.meta.get("injection.sources").map(String::as_str),
        Some("/AP,/Contents,/RC")
    );
    assert_eq!(
        annotation_injection.meta.get("injection.normalised").map(String::as_str),
        Some("true")
    );

    let annotation_action = report
        .findings
        .iter()
        .find(|finding| finding.kind == "annotation_action_chain")
        .expect("annotation action chain");
    assert_eq!(annotation_action.meta.get("annot.subtype").map(String::as_str), Some("/Link"));
    assert_eq!(
        annotation_action.meta.get("annot.trigger_context").map(String::as_str),
        Some("annotation_action")
    );
    assert_eq!(
        annotation_action.meta.get("action.trigger_context").map(String::as_str),
        Some("annotation_action")
    );
    assert_eq!(
        annotation_action.meta.get("chain.trigger").map(String::as_str),
        Some("annotation_action")
    );
}

#[test]
fn annotation_aa_trigger_context_is_preserved() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [4 0 R] >>\nendobj\n",
        "4 0 obj\n<< /Type /Annot /Subtype /Widget /Rect [0 0 120 40] /AA << /O 5 0 R >> >>\nendobj\n",
        "5 0 obj\n<< /S /URI /URI (https://notify.example/open) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let annotation_action = report
        .findings
        .iter()
        .find(|finding| finding.kind == "annotation_action_chain")
        .expect("annotation action chain");
    assert_eq!(
        annotation_action.meta.get("annot.trigger_context").map(String::as_str),
        Some("annotation_aa")
    );
    assert_eq!(
        annotation_action.meta.get("action.trigger_event_normalised").map(String::as_str),
        Some("/O")
    );
    assert_eq!(
        annotation_action.meta.get("action.trigger_type").map(String::as_str),
        Some("automatic")
    );
}
