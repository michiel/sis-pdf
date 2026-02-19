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
fn detects_pdfjs_annotation_injection_indicator() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [4 0 R] >>\nendobj\n",
        "4 0 obj\n<< /Subtype /Annot /AP << /N (app.alert(1)) >> >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(report.findings.iter().any(|finding| finding.kind == "pdfjs_annotation_injection"));
}

#[test]
fn detects_pdfjs_form_injection_indicator() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /FT /Tx /T (name) /V (eval('x')) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(report.findings.iter().any(|finding| finding.kind == "pdfjs_form_injection"));
}

#[test]
fn detects_pdfjs_eval_path_risk_indicator() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> >>\nendobj\n",
        "4 0 obj\n<< /Type /Font /Subtype /Type1 /Encoding << /Differences [0 /A /B] >> >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(report.findings.iter().any(|finding| finding.kind == "pdfjs_eval_path_risk"));
}

#[test]
fn benign_annotation_and_form_do_not_trigger_pdfjs_injection_indicators() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [4 0 R] >>\nendobj\n",
        "4 0 obj\n<< /Subtype /Annot /Contents (simple note) >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /FT /Tx /T (name) /V (Alice) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(!report.findings.iter().any(|finding| finding.kind == "pdfjs_annotation_injection"));
    assert!(!report.findings.iter().any(|finding| finding.kind == "pdfjs_form_injection"));
    assert!(!report.findings.iter().any(|finding| finding.kind == "form_html_injection"));
}

#[test]
fn detects_html_event_handler_injection() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /FT /Tx /T (field) /V (\">'></div><details/open/ontoggle=confirm(document.cookie)></details>) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    let html_finding = report.findings.iter().find(|f| f.kind == "form_html_injection");
    assert!(html_finding.is_some(), "Expected form_html_injection finding");
    let finding = html_finding.unwrap();
    assert_eq!(finding.severity, sis_pdf_core::model::Severity::Medium);
    assert_eq!(finding.confidence, sis_pdf_core::model::Confidence::Strong);
    assert!(finding.meta.get("injection.type").map(|s| s.as_str()) == Some("html_xss"));
}

#[test]
fn detects_html_tag_injection() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /FT /Tx /T (field) /V (<script>alert(1)</script>) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(report.findings.iter().any(|f| f.kind == "form_html_injection"));
}

#[test]
fn detects_html_img_onerror_injection() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /FT /Tx /T (field) /V (<img src=x onerror=alert(1)>) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(report.findings.iter().any(|f| f.kind == "form_html_injection"));
}

#[test]
fn detects_html_svg_injection() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /FT /Tx /T (field) /V (<svg onload=alert(1)>) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(report.findings.iter().any(|f| f.kind == "form_html_injection"));
}

#[test]
fn detects_html_iframe_injection() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /FT /Tx /T (field) /V (<iframe src=javascript:alert(1)>) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    // Should detect both HTML (iframe tag) and JavaScript (javascript: protocol)
    assert!(report.findings.iter().any(|f| f.kind == "form_html_injection"));
}

#[test]
fn detects_html_context_breaking() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /FT /Tx /T (field) /V (\"><script>alert(1)</script>) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(report.findings.iter().any(|f| f.kind == "form_html_injection"));
}

#[test]
fn detects_html_data_uri_injection() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /FT /Tx /T (field) /V (<img src=data:text/html,<script>alert(1)</script>>) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(report.findings.iter().any(|f| f.kind == "form_html_injection"));
}

#[test]
fn detects_html_in_default_value() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /FT /Tx /T (field) /DV (<script>alert(1)</script>) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(report.findings.iter().any(|f| f.kind == "form_html_injection"));
}

#[test]
fn detects_both_js_and_html_injection() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /FT /Tx /T (field) /V (<script>eval(alert(1))</script>) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    // Should detect both types when both patterns present
    assert!(report.findings.iter().any(|f| f.kind == "form_html_injection"));
    assert!(report.findings.iter().any(|f| f.kind == "pdfjs_form_injection"));
}

#[test]
fn detects_split_signals_across_v_and_ap_fields() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /FT /Tx /T (field) /V (<img src=x onerror=confirm(1)>) /AP << /N (eval(alert(1))) >> >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(report.findings.iter().any(|f| f.kind == "form_html_injection"));
    assert!(report.findings.iter().any(|f| f.kind == "pdfjs_form_injection"));
}

#[test]
fn detects_fragmented_signals_across_indirect_refs_in_single_form_value() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /FT /Tx /T (field) /V [7 0 R 8 0 R 9 0 R] >>\nendobj\n",
        "7 0 obj\n(<svg onload=alert(1)>)\nendobj\n",
        "8 0 obj\n(benign filler)\nendobj\n",
        "9 0 obj\n(eval(confirm(1)))\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(report.findings.iter().any(|f| f.kind == "form_html_injection"));
    assert!(report.findings.iter().any(|f| f.kind == "pdfjs_form_injection"));
}

#[test]
fn script_only_form_value_does_not_trigger_html_injection() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /FT /Tx /T (field) /V (confirm(document.cookie)) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(!report.findings.iter().any(|f| f.kind == "form_html_injection"));
}
