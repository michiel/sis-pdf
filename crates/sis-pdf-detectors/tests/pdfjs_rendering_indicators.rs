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
    assert_eq!(finding.meta.get("chain.stage").map(|s| s.as_str()), Some("render"));
    assert_eq!(finding.meta.get("chain.capability").map(|s| s.as_str()), Some("html_injection"));
    assert_eq!(finding.meta.get("chain.trigger").map(|s| s.as_str()), Some("pdfjs"));
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
    let html = report.findings.iter().find(|f| f.kind == "form_html_injection");
    let js = report.findings.iter().find(|f| f.kind == "pdfjs_form_injection");
    assert!(html.is_some());
    assert!(js.is_some());
    let html = html.expect("html finding");
    let js = js.expect("js finding");
    assert_eq!(html.meta.get("injection.sources").map(|v| v.as_str()), Some("/V"));
    assert_eq!(js.meta.get("injection.sources").map(|v| v.as_str()), Some("/AP"));
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

#[test]
fn detects_percent_encoded_html_form_value() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /FT /Tx /T (field) /V (%3Cscript%3Ealert(1)%3C/script%3E) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    let finding = report.findings.iter().find(|f| f.kind == "form_html_injection");
    assert!(finding.is_some(), "Expected HTML injection finding");
    let finding = finding.expect("finding");
    assert_eq!(finding.meta.get("injection.normalised").map(|v| v.as_str()), Some("true"));
}

#[test]
fn detects_js_hex_escape_payload_in_form_value() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /FT /Tx /T (field) /V <5c7836355c7837365c7836315c78366328616c65727428312929> >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    let finding = report.findings.iter().find(|f| f.kind == "pdfjs_form_injection");
    assert!(finding.is_some(), "Expected JavaScript injection finding");
    let finding = finding.expect("finding");
    assert_eq!(finding.meta.get("injection.normalised").map(|v| v.as_str()), Some("true"));
}

#[test]
fn detects_multilayer_fragmented_obfuscation_and_boosts_confidence() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /FT /Tx /T (field) /V [7 0 R 8 0 R] >>\nendobj\n",
        "7 0 obj\n(%2526lt%253Bscript%2526gt%253B)\nendobj\n",
        "8 0 obj\n(%2565%2576%2561%256c%2528alert(1)%2529%2526lt%253B%252Fscript%2526gt%253B)\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    let js_finding = report.findings.iter().find(|f| f.kind == "pdfjs_form_injection");
    assert!(js_finding.is_some(), "Expected JavaScript injection finding");
    let js_finding = js_finding.expect("finding");
    assert_eq!(js_finding.confidence, sis_pdf_core::model::Confidence::Strong);
    assert_eq!(js_finding.meta.get("injection.normalised").map(|v| v.as_str()), Some("true"));
    let layers = js_finding
        .meta
        .get("injection.decode_layers")
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(0);
    assert!(layers >= 2, "Expected multi-layer decode metadata");
    assert!(report.findings.iter().any(|f| f.kind == "form_html_injection"));
}

#[test]
fn detects_scattered_payload_assembly_when_fragments_are_individually_benign() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /FT /Tx /T (field) /V [7 0 R 8 0 R 9 0 R] >>\nendobj\n",
        "7 0 obj\n(%3C)\nendobj\n",
        "8 0 obj\n(script%3Ealert(1)%3C)\nendobj\n",
        "9 0 obj\n(%2Fscript%3E)\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let scattered = report.findings.iter().find(|f| f.kind == "scattered_payload_assembly");
    assert!(scattered.is_some(), "Expected scattered payload finding");
    let scattered = scattered.expect("finding");
    assert_eq!(scattered.meta.get("chain.stage").map(|v| v.as_str()), Some("decode"));
    assert_eq!(scattered.meta.get("chain.capability").map(|v| v.as_str()), Some("payload_scatter"));
    assert_eq!(scattered.meta.get("chain.trigger").map(|v| v.as_str()), Some("pdfjs"));
    assert_eq!(scattered.meta.get("scatter.fragment_count").map(|v| v.as_str()), Some("3"));
    assert_eq!(scattered.meta.get("injection.sources").map(|v| v.as_str()), Some("/V"));
    assert!(
        scattered
            .meta
            .get("scatter.object_ids")
            .map(|v| v.contains("7 0 obj") && v.contains("8 0 obj") && v.contains("9 0 obj"))
            .unwrap_or(false),
        "Expected source object ids in scatter metadata"
    );
}

#[test]
fn benign_fragmented_form_values_do_not_trigger_scattered_payload_assembly() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /FT /Tx /T (field) /V [7 0 R 8 0 R 9 0 R] >>\nendobj\n",
        "7 0 obj\n(hel)\nendobj\n",
        "8 0 obj\n(lo )\nendobj\n",
        "9 0 obj\n(world)\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(!report.findings.iter().any(|f| f.kind == "scattered_payload_assembly"));
}

#[test]
fn detects_cross_stream_payload_assembly_from_js_and_form_fragments() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R /OpenAction 10 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /FT /Tx /T (field) /V [7 0 R 8 0 R 9 0 R] >>\nendobj\n",
        "7 0 obj\n(%3C)\nendobj\n",
        "8 0 obj\n(script%3Ealert(1)%3C)\nendobj\n",
        "9 0 obj\n(%2Fscript%3E)\nendobj\n",
        "10 0 obj\n<< /S /JavaScript /JS <76617220733d537472696e672e66726f6d43686172436f64652836302c3131352c39392c3131342c3130352c3131322c3131362c36322c39372c3130382c3130312c3131342c3131362c34302c34392c34312c36302c34372c3131352c39392c3131342c3130352c3131322c3131362c3632293b> >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let finding = report.findings.iter().find(|f| f.kind == "cross_stream_payload_assembly");
    assert!(finding.is_some(), "Expected cross_stream_payload_assembly finding");
    let finding = finding.expect("finding");
    assert_eq!(finding.meta.get("chain.stage").map(|v| v.as_str()), Some("decode"));
    assert_eq!(
        finding.meta.get("chain.capability").map(|v| v.as_str()),
        Some("cross_stream_assembly")
    );
    assert_eq!(finding.meta.get("js.object.ref").map(|v| v.as_str()), Some("10 0 obj"));
    assert_eq!(finding.meta.get("cross_stream.source_types").map(|v| v.as_str()), Some("form"));
    assert!(
        finding
            .meta
            .get("scatter.object_ids")
            .map(|v| v.contains("7 0 obj") && v.contains("8 0 obj") && v.contains("9 0 obj"))
            .unwrap_or(false),
        "Expected scatter object ids in metadata"
    );
}

#[test]
fn detects_cross_stream_payload_assembly_from_js_and_annotation_fragments() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 10 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [6 0 R] >>\nendobj\n",
        "6 0 obj\n<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] /Contents [7 0 R 8 0 R 9 0 R] >>\nendobj\n",
        "7 0 obj\n(%3C)\nendobj\n",
        "8 0 obj\n(script%3Ealert(1)%3C)\nendobj\n",
        "9 0 obj\n(%2Fscript%3E)\nendobj\n",
        "10 0 obj\n<< /S /JavaScript /JS <76617220733d537472696e672e66726f6d43686172436f64652836302c3131352c39392c3131342c3130352c3131322c3131362c36322c39372c3130382c3130312c3131342c3131362c34302c34392c34312c36302c34372c3131352c39392c3131342c3130352c3131322c3131362c3632293b> >>\nendobj\n",
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
        .find(|f| f.kind == "cross_stream_payload_assembly")
        .expect("cross-stream finding");
    assert_eq!(
        finding.meta.get("cross_stream.source_types").map(|v| v.as_str()),
        Some("annotation")
    );
    assert_eq!(finding.meta.get("injection.sources").map(|v| v.as_str()), Some("/Contents"));
    assert!(
        finding
            .meta
            .get("scatter.object_ids")
            .map(|v| v.contains("7 0 obj") && v.contains("8 0 obj") && v.contains("9 0 obj"))
            .unwrap_or(false),
        "Expected annotation source object ids in metadata"
    );
}

#[test]
fn detects_cross_stream_payload_assembly_from_js_and_metadata_fragments() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 10 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "11 0 obj\n<< /Title [12 0 R 13 0 R 14 0 R] >>\nendobj\n",
        "12 0 obj\n(%3C)\nendobj\n",
        "13 0 obj\n(script%3Ealert(1)%3C)\nendobj\n",
        "14 0 obj\n(%2Fscript%3E)\nendobj\n",
        "10 0 obj\n<< /S /JavaScript /JS <76617220733d537472696e672e66726f6d43686172436f64652836302c3131352c39392c3131342c3130352c3131322c3131362c36322c39372c3130382c3130312c3131342c3131362c34302c34392c34312c36302c34372c3131352c39392c3131342c3130352c3131322c3131362c3632293b> >>\nendobj\n",
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
        .find(|f| f.kind == "cross_stream_payload_assembly")
        .expect("cross-stream finding");
    assert_eq!(finding.meta.get("cross_stream.source_types").map(|v| v.as_str()), Some("metadata"));
    assert_eq!(finding.meta.get("injection.sources").map(|v| v.as_str()), Some("/Title"));
    assert!(
        finding
            .meta
            .get("scatter.object_ids")
            .map(|v| v.contains("12 0 obj") && v.contains("13 0 obj") && v.contains("14 0 obj"))
            .unwrap_or(false),
        "Expected metadata source object ids in metadata"
    );
}
