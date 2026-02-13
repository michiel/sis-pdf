mod common;

use common::default_scan_opts;
use sis_pdf_core::model::Severity;
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
fn detects_known_renderer_divergence_paths() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R /Pages 3 0 R /AcroForm 4 0 R >>\nendobj\n",
        "2 0 obj\n<< /S /JavaScript /JS (app.alert('hi')) >>\nendobj\n",
        "3 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n",
        "4 0 obj\n<< /XFA 5 0 R >>\nendobj\n",
        "5 0 obj\n<< /Length 19 /Subtype /XML >>\nstream\n<xfa:form></xfa:form>\nendstream\nendobj\n",
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
        .find(|finding| finding.kind == "renderer_behavior_divergence_known_path")
        .expect("renderer_behavior_divergence_known_path");
    assert!(finding.severity >= Severity::Medium);
    assert_eq!(
        finding.meta.get("renderer.profile_deltas").map(std::string::String::as_str),
        Some("acrobat:high/high,pdfium:medium/medium,preview:low/low")
    );
    let known_paths = finding.meta.get("renderer.known_paths").cloned().unwrap_or_default();
    assert!(known_paths.contains("open_action_js_path"));
    assert!(known_paths.contains("xfa_interactive_path"));
}

#[test]
fn emits_renderer_exploitation_chain_for_high_risk_combo() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R /Pages 3 0 R /AcroForm 4 0 R >>\nendobj\n",
        "2 0 obj\n<< /S /Launch /F 6 0 R >>\nendobj\n",
        "3 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n",
        "4 0 obj\n<< /XFA 5 0 R >>\nendobj\n",
        "5 0 obj\n<< /Length 19 /Subtype /XML >>\nstream\n<xfa:form></xfa:form>\nendstream\nendobj\n",
        "6 0 obj\n<< /Type /Filespec /F (runme.exe) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let chain = report
        .findings
        .iter()
        .find(|finding| finding.kind == "renderer_behavior_exploitation_chain")
        .expect("renderer_behavior_exploitation_chain");
    assert_eq!(chain.severity, Severity::High);
    let components = chain.meta.get("renderer.chain_components").cloned().unwrap_or_default();
    assert!(components.contains("automatic_trigger=true"));
    assert!(components.contains("high_risk_surface=true"));
}
