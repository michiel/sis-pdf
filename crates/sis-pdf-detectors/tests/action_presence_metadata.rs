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
fn open_action_present_emits_normalised_trigger_context() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "4 0 obj\n<< /S /GoToR /F (https://trigger.example/open) >>\nendobj\n",
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
        .find(|entry| entry.kind == "open_action_present")
        .expect("open action finding");
    assert_eq!(finding.meta.get("action.trigger_context").map(String::as_str), Some("open_action"));
    assert_eq!(finding.meta.get("action.trigger_type").map(String::as_str), Some("automatic"));
    assert_eq!(
        finding.meta.get("action.trigger_event_normalised").map(String::as_str),
        Some("/OpenAction")
    );
    assert_eq!(finding.meta.get("chain.stage").map(String::as_str), Some("execute"));
    assert_eq!(
        finding.meta.get("chain.capability").map(String::as_str),
        Some("action_trigger_chain")
    );
    assert_eq!(finding.meta.get("chain.trigger").map(String::as_str), Some("open_action"));
}

#[test]
fn aa_event_present_emits_normalised_event_and_initiation() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /AA << /O 4 0 R /K 5 0 R >> >>\nendobj\n",
        "4 0 obj\n<< /S /URI /URI (https://trigger.example/open) >>\nendobj\n",
        "5 0 obj\n<< /S /URI /URI (https://trigger.example/key) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let open_event = report
        .findings
        .iter()
        .find(|entry| {
            entry.kind == "aa_event_present"
                && entry.meta.get("action.trigger_event").map(String::as_str) == Some("/O")
        })
        .expect("aa /O event");
    assert_eq!(open_event.meta.get("action.trigger_context").map(String::as_str), Some("aa"));
    assert_eq!(open_event.meta.get("action.trigger_type").map(String::as_str), Some("automatic"));
    assert_eq!(
        open_event.meta.get("action.trigger_event_normalised").map(String::as_str),
        Some("/O")
    );
    assert_eq!(open_event.meta.get("chain.trigger").map(String::as_str), Some("additional_action"));

    let key_event = report
        .findings
        .iter()
        .find(|entry| {
            entry.kind == "aa_event_present"
                && entry.meta.get("action.trigger_event").map(String::as_str) == Some("/K")
        })
        .expect("aa /K event");
    assert_eq!(key_event.meta.get("action.trigger_type").map(String::as_str), Some("user"));
}
