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
fn openaction_nested_next_chain_emits_chain_surface_metadata() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "4 0 obj\n<< /S /GoToR /F (https://stage.example/one) /Next [5 0 R 6 0 R] >>\nendobj\n",
        "5 0 obj\n<< /S /JavaScript /JS (app.alert('x')) /Next 7 0 R >>\nendobj\n",
        "6 0 obj\n<< /S /URI /URI (https://stage.example/two) >>\nendobj\n",
        "7 0 obj\n<< /S /Launch /F (cmd.exe) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let trigger = report
        .findings
        .iter()
        .find(|finding| finding.kind == "action_automatic_trigger")
        .expect("automatic trigger finding");
    assert_eq!(trigger.meta.get("action.trigger_context").map(String::as_str), Some("open_action"));
    assert_eq!(
        trigger.meta.get("action.trigger_event_normalised").map(String::as_str),
        Some("/OpenAction")
    );
    assert_eq!(trigger.meta.get("chain.stage").map(String::as_str), Some("execute"));
    assert_eq!(
        trigger.meta.get("chain.capability").map(String::as_str),
        Some("action_trigger_chain")
    );
    assert_eq!(trigger.meta.get("chain.trigger").map(String::as_str), Some("open_action"));
    assert_eq!(trigger.meta.get("action.next.depth").map(String::as_str), Some("2"));
    assert_eq!(trigger.meta.get("action.next.max_fanout").map(String::as_str), Some("2"));

    let complex = report
        .findings
        .iter()
        .find(|finding| finding.kind == "action_chain_complex")
        .expect("complex action chain finding");
    assert_eq!(complex.meta.get("action.trigger_context").map(String::as_str), Some("open_action"));
    assert_eq!(complex.meta.get("action.next.depth").map(String::as_str), Some("2"));
    assert_eq!(complex.meta.get("action.next.branch_count").map(String::as_str), Some("3"));
}

#[test]
fn aa_trigger_context_is_normalised_for_automatic_events() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /AA << /O 5 0 R /K 6 0 R >> >>\nendobj\n",
        "5 0 obj\n<< /S /URI /URI (https://notify.example/open) >>\nendobj\n",
        "6 0 obj\n<< /S /URI /URI (https://notify.example/key) >>\nendobj\n",
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
        .find(|entry| {
            entry.kind == "action_automatic_trigger"
                && entry.meta.get("action.trigger_event").map(String::as_str) == Some("/O")
        })
        .expect("automatic /AA trigger finding");
    assert_eq!(finding.meta.get("action.trigger_context").map(String::as_str), Some("aa"));
    assert_eq!(finding.meta.get("action.trigger_event_normalised").map(String::as_str), Some("/O"));
    assert_eq!(finding.meta.get("action.trigger_type").map(String::as_str), Some("automatic"));
    assert_eq!(finding.meta.get("chain.stage").map(String::as_str), Some("execute"));
    assert_eq!(
        finding.meta.get("chain.capability").map(String::as_str),
        Some("action_trigger_chain")
    );
    assert_eq!(finding.meta.get("chain.trigger").map(String::as_str), Some("additional_action"));
}
