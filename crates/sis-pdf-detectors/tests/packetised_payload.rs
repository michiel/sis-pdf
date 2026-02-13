mod common;

use common::default_scan_opts;
use sis_pdf_core::model::Severity;
use sis_pdf_detectors::default_detectors;

fn build_pdf_with_raw_objects(objects: &[(usize, Vec<u8>)]) -> Vec<u8> {
    let mut pdf = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.4\n");
    let max_obj = objects.iter().map(|(obj, _)| *obj).max().unwrap_or(0);
    let mut offsets = vec![0usize; max_obj + 1];
    for (obj_num, object_bytes) in objects {
        offsets[*obj_num] = pdf.len();
        pdf.extend_from_slice(object_bytes);
        if !object_bytes.ends_with(b"\n") {
            pdf.push(b'\n');
        }
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

fn packetised_stream(blocks: usize, stride: usize) -> Vec<u8> {
    let mut payload = Vec::new();
    for block_index in 0..blocks {
        payload.extend_from_slice(&(block_index as u16).to_be_bytes());
        payload.extend_from_slice(&(stride as u16 - 4).to_be_bytes());
        for inner_index in 0..(stride - 4) {
            let value = ((block_index * 131 + inner_index * 17 + 73) % 251) as u8;
            payload.push(value);
        }
    }
    payload
}

#[test]
fn detects_packetised_payload_with_execution_bridge() {
    let bytes = include_bytes!("fixtures/packetised_payload_obfuscation.pdf");
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == "packetised_payload_obfuscation")
        .expect("packetised_payload_obfuscation");
    assert!(matches!(finding.severity, Severity::Medium | Severity::High));
    assert_eq!(
        finding
            .meta
            .get("packet.correlation.execution_bridge")
            .map(std::string::String::as_str),
        Some("true")
    );
    assert_eq!(
        finding.meta.get("packet.correlation.trigger_path").map(String::as_str),
        Some("true")
    );
    assert!(
        finding
            .meta
            .get("packet.block_count")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0)
            >= 16
    );
}

#[test]
fn suppresses_packetised_finding_without_execution_bridge() {
    let bytes = include_bytes!("fixtures/packetised_payload_no_bridge.pdf");
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    assert!(
        report.findings.iter().all(|finding| finding.kind != "packetised_payload_obfuscation"),
        "packetised signal should be gated when execution bridge is absent"
    );
}

#[test]
fn packetised_payload_with_trigger_only_bridge_is_medium() {
    let payload = packetised_stream(24, 64);
    let mut stream_obj = Vec::new();
    stream_obj.extend_from_slice(
        format!("3 0 obj\n<< /Length {} >>\nstream\n", payload.len()).as_bytes(),
    );
    stream_obj.extend_from_slice(&payload);
    stream_obj.extend_from_slice(b"\nendstream\nendobj\n");
    let objects = vec![
        (
            1usize,
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n".to_vec(),
        ),
        (2usize, b"2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n".to_vec()),
        (3usize, stream_obj),
        (4usize, b"4 0 obj\n<< /S /GoTo /D [1 0 R /Fit] >>\nendobj\n".to_vec()),
    ];
    let bytes = build_pdf_with_raw_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == "packetised_payload_obfuscation")
        .expect("packetised_payload_obfuscation");
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(
        finding.meta.get("packet.correlation.trigger_path").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        finding.meta.get("packet.correlation.execution_sink").map(String::as_str),
        Some("false")
    );
    assert_eq!(
        finding.meta.get("packet.correlation.launch_path").map(String::as_str),
        Some("false")
    );
}
