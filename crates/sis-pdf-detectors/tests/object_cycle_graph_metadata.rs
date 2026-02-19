mod common;

use common::default_scan_opts;
use sis_pdf_detectors::default_detectors;

fn build_pdf_with_objects(objects: &[String]) -> Vec<u8> {
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
fn cycle_finding_includes_graph_evasion_metadata_near_execute_surface() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [5 0 R] >>\nendobj\n".to_string(),
        "4 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert(1)) /Next 5 0 R >>\nendobj\n"
            .to_string(),
        "5 0 obj\n<< /Type /Annot /Subtype /Link /A 4 0 R >>\nendobj\n".to_string(),
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let cycle = report
        .findings
        .iter()
        .find(|finding| {
            finding.kind == "object_reference_cycle"
                && finding.meta.get("graph.evasion_kind").map(String::as_str)
                    == Some("cycle_near_execute")
        })
        .expect("cycle_near_execute finding");
    assert_eq!(cycle.meta.get("graph.depth").map(String::as_str), Some("2"));
    assert_eq!(cycle.meta.get("graph.conflict_count").map(String::as_str), Some("1"));
    assert_eq!(cycle.meta.get("graph.execute_overlap_count").map(String::as_str), Some("1"));
}

#[test]
fn deep_reference_finding_includes_graph_indirection_metadata() {
    let mut objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n".to_string(),
    ];
    for obj in 4..29u32 {
        let next = obj + 1;
        objects.push(format!("{obj} 0 obj\n<< /Node {next} 0 R >>\nendobj\n"));
    }
    objects.push(
        "29 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('chain')) >>\nendobj\n"
            .to_string(),
    );

    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    let depth = report
        .findings
        .iter()
        .find(|finding| finding.kind == "object_reference_depth_high")
        .expect("object_reference_depth_high finding");
    assert_eq!(depth.meta.get("graph.evasion_kind").map(String::as_str), Some("deep_indirection"));
    assert_eq!(depth.meta.get("graph.conflict_count").map(String::as_str), Some("0"));
    assert_eq!(depth.meta.get("chain.capability").map(String::as_str), Some("graph_indirection"));
    assert!(depth
        .meta
        .get("graph.execute_surface_count")
        .and_then(|value| value.parse::<u32>().ok())
        .is_some_and(|count| count >= 1));
}
