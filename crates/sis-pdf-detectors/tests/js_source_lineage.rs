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
fn js_present_emits_source_container_and_ref_chain_metadata_across_containers() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 10 0 R /Names << /JavaScript 20 0 R >> >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [30 0 R] >>\nendobj\n",
        "10 0 obj\n<< /S /JavaScript /JS (app.alert('open')) >>\nendobj\n",
        "20 0 obj\n<< /Names [(stage) 21 0 R] >>\nendobj\n",
        "21 0 obj\n(app.alert('name-tree'))\nendobj\n",
        "30 0 obj\n<< /Type /Annot /Subtype /Text /Rect [0 0 12 12] /A 31 0 R >>\nendobj\n",
        "31 0 obj\n<< /S /JavaScript /JS (app.alert('annot')) >>\nendobj\n",
        "40 0 obj\n<< /S /JavaScript /JS (app.alert('multi')) /URI (javascript:app.alert('uri')) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let js_findings =
        report.findings.iter().filter(|finding| finding.kind == "js_present").collect::<Vec<_>>();
    assert!(
        js_findings
            .iter()
            .any(|finding| finding.meta.get("js.source").map(String::as_str) == Some("open_action")),
        "expected open_action sourced JavaScript finding"
    );
    assert!(
        js_findings
            .iter()
            .any(|finding| finding.meta.get("js.source").map(String::as_str) == Some("name_tree")),
        "expected name_tree sourced JavaScript finding"
    );
    assert!(
        js_findings
            .iter()
            .any(|finding| finding.meta.get("js.source").map(String::as_str) == Some("annotation")),
        "expected annotation sourced JavaScript finding"
    );
    assert!(
        js_findings.iter().all(|finding| finding.meta.contains_key("js.container_path")),
        "all js_present findings should include js.container_path"
    );
    assert!(
        js_findings.iter().all(|finding| finding.meta.contains_key("js.object_ref_chain")),
        "all js_present findings should include js.object_ref_chain"
    );

    let object_40_count = js_findings
        .iter()
        .filter(|finding| finding.objects.iter().any(|object_ref| object_ref == "40 0 obj"))
        .count();
    assert_eq!(
        object_40_count, 1,
        "multiple JavaScript vectors in one object should not emit duplicate js_present findings"
    );
}
