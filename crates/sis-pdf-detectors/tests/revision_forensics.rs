mod common;

use common::default_scan_opts;
use sis_pdf_detectors::default_detectors;

fn build_incremental_revision_pdf() -> Vec<u8> {
    let mut rev1 = Vec::new();
    rev1.extend_from_slice(b"%PDF-1.4\n");
    let base_objects = [
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 400] /Contents 4 0 R >>\nendobj\n",
        "4 0 obj\n<< /Length 33 >>\nstream\nBT /F1 12 Tf 10 10 Td (Base) Tj ET\nendstream\nendobj\n",
    ];
    let mut base_offsets = [0usize; 5];
    for object in &base_objects {
        let id = object
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        if id < base_offsets.len() {
            base_offsets[id] = rev1.len();
        }
        rev1.extend_from_slice(object.as_bytes());
    }
    let startxref_rev1 = rev1.len();
    rev1.extend_from_slice(b"xref\n0 5\n");
    rev1.extend_from_slice(b"0000000000 65535 f \n");
    for offset in base_offsets.iter().skip(1) {
        rev1.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    rev1.extend_from_slice(b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n");
    rev1.extend_from_slice(startxref_rev1.to_string().as_bytes());
    rev1.extend_from_slice(b"\n%%EOF\n");

    let mut out = rev1;
    out.extend_from_slice(b"\n");
    let rev2_obj4 = out.len();
    out.extend_from_slice(
        b"4 0 obj\n<< /Length 36 >>\nstream\nBT /F1 12 Tf 10 10 Td (Phase2) Tj ET\nendstream\nendobj\n",
    );
    let rev2_obj6 = out.len();
    out.extend_from_slice(
        b"6 0 obj\n<< /Type /Annot /Subtype /Text /Rect [0 0 200 200] /Contents (added) >>\nendobj\n",
    );
    let startxref_rev2 = out.len();
    out.extend_from_slice(b"xref\n4 3\n");
    out.extend_from_slice(format!("{rev2_obj4:010} 00000 n \n").as_bytes());
    out.extend_from_slice(b"0000000000 00000 f \n");
    out.extend_from_slice(format!("{rev2_obj6:010} 00000 n \n").as_bytes());
    out.extend_from_slice(b"trailer\n<< /Size 7 /Root 1 0 R /Prev ");
    out.extend_from_slice(startxref_rev1.to_string().as_bytes());
    out.extend_from_slice(b" >>\nstartxref\n");
    out.extend_from_slice(startxref_rev2.to_string().as_bytes());
    out.extend_from_slice(b"\n%%EOF\n");

    out.extend_from_slice(b"\n");
    let rev3_obj1 = out.len();
    out.extend_from_slice(
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 7 0 R >>\nendobj\n",
    );
    let rev3_obj7 = out.len();
    out.extend_from_slice(b"7 0 obj\n<< /S /JavaScript /JS (app.alert('x')) >>\nendobj\n");
    let startxref_rev3 = out.len();
    out.extend_from_slice(b"xref\n1 1\n");
    out.extend_from_slice(format!("{rev3_obj1:010} 00000 n \n").as_bytes());
    out.extend_from_slice(b"xref\n7 1\n");
    out.extend_from_slice(format!("{rev3_obj7:010} 00000 n \n").as_bytes());
    out.extend_from_slice(b"trailer\n<< /Size 8 /Root 1 0 R /Prev ");
    out.extend_from_slice(startxref_rev2.to_string().as_bytes());
    out.extend_from_slice(b" >>\nstartxref\n");
    out.extend_from_slice(startxref_rev3.to_string().as_bytes());
    out.extend_from_slice(b"\n%%EOF\n");
    out
}

fn build_single_revision_pdf() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"%PDF-1.4\n");
    let objects = [
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>\nendobj\n",
        "4 0 obj\n<< /Length 31 >>\nstream\nBT /F1 12 Tf 1 1 Td (ok) Tj ET\nendstream\nendobj\n",
    ];
    let mut offsets = [0usize; 5];
    for object in &objects {
        let id = object
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        if id < offsets.len() {
            offsets[id] = bytes.len();
        }
        bytes.extend_from_slice(object.as_bytes());
    }
    let startxref = bytes.len();
    bytes.extend_from_slice(b"xref\n0 5\n");
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        bytes.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    bytes.extend_from_slice(b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n");
    bytes.extend_from_slice(startxref.to_string().as_bytes());
    bytes.extend_from_slice(b"\n%%EOF\n");
    bytes
}

#[test]
fn detects_pr16_revision_forensics_findings() {
    let bytes = build_incremental_revision_pdf();
    let detectors = default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");
    let kinds = report.findings.iter().map(|finding| finding.kind.as_str()).collect::<Vec<_>>();
    assert!(kinds.contains(&"revision_page_content_changed"));
    assert!(kinds.contains(&"revision_annotations_changed"));
    assert!(kinds.contains(&"revision_catalog_changed"));
    assert!(kinds.contains(&"revision_anomaly_scoring"));
}

#[test]
fn does_not_emit_revision_findings_for_single_revision_document() {
    let bytes = build_single_revision_pdf();
    let detectors = default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");
    assert!(!report.findings.iter().any(|finding| finding.kind.starts_with("revision_")));
}
