mod common;

use common::default_scan_opts;
use sis_pdf_detectors::default_detectors;

fn build_pdf(objects: &[String], size: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"%PDF-1.4\n");
    let mut offsets = vec![0usize; size];
    for object in objects {
        let id = object
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        if id < offsets.len() {
            offsets[id] = out.len();
        }
        out.extend_from_slice(object.as_bytes());
    }
    let startxref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", size).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n", size).as_bytes(),
    );
    out.extend_from_slice(startxref.to_string().as_bytes());
    out.extend_from_slice(b"\n%%EOF\n");
    out
}

fn build_divergence_fixture() -> Vec<u8> {
    let stream_payload = "1 2 cm\n";
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>\nendobj\n"
            .to_string(),
        format!(
            "4 0 obj\n<< /Length {} >>\nstream\n{}endstream\nendobj\n",
            stream_payload.len(),
            stream_payload
        ),
        format!(
            "5 0 obj\n<< /Length {} /Filter /FlateDecode >>\nstream\n{}endstream\nendobj\n",
            stream_payload.len(),
            stream_payload
        ),
    ];
    build_pdf(&objects, 6)
}

fn build_linearization_integrity_fixture() -> Vec<u8> {
    let objects = vec![
        "1 0 obj\n<< /Linearized 1 /L 999999 /O 9 /E 0 /H [1 2 3] >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Catalog /Pages 3 0 R >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Pages /Count 1 /Kids [4 0 R] >>\nendobj\n".to_string(),
        "4 0 obj\n<< /Type /Page /Parent 3 0 R /MediaBox [0 0 200 200] /Contents 5 0 R >>\nendobj\n"
            .to_string(),
        "5 0 obj\n<< /Length 15 >>\nstream\nBT (x) Tj ET\nendstream\nendobj\n".to_string(),
    ];
    build_pdf(&objects, 6)
}

fn build_valid_text_operator_fixture() -> Vec<u8> {
    let stream_payload = "BT /F1 12 Tf (abc) Tj [(a) 120 (b)] TJ (line) ' 1 2 (x) \" ET\n";
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>\nendobj\n"
            .to_string(),
        format!(
            "4 0 obj\n<< /Length {} >>\nstream\n{}endstream\nendobj\n",
            stream_payload.len(),
            stream_payload
        ),
    ];
    build_pdf(&objects, 5)
}

fn build_unknown_operator_fixture() -> Vec<u8> {
    let stream_payload = "1 2 3 XYZ\n";
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>\nendobj\n"
            .to_string(),
        format!(
            "4 0 obj\n<< /Length {} >>\nstream\n{}endstream\nendobj\n",
            stream_payload.len(),
            stream_payload
        ),
    ];
    build_pdf(&objects, 5)
}

fn build_non_content_cmap_fixture() -> Vec<u8> {
    let page_stream_payload = "BT /F1 12 Tf (ok) Tj ET\n";
    let cmap_payload =
        "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\nendcmap\nend\n";
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
            .to_string(),
        format!(
            "4 0 obj\n<< /Length {} >>\nstream\n{}endstream\nendobj\n",
            page_stream_payload.len(),
            page_stream_payload
        ),
        "5 0 obj\n<< /Type /Font /Subtype /Type0 /BaseFont /Dummy /Encoding /Identity-H /DescendantFonts [6 0 R] /ToUnicode 8 0 R >>\nendobj\n"
            .to_string(),
        "6 0 obj\n<< /Type /Font /Subtype /CIDFontType2 /BaseFont /Dummy /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor 7 0 R >>\nendobj\n"
            .to_string(),
        "7 0 obj\n<< /Type /FontDescriptor /FontName /Dummy /Flags 4 /FontBBox [0 -200 1000 900] /Ascent 800 /Descent -200 /CapHeight 700 /ItalicAngle 0 /StemV 80 >>\nendobj\n"
            .to_string(),
        format!(
            "8 0 obj\n<< /Length {} >>\nstream\n{}endstream\nendobj\n",
            cmap_payload.len(),
            cmap_payload
        ),
    ];
    build_pdf(&objects, 9)
}

#[test]
fn detects_parser_divergence_findings() {
    let bytes = build_divergence_fixture();
    let detectors = default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");
    let kinds = report.findings.iter().map(|finding| finding.kind.as_str()).collect::<Vec<_>>();
    assert!(kinds.contains(&"duplicate_stream_filters"));
    assert!(kinds.contains(&"content_stream_anomaly"));
    assert!(kinds.contains(&"parser_divergence_risk"));
}

#[test]
fn detects_linearization_integrity_finding() {
    let bytes = build_linearization_integrity_fixture();
    let detectors = default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");
    assert!(report.findings.iter().any(|finding| finding.kind == "linearization_integrity"));
}

#[test]
fn valid_text_operators_do_not_raise_content_stream_anomaly() {
    let bytes = build_valid_text_operator_fixture();
    let detectors = default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");
    assert!(
        report.findings.iter().all(|finding| finding.kind != "content_stream_anomaly"),
        "valid text operator stream should not be classified as content_stream_anomaly"
    );
}

#[test]
fn unknown_operator_records_unknown_op_metadata() {
    let bytes = build_unknown_operator_fixture();
    let detectors = default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == "content_stream_anomaly")
        .expect("content_stream_anomaly should be present");
    assert_eq!(finding.meta.get("content.unknown_ops"), Some(&"1".to_string()));
    let list =
        finding.meta.get("content.unknown_op_list").expect("unknown op list should be present");
    assert!(list.contains("XYZ"));
}

#[test]
fn non_content_cmap_stream_does_not_raise_content_stream_anomaly() {
    let bytes = build_non_content_cmap_fixture();
    let detectors = default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");
    assert!(
        report.findings.iter().all(|finding| finding.kind != "content_stream_anomaly"),
        "non-page content streams like ToUnicode CMaps should not trigger content_stream_anomaly"
    );
}
