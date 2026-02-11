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
