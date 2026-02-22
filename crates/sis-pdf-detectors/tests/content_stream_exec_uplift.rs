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

fn build_abusive_fixture() -> Vec<u8> {
    let mut gstate_prefix = String::new();
    for _ in 0..29 {
        gstate_prefix.push_str("q\n");
    }
    let mut gstate_suffix = String::new();
    for _ in 0..30 {
        gstate_suffix.push_str("Q\n");
    }

    let mut outside_noise = String::new();
    for _ in 0..18 {
        outside_noise.push_str("q Q\n");
    }

    let stream_payload = format!(
        "{}q /FmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA Do Q\n{}\n/MC BMC /FmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA Do /F1 12 Tf /FmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA Do /F1 12 Tf /FmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA Do /F1 12 Tf /FmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA Do /F1 12 Tf /FmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA Do EMC\n",
        gstate_prefix,
        gstate_suffix
    ) + &outside_noise;

    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R /Resources << /Font << /F1 6 0 R >> /XObject << /FmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 5 0 R >> >> >>\nendobj\n"
            .to_string(),
        format!(
            "4 0 obj\n<< /Length {} >>\nstream\n{}endstream\nendobj\n",
            stream_payload.len(),
            stream_payload
        ),
        "5 0 obj\n<< /Type /XObject /Subtype /Form /BBox [0 0 10 10] /Length 0 >>\nstream\n\nendstream\nendobj\n"
            .to_string(),
        "6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n".to_string(),
    ];
    build_pdf(&objects, 7)
}

fn build_clean_fixture() -> Vec<u8> {
    let payload = "BT /F1 12 Tf (hello) Tj ET\n";
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
            .to_string(),
        format!(
            "4 0 obj\n<< /Length {} >>\nstream\n{}endstream\nendobj\n",
            payload.len(),
            payload
        ),
        "5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n".to_string(),
    ];
    build_pdf(&objects, 6)
}

#[test]
fn detects_content_stream_exec_uplift_findings() {
    let bytes = build_abusive_fixture();
    let detectors = default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");
    let kinds = report.findings.iter().map(|finding| finding.kind.as_str()).collect::<Vec<_>>();

    assert!(report.findings.iter().any(|finding| finding.kind == "content_stream_gstate_abuse"));
    assert!(
        report.findings.iter().any(|finding| finding.kind == "content_stream_marked_evasion"),
        "missing content_stream_marked_evasion; kinds={kinds:?}"
    );
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.kind == "content_stream_resource_name_obfuscation"));

    let gstate = report
        .findings
        .iter()
        .find(|finding| finding.kind == "content_stream_gstate_abuse")
        .expect("gstate finding");
    assert!(gstate
        .meta
        .get("gstate.max_depth")
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|depth| depth > 28));
}

#[test]
fn clean_stream_does_not_emit_uplift_findings() {
    let bytes = build_clean_fixture();
    let detectors = default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");

    assert!(report.findings.iter().all(|finding| finding.kind != "content_stream_gstate_abuse"));
    assert!(report.findings.iter().all(|finding| finding.kind != "content_stream_marked_evasion"));
    assert!(report
        .findings
        .iter()
        .all(|finding| finding.kind != "content_stream_resource_name_obfuscation"));
}
