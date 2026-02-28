use sis_pdf_core::scan::{CorrelationOptions, FontAnalysisOptions, ProfileFormat, ScanOptions};
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

fn scan_opts() -> ScanOptions {
    ScanOptions {
        deep: true,
        max_decode_bytes: 8 * 1024 * 1024,
        max_total_decoded_bytes: 64 * 1024 * 1024,
        recover_xref: true,
        parallel: false,
        batch_parallel: false,
        diff_parser: false,
        max_objects: 100_000,
        max_recursion_depth: 64,
        fast: false,
        focus_trigger: None,
        focus_depth: 0,
        yara_scope: None,
        strict: false,
        strict_summary: false,
        ir: false,
        ml_config: None,
        font_analysis: FontAnalysisOptions::default(),
        image_analysis: sis_pdf_core::scan::ImageAnalysisOptions::default(),
        filter_allowlist: None,
        filter_allowlist_strict: false,
        profile: false,
        profile_format: ProfileFormat::Text,
        group_chains: true,
        correlation: CorrelationOptions::default(),
        per_file_timeout_ms: None,
    }
}

#[test]
fn content_stream_anomaly_reports_unknown_operator_metadata() {
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
    let bytes = build_pdf(&objects, 5);
    let detectors = default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(&bytes, scan_opts(), &detectors)
        .expect("scan should succeed");

    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == "content_stream_anomaly")
        .expect("content_stream_anomaly should be present");
    assert_eq!(finding.severity, sis_pdf_core::model::Severity::Medium);
    assert_eq!(finding.confidence, sis_pdf_core::model::Confidence::Probable);
    assert_eq!(finding.impact, sis_pdf_core::model::Impact::Low);
    assert_eq!(finding.meta.get("content.unknown_ops"), Some(&"1".to_string()));
    assert_eq!(finding.meta.get("content.arity_mismatches"), Some(&"0".to_string()));
    assert_eq!(finding.meta.get("content.type_mismatches"), Some(&"0".to_string()));
    let unknown_list =
        finding.meta.get("content.unknown_op_list").expect("unknown op list should be present");
    assert!(unknown_list.contains("XYZ"));
}
