use sis_pdf_core::scan::{CorrelationOptions, FontAnalysisOptions, ProfileFormat, ScanOptions};
use sis_pdf_detectors::default_detectors;

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

fn build_pdf_with_icc_stream(icc_profile: &[u8], n_value: i32) -> Vec<u8> {
    let mut doc = Vec::new();
    doc.extend_from_slice(b"%PDF-1.4\n");
    let mut offsets = vec![0usize; 6];

    append_text_object(&mut doc, &mut offsets, 1, b"<< /Type /Catalog /Pages 2 0 R >>\n");
    append_text_object(&mut doc, &mut offsets, 2, b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>\n");
    append_text_object(
        &mut doc,
        &mut offsets,
        3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /DummyICCSpace [/ICCBased 5 0 R] /Contents 4 0 R >>\n",
    );
    append_text_object(&mut doc, &mut offsets, 4, b"<< /Length 0 >>\nstream\n\nendstream\n");

    offsets[5] = doc.len();
    let header = format!(
        "5 0 obj\n<< /N {} /Alternate /DeviceRGB /Length {} >>\nstream\n",
        n_value,
        icc_profile.len()
    );
    doc.extend_from_slice(header.as_bytes());
    doc.extend_from_slice(icc_profile);
    doc.extend_from_slice(b"\nendstream\nendobj\n");

    let startxref = doc.len();
    doc.extend_from_slice(b"xref\n0 6\n0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        doc.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    doc.extend_from_slice(
        format!("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n", startxref).as_bytes(),
    );
    doc
}

fn append_text_object(doc: &mut Vec<u8>, offsets: &mut [usize], object_id: usize, body: &[u8]) {
    offsets[object_id] = doc.len();
    doc.extend_from_slice(format!("{object_id} 0 obj\n").as_bytes());
    doc.extend_from_slice(body);
    doc.extend_from_slice(b"endobj\n");
}

fn malformed_icc_profile_fixture() -> Vec<u8> {
    let mut data = vec![0u8; 160];
    data[0..4].copy_from_slice(&(220u32.to_be_bytes()));
    data[16..20].copy_from_slice(b"RGB ");
    data[36..40].copy_from_slice(b"zzzz");
    data[128..132].copy_from_slice(&(1u32.to_be_bytes()));
    data[132..136].copy_from_slice(b"desc");
    data[136..140].copy_from_slice(&(200u32.to_be_bytes()));
    data[140..144].copy_from_slice(&(80u32.to_be_bytes()));
    data
}

#[test]
fn icc_profile_anomaly_reports_decoded_issue_codes() {
    let bytes = build_pdf_with_icc_stream(&malformed_icc_profile_fixture(), 1);
    let detectors = default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(&bytes, scan_opts(), &detectors)
        .expect("scan should succeed");

    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == "icc_profile_anomaly")
        .expect("icc_profile_anomaly should be present");
    assert_eq!(finding.severity, sis_pdf_core::model::Severity::Medium);
    assert_eq!(finding.confidence, sis_pdf_core::model::Confidence::Probable);
    let issue_codes =
        finding.meta.get("icc.issue_codes").expect("icc.issue_codes should be present");
    assert!(issue_codes.contains("declared_size_exceeds_decoded"));
    assert!(issue_codes.contains("signature_missing"));
    assert!(issue_codes.contains("tag_entry_out_of_bounds"));
    assert_eq!(finding.meta.get("icc.decoded_len"), Some(&"160".to_string()));
    assert_eq!(finding.meta.get("icc.declared_size"), Some(&"220".to_string()));
}
