use sis_pdf_core::scan::{CorrelationOptions, FontAnalysisOptions, ProfileFormat, ScanOptions};

/// Build a minimal PDF with a separate AcroForm object whose `/XFA` entry points
/// to a stream containing `xfa_content`.  The detector searches for `/XFA` at the
/// top level of any dict object, so the AcroForm must be a standalone object.
fn build_xfa_pdf(xfa_content: &[u8]) -> Vec<u8> {
    let content_len = xfa_content.len();
    let mut pdf = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.4\n");

    // obj 1: Catalog → Pages (obj 2) + AcroForm (obj 3)
    let obj1_offset = pdf.len();
    pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 3 0 R >>\nendobj\n");

    // obj 2: Pages
    let obj2_offset = pdf.len();
    pdf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n");

    // obj 3: AcroForm with /XFA → obj 4 (the stream)
    let obj3_offset = pdf.len();
    pdf.extend_from_slice(b"3 0 obj\n<< /XFA 4 0 R >>\nendobj\n");

    // obj 4: XFA stream
    let obj4_offset = pdf.len();
    pdf.extend_from_slice(format!("4 0 obj\n<< /Length {} >>\nstream\n", content_len).as_bytes());
    pdf.extend_from_slice(xfa_content);
    pdf.extend_from_slice(b"\nendstream\nendobj\n");

    let xref_offset = pdf.len();
    pdf.extend_from_slice(b"xref\n0 5\n");
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    pdf.extend_from_slice(format!("{:010} 00000 n \n", obj1_offset).as_bytes());
    pdf.extend_from_slice(format!("{:010} 00000 n \n", obj2_offset).as_bytes());
    pdf.extend_from_slice(format!("{:010} 00000 n \n", obj3_offset).as_bytes());
    pdf.extend_from_slice(format!("{:010} 00000 n \n", obj4_offset).as_bytes());
    pdf.extend_from_slice(
        format!("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n", xref_offset)
            .as_bytes(),
    );
    pdf
}

fn opts() -> ScanOptions {
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
fn detects_xfa_submit_and_sensitive_fields() {
    let bytes = include_bytes!("fixtures/xfa/xfa_submit_sensitive.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains("xfa_submit"));
    assert!(kinds.contains("xfa_sensitive_field"));
    assert!(kinds.contains("xfa_script_count_high"));
}

#[test]
fn detects_xfa_too_large() {
    let bytes = include_bytes!("fixtures/xfa/xfa_large.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains("xfa_too_large"));
}

#[test]
fn rejects_xfa_doctype_payloads() {
    let bytes = include_bytes!("fixtures/xfa/xfa_doctype_submit.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(!kinds.contains("xfa_submit"));
    assert!(!kinds.contains("xfa_sensitive_field"));
    assert!(!kinds.contains("xfa_script_count_high"));
}

#[test]
fn detects_xfa_execute_tags_as_scripts() {
    let bytes = include_bytes!("fixtures/xfa/xfa_execute_high.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains("xfa_script_count_high"));
}

#[test]
fn xfa_submit_finding_reports_metadata() {
    let bytes = include_bytes!("fixtures/xfa/xfa_submit_sensitive.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    let finding =
        report.findings.iter().find(|f| f.kind == "xfa_submit").expect("xfa_submit finding");

    let script_count = finding
        .meta
        .get("xfa.script_count")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    assert!(script_count >= 1, "expected script count metadata");
    assert_eq!(
        finding.meta.get("xfa.submit.url").map(String::as_str),
        Some("https://example.com/submit")
    );
    let sensitive = finding.meta.get("xfa.sensitive_fields").expect("sensitive field metadata");
    assert!(sensitive.contains("user.password"), "expected password field in {}", sensitive);
}

#[test]
fn xfa_cve_2013_2729_reports_script_presence() {
    let bytes = include_bytes!("fixtures/xfa/xfa_cve_2013_2729.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts(), &detectors)
        .expect("scan should succeed");

    assert!(
        report.findings.iter().any(|f| f.kind == "xfa_script_present"),
        "expected xfa_script_present finding"
    );
}

#[test]
fn xfa_deep_scan_detects_eval_in_script() {
    // A minimal XFA payload with eval() in a <xfa:script> block. The deep scan
    // should forward the script to static JS analysis and emit xfa_js.eval_detected.
    let xfa_content = b"<?xml version='1.0'?>\
        <xdp:xdp xmlns:xdp='http://ns.adobe.com/xdp/'>\
        <xfa:script xmlns:xfa='http://www.xfa.org/schema/xfa-template/2.5/'>\
        eval(\"app.alert(1)\");\
        </xfa:script>\
        </xdp:xdp>";
    let pdf = build_xfa_pdf(xfa_content);

    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(&pdf, opts(), &detectors)
        .expect("scan should succeed");

    assert!(
        report.findings.iter().any(|f| f.kind == "xfa_js.eval_detected"),
        "deep scan should emit xfa_js.eval_detected for XFA script with eval(); \
         findings: {:?}",
        report.findings.iter().map(|f| f.kind.as_str()).collect::<Vec<_>>()
    );
}
