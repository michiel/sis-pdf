use std::path::PathBuf;

use sis_pdf_core::model::Confidence;
use sis_pdf_core::scan::{CorrelationOptions, FontAnalysisOptions, ProfileFormat, ScanOptions};

#[cfg(feature = "js-sandbox")]
use sis_pdf_detectors::js_sandbox::JavaScriptSandboxDetector;

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_exec_records_calls() {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../crates/sis-pdf-core/tests/fixtures/synthetic.pdf");
    let bytes = std::fs::read(path).expect("read fixture");

    let opts = ScanOptions {
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
    };

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
    assert!(matches!(
        sandbox.confidence,
        Confidence::Probable | Confidence::Tentative | Confidence::Weak
    ));
    assert_eq!(sandbox.meta.get("js.sandbox_exec").map(String::as_str), Some("true"));
}
