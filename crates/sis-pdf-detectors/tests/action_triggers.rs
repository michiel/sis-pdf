mod common;
use common::default_scan_opts;

#[test]
fn complex_action_reports_chain_metadata() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/action_chain_complex.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(bytes, default_scan_opts(), &detectors)
            .expect("scan");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "action_chain_complex")
        .expect("action_chain_complex finding");
    let depth = finding
        .meta
        .get("action.chain_depth")
        .and_then(|v| v.parse::<usize>().ok())
        .expect("chain depth");
    assert!(depth >= 3, "expected depth >= threshold");
    assert_eq!(finding.meta.get("action.trigger_type").map(String::as_str), Some("automatic"));
    assert!(finding
        .meta
        .get("action.chain_path")
        .map(|path| path.starts_with("OpenAction"))
        .unwrap_or(false));
}

#[test]
fn hidden_action_reports_trigger_type() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/action_hidden_trigger.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(bytes, default_scan_opts(), &detectors)
            .expect("scan");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "action_hidden_trigger")
        .expect("hidden trigger finding");
    assert_eq!(finding.meta.get("action.trigger_type").map(String::as_str), Some("hidden"));
    assert!(finding
        .meta
        .get("action.chain_path")
        .map(|path| path.contains("annotation"))
        .unwrap_or(false));
}
