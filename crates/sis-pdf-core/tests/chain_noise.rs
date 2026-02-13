mod common;

use common::default_scan_opts;
use sis_pdf_core::runner::run_scan_with_detectors;
use sis_pdf_detectors::default_detectors;

#[test]
fn uri_analysis_chain_is_retained_for_visibility() {
    let bytes = include_bytes!("../../sis-pdf-detectors/tests/fixtures/uri_simple.pdf");
    let detectors = default_detectors();
    let report = run_scan_with_detectors(bytes, default_scan_opts(), &detectors).expect("scan");

    assert!(
        report.chains.iter().any(|chain| chain.action.as_deref() == Some("uri_content_analysis")),
        "URI analysis chains should be retained"
    );
}
