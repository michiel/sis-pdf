mod common;
use common::default_scan_opts;

#[test]
fn detects_swf_action_tags() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/media/swf_cve_2011_0611.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(bytes, default_scan_opts(), &detectors)
            .expect("scan");

    let swf_filtered: Vec<&_> = report
        .findings
        .iter()
        .filter(|f| f.kind == "swf_actionscript_detected")
        .collect();
    assert!(!swf_filtered.is_empty(), "expected ActionScript finding");
    let meta = &swf_filtered[0].meta;
    assert_eq!(
        meta.get("swf.action_tag_count").map(String::as_str),
        Some("1")
    );
    assert!(
        meta.get("swf.action_tags")
            .map(|value| value.contains("DoABC"))
            .unwrap_or(false),
        "expected DoABC name"
    );
}
