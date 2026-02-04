mod common;
use common::default_scan_opts;

#[test]
fn detectors_flag_launch_external_program() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/launch_action.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(bytes, default_scan_opts(), &detectors)
            .expect("scan");

    assert!(
        report.findings.iter().any(|f| f.kind == "launch_action_present"),
        "expected launch_action_present finding"
    );
    let external = report
        .findings
        .iter()
        .find(|f| f.kind == "launch_external_program")
        .expect("generic external launch finding");
    assert_eq!(external.meta.get("launch.target_type").map(String::as_str), Some("external"));
    assert!(
        external.meta.get("launch.target_path").map(|v| v.contains("calc.exe")).unwrap_or(false),
        "expected launch target to include calc.exe"
    );
}
