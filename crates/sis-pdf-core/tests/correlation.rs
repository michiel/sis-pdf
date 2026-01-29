use std::collections::HashMap;

use sis_pdf_core::correlation;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};

fn make_finding(
    kind: &str,
    objects: &[&str],
    meta: &[(&str, &str)],
    surface: AttackSurface,
) -> Finding {
    let mut meta_map = HashMap::new();
    for (key, value) in meta {
        meta_map.insert((*key).to_string(), (*value).to_string());
    }
    Finding {
        id: String::new(),
        surface,
        kind: kind.into(),
        severity: Severity::Info,
        confidence: Confidence::Probable,
        title: kind.into(),
        description: "test".into(),
        objects: objects.iter().map(|o| o.to_string()).collect(),
        evidence: Vec::new(),
        remediation: None,
        meta: meta_map,
        yara: None,
        position: None,
        positions: Vec::new(),
    }
}

#[test]
fn correlate_launch_obfuscated_executable() {
    let embedded = make_finding(
        "embedded_executable_present",
        &["12 0 obj"],
        &[("hash.sha256", "deadbeef"), ("entropy", "8.1")],
        AttackSurface::EmbeddedFiles,
    );
    let launch = make_finding(
        "launch_embedded_file",
        &["4 0 obj"],
        &[
            ("launch.embedded_file_hash", "deadbeef"),
            ("launch.target_path", "payload.exe"),
        ],
        AttackSurface::Actions,
    );

    let composites = correlation::correlate_findings(&[embedded.clone(), launch.clone()]);
    assert!(composites
        .iter()
        .any(|f| f.kind == "launch_obfuscated_executable"));
}

#[test]
fn correlate_action_chain_malicious() {
    let chain = make_finding(
        "action_chain_complex",
        &["10 0 obj"],
        &[
            ("action.chain_depth", "4"),
            ("action.trigger", "OpenAction"),
        ],
        AttackSurface::Actions,
    );
    let automatic = make_finding(
        "action_automatic_trigger",
        &["10 0 obj"],
        &[("action.trigger", "OpenAction")],
        AttackSurface::Actions,
    );
    let js = make_finding(
        "embedded_script_present",
        &["10 0 obj"],
        &[("embedded.filename", "payload.js")],
        AttackSurface::EmbeddedFiles,
    );

    let composites =
        correlation::correlate_findings(&[chain.clone(), automatic.clone(), js.clone()]);
    assert!(composites
        .iter()
        .any(|f| f.kind == "action_chain_malicious"));
}

#[test]
fn correlate_xfa_data_exfiltration_risk() {
    let submit = make_finding(
        "xfa_submit",
        &["20 0 obj"],
        &[("xfa.submit.url", "https://evil.com/post")],
        AttackSurface::Forms,
    );
    let sensitive = make_finding(
        "xfa_sensitive_field",
        &["20 0 obj"],
        &[("xfa.field.name", "password")],
        AttackSurface::Forms,
    );

    let composites = correlation::correlate_findings(&[submit.clone(), sensitive.clone()]);
    assert!(composites
        .iter()
        .any(|f| f.kind == "xfa_data_exfiltration_risk"));
}

#[test]
fn correlate_encrypted_payload_delivery() {
    let archive = make_finding(
        "embedded_archive_encrypted",
        &["30 0 obj"],
        &[("hash.sha256", "abc")],
        AttackSurface::EmbeddedFiles,
    );
    let launch = make_finding(
        "launch_embedded_file",
        &["30 0 obj"],
        &[("launch.embedded_file_hash", "abc")],
        AttackSurface::Actions,
    );

    let composites = correlation::correlate_findings(&[archive.clone(), launch.clone()]);
    assert!(composites
        .iter()
        .any(|f| f.kind == "encrypted_payload_delivery"));
}

#[test]
fn correlate_obfuscated_payload() {
    let filter = make_finding(
        "filter_chain_unusual",
        &["40 0 obj"],
        &[("violation_type", "allowlist_miss")],
        AttackSurface::StreamsAndFilters,
    );
    let entropy = make_finding(
        "stream_high_entropy",
        &["40 0 obj"],
        &[("stream.entropy", "7.8")],
        AttackSurface::StreamsAndFilters,
    );

    let composites = correlation::correlate_findings(&[filter.clone(), entropy.clone()]);
    assert!(composites.iter().any(|f| f.kind == "obfuscated_payload"));
}
