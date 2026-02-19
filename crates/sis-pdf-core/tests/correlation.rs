use std::collections::HashMap;

use sis_pdf_core::correlation;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::runner::run_scan_with_detectors;
use sis_pdf_core::scan::{
    CorrelationOptions, FontAnalysisOptions, ImageAnalysisOptions, ProfileFormat, ScanOptions,
};
use sis_pdf_detectors::default_detectors;

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
        impact: None,
        title: kind.into(),
        description: "test".into(),
        objects: objects.iter().map(|o| o.to_string()).collect(),
        evidence: Vec::new(),
        remediation: None,
        meta: meta_map,
        reader_impacts: Vec::new(),
        action_type: None,
        action_target: None,
        action_initiation: None,
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
        &[("launch.embedded_file_hash", "deadbeef"), ("launch.target_path", "payload.exe")],
        AttackSurface::Actions,
    );

    let config = CorrelationOptions::default();
    let composites = correlation::correlate_findings(&[embedded.clone(), launch.clone()], &config);
    assert!(composites.iter().any(|f| f.kind == "launch_obfuscated_executable"));
}

#[test]
fn correlate_action_chain_malicious() {
    let chain = make_finding(
        "action_chain_complex",
        &["10 0 obj"],
        &[("action.chain_depth", "4"), ("action.trigger", "OpenAction")],
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

    let config = CorrelationOptions::default();
    let composites =
        correlation::correlate_findings(&[chain.clone(), automatic.clone(), js.clone()], &config);
    assert!(composites.iter().any(|f| f.kind == "action_chain_malicious"));
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

    let config = CorrelationOptions::default();
    let composites = correlation::correlate_findings(&[submit.clone(), sensitive.clone()], &config);
    assert!(composites.iter().any(|f| f.kind == "xfa_data_exfiltration_risk"));
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

    let config = CorrelationOptions::default();
    let composites = correlation::correlate_findings(&[archive.clone(), launch.clone()], &config);
    assert!(composites.iter().any(|f| f.kind == "encrypted_payload_delivery"));
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

    let config = CorrelationOptions::default();
    let composites = correlation::correlate_findings(&[filter.clone(), entropy.clone()], &config);
    assert!(composites.iter().any(|f| f.kind == "obfuscated_payload"));
}

#[test]
fn correlate_image_decoder_exploit_chain() {
    let jbig2 = make_finding(
        "image.zero_click_jbig2",
        &["11 0 obj"],
        &[("image.format", "JBIG2")],
        AttackSurface::Images,
    );
    let decoder = make_finding(
        "decoder_risk_present",
        &["11 0 obj"],
        &[("decoder.risk.score", "0.95")],
        AttackSurface::StreamsAndFilters,
    );
    let exhaustion = make_finding(
        "parser_resource_exhaustion",
        &["parser"],
        &[("resource_consumption.total_ms", "9000")],
        AttackSurface::FileStructure,
    );

    let composites = correlation::correlate_findings(
        &[jbig2, decoder, exhaustion],
        &CorrelationOptions::default(),
    );
    assert!(composites.iter().any(|f| f.kind == "image_decoder_exploit_chain"));
}

#[test]
fn correlate_resource_external_with_trigger_surface() {
    let external = make_finding(
        "resource.external_reference_high_risk_scheme",
        &["60 0 obj"],
        &[("resource.high_risk_scheme_count", "1")],
        AttackSurface::Actions,
    );
    let trigger = make_finding(
        "action_automatic_trigger",
        &["60 0 obj"],
        &[("action.trigger", "OpenAction")],
        AttackSurface::Actions,
    );
    let composites =
        correlation::correlate_findings(&[external, trigger], &CorrelationOptions::default());
    assert!(composites
        .iter()
        .any(|f| f.kind == "composite.resource_external_with_trigger_surface"));
}

#[test]
fn correlate_decode_amplification_chain() {
    let a = make_finding(
        "image.decode_too_large",
        &["70 0 obj"],
        &[("image.decode_too_large", "true")],
        AttackSurface::Images,
    );
    let b = make_finding(
        "font_payload_present",
        &["71 0 obj"],
        &[("font.stream_len", "5000000")],
        AttackSurface::StreamsAndFilters,
    );
    let c = make_finding(
        "resource.provenance_xref_conflict",
        &["71 0 obj"],
        &[("resource.object_shadowed_revisions", "2")],
        AttackSurface::FileStructure,
    );
    let composites = correlation::correlate_findings(&[a, b, c], &CorrelationOptions::default());
    let decode_chain = composites
        .iter()
        .find(|f| f.kind == "composite.decode_amplification_chain")
        .expect("decode amplification composite should exist");
    assert_eq!(decode_chain.severity, Severity::High);
    assert_eq!(decode_chain.confidence, Confidence::Strong);
    assert_eq!(decode_chain.impact, None);

    let override_chain = composites
        .iter()
        .find(|f| f.kind == "composite.resource_overrides_with_decoder_pressure")
        .expect("override/decoder-pressure composite should exist");
    assert_eq!(override_chain.severity, Severity::High);
    assert_eq!(override_chain.confidence, Confidence::Probable);
    assert_eq!(override_chain.impact, None);
}

#[test]
fn correlate_injection_edge_bridges_for_scatter_and_submitform() {
    let html = make_finding(
        "form_html_injection",
        &["81 0 obj"],
        &[("chain.stage", "render"), ("field.name", "payloadField")],
        AttackSurface::Forms,
    );
    let pdfjs = make_finding(
        "pdfjs_form_injection",
        &["81 0 obj"],
        &[("chain.stage", "render"), ("field.name", "payloadField")],
        AttackSurface::Forms,
    );
    let submit = make_finding(
        "submitform_present",
        &["81 0 obj"],
        &[("chain.stage", "egress")],
        AttackSurface::Actions,
    );
    let scattered = make_finding(
        "scattered_payload_assembly",
        &["81 0 obj"],
        &[("chain.stage", "decode"), ("scatter.fragment_count", "3")],
        AttackSurface::Forms,
    );

    let composites = correlation::correlate_findings(
        &[html, pdfjs, submit, scattered],
        &CorrelationOptions::default(),
    );

    let mut reasons = composites
        .iter()
        .filter(|finding| finding.kind == "composite.injection_edge_bridge")
        .filter_map(|finding| finding.meta.get("edge.reason"))
        .cloned()
        .collect::<Vec<_>>();
    reasons.sort();
    reasons.dedup();

    assert!(reasons.contains(&"form_html_to_pdfjs_form".to_string()));
    assert!(reasons.contains(&"injection_to_submitform".to_string()));
    assert!(reasons.contains(&"scatter_to_injection".to_string()));

    let scatter_bridge = composites
        .iter()
        .find(|finding| {
            finding.kind == "composite.injection_edge_bridge"
                && finding.meta.get("edge.reason").map(String::as_str)
                    == Some("scatter_to_injection")
        })
        .expect("scatter bridge should be present");
    assert_eq!(scatter_bridge.confidence, Confidence::Strong);
    assert_eq!(
        scatter_bridge.meta.get("edge.shared_objects").map(String::as_str),
        Some("81 0 obj")
    );
}

#[test]
fn correlate_injection_edge_bridges_for_name_obfuscation_and_action() {
    let obfuscated_name = make_finding(
        "obfuscated_name_encoding",
        &["90 0 obj"],
        &[("chain.stage", "decode"), ("pdf.name.raw", "/Jav#61Script")],
        AttackSurface::FileStructure,
    );
    let action = make_finding(
        "action_automatic_trigger",
        &["90 0 obj"],
        &[("chain.stage", "execute"), ("action.trigger", "OpenAction")],
        AttackSurface::Actions,
    );

    let composites =
        correlation::correlate_findings(&[obfuscated_name, action], &CorrelationOptions::default());
    let bridge = composites
        .iter()
        .find(|finding| {
            finding.kind == "composite.injection_edge_bridge"
                && finding.meta.get("edge.reason").map(String::as_str)
                    == Some("name_obfuscation_to_action")
        })
        .expect("name obfuscation bridge should be present");

    assert_eq!(bridge.confidence, Confidence::Probable);
    assert_eq!(bridge.meta.get("edge.from").map(String::as_str), Some("obfuscated_name_encoding"));
    assert_eq!(bridge.meta.get("edge.to").map(String::as_str), Some("action_automatic_trigger"));
}

#[test]
fn correlation_launch_obfuscated_integration() {
    let detectors = default_detectors();
    let report = run_scan_with_detectors(
        &build_launch_obfuscated_pdf(&high_entropy_payload()),
        scan_opts(false),
        &detectors,
    )
    .expect("scan should succeed");

    assert!(report.findings.iter().any(|f| f.kind == "launch_obfuscated_executable"));
}

#[test]
fn correlation_xfa_data_exfiltration_integration() {
    let detectors = default_detectors();
    let report = run_scan_with_detectors(
        include_bytes!("fixtures/xfa/xfa_submit_sensitive.pdf"),
        scan_opts(false),
        &detectors,
    )
    .expect("scan should succeed");

    assert!(report.findings.iter().any(|f| f.kind == "xfa_data_exfiltration_risk"));
}

#[test]
fn correlation_obfuscated_payload_integration() {
    let detectors = default_detectors();
    let report = run_scan_with_detectors(
        include_bytes!("fixtures/filters/filter_unusual_chain.pdf"),
        scan_opts(true),
        &detectors,
    )
    .expect("scan should succeed");

    let filter_finding = report
        .findings
        .iter()
        .find(|f| f.kind == "filter_chain_unusual")
        .expect("expected filter_chain_unusual finding");

    let mut meta = std::collections::HashMap::new();
    if let Some(violation) = filter_finding.meta.get("violation_type") {
        meta.insert("violation_type".into(), violation.clone());
    }
    meta.insert("entropy".into(), "7.8".into());

    let stream_finding = Finding {
        id: String::new(),
        surface: filter_finding.surface,
        kind: "stream_high_entropy".into(),
        severity: Severity::Low,
        confidence: Confidence::Probable,
        impact: None,
        title: "Synthetic high entropy stream".into(),
        description: "Synthetic high entropy stream for correlation.".into(),
        objects: filter_finding.objects.clone(),
        evidence: Vec::new(),
        remediation: None,
        meta,
        reader_impacts: Vec::new(),
        action_type: None,
        action_target: None,
        action_initiation: None,
        yara: None,
        position: None,
        positions: Vec::new(),
    };

    let mut augmented = report.findings.clone();
    augmented.push(stream_finding);

    let composites = correlation::correlate_findings(&augmented, &CorrelationOptions::default());
    assert!(composites.iter().any(|f| f.kind == "obfuscated_payload"));
}

fn scan_opts(deep: bool) -> ScanOptions {
    ScanOptions {
        deep,
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
        image_analysis: ImageAnalysisOptions::default(),
        filter_allowlist: None,
        filter_allowlist_strict: false,
        profile: false,
        profile_format: ProfileFormat::Text,
        group_chains: true,
        correlation: CorrelationOptions::default(),
    }
}

fn high_entropy_payload() -> Vec<u8> {
    let mut payload = Vec::with_capacity(1024);
    payload.extend_from_slice(b"MZ");
    payload.extend((0u8..=255).cycle().take(1022));
    payload
}

fn build_launch_obfuscated_pdf(payload: &[u8]) -> Vec<u8> {
    let mut doc = Vec::new();
    doc.extend_from_slice(b"%PDF-1.7\n");
    let mut offsets = Vec::new();

    append_text_object(
        &mut doc,
        &mut offsets,
        1,
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\n",
    );
    append_text_object(&mut doc, &mut offsets, 2, b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>\n");
    append_text_object(&mut doc, &mut offsets, 3, b"<< /Type /Page /Parent 2 0 R >>\n");
    append_text_object(&mut doc, &mut offsets, 4, b"<< /Type /Action /S /Launch /F 5 0 R >>\n");
    append_text_object(
        &mut doc,
        &mut offsets,
        5,
        b"<< /Type /Filespec /F (payload.exe) /EF << /F 6 0 R >> >>\n",
    );

    let offset = doc.len();
    offsets.push(offset);
    doc.extend_from_slice(b"6 0 obj << /Type /EmbeddedFile /Length ");
    doc.extend_from_slice(payload.len().to_string().as_bytes());
    doc.extend_from_slice(b" >>\nstream\n");
    doc.extend_from_slice(payload);
    doc.extend_from_slice(b"\nendstream\nendobj\n");

    let xref_offset = doc.len();
    doc.extend_from_slice(b"xref\n0 7\n");
    doc.extend_from_slice(b"0000000000 65535 f \n");
    for offset in &offsets {
        doc.extend_from_slice(format!("{:010} 00000 n \n", offset).as_bytes());
    }
    doc.extend_from_slice(b"trailer << /Size 7 /Root 1 0 R >>\n");
    doc.extend_from_slice(format!("startxref\n{}\n%%EOF\n", xref_offset).as_bytes());

    doc
}

fn append_text_object(doc: &mut Vec<u8>, offsets: &mut Vec<usize>, number: usize, content: &[u8]) {
    offsets.push(doc.len());
    doc.extend_from_slice(format!("{} 0 obj\n", number).as_bytes());
    doc.extend_from_slice(content);
    if !content.ends_with(b"\n") {
        doc.extend_from_slice(b"\n");
    }
    doc.extend_from_slice(b"endobj\n");
}
