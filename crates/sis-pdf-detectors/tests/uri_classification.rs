mod common;

use common::default_scan_opts;
use sis_pdf_detectors::{default_detectors, uri_classification::analyze_uri_content};

// ---------------------------------------------------------------------------
// Minimal PDF builder (same pattern as action_trigger_chain_context tests)
// ---------------------------------------------------------------------------

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
    pdf.extend_from_slice(format!("xref\n0 {size}\n").as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        if *offset == 0 {
            pdf.extend_from_slice(b"0000000000 00000 f \n");
        } else {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
    }
    pdf.extend_from_slice(
        format!("trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{start_xref}\n%%EOF\n")
            .as_bytes(),
    );
    pdf
}

#[test]
fn parses_authority_and_flags_phishing_indicators() {
    let content =
        analyze_uri_content(b"http://user:pass@evil.tk:8080/login?email=test@example.com");
    assert_eq!(content.domain.as_deref(), Some("evil.tk"));
    assert_eq!(content.port, Some(8080));
    assert!(content.userinfo_present);
    assert!(content.suspicious_tld);
    assert!(content.has_non_standard_port);
    assert!(content.phishing_indicators.contains(&"credential_keyword".to_string()));
    assert!(content.phishing_indicators.contains(&"userinfo_in_url".to_string()));
    assert!(content.phishing_indicators.contains(&"non_standard_port".to_string()));
}

#[test]
fn treats_javascript_uris_as_non_hierarchical() {
    let content = analyze_uri_content(b"javascript:alert(1)");
    assert!(content.is_javascript_uri);
    assert!(content.domain.is_none());
    assert_eq!(content.path.as_deref(), Some("alert(1)"));
}

#[test]
fn detects_tracking_params_and_ip_addresses() {
    let content = analyze_uri_content(b"http://192.168.0.1/update?utm_source=pdf");
    assert!(content.is_ip_address);
    assert!(content.tracking_params.iter().any(|p| p == "utm_source"));
    assert!(content.phishing_indicators.contains(&"ip_address".to_string()));
}

#[test]
fn flags_shorteners_and_suspicious_extensions() {
    let shortener = analyze_uri_content(b"https://t.co/abc123");
    assert!(shortener.has_shortener_domain);

    let suspicious = analyze_uri_content(b"https://example.com/payload.exe");
    assert!(suspicious.has_suspicious_extension);
}

#[test]
fn flags_suspicious_schemes_and_embedded_ip_hosts() {
    let scheme = analyze_uri_content(b"ms-word:ofe|u|http://example.com");
    assert!(scheme.has_suspicious_scheme);

    let embedded_ip = analyze_uri_content(b"https://1-2-3-4.nip.io/landing");
    assert!(embedded_ip.has_embedded_ip_host);
}

#[test]
fn parses_data_uri_and_idn_lookalikes() {
    let data_uri =
        analyze_uri_content(b"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==");
    assert!(data_uri.is_data_uri);
    assert!(data_uri.data_is_base64);
    assert_eq!(data_uri.data_mime.as_deref(), Some("text/html"));
    assert!(data_uri.data_length.unwrap_or(0) > 0);

    let idn = analyze_uri_content("http://ex\u{0430}mple.com/login".as_bytes());
    assert!(idn.has_idn_lookalike);
}

#[test]
fn uri_listing_aggregates_metadata() {
    let bytes = include_bytes!("fixtures/uri_simple.pdf");
    let detectors = default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(bytes, default_scan_opts(), &detectors)
            .expect("scan");

    let listing =
        report.findings.iter().find(|f| f.kind == "uri_listing").expect("uri_listing finding");

    assert!(
        listing.meta.get("uri.count_total").and_then(|v| v.parse::<usize>().ok()).unwrap_or(0) > 0,
        "aggregate finding should count URIs"
    );
    assert!(listing.meta.contains_key("uri.suspicious_count"));
    assert!(listing.meta.contains_key("uri.max_severity"));
    assert!(listing.meta.contains_key("uri.max_confidence"));
    assert!(listing.meta.contains_key("uri.risk_band_counts"));
    assert!(listing.meta.contains_key("uri.list.0.url"));
    assert!(listing.meta.contains_key("uri.list.0.canonical"));
    assert!(listing.meta.contains_key("uri.list.0.chain_depth"));
    assert!(listing.meta.contains_key("uri.list.0.severity"));
    assert!(listing.meta.contains_key("uri.list.0.confidence"));
    assert!(listing.meta.contains_key("uri.list.limit"));
    assert!(listing.meta.contains_key("uri.scan.limit"));
    assert!(listing.meta.contains_key("uri.listing.schema_version"));

    assert!(
        report.findings.iter().all(|f| f.kind != "uri_present"),
        "retired uri_present finding should not be emitted"
    );
}

// ---------------------------------------------------------------------------
// UNC path / NTLM risk detection
// ---------------------------------------------------------------------------

#[test]
fn detects_unc_backslash_form() {
    // Windows UNC path: \\attacker\share
    let content = analyze_uri_content(b"\\\\attacker\\share");
    assert!(content.has_unc_path, "backslash-form UNC should be flagged");
}

#[test]
fn detects_unc_slash_form_without_scheme() {
    // Slash-form without scheme: //attacker/share
    let content = analyze_uri_content(b"//attacker/share");
    assert!(content.has_unc_path, "slash-form UNC with no scheme should be flagged");
}

#[test]
fn does_not_flag_normal_https_double_slash() {
    let content = analyze_uri_content(b"https://example.com/path");
    assert!(!content.has_unc_path, "https:// URL must not be flagged as UNC");
}

#[test]
fn uri_annotation_with_unc_path_emits_ntlm_finding() {
    // PDF with a /URI annotation whose target is a Windows UNC path.
    // The UNC value in hex: \\attacker\share = 5c5c617474 61636b65725c7368617265
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >>\nendobj\n",
        "4 0 obj\n<< /Type /Annot /Subtype /Link /Rect [0 0 100 100] /A 5 0 R >>\nendobj\n",
        // /URI value is \\attacker\share encoded as a hex string to avoid PDF escape ambiguity
        "5 0 obj\n<< /S /URI /URI <5c5c61747461636b65725c7368617265> >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let detectors = default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");

    assert!(
        report.findings.iter().any(|f| f.kind == "uri_unc_path_ntlm_risk"),
        "uri_unc_path_ntlm_risk finding must be emitted for a /URI action with UNC path; \
         findings: {:?}",
        report.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "uri_unc_path_ntlm_risk")
        .unwrap();
    assert_eq!(finding.severity, sis_pdf_core::model::Severity::High);
    assert_eq!(finding.confidence, sis_pdf_core::model::Confidence::Strong);
    assert!(finding.meta.contains_key("uri.unc_path"), "meta must contain uri.unc_path");
}
