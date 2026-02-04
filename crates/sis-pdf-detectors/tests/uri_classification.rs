use sis_pdf_detectors::uri_classification::analyze_uri_content;

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
