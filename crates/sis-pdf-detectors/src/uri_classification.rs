use anyhow::Result;
use std::collections::{HashMap, HashSet};

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::evidence::preview_ascii;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_core::scan::ScanContext;
use sis_pdf_pdf::graph::ObjEntry;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};
use sis_pdf_pdf::typed_graph::EdgeType;

use crate::entry_dict;

/// URI content analysis and classification
#[derive(Debug, Clone)]
pub struct UriContentAnalysis {
    pub url: String,
    pub scheme: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub query_params: Vec<(String, String)>,
    pub port: Option<u16>,
    pub userinfo_present: bool,

    // Signals
    pub obfuscation_level: ObfuscationLevel,
    pub tracking_params: Vec<String>,
    pub suspicious_patterns: Vec<String>,
    pub phishing_indicators: Vec<String>,
    pub length: usize,

    // Risk factors
    pub is_ip_address: bool,
    pub is_file_uri: bool,
    pub is_javascript_uri: bool,
    pub is_data_uri: bool,
    pub is_http: bool,
    pub suspicious_tld: bool,
    pub has_data_exfil_pattern: bool,
    pub has_non_standard_port: bool,
    pub has_shortener_domain: bool,
    pub has_suspicious_extension: bool,
    pub has_suspicious_scheme: bool,
    pub has_embedded_ip_host: bool,
    pub has_idn_lookalike: bool,

    // Data URI details
    pub data_mime: Option<String>,
    pub data_is_base64: bool,
    pub data_length: Option<usize>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ObfuscationLevel {
    None,
    Light,  // Some percent-encoding (normal)
    Medium, // Extensive percent-encoding, base64 params
    Heavy,  // Multiple layers, unicode escapes, etc.
}

impl ObfuscationLevel {
    pub fn as_str(&self) -> &str {
        match self {
            ObfuscationLevel::None => "none",
            ObfuscationLevel::Light => "light",
            ObfuscationLevel::Medium => "medium",
            ObfuscationLevel::Heavy => "heavy",
        }
    }
}

#[derive(Debug, Clone)]
pub struct UriContext {
    pub visibility: UriVisibility,
    pub placement: UriPlacement,
    pub rect: Option<[f32; 4]>,
    pub page_bounds: Option<[f32; 4]>,
    pub flags: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum UriVisibility {
    Visible,    // Normal annotation with visible rect
    HiddenRect, // Rect outside page or zero-size
    HiddenFlag, // Annotation flags mark as hidden
    NoAnnot,    // URI not in annotation (action only)
}

impl UriVisibility {
    pub fn as_str(&self) -> &str {
        match self {
            UriVisibility::Visible => "visible",
            UriVisibility::HiddenRect => "hidden_rect",
            UriVisibility::HiddenFlag => "hidden_flag",
            UriVisibility::NoAnnot => "no_annotation",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum UriPlacement {
    Annotation,        // Normal /Annot with /Subtype /Link
    OpenAction,        // Document /OpenAction
    PageAction,        // /AA (Additional Actions) on page
    FieldAction,       // Form field action
    NonStandardAction, // Other action triggers
}

impl UriPlacement {
    pub fn as_str(&self) -> &str {
        match self {
            UriPlacement::Annotation => "annotation",
            UriPlacement::OpenAction => "open_action",
            UriPlacement::PageAction => "page_action",
            UriPlacement::FieldAction => "field_action",
            UriPlacement::NonStandardAction => "non_standard_action",
        }
    }
}

#[derive(Debug, Clone)]
pub struct UriTrigger {
    pub mechanism: TriggerMechanism,
    pub event: Option<String>, // AA event key (/O, /C, /WC, etc.)
    pub automatic: bool,       // true if no user action required
    pub js_involved: bool,     // true if JavaScript in chain
}

#[derive(Debug, Clone, PartialEq)]
pub enum TriggerMechanism {
    Click,          // Annotation click
    OpenAction,     // Document open
    PageOpen,       // Page navigation
    PageClose,      // Page close
    FormSubmit,     // Form submission
    JavaScript,     // JS-initiated
    FieldCalculate, // Form field calculation
    FieldFormat,    // Form field format
    FieldValidate,  // Form field validation
    Other,
}

impl TriggerMechanism {
    pub fn as_str(&self) -> &str {
        match self {
            TriggerMechanism::Click => "click",
            TriggerMechanism::OpenAction => "open_action",
            TriggerMechanism::PageOpen => "page_open",
            TriggerMechanism::PageClose => "page_close",
            TriggerMechanism::FormSubmit => "form_submit",
            TriggerMechanism::JavaScript => "javascript",
            TriggerMechanism::FieldCalculate => "field_calculate",
            TriggerMechanism::FieldFormat => "field_format",
            TriggerMechanism::FieldValidate => "field_validate",
            TriggerMechanism::Other => "other",
        }
    }
}

/// Parse and analyze URI content
pub fn analyze_uri_content(uri: &[u8]) -> UriContentAnalysis {
    let url = String::from_utf8_lossy(uri).to_string();
    let length = url.len();

    // Parse scheme
    let (scheme, rest) = parse_scheme(&url);

    // Detect special schemes
    let is_javascript_uri = scheme.eq_ignore_ascii_case("javascript");
    let is_file_uri = scheme.eq_ignore_ascii_case("file");
    let is_data_uri = scheme.eq_ignore_ascii_case("data");
    let is_http = scheme.eq_ignore_ascii_case("http");

    // Parse domain and path from rest
    let (domain, path, query_string, port, userinfo_present) = parse_url_parts(&scheme, &rest);

    // Parse query parameters
    let query_params = parse_query_params(&query_string);

    // Detect obfuscation
    let obfuscation_level = detect_obfuscation(&url, &query_params);

    // Detect tracking parameters
    let tracking_params = detect_tracking_params(&query_params);

    // Detect suspicious patterns
    let suspicious_patterns = detect_suspicious_patterns(&url, &domain, &query_params);

    // Check if domain is IP address
    let is_ip_address = domain.as_ref().map_or(false, |d| is_ip_address_domain(d));

    // Check for suspicious TLD
    let suspicious_tld = domain.as_ref().map_or(false, |d| has_suspicious_tld(d));

    // Detect data exfiltration pattern
    let has_data_exfil_pattern = detect_data_exfil_pattern(&query_params);
    let has_non_standard_port = port.map(|p| p != 80 && p != 443).unwrap_or(false);
    let has_shortener_domain = domain.as_ref().map_or(false, |d| is_shortener_domain(d));
    let has_suspicious_extension = path.as_ref().map_or(false, |p| has_suspicious_extension(p));
    let has_suspicious_scheme = is_suspicious_scheme(&scheme);
    let has_embedded_ip_host = domain.as_ref().map_or(false, |d| has_embedded_ip(d));
    let has_idn_lookalike = domain
        .as_ref()
        .map_or(false, |d| has_idn_lookalike_domain(d));
    let (data_mime, data_is_base64, data_length) = if is_data_uri {
        parse_data_uri(rest.as_str())
    } else {
        (None, false, None)
    };
    let phishing_indicators = detect_phishing_indicators(
        &url,
        &domain,
        &path,
        &query_params,
        suspicious_tld,
        is_ip_address,
        userinfo_present,
        has_non_standard_port,
        &suspicious_patterns,
    );

    UriContentAnalysis {
        url,
        scheme,
        domain,
        path,
        query_params,
        port,
        userinfo_present,
        obfuscation_level,
        tracking_params,
        suspicious_patterns,
        phishing_indicators,
        length,
        is_ip_address,
        is_file_uri,
        is_javascript_uri,
        is_data_uri,
        is_http,
        suspicious_tld,
        has_data_exfil_pattern,
        has_non_standard_port,
        has_shortener_domain,
        has_suspicious_extension,
        has_suspicious_scheme,
        has_embedded_ip_host,
        has_idn_lookalike,
        data_mime,
        data_is_base64,
        data_length,
    }
}

fn parse_scheme(url: &str) -> (String, String) {
    if let Some(idx) = url.find(':') {
        let scheme = url[..idx].to_string();
        let rest = url[idx + 1..].to_string();
        (scheme, rest)
    } else {
        ("http".to_string(), url.to_string())
    }
}

fn parse_url_parts(
    scheme: &str,
    rest: &str,
) -> (Option<String>, Option<String>, String, Option<u16>, bool) {
    let scheme_lower = scheme.to_ascii_lowercase();
    if matches!(scheme_lower.as_str(), "javascript" | "data") {
        return (None, Some(rest.to_string()), String::new(), None, false);
    }

    if scheme_lower == "mailto" {
        let (address, query) = if let Some(idx) = rest.find('?') {
            (rest[..idx].to_string(), rest[idx + 1..].to_string())
        } else {
            (rest.to_string(), String::new())
        };
        return (None, Some(address), query, None, false);
    }

    if scheme_lower == "file" {
        let rest = rest.trim_start_matches('/');
        let (path_part, query) = if let Some(idx) = rest.find('?') {
            (rest[..idx].to_string(), rest[idx + 1..].to_string())
        } else {
            (rest.to_string(), String::new())
        };
        return (None, Some(format!("/{}", path_part)), query, None, false);
    }

    // Remove leading slashes for hierarchical schemes
    let rest = rest.trim_start_matches('/');

    let (path_part, query) = if let Some(idx) = rest.find('?') {
        (rest[..idx].to_string(), rest[idx + 1..].to_string())
    } else {
        (rest.to_string(), String::new())
    };

    // Split domain and path
    if let Some(idx) = path_part.find('/') {
        let authority = &path_part[..idx];
        let path = Some(path_part[idx..].to_string());
        let (domain, port, userinfo_present) = parse_authority(authority);
        (domain, path, query, port, userinfo_present)
    } else if !path_part.is_empty() {
        let (domain, port, userinfo_present) = parse_authority(&path_part);
        (domain, None, query, port, userinfo_present)
    } else {
        (None, None, query, None, false)
    }
}

fn parse_query_params(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return Vec::new();
    }

    query
        .split('&')
        .filter_map(|pair| {
            if let Some(idx) = pair.find('=') {
                let key = pair[..idx].to_string();
                let value = pair[idx + 1..].to_string();
                Some((key, value))
            } else {
                Some((pair.to_string(), String::new()))
            }
        })
        .collect()
}

fn detect_obfuscation(url: &str, params: &[(String, String)]) -> ObfuscationLevel {
    // Count percent-encoded characters
    let percent_count = url.matches('%').count();
    let total_chars = url.len();
    let percent_ratio = if total_chars > 0 {
        percent_count as f64 / total_chars as f64
    } else {
        0.0
    };

    // Check for base64 in params
    let has_base64 = params.iter().any(|(_, v)| looks_like_base64(v));

    // Check for unicode escapes
    let has_unicode_escapes = url.contains("\\u") || url.contains("%u");

    // Scoring
    if has_unicode_escapes || (has_base64 && percent_ratio > 0.2) {
        ObfuscationLevel::Heavy
    } else if percent_ratio > 0.3 || has_base64 {
        ObfuscationLevel::Medium
    } else if percent_ratio > 0.1 {
        ObfuscationLevel::Light
    } else {
        ObfuscationLevel::None
    }
}

fn looks_like_base64(s: &str) -> bool {
    if s.len() < 16 {
        return false;
    }

    let alphanumeric_plus = s
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();

    let ratio = alphanumeric_plus as f64 / s.len() as f64;
    ratio > 0.9 && s.len() > 30
}

fn detect_tracking_params(params: &[(String, String)]) -> Vec<String> {
    let tracking_keywords = [
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_content",
        "utm_term",
        "fbclid",
        "gclid",
        "mc_cid",
        "mc_eid",
        "_ga",
        "ref",
        "referer",
    ];

    params
        .iter()
        .filter(|(k, _)| {
            tracking_keywords
                .iter()
                .any(|&tk| k.eq_ignore_ascii_case(tk))
        })
        .map(|(k, _)| k.clone())
        .collect()
}

fn detect_suspicious_patterns(
    url: &str,
    domain: &Option<String>,
    params: &[(String, String)],
) -> Vec<String> {
    let mut patterns = Vec::new();

    // Check for extremely long URL
    if url.len() > 500 {
        patterns.push("extremely_long_url".to_string());
    }

    // Check for many parameters
    if params.len() > 10 {
        patterns.push("many_parameters".to_string());
    }

    // Check for suspicious parameter names
    let exfil_params = ["data", "payload", "info", "d", "p", "content"];
    if params
        .iter()
        .any(|(k, _)| exfil_params.iter().any(|&ep| k.eq_ignore_ascii_case(ep)))
    {
        patterns.push("suspicious_param_names".to_string());
    }

    // Check for subdomain tricks (e.g., paypal.attacker.com)
    if let Some(d) = domain {
        if d.matches('.').count() > 2 {
            patterns.push("many_subdomains".to_string());
        }
        if d.to_ascii_lowercase().contains("xn--") {
            patterns.push("punycode_domain".to_string());
        }
        if has_embedded_ip(d) {
            patterns.push("embedded_ip".to_string());
        }
        if has_idn_lookalike_domain(d) {
            patterns.push("idn_lookalike".to_string());
        }
    }

    patterns
}

fn parse_authority(authority: &str) -> (Option<String>, Option<u16>, bool) {
    let mut userinfo_present = false;
    let mut host_port = authority.trim();
    if let Some(at_idx) = authority.rfind('@') {
        userinfo_present = true;
        host_port = authority[at_idx + 1..].trim();
    }

    if host_port.is_empty() {
        return (None, None, userinfo_present);
    }

    let mut host = host_port;
    let mut port = None;

    if host_port.starts_with('[') {
        if let Some(end_idx) = host_port.find(']') {
            host = &host_port[1..end_idx];
            if let Some(port_str) = host_port[end_idx + 1..].strip_prefix(':') {
                if let Ok(parsed) = port_str.parse::<u16>() {
                    port = Some(parsed);
                }
            }
        }
    } else if let Some(idx) = host_port.rfind(':') {
        let (host_part, port_part) = host_port.split_at(idx);
        if !host_part.is_empty()
            && port_part.len() > 1
            && port_part[1..].chars().all(|c| c.is_ascii_digit())
        {
            host = host_part;
            if let Ok(parsed) = port_part[1..].parse::<u16>() {
                port = Some(parsed);
            }
        }
    }

    let host = host.trim_end_matches('.');
    if host.is_empty() {
        (None, port, userinfo_present)
    } else {
        (Some(host.to_string()), port, userinfo_present)
    }
}

fn is_ip_address_domain(domain: &str) -> bool {
    // Simple IPv4 check
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() == 4 {
        return parts.iter().all(|p| p.parse::<u8>().is_ok());
    }

    // IPv6 check (contains colons)
    domain.contains(':')
}

fn has_suspicious_tld(domain: &str) -> bool {
    let suspicious_tlds = [
        ".tk", ".ml", ".ga", ".cf", ".gq", // Free TLDs often abused
        ".zip", ".mov", // New confusing TLDs
    ];

    suspicious_tlds
        .iter()
        .any(|&tld| domain.to_lowercase().ends_with(tld))
}

fn detect_data_exfil_pattern(params: &[(String, String)]) -> bool {
    if params.len() < 3 {
        return false;
    }

    // Check if many parameters with long values (potential form data)
    let long_value_count = params.iter().filter(|(_, v)| v.len() > 50).count();

    long_value_count > 3 || (params.len() > 5 && long_value_count > 1)
}

fn detect_phishing_indicators(
    url: &str,
    domain: &Option<String>,
    path: &Option<String>,
    params: &[(String, String)],
    suspicious_tld: bool,
    is_ip_address: bool,
    userinfo_present: bool,
    has_non_standard_port: bool,
    suspicious_patterns: &[String],
) -> Vec<String> {
    let mut indicators = Vec::new();

    if userinfo_present {
        indicators.push("userinfo_in_url".to_string());
    }
    if is_ip_address {
        indicators.push("ip_address".to_string());
    }
    if suspicious_tld {
        indicators.push("suspicious_tld".to_string());
    }
    if has_non_standard_port {
        indicators.push("non_standard_port".to_string());
    }

    let keyword_hits = [
        "login", "signin", "verify", "update", "secure", "account", "billing", "password",
    ];

    if let Some(d) = domain {
        let lower = d.to_ascii_lowercase();
        if keyword_hits.iter().any(|&kw| lower.contains(kw)) {
            indicators.push("credential_keyword".to_string());
        }
    }

    if let Some(p) = path {
        let lower = p.to_ascii_lowercase();
        if keyword_hits.iter().any(|&kw| lower.contains(kw)) {
            indicators.push("credential_keyword".to_string());
        }
    }

    if params.iter().any(|(k, _)| {
        let lower = k.to_ascii_lowercase();
        matches!(lower.as_str(), "email" | "user" | "username" | "password")
    }) {
        indicators.push("credential_param".to_string());
    }

    if suspicious_patterns.iter().any(|p| p == "punycode_domain") {
        indicators.push("punycode_domain".to_string());
    }
    if suspicious_patterns.iter().any(|p| p == "many_subdomains") {
        indicators.push("many_subdomains".to_string());
    }
    if suspicious_patterns.iter().any(|p| p == "embedded_ip") {
        indicators.push("embedded_ip".to_string());
    }
    if suspicious_patterns.iter().any(|p| p == "idn_lookalike") {
        indicators.push("idn_lookalike".to_string());
    }

    if url.contains('@') {
        indicators.push("at_symbol".to_string());
    }

    indicators.sort();
    indicators.dedup();
    indicators
}

fn is_shortener_domain(domain: &str) -> bool {
    let domain = domain.to_ascii_lowercase();
    let shorteners = [
        "bit.ly",
        "t.co",
        "tinyurl.com",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "bit.do",
        "cutt.ly",
        "rebrand.ly",
        "shorturl.at",
        "tiny.cc",
        "t.ly",
        "rb.gy",
        "lnkd.in",
        "linktr.ee",
        "short.io",
        "tiny.one",
    ];

    shorteners
        .iter()
        .any(|&shortener| domain == shortener || domain.ends_with(&format!(".{}", shortener)))
}

fn has_suspicious_extension(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let suspicious_exts = [
        ".exe", ".scr", ".js", ".vbs", ".vbe", ".bat", ".cmd", ".ps1", ".psm1", ".msi", ".jar",
        ".dll", ".com", ".chm", ".lnk", ".url", ".hta", ".reg", ".zip", ".rar", ".7z", ".iso",
        ".img",
    ];
    suspicious_exts.iter().any(|&ext| lower.ends_with(ext))
}

fn is_suspicious_scheme(scheme: &str) -> bool {
    let scheme = scheme.to_ascii_lowercase();
    let safe_schemes = ["http", "https", "mailto", "file", "javascript", "data"];
    if safe_schemes.iter().any(|&s| s == scheme) {
        return false;
    }
    let suspicious_schemes = [
        "ms-word",
        "ms-excel",
        "ms-powerpoint",
        "ms-msdt",
        "itms-services",
        "intent",
        "ms-settings",
        "ms-officeapp",
        "ms-outlook",
        "ms-access",
        "ms-publisher",
        "ms-visio",
        "ms-people",
        "ms-contacts",
        "ms-cxh",
        "ms-windows-store",
    ];
    suspicious_schemes.iter().any(|&s| s == scheme)
}

fn has_embedded_ip(domain: &str) -> bool {
    for label in domain.split('.') {
        if label.matches('-').count() == 3 {
            let parts: Vec<&str> = label.split('-').collect();
            if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
                return true;
            }
        }
    }
    false
}

fn has_idn_lookalike_domain(domain: &str) -> bool {
    if domain.chars().any(|c| !c.is_ascii()) {
        let has_ascii_alpha = domain.chars().any(|c| c.is_ascii_alphabetic());
        return has_ascii_alpha;
    }
    false
}

fn parse_data_uri(rest: &str) -> (Option<String>, bool, Option<usize>) {
    let mut mime = None;
    let mut is_base64 = false;
    let mut data_len = None;

    let (meta, data) = if let Some(idx) = rest.find(',') {
        (&rest[..idx], &rest[idx + 1..])
    } else {
        (rest, "")
    };

    if !meta.is_empty() {
        let mut parts = meta.split(';');
        if let Some(first) = parts.next() {
            if !first.is_empty() {
                mime = Some(first.to_string());
            }
        }
        if meta.to_ascii_lowercase().contains("base64") {
            is_base64 = true;
        }
    }

    if !data.is_empty() {
        data_len = Some(data.len());
    }

    (mime, is_base64, data_len)
}

/// Analyze URI context (visibility and placement)
pub fn analyze_uri_context(
    _ctx: &ScanContext,
    _entry: &ObjEntry<'_>,
    dict: &PdfDict<'_>,
) -> Option<UriContext> {
    // Determine placement
    let placement = if dict.has_name(b"/Type", b"/Annot") || dict.has_name(b"/Subtype", b"/Link") {
        UriPlacement::Annotation
    } else if dict.has_name(b"/S", b"/URI") {
        // Could be OpenAction or other action
        UriPlacement::NonStandardAction
    } else {
        UriPlacement::NonStandardAction
    };

    // Extract rect and flags for annotations
    let (rect, flags) = if placement == UriPlacement::Annotation {
        (extract_rect(dict), extract_flags(dict))
    } else {
        (None, None)
    };

    // Get page bounds if we can determine the page
    let page_bounds = None; // TODO: Get from page tree

    // Determine visibility
    let visibility = if let Some(r) = rect {
        if is_zero_size_rect(&r) {
            UriVisibility::HiddenRect
        } else if let Some(pb) = page_bounds {
            if is_rect_outside_bounds(&r, &pb) {
                UriVisibility::HiddenRect
            } else {
                UriVisibility::Visible
            }
        } else if let Some(f) = flags {
            // Check hidden flags (bit 1 = invisible, bit 2 = hidden)
            if (f & 0x02) != 0 || (f & 0x04) != 0 {
                UriVisibility::HiddenFlag
            } else {
                UriVisibility::Visible
            }
        } else {
            UriVisibility::Visible
        }
    } else {
        UriVisibility::NoAnnot
    };

    Some(UriContext {
        visibility,
        placement,
        rect,
        page_bounds,
        flags,
    })
}

fn extract_rect(dict: &PdfDict<'_>) -> Option<[f32; 4]> {
    let (_, obj) = dict.get_first(b"/Rect")?;
    if let PdfAtom::Array(arr) = &obj.atom {
        if arr.len() == 4 {
            let mut rect = [0.0f32; 4];
            for (i, elem) in arr.iter().take(4).enumerate() {
                rect[i] = match &elem.atom {
                    PdfAtom::Int(n) => *n as f32,
                    PdfAtom::Real(f) => *f as f32,
                    _ => return None,
                };
            }
            return Some(rect);
        }
    }
    None
}

fn extract_flags(dict: &PdfDict<'_>) -> Option<u32> {
    let (_, obj) = dict.get_first(b"/F")?;
    if let PdfAtom::Int(n) = &obj.atom {
        return Some(*n as u32);
    }
    None
}

fn is_zero_size_rect(rect: &[f32; 4]) -> bool {
    (rect[2] - rect[0]).abs() < 0.1 && (rect[3] - rect[1]).abs() < 0.1
}

fn is_rect_outside_bounds(rect: &[f32; 4], bounds: &[f32; 4]) -> bool {
    rect[0] < bounds[0] || rect[1] < bounds[1] || rect[2] > bounds[2] || rect[3] > bounds[3]
}

/// Analyze how URI is triggered
pub fn analyze_uri_trigger(
    _ctx: &ScanContext,
    _entry: &ObjEntry<'_>,
    dict: &PdfDict<'_>,
) -> UriTrigger {
    // Check if this is in an AA (Additional Actions) context
    let (mechanism, event, automatic) = if dict.get_first(b"/AA").is_some() {
        // Additional Actions - could be automatic
        (TriggerMechanism::Other, None, true)
    } else if dict.has_name(b"/S", b"/SubmitForm") {
        (TriggerMechanism::FormSubmit, None, true)
    } else if dict.has_name(b"/S", b"/JavaScript") {
        (TriggerMechanism::JavaScript, None, true)
    } else {
        // Default to click for regular annotations
        (TriggerMechanism::Click, None, false)
    };

    // Check if JavaScript is involved in the action chain
    let js_involved = dict.has_name(b"/S", b"/JavaScript")
        || dict.get_first(b"/JS").is_some()
        || dict.get_first(b"/JavaScript").is_some();

    UriTrigger {
        mechanism,
        event,
        automatic,
        js_involved,
    }
}

/// Calculate composite risk score for a URI
pub fn calculate_uri_risk_score(
    content: &UriContentAnalysis,
    context: &Option<UriContext>,
    trigger: &UriTrigger,
) -> u32 {
    let mut score = 0u32;

    // Context modifiers
    if let Some(ctx) = context {
        score += match ctx.visibility {
            UriVisibility::Visible => 0,
            UriVisibility::HiddenRect => 30,
            UriVisibility::HiddenFlag => 40,
            UriVisibility::NoAnnot => 20,
        };
    }

    // Trigger modifiers
    score += match trigger.mechanism {
        TriggerMechanism::Click => 0,
        TriggerMechanism::PageOpen => 20,
        TriggerMechanism::OpenAction => 40,
        TriggerMechanism::JavaScript => 50,
        TriggerMechanism::FormSubmit => 60,
        _ => 10,
    };

    if trigger.automatic {
        score += 20;
    }

    if trigger.js_involved {
        score += 30;
    }

    // Content modifiers
    score += match content.obfuscation_level {
        ObfuscationLevel::None => 0,
        ObfuscationLevel::Light => 10,
        ObfuscationLevel::Medium => 30,
        ObfuscationLevel::Heavy => 50,
    };

    if content.is_javascript_uri {
        score += 70;
    }
    if content.is_file_uri {
        score += 40;
    }
    if content.is_data_uri {
        score += 50;
        if content.data_is_base64 {
            score += 20;
        }
        if content.data_length.unwrap_or(0) > 512 {
            score += 15;
        }
    }
    if content.is_ip_address {
        score += 20;
    }
    if content.suspicious_tld {
        score += 30;
    }
    if content.has_data_exfil_pattern {
        score += 60;
    }
    if content.has_non_standard_port {
        score += 15;
    }
    if content.has_suspicious_extension {
        score += 20;
    }
    if content.has_shortener_domain {
        score += 15;
    }
    if content.has_suspicious_scheme {
        score += 35;
    }
    if content.has_embedded_ip_host {
        score += 20;
    }
    if content.has_idn_lookalike {
        score += 15;
    }
    if !content.phishing_indicators.is_empty() {
        score += 25;
    }
    if !content.suspicious_patterns.is_empty() {
        score += 20;
    }

    score
}

/// Convert risk score to severity
pub fn risk_score_to_severity(score: u32) -> Severity {
    match score {
        0..=20 => Severity::Info,
        21..=50 => Severity::Low,
        51..=80 => Severity::Medium,
        _ => Severity::High,
    }
}

/// Detector for URI content analysis
pub struct UriContentDetector;

impl Detector for UriContentDetector {
    fn id(&self) -> &'static str {
        "uri_content_analysis"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::Actions
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Moderate
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        const MAX_URIS: usize = 1000;

        // Build typed graph to find URI edges
        let typed_graph = ctx.build_typed_graph();

        // Collect unique URI source objects (deduplicate)
        let mut uri_objects = HashSet::new();
        for edge in &typed_graph.edges {
            if matches!(edge.edge_type, EdgeType::UriTarget) {
                uri_objects.insert(edge.src);
                if uri_objects.len() >= MAX_URIS {
                    break;
                }
            }
        }

        // Analyze each URI object
        for (obj, gen) in uri_objects {
            let entry = match ctx.graph.get_object(obj, gen) {
                Some(e) => e,
                None => continue,
            };

            let dict = match entry_dict(entry) {
                Some(d) => d,
                None => continue,
            };

            // Extract URI
            if let Some((k, v)) = dict.get_first(b"/URI") {
                if let Some(uri_bytes) = extract_uri_bytes(v) {
                    let content = analyze_uri_content(&uri_bytes);
                    let context = analyze_uri_context(ctx, entry, dict);
                    let trigger = analyze_uri_trigger(ctx, entry, dict);

                    let risk_score = calculate_uri_risk_score(&content, &context, &trigger);
                    let severity = risk_score_to_severity(risk_score);

                    // Only report if not just info level or has interesting signals
                    if severity != Severity::Info
                        || !content.suspicious_patterns.is_empty()
                        || !content.tracking_params.is_empty()
                        || content.obfuscation_level != ObfuscationLevel::None
                        || content.has_shortener_domain
                        || content.has_suspicious_extension
                        || content.has_suspicious_scheme
                        || content.has_embedded_ip_host
                        || content.has_idn_lookalike
                        || content.is_data_uri
                    {
                        let mut meta = HashMap::new();
                        meta.insert("uri.url".to_string(), preview_ascii(&uri_bytes, 120));
                        meta.insert("uri.scheme".to_string(), content.scheme.clone());
                        meta.insert("uri.length".to_string(), content.length.to_string());
                        meta.insert(
                            "uri.obfuscation".to_string(),
                            content.obfuscation_level.as_str().to_string(),
                        );
                        meta.insert("uri.risk_score".to_string(), risk_score.to_string());

                        if let Some(domain) = &content.domain {
                            meta.insert("uri.domain".to_string(), domain.clone());
                        }

                        if content.is_ip_address {
                            meta.insert("uri.is_ip".to_string(), "true".to_string());
                        }
                        if content.is_javascript_uri {
                            meta.insert("uri.is_javascript".to_string(), "true".to_string());
                        }
                        if content.is_file_uri {
                            meta.insert("uri.is_file".to_string(), "true".to_string());
                        }
                        if content.is_data_uri {
                            meta.insert("uri.data_uri".to_string(), "true".to_string());
                            if let Some(mime) = &content.data_mime {
                                meta.insert("uri.data_mime".to_string(), mime.clone());
                            }
                            if content.data_is_base64 {
                                meta.insert("uri.data_is_base64".to_string(), "true".to_string());
                            }
                            if let Some(len) = content.data_length {
                                meta.insert("uri.data_length".to_string(), len.to_string());
                            }
                        }
                        if content.suspicious_tld {
                            meta.insert("uri.suspicious_tld".to_string(), "true".to_string());
                        }
                        if content.has_data_exfil_pattern {
                            meta.insert("uri.data_exfil_pattern".to_string(), "true".to_string());
                        }

                        if !content.tracking_params.is_empty() {
                            meta.insert("uri.tracking_params".to_string(), "true".to_string());
                            meta.insert(
                                "uri.tracking_params_list".to_string(),
                                content.tracking_params.join(","),
                            );
                        }
                        if !content.suspicious_patterns.is_empty() {
                            meta.insert(
                                "uri.suspicious_patterns".to_string(),
                                content.suspicious_patterns.join(","),
                            );
                        }
                        if !content.phishing_indicators.is_empty() {
                            meta.insert("uri.phishing_indicators".to_string(), "true".to_string());
                            meta.insert(
                                "uri.phishing_indicators_list".to_string(),
                                content.phishing_indicators.join(","),
                            );
                        }
                        if content.has_non_standard_port {
                            meta.insert("uri.non_standard_port".to_string(), "true".to_string());
                        }
                        if content.has_shortener_domain {
                            meta.insert("uri.shortener_domain".to_string(), "true".to_string());
                        }
                        if content.has_suspicious_extension {
                            meta.insert("uri.suspicious_extension".to_string(), "true".to_string());
                        }
                        if content.has_suspicious_scheme {
                            meta.insert("uri.suspicious_scheme".to_string(), "true".to_string());
                        }
                        if content.has_embedded_ip_host {
                            meta.insert("uri.embedded_ip_host".to_string(), "true".to_string());
                        }
                        if content.has_idn_lookalike {
                            meta.insert("uri.idn_lookalike".to_string(), "true".to_string());
                        }

                        if let Some(ctx_info) = &context {
                            meta.insert(
                                "uri.visibility".to_string(),
                                ctx_info.visibility.as_str().to_string(),
                            );
                            meta.insert(
                                "uri.placement".to_string(),
                                ctx_info.placement.as_str().to_string(),
                            );
                            if matches!(
                                ctx_info.visibility,
                                UriVisibility::HiddenRect | UriVisibility::HiddenFlag
                            ) {
                                meta.insert(
                                    "uri.hidden_annotation".to_string(),
                                    "true".to_string(),
                                );
                            }
                        }

                        meta.insert(
                            "uri.trigger".to_string(),
                            trigger.mechanism.as_str().to_string(),
                        );
                        meta.insert("uri.automatic".to_string(), trigger.automatic.to_string());
                        meta.insert(
                            "uri.js_involved".to_string(),
                            trigger.js_involved.to_string(),
                        );

                        let evidence = vec![
                            span_to_evidence(k.span, "URI key"),
                            span_to_evidence(v.span, "URI value"),
                        ];

                        let description = build_description(&content, &context, &trigger);

                        findings.push(Finding {
                            id: String::new(),
                            surface: self.surface(),
                            kind: "uri_content_analysis".to_string(),
                            severity,
                            confidence: Confidence::Probable,
                            title: "URI with suspicious characteristics".to_string(),
                            description,
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence,
                            remediation: Some(
                                "Review URI destination and trigger mechanism.".to_string(),
                            ),
                            meta,
                            yara: None,
                            position: None,
                            positions: Vec::new(),
                        });
                    }
                }
            }
        }

        Ok(findings)
    }
}

fn extract_uri_bytes(obj: &PdfObj<'_>) -> Option<Vec<u8>> {
    match &obj.atom {
        PdfAtom::Str(s) => Some(crate::string_bytes(s)),
        PdfAtom::Name(n) => Some(n.decoded.clone()),
        _ => None,
    }
}

fn build_description(
    content: &UriContentAnalysis,
    context: &Option<UriContext>,
    trigger: &UriTrigger,
) -> String {
    let mut parts = Vec::new();

    if content.is_javascript_uri {
        parts.push("JavaScript URI (can execute arbitrary code)");
    } else if content.is_file_uri {
        parts.push("File URI (can access local filesystem)");
    } else if content.is_data_uri {
        parts.push("data URI payload");
    }

    if let Some(ctx) = context {
        match ctx.visibility {
            UriVisibility::HiddenRect => {
                parts.push("hidden annotation (zero-size or out of bounds)")
            }
            UriVisibility::HiddenFlag => parts.push("annotation marked as hidden"),
            UriVisibility::NoAnnot => parts.push("not in visible annotation"),
            _ => {}
        }
    }

    if trigger.automatic {
        parts.push("automatically triggered");
    }
    if trigger.js_involved {
        parts.push("JavaScript-triggered");
    }

    if content.has_data_exfil_pattern {
        parts.push("potential data exfiltration pattern");
    }

    if content.obfuscation_level != ObfuscationLevel::None {
        parts.push(match content.obfuscation_level {
            ObfuscationLevel::Light => "lightly obfuscated",
            ObfuscationLevel::Medium => "moderately obfuscated",
            ObfuscationLevel::Heavy => "heavily obfuscated",
            _ => "",
        });
    }

    if content.suspicious_tld {
        parts.push("suspicious TLD");
    }

    if content.is_ip_address {
        parts.push("IP address instead of domain");
    }
    if content.has_non_standard_port {
        parts.push("non-standard port");
    }
    if content.has_shortener_domain {
        parts.push("URL shortener domain");
    }
    if content.has_suspicious_extension {
        parts.push("suspicious file extension");
    }
    if content.has_suspicious_scheme {
        parts.push("suspicious URI scheme");
    }
    if content.has_embedded_ip_host {
        parts.push("embedded IP hostname");
    }
    if content.has_idn_lookalike {
        parts.push("IDN lookalike domain");
    }
    if !content.phishing_indicators.is_empty() {
        parts.push("phishing indicators");
    }

    if parts.is_empty() {
        format!("URI to {}", content.domain.as_deref().unwrap_or("unknown"))
    } else {
        format!("URI with: {}", parts.join(", "))
    }
}

/// Detector for document-level URI presence summary
pub struct UriPresenceDetector;

impl Detector for UriPresenceDetector {
    fn id(&self) -> &'static str {
        "uri_presence_summary"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::Actions
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Cheap
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let mut unique_domains = HashSet::new();
        let mut scheme_counts = HashMap::new();

        // Build typed graph to find URI edges
        let typed_graph = ctx.build_typed_graph();

        // Collect unique URI source objects
        let mut uri_objects = HashSet::new();
        for edge in &typed_graph.edges {
            if matches!(edge.edge_type, EdgeType::UriTarget) {
                uri_objects.insert(edge.src);
            }
        }

        // Analyze each URI
        for (obj, gen) in &uri_objects {
            let entry = match ctx.graph.get_object(*obj, *gen) {
                Some(e) => e,
                None => continue,
            };

            let dict = match entry_dict(entry) {
                Some(d) => d,
                None => continue,
            };

            if let Some((_, v)) = dict.get_first(b"/URI") {
                if let Some(uri_bytes) = extract_uri_bytes(v) {
                    let content = analyze_uri_content(&uri_bytes);

                    // Track scheme
                    *scheme_counts.entry(content.scheme.clone()).or_insert(0) += 1;

                    // Track unique domains
                    if let Some(domain) = content.domain {
                        unique_domains.insert(domain);
                    }
                }
            }
        }

        let uri_count = uri_objects.len();
        let has_http = scheme_counts.keys().any(|k| k.eq_ignore_ascii_case("http"));
        let has_https = scheme_counts
            .keys()
            .any(|k| k.eq_ignore_ascii_case("https"));

        // Only create finding if URIs are present
        if uri_count > 0 {
            let mut meta = HashMap::new();
            meta.insert("uri.count_total".to_string(), uri_count.to_string());
            meta.insert(
                "uri.count_unique_domains".to_string(),
                unique_domains.len().to_string(),
            );

            let schemes: Vec<String> = scheme_counts
                .iter()
                .map(|(k, v)| format!("{}:{}", k, v))
                .collect();
            meta.insert("uri.schemes".to_string(), schemes.join(", "));

            let unique_domain_count = unique_domains.len();
            let severity = if uri_count >= 50 || unique_domain_count >= 20 {
                Severity::High
            } else if uri_count >= 25 || unique_domain_count >= 10 {
                Severity::Medium
            } else if uri_count >= 10 || unique_domain_count >= 5 {
                Severity::Low
            } else {
                Severity::Info
            };

            if !unique_domains.is_empty() {
                let domains: Vec<String> = unique_domains.iter().cloned().take(10).collect();
                meta.insert("uri.domains_sample".to_string(), domains.join(", "));
            }

            if has_http && has_https {
                meta.insert("uri.mixed_content".to_string(), "true".to_string());
            }

            let description = if severity == Severity::Info {
                format!(
                    "Found {} URIs pointing to {} unique domains.",
                    uri_count,
                    meta.get("uri.count_unique_domains").unwrap()
                )
            } else {
                format!(
                    "Found {} URIs pointing to {} unique domains, indicating elevated external exposure.",
                    uri_count,
                    meta.get("uri.count_unique_domains").unwrap()
                )
            };

            Ok(vec![Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "uri_presence_summary".to_string(),
                severity,
                confidence: Confidence::Strong,
                title: "Document contains URIs".to_string(),
                description,
                objects: vec!["document".to_string()],
                evidence: vec![],
                remediation: Some(
                    "Review URIs for legitimacy and verify destinations.".to_string(),
                ),
                meta,
                yara: None,
                position: None,
                positions: Vec::new(),
            }])
        } else {
            Ok(Vec::new())
        }
    }
}
