use anyhow::Result;
use std::collections::HashMap;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::evidence::preview_ascii;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::ScanContext;
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::graph::ObjEntry;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};

use crate::entry_dict;

/// URI content analysis and classification
#[derive(Debug, Clone)]
pub struct UriContentAnalysis {
    pub url: String,
    pub scheme: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub query_params: Vec<(String, String)>,

    // Signals
    pub obfuscation_level: ObfuscationLevel,
    pub tracking_params: Vec<String>,
    pub suspicious_patterns: Vec<String>,
    pub length: usize,

    // Risk factors
    pub is_ip_address: bool,
    pub is_file_uri: bool,
    pub is_javascript_uri: bool,
    pub is_http: bool,
    pub suspicious_tld: bool,
    pub has_data_exfil_pattern: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ObfuscationLevel {
    None,
    Light,      // Some percent-encoding (normal)
    Medium,     // Extensive percent-encoding, base64 params
    Heavy,      // Multiple layers, unicode escapes, etc.
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
    Visible,      // Normal annotation with visible rect
    HiddenRect,   // Rect outside page or zero-size
    HiddenFlag,   // Annotation flags mark as hidden
    NoAnnot,      // URI not in annotation (action only)
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
    Annotation,         // Normal /Annot with /Subtype /Link
    OpenAction,         // Document /OpenAction
    PageAction,         // /AA (Additional Actions) on page
    FieldAction,        // Form field action
    NonStandardAction,  // Other action triggers
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
    pub event: Option<String>,       // AA event key (/O, /C, /WC, etc.)
    pub automatic: bool,              // true if no user action required
    pub js_involved: bool,            // true if JavaScript in chain
}

#[derive(Debug, Clone, PartialEq)]
pub enum TriggerMechanism {
    Click,              // Annotation click
    OpenAction,         // Document open
    PageOpen,           // Page navigation
    PageClose,          // Page close
    FormSubmit,         // Form submission
    JavaScript,         // JS-initiated
    FieldCalculate,     // Form field calculation
    FieldFormat,        // Form field format
    FieldValidate,      // Form field validation
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
    let is_http = scheme.eq_ignore_ascii_case("http");

    // Parse domain and path from rest
    let (domain, path, query_string) = parse_url_parts(&rest);

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

    UriContentAnalysis {
        url,
        scheme,
        domain,
        path,
        query_params,
        obfuscation_level,
        tracking_params,
        suspicious_patterns,
        length,
        is_ip_address,
        is_file_uri,
        is_javascript_uri,
        is_http,
        suspicious_tld,
        has_data_exfil_pattern,
    }
}

fn parse_scheme(url: &str) -> (String, String) {
    if let Some(idx) = url.find(':') {
        let scheme = url[..idx].to_string();
        let rest = url[idx+1..].to_string();
        (scheme, rest)
    } else {
        ("http".to_string(), url.to_string())
    }
}

fn parse_url_parts(rest: &str) -> (Option<String>, Option<String>, String) {
    // Remove leading slashes
    let rest = rest.trim_start_matches('/');

    // Find query string
    let (path_part, query) = if let Some(idx) = rest.find('?') {
        (rest[..idx].to_string(), rest[idx+1..].to_string())
    } else {
        (rest.to_string(), String::new())
    };

    // Split domain and path
    if let Some(idx) = path_part.find('/') {
        let domain = Some(path_part[..idx].to_string());
        let path = Some(path_part[idx..].to_string());
        (domain, path, query)
    } else if !path_part.is_empty() {
        (Some(path_part), None, query)
    } else {
        (None, None, query)
    }
}

fn parse_query_params(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return Vec::new();
    }

    query.split('&')
        .filter_map(|pair| {
            if let Some(idx) = pair.find('=') {
                let key = pair[..idx].to_string();
                let value = pair[idx+1..].to_string();
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

    let alphanumeric_plus = s.chars()
        .filter(|c| c.is_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();

    let ratio = alphanumeric_plus as f64 / s.len() as f64;
    ratio > 0.9 && s.len() > 30
}

fn detect_tracking_params(params: &[(String, String)]) -> Vec<String> {
    let tracking_keywords = [
        "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
        "fbclid", "gclid", "mc_cid", "mc_eid", "_ga", "ref", "referer",
    ];

    params.iter()
        .filter(|(k, _)| tracking_keywords.iter().any(|&tk| k.eq_ignore_ascii_case(tk)))
        .map(|(k, _)| k.clone())
        .collect()
}

fn detect_suspicious_patterns(url: &str, domain: &Option<String>, params: &[(String, String)]) -> Vec<String> {
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
    if params.iter().any(|(k, _)| exfil_params.iter().any(|&ep| k.eq_ignore_ascii_case(ep))) {
        patterns.push("suspicious_param_names".to_string());
    }

    // Check for subdomain tricks (e.g., paypal.attacker.com)
    if let Some(d) = domain {
        if d.matches('.').count() > 2 {
            patterns.push("many_subdomains".to_string());
        }
    }

    patterns
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

    suspicious_tlds.iter().any(|&tld| domain.to_lowercase().ends_with(tld))
}

fn detect_data_exfil_pattern(params: &[(String, String)]) -> bool {
    if params.len() < 3 {
        return false;
    }

    // Check if many parameters with long values (potential form data)
    let long_value_count = params.iter()
        .filter(|(_, v)| v.len() > 50)
        .count();

    long_value_count > 3 || (params.len() > 5 && long_value_count > 1)
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
    rect[0] < bounds[0] || rect[1] < bounds[1] ||
    rect[2] > bounds[2] || rect[3] > bounds[3]
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
    let js_involved = dict.has_name(b"/S", b"/JavaScript") ||
                     dict.get_first(b"/JS").is_some() ||
                     dict.get_first(b"/JavaScript").is_some();

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
    if content.is_ip_address {
        score += 20;
    }
    if content.suspicious_tld {
        score += 30;
    }
    if content.has_data_exfil_pattern {
        score += 60;
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
        let mut uri_count = 0;
        const MAX_URIS: usize = 1000;

        for entry in &ctx.graph.objects {
            if uri_count >= MAX_URIS {
                break;
            }

            let dict = match entry_dict(entry) {
                Some(d) => d,
                None => continue,
            };

            // Look for URI actions
            if let Some((k, v)) = dict.get_first(b"/URI") {
                if let Some(uri_bytes) = extract_uri_bytes(v) {
                    uri_count += 1;

                    let content = analyze_uri_content(&uri_bytes);
                    let context = analyze_uri_context(ctx, entry, dict);
                    let trigger = analyze_uri_trigger(ctx, entry, dict);

                    let risk_score = calculate_uri_risk_score(&content, &context, &trigger);
                    let severity = risk_score_to_severity(risk_score);

                    // Only report if not just info level or has interesting signals
                    if severity != Severity::Info || !content.suspicious_patterns.is_empty() ||
                       !content.tracking_params.is_empty() || content.obfuscation_level != ObfuscationLevel::None {

                        let mut meta = HashMap::new();
                        meta.insert("uri.url".to_string(), preview_ascii(&uri_bytes, 120));
                        meta.insert("uri.scheme".to_string(), content.scheme.clone());
                        meta.insert("uri.length".to_string(), content.length.to_string());
                        meta.insert("uri.obfuscation".to_string(), content.obfuscation_level.as_str().to_string());
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
                        if content.suspicious_tld {
                            meta.insert("uri.suspicious_tld".to_string(), "true".to_string());
                        }
                        if content.has_data_exfil_pattern {
                            meta.insert("uri.data_exfil_pattern".to_string(), "true".to_string());
                        }

                        if !content.tracking_params.is_empty() {
                            meta.insert("uri.tracking_params".to_string(), content.tracking_params.join(","));
                        }
                        if !content.suspicious_patterns.is_empty() {
                            meta.insert("uri.suspicious_patterns".to_string(), content.suspicious_patterns.join(","));
                        }

                        if let Some(ctx_info) = &context {
                            meta.insert("uri.visibility".to_string(), ctx_info.visibility.as_str().to_string());
                            meta.insert("uri.placement".to_string(), ctx_info.placement.as_str().to_string());
                        }

                        meta.insert("uri.trigger".to_string(), trigger.mechanism.as_str().to_string());
                        meta.insert("uri.automatic".to_string(), trigger.automatic.to_string());
                        meta.insert("uri.js_involved".to_string(), trigger.js_involved.to_string());

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
                            remediation: Some("Review URI destination and trigger mechanism.".to_string()),
                            meta,
                            yara: None,
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
    }

    if let Some(ctx) = context {
        match ctx.visibility {
            UriVisibility::HiddenRect => parts.push("hidden annotation (zero-size or out of bounds)"),
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
        let mut uri_count = 0;
        let mut unique_domains = std::collections::HashSet::new();
        let mut scheme_counts = HashMap::new();

        for entry in &ctx.graph.objects {
            let dict = match entry_dict(entry) {
                Some(d) => d,
                None => continue,
            };

            if let Some((_, v)) = dict.get_first(b"/URI") {
                if let Some(uri_bytes) = extract_uri_bytes(v) {
                    uri_count += 1;

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

        // Only create finding if URIs are present
        if uri_count > 0 {
            let mut meta = HashMap::new();
            meta.insert("uri.count_total".to_string(), uri_count.to_string());
            meta.insert("uri.count_unique_domains".to_string(), unique_domains.len().to_string());

            let schemes: Vec<String> = scheme_counts.iter()
                .map(|(k, v)| format!("{}:{}", k, v))
                .collect();
            meta.insert("uri.schemes".to_string(), schemes.join(", "));

            if !unique_domains.is_empty() {
                let domains: Vec<String> = unique_domains.into_iter().take(10).collect();
                meta.insert("uri.domains_sample".to_string(), domains.join(", "));
            }

            Ok(vec![Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "uri_presence_summary".to_string(),
                severity: Severity::Info,
                confidence: Confidence::Strong,
                title: "Document contains URIs".to_string(),
                description: format!(
                    "Found {} URIs pointing to {} unique domains.",
                    uri_count,
                    meta.get("uri.count_unique_domains").unwrap()
                ),
                objects: vec!["document".to_string()],
                evidence: vec![],
                remediation: Some("Review URIs for legitimacy and verify destinations.".to_string()),
                meta,
                yara: None,
            }])
        } else {
            Ok(Vec::new())
        }
    }
}
