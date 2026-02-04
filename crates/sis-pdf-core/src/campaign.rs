use std::collections::{BTreeMap, BTreeSet};

use crate::model::Finding;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkIntent {
    pub url: String,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PDFAnalysis {
    pub id: String,
    pub path: Option<String>,
    pub network_intents: Vec<NetworkIntent>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Campaign {
    pub id: String,
    pub domains: Vec<String>,
    pub pdfs: Vec<String>,
}

pub struct MultiStageCorrelator;

impl MultiStageCorrelator {
    pub fn correlate_campaign(&self, pdfs: &[PDFAnalysis]) -> Vec<Campaign> {
        let mut by_domain: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for pdf in pdfs {
            let pid = pdf.path.clone().unwrap_or_else(|| pdf.id.clone());
            for intent in &pdf.network_intents {
                if let Some(domain) = &intent.domain {
                    by_domain
                        .entry(domain.clone())
                        .or_default()
                        .insert(pid.clone());
                }
            }
        }
        let mut campaigns = Vec::new();
        for (domain, pdfs) in by_domain {
            if pdfs.len() < 2 {
                continue;
            }
            campaigns.push(Campaign {
                id: format!("campaign:{}", domain),
                domains: vec![domain],
                pdfs: pdfs.into_iter().collect(),
            });
        }
        campaigns
    }

    pub fn detect_c2_infrastructure(&self, intents: &[NetworkIntent]) -> Vec<String> {
        let mut out = Vec::new();
        for intent in intents {
            if let Some(domain) = &intent.domain {
                if domain.contains(".onion") || domain.contains("pastebin") {
                    out.push(domain.clone());
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct IntentExtractionOptions {
    pub include_domains: bool,
    pub include_obfuscated: bool,
    pub include_scheme_less: bool,
}

pub fn extract_domain(url: &str) -> Option<String> {
    let url = url.trim();
    let url = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let mut end = url.len();
    for (idx, ch) in url.char_indices() {
        if ch == '/' || ch == ':' {
            end = idx;
            break;
        }
    }
    if end == 0 {
        return None;
    }
    Some(url[..end].to_string())
}

pub fn extract_network_intents_from_findings(
    findings: &[Finding],
    options: &IntentExtractionOptions,
) -> Vec<NetworkIntent> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for f in findings {
        for (k, v) in &f.meta {
            if k == "action.target"
                || k == "supply_chain.action_targets"
                || k == "js.ast_urls"
                || k.starts_with("js.")
            {
                for intent in extract_intents_from_value(v, options) {
                    if seen.insert(intent.url.clone()) {
                        out.push(intent);
                    }
                }
            }
            if options.include_domains && k == "js.ast_domains" {
                for intent in extract_domain_intents(v) {
                    if seen.insert(intent.url.clone()) {
                        out.push(intent);
                    }
                }
            }
        }
    }
    out
}

fn extract_intents_from_value(
    input: &str,
    options: &IntentExtractionOptions,
) -> Vec<NetworkIntent> {
    let mut out = Vec::new();
    for raw in input
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .filter(|s| !s.is_empty())
    {
        let trimmed = raw.trim_matches([
            '"', '\'', '(', ')', '[', ']', '{', '}', '<', '>', '.', ';', ':',
        ]);
        if trimmed.is_empty() {
            continue;
        }
        let mut token = trimmed.to_string();
        if options.include_obfuscated {
            token = deobfuscate_url_token(&token);
        }
        if token.starts_with("http://") || token.starts_with("https://") {
            let domain = extract_domain(&token);
            out.push(NetworkIntent { url: token, domain });
        } else if options.include_scheme_less && looks_like_domain(&token) {
            let domain = extract_domain_loose(&token);
            out.push(NetworkIntent { url: token, domain });
        }
    }
    out
}

fn extract_domain_intents(input: &str) -> Vec<NetworkIntent> {
    let mut out = Vec::new();
    for raw in input
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .filter(|s| !s.is_empty())
    {
        let trimmed = raw.trim_matches([
            '"', '\'', '(', ')', '[', ']', '{', '}', '<', '>', '.', ';', ':',
        ]);
        if trimmed.is_empty() {
            continue;
        }
        if let Some(domain) = extract_domain_loose(trimmed) {
            out.push(NetworkIntent {
                url: trimmed.to_string(),
                domain: Some(domain),
            });
        }
    }
    out
}

fn extract_domain_loose(input: &str) -> Option<String> {
    let mut token = input.trim();
    if token.is_empty() {
        return None;
    }
    if let Some(rest) = token.strip_prefix("http://") {
        token = rest;
    } else if let Some(rest) = token.strip_prefix("https://") {
        token = rest;
    }
    let mut end = token.len();
    for (idx, ch) in token.char_indices() {
        if ch == '/' || ch == ':' {
            end = idx;
            break;
        }
    }
    if end == 0 {
        return None;
    }
    let candidate = &token[..end];
    if is_valid_domain(candidate) {
        Some(candidate.to_string())
    } else {
        None
    }
}

fn looks_like_domain(input: &str) -> bool {
    let token = input.trim();
    is_valid_domain_derived(token)
}

fn deobfuscate_url_token(input: &str) -> String {
    let mut out = input.to_string();
    out = out.replace("hxxps://", "https://");
    out = out.replace("hxxp://", "http://");
    out = out.replace("https[:]//", "https://");
    out = out.replace("http[:]//", "http://");
    out = out.replace("hxxps[:]//", "https://");
    out = out.replace("hxxp[:]//", "http://");
    out = out.replace("[.]", ".");
    out = out.replace("(.)", ".");
    out
}

fn is_valid_domain(input: &str) -> bool {
    let token = input.trim();
    if token.len() < 4 || token.len() > 253 {
        return false;
    }
    if token.starts_with('.') || token.ends_with('.') {
        return false;
    }
    if token.contains(['(', ')', '[', ']', '{', '}', '<', '>', '"', '\'', '\\']) {
        return false;
    }
    let labels: Vec<&str> = token.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let mut has_alpha = false;
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        let bytes = label.as_bytes();
        if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
            return false;
        }
        for ch in label.chars() {
            if ch.is_ascii_alphabetic() {
                has_alpha = true;
            }
            if !ch.is_ascii_alphanumeric() && ch != '-' {
                return false;
            }
        }
    }
    let tld = labels[labels.len() - 1];
    if tld.len() < 2 || tld.len() > 24 {
        return false;
    }
    let tld_has_alpha = tld.chars().any(|c| c.is_ascii_alphabetic());
    if !tld_has_alpha {
        return false;
    }
    if is_suspicious_tld(tld) {
        return false;
    }
    if labels.len() == 2 && is_probable_js_member(labels[0], tld) {
        return false;
    }
    has_alpha
}

fn is_valid_domain_derived(input: &str) -> bool {
    let token = input.trim();
    if token.to_ascii_lowercase() != token {
        return false;
    }
    if !is_valid_domain(token) {
        return false;
    }
    let labels: Vec<&str> = token.split('.').collect();
    let has_digit_or_dash = token.chars().any(|c| c.is_ascii_digit() || c == '-');
    if has_digit_or_dash {
        return true;
    }
    let has_jsy_label = labels.iter().any(|label| is_jsy_label(label));
    if has_jsy_label {
        return false;
    }
    true
}

fn is_suspicious_tld(tld: &str) -> bool {
    let tld = tld.to_ascii_lowercase();
    matches!(
        tld.as_str(),
        "split"
            | "replace"
            | "concat"
            | "match"
            | "exec"
            | "substr"
            | "substring"
            | "slice"
            | "splice"
            | "indexof"
            | "join"
            | "charat"
            | "tostring"
            | "getannots"
            | "push"
            | "pop"
            | "shift"
            | "unshift"
            | "map"
            | "filter"
            | "reduce"
            | "reduceRight"
            | "replaceAll"
    )
}

fn is_probable_js_member(object: &str, method: &str) -> bool {
    let object = object.to_ascii_lowercase();
    let method = method.to_ascii_lowercase();
    let object_is_jsy = matches!(
        object.as_str(),
        "this" | "app" | "creator" | "tmp" | "h" | "s" | "y" | "z"
    );
    let method_is_jsy = is_suspicious_tld(&method);
    object_is_jsy && method_is_jsy
}

fn is_jsy_label(label: &str) -> bool {
    matches!(
        label,
        "app"
            | "doc"
            | "collab"
            | "event"
            | "string"
            | "base64"
            | "creator"
            | "this"
            | "window"
            | "document"
            | "util"
            | "math"
            | "console"
    )
}
