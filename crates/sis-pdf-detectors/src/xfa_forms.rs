use anyhow::Result;
use std::collections::HashSet;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::evidence::EvidenceBuilder;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::timeout::TimeoutChecker;
use sis_pdf_pdf::xfa::extract_xfa_script_payloads;

use crate::{entry_dict, xfa_payloads_from_obj};

pub struct XfaFormDetector;

impl Detector for XfaFormDetector {
    fn id(&self) -> &'static str {
        "xfa_forms"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::Forms
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Cheap
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let timeout = TimeoutChecker::new(std::time::Duration::from_millis(100));
        for entry in &ctx.graph.objects {
            if timeout.check().is_err() {
                break;
            }
            let Some(dict) = entry_dict(entry) else {
                continue;
            };
            let Some((k, xfa_obj)) = dict.get_first(b"/XFA") else {
                continue;
            };
            let evidence = EvidenceBuilder::new()
                .file_offset(dict.span.start, dict.span.len() as u32, "XFA dict")
                .file_offset(k.span.start, k.span.len() as u32, "Key /XFA")
                .build();

            let payloads = xfa_payloads_from_obj(ctx, xfa_obj);
            let mut script_count = 0usize;
            for payload in &payloads {
                if payload.bytes.len() > XFA_MAX_BYTES {
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("xfa.size_bytes".into(), payload.bytes.len().to_string());
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "xfa_too_large".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Probable,
                        title: "XFA content exceeds size limit".into(),
                        description: "XFA content size exceeds the configured threshold.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: evidence.clone(),
                        remediation: Some("Review XFA content in a controlled environment.".into()),
                        meta,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                    });
                }

                let lower = String::from_utf8_lossy(&payload.bytes).to_ascii_lowercase();
                if has_doctype(&lower) {
                    continue;
                }

                script_count += extract_xfa_script_payloads(&payload.bytes).len();
                script_count += count_execute_tags(&lower, XFA_EXECUTE_TAG_LIMIT);

                for url in find_submit_urls(&lower, XFA_SUBMIT_URL_LIMIT) {
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("xfa.submit.url".into(), url.clone());
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "xfa_submit".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Probable,
                        title: "XFA submit action present".into(),
                        description: "XFA form contains submit action with target URL.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: evidence.clone(),
                        remediation: Some("Inspect submission targets and data bindings.".into()),
                        meta,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                    });
                }

                let mut field_names = HashSet::new();
                for name in find_field_names(&lower, XFA_FIELD_NAME_LIMIT) {
                    if is_sensitive_field(&name) {
                        field_names.insert(name);
                    }
                }
                for name in field_names {
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("xfa.field.name".into(), name.clone());
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "xfa_sensitive_field".into(),
                        severity: Severity::Low,
                        confidence: Confidence::Probable,
                        title: "XFA sensitive field present".into(),
                        description: "XFA form contains a sensitive field name.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: evidence.clone(),
                        remediation: Some("Inspect field bindings and data handling.".into()),
                        meta,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                    });
                }
            }

            if script_count > XFA_SCRIPT_COUNT_HIGH {
                let mut meta = std::collections::HashMap::new();
                meta.insert("xfa.script.count".into(), script_count.to_string());
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "xfa_script_count_high".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    title: "XFA script count high".into(),
                    description: "XFA contains an unusually high number of script blocks.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: evidence.clone(),
                    remediation: Some("Inspect XFA scripts for malicious behaviour.".into()),
                    meta,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                });
            }
        }
        Ok(findings)
    }
}

const XFA_MAX_BYTES: usize = 1024 * 1024;
const XFA_SCRIPT_COUNT_HIGH: usize = 5;
const XFA_SUBMIT_URL_LIMIT: usize = 5;
const XFA_FIELD_NAME_LIMIT: usize = 20;
const XFA_EXECUTE_TAG_LIMIT: usize = 50;

fn has_doctype(input: &str) -> bool {
    input.contains("<!doctype")
}

fn find_submit_urls(input: &str, limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    for tag in find_tag_blocks(input, "submit", limit) {
        if let Some(url) = extract_attr_value(&tag, "url") {
            out.push(url);
        } else if let Some(url) = extract_attr_value(&tag, "target") {
            out.push(url);
        }
    }
    out
}

fn find_field_names(input: &str, limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    for tag in find_tag_blocks(input, "field", limit) {
        if let Some(name) = extract_attr_value(&tag, "name") {
            out.push(name);
        }
    }
    out
}

fn find_tag_blocks(input: &str, tag: &str, limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    let needle = format!("<{}", tag);
    let mut idx = 0usize;
    while let Some(pos) = input[idx..].find(&needle) {
        let start = idx + pos;
        let Some(end) = input[start..].find('>') else {
            break;
        };
        let tag_block = &input[start..start + end + 1];
        out.push(tag_block.to_string());
        idx = start + end + 1;
        if out.len() >= limit {
            break;
        }
    }
    out
}

fn count_execute_tags(input: &str, limit: usize) -> usize {
    let mut count = find_tag_blocks(input, "execute", limit).len();
    if count < limit {
        count += find_tag_blocks(input, "xfa:execute", limit - count).len();
    }
    count
}

fn extract_attr_value(tag: &str, attr: &str) -> Option<String> {
    let needle = format!("{}=", attr);
    let pos = tag.find(&needle)?;
    let rest = &tag[pos + needle.len()..];
    let rest = rest.trim_start();
    let quote = rest.chars().next()?;
    let rest = rest.trim_start_matches(quote);
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

fn is_sensitive_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["password", "passwd", "ssn", "credit", "card", "cvv", "pin"]
        .iter()
        .any(|needle| lower.contains(needle))
}
