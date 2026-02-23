use anyhow::Result;
use std::collections::HashMap;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::page_tree::build_annotation_parent_map;
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::graph::ObjEntry;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};
use sis_pdf_pdf::span::Span;

use crate::{entry_dict, uri_classification::analyze_uri_content};

pub struct AnnotationAttackDetector;
const ANNOTATION_ACTION_CHAIN_CAP: usize = 25;
const URI_DANGEROUS_SCHEME_CAP: usize = 10;
const ANNOTATION_FIELD_INJECTION_CAP: usize = 10;
const AGGREGATE_SAMPLE_LIMIT: usize = 8;

impl Detector for AnnotationAttackDetector {
    fn id(&self) -> &'static str {
        "annotation_attack"
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

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let annot_parent = build_annotation_parent_map(&ctx.graph);
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            let Some(dict) = entry_dict(entry) else {
                continue;
            };
            if dict.get_first(b"/Subtype").is_none() {
                continue;
            }
            let mut meta = std::collections::HashMap::new();
            if let Some(subtype) = annotation_subtype(dict) {
                meta.insert("annot.subtype".into(), subtype);
            }
            if let Some(parent) = annot_parent
                .get(&sis_pdf_core::graph_walk::ObjRef { obj: entry.obj, gen: entry.gen })
            {
                meta.insert("page.number".into(), parent.number.to_string());
            }
            if let Some(rect) = dict.get_first(b"/Rect").map(|(_, v)| v) {
                if let Some((w, h)) = rect_size(rect) {
                    meta.insert("annot.width".into(), format!("{:.2}", w));
                    meta.insert("annot.height".into(), format!("{:.2}", h));
                    meta.insert("annot.trigger_context".into(), "annotation_geometry".into());
                    if w <= 0.1 || h <= 0.1 {
                        findings.push(Finding {
                            id: String::new(),
                            surface: self.surface(),
                            kind: "annotation_hidden".into(),
                            severity: Severity::Low,
                            confidence: Confidence::Probable,
                            impact: None,
                            title: "Hidden annotation".into(),
                            description: "Annotation rectangle has near-zero size.".into(),
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence: vec![span_to_evidence(dict.span, "Annotation dict")],
                            remediation: Some("Inspect hidden annotations for actions.".into()),
                            meta: meta.clone(),
                            action_type: None,
                            action_target: None,
                            action_initiation: None,
                            yara: None,
                            position: None,
                            positions: Vec::new(),
                        });
                    }
                }
            }
            if let Some(field_injection) =
                check_annotation_field_injection(entry, dict, dict.span)
            {
                findings.push(field_injection);
            }
            if dict.get_first(b"/A").is_some() || dict.get_first(b"/AA").is_some() {
                let (
                    trigger_kind,
                    trigger_context,
                    trigger_event,
                    action_type,
                    action_target,
                    action_initiation,
                ) = annotation_action_context(ctx, dict);
                let severity = annotation_action_severity(
                    action_type.as_str(),
                    action_target.as_str(),
                    action_initiation.as_str(),
                );
                meta.insert("annot.trigger_context".into(), trigger_context.clone());
                if !action_type.is_empty() {
                    meta.insert("action.type".into(), action_type.clone());
                }
                if !action_target.is_empty() {
                    meta.insert("action.target".into(), action_target.clone());
                }
                if action_type.to_ascii_uppercase() == "/URI" && !action_target.is_empty() {
                    let uri_analysis = analyze_uri_content(action_target.as_bytes());
                    if !uri_analysis.scheme.is_empty() {
                        meta.insert("uri.scheme".into(), uri_analysis.scheme.clone());
                    }
                }
                if !action_initiation.is_empty() {
                    meta.insert("action.initiation".into(), action_initiation.clone());
                    meta.insert("action.trigger_type".into(), action_initiation.clone());
                }
                if !trigger_event.is_empty() {
                    meta.insert("action.trigger_event".into(), trigger_event.clone());
                    meta.insert(
                        "action.trigger_event_normalised".into(),
                        normalise_annotation_trigger_event(&trigger_event),
                    );
                }
                meta.insert("action.trigger_context".into(), trigger_context);
                meta.insert("chain.stage".into(), "execute".into());
                meta.insert("chain.capability".into(), "action_trigger_chain".into());
                meta.insert("chain.trigger".into(), "annotation_action".into());
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "annotation_action_chain".into(),
                    severity,
                    confidence: Confidence::Probable,
                    impact: None,
                    title: "Annotation action chain".into(),
                    description: format!(
                        "Annotation contains {} action; type={} target={} initiation={}.",
                        trigger_kind, action_type, action_target, action_initiation
                    ),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: vec![span_to_evidence(dict.span, "Annotation dict")],
                    remediation: Some(
                        "Inspect action target and trigger event; validate whether initiation requires user interaction."
                            .into(),
                    ),
                    meta,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                    ..Finding::default()
                });
                if action_type.to_ascii_uppercase() == "/URI" {
                    if let Some(scheme_finding) =
                        check_uri_dangerous_scheme(entry, &action_target, dict.span)
                    {
                        findings.push(scheme_finding);
                    }
                }
            }
        }
        apply_kind_cap(&mut findings, "annotation_action_chain", ANNOTATION_ACTION_CHAIN_CAP);
        apply_kind_cap(&mut findings, "uri_javascript_scheme", URI_DANGEROUS_SCHEME_CAP);
        apply_kind_cap(&mut findings, "uri_file_scheme", URI_DANGEROUS_SCHEME_CAP);
        apply_kind_cap(&mut findings, "uri_data_html_scheme", URI_DANGEROUS_SCHEME_CAP);
        apply_kind_cap(&mut findings, "uri_command_injection", URI_DANGEROUS_SCHEME_CAP);
        apply_kind_cap(&mut findings, "annotation_field_html_injection", ANNOTATION_FIELD_INJECTION_CAP);
        Ok(findings)
    }
}

fn check_uri_dangerous_scheme(
    entry: &ObjEntry<'_>,
    action_target: &str,
    dict_span: Span,
) -> Option<Finding> {
    if action_target.is_empty() || action_target == "unknown" {
        return None;
    }
    let analysis = analyze_uri_content(action_target.as_bytes());
    let (kind, confidence, classification, description): (&str, Confidence, &str, &str) =
        if analysis.is_javascript_uri {
            (
                "uri_javascript_scheme",
                Confidence::Strong,
                "javascript",
                "URI action uses javascript: scheme enabling direct code execution in the PDF viewer context.",
            )
        } else if analysis.is_file_uri {
            (
                "uri_file_scheme",
                Confidence::Strong,
                "file",
                "URI action uses file:// scheme enabling local file access or process launch.",
            )
        } else if analysis.is_data_uri
            && analysis
                .data_mime
                .as_deref()
                .map(|m| m == "text/html" || m.starts_with("application/"))
                .unwrap_or(false)
        {
            (
                "uri_data_html_scheme",
                Confidence::Strong,
                "data",
                "URI action uses data: scheme with HTML or application MIME type, enabling arbitrary content rendering.",
            )
        } else {
            let lower = action_target.to_ascii_lowercase();
            if lower.starts_with("start ")
                || lower.starts_with("cmd ")
                || lower.starts_with("cmd.exe")
                || lower.starts_with("shell:")
            {
                (
                    "uri_command_injection",
                    Confidence::Probable,
                    "command",
                    "URI action contains OS command injection pattern (START/cmd/shell:) inconsistent with valid URI syntax.",
                )
            } else {
                return None;
            }
        };
    let mut meta = HashMap::new();
    meta.insert("uri.scheme".into(), analysis.scheme.clone());
    meta.insert("uri.target".into(), action_target.to_string());
    meta.insert("uri.classification".into(), classification.into());
    Some(Finding {
        id: String::new(),
        surface: AttackSurface::Actions,
        kind: kind.into(),
        severity: Severity::High,
        confidence,
        impact: None,
        title: format!("Dangerous URI scheme: {}", analysis.scheme),
        description: description.into(),
        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
        evidence: vec![span_to_evidence(dict_span, "Annotation dict /A action")],
        remediation: Some(
            "Treat as active code execution vector; inspect URI content and PDF reader processing."
                .into(),
        ),
        meta,
        yara: None,
        position: None,
        positions: Vec::new(),
        ..Finding::default()
    })
}

/// HTML injection patterns for /T and /Contents annotation field scanning.
const FIELD_INJECTION_PATTERNS: &[&[u8]] = &[
    b"<script",
    b"<iframe",
    b"<svg",
    b"javascript:",
    b"onerror=",
    b"onload=",
    b"ontoggle=",
    b"onfocus=",
    b"><",
    b"'><",
    b"\"><",
];

fn check_annotation_field_injection(
    entry: &ObjEntry<'_>,
    dict: &PdfDict<'_>,
    dict_span: Span,
) -> Option<Finding> {
    let mut matched_field: Option<&'static str> = None;
    let mut matched_patterns: Vec<&str> = Vec::new();

    for (field_key, field_name) in [(b"/T" as &[u8], "/T"), (b"/Contents", "/Contents")] {
        let Some((_, field_obj)) = dict.get_first(field_key) else {
            continue;
        };
        let PdfAtom::Str(s) = &field_obj.atom else {
            continue;
        };
        let bytes = pdf_string_bytes(s);
        let lower = bytes.to_ascii_lowercase();
        let hits: Vec<&str> = FIELD_INJECTION_PATTERNS
            .iter()
            .filter_map(|pat| {
                if lower.windows(pat.len()).any(|w| w == *pat) {
                    Some(std::str::from_utf8(pat).unwrap_or("?"))
                } else {
                    None
                }
            })
            .collect();
        if !hits.is_empty() {
            matched_field = Some(field_name);
            matched_patterns = hits;
            break;
        }
    }

    let field = matched_field?;
    let mut meta = HashMap::new();
    meta.insert("annot.field".into(), field.into());
    if let Some(subtype) = dict.get_first(b"/Subtype").and_then(|(_, obj)| match &obj.atom {
        PdfAtom::Name(name) => {
            Some(String::from_utf8_lossy(&name.decoded).to_string())
        }
        _ => None,
    }) {
        meta.insert("annot.subtype".into(), subtype);
    }
    meta.insert("injection.patterns".into(), matched_patterns.join(", "));
    Some(Finding {
        id: String::new(),
        surface: AttackSurface::ContentPhishing,
        kind: "annotation_field_html_injection".into(),
        severity: Severity::Medium,
        confidence: Confidence::Probable,
        impact: None,
        title: "HTML injection in annotation text field".into(),
        description: format!(
            "Annotation {} field contains HTML or JavaScript-like content. Web-based PDF viewers that render these fields in the DOM may be vulnerable to XSS.",
            field
        ),
        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
        evidence: vec![span_to_evidence(dict_span, &format!("Annotation dict {} field", field))],
        remediation: Some(
            "Inspect annotation text fields for XSS payloads; sanitise before rendering in web viewers."
                .into(),
        ),
        meta,
        yara: None,
        position: None,
        positions: Vec::new(),
        ..Finding::default()
    })
}

fn apply_kind_cap(findings: &mut Vec<Finding>, kind: &str, cap: usize) {
    if cap == 0 || findings.is_empty() {
        return;
    }
    let mut retained = 0usize;
    let mut total = 0usize;
    let mut suppressed = 0usize;
    let mut first_index: Option<usize> = None;
    let mut sample_objects = Vec::new();
    let mut sample_positions = Vec::new();
    let mut out = Vec::with_capacity(findings.len());
    for finding in findings.drain(..) {
        if finding.kind != kind {
            out.push(finding);
            continue;
        }
        total += 1;
        if retained < cap {
            retained += 1;
            if first_index.is_none() {
                first_index = Some(out.len());
            }
            out.push(finding);
            continue;
        }
        suppressed += 1;
        for object in &finding.objects {
            if !sample_objects.contains(object) && sample_objects.len() < AGGREGATE_SAMPLE_LIMIT {
                sample_objects.push(object.clone());
            }
        }
        for position in &finding.positions {
            if !sample_positions.contains(position)
                && sample_positions.len() < AGGREGATE_SAMPLE_LIMIT
            {
                sample_positions.push(position.clone());
            }
        }
    }
    if suppressed > 0 {
        if let Some(index) = first_index {
            if let Some(finding) = out.get_mut(index) {
                let meta: &mut HashMap<String, String> = &mut finding.meta;
                meta.insert("aggregate.enabled".into(), "true".into());
                meta.insert("aggregate.kind".into(), kind.to_string());
                meta.insert("aggregate.total_count".into(), total.to_string());
                meta.insert("aggregate.retained_count".into(), retained.to_string());
                meta.insert("aggregate.suppressed_count".into(), suppressed.to_string());
                if !sample_objects.is_empty() {
                    meta.insert(
                        "aggregate.sample_suppressed_objects".into(),
                        sample_objects.join(", "),
                    );
                }
                if !sample_positions.is_empty() {
                    meta.insert(
                        "aggregate.sample_suppressed_positions".into(),
                        sample_positions.join(", "),
                    );
                }
            }
        }
    }
    *findings = out;
}

fn rect_size(obj: &sis_pdf_pdf::object::PdfObj<'_>) -> Option<(f32, f32)> {
    let PdfAtom::Array(arr) = &obj.atom else {
        return None;
    };
    if arr.len() < 4 {
        return None;
    }
    let vals: Vec<f32> = arr
        .iter()
        .take(4)
        .filter_map(|v| match &v.atom {
            PdfAtom::Int(i) => Some(*i as f32),
            PdfAtom::Real(f) => Some(*f as f32),
            _ => None,
        })
        .collect();
    if vals.len() < 4 {
        return None;
    }
    let w = (vals[2] - vals[0]).abs();
    let h = (vals[3] - vals[1]).abs();
    Some((w, h))
}

fn annotation_action_context(
    ctx: &sis_pdf_core::scan::ScanContext,
    dict: &PdfDict<'_>,
) -> (String, String, String, String, String, String) {
    if let Some((_, action_obj)) = dict.get_first(b"/A") {
        let (action_type, target) = action_type_and_target(ctx, action_obj);
        return (
            "/A".into(),
            "annotation_action".into(),
            "/A".into(),
            action_type.unwrap_or_else(|| "unknown".into()),
            target.unwrap_or_else(|| "unknown".into()),
            "user".into(),
        );
    }

    if let Some((_, aa_obj)) = dict.get_first(b"/AA") {
        if let PdfAtom::Dict(aa_dict) = &aa_obj.atom {
            if let Some((event, action_obj)) = aa_dict.entries.first() {
                let event_name = String::from_utf8_lossy(&event.decoded).to_string();
                let (action_type, target) = action_type_and_target(ctx, action_obj);
                let initiation =
                    if is_automatic_event(&event.decoded) { "automatic" } else { "user" };
                return (
                    format!("/AA {}", event_name),
                    "annotation_aa".into(),
                    event_name,
                    action_type.unwrap_or_else(|| "unknown".into()),
                    target.unwrap_or_else(|| "unknown".into()),
                    initiation.into(),
                );
            }
        }
    }

    (
        "/A or /AA".into(),
        "annotation_action".into(),
        "unknown".into(),
        "unknown".into(),
        "unknown".into(),
        "unknown".into(),
    )
}

fn action_type_and_target(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj: &PdfObj<'_>,
) -> (Option<String>, Option<String>) {
    let action_obj = match &obj.atom {
        PdfAtom::Dict(_) => obj.clone(),
        PdfAtom::Ref { .. } => {
            let resolved = ctx.graph.resolve_ref(obj);
            let Some(entry) = resolved else {
                return (None, None);
            };
            PdfObj { span: entry.body_span, atom: entry.atom }
        }
        _ => return (None, None),
    };

    let PdfAtom::Dict(action_dict) = &action_obj.atom else {
        return (None, None);
    };
    let action_type = action_dict.get_first(b"/S").and_then(|(_, v)| match &v.atom {
        PdfAtom::Name(name) => Some(String::from_utf8_lossy(&name.decoded).to_string()),
        _ => None,
    });
    let action_target = action_dict
        .get_first(b"/URI")
        .and_then(|(_, v)| stringish_value(v))
        .or_else(|| action_dict.get_first(b"/F").and_then(|(_, v)| stringish_value(v)))
        .or_else(|| action_dict.get_first(b"/JS").map(|_| "JavaScript payload".to_string()));
    (action_type, action_target)
}

fn stringish_value(obj: &PdfObj<'_>) -> Option<String> {
    match &obj.atom {
        PdfAtom::Str(s) => Some(String::from_utf8_lossy(&pdf_string_bytes(s)).to_string()),
        PdfAtom::Name(name) => Some(String::from_utf8_lossy(&name.decoded).to_string()),
        _ => None,
    }
}

fn pdf_string_bytes(s: &sis_pdf_pdf::object::PdfStr<'_>) -> Vec<u8> {
    match s {
        sis_pdf_pdf::object::PdfStr::Literal { decoded, .. } => decoded.clone(),
        sis_pdf_pdf::object::PdfStr::Hex { decoded, .. } => decoded.clone(),
    }
}

fn is_automatic_event(name: &[u8]) -> bool {
    matches!(name, b"/O" | b"/C" | b"/PV" | b"/PI" | b"/V" | b"/PO")
}

fn annotation_action_severity(
    action_type: &str,
    action_target: &str,
    initiation: &str,
) -> Severity {
    if !initiation.eq_ignore_ascii_case("user") {
        return Severity::Medium;
    }

    let action_upper = action_type.to_ascii_uppercase();
    if matches!(
        action_upper.as_str(),
        "/JAVASCRIPT" | "/LAUNCH" | "/SUBMITFORM" | "/IMPORTDATA" | "/RENDITION"
    ) {
        return Severity::Medium;
    }

    if action_upper == "/URI" {
        if uri_target_is_suspicious(action_target) {
            return Severity::Medium;
        }
        return Severity::Low;
    }

    Severity::Low
}

fn uri_target_is_suspicious(target: &str) -> bool {
    if target.is_empty() || target == "unknown" {
        return false;
    }
    let analysis = analyze_uri_content(target.as_bytes());
    analysis.userinfo_present
        || analysis.is_javascript_uri
        || analysis.is_data_uri
        || analysis.is_file_uri
        || analysis.is_ip_address
        || analysis.has_embedded_ip_host
        || analysis.has_non_standard_port
        || analysis.suspicious_tld
        || analysis.has_shortener_domain
        || analysis.has_idn_lookalike
}

fn annotation_subtype(dict: &PdfDict<'_>) -> Option<String> {
    dict.get_first(b"/Subtype").and_then(|(_, obj)| match &obj.atom {
        PdfAtom::Name(name) => Some(String::from_utf8_lossy(&name.decoded).to_string()),
        _ => None,
    })
}

fn normalise_annotation_trigger_event(event: &str) -> String {
    if event == "unknown" || event.is_empty() {
        return "unknown".into();
    }
    if event.starts_with('/') {
        return event.into();
    }
    format!("/{event}")
}

#[cfg(test)]
mod tests {
    use super::{annotation_action_severity, apply_kind_cap, uri_target_is_suspicious};
    use sis_pdf_core::model::{Finding, Severity};

    #[test]
    fn annotation_user_benign_uri_is_low() {
        let sev = annotation_action_severity("/URI", "https://australiansuper.com/TMD", "user");
        assert_eq!(sev, Severity::Low);
    }

    #[test]
    fn annotation_user_suspicious_uri_is_medium() {
        let sev = annotation_action_severity("/URI", "https://user@example.com/login", "user");
        assert_eq!(sev, Severity::Medium);
        assert!(uri_target_is_suspicious("https://user@example.com/login"));
    }

    #[test]
    fn annotation_risky_action_stays_medium() {
        let sev = annotation_action_severity("/JavaScript", "JavaScript payload", "user");
        assert_eq!(sev, Severity::Medium);
    }

    #[test]
    fn annotation_automatic_trigger_stays_medium() {
        let sev = annotation_action_severity("/URI", "https://example.com", "automatic");
        assert_eq!(sev, Severity::Medium);
    }

    #[test]
    fn annotation_action_chain_cap_aggregates_overflow() {
        let mut findings = Vec::new();
        for index in 0..35usize {
            findings.push(Finding {
                kind: "annotation_action_chain".into(),
                objects: vec![format!("{index} 0 obj")],
                positions: vec![format!("doc:r0/obj.{index}")],
                ..Finding::default()
            });
        }
        apply_kind_cap(&mut findings, "annotation_action_chain", 25);
        let retained =
            findings.iter().filter(|finding| finding.kind == "annotation_action_chain").count();
        assert_eq!(retained, 25);
        let first = findings
            .iter()
            .find(|finding| finding.kind == "annotation_action_chain")
            .expect("retained finding");
        assert_eq!(first.meta.get("aggregate.suppressed_count").map(String::as_str), Some("10"));
    }

    // --- URI dangerous scheme unit tests ---

    #[test]
    fn uri_javascript_scheme_detection() {
        // javascript: URI should be flagged
        assert!(uri_target_is_suspicious("javascript:confirm(1)"));
    }

    #[test]
    fn uri_file_scheme_is_suspicious() {
        assert!(uri_target_is_suspicious("file:///C:/Windows/calc.exe"));
    }

    #[test]
    fn uri_data_html_scheme_is_suspicious() {
        // data: URIs are flagged by uri_target_is_suspicious via is_data_uri
        assert!(uri_target_is_suspicious("data:text/html,<script>x</script>"));
    }

    #[test]
    fn benign_https_uri_not_suspicious() {
        assert!(!uri_target_is_suspicious("https://example.com/page"));
    }

    #[test]
    fn uri_dangerous_scheme_cap_aggregates_overflow() {
        let mut findings = Vec::new();
        for index in 0..15usize {
            findings.push(Finding {
                kind: "uri_javascript_scheme".into(),
                objects: vec![format!("{index} 0 obj")],
                ..Finding::default()
            });
        }
        apply_kind_cap(&mut findings, "uri_javascript_scheme", 10);
        let retained =
            findings.iter().filter(|f| f.kind == "uri_javascript_scheme").count();
        assert_eq!(retained, 10);
        let first = findings.iter().find(|f| f.kind == "uri_javascript_scheme").expect("finding");
        assert_eq!(first.meta.get("aggregate.suppressed_count").map(String::as_str), Some("5"));
    }
}
