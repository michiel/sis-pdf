use anyhow::Result;
use std::collections::HashMap;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::page_tree::build_annotation_parent_map;
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};

use crate::{entry_dict, uri_classification::analyze_uri_content};

pub struct AnnotationAttackDetector;
const ANNOTATION_ACTION_CHAIN_CAP: usize = 25;
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

                            reader_impacts: Vec::new(),
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
            if dict.get_first(b"/A").is_some() || dict.get_first(b"/AA").is_some() {
                let (
                    trigger_kind,
                    trigger_context,
                    trigger_event,
                    action_type,
                    action_target,
                    action_initiation,
                ) =
                    annotation_action_context(ctx, dict);
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
            }
        }
        apply_kind_cap(&mut findings, "annotation_action_chain", ANNOTATION_ACTION_CHAIN_CAP);
        Ok(findings)
    }
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
            return Severity::Low;
        }
        return Severity::Info;
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
    use sis_pdf_core::model::Finding;
    use sis_pdf_core::model::Severity;

    #[test]
    fn annotation_user_benign_uri_is_info() {
        let sev = annotation_action_severity("/URI", "https://australiansuper.com/TMD", "user");
        assert_eq!(sev, Severity::Info);
    }

    #[test]
    fn annotation_user_suspicious_uri_is_low() {
        let sev = annotation_action_severity("/URI", "https://user@example.com/login", "user");
        assert_eq!(sev, Severity::Low);
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
}
