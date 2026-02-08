use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::page_tree::build_annotation_parent_map;
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};

use crate::entry_dict;

pub struct AnnotationAttackDetector;

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
            if let Some(parent) = annot_parent
                .get(&sis_pdf_core::graph_walk::ObjRef { obj: entry.obj, gen: entry.gen })
            {
                meta.insert("page.number".into(), parent.number.to_string());
            }
            if let Some(rect) = dict.get_first(b"/Rect").map(|(_, v)| v) {
                if let Some((w, h)) = rect_size(rect) {
                    meta.insert("annot.width".into(), format!("{:.2}", w));
                    meta.insert("annot.height".into(), format!("{:.2}", h));
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
                let (trigger_kind, action_type, action_target, action_initiation) =
                    annotation_action_context(ctx, dict);
                if !action_type.is_empty() {
                    meta.insert("action.type".into(), action_type.clone());
                }
                if !action_target.is_empty() {
                    meta.insert("action.target".into(), action_target.clone());
                }
                if !action_initiation.is_empty() {
                    meta.insert("action.initiation".into(), action_initiation.clone());
                }
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "annotation_action_chain".into(),
                    severity: Severity::Medium,
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
        Ok(findings)
    }
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
) -> (String, String, String, String) {
    if let Some((_, action_obj)) = dict.get_first(b"/A") {
        let (action_type, target) = action_type_and_target(ctx, action_obj);
        return (
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
                    action_type.unwrap_or_else(|| "unknown".into()),
                    target.unwrap_or_else(|| "unknown".into()),
                    initiation.into(),
                );
            }
        }
    }

    ("/A or /AA".into(), "unknown".into(), "unknown".into(), "unknown".into())
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
