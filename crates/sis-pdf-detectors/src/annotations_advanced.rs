use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::page_tree::build_annotation_parent_map;
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::PdfAtom;

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
            if let Some(parent) = annot_parent.get(&sis_pdf_core::graph_walk::ObjRef {
                obj: entry.obj,
                gen: entry.gen,
            }) {
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
                            title: "Hidden annotation".into(),
                            description: "Annotation rectangle has near-zero size.".into(),
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence: vec![span_to_evidence(dict.span, "Annotation dict")],
                            remediation: Some("Inspect hidden annotations for actions.".into()),
                            meta: meta.clone(),
                            yara: None,
                            position: None,
                            positions: Vec::new(),
                        });
                    }
                }
            }
            if dict.get_first(b"/A").is_some() || dict.get_first(b"/AA").is_some() {
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "annotation_action_chain".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    title: "Annotation action chain".into(),
                    description: "Annotation contains /A or /AA action entries.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: vec![span_to_evidence(dict.span, "Annotation dict")],
                    remediation: Some("Review annotation actions and appearance streams.".into()),
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
