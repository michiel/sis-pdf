use anyhow::Result;
use std::collections::HashSet;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::evidence::EvidenceBuilder;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::timeout::TimeoutChecker;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};
use std::time::Duration;

use crate::entry_dict;

pub struct ActionTriggerDetector;

impl Detector for ActionTriggerDetector {
    fn id(&self) -> &'static str {
        "action_trigger_analysis"
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
        let mut findings = Vec::new();
        let timeout = TimeoutChecker::new(Duration::from_millis(100));
        for entry in &ctx.graph.objects {
            if timeout.check().is_err() {
                break;
            }
            let Some(dict) = entry_dict(entry) else {
                continue;
            };

            if let Some((k, v)) = dict.get_first(b"/OpenAction") {
                let depth = action_chain_depth(ctx, v, 1, &mut HashSet::new());
                let mut meta = std::collections::HashMap::new();
                meta.insert("action.trigger".into(), "OpenAction".into());
                meta.insert("action.chain_depth".into(), depth.to_string());
                let evidence = EvidenceBuilder::new()
                    .file_offset(dict.span.start, dict.span.len() as u32, "Catalog dict")
                    .file_offset(k.span.start, k.span.len() as u32, "OpenAction key")
                    .build();
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "action_automatic_trigger".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    title: "Automatic action trigger".into(),
                    description: "OpenAction triggers automatically on document open.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence,
                    remediation: Some("Review the action target and payload.".into()),
                    meta: meta.clone(),
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                });
                if depth >= ACTION_CHAIN_COMPLEX_DEPTH {
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "action_chain_complex".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Probable,
                        title: "Complex action chain".into(),
                        description: "Action chain depth exceeds expected threshold.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: EvidenceBuilder::new()
                            .file_offset(k.span.start, k.span.len() as u32, "OpenAction key")
                            .build(),
                        remediation: Some("Inspect action chains for hidden payloads.".into()),
                        meta,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                    });
                }
            }

            if let Some((k, v)) = dict.get_first(b"/AA") {
                if let PdfAtom::Dict(aa_dict) = &v.atom {
                    for (event_name, action_obj) in &aa_dict.entries {
                        let depth = action_chain_depth(ctx, action_obj, 1, &mut HashSet::new());
                        let mut meta = std::collections::HashMap::new();
                        meta.insert(
                            "action.trigger".into(),
                            String::from_utf8_lossy(&event_name.decoded).to_string(),
                        );
                        meta.insert("action.chain_depth".into(), depth.to_string());
                        let evidence = EvidenceBuilder::new()
                            .file_offset(
                                dict.span.start,
                                dict.span.len() as u32,
                                "Action container dict",
                            )
                            .file_offset(k.span.start, k.span.len() as u32, "AA key")
                            .file_offset(
                                event_name.span.start,
                                event_name.span.len() as u32,
                                "AA event",
                            )
                            .build();

                        if is_automatic_event(&event_name.decoded) {
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "action_automatic_trigger".into(),
                                severity: Severity::Medium,
                                confidence: Confidence::Probable,
                                title: "Automatic action trigger".into(),
                                description:
                                    "Additional action triggers without explicit user interaction."
                                        .into(),
                                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                evidence: evidence.clone(),
                                remediation: Some("Review the action target and payload.".into()),
                                meta: meta.clone(),
                                yara: None,
                                position: None,
                                positions: Vec::new(),
                            });
                        }

                        if depth >= ACTION_CHAIN_COMPLEX_DEPTH {
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "action_chain_complex".into(),
                                severity: Severity::Medium,
                                confidence: Confidence::Probable,
                                title: "Complex action chain".into(),
                                description: "Action chain depth exceeds expected threshold."
                                    .into(),
                                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                evidence: EvidenceBuilder::new()
                                    .file_offset(
                                        event_name.span.start,
                                        event_name.span.len() as u32,
                                        "AA event",
                                    )
                                    .build(),
                                remediation: Some(
                                    "Inspect action chains for hidden payloads.".into(),
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

            if is_annotation(dict)
                && (dict.get_first(b"/A").is_some() || dict.get_first(b"/AA").is_some())
            {
                let (hidden, mut meta) = annotation_hidden_status(dict);
                if hidden {
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "action_hidden_trigger".into(),
                        severity: Severity::Low,
                        confidence: Confidence::Probable,
                        title: "Hidden action trigger".into(),
                        description: "Action triggered from a hidden or non-visible annotation."
                            .into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: EvidenceBuilder::new()
                            .file_offset(dict.span.start, dict.span.len() as u32, "Annotation dict")
                            .build(),
                        remediation: Some(
                            "Inspect hidden annotations for action execution.".into(),
                        ),
                        meta: meta.drain().collect(),
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                    });
                }
            }
        }
        Ok(findings)
    }
}

const ACTION_CHAIN_COMPLEX_DEPTH: usize = 3;
const ACTION_CHAIN_MAX_DEPTH: usize = 8;

fn action_chain_depth(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj: &PdfObj<'_>,
    depth: usize,
    visited: &mut HashSet<(u32, u16)>,
) -> usize {
    if depth >= ACTION_CHAIN_MAX_DEPTH {
        return depth;
    }
    match &obj.atom {
        PdfAtom::Ref { obj, gen } => {
            if !visited.insert((*obj, *gen)) {
                return depth;
            }
            let Some(entry) = ctx.graph.get_object(*obj, *gen) else {
                return depth;
            };
            let resolved = PdfObj {
                span: entry.body_span,
                atom: entry.atom.clone(),
            };
            action_chain_depth(ctx, &resolved, depth, visited)
        }
        PdfAtom::Dict(dict) => {
            let mut max_depth = depth;
            if let Some((_, next)) = dict.get_first(b"/Next") {
                let next_depth = action_chain_depth(ctx, next, depth + 1, visited);
                if next_depth > max_depth {
                    max_depth = next_depth;
                }
                if let PdfAtom::Array(arr) = &next.atom {
                    for entry in arr {
                        let entry_depth = action_chain_depth(ctx, entry, depth + 1, visited);
                        if entry_depth > max_depth {
                            max_depth = entry_depth;
                        }
                    }
                }
            }
            max_depth
        }
        PdfAtom::Array(arr) => {
            let mut max_depth = depth;
            for entry in arr {
                let entry_depth = action_chain_depth(ctx, entry, depth, visited);
                if entry_depth > max_depth {
                    max_depth = entry_depth;
                }
            }
            max_depth
        }
        _ => depth,
    }
}

fn is_automatic_event(name: &[u8]) -> bool {
    matches!(name, b"/O" | b"/C" | b"/PV" | b"/PI" | b"/V" | b"/PO")
}

fn is_annotation(dict: &PdfDict<'_>) -> bool {
    dict.get_first(b"/Subtype").is_some()
}

fn annotation_hidden_status(
    dict: &PdfDict<'_>,
) -> (bool, std::collections::HashMap<String, String>) {
    let mut meta = std::collections::HashMap::new();
    if let Some(rect) = dict.get_first(b"/Rect").map(|(_, v)| v) {
        if let Some((w, h)) = rect_size(rect) {
            meta.insert("annot.width".into(), format!("{:.2}", w));
            meta.insert("annot.height".into(), format!("{:.2}", h));
            if w <= 0.1 || h <= 0.1 {
                return (true, meta);
            }
        }
    }
    if let Some((_, flags)) = dict.get_first(b"/F") {
        if let PdfAtom::Int(value) = &flags.atom {
            let flag_value = *value as u32;
            meta.insert("annot.flags".into(), flag_value.to_string());
            if (flag_value & (1 << 1)) != 0 || (flag_value & (1 << 5)) != 0 {
                return (true, meta);
            }
        }
    }
    (false, meta)
}

fn rect_size(obj: &PdfObj<'_>) -> Option<(f32, f32)> {
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
