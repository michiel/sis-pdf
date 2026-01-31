use anyhow::Result;
use std::collections::HashSet;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::evidence::EvidenceBuilder;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::timeout::TimeoutChecker;
use sis_pdf_pdf::classification::ClassificationMap;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj, PdfStr};
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
        let classifications = ctx.classifications();
        for entry in &ctx.graph.objects {
            if timeout.check().is_err() {
                break;
            }
            let Some(dict) = entry_dict(entry) else {
                continue;
            };

            if let Some((k, v)) = dict.get_first(b"/OpenAction") {
                let mut visited = HashSet::new();
                let summary = action_chain_summary(ctx, classifications, v, 1, &mut visited);
                let mut meta = std::collections::HashMap::new();
                meta.insert("action.trigger".into(), "OpenAction".into());
                insert_chain_metadata(
                    &mut meta,
                    "OpenAction",
                    "OpenAction".into(),
                    "automatic",
                    &summary,
                );
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
                if summary.depth >= ACTION_CHAIN_COMPLEX_DEPTH {
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
                        let mut visited = HashSet::new();
                        let summary =
                            action_chain_summary(ctx, classifications, action_obj, 1, &mut visited);
                        let event_label = String::from_utf8_lossy(&event_name.decoded).to_string();
                        let trigger_type = if is_automatic_event(&event_name.decoded) {
                            "automatic"
                        } else {
                            "user"
                        };
                        let mut meta = std::collections::HashMap::new();
                        meta.insert("action.trigger".into(), event_label.clone());
                        insert_chain_metadata(
                            &mut meta,
                            &event_label,
                            event_label.clone(),
                            trigger_type,
                            &summary,
                        );
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

                        if trigger_type == "automatic" {
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

                        if summary.depth >= ACTION_CHAIN_COMPLEX_DEPTH {
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
                    let (event_label, action_obj) = extract_annotation_trigger(dict);
                    let mut visited = HashSet::new();
                    let summary = if let Some(obj) = action_obj {
                        action_chain_summary(ctx, classifications, &obj, 1, &mut visited)
                    } else {
                        ChainSummary::new(1)
                    };
                    insert_chain_metadata(
                        &mut meta,
                        &event_label,
                        event_label.clone(),
                        "hidden",
                        &summary,
                    );
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
                        meta: meta.clone(),
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                    });
                }
            }

            if is_form_field(dict) {
                let field_name = extract_field_name(dict);
                let (hidden_field, hidden_meta) = annotation_hidden_status(dict);

                if let Some((k, action_obj)) = dict.get_first(b"/A") {
                    let mut visited = HashSet::new();
                    let summary =
                        action_chain_summary(ctx, classifications, action_obj, 1, &mut visited);
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("action.trigger".into(), "field".into());
                    meta.insert("action.field_name".into(), field_name.clone());
                    insert_chain_metadata(&mut meta, "field", field_name.clone(), "user", &summary);
                    let evidence = EvidenceBuilder::new()
                        .file_offset(dict.span.start, dict.span.len() as u32, "Field dict")
                        .file_offset(k.span.start, k.span.len() as u32, "/A key")
                        .build();

                    if hidden_field {
                        let mut hidden_with_meta = meta.clone();
                        hidden_with_meta.extend(hidden_meta.clone());
                        findings.push(Finding {
                            id: String::new(),
                            surface: self.surface(),
                            kind: "action_hidden_trigger".into(),
                            severity: Severity::Low,
                            confidence: Confidence::Probable,
                            title: "Hidden action trigger".into(),
                            description:
                                "Form field action triggered from a hidden or non-visible widget."
                                    .into(),
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence: evidence.clone(),
                            remediation: Some(
                                "Inspect hidden fields for unexpected actions.".into(),
                            ),
                            meta: hidden_with_meta,
                            yara: None,
                            position: None,
                            positions: Vec::new(),
                        });
                    }

                    if summary.depth >= ACTION_CHAIN_COMPLEX_DEPTH {
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
                                .file_offset(k.span.start, k.span.len() as u32, "/A key")
                                .build(),
                            remediation: Some("Inspect action chains for hidden payloads.".into()),
                            meta: meta.clone(),
                            yara: None,
                            position: None,
                            positions: Vec::new(),
                        });
                    }
                }

                if let Some((k, aa_obj)) = dict.get_first(b"/AA") {
                    if let PdfAtom::Dict(aa_dict) = &aa_obj.atom {
                        for (event_name, action_obj) in &aa_dict.entries {
                            let mut visited = HashSet::new();
                            let summary = action_chain_summary(
                                ctx,
                                classifications,
                                action_obj,
                                1,
                                &mut visited,
                            );
                            let event_label =
                                String::from_utf8_lossy(&event_name.decoded).to_string();
                            let trigger_type = if is_automatic_event(&event_name.decoded) {
                                "automatic"
                            } else {
                                "user"
                            };
                            let mut meta = std::collections::HashMap::new();
                            meta.insert("action.trigger".into(), event_label.clone());
                            meta.insert("action.field_name".into(), field_name.clone());
                            insert_chain_metadata(
                                &mut meta,
                                &event_label,
                                field_name.clone(),
                                trigger_type,
                                &summary,
                            );
                            let evidence = EvidenceBuilder::new()
                                .file_offset(dict.span.start, dict.span.len() as u32, "Field dict")
                                .file_offset(k.span.start, k.span.len() as u32, "/AA key")
                                .file_offset(
                                    event_name.span.start,
                                    event_name.span.len() as u32,
                                    "AA event",
                                )
                                .build();

                            if trigger_type == "automatic" {
                                findings.push(Finding {
                                    id: String::new(),
                                    surface: self.surface(),
                                    kind: "action_automatic_trigger".into(),
                                    severity: Severity::Medium,
                                    confidence: Confidence::Probable,
                                    title: "Automatic action trigger".into(),
                                    description:
                                        "Field actions triggered automatically via /AA entries."
                                            .into(),
                                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                    evidence: evidence.clone(),
                                    remediation: Some(
                                        "Review automatic field actions for unexpected behavior."
                                            .into(),
                                    ),
                                    meta: meta.clone(),
                                    yara: None,
                                    position: None,
                                    positions: Vec::new(),
                                });
                            }

                            if hidden_field {
                                let mut hidden_with_meta = meta.clone();
                                hidden_with_meta.extend(hidden_meta.clone());
                                findings.push(Finding {
                                    id: String::new(),
                                    surface: self.surface(),
                                    kind: "action_hidden_trigger".into(),
                                    severity: Severity::Low,
                                    confidence: Confidence::Probable,
                                    title: "Hidden action trigger".into(),
                                    description:
                                        "Hidden form field action triggered without visibility."
                                            .into(),
                                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                    evidence: evidence.clone(),
                                    remediation: Some(
                                        "Inspect hidden fields for unexpected actions.".into(),
                                    ),
                                    meta: hidden_with_meta,
                                    yara: None,
                                    position: None,
                                    positions: Vec::new(),
                                });
                            }

                            if summary.depth >= ACTION_CHAIN_COMPLEX_DEPTH {
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
                                    meta: meta.clone(),
                                    yara: None,
                                    position: None,
                                    positions: Vec::new(),
                                });
                            }
                        }
                    }
                }
            }
        }
        Ok(findings)
    }
}

const ACTION_CHAIN_COMPLEX_DEPTH: usize = 3;
const ACTION_CHAIN_MAX_DEPTH: usize = 8;

#[derive(Clone, Default)]
struct ChainSummary {
    depth: usize,
    path: Vec<String>,
}

impl ChainSummary {
    fn new(depth: usize) -> Self {
        Self {
            depth,
            path: Vec::new(),
        }
    }
}

fn action_chain_summary(
    ctx: &sis_pdf_core::scan::ScanContext,
    classifications: &ClassificationMap,
    obj: &PdfObj<'_>,
    depth: usize,
    visited: &mut HashSet<(u32, u16)>,
) -> ChainSummary {
    if depth >= ACTION_CHAIN_MAX_DEPTH {
        return ChainSummary::new(depth);
    }

    match &obj.atom {
        PdfAtom::Ref { obj, gen } => {
            if !visited.insert((*obj, *gen)) {
                let mut summary = ChainSummary::new(depth);
                summary
                    .path
                    .push(describe_object(classifications, *obj, *gen));
                return summary;
            }
            let Some(entry) = ctx.graph.get_object(*obj, *gen) else {
                return ChainSummary::new(depth);
            };
            let resolved = PdfObj {
                span: entry.body_span,
                atom: entry.atom.clone(),
            };
            let mut summary = action_chain_summary(ctx, classifications, &resolved, depth, visited);
            summary
                .path
                .insert(0, describe_object(classifications, *obj, *gen));
            summary
        }
        PdfAtom::Dict(dict) => {
            let mut summary = ChainSummary::new(depth);
            if let Some((_, next)) = dict.get_first(b"/Next") {
                let next_summary =
                    action_chain_summary(ctx, classifications, next, depth + 1, visited);
                summary = best_chain_summary(summary, next_summary);
                if let PdfAtom::Array(arr) = &next.atom {
                    for entry in arr {
                        let branch_summary =
                            action_chain_summary(ctx, classifications, entry, depth + 1, visited);
                        summary = best_chain_summary(summary, branch_summary);
                    }
                }
            }
            summary
        }
        PdfAtom::Array(arr) => {
            let mut summary = ChainSummary::new(depth);
            for entry in arr {
                let branch_summary =
                    action_chain_summary(ctx, classifications, entry, depth, visited);
                summary = best_chain_summary(summary, branch_summary);
            }
            summary
        }
        _ => ChainSummary::new(depth),
    }
}

fn best_chain_summary(a: ChainSummary, b: ChainSummary) -> ChainSummary {
    if b.depth > a.depth {
        b
    } else if b.depth == a.depth && b.path.len() > a.path.len() {
        b
    } else {
        a
    }
}

fn describe_object(classifications: &ClassificationMap, obj: u32, gen: u16) -> String {
    let base = format!("{} {}", obj, gen);
    if let Some(classified) = classifications.get(&(obj, gen)) {
        let mut label = classified.obj_type.as_str().to_string();
        if !classified.roles.is_empty() {
            let roles = classified
                .roles
                .iter()
                .map(|role| role.as_str())
                .collect::<Vec<_>>()
                .join(",");
            label.push_str(&format!(" [{}]", roles));
        }
        format!("{label} ({base})")
    } else {
        format!("obj {base}")
    }
}

fn insert_chain_metadata(
    meta: &mut std::collections::HashMap<String, String>,
    trigger_label: &str,
    trigger_event: String,
    trigger_type: &str,
    summary: &ChainSummary,
) {
    meta.insert("action.chain_depth".into(), summary.depth.to_string());
    meta.insert("action.trigger_event".into(), trigger_event.clone());
    meta.insert("action.trigger_type".into(), trigger_type.into());
    meta.insert(
        "action.chain_path".into(),
        build_chain_path(trigger_label, summary),
    );
}

fn build_chain_path(trigger_label: &str, summary: &ChainSummary) -> String {
    let mut parts = vec![trigger_label.to_string()];
    parts.extend(summary.path.iter().cloned());
    parts.join(" -> ")
}

fn extract_annotation_trigger<'a>(dict: &'a PdfDict<'a>) -> (String, Option<PdfObj<'a>>) {
    if let Some((_, obj)) = dict.get_first(b"/A") {
        return ("annotation".into(), Some(obj.clone()));
    }
    if let Some((_, aa_obj)) = dict.get_first(b"/AA") {
        if let PdfAtom::Dict(aa_dict) = &aa_obj.atom {
            if let Some((event, action_obj)) = aa_dict.entries.first() {
                return (
                    String::from_utf8_lossy(&event.decoded).to_string(),
                    Some(action_obj.clone()),
                );
            }
        }
        return ("annotation".into(), Some(aa_obj.clone()));
    }
    ("annotation".into(), None)
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

fn is_form_field(dict: &PdfDict<'_>) -> bool {
    dict.has_name(b"/Subtype", b"/Widget") || dict.get_first(b"/FT").is_some()
}

fn extract_field_name(dict: &PdfDict<'_>) -> String {
    if let Some((_, obj)) = dict.get_first(b"/T") {
        if let Some(name) = pdf_obj_to_string(obj) {
            return name;
        }
    }
    "unnamed".into()
}

fn pdf_obj_to_string(obj: &PdfObj<'_>) -> Option<String> {
    if let PdfAtom::Str(s) = &obj.atom {
        return Some(match s {
            PdfStr::Literal { decoded, .. } => String::from_utf8_lossy(&decoded).to_string(),
            PdfStr::Hex { decoded, .. } => String::from_utf8_lossy(&decoded).to_string(),
        });
    }
    None
}
