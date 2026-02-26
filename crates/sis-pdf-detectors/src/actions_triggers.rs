use anyhow::Result;
use std::collections::{HashMap, HashSet};

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::evidence::EvidenceBuilder;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::timeout::TimeoutChecker;
use sis_pdf_pdf::classification::ClassificationMap;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj, PdfStr};
use std::time::Duration;

use crate::{action_type_from_obj, annotate_action_meta, entry_dict};

pub struct ActionTriggerDetector;
const ACTION_FINDING_CAP: usize = 25;
const AGGREGATE_SAMPLE_LIMIT: usize = 8;

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
                    "open_action",
                    &summary,
                );
                let action_type =
                    action_type_from_obj(ctx, v).unwrap_or_else(|| "OpenAction".into());
                let severity = if action_type_is_high_risk(&action_type) {
                    Severity::Medium
                } else {
                    Severity::Low
                };
                let target_value = meta.get("action.chain_path").cloned();
                annotate_action_meta(&mut meta, &action_type, target_value.as_deref(), "automatic");
                let evidence = EvidenceBuilder::new()
                    .file_offset(dict.span.start, dict.span.len() as u32, "Catalog dict")
                    .file_offset(k.span.start, k.span.len() as u32, "OpenAction key")
                    .build();
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "action_automatic_trigger".into(),
                    severity,
                    confidence: Confidence::Probable,
                    impact: None,
                    title: "Automatic action trigger".into(),
                    description: "OpenAction triggers automatically on document open.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence,
                    remediation: Some("Review the action target and payload.".into()),
                    meta: meta.clone(),
                    action_type: None,
                    action_target: None,
                    action_initiation: None,
                    yara: None,
                    positions: Vec::new(),
                });
                if summary.depth >= ACTION_CHAIN_COMPLEX_DEPTH {
                    let mut complex_meta = meta.clone();
                    enrich_complex_chain_meta(&mut complex_meta, &summary);
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "action_chain_complex".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Probable,
                        impact: None,
                        title: "Complex action chain".into(),
                        description: complex_action_chain_description(&complex_meta),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: EvidenceBuilder::new()
                            .file_offset(k.span.start, k.span.len() as u32, "OpenAction key")
                            .build(),
                        remediation: Some(
                            "Review the full chain path, terminal action, and payload target for staged execution."
                                .into(),
                        ),
                        meta: complex_meta,
                        action_type: None,
                        action_target: None,
                        action_initiation: None,
                        yara: None,
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
                            "aa",
                            &summary,
                        );
                        let action_type = action_type_from_obj(ctx, action_obj)
                            .unwrap_or_else(|| event_label.clone());
                        let severity = if action_type_is_high_risk(&action_type) {
                            Severity::Medium
                        } else {
                            Severity::Low
                        };
                        let target_value = meta.get("action.chain_path").cloned();
                        annotate_action_meta(
                            &mut meta,
                            &action_type,
                            target_value.as_deref(),
                            trigger_type,
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
                                severity,
                                confidence: Confidence::Probable,
                                impact: None,
                                title: "Automatic action trigger".into(),
                                description:
                                    "Additional action triggers without explicit user interaction."
                                        .into(),
                                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                evidence: evidence.clone(),
                                remediation: Some("Review the action target and payload.".into()),
                                meta: meta.clone(),
                                action_type: None,
                                action_target: None,
                                action_initiation: None,
                                yara: None,
                                positions: Vec::new(),
                            });
                        }

                        if summary.depth >= ACTION_CHAIN_COMPLEX_DEPTH {
                            let mut complex_meta = meta.clone();
                            enrich_complex_chain_meta(&mut complex_meta, &summary);
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "action_chain_complex".into(),
                                severity: Severity::Medium,
                                confidence: Confidence::Probable,
                                impact: None,
                                title: "Complex action chain".into(),
                                description: complex_action_chain_description(&complex_meta),
                                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                evidence: EvidenceBuilder::new()
                                    .file_offset(
                                        event_name.span.start,
                                        event_name.span.len() as u32,
                                        "AA event",
                                    )
                                    .build(),
                                remediation: Some(
                                    "Review the full chain path, terminal action, and payload target for staged execution."
                                        .into(),
                                ),
                                meta: complex_meta,
                                action_type: None,
                                action_target: None,
                                action_initiation: None,
                                yara: None,
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
                    let summary = if let Some(obj) = action_obj.as_ref() {
                        action_chain_summary(ctx, classifications, obj, 1, &mut visited)
                    } else {
                        ChainSummary::new(1)
                    };
                    insert_chain_metadata(
                        &mut meta,
                        &event_label,
                        event_label.clone(),
                        "hidden",
                        "annotation_action",
                        &summary,
                    );
                    let action_type = action_obj
                        .as_ref()
                        .and_then(|obj| action_type_from_obj(ctx, obj))
                        .unwrap_or_else(|| event_label.clone());
                    let target_value = meta.get("action.chain_path").cloned();
                    annotate_action_meta(
                        &mut meta,
                        &action_type,
                        target_value.as_deref(),
                        "hidden",
                    );
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "action_hidden_trigger".into(),
                        severity: Severity::Low,
                        confidence: Confidence::Probable,
                        impact: None,
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
                        action_type: None,
                        action_target: None,
                        action_initiation: None,
                        yara: None,
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
                    insert_chain_metadata(
                        &mut meta,
                        "field",
                        field_name.clone(),
                        "user",
                        "field_action",
                        &summary,
                    );
                    let action_type =
                        action_type_from_obj(ctx, action_obj).unwrap_or_else(|| "field".into());
                    let target = meta.get("action.chain_path").cloned();
                    let initiation = if hidden_field { "hidden" } else { "user" };
                    annotate_action_meta(&mut meta, &action_type, target.as_deref(), initiation);
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
                            impact: None,
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
                            action_type: None,
                            action_target: None,
                            action_initiation: None,
                            yara: None,
                            positions: Vec::new(),
                        });
                    }

                    if summary.depth >= ACTION_CHAIN_COMPLEX_DEPTH {
                        let mut complex_meta = meta.clone();
                        enrich_complex_chain_meta(&mut complex_meta, &summary);
                        findings.push(Finding {
                            id: String::new(),
                            surface: self.surface(),
                            kind: "action_chain_complex".into(),
                            severity: Severity::Medium,
                            confidence: Confidence::Probable,
                            impact: None,
                            title: "Complex action chain".into(),
                            description: complex_action_chain_description(&complex_meta),
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence: EvidenceBuilder::new()
                                .file_offset(k.span.start, k.span.len() as u32, "/A key")
                                .build(),
                            remediation: Some(
                                "Review the full chain path, terminal action, and payload target for staged execution."
                                    .into(),
                            ),
                            meta: complex_meta,
                            action_type: None,
                            action_target: None,
                            action_initiation: None,
                            yara: None,
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
                            let action_type = action_type_from_obj(ctx, action_obj)
                                .unwrap_or_else(|| "field".into());
                            let mut meta = std::collections::HashMap::new();
                            meta.insert("action.trigger".into(), event_label.clone());
                            meta.insert("action.field_name".into(), field_name.clone());
                            insert_chain_metadata(
                                &mut meta,
                                &event_label,
                                field_name.clone(),
                                trigger_type,
                                "field_aa",
                                &summary,
                            );
                            annotate_action_meta(
                                &mut meta,
                                &action_type,
                                Some(field_name.as_str()),
                                trigger_type,
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

                            if action_type
                                .trim_start_matches('/')
                                .eq_ignore_ascii_case("javascript")
                                && is_acroform_field_event(&event_name.decoded)
                            {
                                let mut field_meta = meta.clone();
                                field_meta.insert("action.field_event".into(), event_label.clone());
                                field_meta.insert(
                                    "action.field_event_class".into(),
                                    acroform_field_event_class(&event_name.decoded).into(),
                                );
                                field_meta.insert("chain.stage".into(), "execute".into());
                                field_meta.insert(
                                    "chain.capability".into(),
                                    "acroform_field_action".into(),
                                );
                                field_meta
                                    .insert("chain.trigger".into(), "acroform_field_aa".into());
                                let severity = if acroform_field_event_class(&event_name.decoded)
                                    == "calculate"
                                {
                                    Severity::High
                                } else {
                                    Severity::Medium
                                };
                                findings.push(Finding {
                                    id: String::new(),
                                    surface: self.surface(),
                                    kind: "acroform_field_action".into(),
                                    severity,
                                    confidence: Confidence::Strong,
                                    impact: None,
                                    title: "AcroForm field JavaScript action".into(),
                                    description: format!(
                                        "Field /AA event {} carries a JavaScript action.",
                                        event_label
                                    ),
                                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                    evidence: evidence.clone(),
                                    remediation: Some(
                                        "Inspect per-field /AA JavaScript handlers (keystroke/format/validate/calculate) for hidden logic and abuse paths."
                                            .into(),
                                    ),
                                    meta: field_meta,
                                    action_type: None,
                                    action_target: None,
                                    action_initiation: None,
                                    yara: None,
                                    positions: Vec::new(),
                                });
                            }

                            if trigger_type == "automatic" {
                                findings.push(Finding {
                                    id: String::new(),
                                    surface: self.surface(),
                                    kind: "action_automatic_trigger".into(),
                                    severity: Severity::Medium,
                                    confidence: Confidence::Probable,
                                    impact: None,
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
                                    action_type: None,
                                    action_target: None,
                                    action_initiation: None,
                                    yara: None,
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
                                    impact: None,
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
                                    action_type: None,
                                    action_target: None,
                                    action_initiation: None,
                                    yara: None,
                                    positions: Vec::new(),
                                });
                            }

                            if summary.depth >= ACTION_CHAIN_COMPLEX_DEPTH {
                                let mut complex_meta = meta.clone();
                                enrich_complex_chain_meta(&mut complex_meta, &summary);
                                findings.push(Finding {
                                    id: String::new(),
                                    surface: self.surface(),
                                    kind: "action_chain_complex".into(),
                                    severity: Severity::Medium,
                                    confidence: Confidence::Probable,
                                    impact: None,
                                    title: "Complex action chain".into(),
                                    description: complex_action_chain_description(&complex_meta),
                                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                    evidence: EvidenceBuilder::new()
                                        .file_offset(
                                            event_name.span.start,
                                            event_name.span.len() as u32,
                                            "AA event",
                                        )
                                        .build(),
                                    remediation: Some(
                                        "Review the full chain path, terminal action, and payload target for staged execution."
                                            .into(),
                                    ),
                                    meta: complex_meta,
                                    action_type: None,
                                    action_target: None,
                                    action_initiation: None,
                                    yara: None,
                                    positions: Vec::new(),
                                });
                            }
                        }
                    }
                }
            }
        }
        apply_kind_cap(&mut findings, "action_automatic_trigger", ACTION_FINDING_CAP);
        apply_kind_cap(&mut findings, "action_chain_complex", ACTION_FINDING_CAP);
        apply_kind_cap(&mut findings, "acroform_field_action", ACTION_FINDING_CAP);
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

const ACTION_CHAIN_COMPLEX_DEPTH: usize = 3;
const ACTION_CHAIN_MAX_DEPTH: usize = 8;

#[derive(Clone, Default)]
struct ChainSummary {
    depth: usize,
    path: Vec<String>,
    next_depth: usize,
    next_branch_count: usize,
    next_max_fanout: usize,
    has_cycle: bool,
}

impl ChainSummary {
    fn new(depth: usize) -> Self {
        Self {
            depth,
            path: Vec::new(),
            next_depth: 0,
            next_branch_count: 0,
            next_max_fanout: 0,
            has_cycle: false,
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
                summary.path.push(describe_object(classifications, *obj, *gen));
                summary.has_cycle = true;
                return summary;
            }
            let Some(entry) = ctx.graph.get_object(*obj, *gen) else {
                return ChainSummary::new(depth);
            };
            let resolved = PdfObj { span: entry.body_span, atom: entry.atom.clone() };
            let mut summary = action_chain_summary(ctx, classifications, &resolved, depth, visited);
            summary.path.insert(0, describe_object(classifications, *obj, *gen));
            visited.remove(&(*obj, *gen));
            summary
        }
        PdfAtom::Dict(dict) => {
            let mut summary = ChainSummary::new(depth);
            if let Some((_, next)) = dict.get_first(b"/Next") {
                if let PdfAtom::Array(arr) = &next.atom {
                    let mut best_branch = ChainSummary::new(depth + 1);
                    for entry in arr {
                        let branch_summary =
                            action_chain_summary(ctx, classifications, entry, depth + 1, visited);
                        best_branch = best_chain_summary(best_branch, branch_summary);
                    }
                    summary = best_chain_summary(summary, best_branch.clone());
                    summary.next_depth = summary.next_depth.max(best_branch.next_depth + 1);
                    summary.next_branch_count = arr.len() + best_branch.next_branch_count;
                    summary.next_max_fanout =
                        summary.next_max_fanout.max(arr.len().max(best_branch.next_max_fanout));
                    summary.has_cycle |= best_branch.has_cycle;
                } else {
                    let next_summary =
                        action_chain_summary(ctx, classifications, next, depth + 1, visited);
                    summary = best_chain_summary(summary, next_summary.clone());
                    summary.next_depth = summary.next_depth.max(next_summary.next_depth + 1);
                    summary.next_branch_count = 1 + next_summary.next_branch_count;
                    summary.next_max_fanout =
                        summary.next_max_fanout.max(1.max(next_summary.next_max_fanout));
                    summary.has_cycle |= next_summary.has_cycle;
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
    let mut out = if b.depth > a.depth || (b.depth == a.depth && b.path.len() > a.path.len()) {
        b.clone()
    } else {
        a.clone()
    };
    out.next_depth = out.next_depth.max(a.next_depth.max(b.next_depth));
    out.next_branch_count = out.next_branch_count.max(a.next_branch_count.max(b.next_branch_count));
    out.next_max_fanout = out.next_max_fanout.max(a.next_max_fanout.max(b.next_max_fanout));
    out.has_cycle |= a.has_cycle || b.has_cycle;
    out
}

fn describe_object(classifications: &ClassificationMap, obj: u32, gen: u16) -> String {
    let base = format!("{} {}", obj, gen);
    if let Some(classified) = classifications.get(&(obj, gen)) {
        let mut label = classified.obj_type.as_str().to_string();
        if !classified.roles.is_empty() {
            let roles =
                classified.roles.iter().map(|role| role.as_str()).collect::<Vec<_>>().join(",");
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
    trigger_context: &str,
    summary: &ChainSummary,
) {
    meta.insert("action.chain_depth".into(), summary.depth.to_string());
    meta.insert("threshold.depth".into(), ACTION_CHAIN_COMPLEX_DEPTH.to_string());
    meta.insert("action.trigger_event".into(), trigger_event.clone());
    meta.insert("action.trigger_type".into(), trigger_type.into());
    meta.insert("action.trigger_context".into(), trigger_context.into());
    meta.insert("action.trigger_event_normalised".into(), normalise_trigger_event(&trigger_event));
    if summary.next_depth > 0 {
        meta.insert("action.next.depth".into(), summary.next_depth.to_string());
        meta.insert("action.next.branch_count".into(), summary.next_branch_count.to_string());
        meta.insert("action.next.max_fanout".into(), summary.next_max_fanout.to_string());
    }
    if summary.has_cycle {
        meta.insert("action.next.has_cycle".into(), "true".into());
    }
    meta.insert("chain.stage".into(), "execute".into());
    meta.insert("chain.capability".into(), "action_trigger_chain".into());
    meta.insert("chain.trigger".into(), chain_trigger_from_context(trigger_context).into());
    meta.insert("action.chain_path".into(), build_chain_path(trigger_label, summary));
}

fn chain_trigger_from_context(trigger_context: &str) -> &'static str {
    match trigger_context {
        "open_action" => "open_action",
        "aa" | "field_aa" => "additional_action",
        "annotation_action" => "annotation_action",
        "field_action" => "field_action",
        _ => "action",
    }
}

fn normalise_trigger_event(trigger_event: &str) -> String {
    if trigger_event == "OpenAction" {
        return "/OpenAction".into();
    }
    if trigger_event.starts_with('/') {
        return trigger_event.to_string();
    }
    format!("/{trigger_event}")
}

fn enrich_complex_chain_meta(
    meta: &mut std::collections::HashMap<String, String>,
    summary: &ChainSummary,
) {
    meta.insert("observed.chain_depth".into(), summary.depth.to_string());
    meta.insert("threshold.depth".into(), ACTION_CHAIN_COMPLEX_DEPTH.to_string());
    if let Some(last) = summary.path.last() {
        meta.insert("observed.terminal_action".into(), last.clone());
    }
    meta.insert("query.next".into(), "actions.chains --where \"depth >= 3\"".into());
}

fn complex_action_chain_description(meta: &std::collections::HashMap<String, String>) -> String {
    let observed = meta.get("observed.chain_depth").cloned().unwrap_or_else(|| "?".into());
    let threshold = meta.get("threshold.depth").cloned().unwrap_or_else(|| "?".into());
    let trigger = meta.get("action.trigger_event").cloned().unwrap_or_else(|| "unknown".into());
    let path = meta.get("action.chain_path").cloned().unwrap_or_else(|| "unknown".into());
    let terminal =
        meta.get("observed.terminal_action").cloned().unwrap_or_else(|| "unknown".into());
    format!(
        "Action chain depth {observed} exceeds threshold {threshold}; trigger={trigger}, terminal={terminal}, path={path}."
    )
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

fn is_acroform_field_event(name: &[u8]) -> bool {
    matches!(name, b"/K" | b"/F" | b"/V" | b"/C")
}

fn acroform_field_event_class(name: &[u8]) -> &'static str {
    match name {
        b"/K" => "keystroke",
        b"/F" => "format",
        b"/V" => "validate",
        b"/C" => "calculate",
        _ => "other",
    }
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
            PdfStr::Literal { decoded, .. } => String::from_utf8_lossy(decoded).to_string(),
            PdfStr::Hex { decoded, .. } => String::from_utf8_lossy(decoded).to_string(),
        });
    }
    None
}

fn action_type_is_high_risk(action_type: &str) -> bool {
    match action_type.trim_start_matches('/') {
        "JavaScript" | "Launch" | "URI" | "GoToR" | "GoToE" | "SubmitForm" => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_kind_cap_suppresses_overflow() {
        let mut findings = Vec::new();
        for index in 0..31usize {
            findings.push(Finding {
                kind: "action_chain_complex".into(),
                objects: vec![format!("{index} 0 obj")],
                positions: vec![format!("doc:r0/obj.{index}")],
                ..Finding::default()
            });
        }
        apply_kind_cap(&mut findings, "action_chain_complex", 25);
        let retained =
            findings.iter().filter(|finding| finding.kind == "action_chain_complex").count();
        assert_eq!(retained, 25);
        let first = findings
            .iter()
            .find(|finding| finding.kind == "action_chain_complex")
            .expect("retained finding");
        assert_eq!(first.meta.get("aggregate.suppressed_count").map(String::as_str), Some("6"));
    }
}
