use std::collections::{HashMap, HashSet};

use serde::Serialize;
use serde_json::{json, Value};
use sis_pdf_pdf::object::{PdfAtom, PdfDict};

use crate::graph_walk::{build_adjacency, reachable_from, ObjRef};
use crate::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use crate::revision_timeline::{build_revision_timeline, DEFAULT_MAX_REVISIONS};
use crate::scan::ScanContext;

#[derive(Debug, Clone, Serialize)]
pub struct StructureOverlayNode {
    pub id: String,
    pub kind: String,
    pub attrs: OverlayNodeAttrs,
}

#[derive(Debug, Clone, Serialize)]
pub struct StructureOverlayEdge {
    pub from: String,
    pub to: String,
    pub edge_type: String,
    pub suspicious: bool,
    pub attrs: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct StructureOverlay {
    pub nodes: Vec<StructureOverlayNode>,
    pub edges: Vec<StructureOverlayEdge>,
    pub stats: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind")]
pub enum OverlayNodeAttrs {
    #[serde(rename = "file_root")]
    FileRoot,
    #[serde(rename = "startxref")]
    StartXref { idx: usize, offset: u64, section_match: bool },
    #[serde(rename = "xref_section")]
    XrefSection {
        idx: usize,
        offset: u64,
        section_kind: XrefSectionKind,
        has_trailer: bool,
        prev: Option<u64>,
        trailer_size: Option<u64>,
        trailer_root: Option<String>,
    },
    #[serde(rename = "trailer")]
    Trailer {
        idx: usize,
        has_root: bool,
        has_info: bool,
        has_encrypt: bool,
        size: Option<u64>,
        unresolved: Vec<String>,
        prev_unresolved: bool,
    },
    #[serde(rename = "objstm")]
    ObjStm { container_obj: u32, container_gen: u16 },
    #[serde(rename = "carved_stream")]
    CarvedStream { carrier_obj: u32, carrier_gen: u16 },
    #[serde(rename = "revision")]
    Revision {
        n: usize,
        startxref_offset: u64,
        post_cert: bool,
        covered_by_signature: bool,
        changed_object_count: usize,
        changed_object_edge_count: usize,
        truncated: bool,
    },
    #[serde(rename = "telemetry")]
    Telemetry {
        idx: usize,
        domain: String,
        event_kind: String,
        level: String,
        object_ref: Option<String>,
    },
    #[serde(rename = "signature")]
    Signature { idx: usize, boundary: u64 },
}

#[derive(Debug, Clone, Copy, Default)]
pub struct StructureOverlayBuildOptions {
    pub include_telemetry: bool,
    pub include_signature: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum XrefSectionKind {
    Table,
    Stream,
    Unknown,
}

pub const REVISION_CHANGED_OBJECT_EDGE_CAP: usize = 50;
pub const DETACHED_OBJECTS_CAP: usize = 100;

pub fn parse_xref_kind(kind: &str) -> XrefSectionKind {
    match kind {
        "table" => XrefSectionKind::Table,
        "stream" => XrefSectionKind::Stream,
        _ => XrefSectionKind::Unknown,
    }
}

pub fn build_structure_overlay(
    ctx: &ScanContext<'_>,
    options: StructureOverlayBuildOptions,
) -> StructureOverlay {
    build_structure_overlay_with_findings(ctx, options, None)
}

pub fn build_structure_overlay_with_findings(
    ctx: &ScanContext<'_>,
    options: StructureOverlayBuildOptions,
    findings: Option<&[Finding]>,
) -> StructureOverlay {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let suspicious_targets = high_critical_object_refs(findings);

    nodes.push(StructureOverlayNode {
        id: "file.root".to_string(),
        kind: "file_root".to_string(),
        attrs: OverlayNodeAttrs::FileRoot,
    });

    let mut section_by_offset: HashMap<u64, Vec<usize>> = HashMap::new();
    for (idx, section) in ctx.graph.xref_sections.iter().enumerate() {
        section_by_offset.entry(section.offset).or_default().push(idx);
    }
    let mut startxref_by_offset: HashMap<u64, usize> = HashMap::new();
    for (idx, offset) in ctx.graph.startxrefs.iter().enumerate() {
        startxref_by_offset.entry(*offset).or_insert(idx);
    }

    for (idx, offset) in ctx.graph.startxrefs.iter().enumerate() {
        let startxref_id = format!("startxref.{idx}");
        let matches = section_by_offset.get(offset);
        let section_match = matches.map(|items| !items.is_empty()).unwrap_or(false);
        nodes.push(StructureOverlayNode {
            id: startxref_id.clone(),
            kind: "startxref".to_string(),
            attrs: OverlayNodeAttrs::StartXref { idx, offset: *offset, section_match },
        });
        edges.push(StructureOverlayEdge {
            from: "file.root".to_string(),
            to: startxref_id.clone(),
            edge_type: "file_root_to_startxref".to_string(),
            suspicious: false,
            attrs: json!({}),
        });
        if let Some(matches) = matches {
            for section_idx in matches {
                edges.push(StructureOverlayEdge {
                    from: startxref_id.clone(),
                    to: format!("xref.section.{section_idx}"),
                    edge_type: "startxref_to_section".to_string(),
                    suspicious: false,
                    attrs: json!({}),
                });
            }
        }
    }

    for (idx, section) in ctx.graph.xref_sections.iter().enumerate() {
        nodes.push(StructureOverlayNode {
            id: format!("xref.section.{idx}"),
            kind: "xref_section".to_string(),
            attrs: OverlayNodeAttrs::XrefSection {
                idx,
                offset: section.offset,
                section_kind: parse_xref_kind(section.kind.as_str()),
                has_trailer: section.has_trailer,
                prev: section.prev,
                trailer_size: section.trailer_size,
                trailer_root: section.trailer_root.clone(),
            },
        });
        if section.has_trailer && idx < ctx.graph.trailers.len() {
            edges.push(StructureOverlayEdge {
                from: format!("xref.section.{idx}"),
                to: format!("trailer.{idx}"),
                edge_type: "section_to_trailer".to_string(),
                suspicious: false,
                attrs: json!({}),
            });
        }
        if let Some(prev) = section.prev {
            if let Some(prev_sections) = section_by_offset.get(&prev) {
                for prev_idx in prev_sections {
                    edges.push(StructureOverlayEdge {
                        from: format!("xref.section.{idx}"),
                        to: format!("xref.section.{prev_idx}"),
                        edge_type: "section_prev".to_string(),
                        suspicious: false,
                        attrs: json!({}),
                    });
                }
            }
        }
    }

    for (idx, trailer) in ctx.graph.trailers.iter().enumerate() {
        let mut unresolved = Vec::new();
        let mut prev_unresolved = false;
        let has_root = trailer.get_first(b"/Root").is_some();
        let has_info = trailer.get_first(b"/Info").is_some();
        let has_encrypt = trailer.get_first(b"/Encrypt").is_some();
        let size = trailer_int_value(trailer, b"/Size");

        resolve_trailer_ref_edge(
            &ctx.graph,
            trailer,
            b"/Root",
            "trailer_root",
            idx,
            &suspicious_targets,
            &mut edges,
            &mut unresolved,
        );
        resolve_trailer_ref_edge(
            &ctx.graph,
            trailer,
            b"/Info",
            "trailer_info",
            idx,
            &suspicious_targets,
            &mut edges,
            &mut unresolved,
        );
        resolve_trailer_ref_edge(
            &ctx.graph,
            trailer,
            b"/Encrypt",
            "trailer_encrypt",
            idx,
            &suspicious_targets,
            &mut edges,
            &mut unresolved,
        );

        if let Some(prev) = trailer_int_value(trailer, b"/Prev") {
            if let Some(startxref_idx) = startxref_by_offset.get(&prev) {
                edges.push(StructureOverlayEdge {
                    from: format!("trailer.{idx}"),
                    to: format!("startxref.{startxref_idx}"),
                    edge_type: "trailer_prev".to_string(),
                    suspicious: false,
                    attrs: json!({}),
                });
            } else {
                prev_unresolved = true;
            }
        }

        nodes.push(StructureOverlayNode {
            id: format!("trailer.{idx}"),
            kind: "trailer".to_string(),
            attrs: OverlayNodeAttrs::Trailer {
                idx,
                has_root,
                has_info,
                has_encrypt,
                size,
                unresolved,
                prev_unresolved,
            },
        });
    }

    let mut node_ids = nodes.iter().map(|node| node.id.clone()).collect::<HashSet<_>>();
    let mut edge_ids = edges
        .iter()
        .map(|edge| (edge.from.clone(), edge.to.clone(), edge.edge_type.clone()))
        .collect::<HashSet<_>>();

    for entry in &ctx.graph.objects {
        match entry.provenance {
            sis_pdf_pdf::graph::ObjProvenance::ObjStm { obj, gen } => {
                let node_id = format!("objstm.{obj}.{gen}");
                push_overlay_node_if_missing(
                    &mut nodes,
                    &mut node_ids,
                    node_id.clone(),
                    "objstm",
                    OverlayNodeAttrs::ObjStm { container_obj: obj, container_gen: gen },
                );
                push_overlay_edge_unique(
                    &mut edges,
                    &mut edge_ids,
                    node_id,
                    format!("{} {}", entry.obj, entry.gen),
                    "objstm_contains",
                    false,
                    json!({}),
                );
            }
            sis_pdf_pdf::graph::ObjProvenance::CarvedStream { obj, gen } => {
                let node_id = format!("carved.{obj}.{gen}");
                push_overlay_node_if_missing(
                    &mut nodes,
                    &mut node_ids,
                    node_id.clone(),
                    "carved_stream",
                    OverlayNodeAttrs::CarvedStream { carrier_obj: obj, carrier_gen: gen },
                );
                push_overlay_edge_unique(
                    &mut edges,
                    &mut edge_ids,
                    node_id,
                    format!("{} {}", entry.obj, entry.gen),
                    "carved_from_stream",
                    false,
                    json!({}),
                );
            }
            sis_pdf_pdf::graph::ObjProvenance::Indirect => {}
        }
    }

    let timeline = build_revision_timeline(ctx, DEFAULT_MAX_REVISIONS);
    for record in &timeline.revisions {
        let node_id = format!("revision.{}", record.revision);
        let mut changed = Vec::new();
        changed.extend(record.objects_added_refs.iter().cloned());
        changed.extend(record.objects_modified_refs.iter().cloned());
        changed.sort();
        changed.dedup();

        let post_cert = !record.covered_by_signature;
        let emit_count = changed.len().min(REVISION_CHANGED_OBJECT_EDGE_CAP);
        push_overlay_node_if_missing(
            &mut nodes,
            &mut node_ids,
            node_id.clone(),
            "revision",
            OverlayNodeAttrs::Revision {
                n: record.revision,
                startxref_offset: record.startxref,
                post_cert,
                covered_by_signature: record.covered_by_signature,
                changed_object_count: changed.len(),
                changed_object_edge_count: emit_count,
                truncated: changed.len() > REVISION_CHANGED_OBJECT_EDGE_CAP,
            },
        );

        if let Some(startxref_idx) = startxref_by_offset.get(&record.startxref) {
            push_overlay_edge_unique(
                &mut edges,
                &mut edge_ids,
                node_id.clone(),
                format!("startxref.{startxref_idx}"),
                "revision_to_startxref",
                false,
                json!({}),
            );
        }

        for item in changed.into_iter().take(REVISION_CHANGED_OBJECT_EDGE_CAP) {
            if let Some(target) = parse_object_ref_id(&item) {
                push_overlay_edge_unique(
                    &mut edges,
                    &mut edge_ids,
                    node_id.clone(),
                    target,
                    "revision_changed_object",
                    post_cert,
                    json!({}),
                );
            }
        }
    }

    let mut telemetry_node_count = 0usize;
    if options.include_telemetry {
        for (idx, event) in ctx.graph.telemetry_events.iter().enumerate() {
            let telemetry_id = format!("telemetry.{idx}");
            push_overlay_node_if_missing(
                &mut nodes,
                &mut node_ids,
                telemetry_id.clone(),
                "telemetry",
                OverlayNodeAttrs::Telemetry {
                    idx,
                    domain: event.domain.to_string(),
                    event_kind: event.kind.to_string(),
                    level: format!("{:?}", event.level),
                    object_ref: event.object_ref.clone(),
                },
            );
            telemetry_node_count += 1;
            if let Some(object_ref) = &event.object_ref {
                if let Some(target) = parse_object_ref_id(object_ref) {
                    push_overlay_edge_unique(
                        &mut edges,
                        &mut edge_ids,
                        telemetry_id.clone(),
                        target,
                        "telemetry_ref",
                        false,
                        json!({}),
                    );
                }
            }
        }
    }

    let mut signature_node_count = 0usize;
    if options.include_signature {
        for (idx, boundary) in timeline.signature_boundaries.iter().enumerate() {
            let signature_id = format!("signature.{idx}");
            push_overlay_node_if_missing(
                &mut nodes,
                &mut node_ids,
                signature_id.clone(),
                "signature",
                OverlayNodeAttrs::Signature { idx, boundary: *boundary },
            );
            signature_node_count += 1;
            for record in &timeline.revisions {
                if *boundary >= record.startxref {
                    push_overlay_edge_unique(
                        &mut edges,
                        &mut edge_ids,
                        signature_id.clone(),
                        format!("revision.{}", record.revision),
                        "signature_covers_revision",
                        false,
                        json!({}),
                    );
                }
            }
        }
    }

    let adjacency = build_adjacency(&ctx.graph.objects);
    let mut root_seeds = Vec::new();
    for trailer in &ctx.graph.trailers {
        if let Some((_, root_obj)) = trailer.get_first(b"/Root") {
            if let PdfAtom::Ref { obj, gen } = root_obj.atom {
                root_seeds.push(ObjRef { obj, gen });
            }
        }
    }
    let max_depth = ctx.graph.objects.len().saturating_add(8);
    let reachable = reachable_from(&adjacency, &root_seeds, max_depth);
    let mut detached = ctx
        .graph
        .objects
        .iter()
        .map(|entry| ObjRef { obj: entry.obj, gen: entry.gen })
        .collect::<HashSet<_>>()
        .into_iter()
        .filter(|obj_ref| !reachable.contains(obj_ref))
        .map(|obj_ref| format!("{} {}", obj_ref.obj, obj_ref.gen))
        .collect::<Vec<_>>();
    detached.sort();
    let detached_total = detached.len();
    let detached_truncated = detached_total > DETACHED_OBJECTS_CAP;
    if detached_truncated {
        detached.truncate(DETACHED_OBJECTS_CAP);
    }

    StructureOverlay {
        stats: json!({
            "node_count": nodes.len(),
            "edge_count": edges.len(),
            "trailer_count": ctx.graph.trailers.len(),
            "startxref_count": ctx.graph.startxrefs.len(),
            "xref_section_count": ctx.graph.xref_sections.len(),
            "revision_count": timeline.revisions.len(),
            "telemetry_node_count": telemetry_node_count,
            "signature_node_count": signature_node_count,
            "include_telemetry": options.include_telemetry,
            "include_signature": options.include_signature,
            "detached_total": detached_total,
            "detached_truncated": detached_truncated,
            "detached_objects": detached,
        }),
        nodes,
        edges,
    }
}

pub fn structural_complexity_summary_finding(ctx: &ScanContext<'_>) -> Finding {
    let overlay = build_structure_overlay(ctx, StructureOverlayBuildOptions::default());
    let stats = &overlay.stats;
    let trailer_count = json_u64(stats, "trailer_count");
    let startxref_count = json_u64(stats, "startxref_count");
    let revision_count = json_u64(stats, "revision_count");
    let detached_objects = json_u64(stats, "detached_total");
    let xref_section_count = json_u64(stats, "xref_section_count");

    let mut meta = std::collections::HashMap::new();
    meta.insert("trailer_count".into(), trailer_count.to_string());
    meta.insert("startxref_count".into(), startxref_count.to_string());
    meta.insert("xref_section_count".into(), xref_section_count.to_string());
    meta.insert("revision_count".into(), revision_count.to_string());
    meta.insert("detached_objects".into(), detached_objects.to_string());

    Finding {
        kind: "structural_complexity_summary".into(),
        severity: Severity::Info,
        confidence: Confidence::Certain,
        impact: Some(Impact::None),
        title: "Structural complexity summary".into(),
        description: format!(
            "Structural complexity: {trailer_count} trailers, {xref_section_count} xref sections, {revision_count} revisions, {detached_objects} detached objects."
        ),
        remediation: Some(
            "Use structure overlay queries to inspect detached objects and revision provenance."
                .into(),
        ),
        surface: AttackSurface::FileStructure,
        objects: vec!["object_graph".into()],
        meta,
        ..Finding::default()
    }
}

fn json_u64(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn trailer_int_value(trailer: &PdfDict<'_>, key: &[u8]) -> Option<u64> {
    trailer.get_first(key).and_then(|(_, value)| match value.atom {
        PdfAtom::Int(v) if v >= 0 => Some(v as u64),
        _ => None,
    })
}

fn parse_object_ref_id(value: &str) -> Option<String> {
    let mut parts = value.split_whitespace();
    let obj = parts.next()?.parse::<u32>().ok()?;
    let gen = parts.next()?.parse::<u16>().ok()?;
    Some(format!("{obj} {gen}"))
}

fn resolve_trailer_ref_edge(
    graph: &sis_pdf_pdf::ObjectGraph<'_>,
    trailer: &PdfDict<'_>,
    key: &[u8],
    edge_type: &str,
    trailer_idx: usize,
    suspicious_targets: &HashSet<String>,
    edges: &mut Vec<StructureOverlayEdge>,
    unresolved: &mut Vec<String>,
) {
    if let Some((_, value)) = trailer.get_first(key) {
        match value.atom {
            PdfAtom::Ref { obj, gen } => {
                if graph.get_object(obj, gen).is_some() {
                    let target = format!("{obj} {gen}");
                    edges.push(StructureOverlayEdge {
                        from: format!("trailer.{trailer_idx}"),
                        to: target.clone(),
                        edge_type: edge_type.to_string(),
                        suspicious: suspicious_targets.contains(&target),
                        attrs: json!({}),
                    });
                } else {
                    unresolved.push(String::from_utf8_lossy(key).to_string());
                }
            }
            _ => unresolved.push(String::from_utf8_lossy(key).to_string()),
        }
    }
}

fn high_critical_object_refs(findings: Option<&[Finding]>) -> HashSet<String> {
    let mut refs = HashSet::new();
    if let Some(findings_list) = findings {
        for finding in findings_list {
            if !matches!(finding.severity, Severity::High | Severity::Critical) {
                continue;
            }
            for object in &finding.objects {
                if let Some(target) = parse_object_ref_id(object) {
                    refs.insert(target);
                }
            }
        }
    }
    refs
}

fn push_overlay_node_if_missing(
    nodes: &mut Vec<StructureOverlayNode>,
    node_ids: &mut HashSet<String>,
    id: String,
    kind: &str,
    attrs: OverlayNodeAttrs,
) {
    if node_ids.insert(id.clone()) {
        nodes.push(StructureOverlayNode { id, kind: kind.to_string(), attrs });
    }
}

fn push_overlay_edge_unique(
    edges: &mut Vec<StructureOverlayEdge>,
    edge_ids: &mut HashSet<(String, String, String)>,
    from: String,
    to: String,
    edge_type: &str,
    suspicious: bool,
    attrs: Value,
) {
    let key = (from.clone(), to.clone(), edge_type.to_string());
    if edge_ids.insert(key) {
        edges.push(StructureOverlayEdge {
            from,
            to,
            edge_type: edge_type.to_string(),
            suspicious,
            attrs,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{high_critical_object_refs, json_u64, parse_xref_kind, XrefSectionKind};
    use crate::model::{AttackSurface, Confidence, Finding, Severity};
    use serde_json::json;

    #[test]
    fn parse_xref_kind_maps_known_and_unknown_values() {
        assert_eq!(parse_xref_kind("table"), XrefSectionKind::Table);
        assert_eq!(parse_xref_kind("stream"), XrefSectionKind::Stream);
        assert_eq!(parse_xref_kind("unknown_future_value"), XrefSectionKind::Unknown);
    }

    #[test]
    fn json_u64_defaults_to_zero_when_missing_or_invalid() {
        assert_eq!(json_u64(&json!({"value": 12}), "value"), 12);
        assert_eq!(json_u64(&json!({"value": "bad"}), "value"), 0);
        assert_eq!(json_u64(&json!({}), "missing"), 0);
    }

    #[test]
    fn high_critical_object_refs_collects_high_signal_objects_only() {
        let findings = vec![
            Finding {
                surface: AttackSurface::FileStructure,
                kind: "low".into(),
                severity: Severity::Low,
                confidence: Confidence::Certain,
                objects: vec!["10 0".into()],
                ..Finding::default()
            },
            Finding {
                surface: AttackSurface::FileStructure,
                kind: "high".into(),
                severity: Severity::High,
                confidence: Confidence::Certain,
                objects: vec!["11 0".into(), "not_an_object".into()],
                ..Finding::default()
            },
            Finding {
                surface: AttackSurface::FileStructure,
                kind: "critical".into(),
                severity: Severity::Critical,
                confidence: Confidence::Certain,
                objects: vec!["12 0".into()],
                ..Finding::default()
            },
        ];
        let refs = high_critical_object_refs(Some(&findings));
        assert!(!refs.contains("10 0"));
        assert!(refs.contains("11 0"));
        assert!(refs.contains("12 0"));
    }
}
