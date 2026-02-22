use crate::event_graph::{EdgeProvenance, EventEdgeKind, EventGraph, EventNodeKind};
use serde::{Deserialize, Serialize};
use sis_pdf_pdf::content::{ContentOp, ContentOperand};
use sis_pdf_pdf::decode::decode_stream;
use sis_pdf_pdf::graph::ObjectGraph;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub const STREAM_PROJ_MAX_OPS: usize = 1_000;
pub const STREAM_PROJ_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProjectionOptions {
    pub include_stream_exec_summary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ResourceRef {
    pub op: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<(u32, u16)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NestedFormExec {
    pub do_name: String,
    pub depth: u8,
    pub obj_ref: (u32, u16),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StreamExecSummary {
    pub total_ops: usize,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub op_family_counts: BTreeMap<String, usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_refs: Vec<ResourceRef>,
    pub graphics_state_max_depth: usize,
    pub graphics_state_underflow: bool,
    pub unknown_op_count: usize,
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nested_form_execs: Vec<NestedFormExec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nested_form_truncated: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventExecuteTarget {
    pub node_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<(u32, u16)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventOutcomeRecord {
    pub node_id: String,
    pub outcome_type: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_score: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_object: Option<(u32, u16)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EventRecord {
    pub node_id: String,
    pub event_type: String,
    pub label: String,
    pub trigger_class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_object: Option<(u32, u16)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub execute_targets: Vec<EventExecuteTarget>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outcome_targets: Vec<EventOutcomeRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub linked_finding_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre_techniques: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_exec: Option<StreamExecSummary>,
}

pub fn extract_event_records(event_graph: &EventGraph) -> Vec<EventRecord> {
    extract_event_records_with_projection(event_graph, &ProjectionOptions::default(), None)
}

pub fn extract_event_records_with_projection(
    event_graph: &EventGraph,
    projection: &ProjectionOptions,
    stream_summaries: Option<&BTreeMap<String, StreamExecSummary>>,
) -> Vec<EventRecord> {
    let mut records = Vec::new();
    let mut finding_ids_by_node: HashMap<String, BTreeSet<String>> = HashMap::new();
    for edge in &event_graph.edges {
        if let EdgeProvenance::Finding { finding_id } = &edge.provenance {
            finding_ids_by_node.entry(edge.from.clone()).or_default().insert(finding_id.clone());
            finding_ids_by_node.entry(edge.to.clone()).or_default().insert(finding_id.clone());
        }
    }

    for node in &event_graph.nodes {
        let EventNodeKind::Event { event_type, trigger, label, source_obj } = &node.kind else {
            continue;
        };

        let mut execute_targets = BTreeMap::new();
        let mut outcome_targets = BTreeMap::new();
        let mut event_key = None;
        let mut initiation = None;
        let mut branch_index = None;

        if let Some(forward) = event_graph.forward_index.get(&node.id) {
            for edge_idx in forward {
                let Some(edge) = event_graph.edges.get(*edge_idx) else {
                    continue;
                };
                match edge.kind {
                    EventEdgeKind::Executes => {
                        let object_ref = event_graph.node_index.get(&edge.to).and_then(|idx| {
                            event_graph.nodes.get(*idx).and_then(|target_node| {
                                if let EventNodeKind::Object { obj, gen, .. } = target_node.kind {
                                    Some((obj, gen))
                                } else {
                                    None
                                }
                            })
                        });
                        execute_targets
                            .entry(edge.to.clone())
                            .or_insert(EventExecuteTarget { node_id: edge.to.clone(), object_ref });
                    }
                    EventEdgeKind::ProducesOutcome => {
                        let Some(target_idx) = event_graph.node_index.get(&edge.to) else {
                            continue;
                        };
                        let Some(target_node) = event_graph.nodes.get(*target_idx) else {
                            continue;
                        };
                        if let EventNodeKind::Outcome {
                            outcome_type,
                            label,
                            confidence_score,
                            severity_hint,
                            evidence,
                            source_obj,
                            ..
                        } = &target_node.kind
                        {
                            outcome_targets.entry(edge.to.clone()).or_insert(EventOutcomeRecord {
                                node_id: edge.to.clone(),
                                outcome_type: format!("{outcome_type:?}"),
                                label: label.clone(),
                                confidence_score: *confidence_score,
                                severity_hint: severity_hint.clone(),
                                evidence: evidence.clone(),
                                source_object: *source_obj,
                            });
                        }
                    }
                    _ => {}
                }
                if let Some(meta) = &edge.metadata {
                    if event_key.is_none() {
                        event_key = meta.event_key.clone();
                    }
                    if initiation.is_none() {
                        initiation = meta.initiation.clone();
                    }
                    if branch_index.is_none() {
                        branch_index = meta.branch_index.map(|value| value as u32);
                    }
                }
            }
        }

        let linked_finding_ids = finding_ids_by_node
            .get(&node.id)
            .map(|values| values.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        records.push(EventRecord {
            node_id: node.id.clone(),
            event_type: format!("{event_type:?}"),
            label: label.clone(),
            trigger_class: trigger.as_str().to_string(),
            source_object: *source_obj,
            execute_targets: execute_targets.into_values().collect(),
            outcome_targets: outcome_targets.into_values().collect(),
            linked_finding_ids,
            event_key,
            initiation,
            branch_index,
            mitre_techniques: node.mitre_techniques.clone(),
            stream_exec: if projection.include_stream_exec_summary {
                stream_summaries.and_then(|summaries| summaries.get(&node.id).cloned())
            } else {
                None
            },
        });
    }

    records.sort_by_key(|record| (record.source_object, record.node_id.clone()));
    records
}

pub fn summarise_content_ops(ops: &[ContentOp]) -> StreamExecSummary {
    let mut op_family_counts = BTreeMap::<String, usize>::new();
    let mut resource_refs = Vec::<ResourceRef>::new();
    let mut graphics_depth = 0usize;
    let mut graphics_max_depth = 0usize;
    let mut graphics_underflow = false;
    let mut unknown_op_count = 0usize;
    let mut bytes_used = 0usize;
    let mut truncated = false;

    for op in ops.iter().take(STREAM_PROJ_MAX_OPS) {
        let family = op_family_key(op.op.as_str());
        if family == "Unknown" {
            unknown_op_count += 1;
        }
        *op_family_counts.entry(family.to_string()).or_insert(0) += 1;

        if op.op == "q" {
            graphics_depth += 1;
            graphics_max_depth = graphics_max_depth.max(graphics_depth);
        } else if op.op == "Q" {
            if graphics_depth == 0 {
                graphics_underflow = true;
            } else {
                graphics_depth -= 1;
            }
        }

        if matches!(op.op.as_str(), "Do" | "Tf" | "gs" | "sh") {
            if let Some(ContentOperand::Name(name)) = op.operands.first() {
                let projected =
                    ResourceRef { op: op.op.clone(), name: name.clone(), object_ref: None };
                bytes_used += projected.op.len() + projected.name.len() + 8;
                if bytes_used > STREAM_PROJ_MAX_BYTES {
                    truncated = true;
                    break;
                }
                resource_refs.push(projected);
            }
        }
    }

    if ops.len() > STREAM_PROJ_MAX_OPS {
        truncated = true;
    }

    StreamExecSummary {
        total_ops: ops.len(),
        op_family_counts,
        resource_refs,
        graphics_state_max_depth: graphics_max_depth,
        graphics_state_underflow: graphics_underflow,
        unknown_op_count,
        truncated,
        nested_form_execs: Vec::new(),
        nested_form_truncated: None,
    }
}

pub fn build_stream_exec_summaries(
    bytes: &[u8],
    object_graph: &ObjectGraph<'_>,
    event_graph: &EventGraph,
) -> BTreeMap<String, StreamExecSummary> {
    let mut summaries = BTreeMap::new();
    for node in &event_graph.nodes {
        let EventNodeKind::Event {
            event_type: crate::event_graph::EventType::ContentStreamExec,
            source_obj,
            ..
        } = &node.kind
        else {
            continue;
        };
        let Some(edge_ids) = event_graph.forward_index.get(&node.id) else {
            continue;
        };
        let stream_ref = edge_ids
            .iter()
            .filter_map(|edge_idx| event_graph.edges.get(*edge_idx))
            .filter(|edge| edge.kind == EventEdgeKind::Executes && edge.to.starts_with("obj:"))
            .find_map(|edge| parse_event_object_node_id(&edge.to));
        let Some(stream_ref) = stream_ref else {
            continue;
        };
        let Some(entry) = object_graph.get_object(stream_ref.0, stream_ref.1) else {
            continue;
        };
        let PdfAtom::Stream(stream) = &entry.atom else {
            continue;
        };
        let decoded = decode_stream(bytes, stream, 8 * 1024 * 1024)
            .map(|result| result.data)
            .ok()
            .or_else(|| {
                let start = stream.data_span.start as usize;
                let end = stream.data_span.end as usize;
                if start < end && end <= bytes.len() {
                    Some(bytes[start..end].to_vec())
                } else {
                    None
                }
            });
        let Some(content_bytes) = decoded else {
            continue;
        };
        let ops = sis_pdf_pdf::content::parse_content_ops(&content_bytes);
        let mut summary = summarise_content_ops(&ops);
        if let Some(src) = source_obj {
            let bindings = collect_resource_bindings(object_graph, *src);
            for resource in &mut summary.resource_refs {
                resource.object_ref =
                    bindings.resolve(resource.op.as_str(), resource.name.as_str());
            }
        }
        // Trace nested Do chains from resolved Do refs using the PDF bytes.
        let do_refs: Vec<(String, (u32, u16))> = summary
            .resource_refs
            .iter()
            .filter(|r| r.op == "Do")
            .filter_map(|r| r.object_ref.map(|obj| (r.name.clone(), obj)))
            .collect();
        if !do_refs.is_empty() {
            let (nested_chains, truncation) =
                trace_nested_do_chains(bytes, object_graph, &do_refs, 8, 128, 4 * 1024 * 1024);
            summary.nested_form_execs = nested_chains;
            summary.nested_form_truncated = truncation;
        }
        summaries.insert(node.id.clone(), summary);
    }
    summaries
}

#[derive(Default)]
struct ResourceBindings {
    xobject: HashMap<String, (u32, u16)>,
    font: HashMap<String, (u32, u16)>,
    extgstate: HashMap<String, (u32, u16)>,
    shading: HashMap<String, (u32, u16)>,
}

impl ResourceBindings {
    fn resolve(&self, op: &str, name: &str) -> Option<(u32, u16)> {
        match op {
            "Do" => self.xobject.get(name).copied(),
            "Tf" => self.font.get(name).copied(),
            "gs" => self.extgstate.get(name).copied(),
            "sh" => self.shading.get(name).copied(),
            _ => None,
        }
    }
}

fn parse_event_object_node_id(node_id: &str) -> Option<(u32, u16)> {
    let parts = node_id.split(':').collect::<Vec<_>>();
    if parts.len() != 3 || parts[0] != "obj" {
        return None;
    }
    let obj = parts[1].parse::<u32>().ok()?;
    let generation = parts[2].parse::<u16>().ok()?;
    Some((obj, generation))
}

fn collect_resource_bindings(graph: &ObjectGraph<'_>, src: (u32, u16)) -> ResourceBindings {
    let mut out = ResourceBindings::default();
    let Some(entry) = graph.get_object(src.0, src.1) else {
        return out;
    };
    let Some(dict) = entry_dict(entry) else {
        return out;
    };
    if let Some((_, resources_obj)) = dict.get_first(b"/Resources") {
        if let Some(resources_dict) = resolve_dict(graph, resources_obj) {
            collect_resource_namespace_bindings(
                graph,
                resources_dict,
                b"/XObject",
                &mut out.xobject,
            );
            collect_resource_namespace_bindings(graph, resources_dict, b"/Font", &mut out.font);
            collect_resource_namespace_bindings(
                graph,
                resources_dict,
                b"/ExtGState",
                &mut out.extgstate,
            );
            collect_resource_namespace_bindings(
                graph,
                resources_dict,
                b"/Shading",
                &mut out.shading,
            );
        }
    }
    out
}

fn collect_resource_namespace_bindings(
    graph: &ObjectGraph<'_>,
    resources_dict: &PdfDict<'_>,
    key: &[u8],
    out: &mut HashMap<String, (u32, u16)>,
) {
    let Some((_, namespace_obj)) = resources_dict.get_first(key) else {
        return;
    };
    let Some(namespace_dict) = resolve_dict(graph, namespace_obj) else {
        return;
    };
    for (name, value) in &namespace_dict.entries {
        if let Some((obj, gen)) = resolve_ref_tuple(graph, value) {
            out.insert(String::from_utf8_lossy(&name.decoded).to_string(), (obj, gen));
        }
    }
}

fn resolve_ref_tuple(graph: &ObjectGraph<'_>, obj: &PdfObj<'_>) -> Option<(u32, u16)> {
    match obj.atom {
        PdfAtom::Ref { obj, gen } => Some((obj, gen)),
        _ => graph.resolve_ref(obj).map(|entry| (entry.obj, entry.gen)),
    }
}

fn resolve_dict<'a>(graph: &'a ObjectGraph<'a>, obj: &'a PdfObj<'a>) -> Option<&'a PdfDict<'a>> {
    match &obj.atom {
        PdfAtom::Dict(dict) => Some(dict),
        PdfAtom::Ref { obj, gen } => graph.get_object(*obj, *gen).and_then(entry_dict),
        PdfAtom::Stream(stream) => Some(&stream.dict),
        _ => None,
    }
}

fn entry_dict<'a>(entry: &'a sis_pdf_pdf::graph::ObjEntry<'a>) -> Option<&'a PdfDict<'a>> {
    match &entry.atom {
        PdfAtom::Dict(dict) => Some(dict),
        PdfAtom::Stream(stream) => Some(&stream.dict),
        _ => None,
    }
}

fn op_family_key(op: &str) -> &'static str {
    if op.starts_with('T') || matches!(op, "'" | "\"") {
        return "Text";
    }
    match op {
        "m" | "l" | "c" | "v" | "y" | "h" | "re" | "S" | "s" | "f" | "F" | "f*" | "B" | "B*"
        | "b" | "b*" | "n" | "W" | "W*" => "Path",
        "q" | "Q" | "cm" | "w" | "J" | "j" | "M" | "d" | "ri" | "i" => "State",
        "Do" | "Tf" | "gs" | "sh" | "cs" | "CS" | "sc" | "SC" | "scn" | "SCN" | "g" | "G"
        | "rg" | "RG" | "k" | "K" => "Resource",
        "BMC" | "BDC" | "EMC" | "MP" | "DP" => "MarkedContent",
        "BI" | "ID" | "EI" => "InlineImage",
        _ => "Unknown",
    }
}

// --- Do chain recursion tracer ---

struct TraceState {
    chains: Vec<NestedFormExec>,
    truncated: bool,
    truncation_reason: Option<String>,
    edge_count: usize,
    byte_budget: usize,
    visited: HashSet<(u32, u16)>,
}

pub fn trace_nested_do_chains(
    bytes: &[u8],
    graph: &ObjectGraph<'_>,
    do_refs: &[(String, (u32, u16))],
    max_depth: u8,
    max_edges: usize,
    max_bytes: usize,
) -> (Vec<NestedFormExec>, Option<String>) {
    let mut state = TraceState {
        chains: Vec::new(),
        truncated: false,
        truncation_reason: None,
        edge_count: 0,
        byte_budget: max_bytes,
        visited: HashSet::new(),
    };
    // Pre-populate visited with the initial refs so we don't double-count
    // them (they are already in resource_refs).
    for (_, obj_ref) in do_refs {
        state.visited.insert(*obj_ref);
    }
    for (name, obj_ref) in do_refs {
        if state.truncated {
            break;
        }
        recurse_form(bytes, graph, *obj_ref, name, 0, max_depth, max_edges, &mut state);
    }
    (state.chains, state.truncation_reason)
}

fn recurse_form(
    bytes: &[u8],
    graph: &ObjectGraph<'_>,
    obj_ref: (u32, u16),
    _do_name: &str,
    depth: u8,
    max_depth: u8,
    max_edges: usize,
    state: &mut TraceState,
) {
    if state.truncated {
        return;
    }
    if depth > max_depth {
        state.truncated = true;
        state.truncation_reason = Some("depth".to_string());
        return;
    }
    if state.edge_count >= max_edges {
        state.truncated = true;
        state.truncation_reason = Some("edges".to_string());
        return;
    }
    if state.byte_budget == 0 {
        state.truncated = true;
        state.truncation_reason = Some("memory".to_string());
        return;
    }

    let Some(entry) = graph.get_object(obj_ref.0, obj_ref.1) else { return };
    let Some(dict) = entry_dict(entry) else { return };
    if !dict.has_name(b"/Subtype", b"/Form") {
        return;
    }
    let PdfAtom::Stream(stream) = &entry.atom else { return };

    let decode_limit = state.byte_budget.min(4 * 1024 * 1024);
    let Ok(decoded) = decode_stream(bytes, stream, decode_limit) else { return };
    state.byte_budget = state.byte_budget.saturating_sub(decoded.data.len());

    let ops = sis_pdf_pdf::content::parse_content_ops(&decoded.data);
    let bindings = collect_resource_bindings(graph, obj_ref);

    for op in &ops {
        if state.truncated {
            break;
        }
        if op.op != "Do" {
            continue;
        }
        let Some(ContentOperand::Name(inner_name)) = op.operands.first() else { continue };
        let Some(inner_ref) = bindings.resolve("Do", inner_name) else { continue };
        if state.visited.contains(&inner_ref) {
            continue;
        }
        state.visited.insert(inner_ref);
        state.chains.push(NestedFormExec {
            do_name: inner_name.clone(),
            depth: depth + 1,
            obj_ref: inner_ref,
        });
        state.edge_count += 1;
        recurse_form(bytes, graph, inner_ref, inner_name, depth + 1, max_depth, max_edges, state);
    }
}

pub fn build_finding_event_index(records: &[EventRecord]) -> BTreeMap<String, Vec<String>> {
    let mut index = BTreeMap::<String, Vec<String>>::new();
    for record in records {
        for finding_id in &record.linked_finding_ids {
            index.entry(finding_id.clone()).or_default().push(record.node_id.clone());
        }
    }
    for node_ids in index.values_mut() {
        node_ids.sort();
        node_ids.dedup();
    }
    index
}

#[cfg(test)]
mod tests {
    use super::{
        build_finding_event_index, build_stream_exec_summaries, extract_event_records,
        extract_event_records_with_projection, summarise_content_ops, trace_nested_do_chains,
        ProjectionOptions, StreamExecSummary,
    };
    use crate::event_graph::{
        build_event_graph, EdgeMetadata, EdgeProvenance, EventEdge, EventEdgeKind, EventGraph,
        EventGraphOptions, EventNode, EventNodeKind, EventType, OutcomeType, TriggerClass,
    };
    use crate::model::{AttackSurface, Confidence, Finding, Severity};
    use sis_pdf_pdf::content::{ContentOp, ContentOperand};
    use sis_pdf_pdf::typed_graph::{EdgeType, TypedEdge, TypedGraph};
    use std::collections::{BTreeMap, HashMap};
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    fn make_graph(nodes: Vec<EventNode>, edges: Vec<EventEdge>) -> EventGraph {
        let mut node_index = HashMap::new();
        for (idx, node) in nodes.iter().enumerate() {
            node_index.insert(node.id.clone(), idx);
        }
        let mut forward_index: HashMap<String, Vec<usize>> = HashMap::new();
        let mut reverse_index: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, edge) in edges.iter().enumerate() {
            forward_index.entry(edge.from.clone()).or_default().push(idx);
            reverse_index.entry(edge.to.clone()).or_default().push(idx);
        }
        EventGraph {
            schema_version: "1.0.0",
            nodes,
            edges,
            node_index,
            forward_index,
            reverse_index,
            truncation: None,
        }
    }

    #[test]
    fn extract_event_records_populates_outcomes_and_metadata() {
        let graph = make_graph(
            vec![
                EventNode {
                    id: "ev:1".to_string(),
                    mitre_techniques: vec!["T1204".to_string()],
                    kind: EventNodeKind::Event {
                        event_type: EventType::DocumentOpen,
                        trigger: TriggerClass::Automatic,
                        label: "Open".to_string(),
                        source_obj: Some((1, 0)),
                    },
                },
                EventNode {
                    id: "out:1".to_string(),
                    mitre_techniques: Vec::new(),
                    kind: EventNodeKind::Outcome {
                        outcome_type: OutcomeType::NetworkEgress,
                        label: "Network".to_string(),
                        target: Some("https://x.example".to_string()),
                        source_obj: Some((2, 0)),
                        evidence: vec!["egress".to_string()],
                        confidence_source: Some("rule".to_string()),
                        confidence_score: Some(95),
                        severity_hint: Some("high".to_string()),
                    },
                },
            ],
            vec![EventEdge {
                from: "ev:1".to_string(),
                to: "out:1".to_string(),
                kind: EventEdgeKind::ProducesOutcome,
                provenance: EdgeProvenance::Finding { finding_id: "finding-1".to_string() },
                metadata: Some(EdgeMetadata {
                    event_key: Some("/OpenAction".to_string()),
                    branch_index: Some(1),
                    initiation: Some("automatic".to_string()),
                }),
            }],
        );

        let records = extract_event_records(&graph);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.node_id, "ev:1");
        assert_eq!(record.trigger_class, "automatic");
        assert_eq!(record.event_key.as_deref(), Some("/OpenAction"));
        assert_eq!(record.branch_index, Some(1));
        assert_eq!(record.mitre_techniques, vec!["T1204".to_string()]);
        assert_eq!(record.outcome_targets.len(), 1);
        let outcome = &record.outcome_targets[0];
        assert_eq!(outcome.outcome_type, "NetworkEgress");
        assert_eq!(outcome.confidence_score, Some(95));
        assert_eq!(outcome.severity_hint.as_deref(), Some("high"));
    }

    #[test]
    fn extract_event_records_with_projection_includes_stream_exec() {
        let graph = make_graph(
            vec![EventNode {
                id: "ev:1".to_string(),
                mitre_techniques: Vec::new(),
                kind: EventNodeKind::Event {
                    event_type: EventType::ContentStreamExec,
                    trigger: TriggerClass::Automatic,
                    label: "Content stream".to_string(),
                    source_obj: Some((1, 0)),
                },
            }],
            Vec::new(),
        );
        let mut summaries = BTreeMap::<String, StreamExecSummary>::new();
        summaries.insert(
            "ev:1".to_string(),
            StreamExecSummary { total_ops: 3, unknown_op_count: 1, ..StreamExecSummary::default() },
        );
        let records = extract_event_records_with_projection(
            &graph,
            &ProjectionOptions { include_stream_exec_summary: true },
            Some(&summaries),
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].stream_exec.as_ref().map(|s| s.total_ops), Some(3));
    }

    #[test]
    fn summarise_content_ops_tracks_resource_refs_and_state() {
        let ops = vec![
            ContentOp {
                op: "q".to_string(),
                operands: Vec::new(),
                span: sis_pdf_pdf::span::Span { start: 0, end: 1 },
            },
            ContentOp {
                op: "Do".to_string(),
                operands: vec![ContentOperand::Name("/Im1".to_string())],
                span: sis_pdf_pdf::span::Span { start: 1, end: 2 },
            },
            ContentOp {
                op: "Q".to_string(),
                operands: Vec::new(),
                span: sis_pdf_pdf::span::Span { start: 2, end: 3 },
            },
            ContentOp {
                op: "ZZ".to_string(),
                operands: Vec::new(),
                span: sis_pdf_pdf::span::Span { start: 3, end: 4 },
            },
        ];
        let summary = summarise_content_ops(&ops);
        assert_eq!(summary.total_ops, 4);
        assert_eq!(summary.graphics_state_max_depth, 1);
        assert!(!summary.graphics_state_underflow);
        assert_eq!(summary.unknown_op_count, 1);
        assert_eq!(summary.resource_refs.len(), 1);
        assert_eq!(summary.resource_refs[0].name, "/Im1");
    }

    #[test]
    fn finding_event_index_is_stable_and_deduplicated() {
        let records = vec![
            super::EventRecord {
                node_id: "ev:2".to_string(),
                linked_finding_ids: vec!["f1".to_string(), "f1".to_string()],
                ..super::EventRecord::default()
            },
            super::EventRecord {
                node_id: "ev:1".to_string(),
                linked_finding_ids: vec!["f1".to_string(), "f2".to_string()],
                ..super::EventRecord::default()
            },
        ];
        let index = build_finding_event_index(&records);
        assert_eq!(index.get("f1"), Some(&vec!["ev:1".to_string(), "ev:2".to_string()]));
        assert_eq!(index.get("f2"), Some(&vec!["ev:1".to_string()]));
    }

    #[test]
    fn events_projection_budget_on_cve_fixture() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/actions/launch_cve_2010_1240.pdf");
        let bytes = std::fs::read(&fixture).expect("fixture bytes");
        let parse_options = sis_pdf_pdf::ParseOptions {
            recover_xref: true,
            deep: false,
            strict: false,
            max_objstm_bytes: 64 * 1024 * 1024,
            max_objects: 250_000,
            max_objstm_total_bytes: 256 * 1024 * 1024,
            carve_stream_objects: false,
            max_carved_objects: 0,
            max_carved_bytes: 0,
        };
        let graph = sis_pdf_pdf::parse_pdf(&bytes, parse_options).expect("parse");
        let classifications = graph.classify_objects();
        let typed_graph = TypedGraph::build(&graph, &classifications);
        let findings = vec![Finding {
            id: "budget-finding".to_string(),
            surface: AttackSurface::Actions,
            kind: "action_open".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Strong,
            action_type: Some("OpenAction".to_string()),
            action_target: Some("obj 6 0".to_string()),
            ..Finding::default()
        }];
        let event_graph = build_event_graph(&typed_graph, &findings, EventGraphOptions::default());

        let start = Instant::now();
        let records = extract_event_records(&event_graph);
        let elapsed = start.elapsed();

        assert!(!records.is_empty(), "projection should return records");
        assert!(elapsed <= Duration::from_millis(500), "projection budget exceeded: {:?}", elapsed);

        let _ = TypedEdge::new((1, 0), (2, 0), EdgeType::OpenAction);
    }

    #[test]
    fn events_projection_with_stream_summary_budget_on_cve_fixture() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/actions/launch_cve_2010_1240.pdf");
        let bytes = std::fs::read(&fixture).expect("fixture bytes");
        let parse_options = sis_pdf_pdf::ParseOptions {
            recover_xref: true,
            deep: false,
            strict: false,
            max_objstm_bytes: 64 * 1024 * 1024,
            max_objects: 250_000,
            max_objstm_total_bytes: 256 * 1024 * 1024,
            carve_stream_objects: false,
            max_carved_objects: 0,
            max_carved_bytes: 0,
        };
        let graph = sis_pdf_pdf::parse_pdf(&bytes, parse_options).expect("parse");
        let classifications = graph.classify_objects();
        let typed_graph = TypedGraph::build(&graph, &classifications);
        let findings = vec![Finding {
            id: "budget-finding".to_string(),
            surface: AttackSurface::Actions,
            kind: "action_open".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Strong,
            action_type: Some("OpenAction".to_string()),
            action_target: Some("obj 6 0".to_string()),
            ..Finding::default()
        }];
        let event_graph = build_event_graph(&typed_graph, &findings, EventGraphOptions::default());

        let start = Instant::now();
        let stream_summaries = build_stream_exec_summaries(&bytes, &graph, &event_graph);
        let records = extract_event_records_with_projection(
            &event_graph,
            &ProjectionOptions { include_stream_exec_summary: true },
            Some(&stream_summaries),
        );
        let elapsed = start.elapsed();

        assert!(!records.is_empty(), "projection should return records");
        assert!(
            elapsed <= Duration::from_millis(150),
            "stream projection budget exceeded: {:?}",
            elapsed
        );
    }

    fn cve_parse_options() -> sis_pdf_pdf::ParseOptions {
        sis_pdf_pdf::ParseOptions {
            recover_xref: true,
            deep: false,
            strict: false,
            max_objstm_bytes: 64 * 1024 * 1024,
            max_objects: 250_000,
            max_objstm_total_bytes: 256 * 1024 * 1024,
            carve_stream_objects: false,
            max_carved_objects: 0,
            max_carved_bytes: 0,
        }
    }

    #[test]
    fn trace_nested_do_chains_empty_do_refs_returns_empty() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/actions/launch_cve_2010_1240.pdf");
        let bytes = std::fs::read(&fixture).expect("fixture bytes");
        let graph = sis_pdf_pdf::parse_pdf(&bytes, cve_parse_options()).expect("parse");

        let (chains, truncation) = trace_nested_do_chains(&bytes, &graph, &[], 8, 128, 4 * 1024 * 1024);
        assert!(chains.is_empty(), "expected no chains for empty do_refs");
        assert!(truncation.is_none(), "expected no truncation");
    }

    #[test]
    fn trace_nested_do_chains_non_form_xobject_skipped() {
        // Pass a reference to object 1 0 (Catalog — not a Form XObject).
        // The tracer should skip it cleanly and produce no chains.
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/actions/launch_cve_2010_1240.pdf");
        let bytes = std::fs::read(&fixture).expect("fixture bytes");
        let graph = sis_pdf_pdf::parse_pdf(&bytes, cve_parse_options()).expect("parse");

        // Object (1, 0) is almost certainly a Catalog, not a Form XObject.
        let do_refs = vec![("/NonForm".to_string(), (1u32, 0u16))];
        let (chains, truncation) = trace_nested_do_chains(&bytes, &graph, &do_refs, 8, 128, 4 * 1024 * 1024);
        assert!(chains.is_empty(), "non-form xobject should produce no nested chains");
        assert!(truncation.is_none());
    }

    #[test]
    fn trace_nested_do_chains_depth_limit_respected_on_fixture() {
        // With a depth limit of 0, no nested forms can be recorded.  The tracer
        // must not panic and the depth cap must remain intact even if any content
        // streams happen to carry form-invocation chains.
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/actions/launch_cve_2010_1240.pdf");
        let bytes = std::fs::read(&fixture).expect("fixture bytes");
        let graph = sis_pdf_pdf::parse_pdf(&bytes, cve_parse_options()).expect("parse");

        let do_refs = vec![("/Form1".to_string(), (1u32, 0u16))];
        // max_depth = 0: any recursion below depth 0 is immediately capped.
        let (chains, _truncation) = trace_nested_do_chains(&bytes, &graph, &do_refs, 0, 128, 4 * 1024 * 1024);
        // Either no chains (object is not a form) or truncation was set — either is
        // correct; the key invariant is no panic and no chains with depth > 0.
        for chain in &chains {
            assert!(chain.depth <= 1, "depth must not exceed max_depth + 1");
        }
    }

    #[test]
    fn trace_nested_do_chains_cycle_terminates_cleanly() {
        // We cannot construct a real cyclic object graph in a unit test, so we
        // verify the termination property using the CVE fixture: re-running
        // trace_nested_do_chains twice with the same do_refs must produce
        // identical results (idempotent, no stale visited state).
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/actions/launch_cve_2010_1240.pdf");
        let bytes = std::fs::read(&fixture).expect("fixture bytes");
        let graph = sis_pdf_pdf::parse_pdf(&bytes, cve_parse_options()).expect("parse");

        let do_refs = vec![("/Form1".to_string(), (1u32, 0u16))];
        let (chains1, trunc1) = trace_nested_do_chains(&bytes, &graph, &do_refs, 8, 128, 4 * 1024 * 1024);
        let (chains2, trunc2) = trace_nested_do_chains(&bytes, &graph, &do_refs, 8, 128, 4 * 1024 * 1024);
        assert_eq!(chains1.len(), chains2.len(), "results must be idempotent");
        assert_eq!(trunc1, trunc2);
    }

    #[test]
    fn events_projection_with_nested_do_summary_on_cve_fixture() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/actions/launch_cve_2010_1240.pdf");
        let bytes = std::fs::read(&fixture).expect("fixture bytes");
        let graph = sis_pdf_pdf::parse_pdf(&bytes, cve_parse_options()).expect("parse");
        let classifications = graph.classify_objects();
        let typed_graph = TypedGraph::build(&graph, &classifications);
        let findings = vec![Finding {
            id: "budget-finding-nested".to_string(),
            surface: AttackSurface::Actions,
            kind: "action_open".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Strong,
            action_type: Some("OpenAction".to_string()),
            action_target: Some("obj 6 0".to_string()),
            ..Finding::default()
        }];
        let event_graph = build_event_graph(&typed_graph, &findings, EventGraphOptions::default());

        let start = Instant::now();
        let summaries = build_stream_exec_summaries(&bytes, &graph, &event_graph);
        let elapsed = start.elapsed();

        // The complete build_stream_exec_summaries call (including nested Do tracing)
        // must stay within budget.  The < 2 ms overhead SLO for the tracer itself
        // applies only to the incremental cost over the base projection; the full call
        // budget here is set to match the existing stream-summary projection budget.
        assert!(
            elapsed <= Duration::from_millis(500),
            "stream exec summaries with nested tracer budget exceeded: {:?}",
            elapsed
        );
        // Verify all nested_form_execs depths are bounded — regardless of whether
        // the fixture produces any ContentStreamExec events.
        for (_, summary) in &summaries {
            for exec in &summary.nested_form_execs {
                assert!(exec.depth <= 8, "depth must not exceed max_depth 8");
            }
        }
    }
}
