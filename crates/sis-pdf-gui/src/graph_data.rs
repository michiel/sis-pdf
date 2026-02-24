use std::collections::HashMap;

use crate::object_data::ObjectData;
use sis_pdf_core::event_graph::{EventEdgeKind, EventGraph, EventNodeKind};

/// Maximum nodes the graph will render. Beyond this, return an error
/// prompting the user to filter first.
pub const MAX_GRAPH_NODES: usize = 2000;

/// A directed graph of PDF objects and their references.
#[derive(Debug, Default)]
pub struct GraphData {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    /// Map from (obj, gen) to node index for fast lookup.
    pub node_index: HashMap<(u32, u16), usize>,
}

/// A node in the object reference graph.
#[derive(Debug, Clone, Default)]
pub struct GraphNode {
    pub object_ref: Option<(u32, u16)>,
    pub event_node_id: Option<String>,
    pub obj_type: String,
    pub label: String,
    pub roles: Vec<String>,
    pub confidence: Option<f32>,
    pub position: [f64; 2],
    pub target_obj: Option<(u32, u16)>,
    pub is_content_stream_exec: bool,
}

/// An edge in the object reference graph.
#[derive(Debug, Clone)]
pub struct GraphEdge {
    pub from_idx: usize,
    pub to_idx: usize,
    /// Whether this edge is suspicious (action->stream, roles containing
    /// JsContainer or UriTarget).
    pub suspicious: bool,
    pub edge_kind: Option<String>,
    pub provenance: Option<String>,
    pub metadata: Option<String>,
}

/// Error returned when the graph cannot be built.
#[derive(Debug, PartialEq)]
pub enum GraphError {
    TooManyNodes { count: usize, limit: usize },
    ParseFailed(String),
}

impl std::fmt::Display for GraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyNodes { count, limit } => {
                write!(
                    f,
                    "Graph has {} nodes (limit {}). Apply type or depth filters to reduce.",
                    count, limit
                )
            }
            Self::ParseFailed(msg) => write!(f, "Unable to build event graph: {}", msg),
        }
    }
}

/// Build a `GraphData` from a `ContentStreamGraph` for the graph viewer's ContentStream mode.
///
/// Converts `CsgNode`/`CsgEdge` to `GraphNode`/`GraphEdge`. Node positions are not set
/// here — the layout engine initialises them after this call.
///
/// `correlated_findings` annotates graph nodes whose decoded span overlaps a finding's evidence
/// offset (Stage 5). Pass an empty slice when findings are not available.
pub fn from_content_graph(
    csg: &sis_pdf_pdf::content_summary::ContentStreamGraph,
    correlated_findings: &[sis_pdf_core::content_correlation::CorrelatedStreamFinding],
) -> Result<GraphData, GraphError> {
    use sis_pdf_pdf::content_summary::{CsgEdgeKind, CsgNodeKind};

    // Build a map from stable CsgNode id to sequential index.
    let id_to_idx: HashMap<&str, usize> =
        csg.nodes.iter().enumerate().map(|(i, n)| (n.id.as_str(), i)).collect();

    let mut node_index: HashMap<(u32, u16), usize> = HashMap::new();
    let nodes: Vec<GraphNode> = csg
        .nodes
        .iter()
        .enumerate()
        .map(|(idx, node)| {
            // Check if any finding's decoded_offset falls within this node's span.
            let has_finding = correlated_findings.iter().any(|f| {
                f.decoded_offset
                    .map(|o| o >= node.span_start && o <= node.span_end)
                    .unwrap_or(false)
            });
            // Merge finding annotation with existing anomaly flag.
            let anomaly = node.anomaly || has_finding;

            let (obj_type, mut label, object_ref) = match &node.kind {
                CsgNodeKind::TextBlock { strings, fonts } => {
                    let font_str =
                        if fonts.is_empty() { String::new() } else { fonts.join(", ") };
                    let preview: Vec<&str> =
                        strings.iter().take(2).map(|s| s.as_str()).collect();
                    let mut text_preview = preview.join("  ");
                    if text_preview.len() > 40 {
                        text_preview.truncate(37);
                        text_preview.push_str("...");
                    }
                    let label = if text_preview.is_empty() {
                        format!("Text [{}]", font_str)
                    } else {
                        format!("Text [{}]\n{}", font_str, text_preview)
                    };
                    ("content_text".to_string(), label, None)
                }
                CsgNodeKind::XObjectRef { name, subtype } => {
                    let st = subtype.as_deref().unwrap_or("?");
                    let obj_type = match subtype.as_deref() {
                        Some("Image") => "content_image",
                        Some("Form") => "content_form_xobj",
                        _ => "content_image",
                    };
                    (obj_type.to_string(), format!("{} [{}]", name, st), None)
                }
                CsgNodeKind::InlineImage { width, height } => {
                    let dims = match (width, height) {
                        (Some(w), Some(h)) => format!("{}×{}", w, h),
                        _ => "?×?".to_string(),
                    };
                    ("content_inline_image".to_string(), format!("Inline Image {}", dims), None)
                }
                CsgNodeKind::MarkedContent { tag } => {
                    ("content_marked".to_string(), format!("MC {}", tag), None)
                }
                CsgNodeKind::GraphicsState { depth } => (
                    "content_gstate".to_string(),
                    format!("q…Q (depth {})", depth),
                    None,
                ),
                CsgNodeKind::OpGroup { label, count } => (
                    "content_ops".to_string(),
                    format!("{} ({} ops)", label, count),
                    None,
                ),
                CsgNodeKind::PdfObject { obj, gen, obj_type } => {
                    let r = Some((*obj, *gen));
                    node_index.insert((*obj, *gen), idx);
                    ("object".to_string(), format!("{} {} R [{}]", obj, gen, obj_type), r)
                }
            };
            // Append finding kind annotation to label if applicable.
            if has_finding {
                for f in correlated_findings {
                    if f.decoded_offset.map(|o| o >= node.span_start && o <= node.span_end).unwrap_or(false) {
                        label.push_str(&format!("\n[{}]", f.kind));
                        break;
                    }
                }
            }
            GraphNode {
                object_ref,
                event_node_id: Some(node.id.clone()),
                obj_type,
                label,
                roles: if anomaly { vec!["finding".to_string()] } else { Vec::new() },
                confidence: None,
                position: [node.sequence as f64 * 120.0, 0.0],
                target_obj: None,
                is_content_stream_exec: false,
            }
        })
        .collect();

    let edges: Vec<GraphEdge> = csg
        .edges
        .iter()
        .filter_map(|edge| {
            let from_idx = *id_to_idx.get(edge.from.as_str())?;
            let to_idx = *id_to_idx.get(edge.to.as_str())?;
            let edge_kind = Some(match edge.kind {
                CsgEdgeKind::Sequence => "sequence",
                CsgEdgeKind::ResourceRef => "resource_ref",
                CsgEdgeKind::XObjectContains => "xobj_contains",
                CsgEdgeKind::Nesting => "nesting",
            })
            .map(|s: &str| s.to_string());
            Some(GraphEdge {
                from_idx,
                to_idx,
                suspicious: false,
                edge_kind,
                provenance: None,
                metadata: None,
            })
        })
        .collect();

    Ok(GraphData { nodes, edges, node_index })
}

/// Build a complete graph from all objects in the data set.
pub fn from_object_data(data: &ObjectData) -> Result<GraphData, GraphError> {
    if data.objects.len() > MAX_GRAPH_NODES {
        return Err(GraphError::TooManyNodes { count: data.objects.len(), limit: MAX_GRAPH_NODES });
    }
    build_graph(data, |_| true)
}

/// Build a graph from the core EventGraph model.
pub fn from_event_graph(data: &EventGraph) -> Result<GraphData, GraphError> {
    if data.nodes.len() > MAX_GRAPH_NODES {
        return Err(GraphError::TooManyNodes { count: data.nodes.len(), limit: MAX_GRAPH_NODES });
    }

    let mut nodes = Vec::new();
    let mut node_index = HashMap::new();
    let mut id_to_idx = HashMap::new();

    for node in &data.nodes {
        let (object_ref, obj_type, label, mut roles, confidence, is_content_stream_exec) =
            match &node.kind {
                EventNodeKind::Object { obj, gen, obj_type } => (
                    Some((*obj, *gen)),
                    obj_type.clone().unwrap_or_else(|| "object".to_string()),
                    format!("{} {}", obj, gen),
                    Vec::new(),
                    None,
                    false,
                ),
                EventNodeKind::Event { event_type, trigger, label, source_obj } => (
                    *source_obj,
                    "event".to_string(),
                    label.clone(),
                    vec![format!("{:?}", event_type), trigger.as_str().to_string()],
                    None,
                    matches!(event_type, sis_pdf_core::event_graph::EventType::ContentStreamExec),
                ),
                EventNodeKind::Outcome {
                    outcome_type,
                    label,
                    target,
                    source_obj,
                    confidence_score,
                    ..
                } => (
                    *source_obj,
                    "outcome".to_string(),
                    target
                        .clone()
                        .map(|value| format!("{label} ({value})"))
                        .unwrap_or_else(|| label.clone()),
                    vec![format!("{:?}", outcome_type)],
                    confidence_score.map(|value| value as f32 / 100.0),
                    false,
                ),
                EventNodeKind::Collapse { label, member_count, .. } => (
                    None,
                    "collapse".to_string(),
                    format!("{label} ({member_count})"),
                    vec!["collapsed".to_string()],
                    None,
                    false,
                ),
            };
        if !node.mitre_techniques.is_empty() {
            roles.push(format!("MITRE: {}", node.mitre_techniques.join(",")));
        }

        let idx = nodes.len();
        id_to_idx.insert(node.id.clone(), idx);
        if let (Some((obj, gen)), EventNodeKind::Object { .. }) = (object_ref, &node.kind) {
            node_index.insert((obj, gen), idx);
        }
        nodes.push(GraphNode {
            object_ref,
            event_node_id: Some(node.id.clone()),
            obj_type,
            label,
            roles,
            confidence,
            position: [0.0, 0.0],
            is_content_stream_exec,
            ..Default::default()
        });
    }

    for edge in &data.edges {
        if edge.kind != EventEdgeKind::Executes {
            continue;
        }
        let Some(&from_idx) = id_to_idx.get(&edge.from) else {
            continue;
        };
        let Some(&to_idx) = id_to_idx.get(&edge.to) else {
            continue;
        };
        if nodes[from_idx].obj_type != "event" || !nodes[from_idx].is_content_stream_exec {
            continue;
        }
        nodes[from_idx].target_obj = nodes[to_idx].object_ref;
    }

    let mut edges = Vec::new();
    for edge in &data.edges {
        let Some(&from_idx) = id_to_idx.get(&edge.from) else {
            continue;
        };
        let Some(&to_idx) = id_to_idx.get(&edge.to) else {
            continue;
        };
        let suspicious =
            matches!(edge.kind, EventEdgeKind::Executes | EventEdgeKind::ProducesOutcome);
        let provenance = match &edge.provenance {
            sis_pdf_core::event_graph::EdgeProvenance::TypedEdge { edge_type } => {
                Some(format!("typed:{edge_type}"))
            }
            sis_pdf_core::event_graph::EdgeProvenance::Finding { finding_id } => {
                Some(format!("finding:{finding_id}"))
            }
            sis_pdf_core::event_graph::EdgeProvenance::Heuristic => Some("heuristic".to_string()),
        };
        edges.push(GraphEdge {
            from_idx,
            to_idx,
            suspicious,
            edge_kind: Some(format!("{:?}", edge.kind)),
            provenance,
            metadata: edge.metadata.as_ref().map(|meta| {
                let mut fields = Vec::new();
                if let Some(event_key) = &meta.event_key {
                    fields.push(format!("event_key={event_key}"));
                }
                if let Some(branch_index) = meta.branch_index {
                    fields.push(format!("branch_index={branch_index}"));
                }
                if let Some(initiation) = &meta.initiation {
                    fields.push(format!("initiation={initiation}"));
                }
                fields.join(", ")
            }),
        });
    }

    Ok(GraphData { nodes, edges, node_index })
}

/// Build a graph including only objects matching one of the given types.
pub fn from_object_data_filtered(
    data: &ObjectData,
    types: &[&str],
) -> Result<GraphData, GraphError> {
    build_graph(data, |obj| types.iter().any(|t| obj.obj_type.eq_ignore_ascii_case(t)))
}

/// Build a graph via BFS from a centre node up to `max_depth` hops.
pub fn from_object_data_depth(
    data: &ObjectData,
    centre: (u32, u16),
    max_depth: usize,
) -> Result<GraphData, GraphError> {
    // BFS to find reachable nodes within depth
    let mut visited: HashMap<(u32, u16), usize> = HashMap::new(); // key -> depth
    let mut queue = std::collections::VecDeque::new();

    if data.index.contains_key(&centre) {
        visited.insert(centre, 0);
        queue.push_back((centre, 0));
    }

    while let Some((key, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        if let Some(&idx) = data.index.get(&key) {
            let obj = &data.objects[idx];
            // Follow outgoing references
            for &target in &obj.references_from {
                if !visited.contains_key(&target) && data.index.contains_key(&target) {
                    if visited.len() >= MAX_GRAPH_NODES {
                        return Err(GraphError::TooManyNodes {
                            count: visited.len() + 1,
                            limit: MAX_GRAPH_NODES,
                        });
                    }
                    visited.insert(target, depth + 1);
                    queue.push_back((target, depth + 1));
                }
            }
            // Follow incoming references
            for &source in &obj.references_to {
                if !visited.contains_key(&source) && data.index.contains_key(&source) {
                    if visited.len() >= MAX_GRAPH_NODES {
                        return Err(GraphError::TooManyNodes {
                            count: visited.len() + 1,
                            limit: MAX_GRAPH_NODES,
                        });
                    }
                    visited.insert(source, depth + 1);
                    queue.push_back((source, depth + 1));
                }
            }
        }
    }

    let reachable: std::collections::HashSet<(u32, u16)> = visited.keys().copied().collect();
    build_graph(data, |obj| reachable.contains(&(obj.obj, obj.gen)))
}

/// Internal builder that creates a graph from objects matching a predicate.
fn build_graph(
    data: &ObjectData,
    include: impl Fn(&crate::object_data::ObjectSummary) -> bool,
) -> Result<GraphData, GraphError> {
    let mut nodes = Vec::new();
    let mut node_index = HashMap::new();

    for obj in &data.objects {
        if !include(obj) {
            continue;
        }
        let idx = nodes.len();
        node_index.insert((obj.obj, obj.gen), idx);
        nodes.push(GraphNode {
            object_ref: Some((obj.obj, obj.gen)),
            obj_type: obj.obj_type.clone(),
            label: format!("{} {}", obj.obj, obj.gen),
            roles: obj.roles.clone(),
            confidence: None,
            position: [0.0, 0.0],
            ..Default::default()
        });
    }

    if nodes.len() > MAX_GRAPH_NODES {
        return Err(GraphError::TooManyNodes { count: nodes.len(), limit: MAX_GRAPH_NODES });
    }

    // Build edges from references_from, only between included nodes
    let mut edges = Vec::new();
    for obj in &data.objects {
        let Some(&from_idx) = node_index.get(&(obj.obj, obj.gen)) else {
            continue;
        };
        for &(target_obj, target_gen) in &obj.references_from {
            if let Some(&to_idx) = node_index.get(&(target_obj, target_gen)) {
                let suspicious =
                    is_suspicious_edge(obj, &data.objects[data.index[&(target_obj, target_gen)]]);
                edges.push(GraphEdge {
                    from_idx,
                    to_idx,
                    suspicious,
                    edge_kind: None,
                    provenance: None,
                    metadata: None,
                });
            }
        }
    }

    Ok(GraphData { nodes, edges, node_index })
}

/// Heuristic: an edge is suspicious if it goes from an action to a stream,
/// or if the source has JsContainer/UriTarget roles.
fn is_suspicious_edge(
    from: &crate::object_data::ObjectSummary,
    to: &crate::object_data::ObjectSummary,
) -> bool {
    let from_is_action = from.obj_type.eq_ignore_ascii_case("action");
    let to_is_stream = to.has_stream;

    if from_is_action && to_is_stream {
        return true;
    }

    let suspicious_roles = ["JsContainer", "UriTarget"];
    for role in &from.roles {
        if suspicious_roles.iter().any(|r| role.contains(r)) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_data::{ObjectData, ObjectSummary};
    use sis_pdf_core::event_graph::{
        EdgeProvenance, EventEdge, EventEdgeKind, EventGraph, EventNode, EventNodeKind, EventType,
        TriggerClass,
    };

    fn make_object(obj: u32, gen: u16, obj_type: &str, refs: Vec<(u32, u16)>) -> ObjectSummary {
        ObjectSummary {
            obj,
            gen,
            obj_type: obj_type.to_string(),
            roles: Vec::new(),
            dict_entries: Vec::new(),
            dict_entries_tree: Vec::new(),
            has_stream: false,
            stream_text: None,
            stream_raw: None,
            stream_filters: Vec::new(),
            stream_length: None,
            stream_data_span: None,
            stream_content_type: None,
            image_width: None,
            image_height: None,
            image_bits: None,
            image_color_space: None,
            image_preview: None,
            image_preview_status: None,
            preview_statuses: Vec::new(),
            preview_summary: None,
            preview_source: None,
            references_from: refs,
            references_to: Vec::new(),
        }
    }

    fn small_object_data() -> ObjectData {
        let mut objects = vec![
            make_object(1, 0, "catalog", vec![(2, 0), (3, 0)]),
            make_object(2, 0, "page", vec![(4, 0)]),
            make_object(3, 0, "action", vec![(4, 0)]),
            make_object(4, 0, "stream", vec![]),
        ];
        // Build reverse references
        objects[1].references_to = vec![(1, 0)];
        objects[2].references_to = vec![(1, 0)];
        objects[3].references_to = vec![(2, 0), (3, 0)];

        let mut index = HashMap::new();
        for (i, obj) in objects.iter().enumerate() {
            index.insert((obj.obj, obj.gen), i);
        }

        ObjectData { objects, index, xref_sections: Vec::new(), deviations: Vec::new() }
    }

    fn make_event_graph(nodes: Vec<EventNode>, edges: Vec<EventEdge>) -> EventGraph {
        EventGraph {
            schema_version: "1.0.0",
            nodes,
            edges,
            node_index: HashMap::new(),
            forward_index: HashMap::new(),
            reverse_index: HashMap::new(),
            truncation: None,
        }
    }

    #[test]
    fn build_from_small_data() {
        let data = small_object_data();
        let graph = from_object_data(&data).expect("should build");
        assert_eq!(graph.nodes.len(), 4);
        // Catalog refs 2 objects, page refs 1, action refs 1
        assert_eq!(graph.edges.len(), 4);
    }

    #[test]
    fn cap_enforcement() {
        let mut objects = Vec::new();
        let mut index = HashMap::new();
        for i in 0..(MAX_GRAPH_NODES + 1) as u32 {
            let obj = make_object(i, 0, "other", vec![]);
            index.insert((i, 0u16), objects.len());
            objects.push(obj);
        }
        let data = ObjectData { objects, index, xref_sections: Vec::new(), deviations: Vec::new() };
        let result = from_object_data(&data);
        assert!(result.is_err());
        match result {
            Err(GraphError::TooManyNodes { count, limit }) => {
                assert_eq!(count, MAX_GRAPH_NODES + 1);
                assert_eq!(limit, MAX_GRAPH_NODES);
            }
            _ => panic!("Expected TooManyNodes"),
        }
    }

    #[test]
    fn filter_by_type() {
        let data = small_object_data();
        let graph = from_object_data_filtered(&data, &["page", "catalog"]).expect("should build");
        assert_eq!(graph.nodes.len(), 2);
        // Only catalog->page edge should be present (both endpoints included)
        assert_eq!(graph.edges.len(), 1);
    }

    #[test]
    fn depth_limited_bfs() {
        let data = small_object_data();
        // From catalog (obj 1), depth=1 should include catalog + direct refs (2, 3)
        let graph = from_object_data_depth(&data, (1, 0), 1).expect("should build");
        assert_eq!(graph.nodes.len(), 3);
    }

    #[test]
    fn suspicious_edge_detection() {
        let mut data = small_object_data();
        // Make object 4 (stream) actually have has_stream=true
        data.objects[3].has_stream = true;
        let graph = from_object_data(&data).expect("should build");
        // Edge from action (obj 3) to stream (obj 4) should be suspicious
        let suspicious: Vec<_> = graph.edges.iter().filter(|e| e.suspicious).collect();
        assert!(!suspicious.is_empty(), "Expected at least one suspicious edge");
        // Find the specific edge 3->4
        let action_to_stream = graph.edges.iter().find(|e| {
            graph.nodes[e.from_idx].object_ref == Some((3, 0))
                && graph.nodes[e.to_idx].object_ref == Some((4, 0))
        });
        assert!(action_to_stream.is_some(), "action->stream edge should exist");
        assert!(action_to_stream.expect("checked").suspicious);
    }

    #[test]
    fn empty_data_builds_empty_graph() {
        let data = ObjectData::default();
        let graph = from_object_data(&data).expect("should build");
        assert_eq!(graph.nodes.len(), 0);
        assert_eq!(graph.edges.len(), 0);
    }

    #[test]
    fn from_event_graph_sets_target_obj_only_for_content_stream_exec() {
        let graph = make_event_graph(
            vec![
                EventNode {
                    id: "obj:3:0".to_string(),
                    mitre_techniques: Vec::new(),
                    kind: EventNodeKind::Object {
                        obj: 3,
                        gen: 0,
                        obj_type: Some("page".to_string()),
                    },
                },
                EventNode {
                    id: "ev:3:0:ContentStreamExec:0".to_string(),
                    mitre_techniques: Vec::new(),
                    kind: EventNodeKind::Event {
                        event_type: EventType::ContentStreamExec,
                        trigger: TriggerClass::Automatic,
                        label: "Content stream execution".to_string(),
                        source_obj: Some((3, 0)),
                    },
                },
                EventNode {
                    id: "obj:7:0".to_string(),
                    mitre_techniques: Vec::new(),
                    kind: EventNodeKind::Object {
                        obj: 7,
                        gen: 0,
                        obj_type: Some("stream".to_string()),
                    },
                },
            ],
            vec![
                EventEdge {
                    from: "obj:3:0".to_string(),
                    to: "ev:3:0:ContentStreamExec:0".to_string(),
                    kind: EventEdgeKind::Triggers,
                    provenance: EdgeProvenance::Heuristic,
                    metadata: None,
                },
                EventEdge {
                    from: "ev:3:0:ContentStreamExec:0".to_string(),
                    to: "obj:7:0".to_string(),
                    kind: EventEdgeKind::Executes,
                    provenance: EdgeProvenance::Heuristic,
                    metadata: None,
                },
            ],
        );
        let gui_graph = from_event_graph(&graph).expect("graph should parse");
        let event_node = gui_graph
            .nodes
            .iter()
            .find(|node| node.label == "Content stream execution")
            .expect("event node should exist");
        assert!(event_node.is_content_stream_exec);
        assert_eq!(event_node.object_ref, Some((3, 0)));
        assert_eq!(event_node.target_obj, Some((7, 0)));
    }

    #[test]
    fn from_event_graph_non_content_stream_exec_keeps_target_obj_none() {
        let graph = make_event_graph(
            vec![
                EventNode {
                    id: "obj:1:0".to_string(),
                    mitre_techniques: Vec::new(),
                    kind: EventNodeKind::Object {
                        obj: 1,
                        gen: 0,
                        obj_type: Some("catalog".to_string()),
                    },
                },
                EventNode {
                    id: "ev:1:0:DocumentOpen:0".to_string(),
                    mitre_techniques: Vec::new(),
                    kind: EventNodeKind::Event {
                        event_type: EventType::DocumentOpen,
                        trigger: TriggerClass::Automatic,
                        label: "Document open".to_string(),
                        source_obj: Some((1, 0)),
                    },
                },
                EventNode {
                    id: "obj:8:0".to_string(),
                    mitre_techniques: Vec::new(),
                    kind: EventNodeKind::Object {
                        obj: 8,
                        gen: 0,
                        obj_type: Some("action".to_string()),
                    },
                },
            ],
            vec![
                EventEdge {
                    from: "obj:1:0".to_string(),
                    to: "ev:1:0:DocumentOpen:0".to_string(),
                    kind: EventEdgeKind::Triggers,
                    provenance: EdgeProvenance::Heuristic,
                    metadata: None,
                },
                EventEdge {
                    from: "ev:1:0:DocumentOpen:0".to_string(),
                    to: "obj:8:0".to_string(),
                    kind: EventEdgeKind::Executes,
                    provenance: EdgeProvenance::Heuristic,
                    metadata: None,
                },
            ],
        );
        let gui_graph = from_event_graph(&graph).expect("graph should parse");
        let event_node = gui_graph
            .nodes
            .iter()
            .find(|node| node.label == "Document open")
            .expect("event node should exist");
        assert!(!event_node.is_content_stream_exec);
        assert_eq!(event_node.target_obj, None);
        assert_eq!(event_node.object_ref, Some((1, 0)));
    }
}
