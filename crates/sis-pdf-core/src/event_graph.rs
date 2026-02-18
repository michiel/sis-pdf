use crate::model::Finding;
use serde::{Deserialize, Serialize};
use sis_pdf_pdf::typed_graph::{EdgeType, TypedGraph};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub type EventNodeId = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriggerClass {
    Automatic,
    Hidden,
    User,
}

impl TriggerClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::Hidden => "hidden",
            Self::User => "user",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    DocumentOpen,
    DocumentWillClose,
    DocumentWillSave,
    DocumentDidSave,
    DocumentWillPrint,
    DocumentDidPrint,
    PageOpen,
    PageClose,
    PageVisible,
    PageInvisible,
    FieldKeystroke,
    FieldFormat,
    FieldValidate,
    FieldCalculate,
    FieldMouseDown,
    FieldMouseUp,
    FieldMouseEnter,
    FieldMouseExit,
    FieldOnFocus,
    FieldOnBlur,
    FieldActivation,
    AnnotationActivation,
    NextAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutcomeType {
    NetworkEgress,
    FilesystemWrite,
    ExternalLaunch,
    CodeExecution,
    FormSubmission,
    EmbeddedPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventNodeKind {
    Object {
        obj: u32,
        gen: u16,
        obj_type: Option<String>,
    },
    Event {
        event_type: EventType,
        trigger: TriggerClass,
        label: String,
        source_obj: Option<(u32, u16)>,
    },
    Outcome {
        outcome_type: OutcomeType,
        label: String,
        target: Option<String>,
        source_obj: Option<(u32, u16)>,
        evidence: Vec<String>,
        confidence_source: Option<String>,
        confidence_score: Option<u8>,
        severity_hint: Option<String>,
    },
    Collapse {
        label: String,
        member_count: usize,
        collapsed_members: Vec<EventNodeId>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventEdgeKind {
    Structural,
    Triggers,
    Executes,
    ProducesOutcome,
    CollapsedStructural,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum EdgeProvenance {
    TypedEdge { edge_type: String },
    Finding { finding_id: String },
    Heuristic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventNode {
    pub id: EventNodeId,
    pub mitre_techniques: Vec<String>,
    #[serde(flatten)]
    pub kind: EventNodeKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventEdge {
    pub from: EventNodeId,
    pub to: EventNodeId,
    pub kind: EventEdgeKind,
    pub provenance: EdgeProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventGraph {
    pub schema_version: &'static str,
    pub nodes: Vec<EventNode>,
    pub edges: Vec<EventEdge>,
    pub node_index: HashMap<EventNodeId, usize>,
    pub forward_index: HashMap<EventNodeId, Vec<usize>>,
    pub reverse_index: HashMap<EventNodeId, Vec<usize>>,
}

#[derive(Debug, Clone, Copy)]
pub struct EventGraphOptions {
    pub include_structure_edges: bool,
    pub collapse_structure_only: bool,
}

impl Default for EventGraphOptions {
    fn default() -> Self {
        Self { include_structure_edges: true, collapse_structure_only: true }
    }
}

pub fn build_event_graph(
    typed_graph: &TypedGraph<'_>,
    findings: &[Finding],
    options: EventGraphOptions,
) -> EventGraph {
    let mut nodes = Vec::<EventNode>::new();
    let mut edges = Vec::<EventEdge>::new();
    let mut object_nodes = BTreeMap::<(u32, u16), EventNodeId>::new();
    let mut object_node_type = HashMap::<EventNodeId, Option<String>>::new();
    let mut event_counter = 0usize;
    let mut outcome_counter = 0usize;
    let mut object_events = HashMap::<(u32, u16), Vec<EventNodeId>>::new();
    let classifications = typed_graph.graph.classify_objects();

    for entry in &typed_graph.graph.objects {
        let id = object_node_id(entry.obj, entry.gen);
        let obj_type = classifications
            .get(&(entry.obj, entry.gen))
            .map(|c| format!("{:?}", c.obj_type).to_ascii_lowercase());
        object_node_type.insert(id.clone(), obj_type.clone());
        nodes.push(EventNode {
            id: id.clone(),
            mitre_techniques: Vec::new(),
            kind: EventNodeKind::Object { obj: entry.obj, gen: entry.gen, obj_type },
        });
        object_nodes.insert((entry.obj, entry.gen), id);
    }

    for edge in &typed_graph.edges {
        if options.include_structure_edges {
            let provenance =
                EdgeProvenance::TypedEdge { edge_type: edge.edge_type.as_str().to_string() };
            edges.push(EventEdge {
                from: object_node_id(edge.src.0, edge.src.1),
                to: object_node_id(edge.dst.0, edge.dst.1),
                kind: EventEdgeKind::Structural,
                provenance: provenance.clone(),
            });
        }

        if let Some((event_type, trigger, label)) = edge_to_event(&edge.edge_type) {
            let id = format!("ev:{}:{}:{:?}:{}", edge.src.0, edge.src.1, event_type, event_counter);
            event_counter += 1;
            nodes.push(EventNode {
                id: id.clone(),
                mitre_techniques: mitre_techniques_for_event(event_type),
                kind: EventNodeKind::Event {
                    event_type,
                    trigger,
                    label,
                    source_obj: Some(edge.src),
                },
            });
            object_events.entry(edge.src).or_default().push(id.clone());
            edges.push(EventEdge {
                from: object_node_id(edge.src.0, edge.src.1),
                to: id.clone(),
                kind: EventEdgeKind::Triggers,
                provenance: EdgeProvenance::TypedEdge {
                    edge_type: edge.edge_type.as_str().to_string(),
                },
            });
            edges.push(EventEdge {
                from: id,
                to: object_node_id(edge.dst.0, edge.dst.1),
                kind: EventEdgeKind::Executes,
                provenance: EdgeProvenance::TypedEdge {
                    edge_type: edge.edge_type.as_str().to_string(),
                },
            });
        }

        if let Some((outcome_type, label)) = edge_to_outcome(&edge.edge_type) {
            let id =
                format!("out:{}:{}:{:?}:{}", edge.src.0, edge.src.1, outcome_type, outcome_counter);
            outcome_counter += 1;
            let source_obj = Some(edge.src);
            nodes.push(EventNode {
                id: id.clone(),
                mitre_techniques: mitre_techniques_for_outcome(outcome_type),
                kind: EventNodeKind::Outcome {
                    outcome_type,
                    label,
                    target: Some(format!("{} {}", edge.dst.0, edge.dst.1)),
                    source_obj,
                    evidence: vec![edge.edge_type.as_str().to_string()],
                    confidence_source: Some("typed_edge".to_string()),
                    confidence_score: Some(70),
                    severity_hint: Some("medium".to_string()),
                },
            });
            edges.push(EventEdge {
                from: object_node_id(edge.src.0, edge.src.1),
                to: id,
                kind: EventEdgeKind::ProducesOutcome,
                provenance: EdgeProvenance::TypedEdge {
                    edge_type: edge.edge_type.as_str().to_string(),
                },
            });
        }
    }

    for finding in findings {
        let refs =
            finding.objects.iter().filter_map(|value| parse_object_ref(value)).collect::<Vec<_>>();
        if refs.is_empty() {
            continue;
        }

        let target = finding
            .action_target
            .clone()
            .or_else(|| finding.meta.get("action.target").cloned())
            .or_else(|| finding.meta.get("uri").cloned());
        let mapped = infer_outcome_from_finding(finding, target.as_deref());
        let Some((outcome_type, label)) = mapped else {
            continue;
        };

        let base_ref = refs[0];
        let id =
            format!("out:{}:{}:{:?}:{}", base_ref.0, base_ref.1, outcome_type, outcome_counter);
        outcome_counter += 1;
        nodes.push(EventNode {
            id: id.clone(),
            mitre_techniques: mitre_techniques_for_outcome(outcome_type),
            kind: EventNodeKind::Outcome {
                outcome_type,
                label,
                target,
                source_obj: Some(base_ref),
                evidence: vec![finding.id.clone()],
                confidence_source: Some("finding".to_string()),
                confidence_score: Some(confidence_to_score(finding.confidence)),
                severity_hint: Some(format!("{:?}", finding.severity).to_ascii_lowercase()),
            },
        });

        for (obj, gen) in refs {
            let from = object_node_id(obj, gen);
            if object_nodes.contains_key(&(obj, gen)) {
                edges.push(EventEdge {
                    from: from.clone(),
                    to: id.clone(),
                    kind: EventEdgeKind::ProducesOutcome,
                    provenance: EdgeProvenance::Finding { finding_id: finding.id.clone() },
                });
            }
            if let Some(event_ids) = object_events.get(&(obj, gen)) {
                for event_id in event_ids {
                    edges.push(EventEdge {
                        from: event_id.clone(),
                        to: id.clone(),
                        kind: EventEdgeKind::ProducesOutcome,
                        provenance: EdgeProvenance::Finding { finding_id: finding.id.clone() },
                    });
                }
            }
        }
    }

    if options.collapse_structure_only {
        collapse_structure_only_nodes(&mut nodes, &mut edges, &object_node_type);
    }

    dedup_edges(&mut edges);
    build_indices(nodes, edges)
}

pub fn export_event_graph_json(event_graph: &EventGraph) -> serde_json::Value {
    serde_json::to_value(event_graph).unwrap_or_else(|_| serde_json::json!({}))
}

pub fn export_event_graph_dot(event_graph: &EventGraph) -> String {
    let mut out = String::from("digraph event_graph {\n");
    for node in &event_graph.nodes {
        let (shape, label, color) = match &node.kind {
            EventNodeKind::Object { obj, gen, obj_type } => (
                "ellipse",
                format!(
                    "{} {}\\n{}",
                    obj,
                    gen,
                    obj_type.clone().unwrap_or_else(|| "object".into())
                ),
                "gray",
            ),
            EventNodeKind::Event { label, trigger, .. } => {
                ("diamond", format!("{}\\n{}", label, trigger.as_str()), "orange")
            }
            EventNodeKind::Outcome { label, target, .. } => (
                "box",
                format!("{}\\n{}", label, target.clone().unwrap_or_else(|| "-".into())),
                "red",
            ),
            EventNodeKind::Collapse { label, member_count, .. } => {
                ("box3d", format!("{}\\n{} members", label, member_count), "lightgray")
            }
        };
        out.push_str(&format!(
            "  \"{}\" [shape={}, color={}, label=\"{}\"];\n",
            node.id,
            shape,
            color,
            label.replace('"', "\\\"")
        ));
    }

    for edge in &event_graph.edges {
        let style = match edge.kind {
            EventEdgeKind::Structural => "color=gray",
            EventEdgeKind::Triggers => "color=orange, style=bold",
            EventEdgeKind::Executes => "color=blue",
            EventEdgeKind::ProducesOutcome => "color=red, style=bold",
            EventEdgeKind::CollapsedStructural => "color=gray, style=dashed",
        };
        out.push_str(&format!(
            "  \"{}\" -> \"{}\" [{}];\n",
            edge.from.replace('"', "\\\""),
            edge.to.replace('"', "\\\""),
            style
        ));
    }
    out.push_str("}\n");
    out
}

fn object_node_id(obj: u32, gen: u16) -> EventNodeId {
    format!("obj:{obj}:{gen}")
}

fn edge_to_event(edge_type: &EdgeType) -> Option<(EventType, TriggerClass, String)> {
    match edge_type {
        EdgeType::OpenAction => {
            Some((EventType::DocumentOpen, TriggerClass::Automatic, "/OpenAction".to_string()))
        }
        EdgeType::PageAction { event } => Some((
            map_page_event(event),
            if matches!(event.as_str(), "/O" | "/C" | "/PV" | "/PI") {
                TriggerClass::Automatic
            } else {
                TriggerClass::User
            },
            format!("/PageAA {event}"),
        )),
        EdgeType::AnnotationAction => Some((
            EventType::AnnotationActivation,
            TriggerClass::Hidden,
            "/AnnotationAction".to_string(),
        )),
        EdgeType::FormFieldAction { event } => {
            Some((map_field_event(event), TriggerClass::User, format!("/FieldAA {event}")))
        }
        EdgeType::AdditionalAction { event } => Some((
            map_additional_event(event),
            if matches!(event.as_str(), "/WC" | "/WS" | "/DS" | "/WP" | "/DP") {
                TriggerClass::Automatic
            } else {
                TriggerClass::User
            },
            format!("/AA {event}"),
        )),
        EdgeType::NextAction => {
            Some((EventType::NextAction, TriggerClass::Hidden, "/Next".to_string()))
        }
        _ => None,
    }
}

fn edge_to_outcome(edge_type: &EdgeType) -> Option<(OutcomeType, String)> {
    match edge_type {
        EdgeType::UriTarget => Some((OutcomeType::NetworkEgress, "Network egress".to_string())),
        EdgeType::SubmitFormTarget => {
            Some((OutcomeType::FormSubmission, "Form submission".to_string()))
        }
        EdgeType::LaunchTarget | EdgeType::GoToRTarget => {
            Some((OutcomeType::ExternalLaunch, "External launch".to_string()))
        }
        EdgeType::EmbeddedFileRef => {
            Some((OutcomeType::EmbeddedPayload, "Embedded payload".to_string()))
        }
        EdgeType::JavaScriptPayload => {
            Some((OutcomeType::CodeExecution, "JavaScript execution".to_string()))
        }
        _ => None,
    }
}

fn infer_outcome_from_finding(
    finding: &Finding,
    target: Option<&str>,
) -> Option<(OutcomeType, String)> {
    let kind = finding.kind.to_ascii_lowercase();
    if kind.contains("exfil") || kind.contains("uri") || kind.contains("network") {
        return Some((OutcomeType::NetworkEgress, "Network egress".to_string()));
    }
    if kind.contains("submit") || kind.contains("form") {
        return Some((OutcomeType::FormSubmission, "Form submission".to_string()));
    }
    if kind.contains("launch") || kind.contains("gotor") || kind.contains("external") {
        return Some((OutcomeType::ExternalLaunch, "External launch".to_string()));
    }
    if kind.contains("embedded") || kind.contains("payload") {
        return Some((OutcomeType::EmbeddedPayload, "Embedded payload".to_string()));
    }
    if kind.contains("filesystem") || kind.contains("file_write") || kind.contains("dropper") {
        return Some((OutcomeType::FilesystemWrite, "Filesystem write".to_string()));
    }
    if kind.contains("javascript") || kind.contains("shell") || kind.contains("execution") {
        return Some((OutcomeType::CodeExecution, "Code execution".to_string()));
    }
    if let Some(value) = target {
        let lower = value.to_ascii_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") {
            return Some((OutcomeType::NetworkEgress, "Network egress".to_string()));
        }
    }
    None
}

fn confidence_to_score(confidence: crate::model::Confidence) -> u8 {
    match confidence {
        crate::model::Confidence::Certain => 95,
        crate::model::Confidence::Strong => 85,
        crate::model::Confidence::Probable => 72,
        crate::model::Confidence::Tentative => 55,
        crate::model::Confidence::Weak => 35,
        crate::model::Confidence::Heuristic => 45,
    }
}

fn parse_object_ref(value: &str) -> Option<(u32, u16)> {
    let clean = value.replace("obj", "");
    let tokens = clean
        .split(|ch: char| ch.is_whitespace() || ch == ':' || ch == ',' || ch == ';')
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    for window in tokens.windows(2) {
        let obj = window[0].parse::<u32>().ok();
        let gen = window[1].parse::<u16>().ok();
        if let (Some(obj), Some(gen)) = (obj, gen) {
            return Some((obj, gen));
        }
    }
    None
}

fn map_page_event(event: &str) -> EventType {
    match event {
        "/O" => EventType::PageOpen,
        "/C" => EventType::PageClose,
        "/PV" => EventType::PageVisible,
        "/PI" => EventType::PageInvisible,
        _ => EventType::PageOpen,
    }
}

fn map_field_event(event: &str) -> EventType {
    match event {
        "/K" => EventType::FieldKeystroke,
        "/F" => EventType::FieldFormat,
        "/V" => EventType::FieldValidate,
        "/C" => EventType::FieldCalculate,
        "/D" => EventType::FieldMouseDown,
        "/U" => EventType::FieldMouseUp,
        "/E" => EventType::FieldMouseEnter,
        "/X" => EventType::FieldMouseExit,
        "/Fo" => EventType::FieldOnFocus,
        "/Bl" => EventType::FieldOnBlur,
        _ => EventType::FieldActivation,
    }
}

fn map_additional_event(event: &str) -> EventType {
    match event {
        "/WC" => EventType::DocumentWillClose,
        "/WS" => EventType::DocumentWillSave,
        "/DS" => EventType::DocumentDidSave,
        "/WP" => EventType::DocumentWillPrint,
        "/DP" => EventType::DocumentDidPrint,
        "/K" => EventType::FieldKeystroke,
        "/V" => EventType::FieldValidate,
        _ => EventType::FieldActivation,
    }
}

fn mitre_techniques_for_event(event: EventType) -> Vec<String> {
    match event {
        EventType::DocumentOpen => vec!["T1204.002".to_string()],
        EventType::FieldActivation | EventType::AnnotationActivation => {
            vec!["T1204.001".to_string()]
        }
        EventType::NextAction => vec!["T1059.007".to_string()],
        _ => Vec::new(),
    }
}

fn mitre_techniques_for_outcome(outcome: OutcomeType) -> Vec<String> {
    match outcome {
        OutcomeType::NetworkEgress => vec!["T1071".to_string()],
        OutcomeType::ExternalLaunch => vec!["T1204.002".to_string()],
        OutcomeType::CodeExecution => vec!["T1059.007".to_string()],
        OutcomeType::FormSubmission => vec!["T1056.003".to_string()],
        OutcomeType::EmbeddedPayload => vec!["T1027.006".to_string()],
        OutcomeType::FilesystemWrite => vec!["T1565.001".to_string()],
    }
}

fn collapse_structure_only_nodes(
    nodes: &mut Vec<EventNode>,
    edges: &mut Vec<EventEdge>,
    object_node_type: &HashMap<EventNodeId, Option<String>>,
) {
    let event_or_outcome_node_ids = nodes
        .iter()
        .filter_map(|node| match node.kind {
            EventNodeKind::Event { .. } | EventNodeKind::Outcome { .. } => Some(node.id.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    if event_or_outcome_node_ids.is_empty() {
        return;
    }

    let mut active_objects = BTreeSet::<EventNodeId>::new();
    for edge in edges.iter() {
        if event_or_outcome_node_ids.contains(&edge.from) && object_node_type.contains_key(&edge.to)
        {
            active_objects.insert(edge.to.clone());
        }
        if event_or_outcome_node_ids.contains(&edge.to) && object_node_type.contains_key(&edge.from)
        {
            active_objects.insert(edge.from.clone());
        }
    }

    let passive_objects = nodes
        .iter()
        .filter_map(|node| match node.kind {
            EventNodeKind::Object { .. } if !active_objects.contains(&node.id) => {
                Some(node.id.clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if passive_objects.is_empty() {
        return;
    }

    let passive_set = passive_objects.iter().cloned().collect::<BTreeSet<_>>();
    let collapse_id = "collapse:0".to_string();
    nodes.push(EventNode {
        id: collapse_id.clone(),
        mitre_techniques: Vec::new(),
        kind: EventNodeKind::Collapse {
            label: "Collapsed structure".to_string(),
            member_count: passive_objects.len(),
            collapsed_members: passive_objects.clone(),
        },
    });

    let mut collapsed_edges = Vec::new();
    for edge in edges.iter() {
        let from_passive = passive_set.contains(&edge.from);
        let to_passive = passive_set.contains(&edge.to);
        match (from_passive, to_passive) {
            (true, false) => {
                collapsed_edges.push(EventEdge {
                    from: collapse_id.clone(),
                    to: edge.to.clone(),
                    kind: EventEdgeKind::CollapsedStructural,
                    provenance: EdgeProvenance::Heuristic,
                });
            }
            (false, true) => {
                collapsed_edges.push(EventEdge {
                    from: edge.from.clone(),
                    to: collapse_id.clone(),
                    kind: EventEdgeKind::CollapsedStructural,
                    provenance: EdgeProvenance::Heuristic,
                });
            }
            _ => {}
        }
    }

    nodes.retain(|node| !passive_set.contains(&node.id));
    edges.retain(|edge| !passive_set.contains(&edge.from) && !passive_set.contains(&edge.to));
    edges.extend(collapsed_edges);
}

fn dedup_edges(edges: &mut Vec<EventEdge>) {
    let mut seen = BTreeSet::<(String, String, EventEdgeKind)>::new();
    edges.retain(|edge| seen.insert((edge.from.clone(), edge.to.clone(), edge.kind)));
}

fn build_indices(nodes: Vec<EventNode>, edges: Vec<EventEdge>) -> EventGraph {
    let mut node_index = HashMap::new();
    for (idx, node) in nodes.iter().enumerate() {
        node_index.insert(node.id.clone(), idx);
    }
    let mut forward_index: HashMap<EventNodeId, Vec<usize>> = HashMap::new();
    let mut reverse_index: HashMap<EventNodeId, Vec<usize>> = HashMap::new();
    for (idx, edge) in edges.iter().enumerate() {
        forward_index.entry(edge.from.clone()).or_default().push(idx);
        reverse_index.entry(edge.to.clone()).or_default().push(idx);
    }
    EventGraph { schema_version: "1.0", nodes, edges, node_index, forward_index, reverse_index }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sis_pdf_pdf::graph::ObjectGraph;
    use sis_pdf_pdf::typed_graph::TypedEdge;

    fn test_typed_graph<'a>() -> TypedGraph<'a> {
        let graph = ObjectGraph {
            bytes: &[],
            objects: Vec::new(),
            index: HashMap::new(),
            trailers: Vec::new(),
            startxrefs: Vec::new(),
            xref_sections: Vec::new(),
            deviations: Vec::new(),
            telemetry_events: Vec::new(),
        };
        let edges = vec![
            TypedEdge::new((1, 0), (2, 0), EdgeType::OpenAction),
            TypedEdge::new((2, 0), (3, 0), EdgeType::NextAction),
            TypedEdge::new((3, 0), (4, 0), EdgeType::UriTarget),
        ];
        let mut forward_index = HashMap::new();
        forward_index.insert((1, 0), vec![0]);
        forward_index.insert((2, 0), vec![1]);
        forward_index.insert((3, 0), vec![2]);
        let mut reverse_index = HashMap::new();
        reverse_index.insert((2, 0), vec![0]);
        reverse_index.insert((3, 0), vec![1]);
        reverse_index.insert((4, 0), vec![2]);
        TypedGraph { graph: Box::leak(Box::new(graph)), edges, forward_index, reverse_index }
    }

    #[test]
    fn event_graph_contains_event_and_outcome_nodes() {
        let typed = test_typed_graph();
        let event_graph = build_event_graph(&typed, &[], EventGraphOptions::default());
        assert!(event_graph
            .nodes
            .iter()
            .any(|node| matches!(node.kind, EventNodeKind::Event { .. })));
        assert!(event_graph
            .nodes
            .iter()
            .any(|node| matches!(node.kind, EventNodeKind::Outcome { .. })));
    }

    #[test]
    fn event_graph_dot_contains_graph_header() {
        let typed = test_typed_graph();
        let event_graph = build_event_graph(&typed, &[], EventGraphOptions::default());
        let dot = export_event_graph_dot(&event_graph);
        assert!(dot.contains("digraph event_graph"));
    }
}
