use crate::analysis::AnalysisResult;
use sis_pdf_core::event_graph::{EdgeProvenance, EventGraph, EventNodeKind};
use sis_pdf_core::model::Finding;
use sis_pdf_pdf::{parse_pdf, ParseOptions};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventViewModel {
    pub node_id: String,
    pub event_type: String,
    pub trigger_class: String,
    pub source_object: Option<(u32, u16)>,
    pub execute_targets: Vec<String>,
    pub outcome_targets: Vec<String>,
    pub linked_finding_ids: Vec<String>,
    pub event_key: Option<String>,
    pub initiation: Option<String>,
    pub branch_index: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnmappedFindingEventSignal {
    pub finding_id: String,
    pub kind: String,
    pub title: String,
}

pub fn build_event_graph_for_result(result: &AnalysisResult) -> Result<EventGraph, String> {
    let parse_options = ParseOptions {
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
    let graph = parse_pdf(&result.bytes, parse_options).map_err(|err| err.to_string())?;
    let classifications = graph.classify_objects();
    let typed_graph = sis_pdf_pdf::typed_graph::TypedGraph::build(&graph, &classifications);
    Ok(sis_pdf_core::event_graph::build_event_graph(
        &typed_graph,
        &result.report.findings,
        sis_pdf_core::event_graph::EventGraphOptions::default(),
    ))
}

pub fn extract_event_view_models(event_graph: &EventGraph) -> Vec<EventViewModel> {
    let mut event_rows: BTreeMap<String, EventViewModel> = BTreeMap::new();
    let mut finding_ids_by_node: HashMap<String, BTreeSet<String>> = HashMap::new();
    for edge in &event_graph.edges {
        if let EdgeProvenance::Finding { finding_id } = &edge.provenance {
            finding_ids_by_node.entry(edge.from.clone()).or_default().insert(finding_id.clone());
            finding_ids_by_node.entry(edge.to.clone()).or_default().insert(finding_id.clone());
        }
    }

    for node in &event_graph.nodes {
        let EventNodeKind::Event { event_type, trigger, source_obj, .. } = &node.kind else {
            continue;
        };
        let mut execute_targets = Vec::new();
        let mut outcome_targets = Vec::new();
        let mut event_key = None;
        let mut initiation = None;
        let mut branch_index = None;

        if let Some(forward) = event_graph.forward_index.get(&node.id) {
            for edge_idx in forward {
                if let Some(edge) = event_graph.edges.get(*edge_idx) {
                    match edge.kind {
                        sis_pdf_core::event_graph::EventEdgeKind::Executes => {
                            execute_targets.push(edge.to.clone());
                        }
                        sis_pdf_core::event_graph::EventEdgeKind::ProducesOutcome => {
                            outcome_targets.push(edge.to.clone());
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
        }

        execute_targets.sort();
        execute_targets.dedup();
        outcome_targets.sort();
        outcome_targets.dedup();
        let linked_finding_ids = finding_ids_by_node
            .get(&node.id)
            .map(|values| values.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        event_rows.insert(
            node.id.clone(),
            EventViewModel {
                node_id: node.id.clone(),
                event_type: format!("{event_type:?}"),
                trigger_class: trigger.as_str().to_string(),
                source_object: *source_obj,
                execute_targets,
                outcome_targets,
                linked_finding_ids,
                event_key,
                initiation,
                branch_index,
            },
        );
    }

    event_rows.into_values().collect()
}

pub fn collect_unmapped_finding_event_signals(
    findings: &[Finding],
    events: &[EventViewModel],
) -> Vec<UnmappedFindingEventSignal> {
    let linked_finding_ids = events
        .iter()
        .flat_map(|event| event.linked_finding_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    findings
        .iter()
        .filter(|finding| finding_has_event_signal(finding))
        .filter(|finding| !linked_finding_ids.contains(&finding.id))
        .map(|finding| UnmappedFindingEventSignal {
            finding_id: finding.id.clone(),
            kind: finding.kind.clone(),
            title: finding.title.clone(),
        })
        .collect()
}

pub fn finding_has_event_signal(finding: &Finding) -> bool {
    finding.meta.contains_key("action.trigger_event_normalised")
        || finding.meta.contains_key("action.trigger_event")
        || finding.meta.contains_key("action.event_key")
        || finding.meta.contains_key("action.trigger_type")
        || finding.meta.contains_key("action.trigger_context")
        || finding.meta.contains_key("action.trigger_surface")
        || finding.meta.contains_key("action.initiation")
        || finding.meta.contains_key("annot.trigger_context")
        || finding.action_initiation.is_some()
        || finding.action_type.is_some()
        || finding.action_target.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sis_pdf_core::event_graph::{
        EdgeProvenance, EventEdge, EventEdgeKind, EventNode, EventType, TriggerClass,
    };
    use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
    use std::collections::HashMap;

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
    fn extract_event_view_models_filters_non_event_nodes_and_sorts_by_node_id() {
        let graph = make_graph(
            vec![
                EventNode {
                    id: "obj:1:0".to_string(),
                    mitre_techniques: Vec::new(),
                    kind: EventNodeKind::Object { obj: 1, gen: 0, obj_type: None },
                },
                EventNode {
                    id: "ev:b".to_string(),
                    mitre_techniques: Vec::new(),
                    kind: EventNodeKind::Event {
                        event_type: EventType::JsTimerDelayed,
                        trigger: TriggerClass::Hidden,
                        label: "B".to_string(),
                        source_obj: Some((1, 0)),
                    },
                },
                EventNode {
                    id: "ev:a".to_string(),
                    mitre_techniques: Vec::new(),
                    kind: EventNodeKind::Event {
                        event_type: EventType::ContentStreamExec,
                        trigger: TriggerClass::Automatic,
                        label: "A".to_string(),
                        source_obj: Some((2, 0)),
                    },
                },
            ],
            Vec::new(),
        );
        let events = extract_event_view_models(&graph);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].node_id, "ev:a");
        assert_eq!(events[0].event_type, "ContentStreamExec");
        assert_eq!(events[1].node_id, "ev:b");
    }

    #[test]
    fn collect_unmapped_finding_event_signals_returns_only_unlinked_signals() {
        let finding = Finding {
            id: "f-1".to_string(),
            surface: AttackSurface::Actions,
            kind: "action_automatic_trigger".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Strong,
            title: "Trigger".to_string(),
            description: "desc".to_string(),
            meta: HashMap::from([("action.trigger_event".to_string(), "OpenAction".to_string())]),
            ..Finding::default()
        };
        let linked = EventViewModel {
            node_id: "ev:1".to_string(),
            event_type: "DocumentOpen".to_string(),
            trigger_class: "automatic".to_string(),
            source_object: Some((1, 0)),
            execute_targets: Vec::new(),
            outcome_targets: Vec::new(),
            linked_finding_ids: vec!["f-2".to_string()],
            event_key: None,
            initiation: None,
            branch_index: None,
        };
        let unmapped = collect_unmapped_finding_event_signals(&[finding], &[linked]);
        assert_eq!(unmapped.len(), 1);
        assert_eq!(unmapped[0].finding_id, "f-1");
    }

    #[test]
    fn extract_event_view_models_collects_provenance_finding_links() {
        let graph = make_graph(
            vec![
                EventNode {
                    id: "ev:1".to_string(),
                    mitre_techniques: Vec::new(),
                    kind: EventNodeKind::Event {
                        event_type: EventType::DocumentOpen,
                        trigger: TriggerClass::Automatic,
                        label: "open".to_string(),
                        source_obj: Some((1, 0)),
                    },
                },
                EventNode {
                    id: "obj:2:0".to_string(),
                    mitre_techniques: Vec::new(),
                    kind: EventNodeKind::Object { obj: 2, gen: 0, obj_type: None },
                },
            ],
            vec![EventEdge {
                from: "ev:1".to_string(),
                to: "obj:2:0".to_string(),
                kind: EventEdgeKind::Executes,
                provenance: EdgeProvenance::Finding { finding_id: "f-9".to_string() },
                metadata: None,
            }],
        );
        let events = extract_event_view_models(&graph);
        assert_eq!(events[0].linked_finding_ids, vec!["f-9".to_string()]);
    }
}
