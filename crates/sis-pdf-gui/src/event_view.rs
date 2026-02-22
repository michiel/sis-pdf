use crate::analysis::AnalysisResult;
use sis_pdf_core::event_graph::EventGraph;
use sis_pdf_core::event_projection::{extract_event_records, EventOutcomeRecord, EventRecord};
use sis_pdf_core::model::Finding;
use sis_pdf_pdf::{parse_pdf, ParseOptions};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct OutcomeDetail {
    pub node_id: String,
    pub outcome_type: String,
    pub label: String,
    pub confidence_score: Option<u8>,
    pub severity_hint: Option<String>,
    pub evidence: Vec<String>,
    pub source_obj: Option<(u32, u16)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ExecuteTargetDetail {
    pub node_id: String,
    pub object_ref: Option<(u32, u16)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct EventViewModel {
    pub node_id: String,
    pub event_type: String,
    /// Human-readable label set by the EventGraph builder (e.g. "Page 3 content stream exec").
    pub label: String,
    pub trigger_class: String,
    pub source_object: Option<(u32, u16)>,
    pub execute_targets: Vec<ExecuteTargetDetail>,
    pub outcome_targets: Vec<OutcomeDetail>,
    pub linked_finding_ids: Vec<String>,
    pub event_key: Option<String>,
    pub initiation: Option<String>,
    pub branch_index: Option<u32>,
    /// MITRE ATT&CK technique IDs associated with this event node.
    pub mitre_techniques: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnmappedFindingEventSignal {
    pub finding_id: String,
    /// Index of this finding in the report's findings slice, for navigation.
    pub finding_idx: usize,
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

fn map_outcome(outcome: EventOutcomeRecord) -> OutcomeDetail {
    OutcomeDetail {
        node_id: outcome.node_id,
        outcome_type: outcome.outcome_type,
        label: outcome.label,
        confidence_score: outcome.confidence_score,
        severity_hint: outcome.severity_hint,
        evidence: outcome.evidence,
        source_obj: outcome.source_object,
    }
}

pub fn map_event_record_to_view(record: EventRecord) -> EventViewModel {
    EventViewModel {
        node_id: record.node_id,
        event_type: record.event_type,
        label: record.label,
        trigger_class: record.trigger_class,
        source_object: record.source_object,
        execute_targets: record
            .execute_targets
            .into_iter()
            .map(|target| ExecuteTargetDetail {
                node_id: target.node_id,
                object_ref: target.object_ref,
            })
            .collect(),
        outcome_targets: record.outcome_targets.into_iter().map(map_outcome).collect(),
        linked_finding_ids: record.linked_finding_ids,
        event_key: record.event_key,
        initiation: record.initiation,
        branch_index: record.branch_index,
        mitre_techniques: record.mitre_techniques,
    }
}

pub fn extract_event_view_models(event_graph: &EventGraph) -> Vec<EventViewModel> {
    extract_event_records(event_graph).into_iter().map(map_event_record_to_view).collect()
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
        .enumerate()
        .filter(|(_, finding)| finding_has_event_signal(finding))
        .filter(|(_, finding)| !linked_finding_ids.contains(&finding.id))
        .map(|(idx, finding)| UnmappedFindingEventSignal {
            finding_id: finding.id.clone(),
            finding_idx: idx,
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
        EdgeMetadata, EdgeProvenance, EventEdge, EventEdgeKind, EventNode, EventNodeKind,
        EventType, OutcomeType, TriggerClass,
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
    fn extract_event_view_models_filters_non_event_nodes_and_sorts_stably() {
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
                        source_obj: Some((2, 0)),
                    },
                },
                EventNode {
                    id: "ev:a".to_string(),
                    mitre_techniques: Vec::new(),
                    kind: EventNodeKind::Event {
                        event_type: EventType::ContentStreamExec,
                        trigger: TriggerClass::Automatic,
                        label: "A".to_string(),
                        source_obj: Some((1, 0)),
                    },
                },
            ],
            Vec::new(),
        );
        let events = extract_event_view_models(&graph);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].node_id, "ev:a");
        assert_eq!(events[1].node_id, "ev:b");
    }

    #[test]
    fn extract_event_view_models_resolves_execute_and_outcome_details() {
        let graph = make_graph(
            vec![
                EventNode {
                    id: "ev:1".to_string(),
                    mitre_techniques: vec!["T1204".to_string()],
                    kind: EventNodeKind::Event {
                        event_type: EventType::ContentStreamExec,
                        trigger: TriggerClass::Automatic,
                        label: "content stream".to_string(),
                        source_obj: Some((3, 0)),
                    },
                },
                EventNode {
                    id: "obj:7:0".to_string(),
                    mitre_techniques: Vec::new(),
                    kind: EventNodeKind::Object { obj: 7, gen: 0, obj_type: None },
                },
                EventNode {
                    id: "out:1".to_string(),
                    mitre_techniques: Vec::new(),
                    kind: EventNodeKind::Outcome {
                        outcome_type: OutcomeType::NetworkEgress,
                        label: "egress".to_string(),
                        target: Some("https://x.example".to_string()),
                        source_obj: Some((9, 0)),
                        evidence: vec!["network".to_string()],
                        confidence_source: None,
                        confidence_score: Some(92),
                        severity_hint: Some("high".to_string()),
                    },
                },
            ],
            vec![
                EventEdge {
                    from: "ev:1".to_string(),
                    to: "obj:7:0".to_string(),
                    kind: EventEdgeKind::Executes,
                    provenance: EdgeProvenance::Heuristic,
                    metadata: Some(EdgeMetadata {
                        event_key: Some("/OpenAction".to_string()),
                        branch_index: Some(1),
                        initiation: Some("automatic".to_string()),
                    }),
                },
                EventEdge {
                    from: "ev:1".to_string(),
                    to: "out:1".to_string(),
                    kind: EventEdgeKind::ProducesOutcome,
                    provenance: EdgeProvenance::Finding { finding_id: "f-9".to_string() },
                    metadata: None,
                },
            ],
        );
        let events = extract_event_view_models(&graph);
        assert_eq!(events[0].execute_targets[0].object_ref, Some((7, 0)));
        assert_eq!(events[0].outcome_targets[0].outcome_type, "NetworkEgress");
        assert_eq!(events[0].outcome_targets[0].confidence_score, Some(92));
        assert_eq!(events[0].event_key.as_deref(), Some("/OpenAction"));
        assert_eq!(events[0].linked_finding_ids, vec!["f-9".to_string()]);
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
            linked_finding_ids: vec!["f-2".to_string()],
            ..EventViewModel::default()
        };
        let unmapped = collect_unmapped_finding_event_signals(&[finding], &[linked]);
        assert_eq!(unmapped.len(), 1);
        assert_eq!(unmapped[0].finding_id, "f-1");
    }
}
