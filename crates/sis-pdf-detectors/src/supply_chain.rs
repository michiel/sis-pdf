use anyhow::Result;
use std::collections::{BTreeSet, HashSet};

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::classification::ObjectRole;
use sis_pdf_pdf::typed_graph::{EdgeType, TypedEdge};

use crate::{entry_dict, js_payload_candidates_from_entry, JsPayloadSource};

pub struct SupplyChainDetector;

impl Detector for SupplyChainDetector {
    fn id(&self) -> &'static str {
        "supply_chain"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::Actions
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Moderate
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Build typed graph and get classifications
        let typed_graph = ctx.build_typed_graph();
        let classifications = ctx.classifications();

        // Find embedded files using classifications
        let mut embedded_names = Vec::new();
        for ((obj, gen), classified) in classifications.iter() {
            if classified.has_role(ObjectRole::EmbeddedFile) {
                if let Some(entry) = ctx.graph.get_object(*obj, *gen) {
                    if let Some(dict) = entry_dict(entry) {
                        if let Some(name) = filespec_name(dict) {
                            embedded_names.push(name);
                        }
                    }
                }
            }
        }
        let has_embedded = !embedded_names.is_empty();

        // Collect all action targets from typed graph edges
        let mut action_targets_global = HashSet::new();
        for edge in &typed_graph.edges {
            if let Some(target) = extract_action_target(edge) {
                action_targets_global.insert(target);
            }
        }

        let analyzer = sis_pdf_core::supply_chain::SupplyChainDetector;

        // Analyze each JavaScript payload (including javascript: URIs)
        for entry in &ctx.graph.objects {
            let candidates = js_payload_candidates_from_entry(ctx, entry);
            if candidates.is_empty() {
                continue;
            }

            // Collect action targets reachable from this object
            let mut local_action_targets = Vec::new();
            for edge in typed_graph.outgoing_edges(entry.obj, entry.gen) {
                if let Some(target) = extract_action_target(edge) {
                    local_action_targets.push(target);
                }
            }
            local_action_targets.sort();
            local_action_targets.dedup();

            let incoming = typed_graph.incoming_edges(entry.obj, entry.gen);
            let trigger_edges = incoming
                .iter()
                .filter(|edge| is_action_trigger_edge(edge))
                .map(|edge| edge.edge_type.as_str().to_string())
                .collect::<BTreeSet<_>>();
            let has_trigger_edges = !trigger_edges.is_empty();

            for candidate in candidates {
                let has_action_trigger =
                    has_trigger_edges || source_implies_action_trigger(candidate.source);
                let info = candidate.payload;
                let mut evidence = candidate.evidence;
                if evidence.is_empty() {
                    evidence.push(span_to_evidence(entry.full_span, "JavaScript dict"));
                }
                let js_fetch_targets = extract_js_fetch_targets(&info.bytes);
                let stage_fetch_targets =
                    merge_stage_fetch_targets(&local_action_targets, &js_fetch_targets);
                let stage_fetch_target_count = stage_fetch_targets.len();
                let has_execution_bridge =
                    has_embedded || has_action_trigger || !local_action_targets.is_empty();
                let execution_bridge_sources = collect_execution_bridge_sources(
                    has_embedded,
                    has_action_trigger,
                    &local_action_targets,
                );

                let staged = analyzer.detect_staged_payload(&info.bytes);
                let remote_template_signals = detect_remote_template_signals(&info.bytes);
                if !staged.is_empty() {
                    let indicators =
                        staged.iter().map(|s| s.indicator.clone()).collect::<Vec<_>>().join(",");
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("supply_chain.indicators".into(), indicators);
                    meta.insert("stage.count".into(), staged.len().to_string());
                    meta.insert(
                        "stage.sources".into(),
                        stage_sources("javascript", has_embedded, has_action_trigger, false),
                    );
                    meta.insert(
                        "stage.fetch_targets".into(),
                        if !stage_fetch_targets.is_empty() {
                            stage_fetch_targets.join(",")
                        } else {
                            "unknown".into()
                        },
                    );
                    meta.insert(
                        "stage.fetch_target_count".into(),
                        stage_fetch_target_count.to_string(),
                    );
                    meta.insert(
                        "stage.execution_bridge".into(),
                        if has_execution_bridge { "true" } else { "false" }.into(),
                    );
                    meta.insert(
                        "stage.execution_bridge_source".into(),
                        if execution_bridge_sources.is_empty() {
                            "none".into()
                        } else {
                            execution_bridge_sources.join(",")
                        },
                    );
                    if !trigger_edges.is_empty() {
                        meta.insert(
                            "stage.trigger_edges".into(),
                            trigger_edges.iter().cloned().collect::<Vec<_>>().join(","),
                        );
                    }
                    if has_embedded {
                        meta.insert("supply_chain.embedded_present".into(), "true".into());
                    }
                    if !embedded_names.is_empty() {
                        meta.insert("supply_chain.embedded_names".into(), embedded_names.join(","));
                    }
                    if !local_action_targets.is_empty() {
                        meta.insert(
                            "supply_chain.action_targets".into(),
                            local_action_targets.join(","),
                        );
                    }
                    if !js_fetch_targets.is_empty() {
                        meta.insert(
                            "supply_chain.js_fetch_targets".into(),
                            js_fetch_targets.join(","),
                        );
                    }
                    if let Some(label) = candidate.source.meta_value() {
                        meta.insert("js.source".into(), label.into());
                    }
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "supply_chain_staged_payload".into(),
                        severity: if has_execution_bridge {
                            Severity::High
                        } else {
                            Severity::Medium
                        },
                        confidence: Confidence::Probable,
                        impact: None,
                        title: "Staged payload delivery".into(),
                        description: "JavaScript indicates download or staged payload execution."
                            .into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: evidence.clone(),
                        remediation: Some("Inspect outbound URLs and staged payloads.".into()),
                        meta,
                        yara: None,
                        positions: Vec::new(),
                        ..Finding::default()
                    });
                }

                if !remote_template_signals.is_empty() {
                    let mut meta = std::collections::HashMap::new();
                    meta.insert(
                        "stage.sources".into(),
                        stage_sources("javascript", has_embedded, has_action_trigger, true),
                    );
                    meta.insert(
                        "stage.fetch_targets".into(),
                        if !stage_fetch_targets.is_empty() {
                            stage_fetch_targets.join(",")
                        } else {
                            "unknown".into()
                        },
                    );
                    meta.insert(
                        "stage.fetch_target_count".into(),
                        stage_fetch_target_count.to_string(),
                    );
                    meta.insert("stage.count".into(), "1".into());
                    meta.insert("stage.execution_bridge".into(), "false".into());
                    meta.insert(
                        "stage.execution_bridge_source".into(),
                        if execution_bridge_sources.is_empty() {
                            "none".into()
                        } else {
                            execution_bridge_sources.join(",")
                        },
                    );
                    if !trigger_edges.is_empty() {
                        meta.insert(
                            "stage.trigger_edges".into(),
                            trigger_edges.iter().cloned().collect::<Vec<_>>().join(","),
                        );
                    }
                    meta.insert(
                        "stage.remote_template_indicators".into(),
                        remote_template_signals.join(","),
                    );
                    if !js_fetch_targets.is_empty() {
                        meta.insert(
                            "supply_chain.js_fetch_targets".into(),
                            js_fetch_targets.join(","),
                        );
                    }
                    if let Some(label) = candidate.source.meta_value() {
                        meta.insert("js.source".into(), label.into());
                    }
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "staged_remote_template_fetch_unresolved".into(),
                        severity: if has_action_trigger { Severity::Medium } else { Severity::Low },
                        confidence: if has_action_trigger || remote_template_signals.len() > 1 {
                            Confidence::Strong
                        } else {
                            Confidence::Probable
                        },
                        impact: None,
                        title: "Staged remote template fetch (unresolved bridge)".into(),
                        description: "JavaScript indicates remote template or form-fetch behaviour, but a concrete execution bridge is not yet resolved.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: evidence.clone(),
                        remediation: Some("Correlate template fetch signals with launch/open triggers and downstream execution pathways.".into()),
                        meta,
                        yara: None,
                        positions: Vec::new(),
                        ..Finding::default()
                    });
                }

                let updates = analyzer.analyze_update_mechanisms(&info.bytes);
                if !updates.is_empty() {
                    let indicators =
                        updates.iter().map(|s| s.indicator.clone()).collect::<Vec<_>>().join(",");
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("supply_chain.update_indicators".into(), indicators);
                    if !embedded_names.is_empty() {
                        meta.insert("supply_chain.embedded_names".into(), embedded_names.join(","));
                    }
                    if !local_action_targets.is_empty() {
                        meta.insert(
                            "supply_chain.action_targets".into(),
                            local_action_targets.join(","),
                        );
                    }
                    if let Some(label) = candidate.source.meta_value() {
                        meta.insert("js.source".into(), label.into());
                    }
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "supply_chain_update_vector".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Heuristic,
                        impact: None,
                        title: "Update mechanism references".into(),
                        description: "JavaScript references update or installer logic.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: evidence.clone(),
                        remediation: Some("Verify update channels and signing policies.".into()),
                        meta,
                        yara: None,
                        positions: Vec::new(),
                        ..Finding::default()
                    });
                }

                let persistence = analyzer.check_persistence_methods(&info.bytes);
                if !persistence.is_empty() {
                    let indicators = persistence
                        .iter()
                        .map(|s| s.indicator.clone())
                        .collect::<Vec<_>>()
                        .join(",");
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("supply_chain.persistence_indicators".into(), indicators);
                    if !embedded_names.is_empty() {
                        meta.insert("supply_chain.embedded_names".into(), embedded_names.join(","));
                    }
                    if !local_action_targets.is_empty() {
                        meta.insert(
                            "supply_chain.action_targets".into(),
                            local_action_targets.join(","),
                        );
                    }
                    if let Some(label) = candidate.source.meta_value() {
                        meta.insert("js.source".into(), label.into());
                    }
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "supply_chain_persistence".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Probable,
                        impact: None,
                        title: "Persistence-related JavaScript".into(),
                        description: "JavaScript references persistence-like viewer hooks.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: evidence.clone(),
                        remediation: Some("Review persistence-related APIs and triggers.".into()),
                        meta,
                        yara: None,
                        positions: Vec::new(),
                        ..Finding::default()
                    });
                }
            }
        }

        // If no JS findings but we have action targets, report that
        if findings.is_empty() && !action_targets_global.is_empty() {
            let targets_vec: Vec<String> = action_targets_global.into_iter().collect();
            let mut meta = std::collections::HashMap::new();
            meta.insert("supply_chain.action_targets".into(), targets_vec.join(","));
            meta.insert("stage.sources".into(), "action_targets".into());
            meta.insert("stage.count".into(), "1".into());
            meta.insert("stage.fetch_targets".into(), targets_vec.join(","));
            meta.insert("stage.fetch_target_count".into(), targets_vec.len().to_string());
            meta.insert("stage.execution_bridge".into(), "false".into());
            meta.insert("stage.execution_bridge_source".into(), "action_targets".into());
            if !embedded_names.is_empty() {
                meta.insert("supply_chain.embedded_names".into(), embedded_names.join(","));
            }
            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "supply_chain_staged_payload".into(),
                severity: Severity::Medium,
                confidence: Confidence::Heuristic,
                impact: None,
                title: "Action targets indicate staged payloads".into(),
                description: "Action targets reference external resources or files without JavaScript payloads.".into(),
                objects: vec!["action_targets".into()],
                evidence: Vec::new(),
                remediation: Some("Inspect action targets and embedded files.".into()),
                meta,
                yara: None,
                positions: Vec::new(),
                ..Finding::default()
            });
        }
        Ok(findings)
    }
}

fn filespec_name(dict: &sis_pdf_pdf::object::PdfDict<'_>) -> Option<String> {
    for key in [b"/F".as_slice(), b"/UF".as_slice()] {
        if let Some((_, obj)) = dict.get_first(key) {
            if let sis_pdf_pdf::object::PdfAtom::Str(s) = &obj.atom {
                let bytes = match s {
                    sis_pdf_pdf::object::PdfStr::Literal { decoded, .. } => decoded.clone(),
                    sis_pdf_pdf::object::PdfStr::Hex { decoded, .. } => decoded.clone(),
                };
                return Some(String::from_utf8_lossy(&bytes).to_string());
            }
        }
    }
    None
}

/// Extract action target from a typed graph edge
fn extract_action_target(edge: &sis_pdf_pdf::typed_graph::TypedEdge) -> Option<String> {
    match &edge.edge_type {
        EdgeType::UriTarget => Some(format!("URI:{:?}", edge.dst)),
        EdgeType::LaunchTarget => Some(format!("Launch:{:?}", edge.dst)),
        EdgeType::GoToRTarget => Some(format!("GoToR:{:?}", edge.dst)),
        EdgeType::SubmitFormTarget => Some(format!("SubmitForm:{:?}", edge.dst)),
        _ => None,
    }
}

fn detect_remote_template_signals(bytes: &[u8]) -> Vec<String> {
    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let mut out = Vec::new();
    for needle in ["template", ".xdp", ".xfdf", ".xfa", "stylesheet", "xfa.host"] {
        if lower.contains(needle) {
            out.push(needle.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

fn is_action_trigger_edge(edge: &TypedEdge) -> bool {
    matches!(
        edge.edge_type,
        EdgeType::OpenAction
            | EdgeType::AnnotationAction
            | EdgeType::AdditionalAction { .. }
            | EdgeType::PageAction { .. }
            | EdgeType::FormFieldAction { .. }
            | EdgeType::NextAction
    ) || matches!(&edge.edge_type, EdgeType::DictReference { key } if key == "/Next")
}

fn extract_js_fetch_targets(bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    for token in text.split(['"', '\'', ' ', '\n', '\r', '\t', '(', ')', '[', ']', ',', ';']) {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("smb://")
            || lower.starts_with("file://")
            || lower.starts_with("\\\\")
        {
            out.push(trimmed.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

fn merge_stage_fetch_targets(
    action_targets: &[String],
    js_fetch_targets: &[String],
) -> Vec<String> {
    let mut merged = BTreeSet::new();
    for target in action_targets {
        merged.insert(target.clone());
    }
    for target in js_fetch_targets {
        merged.insert(target.clone());
    }
    merged.into_iter().collect()
}

fn collect_execution_bridge_sources(
    has_embedded: bool,
    has_action_trigger: bool,
    action_targets: &[String],
) -> Vec<String> {
    let mut sources = BTreeSet::new();
    if has_embedded {
        sources.insert("embedded_file".to_string());
    }
    if has_action_trigger {
        sources.insert("action_trigger".to_string());
    }
    if !action_targets.is_empty() {
        sources.insert("action_target".to_string());
    }
    sources.into_iter().collect()
}

fn stage_sources(
    primary: &str,
    has_embedded: bool,
    has_action_trigger: bool,
    include_remote_template_hint: bool,
) -> String {
    let mut out = BTreeSet::new();
    out.insert(primary.to_string());
    if has_embedded {
        out.insert("embedded-file".into());
    }
    if has_action_trigger {
        out.insert("action-trigger".into());
    }
    if include_remote_template_hint {
        out.insert("remote-template-hint".into());
    }
    out.into_iter().collect::<Vec<_>>().join(",")
}

fn source_implies_action_trigger(source: JsPayloadSource) -> bool {
    matches!(
        source,
        JsPayloadSource::OpenAction | JsPayloadSource::AaEvent | JsPayloadSource::AnnotationAction
    )
}

#[cfg(test)]
mod tests {
    use super::{
        collect_execution_bridge_sources, extract_js_fetch_targets, is_action_trigger_edge,
        merge_stage_fetch_targets, source_implies_action_trigger, stage_sources,
    };
    use crate::JsPayloadSource;
    use sis_pdf_pdf::typed_graph::{EdgeType, TypedEdge};

    #[test]
    fn extracts_js_fetch_targets_for_common_protocols() {
        let bytes =
            br#"var a="https://a.example/a"; var b='smb://corp-fs/share/p'; var c="file://tmp/a";"#;
        let targets = extract_js_fetch_targets(bytes);
        assert!(targets.iter().any(|value| value.starts_with("https://")));
        assert!(targets.iter().any(|value| value.starts_with("smb://")));
        assert!(targets.iter().any(|value| value.starts_with("file://")));
    }

    #[test]
    fn merges_stage_targets_deduplicated() {
        let merged = merge_stage_fetch_targets(
            &["Launch:(2, 0)".into(), "https://a.example/a".into()],
            &["https://a.example/a".into(), "smb://corp-fs/share/p".into()],
        );
        assert_eq!(merged.len(), 3);
    }

    #[test]
    fn execution_bridge_sources_are_reported_stably() {
        let sources = collect_execution_bridge_sources(true, true, &["Launch:(2, 0)".into()]);
        assert_eq!(sources.join(","), "action_target,action_trigger,embedded_file");
        assert_eq!(
            stage_sources("javascript", true, true, true),
            "action-trigger,embedded-file,javascript,remote-template-hint"
        );
    }

    #[test]
    fn action_trigger_edge_accepts_next_action_variant() {
        let edge = TypedEdge::new((1, 0), (2, 0), EdgeType::NextAction);
        assert!(is_action_trigger_edge(&edge));
    }

    #[test]
    fn trigger_capable_sources_are_detected() {
        assert!(source_implies_action_trigger(JsPayloadSource::OpenAction));
        assert!(source_implies_action_trigger(JsPayloadSource::AaEvent));
        assert!(source_implies_action_trigger(JsPayloadSource::AnnotationAction));
        assert!(!source_implies_action_trigger(JsPayloadSource::Action));
        assert!(!source_implies_action_trigger(JsPayloadSource::CatalogJs));
    }
}
