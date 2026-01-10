use anyhow::Result;
use std::collections::HashSet;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::classification::ObjectRole;
use sis_pdf_pdf::typed_graph::EdgeType;

use crate::{entry_dict, resolve_payload};

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

        // Find all JavaScript objects via typed graph edges
        let mut js_objects = HashSet::new();
        for edge in &typed_graph.edges {
            if matches!(edge.edge_type, EdgeType::JavaScriptPayload) {
                js_objects.insert(edge.dst);
            }
        }

        // Analyze each JavaScript object
        for (obj, gen) in js_objects {
            let Some(entry) = ctx.graph.get_object(obj, gen) else { continue };
            let Some(dict) = entry_dict(entry) else { continue };
            let Some((_, js_obj)) = dict.get_first(b"/JS") else { continue };

            let payload = resolve_payload(ctx, js_obj);
            let Some(info) = payload.payload else { continue };

            // Collect action targets reachable from this JS object
            let mut local_action_targets = Vec::new();
            for edge in typed_graph.outgoing_edges(obj, gen) {
                if let Some(target) = extract_action_target(edge) {
                    local_action_targets.push(target);
                }
            }

            let staged = analyzer.detect_staged_payload(&info.bytes);
            if !staged.is_empty() {
                let indicators = staged
                    .iter()
                    .map(|s| s.indicator.clone())
                    .collect::<Vec<_>>()
                    .join(",");
                let mut meta = std::collections::HashMap::new();
                meta.insert("supply_chain.indicators".into(), indicators);
                if has_embedded {
                    meta.insert("supply_chain.embedded_present".into(), "true".into());
                }
                if !embedded_names.is_empty() {
                    meta.insert("supply_chain.embedded_names".into(), embedded_names.join(","));
                }
                if !local_action_targets.is_empty() {
                    meta.insert("supply_chain.action_targets".into(), local_action_targets.join(","));
                }
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "supply_chain_staged_payload".into(),
                    severity: Severity::High,
                    confidence: Confidence::Probable,
                    title: "Staged payload delivery".into(),
                    description: "JavaScript indicates download or staged payload execution.".into(),
                    objects: vec![format!("{} {} obj", obj, gen)],
                    evidence: vec![span_to_evidence(entry.full_span, "JavaScript dict")],
                    remediation: Some("Inspect outbound URLs and staged payloads.".into()),
                    meta,
                    yara: None,
        position: None,
        positions: Vec::new(),
                });
            }

            let updates = analyzer.analyze_update_mechanisms(&info.bytes);
            if !updates.is_empty() {
                let indicators = updates
                    .iter()
                    .map(|s| s.indicator.clone())
                    .collect::<Vec<_>>()
                    .join(",");
                let mut meta = std::collections::HashMap::new();
                meta.insert("supply_chain.update_indicators".into(), indicators);
                if !embedded_names.is_empty() {
                    meta.insert("supply_chain.embedded_names".into(), embedded_names.join(","));
                }
                if !local_action_targets.is_empty() {
                    meta.insert("supply_chain.action_targets".into(), local_action_targets.join(","));
                }
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "supply_chain_update_vector".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Heuristic,
                    title: "Update mechanism references".into(),
                    description: "JavaScript references update or installer logic.".into(),
                    objects: vec![format!("{} {} obj", obj, gen)],
                    evidence: vec![span_to_evidence(entry.full_span, "JavaScript dict")],
                    remediation: Some("Verify update channels and signing policies.".into()),
                    meta,
                    yara: None,
        position: None,
        positions: Vec::new(),
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
                    meta.insert("supply_chain.action_targets".into(), local_action_targets.join(","));
                }
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "supply_chain_persistence".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    title: "Persistence-related JavaScript".into(),
                    description: "JavaScript references persistence-like viewer hooks.".into(),
                    objects: vec![format!("{} {} obj", obj, gen)],
                    evidence: vec![span_to_evidence(entry.full_span, "JavaScript dict")],
                    remediation: Some("Review persistence-related APIs and triggers.".into()),
                    meta,
                    yara: None,
        position: None,
        positions: Vec::new(),
                });
            }
        }

        // If no JS findings but we have action targets, report that
        if findings.is_empty() && !action_targets_global.is_empty() {
            let targets_vec: Vec<String> = action_targets_global.into_iter().collect();
            let mut meta = std::collections::HashMap::new();
            meta.insert(
                "supply_chain.action_targets".into(),
                targets_vec.join(","),
            );
            if !embedded_names.is_empty() {
                meta.insert("supply_chain.embedded_names".into(), embedded_names.join(","));
            }
            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "supply_chain_staged_payload".into(),
                severity: Severity::Medium,
                confidence: Confidence::Heuristic,
                title: "Action targets indicate staged payloads".into(),
                description: "Action targets reference external resources or files without JavaScript payloads.".into(),
                objects: vec!["action_targets".into()],
                evidence: Vec::new(),
                remediation: Some("Inspect action targets and embedded files.".into()),
                meta,
                yara: None,
        position: None,
        positions: Vec::new(),
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
