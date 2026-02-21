use anyhow::Result;
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_pdf::classification::ObjectRole;
use sis_pdf_pdf::object::PdfAtom;
use sis_pdf_pdf::typed_graph::EdgeType;
use std::collections::BTreeSet;

use crate::entry_dict;

pub struct RendererDivergenceDetector;

impl Detector for RendererDivergenceDetector {
    fn id(&self) -> &'static str {
        "renderer_divergence"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::FileStructure
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Cheap
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let typed_graph = ctx.build_typed_graph();
        let classifications = ctx.classifications();

        let has_open_action =
            typed_graph.edges.iter().any(|edge| matches!(edge.edge_type, EdgeType::OpenAction));
        let has_additional_action = typed_graph
            .edges
            .iter()
            .any(|edge| matches!(edge.edge_type, EdgeType::AdditionalAction { .. }));
        let has_page_or_field_action = typed_graph.edges.iter().any(|edge| {
            matches!(edge.edge_type, EdgeType::PageAction { .. } | EdgeType::FormFieldAction { .. })
        });
        let has_launch =
            typed_graph.edges.iter().any(|edge| matches!(edge.edge_type, EdgeType::LaunchTarget));
        let has_external_action = typed_graph.edges.iter().any(|edge| {
            matches!(
                edge.edge_type,
                EdgeType::UriTarget | EdgeType::SubmitFormTarget | EdgeType::GoToRTarget
            )
        });
        let has_xfa =
            typed_graph.edges.iter().any(|edge| matches!(edge.edge_type, EdgeType::XfaReference));
        let has_richmedia = typed_graph.edges.iter().any(|edge| {
            matches!(
                edge.edge_type,
                EdgeType::RichMediaRef
                    | EdgeType::ThreeDRef
                    | EdgeType::MovieRef
                    | EdgeType::SoundRef
            )
        });
        let has_embedded = classifications
            .iter()
            .any(|(_, classified)| classified.has_role(ObjectRole::EmbeddedFile));
        let has_js_edge = typed_graph.edges.iter().any(|edge| {
            matches!(edge.edge_type, EdgeType::JavaScriptPayload | EdgeType::JavaScriptNames)
        });
        let has_inline_js = ctx.graph.objects.iter().any(|entry| {
            let Some(dict) = entry_dict(entry) else {
                return false;
            };
            dict.get_first(b"/JS").is_some() || dict.get_first(b"/JavaScript").is_some()
        });
        let has_js = has_js_edge || has_inline_js;

        let mut known_paths = BTreeSet::new();
        let action_handling_path =
            has_open_action || has_additional_action || has_page_or_field_action;
        let js_execution_policy_path = has_js && action_handling_path;
        let attachment_open_behavior_path =
            has_embedded && (has_launch || has_open_action || has_additional_action);
        let renderer_family_count = usize::from(action_handling_path)
            + usize::from(js_execution_policy_path)
            + usize::from(attachment_open_behavior_path);

        if has_open_action && has_js {
            known_paths.insert("open_action_js_path".to_string());
        }
        if has_launch {
            known_paths.insert("launch_action_path".to_string());
        }
        if has_xfa
            && (has_js || has_open_action || has_additional_action || has_page_or_field_action)
        {
            known_paths.insert("xfa_interactive_path".to_string());
        }
        if has_richmedia && (has_js || has_open_action) {
            known_paths.insert("richmedia_interactive_path".to_string());
        }
        if has_external_action && (has_js || has_open_action || has_additional_action) {
            known_paths.insert("external_action_path".to_string());
        }
        if action_handling_path {
            known_paths.insert("action_handling_divergence_path".to_string());
        }
        if js_execution_policy_path {
            known_paths.insert("js_execution_policy_divergence_path".to_string());
        }
        if attachment_open_behavior_path {
            known_paths.insert("attachment_open_behavior_path".to_string());
        }

        if known_paths.is_empty() {
            return Ok(Vec::new());
        }

        let automatic_trigger =
            has_open_action || has_additional_action || has_page_or_field_action;
        let mut risk_score = 0usize;
        risk_score += known_paths.len() * 2;
        risk_score += usize::from(automatic_trigger);
        risk_score += usize::from(has_launch);
        risk_score += usize::from(has_xfa);
        risk_score += usize::from(has_richmedia);

        let (severity, confidence, impact) = if risk_score >= 7 {
            (Severity::High, Confidence::Strong, Impact::High)
        } else if risk_score >= 4 {
            (Severity::Medium, Confidence::Strong, Impact::Medium)
        } else {
            (Severity::Low, Confidence::Probable, Impact::Low)
        };

        let mut objects = Vec::new();
        for entry in &ctx.graph.objects {
            if let PdfAtom::Dict(_) | PdfAtom::Stream(_) = &entry.atom {
                objects.push(format!("{} {} obj", entry.obj, entry.gen));
            }
            if objects.len() >= 8 {
                break;
            }
        }

        let profile_deltas = "acrobat:high/high,pdfium:medium/medium,preview:low/low";
        let mut meta = std::collections::HashMap::new();
        let catalogue_entries = known_paths.iter().cloned().collect::<Vec<_>>().join(",");
        meta.insert("renderer.known_paths".into(), catalogue_entries.clone());
        meta.insert("renderer.catalogue_version".into(), "2026-02-13".into());
        meta.insert("renderer.catalogue_entries".into(), catalogue_entries);
        meta.insert("renderer.profile_deltas".into(), profile_deltas.into());
        meta.insert("renderer.executable_path_variance".into(), known_paths.len().to_string());
        meta.insert("renderer.risk_score".into(), risk_score.to_string());
        meta.insert("renderer.automatic_trigger".into(), automatic_trigger.to_string());
        meta.insert(
            "renderer.catalogue.family.action_handling".into(),
            action_handling_path.to_string(),
        );
        meta.insert(
            "renderer.catalogue.family.js_execution_policy".into(),
            js_execution_policy_path.to_string(),
        );
        meta.insert(
            "renderer.catalogue.family.attachment_open".into(),
            attachment_open_behavior_path.to_string(),
        );
        meta.insert("renderer.catalogue.family_count".into(), renderer_family_count.to_string());

        let mut findings = vec![Finding {
            id: String::new(),
            surface: self.surface(),
            kind: "renderer_behavior_divergence_known_path".into(),
            severity,
            confidence,
            impact: Some(impact),
            title: "Known renderer behaviour divergence path".into(),
            description:
                "Known reader-behaviour divergence paths were detected across action, script, or form surfaces."
                    .into(),
            objects: objects.clone(),
            evidence: Vec::new(),
            remediation: Some(
                "Replay with multiple renderer profiles and prioritise path-specific controls for high-variance execution surfaces."
                    .into(),
            ),
            meta,
            action_type: None,
            action_target: None,
            action_initiation: None,
            yara: None,
            position: None,
            positions: Vec::new(),
        }];

        if automatic_trigger
            && (has_js || has_launch)
            && (has_xfa || has_richmedia || has_embedded)
            && known_paths.len() >= 2
            && renderer_family_count >= 2
        {
            let mut chain_meta = std::collections::HashMap::new();
            chain_meta.insert(
                "renderer.known_paths".into(),
                known_paths.iter().cloned().collect::<Vec<_>>().join(","),
            );
            chain_meta.insert("renderer.catalogue_version".into(), "2026-02-13".into());
            chain_meta.insert(
                "renderer.catalogue_entries".into(),
                known_paths.iter().cloned().collect::<Vec<_>>().join(","),
            );
            chain_meta.insert("renderer.profile_deltas".into(), profile_deltas.into());
            chain_meta.insert("renderer.risk_score".into(), (risk_score + 2).to_string());
            chain_meta
                .insert("renderer.executable_path_variance".into(), known_paths.len().to_string());
            chain_meta.insert(
                "renderer.catalogue.family_count".into(),
                renderer_family_count.to_string(),
            );
            chain_meta.insert(
                "renderer.chain_components".into(),
                format!(
                    "automatic_trigger={},script_or_launch={},high_risk_surface={}",
                    automatic_trigger,
                    has_js || has_launch,
                    has_xfa || has_richmedia || has_embedded
                ),
            );
            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "renderer_behavior_exploitation_chain".into(),
                severity: Severity::High,
                confidence: Confidence::Strong,
                impact: Some(Impact::High),
                title: "Renderer behaviour exploitation chain".into(),
                description:
                    "Automatic trigger paths and high-risk renderer surfaces co-occur with script/action capabilities, consistent with exploitation-chain setup."
                        .into(),
                objects,
                evidence: Vec::new(),
                remediation: Some(
                    "Prioritise containment and multi-renderer replay; treat as high-risk divergence chain until disproven."
                        .into(),
                ),
                meta: chain_meta,
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
            });
        }

        Ok(findings)
    }
}
