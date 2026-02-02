use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_pdf::classification::ObjectRole;
use sis_pdf_pdf::typed_graph::EdgeType;

use crate::{js_payload_candidates_from_entry, JsPayloadSource};

pub struct MultiStageDetector;

impl Detector for MultiStageDetector {
    fn id(&self) -> &'static str {
        "multi_stage_attack"
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
        // Build typed graph to analyze document structure
        let typed_graph = ctx.build_typed_graph();
        let classifications = ctx.classifications();

        // Check for JavaScript edges
        let mut has_js = typed_graph.edges.iter().any(|e| {
            matches!(
                e.edge_type,
                EdgeType::JavaScriptPayload | EdgeType::JavaScriptNames
            )
        });
        let mut js_uri_count = 0usize;
        for entry in &ctx.graph.objects {
            js_uri_count += js_payload_candidates_from_entry(ctx, entry)
                .iter()
                .filter(|candidate| candidate.source != JsPayloadSource::Action)
                .count();
        }
        if js_uri_count > 0 {
            has_js = true;
        }

        // Check for embedded files via classifications
        let has_embedded = classifications
            .iter()
            .any(|(_, classified)| classified.has_role(ObjectRole::EmbeddedFile));

        // Check for external action edges
        let has_external_action = typed_graph.edges.iter().any(|e| {
            matches!(
                e.edge_type,
                EdgeType::UriTarget
                    | EdgeType::LaunchTarget
                    | EdgeType::GoToRTarget
                    | EdgeType::SubmitFormTarget
            )
        });

        // Multi-stage attack requires all three components
        if has_js && has_embedded && has_external_action {
            let mut meta = std::collections::HashMap::new();
            meta.insert("multi_stage.js".into(), has_js.to_string());
            meta.insert("multi_stage.embedded".into(), has_embedded.to_string());
            meta.insert(
                "multi_stage.external_action".into(),
                has_external_action.to_string(),
            );

            // Count each component for better visibility
            let js_count = typed_graph
                .edges
                .iter()
                .filter(|e| {
                    matches!(
                        e.edge_type,
                        EdgeType::JavaScriptPayload | EdgeType::JavaScriptNames
                    )
                })
                .count()
                + js_uri_count;
            let embedded_count = classifications
                .iter()
                .filter(|(_, c)| c.has_role(ObjectRole::EmbeddedFile))
                .count();
            let action_count = typed_graph
                .edges
                .iter()
                .filter(|e| {
                    matches!(
                        e.edge_type,
                        EdgeType::UriTarget
                            | EdgeType::LaunchTarget
                            | EdgeType::GoToRTarget
                            | EdgeType::SubmitFormTarget
                    )
                })
                .count();

            meta.insert("multi_stage.js_count".into(), js_count.to_string());
            if js_uri_count > 0 {
                meta.insert("multi_stage.js_uri_count".into(), js_uri_count.to_string());
            }
            meta.insert(
                "multi_stage.embedded_count".into(),
                embedded_count.to_string(),
            );
            meta.insert("multi_stage.action_count".into(), action_count.to_string());

            return Ok(vec![Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "multi_stage_attack_chain".into(),
                severity: Severity::High,
                confidence: Confidence::Probable,
                impact: None,
                title: "Multi-stage attack chain indicators".into(),
                description:
                    "Detected JavaScript, embedded content, and outbound action indicators.".into(),
                objects: vec!["multi_stage".into()],
                evidence: Vec::new(),
                remediation: Some("Review staging flow and embedded payloads.".into()),
                meta,
                yara: None,
                position: None,
                positions: Vec::new(),
                ..Finding::default()
            }]);
        }

        Ok(Vec::new())
    }
}
