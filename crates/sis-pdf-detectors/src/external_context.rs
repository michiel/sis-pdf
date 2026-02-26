use anyhow::Result;
use std::collections::HashSet;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::decode::stream_filters;
use sis_pdf_pdf::object::{PdfAtom, PdfName};
use sis_pdf_pdf::typed_graph::EdgeType;

pub struct ExternalActionContextDetector;

impl Detector for ExternalActionContextDetector {
    fn id(&self) -> &'static str {
        "external_action_risk_context"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::Actions
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH | Needs::STREAM_INDEX
    }
    fn cost(&self) -> Cost {
        Cost::Moderate
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        // Build typed graph to find external actions
        let typed_graph = ctx.build_typed_graph();

        // Find external action edges
        let mut action_objects = HashSet::new();
        let mut action_types = Vec::new();

        for edge in &typed_graph.edges {
            match &edge.edge_type {
                EdgeType::UriTarget => {
                    action_objects.insert(edge.src);
                    action_types.push("URI");
                }
                EdgeType::LaunchTarget => {
                    action_objects.insert(edge.src);
                    action_types.push("Launch");
                }
                EdgeType::GoToRTarget => {
                    action_objects.insert(edge.src);
                    action_types.push("GoToR");
                }
                EdgeType::SubmitFormTarget => {
                    action_objects.insert(edge.src);
                    action_types.push("SubmitForm");
                }
                _ => {}
            }
        }

        if action_objects.is_empty() {
            return Ok(Vec::new());
        }

        // Count obfuscation markers
        let hex_name_count = count_hex_names(&ctx.graph);
        let deep_filter_count = count_deep_filters(&ctx.graph);

        if hex_name_count == 0 && deep_filter_count == 0 {
            return Ok(Vec::new());
        }

        let mut meta = std::collections::HashMap::new();
        meta.insert("external.action_count".into(), action_objects.len().to_string());
        meta.insert("external.action_types".into(), action_types.join(", "));
        if hex_name_count > 0 {
            meta.insert("obfuscation.hex_name_count".into(), hex_name_count.to_string());
        }
        if deep_filter_count > 0 {
            meta.insert("obfuscation.deep_filter_streams".into(), deep_filter_count.to_string());
        }

        // Collect evidence from action source objects
        let mut evidence = Vec::new();
        for (obj, gen) in action_objects.iter().take(8) {
            if let Some(entry) = ctx.graph.get_object(*obj, *gen) {
                evidence.push(span_to_evidence(entry.full_span, "External action"));
            }
        }

        let objects: Vec<String> =
            action_objects.iter().map(|(obj, gen)| format!("{} {} obj", obj, gen)).collect();

        Ok(vec![Finding {
            id: String::new(),
            surface: self.surface(),
            kind: "external_action_risk_context".into(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            impact: Impact::Unknown,
            title: "External action with obfuscation context".into(),
            description:
                "External action targets are present alongside obfuscation markers (hex-encoded names or deep filter chains)."
                    .into(),
            objects,
            evidence,
            remediation: Some(
                "Inspect action targets and decode nested streams to confirm intent.".into(),
            ),
            meta,
            yara: None,
        positions: Vec::new(),
        ..Finding::default()
        }])
    }
}

fn count_hex_names(graph: &sis_pdf_pdf::ObjectGraph<'_>) -> usize {
    let mut count = 0usize;
    for entry in &graph.objects {
        let dict = match crate::entry_dict(entry) {
            Some(d) => d,
            None => continue,
        };
        for (name, _) in &dict.entries {
            if name_has_hex(name) {
                count += 1;
            }
        }
    }
    count
}

fn name_has_hex(name: &PdfName<'_>) -> bool {
    name.raw.contains(&b'#')
}

fn count_deep_filters(graph: &sis_pdf_pdf::ObjectGraph<'_>) -> usize {
    let mut count = 0usize;
    for entry in &graph.objects {
        if let PdfAtom::Stream(st) = &entry.atom {
            let filters = stream_filters(&st.dict);
            if filters.len() >= 3 {
                count += 1;
            }
        }
    }
    count
}
