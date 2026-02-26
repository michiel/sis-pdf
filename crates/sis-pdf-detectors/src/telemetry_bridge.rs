use anyhow::Result;
use std::collections::HashMap;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::graph::TelemetryEvent;

pub struct TelemetryBridgeDetector;

impl Detector for TelemetryBridgeDetector {
    fn id(&self) -> &'static str {
        "telemetry_bridge"
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
        if ctx.graph.telemetry_events.is_empty() {
            return Ok(Vec::new());
        }

        let mut grouped: HashMap<(String, String, String), Vec<&TelemetryEvent>> = HashMap::new();
        for event in &ctx.graph.telemetry_events {
            let group_kind = map_group_kind(event);
            if group_kind.is_empty() {
                continue;
            }
            let object_key = event.object_ref.clone().unwrap_or_else(|| "-".into());
            grouped
                .entry((group_kind.to_string(), event.domain.clone(), object_key))
                .or_default()
                .push(event);
        }

        let mut findings = Vec::new();
        for ((kind, domain, object_key), events) in grouped {
            let mut meta = HashMap::new();
            meta.insert("telemetry.count".into(), events.len().to_string());
            meta.insert("telemetry.domain".into(), domain);
            let mut event_kinds =
                events.iter().map(|event| event.kind.as_str()).collect::<Vec<_>>();
            event_kinds.sort();
            event_kinds.dedup();
            meta.insert("telemetry.kinds".into(), event_kinds.join(","));

            let mut messages =
                events.iter().map(|event| event.message.as_str()).collect::<Vec<_>>();
            messages.sort();
            messages.dedup();
            if let Some(message) = messages.first() {
                meta.insert("telemetry.message".into(), (*message).to_string());
            }

            for event in &events {
                for (key, value) in &event.meta {
                    let meta_key = format!("telemetry.{}", key);
                    meta.entry(meta_key).or_insert_with(|| value.clone());
                }
            }

            let mut evidence = Vec::new();
            for event in events.iter().take(5) {
                if let Some(span) = event.span {
                    evidence.push(span_to_evidence(span, "Telemetry event span"));
                }
            }

            let mut objects = Vec::new();
            if object_key != "-" {
                objects.push(object_key.clone());
            }
            if objects.is_empty() {
                objects.push("telemetry".into());
            }

            let (severity, impact, confidence, title, description, remediation) =
                map_attributes(&kind, events.len());

            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind,
                severity,
                confidence,
                impact,
                title,
                description,
                objects,
                evidence,
                remediation: Some(remediation),
                meta,
                yara: None,
                positions: Vec::new(),
                ..Finding::default()
            });
        }

        Ok(findings)
    }
}

fn map_group_kind(event: &TelemetryEvent) -> &'static str {
    match event.kind.as_str() {
        "xref_loop_detected" => "xref_loop_detected",
        "xref_offset_oob" => "xref_offset_oob",
        "objstm_recursive_reference" => "objstm_recursive_reference",
        "objstm_nested_reference" => "objstm_nested_reference",
        "max_objects_total_reached"
        | "high_objstm_count"
        | "objstm_count_exceeded"
        | "objstm_decode_budget_reached"
        | "objstm_decode_budget_exceeded"
        | "objstm_decoded_bytes_high"
        | "objstm_decoded_bytes_exceeded" => "objstm_processing_limited",
        _ => "",
    }
}

fn map_attributes(
    kind: &str,
    count: usize,
) -> (Severity, Option<Impact>, Confidence, String, String, String) {
    match kind {
        "xref_loop_detected" => (
            Severity::Medium,
            Some(Impact::Medium),
            Confidence::Strong,
            "XRef loop detected".into(),
            format!(
                "XRef traversal encountered a loop ({} telemetry events).",
                count
            ),
            "Inspect xref /Prev chain for cyclic references.".into(),
        ),
        "xref_offset_oob" => (
            Severity::Medium,
            Some(Impact::Medium),
            Confidence::Strong,
            "XRef offset out of bounds".into(),
            format!(
                "XRef traversal referenced offsets outside file bounds ({} telemetry events).",
                count
            ),
            "Validate startxref and xref section offsets.".into(),
        ),
        "objstm_recursive_reference" | "objstm_nested_reference" => (
            Severity::Low,
            Some(Impact::Low),
            Confidence::Strong,
            "ObjStm recursive reference".into(),
            format!(
                "Object stream expansion observed recursive or nested ObjStm references ({} events).",
                count
            ),
            "Inspect object stream references for recursion-based concealment.".into(),
        ),
        "objstm_processing_limited" => (
            Severity::Medium,
            Some(Impact::Medium),
            Confidence::Strong,
            "ObjStm processing limits reached".into(),
            format!(
                "Object stream expansion hit processing or decode limits ({} events).",
                count
            ),
            "Run deeper inspection with adjusted safe limits and review hidden objects.".into(),
        ),
        _ => (
            Severity::Info,
            None,
            Confidence::Heuristic,
            "Telemetry event".into(),
            format!("Aggregated telemetry events: {}", count),
            "Review telemetry details.".into(),
        ),
    }
}
