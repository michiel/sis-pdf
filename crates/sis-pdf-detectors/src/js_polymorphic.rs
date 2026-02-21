use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;

use crate::js_payload_candidates_from_entry;
use js_analysis::static_analysis::{decode_layers, extract_js_signals_with_ast};

pub struct JsPolymorphicDetector {
    pub(crate) enable_ast: bool,
}

impl Detector for JsPolymorphicDetector {
    fn id(&self) -> &'static str {
        "js_polymorphic"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::JavaScript
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Moderate
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            let candidates = js_payload_candidates_from_entry(ctx, entry);
            if candidates.is_empty() {
                continue;
            }
            for candidate in candidates {
                let info = candidate.payload;
                let decoded = decode_layers(&info.bytes, 4);
                let sig = extract_js_signals_with_ast(&info.bytes, self.enable_ast);
                let mut meta = sig;
                meta.insert("payload.decode_layers".into(), decoded.layers.to_string());
                if let Some(label) = candidate.source.meta_value() {
                    meta.insert("js.source".into(), label.into());
                }
                let base64_like =
                    meta.get("js.has_base64_like").map(|v| v == "true").unwrap_or(false);
                let has_eval = meta.get("js.contains_eval").map(|v| v == "true").unwrap_or(false);
                let has_fcc =
                    meta.get("js.contains_fromcharcode").map(|v| v == "true").unwrap_or(false);
                let has_unescape =
                    meta.get("js.contains_unescape").map(|v| v == "true").unwrap_or(false);
                let multi_stage = decoded.layers >= 2;
                let polymorphic = has_eval && (has_fcc || has_unescape || base64_like);

                let mut evidence = candidate.evidence;
                if evidence.is_empty() {
                    evidence.push(span_to_evidence(entry.full_span, "JavaScript object"));
                }
                if polymorphic {
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "js_polymorphic".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Probable,
                        impact: None,
                        title: "Polymorphic JavaScript patterns".into(),
                        description: "JavaScript shows traits of polymorphic or staged code."
                            .into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: evidence.clone(),
                        remediation: Some(
                            "Deobfuscate JavaScript and inspect dynamic behavior.".into(),
                        ),
                        meta: meta.clone(),
                        action_type: None,
                        action_target: None,
                        action_initiation: None,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                    });
                }
                for (meta_key, kind, title, description) in [
                    (
                        "js.jsfuck_encoding",
                        "js_jsfuck_encoding",
                        "JSFuck encoding detected",
                        "JavaScript appears obfuscated with JSFuck character-restricted encoding.",
                    ),
                    (
                        "js.jjencode_encoding",
                        "js_jjencode_encoding",
                        "JJEncode encoding detected",
                        "JavaScript appears obfuscated with JJEncode symbol-heavy encoding.",
                    ),
                    (
                        "js.aaencode_encoding",
                        "js_aaencode_encoding",
                        "AAEncode encoding detected",
                        "JavaScript appears obfuscated with AAEncode fullwidth/emoticon-style encoding.",
                    ),
                    (
                        "js.control_flow_flattening",
                        "js_control_flow_flattening",
                        "Control flow flattening detected",
                        "JavaScript uses control-flow flattening dispatcher patterns consistent with advanced obfuscation.",
                    ),
                    (
                        "js.dead_code_injection",
                        "js_dead_code_injection",
                        "Dead code injection detected",
                        "JavaScript contains unreachable code blocks consistent with anti-analysis dead-code injection.",
                    ),
                    (
                        "js.array_rotation_decode",
                        "js_array_rotation_decode",
                        "Array rotation decode pattern detected",
                        "JavaScript contains array rotation string-decoding patterns common in obfuscator-style loaders.",
                    ),
                    (
                        "js.semantic_source_to_sink_flow",
                        "js_semantic_source_to_sink_flow",
                        "Semantic source-to-sink flow detected",
                        "AST semantic call graph indicates a source-to-sink flow with transformation depth, resilient to syntactic rewrites.",
                    ),
                ] {
                    if matches!(meta.get(meta_key).map(String::as_str), Some("true")) {
                        findings.push(Finding {
                            id: String::new(),
                            surface: self.surface(),
                            kind: kind.into(),
                            severity: Severity::Medium,
                            confidence: Confidence::Strong,
                            impact: None,
                            title: title.into(),
                            description: description.into(),
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence: evidence.clone(),
                            remediation: Some(
                                "Deobfuscate the payload and inspect decoded execution paths."
                                    .into(),
                            ),
                            meta: meta.clone(),
                            action_type: None,
                            action_target: None,
                            action_initiation: None,
                            yara: None,
                            position: None,
                            positions: Vec::new(),
                        });
                    }
                }
                for (meta_key, kind, title, description, severity, confidence) in [
                    (
                        "js.heap_grooming",
                        "js_heap_grooming",
                        "Heap grooming pattern detected",
                        "JavaScript shows repeated heap allocation and view-shaping patterns consistent with grooming.",
                        Severity::High,
                        Confidence::Probable,
                    ),
                    (
                        "js.lfh_priming",
                        "js_lfh_priming",
                        "LFH priming pattern detected",
                        "JavaScript appears to prime allocation buckets through repeated allocation/free cycles.",
                        Severity::Medium,
                        Confidence::Probable,
                    ),
                    (
                        "js.rop_chain_construction",
                        "js_rop_chain_construction",
                        "ROP chain construction pattern detected",
                        "JavaScript uses address arithmetic and sequential write patterns consistent with ROP chain staging.",
                        Severity::High,
                        Confidence::Strong,
                    ),
                    (
                        "js.info_leak_primitive",
                        "js_info_leak_primitive",
                        "Info-leak primitive pattern detected",
                        "JavaScript exhibits ArrayBuffer/TypedArray patterns consistent with out-of-bounds memory disclosure primitives.",
                        Severity::High,
                        Confidence::Probable,
                    ),
                ] {
                    if matches!(meta.get(meta_key).map(String::as_str), Some("true")) {
                        findings.push(Finding {
                            id: String::new(),
                            surface: self.surface(),
                            kind: kind.into(),
                            severity,
                            confidence,
                            impact: None,
                            title: title.into(),
                            description: description.into(),
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence: evidence.clone(),
                            remediation: Some(
                                "Review heap allocation/view/write logic and correlate with dynamic runtime telemetry."
                                    .into(),
                            ),
                            meta: meta.clone(),
                            action_type: None,
                            action_target: None,
                            action_initiation: None,
                            yara: None,
                            position: None,
                            positions: Vec::new(),
                        });
                    }
                }
                if multi_stage {
                    let mut meta2 = meta.clone();
                    meta2.insert(
                        "payload.deobfuscated_preview".into(),
                        sis_pdf_core::evidence::preview_ascii(&decoded.bytes, 120),
                    );
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "js_multi_stage_decode".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Probable,
                        impact: None,
                        title: "Multi-stage JavaScript decoding".into(),
                        description: "JavaScript contains multiple decoding layers.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: evidence.clone(),
                        remediation: Some("Inspect the deobfuscated payload.".into()),
                        meta: meta2,
                        action_type: None,
                        action_target: None,
                        action_initiation: None,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                    });
                }
                if decoded.layers > 0 && decoded.bytes != info.bytes {
                    let mut meta3 = meta.clone();
                    meta3.insert(
                        "payload.deobfuscated_preview".into(),
                        sis_pdf_core::evidence::preview_ascii(&decoded.bytes, 120),
                    );
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "js_obfuscation_deep".into(),
                        severity: Severity::Low,
                        confidence: Confidence::Heuristic,
                        impact: None,
                        title: "Deep JavaScript deobfuscation".into(),
                        description: "Deobfuscation produced a simplified payload variant.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence,
                        remediation: Some("Review decoded layers for hidden behavior.".into()),
                        meta: meta3,
                        action_type: None,
                        action_target: None,
                        action_initiation: None,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                    });
                }
            }
        }
        Ok(findings)
    }
}
