use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;

use crate::{entry_dict, resolve_payload};
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
            let Some(dict) = entry_dict(entry) else { continue };
            if !dict.has_name(b"/S", b"/JavaScript") && dict.get_first(b"/JS").is_none() {
                continue;
            }
            let Some((_, obj)) = dict.get_first(b"/JS") else { continue };
            let payload = resolve_payload(ctx, obj);
            let Some(info) = payload.payload else { continue };
            let decoded = decode_layers(&info.bytes, 4);
            let sig = extract_js_signals_with_ast(&info.bytes, self.enable_ast);
            let mut meta = sig;
            meta.insert("payload.decode_layers".into(), decoded.layers.to_string());
            let base64_like = meta
                .get("js.has_base64_like")
                .map(|v| v == "true")
                .unwrap_or(false);
            let has_eval = meta
                .get("js.contains_eval")
                .map(|v| v == "true")
                .unwrap_or(false);
            let has_fcc = meta
                .get("js.contains_fromcharcode")
                .map(|v| v == "true")
                .unwrap_or(false);
            let has_unescape = meta
                .get("js.contains_unescape")
                .map(|v| v == "true")
                .unwrap_or(false);
            let multi_stage = decoded.layers >= 2;
            let polymorphic = (has_eval && (has_fcc || has_unescape)) || (base64_like && has_eval);

            if polymorphic {
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "js_polymorphic".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    title: "Polymorphic JavaScript patterns".into(),
                    description: "JavaScript shows traits of polymorphic or staged code.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                    remediation: Some("Deobfuscate JavaScript and inspect dynamic behavior.".into()),
                    meta: meta.clone(),
                    yara: None,
        position: None,
        positions: Vec::new(),
                });
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
                    title: "Multi-stage JavaScript decoding".into(),
                    description: "JavaScript contains multiple decoding layers.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                    remediation: Some("Inspect the deobfuscated payload.".into()),
                    meta: meta2,
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
                    title: "Deep JavaScript deobfuscation".into(),
                    description: "Deobfuscation produced a simplified payload variant.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                    remediation: Some("Review decoded layers for hidden behavior.".into()),
                    meta: meta3,
                    yara: None,
        position: None,
        positions: Vec::new(),
                });
            }
        }
        Ok(findings)
    }
}
