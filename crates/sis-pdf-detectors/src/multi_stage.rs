use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};

use crate::{entry_dict, resolve_action_details};

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
        let mut has_js = false;
        let mut has_embedded = false;
        let mut has_action = false;
        for entry in &ctx.graph.objects {
            let Some(dict) = entry_dict(entry) else { continue };
            if dict.has_name(b"/S", b"/JavaScript") || dict.get_first(b"/JS").is_some() {
                has_js = true;
            }
            if dict.has_name(b"/Type", b"/EmbeddedFile") || dict.has_name(b"/Type", b"/Filespec") {
                has_embedded = true;
            }
            if dict.has_name(b"/S", b"/Launch")
                || dict.has_name(b"/S", b"/URI")
                || dict.has_name(b"/S", b"/GoToR")
                || dict.has_name(b"/S", b"/SubmitForm")
            {
                has_action = true;
            }
            if let Some((_, v)) = dict.get_first(b"/A") {
                if has_action_in_obj(ctx, v) {
                    has_action = true;
                }
            }
            if let Some((_, v)) = dict.get_first(b"/OpenAction") {
                if has_action_in_obj(ctx, v) {
                    has_action = true;
                }
            }
            if let Some((_, v)) = dict.get_first(b"/AA") {
                if let sis_pdf_pdf::object::PdfAtom::Dict(aa_dict) = &v.atom {
                    for (_, action) in &aa_dict.entries {
                        if has_action_in_obj(ctx, action) {
                            has_action = true;
                        }
                    }
                }
            }
        }
        if has_js && has_embedded && has_action {
            let mut meta = std::collections::HashMap::new();
            meta.insert("multi_stage.js".into(), has_js.to_string());
            meta.insert("multi_stage.embedded".into(), has_embedded.to_string());
            meta.insert("multi_stage.action".into(), has_action.to_string());
            return Ok(vec![Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "multi_stage_attack_chain".into(),
                severity: Severity::High,
                confidence: Confidence::Probable,
                title: "Multi-stage attack chain indicators".into(),
                description: "Detected JavaScript, embedded content, and outbound action indicators.".into(),
                objects: vec!["multi_stage".into()],
                evidence: Vec::new(),
                remediation: Some("Review staging flow and embedded payloads.".into()),
                meta,
                yara: None,
            }]);
        }
        Ok(Vec::new())
    }
}

fn has_action_in_obj(ctx: &sis_pdf_core::scan::ScanContext, obj: &sis_pdf_pdf::object::PdfObj<'_>) -> bool {
    if let Some(details) = resolve_action_details(ctx, obj) {
        if let Some(kind) = details.meta.get("action.s") {
            return matches!(
                kind.as_str(),
                "/Launch" | "/URI" | "/GoToR" | "/SubmitForm" | "/JavaScript"
            );
        }
    }
    false
}
