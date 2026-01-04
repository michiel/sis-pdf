use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;

use crate::{entry_dict, resolve_action_details, resolve_payload};

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
        let mut has_embedded = false;
        let mut embedded_names = Vec::new();
        for entry in &ctx.graph.objects {
            if let Some(dict) = entry_dict(entry) {
                if dict.has_name(b"/Type", b"/EmbeddedFile") || dict.has_name(b"/Type", b"/Filespec") {
                    has_embedded = true;
                    if let Some(name) = filespec_name(dict) {
                        embedded_names.push(name);
                    }
                }
            }
        }
        let analyzer = sis_pdf_core::supply_chain::SupplyChainDetector;
        for entry in &ctx.graph.objects {
            let Some(dict) = entry_dict(entry) else { continue };
            if dict.get_first(b"/JS").is_none() && !dict.has_name(b"/S", b"/JavaScript") {
                continue;
            }
            let Some((_, obj)) = dict.get_first(b"/JS") else { continue };
            let payload = resolve_payload(ctx, obj);
            let Some(info) = payload.payload else { continue };

            let staged = analyzer.detect_staged_payload(&info.bytes);
            let mut action_targets = Vec::new();
            for key in [b"/A".as_slice(), b"/OpenAction".as_slice()] {
                if let Some((_, v)) = dict.get_first(key) {
                    if let Some(details) = resolve_action_details(ctx, v) {
                        if let Some(target) = details.meta.get("action.target") {
                            action_targets.push(target.clone());
                        }
                    }
                }
            }
            if let Some((_, aa)) = dict.get_first(b"/AA") {
                if let sis_pdf_pdf::object::PdfAtom::Dict(aa_dict) = &aa.atom {
                    for (_, v) in &aa_dict.entries {
                        if let Some(details) = resolve_action_details(ctx, v) {
                            if let Some(target) = details.meta.get("action.target") {
                                action_targets.push(target.clone());
                            }
                        }
                    }
                }
            }

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
                if !action_targets.is_empty() {
                    meta.insert("supply_chain.action_targets".into(), action_targets.join(","));
                }
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "supply_chain_staged_payload".into(),
                    severity: Severity::High,
                    confidence: Confidence::Probable,
                    title: "Staged payload delivery".into(),
                    description: "JavaScript indicates download or staged payload execution.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                    remediation: Some("Inspect outbound URLs and staged payloads.".into()),
                    meta,
                    yara: None,
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
                if !action_targets.is_empty() {
                    meta.insert("supply_chain.action_targets".into(), action_targets.join(","));
                }
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "supply_chain_update_vector".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Heuristic,
                    title: "Update mechanism references".into(),
                    description: "JavaScript references update or installer logic.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                    remediation: Some("Verify update channels and signing policies.".into()),
                    meta,
                    yara: None,
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
                if !action_targets.is_empty() {
                    meta.insert("supply_chain.action_targets".into(), action_targets.join(","));
                }
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "supply_chain_persistence".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    title: "Persistence-related JavaScript".into(),
                    description: "JavaScript references persistence-like viewer hooks.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                    remediation: Some("Review persistence-related APIs and triggers.".into()),
                    meta,
                    yara: None,
                });
            }
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
