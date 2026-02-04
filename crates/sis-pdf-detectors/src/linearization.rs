use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::PdfAtom;

use crate::{dict_int, entry_dict};

pub struct LinearizationDetector;

impl Detector for LinearizationDetector {
    fn id(&self) -> &'static str {
        "linearization_anomaly"
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
        let mut linearized = Vec::new();
        for entry in &ctx.graph.objects {
            if let Some(dict) = entry_dict(entry) {
                if dict.get_first(b"/Linearized").is_some() {
                    linearized.push(entry);
                }
            }
        }
        let mut findings = Vec::new();
        if linearized.len() > 1 {
            let evidence = linearized
                .iter()
                .map(|e| span_to_evidence(e.full_span, "Linearization object"))
                .collect();
            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "linearization_multiple".into(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                impact: None,
                title: "Multiple linearization dictionaries".into(),
                description: format!("Found {} linearization dictionaries.", linearized.len()),
                objects: linearized.iter().map(|e| format!("{} {} obj", e.obj, e.gen)).collect(),
                evidence,
                remediation: Some("Validate linearization with a strict parser.".into()),
                meta: Default::default(),

                reader_impacts: Vec::new(),
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
            });
        }
        if let Some(entry) = linearized.first() {
            if let Some(dict) = entry_dict(entry) {
                let mut invalid = false;
                let mut meta = std::collections::HashMap::new();
                let file_len = ctx.bytes.len() as u32;
                if let Some(l) = dict_int(dict, b"/L") {
                    meta.insert("linearized.length".into(), l.to_string());
                    if l == 0 || l > file_len.saturating_add(16) {
                        invalid = true;
                    }
                }
                if let Some(o) = dict_int(dict, b"/O") {
                    meta.insert("linearized.first_page_obj".into(), o.to_string());
                    if o == 0 {
                        invalid = true;
                    }
                }
                if let Some(e) = dict_int(dict, b"/E") {
                    meta.insert("linearized.first_end".into(), e.to_string());
                    if e == 0 {
                        invalid = true;
                    }
                }
                if let Some(h) = dict.get_first(b"/H") {
                    if let PdfAtom::Array(arr) = &h.1.atom {
                        meta.insert("linearized.hint_count".into(), arr.len().to_string());
                    }
                }
                if invalid {
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "linearization_invalid".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Probable,
                        impact: None,
                        title: "Linearization values inconsistent".into(),
                        description: "Linearization dictionary fields do not match file layout."
                            .into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(entry.full_span, "Linearization dict")],
                        remediation: Some("Inspect linearized offsets and hint tables.".into()),
                        meta,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                        ..Finding::default()
                    });
                } else if dict.get_first(b"/H").is_some() {
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "linearization_hint_anomaly".into(),
                        severity: Severity::Low,
                        confidence: Confidence::Heuristic,
                        impact: None,
                        title: "Linearization hint tables present".into(),
                        description: "Linearization hint tables may hide malformed offsets.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(entry.full_span, "Linearization dict")],
                        remediation: Some("Validate hint table offsets and object access.".into()),
                        meta,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                        ..Finding::default()
                    });
                }
            }
        }
        Ok(findings)
    }
}
