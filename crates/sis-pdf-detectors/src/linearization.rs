use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
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
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                positions: Vec::new(),
            });
        }
        if let Some(entry) = linearized.first() {
            if let Some(dict) = entry_dict(entry) {
                let mut invalid = false;
                let mut meta = std::collections::HashMap::new();
                let mut reasons = Vec::new();
                let file_len = ctx.bytes.len() as u32;
                meta.insert("linearization.file_len".into(), file_len.to_string());
                if let Some(l) = dict_int(dict, b"/L") {
                    meta.insert("linearized.length".into(), l.to_string());
                    if l == 0 {
                        invalid = true;
                        reasons.push("L_is_zero".to_string());
                    }
                    let delta = l.abs_diff(file_len);
                    meta.insert("linearized.length_delta".into(), delta.to_string());
                    if delta > 16 {
                        invalid = true;
                        reasons.push("L_file_size_mismatch".to_string());
                    }
                } else {
                    invalid = true;
                    reasons.push("L_missing".to_string());
                }
                if let Some(o) = dict_int(dict, b"/O") {
                    meta.insert("linearized.first_page_obj".into(), o.to_string());
                    if o == 0 {
                        invalid = true;
                        reasons.push("O_is_zero".to_string());
                    }
                    if let Some(first_page_entry) = ctx.graph.get_object(o, 0) {
                        meta.insert(
                            "linearized.first_page_offset".into(),
                            first_page_entry.full_span.start.to_string(),
                        );
                        if let Some(e) = dict_int(dict, b"/E") {
                            if first_page_entry.full_span.start >= e as u64 {
                                invalid = true;
                                reasons.push("O_offset_outside_E_window".to_string());
                            }
                        }
                    } else {
                        invalid = true;
                        reasons.push("O_object_not_found".to_string());
                    }
                } else {
                    invalid = true;
                    reasons.push("O_missing".to_string());
                }
                if let Some(e) = dict_int(dict, b"/E") {
                    meta.insert("linearized.first_end".into(), e.to_string());
                    if e == 0 {
                        invalid = true;
                        reasons.push("E_is_zero".to_string());
                    }
                    if e > file_len {
                        invalid = true;
                        reasons.push("E_exceeds_file_len".to_string());
                    }
                    if let Some(min_startxref) = ctx.graph.startxrefs.iter().min() {
                        meta.insert("linearized.min_startxref".into(), min_startxref.to_string());
                        if *min_startxref > e as u64 {
                            invalid = true;
                            reasons.push("startxref_after_E".to_string());
                        }
                    }
                } else {
                    invalid = true;
                    reasons.push("E_missing".to_string());
                }
                if let Some(h) = dict.get_first(b"/H") {
                    if let PdfAtom::Array(arr) = &h.1.atom {
                        meta.insert("linearized.hint_count".into(), arr.len().to_string());
                        if arr.len() % 2 != 0 || arr.is_empty() {
                            invalid = true;
                            reasons.push("H_shape_invalid".to_string());
                        }
                        let mut values = Vec::new();
                        for item in arr {
                            match item.atom {
                                PdfAtom::Int(value) if value >= 0 => values.push(value as u32),
                                _ => {
                                    invalid = true;
                                    reasons.push("H_non_integer".to_string());
                                    break;
                                }
                            }
                        }
                        for pair in values.chunks(2) {
                            if pair.len() != 2 {
                                continue;
                            }
                            let start = pair[0];
                            let len = pair[1];
                            let end = start.saturating_add(len);
                            if start == 0 || len == 0 || end > file_len {
                                invalid = true;
                                reasons.push("H_bounds_invalid".to_string());
                                break;
                            }
                        }
                    }
                }
                if invalid {
                    reasons.sort();
                    reasons.dedup();
                    if !reasons.is_empty() {
                        meta.insert("linearization.integrity_reasons".into(), reasons.join(","));
                    }
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "linearization_integrity".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Strong,
                        impact: Some(Impact::Medium),
                        title: "Linearization integrity anomaly".into(),
                        description:
                            "Linearization dictionary integrity checks failed (size, hint offsets, xref relation, or object ordering)."
                                .into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(entry.full_span, "Linearization dict")],
                        remediation: Some(
                            "Treat linearisation hints as untrusted and validate with strict parsing before rendering."
                                .into(),
                        ),
                        meta: meta.clone(),
                        yara: None,
                        positions: Vec::new(),
                        ..Finding::default()
                    });
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
                        positions: Vec::new(),
                        ..Finding::default()
                    });
                }
            }
        }
        Ok(findings)
    }
}
