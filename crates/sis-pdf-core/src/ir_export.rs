use crate::ir_enhanced::{EnhancedIrExport, EnhancedPdfIrObject, IrLineRef};
use crate::model::Finding;
use sis_pdf_pdf::ir::PdfIrObject;

pub fn export_ir_json(ir_objects: &[PdfIrObject]) -> serde_json::Value {
    let objects: Vec<serde_json::Value> = ir_objects
        .iter()
        .map(|obj| {
            let lines: Vec<serde_json::Value> = obj
                .lines
                .iter()
                .enumerate()
                .map(|(idx, line)| {
                    serde_json::json!({
                        "line_index": idx,
                        "obj": format!("{} {}", line.obj_ref.0, line.obj_ref.1),
                        "path": line.path,
                        "type": line.value_type,
                        "value": line.value,
                    })
                })
                .collect();
            serde_json::json!({
                "obj": format!("{} {}", obj.obj_ref.0, obj.obj_ref.1),
                "lines": lines,
                "deviations": obj.deviations,
            })
        })
        .collect();
    serde_json::json!({"objects": objects})
}

pub fn export_ir_text(ir_objects: &[PdfIrObject]) -> String {
    let mut out = String::new();
    for obj in ir_objects {
        out.push_str(&format!("# {} {}\n", obj.obj_ref.0, obj.obj_ref.1));
        for line in &obj.lines {
            out.push_str(&format!(
                "{}-{}, {}, {}, {}\n",
                line.obj_ref.0, line.obj_ref.1, line.path, line.value_type, line.value
            ));
        }
        if !obj.deviations.is_empty() {
            out.push_str(&format!("# deviations: {}\n", obj.deviations.join(",")));
        }
        out.push('\n');
    }
    out
}

/// Convert basic PdfIrObject to EnhancedPdfIrObject with findings
pub fn convert_to_enhanced_ir(basic_ir: &PdfIrObject, findings: &[Finding]) -> EnhancedPdfIrObject {
    // Convert PdfIrLine to IrLineRef
    let lines: Vec<IrLineRef> = basic_ir
        .lines
        .iter()
        .map(|line| IrLineRef {
            path: line.path.clone(),
            value_type: line.value_type.clone(),
            value: line.value.clone(),
        })
        .collect();

    EnhancedPdfIrObject::from_basic_ir(
        basic_ir.obj_ref,
        lines,
        basic_ir.deviations.clone(),
        findings,
    )
}

/// Generate complete EnhancedIrExport from basic IR objects and findings
pub fn generate_enhanced_ir_export(
    basic_ir_objects: &[PdfIrObject],
    findings: &[Finding],
) -> EnhancedIrExport {
    let enhanced_objects: Vec<EnhancedPdfIrObject> =
        basic_ir_objects.iter().map(|obj| convert_to_enhanced_ir(obj, findings)).collect();

    EnhancedIrExport::new(enhanced_objects)
}

/// Export enhanced IR to JSON
pub fn export_enhanced_ir_json(enhanced_ir: &EnhancedIrExport) -> serde_json::Value {
    serde_json::to_value(enhanced_ir).expect("Failed to serialize enhanced IR")
}

/// Export enhanced IR to JSON with pretty formatting
pub fn export_enhanced_ir_json_pretty(enhanced_ir: &EnhancedIrExport) -> String {
    serde_json::to_string_pretty(enhanced_ir).expect("Failed to serialize enhanced IR")
}

/// Export enhanced IR to text format (human-readable summary)
pub fn export_enhanced_ir_text(enhanced_ir: &EnhancedIrExport) -> String {
    let mut out = String::new();

    // Document summary
    out.push_str("=== DOCUMENT SUMMARY ===\n");
    out.push_str(&format!("Total objects: {}\n", enhanced_ir.document_summary.total_objects));
    out.push_str(&format!(
        "Objects with findings: {}\n",
        enhanced_ir.document_summary.objects_with_findings
    ));
    out.push_str(&format!(
        "Max object risk: {:.2}\n",
        enhanced_ir.document_summary.max_object_risk
    ));
    out.push_str(&format!(
        "Attack surface diversity: {}\n",
        enhanced_ir.document_summary.attack_surface_diversity
    ));
    out.push_str(&format!("\nExplanation: {}\n", enhanced_ir.document_summary.explanation));

    // Severity breakdown
    out.push_str("\n--- Severity Breakdown ---\n");
    for (severity, count) in &enhanced_ir.document_summary.severity_counts {
        out.push_str(&format!("  {}: {}\n", severity, count));
    }

    // Attack surface breakdown
    out.push_str("\n--- Attack Surface Breakdown ---\n");
    for (surface, count) in &enhanced_ir.document_summary.surface_counts {
        out.push_str(&format!("  {}: {}\n", surface, count));
    }

    // Objects with findings
    out.push_str("\n\n=== OBJECTS WITH FINDINGS ===\n");
    for obj in &enhanced_ir.objects {
        if obj.findings.is_empty() {
            continue;
        }

        out.push_str(&format!("\n# Object {} {}\n", obj.obj_ref.0, obj.obj_ref.1));
        out.push_str(&format!("Risk Score: {:.2}\n", obj.risk_score));

        if let Some(severity) = &obj.max_severity {
            out.push_str(&format!("Max Severity: {}\n", severity));
        }

        out.push_str(&format!("Attack Surfaces: {}\n", obj.attack_surfaces.join(", ")));

        if let Some(explanation) = &obj.explanation {
            out.push_str(&format!("Explanation: {}\n", explanation));
        }

        out.push_str("\nFindings:\n");
        for finding in &obj.findings {
            out.push_str(&format!(
                "  - {} [{}] (confidence: {})\n",
                finding.kind, finding.severity, finding.confidence
            ));

            if !finding.signals.is_empty() {
                out.push_str("    Signals:\n");
                for (key, value) in &finding.signals {
                    out.push_str(&format!("      {}: {:?}\n", key, value));
                }
            }
        }

        if !obj.deviations.is_empty() {
            out.push_str(&format!("\nDeviations: {}\n", obj.deviations.join(", ")));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AttackSurface, Confidence, Severity};
    use sis_pdf_pdf::ir::PdfIrLine;
    use std::collections::HashMap;

    fn create_test_finding(kind: &str, severity: Severity, obj_id: u32) -> Finding {
        Finding {
            id: format!("test-{}", kind),
            kind: kind.to_string(),
            severity,
            confidence: Confidence::Strong,
            impact: None,
            surface: AttackSurface::JavaScript,
            title: format!("Test {}", kind),
            description: "Test finding".to_string(),
            objects: vec![format!("{} 0 obj", obj_id)],
            evidence: vec![],
            remediation: None,
            positions: Vec::new(),
            meta: HashMap::new(),
            action_type: None,
            action_target: None,
            action_initiation: None,
            yara: None,
        }
    }

    fn create_test_ir_object(obj_id: u32) -> PdfIrObject {
        PdfIrObject {
            obj_ref: (obj_id, 0),
            lines: vec![PdfIrLine {
                obj_ref: (obj_id, 0),
                path: "$.Type".to_string(),
                value_type: "name".to_string(),
                value: "/Page".to_string(),
            }],
            deviations: vec![],
        }
    }

    #[test]
    fn test_convert_to_enhanced_ir() {
        let basic_ir = create_test_ir_object(1);
        let findings = vec![create_test_finding("js_eval", Severity::High, 1)];

        let enhanced = convert_to_enhanced_ir(&basic_ir, &findings);

        assert_eq!(enhanced.obj_ref, (1, 0));
        assert_eq!(enhanced.lines.len(), 1);
        assert_eq!(enhanced.findings.len(), 1);
        assert!(enhanced.risk_score > 0.0);
    }

    #[test]
    fn test_generate_enhanced_ir_export() {
        let basic_ir_objects = vec![create_test_ir_object(1), create_test_ir_object(2)];
        let findings = vec![create_test_finding("js_eval", Severity::High, 1)];

        let export = generate_enhanced_ir_export(&basic_ir_objects, &findings);

        assert_eq!(export.objects.len(), 2);
        assert_eq!(export.document_summary.total_objects, 2);
        assert_eq!(export.document_summary.objects_with_findings, 1);
    }

    #[test]
    fn test_export_enhanced_ir_json() {
        let basic_ir_objects = vec![create_test_ir_object(1)];
        let findings = vec![create_test_finding("js_eval", Severity::High, 1)];
        let export = generate_enhanced_ir_export(&basic_ir_objects, &findings);

        let json = export_enhanced_ir_json(&export);

        assert!(json.is_object());
        assert!(json.get("objects").is_some());
        assert!(json.get("document_summary").is_some());
    }

    #[test]
    fn test_export_enhanced_ir_json_pretty() {
        let basic_ir_objects = vec![create_test_ir_object(1)];
        let findings = vec![create_test_finding("js_eval", Severity::High, 1)];
        let export = generate_enhanced_ir_export(&basic_ir_objects, &findings);

        let json_str = export_enhanced_ir_json_pretty(&export);

        assert!(json_str.contains("objects"));
        assert!(json_str.contains("document_summary"));
        assert!(json_str.contains("js_eval"));
    }

    #[test]
    fn test_export_enhanced_ir_text() {
        let basic_ir_objects = vec![create_test_ir_object(1)];
        let findings = vec![create_test_finding("js_eval", Severity::High, 1)];
        let export = generate_enhanced_ir_export(&basic_ir_objects, &findings);

        let text = export_enhanced_ir_text(&export);

        assert!(text.contains("DOCUMENT SUMMARY"));
        assert!(text.contains("Total objects: 1"));
        assert!(text.contains("js_eval"));
        assert!(text.contains("Risk Score"));
    }

    #[test]
    fn test_enhanced_ir_with_no_findings() {
        let basic_ir_objects = vec![create_test_ir_object(1)];
        let findings = vec![];
        let export = generate_enhanced_ir_export(&basic_ir_objects, &findings);

        assert_eq!(export.objects.len(), 1);
        assert_eq!(export.document_summary.objects_with_findings, 0);
        assert_eq!(export.document_summary.max_object_risk, 0.0);
    }
}
