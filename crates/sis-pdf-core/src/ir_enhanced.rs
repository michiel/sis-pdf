//! Enhanced Intermediate Representation (IR) with semantic annotations
//!
//! This module extends the basic PDF IR with security-relevant metadata:
//! - Findings associated with each object
//! - Attack surfaces present in each object
//! - Risk scores computed from findings
//! - Natural language explanations for objects and documents

use crate::model::{Confidence, Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Enhanced PDF IR object with semantic security annotations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedPdfIrObject {
    /// Object reference (obj_id, gen_id)
    pub obj_ref: (u32, u16),

    /// IR lines from basic IR generation
    pub lines: Vec<IrLineRef>,

    /// Structural deviations from PDF spec
    pub deviations: Vec<String>,

    // NEW: Semantic annotations
    /// Findings associated with this object
    pub findings: Vec<IrFindingSummary>,

    /// Attack surfaces present in this object
    pub attack_surfaces: Vec<String>,

    /// Maximum severity level of findings
    pub max_severity: Option<String>,

    /// Computed risk score (0.0 - 1.0)
    pub risk_score: f32,

    /// Natural language explanation for this object
    pub explanation: Option<String>,
}

/// Reference to an IR line (simplified version for enhanced IR)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrLineRef {
    /// Path in the object tree (e.g., "$.Type", "$.Kids[0]")
    pub path: String,

    /// Type of the value (e.g., "name", "string", "array")
    pub value_type: String,

    /// String representation of the value
    pub value: String,
}

/// Summary of a finding for IR export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrFindingSummary {
    /// Finding kind (e.g., "js_eval", "xref_conflict")
    pub kind: String,

    /// Severity level
    pub severity: String,

    /// Confidence level
    pub confidence: String,

    /// Attack surface category
    pub surface: String,

    /// Extracted signals from finding metadata
    pub signals: HashMap<String, serde_json::Value>,
}

/// Enhanced IR export with document-level summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedIrExport {
    /// All enhanced objects
    pub objects: Vec<EnhancedPdfIrObject>,

    /// Document-level summary
    pub document_summary: DocumentSummary,
}

/// Document-level aggregation and summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentSummary {
    /// Total number of objects in document
    pub total_objects: usize,

    /// Number of objects with at least one finding
    pub objects_with_findings: usize,

    /// Maximum risk score across all objects
    pub max_object_risk: f32,

    /// Number of distinct attack surfaces detected
    pub attack_surface_diversity: usize,

    /// Natural language explanation for the entire document
    pub explanation: String,

    /// Breakdown by severity
    pub severity_counts: HashMap<String, usize>,

    /// Breakdown by attack surface
    pub surface_counts: HashMap<String, usize>,
}

impl EnhancedPdfIrObject {
    /// Create an enhanced IR object from findings
    pub fn from_basic_ir(
        obj_ref: (u32, u16),
        lines: Vec<IrLineRef>,
        deviations: Vec<String>,
        findings: &[Finding],
    ) -> Self {
        // Filter findings for this object
        let obj_str = format!("{} {} obj", obj_ref.0, obj_ref.1);
        let obj_findings: Vec<_> =
            findings.iter().filter(|f| f.objects.contains(&obj_str)).collect();

        // Extract finding summaries
        let finding_summaries: Vec<IrFindingSummary> = obj_findings
            .iter()
            .map(|f| IrFindingSummary {
                kind: f.kind.clone(),
                severity: format!("{:?}", f.severity),
                confidence: format!("{:?}", f.confidence),
                surface: format!("{:?}", f.surface),
                signals: extract_signals_from_meta(&f.meta),
            })
            .collect();

        // Aggregate attack surfaces
        let attack_surfaces: Vec<String> = obj_findings
            .iter()
            .map(|f| format!("{:?}", f.surface))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        // Compute max severity
        let max_severity =
            obj_findings.iter().map(|f| f.severity).max().map(|s| format!("{:?}", s));

        // Compute risk score
        let risk_score = compute_object_risk_score(&obj_findings);

        // Generate explanation for this object
        let explanation = if !obj_findings.is_empty() {
            Some(generate_object_explanation(&obj_findings))
        } else {
            None
        };

        Self {
            obj_ref,
            lines,
            deviations,
            findings: finding_summaries,
            attack_surfaces,
            max_severity,
            risk_score,
            explanation,
        }
    }
}

impl EnhancedIrExport {
    /// Create an enhanced IR export from objects and generate document summary
    pub fn new(objects: Vec<EnhancedPdfIrObject>) -> Self {
        let document_summary = DocumentSummary::from_objects(&objects);
        Self { objects, document_summary }
    }
}

impl DocumentSummary {
    /// Generate document summary from enhanced IR objects
    pub fn from_objects(objects: &[EnhancedPdfIrObject]) -> Self {
        let total_objects = objects.len();
        let objects_with_findings = objects.iter().filter(|o| !o.findings.is_empty()).count();
        let max_object_risk = objects.iter().map(|o| o.risk_score).fold(0.0f32, f32::max);

        // Count distinct attack surfaces
        let all_surfaces: HashSet<_> =
            objects.iter().flat_map(|o| o.attack_surfaces.iter()).collect();
        let attack_surface_diversity = all_surfaces.len();

        // Count by severity
        let mut severity_counts: HashMap<String, usize> = HashMap::new();
        for obj in objects {
            for finding in &obj.findings {
                *severity_counts.entry(finding.severity.clone()).or_insert(0) += 1;
            }
        }

        // Count by attack surface
        let mut surface_counts: HashMap<String, usize> = HashMap::new();
        for obj in objects {
            for finding in &obj.findings {
                *surface_counts.entry(finding.surface.clone()).or_insert(0) += 1;
            }
        }

        // Generate explanation
        let explanation = generate_document_explanation(
            total_objects,
            objects_with_findings,
            max_object_risk,
            &severity_counts,
            &surface_counts,
        );

        Self {
            total_objects,
            objects_with_findings,
            max_object_risk,
            attack_surface_diversity,
            explanation,
            severity_counts,
            surface_counts,
        }
    }
}

/// Extract signals from finding metadata
fn extract_signals_from_meta(meta: &HashMap<String, String>) -> HashMap<String, serde_json::Value> {
    let mut signals = HashMap::new();

    for (key, value) in meta {
        // Try to parse as different types
        if let Ok(num) = value.parse::<f64>() {
            signals.insert(key.clone(), serde_json::json!(num));
        } else if let Ok(b) = value.parse::<bool>() {
            signals.insert(key.clone(), serde_json::json!(b));
        } else {
            signals.insert(key.clone(), serde_json::json!(value));
        }
    }

    signals
}

/// Compute risk score for an object based on its findings
fn compute_object_risk_score(findings: &[&Finding]) -> f32 {
    if findings.is_empty() {
        return 0.0;
    }

    // Weighted sum by severity
    let severity_weight: f32 = findings
        .iter()
        .map(|f| match f.severity {
            Severity::Critical => 1.0,
            Severity::High => 0.8,
            Severity::Medium => 0.5,
            Severity::Low => 0.2,
            Severity::Info => 0.0,
        })
        .sum();

    // Average confidence multiplier
    let confidence_mult = findings
        .iter()
        .map(|f| match f.confidence {
            Confidence::Certain | Confidence::Strong => 1.0,
            Confidence::Probable => 0.7,
            Confidence::Tentative => 0.5,
            Confidence::Weak => 0.3,
            Confidence::Heuristic => 0.4,
        })
        .sum::<f32>()
        / findings.len() as f32;

    // Normalize by number of findings and clamp to [0, 1]
    (severity_weight * confidence_mult / findings.len() as f32).min(1.0)
}

/// Generate natural language explanation for an object
fn generate_object_explanation(findings: &[&Finding]) -> String {
    if findings.is_empty() {
        return String::new();
    }

    let critical_count = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high_count = findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium_count = findings.iter().filter(|f| f.severity == Severity::Medium).count();

    // Collect unique surfaces
    let surfaces: HashSet<_> = findings.iter().map(|f| format!("{:?}", f.surface)).collect();
    let surface_list = if surfaces.len() <= 3 {
        surfaces.into_iter().collect::<Vec<_>>().join(", ")
    } else {
        format!("{} distinct attack surfaces", surfaces.len())
    };

    // Build explanation
    let mut parts = vec![];

    if critical_count > 0 {
        parts.push(format!(
            "{} critical issue{}",
            critical_count,
            if critical_count > 1 { "s" } else { "" }
        ));
    }
    if high_count > 0 {
        parts.push(format!(
            "{} high severity issue{}",
            high_count,
            if high_count > 1 { "s" } else { "" }
        ));
    }
    if medium_count > 0 && critical_count == 0 && high_count == 0 {
        parts.push(format!(
            "{} medium severity issue{}",
            medium_count,
            if medium_count > 1 { "s" } else { "" }
        ));
    }

    let severity_desc =
        if parts.is_empty() { "Low severity issues".to_string() } else { parts.join(", ") };

    format!("Object contains {}. Attack surfaces: {}", severity_desc, surface_list)
}

/// Generate natural language explanation for the entire document
fn generate_document_explanation(
    total_objects: usize,
    objects_with_findings: usize,
    max_risk: f32,
    severity_counts: &HashMap<String, usize>,
    surface_counts: &HashMap<String, usize>,
) -> String {
    if objects_with_findings == 0 {
        return format!(
            "Clean document with {} objects and no security findings detected.",
            total_objects
        );
    }

    let critical = severity_counts.get("Critical").copied().unwrap_or(0);
    let high = severity_counts.get("High").copied().unwrap_or(0);
    let medium = severity_counts.get("Medium").copied().unwrap_or(0);

    let risk_level = if max_risk > 0.8 {
        "very high risk"
    } else if max_risk > 0.6 {
        "high risk"
    } else if max_risk > 0.4 {
        "moderate risk"
    } else {
        "low risk"
    };

    let mut severity_parts = vec![];
    if critical > 0 {
        severity_parts.push(format!("{} critical", critical));
    }
    if high > 0 {
        severity_parts.push(format!("{} high", high));
    }
    if medium > 0 {
        severity_parts.push(format!("{} medium", medium));
    }

    let severity_desc = if severity_parts.is_empty() {
        "low severity issues".to_string()
    } else {
        severity_parts.join(", ")
    };

    // Top attack surfaces
    let mut surface_vec: Vec<_> = surface_counts.iter().collect();
    surface_vec.sort_by(|a, b| b.1.cmp(a.1));
    let top_surfaces: Vec<String> =
        surface_vec.iter().take(3).map(|(s, c)| format!("{} ({})", s, c)).collect();

    format!(
        "Document contains {} objects, {} with findings ({}). {} with {}. Primary attack surfaces: {}",
        total_objects,
        objects_with_findings,
        risk_level,
        severity_desc,
        if objects_with_findings == 1 { "finding" } else { "findings" },
        top_surfaces.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AttackSurface;

    fn create_test_finding(
        kind: &str,
        severity: Severity,
        confidence: Confidence,
        surface: AttackSurface,
        obj_id: u32,
    ) -> Finding {
        let mut meta = HashMap::new();
        meta.insert("test_key".to_string(), "test_value".to_string());

        Finding {
            id: format!("test-{}", kind),
            kind: kind.to_string(),
            severity,
            confidence,
            surface,
            title: format!("Test {}", kind),
            description: format!("Test finding for {}", kind),
            objects: vec![format!("{} 0 obj", obj_id)],
            evidence: vec![],
            remediation: None,
            positions: Vec::new(),
            meta,
            yara: None,
            ..Finding::default()
        }
    }

    #[test]
    fn test_enhanced_ir_object_creation() {
        let findings = vec![
            create_test_finding(
                "js_eval",
                Severity::High,
                Confidence::Strong,
                AttackSurface::JavaScript,
                1,
            ),
            create_test_finding(
                "xref_conflict",
                Severity::Medium,
                Confidence::Probable,
                AttackSurface::FileStructure,
                1,
            ),
        ];

        let enhanced = EnhancedPdfIrObject::from_basic_ir((1, 0), vec![], vec![], &findings);

        assert_eq!(enhanced.obj_ref, (1, 0));
        assert_eq!(enhanced.findings.len(), 2);
        assert!(enhanced.risk_score > 0.0);
        assert!(enhanced.explanation.is_some());
        assert_eq!(enhanced.attack_surfaces.len(), 2);
        assert_eq!(enhanced.max_severity, Some("High".to_string()));
    }

    #[test]
    fn test_object_risk_score_empty() {
        let score = compute_object_risk_score(&[]);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_object_risk_score_critical() {
        let finding = create_test_finding(
            "test",
            Severity::Critical,
            Confidence::Strong,
            AttackSurface::JavaScript,
            1,
        );
        let score = compute_object_risk_score(&[&finding]);
        assert!(score > 0.9); // Critical + Strong should be near 1.0
    }

    #[test]
    fn test_object_risk_score_weighted() {
        let f1 = create_test_finding(
            "test1",
            Severity::High,
            Confidence::Strong,
            AttackSurface::JavaScript,
            1,
        );
        let f2 = create_test_finding(
            "test2",
            Severity::Low,
            Confidence::Heuristic,
            AttackSurface::FileStructure,
            1,
        );
        let score = compute_object_risk_score(&[&f1, &f2]);

        // severity_weight = 0.8 + 0.2 = 1.0
        // confidence_mult = (1.0 + 0.4) / 2 = 0.7
        // result = (1.0 * 0.7) / 2 = 0.35
        assert!(score > 0.3 && score < 0.4);
    }

    #[test]
    fn test_object_explanation_generation() {
        let findings = vec![
            create_test_finding(
                "js_eval",
                Severity::Critical,
                Confidence::Strong,
                AttackSurface::JavaScript,
                1,
            ),
            create_test_finding(
                "aa_launch",
                Severity::High,
                Confidence::Strong,
                AttackSurface::Actions,
                1,
            ),
        ];
        let refs: Vec<_> = findings.iter().collect();

        let explanation = generate_object_explanation(&refs);

        assert!(explanation.contains("1 critical issue"));
        assert!(explanation.contains("1 high severity issue"));
        assert!(explanation.contains("Attack surfaces"));
    }

    #[test]
    fn test_document_summary_clean() {
        let objects = vec![];
        let summary = DocumentSummary::from_objects(&objects);

        assert_eq!(summary.total_objects, 0);
        assert_eq!(summary.objects_with_findings, 0);
        assert_eq!(summary.max_object_risk, 0.0);
        assert!(summary.explanation.contains("Clean document"));
    }

    #[test]
    fn test_document_summary_with_findings() {
        let findings = vec![create_test_finding(
            "js_eval",
            Severity::Critical,
            Confidence::Strong,
            AttackSurface::JavaScript,
            1,
        )];

        let obj1 = EnhancedPdfIrObject::from_basic_ir((1, 0), vec![], vec![], &findings);
        let obj2 = EnhancedPdfIrObject::from_basic_ir((2, 0), vec![], vec![], &[]);

        let summary = DocumentSummary::from_objects(&[obj1, obj2]);

        assert_eq!(summary.total_objects, 2);
        assert_eq!(summary.objects_with_findings, 1);
        assert!(summary.max_object_risk > 0.0);
        assert_eq!(summary.severity_counts.get("Critical"), Some(&1));
        assert!(
            summary.explanation.contains("very high risk")
                || summary.explanation.contains("high risk")
        );
    }

    #[test]
    fn test_extract_signals_from_meta() {
        let mut meta = HashMap::new();
        meta.insert("score".to_string(), "0.85".to_string());
        meta.insert("enabled".to_string(), "true".to_string());
        meta.insert("name".to_string(), "test".to_string());

        let signals = extract_signals_from_meta(&meta);

        assert_eq!(signals.len(), 3);
        assert!(signals.contains_key("score"));
        assert!(signals.contains_key("enabled"));
        assert!(signals.contains_key("name"));
    }

    #[test]
    fn test_enhanced_ir_export_creation() {
        let findings = vec![create_test_finding(
            "js_eval",
            Severity::High,
            Confidence::Strong,
            AttackSurface::JavaScript,
            1,
        )];

        let obj1 = EnhancedPdfIrObject::from_basic_ir((1, 0), vec![], vec![], &findings);
        let export = EnhancedIrExport::new(vec![obj1]);

        assert_eq!(export.objects.len(), 1);
        assert_eq!(export.document_summary.total_objects, 1);
        assert_eq!(export.document_summary.objects_with_findings, 1);
    }

    #[test]
    fn test_ir_finding_summary_serialization() -> serde_json::Result<()> {
        let summary = IrFindingSummary {
            kind: "test".to_string(),
            severity: "High".to_string(),
            confidence: "Strong".to_string(),
            surface: "JavaScript".to_string(),
            signals: HashMap::new(),
        };

        let json = serde_json::to_string(&summary)?;
        let deserialized: IrFindingSummary = serde_json::from_str(&json)?;

        assert_eq!(deserialized.kind, "test");
        assert_eq!(deserialized.severity, "High");
        Ok(())
    }
}
