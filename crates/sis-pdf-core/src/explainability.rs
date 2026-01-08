// ML Explainability Module
//
// Provides structures and functions for explaining ML predictions:
// - Feature attribution (SHAP-like importance scores)
// - Natural language explanation generation
// - Evidence chain linking (features → findings → byte offsets)
// - Comparative analysis against benign baselines

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::model::{Finding, Severity, AttackSurface, EvidenceSpan};

/// Feature attribution showing how much a feature contributed to the prediction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureAttribution {
    pub feature_name: String,
    pub value: f32,
    pub contribution: f32,      // How much this feature contributed to the prediction
    pub baseline: f32,          // Expected value for benign files
    pub percentile: f32,        // Percentile in benign distribution (0-100)
}

/// Comprehensive ML explanation combining multiple explanation methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlExplanation {
    pub prediction: f32,
    pub baseline_score: f32,
    pub top_positive_features: Vec<FeatureAttribution>,  // Top 10 features increasing risk
    pub top_negative_features: Vec<FeatureAttribution>,  // Top 10 features decreasing risk
    pub feature_group_importance: HashMap<String, f32>,  // Importance per feature category
    pub summary: String,                                 // Natural language explanation
}

/// Benign baseline statistics for comparative analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenignBaseline {
    pub feature_means: HashMap<String, f32>,
    pub feature_stddevs: HashMap<String, f32>,
    pub feature_percentiles: HashMap<String, Vec<f32>>,  // [P10, P25, P50, P75, P90, P95, P99]
}

impl Default for BenignBaseline {
    fn default() -> Self {
        Self {
            feature_means: HashMap::new(),
            feature_stddevs: HashMap::new(),
            feature_percentiles: HashMap::new(),
        }
    }
}

impl BenignBaseline {
    /// Load baseline from JSON file
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let baseline: BenignBaseline = serde_json::from_str(&content)?;
        Ok(baseline)
    }

    /// Save baseline to JSON file
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

/// Evidence chain linking features to findings to byte offsets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceChain {
    pub feature_name: String,
    pub feature_value: f32,
    pub contribution: f32,
    pub derived_from_findings: Vec<String>,  // Finding kinds
    pub evidence_spans: Vec<EvidenceSpan>,
}

/// Comparative feature showing how this file differs from benign baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparativeFeature {
    pub feature_name: String,
    pub value: f32,
    pub benign_mean: f32,
    pub benign_stddev: f32,
    pub z_score: f32,
    pub percentile: f32,
    pub interpretation: String,
}

/// Compute percentile from percentile array [P10, P25, P50, P75, P90, P95, P99]
pub fn compute_percentile(value: f32, percentiles: &[f32]) -> f32 {
    if percentiles.len() != 7 {
        return 50.0;  // Default to median if invalid
    }

    if value <= percentiles[0] { return 10.0; }
    if value >= percentiles[6] { return 99.0; }

    // Linear interpolation
    let pct_values = [10.0, 25.0, 50.0, 75.0, 90.0, 95.0, 99.0];
    for i in 0..percentiles.len()-1 {
        if value >= percentiles[i] && value <= percentiles[i+1] {
            let ratio = (value - percentiles[i]) / (percentiles[i+1] - percentiles[i]);
            return pct_values[i] + ratio * (pct_values[i+1] - pct_values[i]);
        }
    }

    50.0  // Fallback
}

/// Build evidence chains from feature attribution and findings
pub fn build_evidence_chains(
    attribution: &[FeatureAttribution],
    findings: &[Finding],
) -> Vec<EvidenceChain> {
    let mut chains = Vec::new();

    for attr in attribution.iter().take(20) {  // Top 20 features
        let relevant_findings = find_contributing_findings(&attr.feature_name, findings);
        let evidence_spans: Vec<_> = relevant_findings
            .iter()
            .flat_map(|f| f.evidence.clone())
            .collect();

        if !relevant_findings.is_empty() {
            chains.push(EvidenceChain {
                feature_name: attr.feature_name.clone(),
                feature_value: attr.value,
                contribution: attr.contribution,
                derived_from_findings: relevant_findings.iter()
                    .map(|f| f.kind.clone())
                    .collect(),
                evidence_spans,
            });
        }
    }

    chains
}

/// Find findings that contributed to a specific feature
fn find_contributing_findings<'a>(feature_name: &str, findings: &'a [Finding]) -> Vec<&'a Finding> {

    // Map feature names to finding types
    if feature_name.starts_with("js_signals.") {
        findings.iter().filter(|f| f.surface == AttackSurface::JavaScript).collect()
    } else if feature_name.starts_with("uri_signals.") {
        findings.iter().filter(|f| f.kind.contains("uri")).collect()
    } else if feature_name.starts_with("finding.") {
        let kind = feature_name.strip_prefix("finding.").unwrap()
            .strip_suffix("_count").or_else(|| feature_name.strip_suffix("_present"))
            .unwrap_or(feature_name);
        findings.iter().filter(|f| f.kind == kind).collect()
    } else if feature_name.starts_with("supply_chain") {
        findings.iter().filter(|f| f.kind.starts_with("supply_chain")).collect()
    } else if feature_name.starts_with("crypto_signals.") {
        findings.iter().filter(|f| f.kind.starts_with("crypto_")).collect()
    } else if feature_name.starts_with("embedded_content.") {
        findings.iter().filter(|f| f.surface == AttackSurface::EmbeddedFiles).collect()
    } else if feature_name.starts_with("action_chains.") {
        findings.iter().filter(|f| f.surface == AttackSurface::Actions).collect()
    } else {
        Vec::new()
    }
}

/// Generate natural language explanation from prediction and findings
pub fn generate_explanation_text(
    prediction: f32,
    top_features: &[FeatureAttribution],
    findings: &[Finding],
) -> String {

    let severity_level = match prediction {
        p if p > 0.8 => "highly",
        p if p > 0.6 => "moderately",
        _ => "somewhat",
    };

    let mut summary = format!(
        "This PDF is {} suspicious (ML risk score: {:.2}). ",
        severity_level, prediction
    );

    // Primary threat vector
    if let Some(top) = top_features.first() {
        summary.push_str(&format!(
            "The strongest indicator is {} (value: {:.2}, contribution: {:+.2}, baseline: {:.2}). ",
            humanize_feature_name(&top.feature_name),
            top.value,
            top.contribution,
            top.baseline
        ));
    }

    // High-severity findings
    let high_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::High || f.severity == Severity::Critical)
        .collect();

    if !high_findings.is_empty() {
        summary.push_str(&format!(
            "Found {} high-severity issues: ",
            high_findings.len()
        ));

        for (i, f) in high_findings.iter().take(3).enumerate() {
            if i > 0 { summary.push_str(", "); }
            summary.push_str(&humanize_finding_kind(&f.kind));
        }

        if high_findings.len() > 3 {
            summary.push_str(&format!(", and {} more", high_findings.len() - 3));
        }
        summary.push_str(". ");
    }

    // Attack pattern recognition
    let attack_pattern = recognize_attack_pattern(findings);
    if let Some(pattern) = attack_pattern {
        summary.push_str(&format!("This appears to be a {}. ", pattern));
    }

    // Recommendation
    let recommendation = match prediction {
        p if p > 0.8 => "Recommend: Block and investigate in sandbox environment.",
        p if p > 0.6 => "Recommend: Flag for manual review before allowing.",
        p if p > 0.4 => "Recommend: Monitor and log for security audit.",
        _ => "Recommend: Allow with standard monitoring.",
    };
    summary.push_str(recommendation);

    summary
}

/// Convert feature name to human-readable description
pub fn humanize_feature_name(name: &str) -> String {
    match name {
        "js_signals.max_obfuscation_score" => "highly obfuscated JavaScript".to_string(),
        "finding.js_polymorphic_count" => "polymorphic JavaScript patterns".to_string(),
        "action_chains.automatic_trigger_count" => "automatic action triggers".to_string(),
        "uri_signals.ip_address_count" => "URIs with direct IP addresses".to_string(),
        "js_signals.time_evasion_present" => "time-based evasion in JavaScript".to_string(),
        "supply_chain.multi_stage_chains" => "multi-stage attack chains".to_string(),
        "graph.js_payload_edges" => "JavaScript payload references".to_string(),
        "graph.open_action_edges" => "automatic OpenAction triggers".to_string(),
        "uri_signals.hidden_annotation_count" => "hidden URI annotations".to_string(),
        "embedded_content.file_count" => "embedded files".to_string(),
        // Fallback: convert underscores to spaces
        _ => name.replace("_", " ").replace(".", ": ")
    }
}

/// Convert finding kind to human-readable description
fn humanize_finding_kind(kind: &str) -> String {
    match kind {
        "js_polymorphic" => "polymorphic JavaScript".to_string(),
        "js_obfuscation_deep" => "deeply obfuscated JavaScript".to_string(),
        "open_action_present" => "automatic OpenAction trigger".to_string(),
        "uri_content_analysis" => "suspicious URI with obfuscation".to_string(),
        "multi_stage_attack_chain" => "multi-stage attack chain".to_string(),
        "supply_chain_persistence" => "supply chain persistence mechanism".to_string(),
        _ => kind.replace("_", " ")
    }
}

/// Recognize attack patterns from findings
fn recognize_attack_pattern(findings: &[Finding]) -> Option<String> {

    let has_js = findings.iter().any(|f| f.surface == AttackSurface::JavaScript);
    let has_obf = findings.iter().any(|f| f.kind.contains("obfuscation"));
    let has_auto = findings.iter().any(|f| f.kind.contains("open_action"));
    let has_uri = findings.iter().any(|f| f.surface == AttackSurface::Actions && f.kind.contains("uri"));
    let has_embed = findings.iter().any(|f| f.surface == AttackSurface::EmbeddedFiles);
    let has_multi = findings.iter().any(|f| f.kind.contains("multi_stage"));

    if has_js && has_obf && has_auto && has_uri {
        Some("sophisticated phishing attack with automatic JavaScript execution".to_string())
    } else if has_js && has_multi && has_embed {
        Some("multi-stage malware delivery via embedded payloads".to_string())
    } else if has_js && has_obf {
        Some("JavaScript-based attack with obfuscation".to_string())
    } else if has_auto && has_uri {
        Some("automatic external resource loading".to_string())
    } else {
        None
    }
}

/// Compute comparative explanation showing how features differ from benign baseline
pub fn compute_comparative_explanation(
    feature_map: &HashMap<String, f32>,
    baseline: &BenignBaseline,
    top_n: usize,
) -> Vec<ComparativeFeature> {
    let mut comparisons = Vec::new();

    for (name, &value) in feature_map {
        let mean = baseline.feature_means.get(name).copied().unwrap_or(0.0);
        let stddev = baseline.feature_stddevs.get(name).copied().unwrap_or(1.0);
        let z_score = if stddev > 0.0 {
            (value - mean) / stddev
        } else {
            0.0
        };

        if z_score.abs() > 1.5 {  // More than 1.5 standard deviations
            let percentile = if let Some(pcts) = baseline.feature_percentiles.get(name) {
                compute_percentile(value, pcts)
            } else {
                50.0
            };

            let interpretation = if z_score > 0.0 {
                if z_score > 3.0 {
                    format!("Extremely high ({:.1}σ above benign average) - highly unusual", z_score)
                } else if z_score > 2.0 {
                    format!("Very high ({:.1}σ above benign average) - suspicious", z_score)
                } else {
                    format!("Higher than typical ({:.1}σ above benign average)", z_score)
                }
            } else {
                format!("Lower than typical ({:.1}σ below benign average)", z_score.abs())
            };

            comparisons.push(ComparativeFeature {
                feature_name: name.clone(),
                value,
                benign_mean: mean,
                benign_stddev: stddev,
                z_score,
                percentile,
                interpretation,
            });
        }
    }

    // Sort by absolute z-score
    comparisons.sort_by(|a, b| b.z_score.abs().partial_cmp(&a.z_score.abs()).unwrap());
    comparisons.truncate(top_n);
    comparisons
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_percentile_computation() {
        let percentiles = vec![10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0];

        assert_eq!(compute_percentile(5.0, &percentiles), 10.0);  // Below P10
        assert_eq!(compute_percentile(75.0, &percentiles), 99.0); // Above P99
        assert_eq!(compute_percentile(30.0, &percentiles), 50.0); // Exact P50
    }

    #[test]
    fn test_humanize_feature_name() {
        assert_eq!(
            humanize_feature_name("js_signals.max_obfuscation_score"),
            "highly obfuscated JavaScript"
        );
        assert_eq!(
            humanize_feature_name("unknown_feature"),
            "unknown: feature"
        );
    }

    #[test]
    fn test_explanation_text_generation() {
        let features = vec![
            FeatureAttribution {
                feature_name: "js_signals.max_obfuscation_score".to_string(),
                value: 0.95,
                contribution: 0.18,
                baseline: 0.0,
                percentile: 99.5,
            }
        ];

        let findings = vec![];
        let summary = generate_explanation_text(0.87, &features, &findings);

        assert!(summary.contains("highly suspicious"));
        assert!(summary.contains("obfuscated JavaScript"));
        assert!(summary.contains("Block and investigate"));
    }
}
