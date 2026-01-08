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

/// Compute permutation importance for feature attribution
///
/// This is a model-agnostic approach where each feature is replaced with its baseline value
/// and the change in prediction is measured. The difference is the feature's contribution.
///
/// # Arguments
/// * `model` - Function that takes feature values and returns prediction
/// * `feature_values` - Original feature values as flat vector
/// * `feature_names` - Names of all features
/// * `baseline` - Benign baseline statistics
///
/// # Returns
/// Vector of feature attributions sorted by absolute contribution
pub fn compute_permutation_importance(
    model: &dyn Fn(&[f32]) -> f32,
    feature_values: &[f32],
    feature_names: &[String],
    baseline: &BenignBaseline,
) -> Vec<FeatureAttribution> {
    let original_pred = model(feature_values);
    let mut attributions = Vec::new();

    for (idx, (name, &value)) in feature_names.iter().zip(feature_values).enumerate() {
        // Get baseline value for this feature
        let baseline_value = baseline.feature_means.get(name).copied().unwrap_or(0.0);

        // Create permuted feature vector with this feature set to baseline
        let mut permuted = feature_values.to_vec();
        permuted[idx] = baseline_value;

        // Measure prediction change
        let permuted_pred = model(&permuted);
        let contribution = original_pred - permuted_pred;

        // Compute percentile
        let percentile = if let Some(pcts) = baseline.feature_percentiles.get(name) {
            compute_percentile(value, pcts)
        } else {
            50.0
        };

        attributions.push(FeatureAttribution {
            feature_name: name.clone(),
            value,
            contribution,
            baseline: baseline_value,
            percentile,
        });
    }

    // Sort by absolute contribution (most impactful features first)
    attributions.sort_by(|a, b| b.contribution.abs().partial_cmp(&a.contribution.abs()).unwrap());
    attributions
}

/// Compute feature group importance from individual feature attributions
///
/// Groups features by their prefix (e.g., "js_signals.", "uri_signals.") and sums
/// the absolute contributions within each group.
pub fn compute_feature_group_importance(
    attributions: &[FeatureAttribution],
) -> HashMap<String, f32> {
    let mut group_importance: HashMap<String, f32> = HashMap::new();

    for attr in attributions {
        // Extract group name from feature name (everything before the last dot)
        let group = if let Some(dot_pos) = attr.feature_name.rfind('.') {
            &attr.feature_name[..dot_pos]
        } else {
            "legacy"
        };

        *group_importance.entry(group.to_string()).or_insert(0.0) += attr.contribution.abs();
    }

    group_importance
}

/// Create a complete ML explanation from prediction and feature attributions
///
/// # Arguments
/// * `prediction` - Model prediction score
/// * `attributions` - All feature attributions
/// * `baseline` - Benign baseline for baseline_score
/// * `findings` - PDF findings for context in summary
///
/// # Returns
/// Complete MlExplanation with top features, group importance, and summary
pub fn create_ml_explanation(
    prediction: f32,
    attributions: Vec<FeatureAttribution>,
    baseline: &BenignBaseline,
    findings: &[Finding],
) -> MlExplanation {
    // Compute baseline score (average of benign means)
    let baseline_score = if !baseline.feature_means.is_empty() {
        baseline.feature_means.values().sum::<f32>() / baseline.feature_means.len() as f32
    } else {
        0.0
    };

    // Split into positive and negative contributions
    let mut positive_features: Vec<_> = attributions
        .iter()
        .filter(|a| a.contribution > 0.0)
        .cloned()
        .collect();
    positive_features.sort_by(|a, b| b.contribution.partial_cmp(&a.contribution).unwrap());
    positive_features.truncate(10);

    let mut negative_features: Vec<_> = attributions
        .iter()
        .filter(|a| a.contribution < 0.0)
        .cloned()
        .collect();
    negative_features.sort_by(|a, b| a.contribution.partial_cmp(&b.contribution).unwrap());
    negative_features.truncate(10);

    // Compute group importance
    let feature_group_importance = compute_feature_group_importance(&attributions);

    // Generate natural language summary
    let summary = generate_explanation_text(prediction, &positive_features, findings);

    MlExplanation {
        prediction,
        baseline_score,
        top_positive_features: positive_features,
        top_negative_features: negative_features,
        feature_group_importance,
        summary,
    }
}

/// Compute baseline statistics from a collection of benign samples
///
/// # Arguments
/// * `benign_feature_maps` - Vector of feature name -> value maps from benign PDFs
///
/// # Returns
/// BenignBaseline with computed means, stddevs, and percentiles
pub fn compute_baseline_from_samples(
    benign_feature_maps: &[HashMap<String, f32>],
) -> BenignBaseline {
    if benign_feature_maps.is_empty() {
        return BenignBaseline::default();
    }

    let mut feature_means = HashMap::new();
    let mut feature_stddevs = HashMap::new();
    let mut feature_percentiles = HashMap::new();

    // Collect all feature names
    let mut all_features = std::collections::HashSet::new();
    for map in benign_feature_maps {
        all_features.extend(map.keys().cloned());
    }

    // Compute statistics for each feature
    for feature_name in all_features {
        let mut values: Vec<f32> = benign_feature_maps
            .iter()
            .filter_map(|m| m.get(&feature_name).copied())
            .collect();

        if values.is_empty() {
            continue;
        }

        // Compute mean
        let mean = values.iter().sum::<f32>() / values.len() as f32;
        feature_means.insert(feature_name.clone(), mean);

        // Compute stddev
        let variance = values.iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f32>() / values.len() as f32;
        let stddev = variance.sqrt();
        feature_stddevs.insert(feature_name.clone(), stddev);

        // Compute percentiles
        values.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let percentiles = vec![
            compute_nth_percentile(&values, 10.0),
            compute_nth_percentile(&values, 25.0),
            compute_nth_percentile(&values, 50.0),
            compute_nth_percentile(&values, 75.0),
            compute_nth_percentile(&values, 90.0),
            compute_nth_percentile(&values, 95.0),
            compute_nth_percentile(&values, 99.0),
        ];
        feature_percentiles.insert(feature_name, percentiles);
    }

    BenignBaseline {
        feature_means,
        feature_stddevs,
        feature_percentiles,
    }
}

/// Compute the nth percentile from a sorted array
fn compute_nth_percentile(sorted_values: &[f32], percentile: f32) -> f32 {
    if sorted_values.is_empty() {
        return 0.0;
    }

    let index = (percentile / 100.0 * (sorted_values.len() - 1) as f32).round() as usize;
    sorted_values[index.min(sorted_values.len() - 1)]
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
            "unknown feature"  // Underscores replaced with spaces
        );
        assert_eq!(
            humanize_feature_name("group.feature_name"),
            "group: feature name"  // Both dots and underscores replaced
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

    #[test]
    fn test_compute_permutation_importance() {
        // Mock model that returns sum of features
        let model = |features: &[f32]| -> f32 {
            features.iter().sum::<f32>() / features.len() as f32
        };

        let feature_values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let feature_names = vec![
            "feature_a".to_string(),
            "feature_b".to_string(),
            "feature_c".to_string(),
            "feature_d".to_string(),
            "feature_e".to_string(),
        ];

        let mut baseline = BenignBaseline::default();
        baseline.feature_means.insert("feature_a".to_string(), 0.5);
        baseline.feature_means.insert("feature_b".to_string(), 1.0);
        baseline.feature_means.insert("feature_c".to_string(), 1.5);
        baseline.feature_means.insert("feature_d".to_string(), 2.0);
        baseline.feature_means.insert("feature_e".to_string(), 2.5);

        let attributions = compute_permutation_importance(
            &model,
            &feature_values,
            &feature_names,
            &baseline,
        );

        assert_eq!(attributions.len(), 5);

        // All contributions should be positive since we're replacing with smaller values
        for attr in &attributions {
            assert!(attr.contribution >= 0.0,
                "Feature {} contribution should be positive: {}",
                attr.feature_name, attr.contribution);
        }

        // Should be sorted by absolute contribution
        for i in 0..attributions.len()-1 {
            assert!(attributions[i].contribution.abs() >= attributions[i+1].contribution.abs(),
                "Attributions should be sorted by absolute contribution");
        }
    }

    #[test]
    fn test_compute_feature_group_importance() {
        let attributions = vec![
            FeatureAttribution {
                feature_name: "js_signals.obfuscation".to_string(),
                value: 0.8,
                contribution: 0.15,
                baseline: 0.1,
                percentile: 95.0,
            },
            FeatureAttribution {
                feature_name: "js_signals.eval_count".to_string(),
                value: 5.0,
                contribution: 0.10,
                baseline: 0.0,
                percentile: 98.0,
            },
            FeatureAttribution {
                feature_name: "uri_signals.ip_address".to_string(),
                value: 1.0,
                contribution: 0.08,
                baseline: 0.0,
                percentile: 90.0,
            },
            FeatureAttribution {
                feature_name: "general.file_size".to_string(),
                value: 1000.0,
                contribution: 0.02,
                baseline: 500.0,
                percentile: 60.0,
            },
        ];

        let group_importance = compute_feature_group_importance(&attributions);

        assert!(group_importance.contains_key("js_signals"));
        assert!(group_importance.contains_key("uri_signals"));
        assert!(group_importance.contains_key("general"));

        // JS signals should have highest importance (0.15 + 0.10 = 0.25)
        assert_eq!(group_importance.get("js_signals").unwrap(), &0.25);
        assert_eq!(group_importance.get("uri_signals").unwrap(), &0.08);
        assert_eq!(group_importance.get("general").unwrap(), &0.02);
    }

    #[test]
    fn test_create_ml_explanation() {
        let attributions = vec![
            FeatureAttribution {
                feature_name: "js_signals.max_obfuscation_score".to_string(),
                value: 0.9,
                contribution: 0.20,
                baseline: 0.1,
                percentile: 99.0,
            },
            FeatureAttribution {
                feature_name: "uri_signals.ip_address_count".to_string(),
                value: 2.0,
                contribution: 0.15,
                baseline: 0.0,
                percentile: 95.0,
            },
            FeatureAttribution {
                feature_name: "general.object_count".to_string(),
                value: 100.0,
                contribution: -0.05, // Negative contribution
                baseline: 150.0,
                percentile: 40.0,
            },
        ];

        let mut baseline = BenignBaseline::default();
        baseline.feature_means.insert("test".to_string(), 0.5);

        let findings = vec![];

        let explanation = create_ml_explanation(
            0.85,
            attributions,
            &baseline,
            &findings,
        );

        assert_eq!(explanation.prediction, 0.85);
        assert_eq!(explanation.top_positive_features.len(), 2);
        assert_eq!(explanation.top_negative_features.len(), 1);

        // Check positive features are sorted correctly
        assert_eq!(explanation.top_positive_features[0].feature_name,
            "js_signals.max_obfuscation_score");
        assert_eq!(explanation.top_positive_features[1].feature_name,
            "uri_signals.ip_address_count");

        // Check group importance
        assert!(explanation.feature_group_importance.contains_key("js_signals"));
        assert!(explanation.feature_group_importance.contains_key("uri_signals"));

        // Check summary is generated
        assert!(!explanation.summary.is_empty());
        assert!(explanation.summary.contains("suspicious"));
    }

    #[test]
    fn test_compute_baseline_from_samples() {
        let mut sample1 = HashMap::new();
        sample1.insert("feature_a".to_string(), 1.0);
        sample1.insert("feature_b".to_string(), 2.0);
        sample1.insert("feature_c".to_string(), 3.0);

        let mut sample2 = HashMap::new();
        sample2.insert("feature_a".to_string(), 3.0);
        sample2.insert("feature_b".to_string(), 4.0);
        sample2.insert("feature_c".to_string(), 5.0);

        let mut sample3 = HashMap::new();
        sample3.insert("feature_a".to_string(), 5.0);
        sample3.insert("feature_b".to_string(), 6.0);
        sample3.insert("feature_c".to_string(), 7.0);

        let samples = vec![sample1, sample2, sample3];

        let baseline = compute_baseline_from_samples(&samples);

        // Check means
        assert_eq!(baseline.feature_means.get("feature_a").unwrap(), &3.0); // (1+3+5)/3
        assert_eq!(baseline.feature_means.get("feature_b").unwrap(), &4.0); // (2+4+6)/3
        assert_eq!(baseline.feature_means.get("feature_c").unwrap(), &5.0); // (3+5+7)/3

        // Check stddevs exist
        assert!(baseline.feature_stddevs.contains_key("feature_a"));
        assert!(baseline.feature_stddevs.get("feature_a").unwrap() > &0.0);

        // Check percentiles
        assert!(baseline.feature_percentiles.contains_key("feature_a"));
        assert_eq!(baseline.feature_percentiles.get("feature_a").unwrap().len(), 7);
    }

    #[test]
    fn test_compute_nth_percentile() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];

        assert_eq!(compute_nth_percentile(&values, 0.0), 1.0);   // Min (index 0)
        assert_eq!(compute_nth_percentile(&values, 50.0), 6.0);  // Median (index 5 after rounding 4.5)
        assert_eq!(compute_nth_percentile(&values, 100.0), 10.0); // Max (index 9)

        // Test with smaller array
        let small = vec![1.0, 5.0, 10.0];
        assert_eq!(compute_nth_percentile(&small, 50.0), 5.0);  // Index 1
        assert_eq!(compute_nth_percentile(&small, 0.0), 1.0);
        assert_eq!(compute_nth_percentile(&small, 100.0), 10.0);
    }

    #[test]
    fn test_compute_nth_percentile_empty() {
        let values = vec![];
        assert_eq!(compute_nth_percentile(&values, 50.0), 0.0);
    }

    #[test]
    fn test_baseline_save_and_load() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("baseline.json");

        let mut baseline = BenignBaseline::default();
        baseline.feature_means.insert("test_feature".to_string(), 1.5);
        baseline.feature_stddevs.insert("test_feature".to_string(), 0.5);
        baseline.feature_percentiles.insert(
            "test_feature".to_string(),
            vec![0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 3.5],
        );

        // Save
        baseline.save_to_file(&file_path).unwrap();

        // Load
        let loaded = BenignBaseline::load_from_file(&file_path).unwrap();

        assert_eq!(loaded.feature_means.get("test_feature").unwrap(), &1.5);
        assert_eq!(loaded.feature_stddevs.get("test_feature").unwrap(), &0.5);
        assert_eq!(loaded.feature_percentiles.get("test_feature").unwrap().len(), 7);
    }

    #[test]
    fn test_feature_group_importance_with_negative_contributions() {
        let attributions = vec![
            FeatureAttribution {
                feature_name: "js_signals.obfuscation".to_string(),
                value: 0.8,
                contribution: 0.15,
                baseline: 0.1,
                percentile: 95.0,
            },
            FeatureAttribution {
                feature_name: "js_signals.eval_count".to_string(),
                value: 5.0,
                contribution: -0.10, // Negative contribution
                baseline: 0.0,
                percentile: 98.0,
            },
        ];

        let group_importance = compute_feature_group_importance(&attributions);

        // Should sum absolute values: |0.15| + |-0.10| = 0.25
        assert_eq!(group_importance.get("js_signals").unwrap(), &0.25);
    }
}
