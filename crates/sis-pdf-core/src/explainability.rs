// ML Explainability Module
//
// Provides structures and functions for explaining ML predictions:
// - Feature attribution (SHAP-like importance scores)
// - Natural language explanation generation
// - Evidence chain linking (features → findings → byte offsets)
// - Comparative analysis against benign baselines

use crate::ml::LinearModel;
use crate::model::{AttackSurface, EvidenceSpan, Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Feature attribution showing how much a feature contributed to the prediction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureAttribution {
    pub feature_name: String,
    pub value: f32,
    pub contribution: f32, // How much this feature contributed to the prediction
    pub baseline: f32,     // Expected value for benign files
    pub percentile: f32,   // Percentile in benign distribution (0-100)
}

/// Comprehensive ML explanation combining multiple explanation methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlExplanation {
    pub prediction: f32,
    pub baseline_score: f32,
    pub top_positive_features: Vec<FeatureAttribution>, // Top 10 features increasing risk
    pub top_negative_features: Vec<FeatureAttribution>, // Top 10 features decreasing risk
    pub feature_group_importance: HashMap<String, f32>, // Importance per feature category
    pub summary: String,                                // Natural language explanation
}

/// Benign baseline statistics for comparative analysis
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BenignBaseline {
    pub feature_means: HashMap<String, f32>,
    pub feature_stddevs: HashMap<String, f32>,
    pub feature_percentiles: HashMap<String, Vec<f32>>, // [P10, P25, P50, P75, P90, P95, P99]
}

impl BenignBaseline {
    /// Load baseline from JSON file
    #[cfg(feature = "filesystem")]
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let baseline: BenignBaseline = serde_json::from_str(&content)?;
        Ok(baseline)
    }

    /// Save baseline to JSON file
    #[cfg(feature = "filesystem")]
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
    pub derived_from_findings: Vec<String>, // Finding kinds
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

// ============================================================================
// Graph Path Explainability
// ============================================================================

/// Explanation of suspicious paths through the PDF object graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphPathExplanation {
    /// Top suspicious paths found in the document
    pub suspicious_paths: Vec<SuspiciousPath>,
    /// Maximum risk score across all paths
    pub max_path_risk: f32,
    /// Average risk score across all paths
    pub avg_path_risk: f32,
}

/// A suspicious path through the PDF object graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousPath {
    /// Sequence of nodes in the path
    pub path: Vec<PathNode>,
    /// Computed risk score for this path (0.0-1.0)
    pub risk_score: f32,
    /// Natural language explanation of the path
    pub explanation: String,
    /// Classified attack pattern, if recognized
    pub attack_pattern: Option<String>,
}

/// A node in a suspicious path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathNode {
    /// Object reference (obj_id, gen_id)
    pub obj_ref: (u32, u16),
    /// Type of the node (Page, Action, JavaScript, etc.)
    pub node_type: String,
    /// Edge to the next node in the path
    pub edge_to_next: Option<EdgeInfo>,
    /// Finding kinds present at this node
    pub findings: Vec<String>,
}

/// Information about an edge in a path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeInfo {
    /// Type of the edge (Reference, JavaScriptPayload, UriTarget, etc.)
    pub edge_type: String,
    /// Dictionary key that created this edge (e.g., "/OpenAction", "/JS")
    pub key: String,
    /// Whether this edge is considered suspicious
    pub suspicious: bool,
}

// ============================================================================
// Document-Level Risk Profile
// ============================================================================

/// Comprehensive document-level risk assessment with calibrated predictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentRiskProfile {
    /// Calibrated ML prediction
    pub prediction: CalibratedPrediction,

    /// Basic statistics
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_severity_count: usize,
    pub medium_severity_count: usize,
    pub low_severity_count: usize,
    pub attack_surface_diversity: usize,
    pub max_confidence: String,

    // Category-specific risk profiles
    pub js_risk: JsRiskProfile,
    pub uri_risk: UriRiskProfile,
    pub structural_risk: StructuralRiskProfile,
    pub supply_chain_risk: SupplyChainRiskProfile,
    pub content_risk: ContentRiskProfile,
    pub crypto_risk: CryptoRiskProfile,

    // Comprehensive explanations
    pub explanation: MlExplanation,
    pub comparative_analysis: Vec<ComparativeFeature>,
    pub graph_paths: Option<GraphPathExplanation>,
    pub evidence_chains: Vec<EvidenceChain>,
}

/// Calibrated prediction with confidence intervals
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibratedPrediction {
    /// Raw model score (0.0-1.0)
    pub raw_score: f32,
    /// Calibrated probability (0.0-1.0)
    pub calibrated_score: f32,
    /// 95% confidence interval
    pub confidence_interval: (f32, f32),
    /// Calibration method used
    pub calibration_method: String,
    /// Human-readable interpretation
    pub interpretation: String,
}

/// JavaScript risk profile
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JsRiskProfile {
    pub present: bool,
    pub count: usize,
    pub max_obfuscation: f32,
    pub avg_obfuscation: f32,
    pub evasion_techniques: Vec<String>,
    pub multi_stage: bool,
    pub eval_usage: bool,
    pub risk_score: f32,
}

/// URI/external action risk profile
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UriRiskProfile {
    pub present: bool,
    pub count: usize,
    pub suspicious_domains: Vec<String>,
    pub suspicious_schemes: Vec<String>,
    pub phishing_indicators: usize,
    pub external_connections: usize,
    pub risk_score: f32,
}

/// Structural anomaly risk profile
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StructuralRiskProfile {
    pub spec_violations: usize,
    pub xref_issues: usize,
    pub object_stream_anomalies: usize,
    pub compression_ratio: f32,
    pub encryption_present: bool,
    pub risk_score: f32,
}

/// Supply chain risk profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainRiskProfile {
    pub producer: Option<String>,
    pub creator: Option<String>,
    pub creation_date: Option<String>,
    pub modification_date: Option<String>,
    pub producer_trusted: bool,
    pub timestamps_consistent: bool,
    pub signature_present: bool,
    pub signature_valid: bool,
    pub risk_score: f32,
}

impl Default for SupplyChainRiskProfile {
    fn default() -> Self {
        Self {
            producer: None,
            creator: None,
            creation_date: None,
            modification_date: None,
            producer_trusted: false,
            timestamps_consistent: true,
            signature_present: false,
            signature_valid: false,
            risk_score: 0.0,
        }
    }
}

/// Content-based risk profile
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContentRiskProfile {
    pub text_anomalies: usize,
    pub font_issues: usize,
    pub image_anomalies: usize,
    pub hidden_content: bool,
    pub overlapping_objects: bool,
    pub phishing_keywords: Vec<String>,
    pub risk_score: f32,
}

/// Cryptographic risk profile
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CryptoRiskProfile {
    pub encryption_algorithm: Option<String>,
    pub weak_encryption: bool,
    pub certificate_issues: usize,
    pub signature_anomalies: usize,
    pub risk_score: f32,
}

/// Compute percentile from percentile array [P10, P25, P50, P75, P90, P95, P99]
pub fn compute_percentile(value: f32, percentiles: &[f32]) -> f32 {
    if percentiles.len() != 7 {
        return 50.0; // Default to median if invalid
    }

    if value <= percentiles[0] {
        return 10.0;
    }
    if value >= percentiles[6] {
        return 99.0;
    }

    // Linear interpolation
    let pct_values = [10.0, 25.0, 50.0, 75.0, 90.0, 95.0, 99.0];
    for i in 0..percentiles.len() - 1 {
        if value >= percentiles[i] && value <= percentiles[i + 1] {
            let ratio = (value - percentiles[i]) / (percentiles[i + 1] - percentiles[i]);
            return pct_values[i] + ratio * (pct_values[i + 1] - pct_values[i]);
        }
    }

    50.0 // Fallback
}

/// Build evidence chains from feature attribution and findings
pub fn build_evidence_chains(
    attribution: &[FeatureAttribution],
    findings: &[Finding],
) -> Vec<EvidenceChain> {
    let mut chains = Vec::new();

    for attr in attribution.iter().take(20) {
        // Top 20 features
        let relevant_findings = find_contributing_findings(&attr.feature_name, findings);
        let evidence_spans: Vec<_> =
            relevant_findings.iter().flat_map(|f| f.evidence.clone()).collect();

        if !relevant_findings.is_empty() {
            chains.push(EvidenceChain {
                feature_name: attr.feature_name.clone(),
                feature_value: attr.value,
                contribution: attr.contribution,
                derived_from_findings: relevant_findings.iter().map(|f| f.kind.clone()).collect(),
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
        let Some(base) = feature_name.strip_prefix("finding.") else {
            return Vec::new();
        };
        let kind =
            base.strip_suffix("_count").or_else(|| base.strip_suffix("_present")).unwrap_or(base);
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

    let mut summary =
        format!("This PDF is {} suspicious (ML risk score: {:.2}). ", severity_level, prediction);

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
        summary.push_str(&format!("Found {} high-severity issues: ", high_findings.len()));

        for (i, f) in high_findings.iter().take(3).enumerate() {
            if i > 0 {
                summary.push_str(", ");
            }
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
        _ => name.replace("_", " ").replace(".", ": "),
    }
}

/// Convert finding kind to human-readable description
fn humanize_finding_kind(kind: &str) -> String {
    match kind {
        "js_polymorphic" => "polymorphic JavaScript".to_string(),
        "js_obfuscation_deep" => "deeply obfuscated JavaScript".to_string(),
        "open_action_present" => "automatic OpenAction trigger".to_string(),
        "uri_listing" => "document-level URI inventory with risk summary".to_string(),
        "uri_content_analysis" => "suspicious URI with obfuscation".to_string(),
        "multi_stage_attack_chain" => "multi-stage attack chain".to_string(),
        "supply_chain_persistence" => "supply chain persistence mechanism".to_string(),
        _ => kind.replace("_", " "),
    }
}

/// Recognize attack patterns from findings
fn recognize_attack_pattern(findings: &[Finding]) -> Option<String> {
    let has_js = findings.iter().any(|f| f.surface == AttackSurface::JavaScript);
    let has_obf = findings.iter().any(|f| f.kind.contains("obfuscation"));
    let has_auto = findings.iter().any(|f| f.kind.contains("open_action"));
    let has_uri =
        findings.iter().any(|f| f.surface == AttackSurface::Actions && f.kind.contains("uri"));
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

// ============================================================================
// Risk Score Calibration
// ============================================================================

/// Calibration model for converting raw scores to calibrated probabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationModel {
    pub method: CalibrationMethod,
}

/// Calibration methods supported
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CalibrationMethod {
    /// Platt scaling: logistic regression on raw scores
    PlattScaling { a: f32, b: f32 },
    /// Isotonic regression: piecewise constant calibration
    IsotonicRegression { x: Vec<f32>, y: Vec<f32> },
}

impl CalibrationModel {
    /// Create a new Platt scaling calibration model
    pub fn platt_scaling(a: f32, b: f32) -> Self {
        Self { method: CalibrationMethod::PlattScaling { a, b } }
    }

    /// Create a new isotonic regression calibration model
    pub fn isotonic_regression(x: Vec<f32>, y: Vec<f32>) -> Self {
        Self { method: CalibrationMethod::IsotonicRegression { x, y } }
    }

    /// Calibrate a raw score
    pub fn calibrate(&self, raw_score: f32) -> f32 {
        match &self.method {
            CalibrationMethod::PlattScaling { a, b } => {
                // Sigmoid: 1 / (1 + exp(-a * raw_score - b))
                1.0 / (1.0 + (-a * raw_score - b).exp())
            }
            CalibrationMethod::IsotonicRegression { x, y } => {
                // Linear interpolation in isotonic curve
                if x.is_empty() || y.is_empty() || x.len() != y.len() {
                    return raw_score;
                }

                if raw_score <= x[0] {
                    return y[0];
                }
                if let (Some(&x_last), Some(&y_last)) = (x.last(), y.last()) {
                    if raw_score >= x_last {
                        return y_last;
                    }
                }

                for i in 0..x.len() - 1 {
                    if raw_score >= x[i] && raw_score <= x[i + 1] {
                        let ratio = (raw_score - x[i]) / (x[i + 1] - x[i]);
                        return y[i] + ratio * (y[i + 1] - y[i]);
                    }
                }

                raw_score
            }
        }
    }

    /// Load calibration model from JSON file
    #[cfg(feature = "filesystem")]
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let json = std::fs::read_to_string(path)?;
        let model: CalibrationModel = serde_json::from_str(&json)?;
        Ok(model)
    }

    /// Save calibration model to JSON file
    #[cfg(feature = "filesystem")]
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

/// Calibrate a prediction and generate comprehensive metadata
pub fn calibrate_prediction(raw_score: f32, calibrator: &CalibrationModel) -> CalibratedPrediction {
    let calibrated_score = calibrator.calibrate(raw_score);

    // Estimate confidence interval (simplified - real implementation would use bootstrap)
    // Width is wider near 0.5 (maximum uncertainty) and narrower near 0 or 1
    let ci_width = 0.1 * (1.0 - calibrated_score) * calibrated_score * 4.0;
    let confidence_interval =
        ((calibrated_score - ci_width).max(0.0), (calibrated_score + ci_width).min(1.0));

    let calibration_method = match &calibrator.method {
        CalibrationMethod::PlattScaling { .. } => "Platt Scaling",
        CalibrationMethod::IsotonicRegression { .. } => "Isotonic Regression",
    }
    .to_string();

    let interpretation = if calibrated_score >= 0.9 {
        format!(
            "Very high confidence malicious: {:.1}% probability ({:.1}%-{:.1}% CI)",
            calibrated_score * 100.0,
            confidence_interval.0 * 100.0,
            confidence_interval.1 * 100.0
        )
    } else if calibrated_score >= 0.7 {
        format!(
            "Likely malicious: {:.1}% probability ({:.1}%-{:.1}% CI)",
            calibrated_score * 100.0,
            confidence_interval.0 * 100.0,
            confidence_interval.1 * 100.0
        )
    } else if calibrated_score >= 0.5 {
        format!(
            "Possibly malicious: {:.1}% probability ({:.1}%-{:.1}% CI)",
            calibrated_score * 100.0,
            confidence_interval.0 * 100.0,
            confidence_interval.1 * 100.0
        )
    } else if calibrated_score >= 0.3 {
        format!(
            "Unlikely malicious: {:.1}% probability ({:.1}%-{:.1}% CI)",
            calibrated_score * 100.0,
            confidence_interval.0 * 100.0,
            confidence_interval.1 * 100.0
        )
    } else {
        format!(
            "Very low risk: {:.1}% probability ({:.1}%-{:.1}% CI)",
            calibrated_score * 100.0,
            confidence_interval.0 * 100.0,
            confidence_interval.1 * 100.0
        )
    };

    CalibratedPrediction {
        raw_score,
        calibrated_score,
        confidence_interval,
        calibration_method,
        interpretation,
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
        let z_score = if stddev > 0.0 { (value - mean) / stddev } else { 0.0 };

        if z_score.abs() > 1.5 {
            // More than 1.5 standard deviations
            let percentile = if let Some(pcts) = baseline.feature_percentiles.get(name) {
                compute_percentile(value, pcts)
            } else {
                50.0
            };

            let interpretation = if z_score > 0.0 {
                if z_score > 3.0 {
                    format!(
                        "Extremely high ({:.1}σ above benign average) - highly unusual",
                        z_score
                    )
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
    comparisons.sort_by(|a, b| b.z_score.abs().total_cmp(&a.z_score.abs()));
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
    attributions.sort_by(|a, b| b.contribution.abs().total_cmp(&a.contribution.abs()));
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
    let mut positive_features: Vec<_> =
        attributions.iter().filter(|a| a.contribution > 0.0).cloned().collect();
    positive_features.sort_by(|a, b| b.contribution.total_cmp(&a.contribution));
    positive_features.truncate(10);

    let mut negative_features: Vec<_> =
        attributions.iter().filter(|a| a.contribution < 0.0).cloned().collect();
    negative_features.sort_by(|a, b| a.contribution.total_cmp(&b.contribution));
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
        let mut values: Vec<f32> =
            benign_feature_maps.iter().filter_map(|m| m.get(&feature_name).copied()).collect();

        if values.is_empty() {
            continue;
        }

        // Compute mean
        let mean = values.iter().sum::<f32>() / values.len() as f32;
        feature_means.insert(feature_name.clone(), mean);

        // Compute stddev
        let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f32>() / values.len() as f32;
        let stddev = variance.sqrt();
        feature_stddevs.insert(feature_name.clone(), stddev);

        // Compute percentiles
        values.sort_by(|a, b| a.total_cmp(b));
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

    BenignBaseline { feature_means, feature_stddevs, feature_percentiles }
}

/// Compute the nth percentile from a sorted array
fn compute_nth_percentile(sorted_values: &[f32], percentile: f32) -> f32 {
    if sorted_values.is_empty() {
        return 0.0;
    }

    let index = (percentile / 100.0 * (sorted_values.len() - 1) as f32).round() as usize;
    sorted_values[index.min(sorted_values.len() - 1)]
}

// ============================================================================
// Document Risk Profile Generation
// ============================================================================

/// Generate comprehensive document-level risk profile
pub fn generate_document_risk_profile(
    findings: &[Finding],
    prediction: CalibratedPrediction,
    explanation: MlExplanation,
    comparative_analysis: Vec<ComparativeFeature>,
    graph_paths: Option<GraphPathExplanation>,
    evidence_chains: Vec<EvidenceChain>,
) -> DocumentRiskProfile {
    // Count findings by severity
    let critical_count = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high_severity_count = findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium_severity_count = findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low_severity_count = findings.iter().filter(|f| f.severity == Severity::Low).count();

    // Attack surface diversity
    let surfaces: std::collections::HashSet<_> = findings.iter().map(|f| f.surface).collect();
    let attack_surface_diversity = surfaces.len();

    // Max confidence
    let max_confidence = findings
        .iter()
        .map(|f| f.confidence)
        .max()
        .map(|c| format!("{:?}", c))
        .unwrap_or_else(|| "None".to_string());

    // Generate category-specific risk profiles
    let js_risk = extract_js_risk_profile(findings);
    let uri_risk = extract_uri_risk_profile(findings);
    let structural_risk = extract_structural_risk_profile(findings);
    let supply_chain_risk = extract_supply_chain_risk_profile(findings);
    let content_risk = extract_content_risk_profile(findings);
    let crypto_risk = extract_crypto_risk_profile(findings);

    DocumentRiskProfile {
        prediction,
        total_findings: findings.len(),
        critical_count,
        high_severity_count,
        medium_severity_count,
        low_severity_count,
        attack_surface_diversity,
        max_confidence,
        js_risk,
        uri_risk,
        structural_risk,
        supply_chain_risk,
        content_risk,
        crypto_risk,
        explanation,
        comparative_analysis,
        graph_paths,
        evidence_chains,
    }
}

// ============================================================================
// Advanced Explainability (Phase 7)
// ============================================================================

/// Counterfactual change suggestion for a single feature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterfactualChange {
    pub feature_name: String,
    pub from_value: f32,
    pub to_value: f32,
    pub delta: f32,
    pub weight: f32,
}

/// Counterfactual explanation with proposed feature changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterfactualExplanation {
    pub original_score: f32,
    pub target_score: f32,
    pub achieved_score: f32,
    pub changes: Vec<CounterfactualChange>,
    pub notes: Vec<String>,
}

/// Temporal snapshot for incremental update analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalSnapshot {
    pub version_label: String,
    pub score: f32,
    pub high_severity_count: usize,
    pub finding_count: usize,
}

/// Temporal explanation showing risk evolution across updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalExplanation {
    pub snapshots: Vec<TemporalSnapshot>,
    pub score_delta: f32,
    pub trend: String,
    pub notable_changes: Vec<String>,
}

/// Feature interaction detected from co-occurring high-impact signals
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureInteraction {
    pub feature_a: String,
    pub feature_b: String,
    pub interaction_score: f32,
    pub summary: String,
}

/// Generate counterfactual feature changes for a linear model.
///
/// This focuses on reducing the score to the target by moving features toward
/// benign baselines (or zero if no baseline is available).
pub fn generate_counterfactual_linear(
    model: &LinearModel,
    feature_values: &[f32],
    feature_names: &[String],
    target_score: f32,
    max_changes: usize,
    baseline: Option<&BenignBaseline>,
) -> CounterfactualExplanation {
    let original_logit = linear_logit(model, feature_values);
    let original_score = sigmoid(original_logit);
    let target_logit = logit(target_score.clamp(0.0001, 0.9999));

    let mut notes = Vec::new();
    if target_logit >= original_logit {
        notes.push("Target score is not lower than the current score.".to_string());
        return CounterfactualExplanation {
            original_score,
            target_score,
            achieved_score: original_score,
            changes: Vec::new(),
            notes,
        };
    }

    let mut candidates = Vec::new();
    for (idx, (name, &value)) in feature_names.iter().zip(feature_values).enumerate() {
        let weight = model.weights.get(idx).copied().unwrap_or(0.0);
        if weight <= 0.0 {
            continue;
        }
        let baseline_value =
            baseline.and_then(|b| b.feature_means.get(name).copied()).unwrap_or(0.0);
        if value <= baseline_value {
            continue;
        }
        let delta = baseline_value - value;
        let logit_change = weight * delta;
        candidates.push((idx, logit_change, baseline_value));
    }

    candidates.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut new_values = feature_values.to_vec();
    let mut changes = Vec::new();
    let mut current_logit = original_logit;
    for (idx, logit_change, baseline_value) in candidates.into_iter().take(max_changes) {
        if current_logit <= target_logit {
            break;
        }
        let from_value = new_values[idx];
        let to_value = baseline_value;
        new_values[idx] = to_value;
        current_logit += logit_change;
        changes.push(CounterfactualChange {
            feature_name: feature_names[idx].clone(),
            from_value,
            to_value,
            delta: to_value - from_value,
            weight: model.weights.get(idx).copied().unwrap_or(0.0),
        });
    }

    let achieved_score = sigmoid(current_logit);
    if achieved_score > target_score {
        notes.push("Target score not reached with available changes.".to_string());
    }

    CounterfactualExplanation { original_score, target_score, achieved_score, changes, notes }
}

/// Analyse temporal risk evolution from a sequence of snapshots.
pub fn analyse_temporal_risk(samples: &[TemporalSnapshot]) -> TemporalExplanation {
    if samples.is_empty() {
        return TemporalExplanation {
            snapshots: Vec::new(),
            score_delta: 0.0,
            trend: "no data".to_string(),
            notable_changes: Vec::new(),
        };
    }

    let (Some(first), Some(last)) = (samples.first(), samples.last()) else {
        return TemporalExplanation {
            snapshots: samples.to_vec(),
            score_delta: 0.0,
            trend: "no data".to_string(),
            notable_changes: Vec::new(),
        };
    };
    let score_delta = last.score - first.score;
    let trend = if score_delta > 0.05 {
        "increasing".to_string()
    } else if score_delta < -0.05 {
        "decreasing".to_string()
    } else {
        "stable".to_string()
    };

    let mut notable_changes = Vec::new();
    for window in samples.windows(2) {
        let prev = &window[0];
        let next = &window[1];
        let delta = next.score - prev.score;
        if delta.abs() >= 0.1 {
            notable_changes.push(format!(
                "Score changed from {:.2} to {:.2} between {} and {}.",
                prev.score, next.score, prev.version_label, next.version_label
            ));
        }
        if next.high_severity_count > prev.high_severity_count {
            notable_changes.push(format!(
                "High-severity findings increased from {} to {} at {}.",
                prev.high_severity_count, next.high_severity_count, next.version_label
            ));
        }
    }

    TemporalExplanation { snapshots: samples.to_vec(), score_delta, trend, notable_changes }
}

/// Detect interactions between strong outlier features based on z-scores.
pub fn detect_feature_interactions(
    feature_map: &HashMap<String, f32>,
    baseline: &BenignBaseline,
    max_pairs: usize,
) -> Vec<FeatureInteraction> {
    let mut outliers: Vec<(String, f32)> = Vec::new();
    for (name, &value) in feature_map {
        let mean = baseline.feature_means.get(name).copied().unwrap_or(0.0);
        let stddev = baseline.feature_stddevs.get(name).copied().unwrap_or(0.0);
        if stddev == 0.0 {
            continue;
        }
        let z_score = (value - mean) / stddev;
        if z_score.abs() >= 2.0 {
            outliers.push((name.clone(), z_score));
        }
    }

    let mut interactions = Vec::new();
    for i in 0..outliers.len() {
        for j in (i + 1)..outliers.len() {
            let (ref a, za) = outliers[i];
            let (ref b, zb) = outliers[j];
            let score = za.abs() * zb.abs();
            interactions.push(FeatureInteraction {
                feature_a: a.clone(),
                feature_b: b.clone(),
                interaction_score: score,
                summary: format!(
                    "{} and {} are both extreme outliers (z-scores {:.1}, {:.1}).",
                    humanize_feature_name(a),
                    humanize_feature_name(b),
                    za,
                    zb
                ),
            });
        }
    }

    interactions.sort_by(|a, b| b.interaction_score.total_cmp(&a.interaction_score));
    interactions.truncate(max_pairs);
    interactions
}

fn linear_logit(model: &LinearModel, feature_values: &[f32]) -> f32 {
    let mut sum = model.bias;
    for (w, x) in model.weights.iter().zip(feature_values.iter()) {
        sum += w * x;
    }
    sum
}

fn logit(p: f32) -> f32 {
    (p / (1.0 - p)).ln()
}

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

/// Extract JavaScript risk profile from findings
fn extract_js_risk_profile(findings: &[Finding]) -> JsRiskProfile {
    let js_findings: Vec<_> =
        findings.iter().filter(|f| f.surface == AttackSurface::JavaScript).collect();

    if js_findings.is_empty() {
        return JsRiskProfile::default();
    }

    let count = js_findings.len();
    let mut obfuscation_scores = Vec::new();
    let mut evasion_techniques = Vec::new();
    let mut eval_usage = false;
    let mut multi_stage = false;

    for finding in &js_findings {
        // Parse obfuscation score
        if let Some(score_str) = finding.meta.get("js.obfuscation_score") {
            if let Ok(score) = score_str.parse::<f32>() {
                obfuscation_scores.push(score);
            }
        }

        // Check for evasion techniques
        if finding.meta.contains_key("js.time_evasion") {
            evasion_techniques.push("time-based evasion".to_string());
        }
        if finding.meta.contains_key("js.environment_detect") {
            evasion_techniques.push("environment detection".to_string());
        }

        // Check for eval usage
        if finding.kind.contains("eval") || finding.kind.contains("function_constructor") {
            eval_usage = true;
        }

        // Check for multi-stage
        if finding.kind.contains("multi_stage") || finding.kind.contains("polymorphic") {
            multi_stage = true;
        }
    }

    let max_obfuscation = obfuscation_scores.iter().fold(0.0f32, |a, &b| a.max(b));
    let avg_obfuscation = if !obfuscation_scores.is_empty() {
        obfuscation_scores.iter().sum::<f32>() / obfuscation_scores.len() as f32
    } else {
        0.0
    };

    // Compute risk score
    let risk_score = (max_obfuscation * 0.4
        + if eval_usage { 0.3 } else { 0.0 }
        + if multi_stage { 0.2 } else { 0.0 }
        + (evasion_techniques.len() as f32 * 0.1))
        .min(1.0);

    JsRiskProfile {
        present: true,
        count,
        max_obfuscation,
        avg_obfuscation,
        evasion_techniques,
        multi_stage,
        eval_usage,
        risk_score,
    }
}

/// Extract URI risk profile from findings
fn extract_uri_risk_profile(findings: &[Finding]) -> UriRiskProfile {
    let uri_findings: Vec<_> = findings
        .iter()
        .filter(|f| matches!(f.surface, AttackSurface::Actions | AttackSurface::Forms))
        .filter(|f| f.kind.contains("uri") || f.kind.contains("launch") || f.kind.contains("url"))
        .collect();

    if uri_findings.is_empty() {
        return UriRiskProfile::default();
    }

    let count = uri_findings.len();
    let mut suspicious_domains = Vec::new();
    let mut suspicious_schemes = Vec::new();
    let mut phishing_indicators = 0;
    let external_connections = count;

    for finding in &uri_findings {
        if let Some(domain) = finding.meta.get("uri.domain") {
            if finding.kind.contains("suspicious") || finding.kind.contains("phishing") {
                suspicious_domains.push(domain.clone());
            }
        }

        if let Some(scheme) = finding.meta.get("uri.scheme") {
            if scheme != "http" && scheme != "https" {
                suspicious_schemes.push(scheme.clone());
            }
        }

        if finding.kind.contains("phishing") {
            phishing_indicators += 1;
        }
    }

    let risk_score = ((suspicious_domains.len() as f32 * 0.3)
        + (suspicious_schemes.len() as f32 * 0.2)
        + (phishing_indicators as f32 * 0.4)
        + 0.1)
        .min(1.0);

    UriRiskProfile {
        present: true,
        count,
        suspicious_domains,
        suspicious_schemes,
        phishing_indicators,
        external_connections,
        risk_score,
    }
}

/// Extract structural risk profile from findings
fn extract_structural_risk_profile(findings: &[Finding]) -> StructuralRiskProfile {
    let structural_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            matches!(
                f.surface,
                AttackSurface::FileStructure
                    | AttackSurface::XRefTrailer
                    | AttackSurface::ObjectStreams
                    | AttackSurface::StreamsAndFilters
            )
        })
        .collect();

    let spec_violations = structural_findings
        .iter()
        .filter(|f| f.kind.contains("invalid") || f.kind.contains("malformed"))
        .count();

    let xref_issues = structural_findings.iter().filter(|f| f.kind.contains("xref")).count();

    let object_stream_anomalies = structural_findings
        .iter()
        .filter(|f| f.kind.contains("objstm") || f.kind.contains("object_stream"))
        .count();

    let encryption_present =
        findings.iter().any(|f| f.kind.contains("encrypted") || f.kind.contains("encryption"));

    let risk_score = ((spec_violations as f32 * 0.2)
        + (xref_issues as f32 * 0.3)
        + (object_stream_anomalies as f32 * 0.2)
        + if encryption_present { 0.1 } else { 0.0 })
    .min(1.0);

    let compression_ratio = max_compression_ratio_from_findings(findings);

    StructuralRiskProfile {
        spec_violations,
        xref_issues,
        object_stream_anomalies,
        compression_ratio,
        encryption_present,
        risk_score,
    }
}

fn max_compression_ratio_from_findings(findings: &[Finding]) -> f32 {
    let mut highest = 0.0f32;
    for finding in findings {
        for key in ["stream.decompression_ratio", "swf.decompression_ratio"] {
            if let Some(ratio_str) = finding.meta.get(key) {
                if let Ok(ratio) = ratio_str.parse::<f32>() {
                    highest = highest.max(ratio);
                }
            }
        }
    }
    highest
}

/// Extract supply chain risk profile from findings
fn extract_supply_chain_risk_profile(findings: &[Finding]) -> SupplyChainRiskProfile {
    let supply_chain_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.kind.contains("producer") || f.kind.contains("creator") || f.kind.contains("metadata")
        })
        .collect();

    let mut profile = SupplyChainRiskProfile::default();

    for finding in &supply_chain_findings {
        if let Some(producer) = finding.meta.get("metadata.producer") {
            profile.producer = Some(producer.clone());
        }
        if let Some(creator) = finding.meta.get("metadata.creator") {
            profile.creator = Some(creator.clone());
        }
        if let Some(date) = finding.meta.get("metadata.creation_date") {
            profile.creation_date = Some(date.clone());
        }
        if let Some(date) = finding.meta.get("metadata.mod_date") {
            profile.modification_date = Some(date.clone());
        }

        if finding.kind.contains("suspicious_producer") {
            profile.producer_trusted = false;
            profile.risk_score += 0.3;
        }

        if finding.kind.contains("signature") {
            profile.signature_present = true;
            if finding.kind.contains("invalid") {
                profile.signature_valid = false;
                profile.risk_score += 0.4;
            } else {
                profile.signature_valid = true;
            }
        }
    }

    profile.risk_score = profile.risk_score.min(1.0);
    profile
}

/// Extract content risk profile from findings
fn extract_content_risk_profile(findings: &[Finding]) -> ContentRiskProfile {
    let content_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.surface == AttackSurface::ContentPhishing
                || f.kind.contains("content")
                || f.kind.contains("text")
        })
        .collect();

    let text_anomalies = content_findings
        .iter()
        .filter(|f| f.kind.contains("text_anomaly") || f.kind.contains("hidden_text"))
        .count();

    let font_issues = content_findings.iter().filter(|f| f.kind.contains("font")).count();

    let image_anomalies = content_findings.iter().filter(|f| f.kind.contains("image")).count();

    let hidden_content = content_findings.iter().any(|f| f.kind.contains("hidden"));
    let overlapping_objects = content_findings.iter().any(|f| f.kind.contains("overlapping"));

    let phishing_keywords: Vec<String> = content_findings
        .iter()
        .filter(|f| f.kind.contains("phishing"))
        .filter_map(|f| f.meta.get("keyword").cloned())
        .collect();

    let risk_score = ((text_anomalies as f32 * 0.1)
        + (font_issues as f32 * 0.1)
        + (phishing_keywords.len() as f32 * 0.3)
        + if hidden_content { 0.2 } else { 0.0 }
        + if overlapping_objects { 0.1 } else { 0.0 })
    .min(1.0);

    ContentRiskProfile {
        text_anomalies,
        font_issues,
        image_anomalies,
        hidden_content,
        overlapping_objects,
        phishing_keywords,
        risk_score,
    }
}

/// Extract crypto risk profile from findings
fn extract_crypto_risk_profile(findings: &[Finding]) -> CryptoRiskProfile {
    let crypto_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.surface == AttackSurface::CryptoSignatures
                || f.kind.contains("crypto")
                || f.kind.contains("encryption")
        })
        .collect();

    let mut profile = CryptoRiskProfile::default();

    for finding in &crypto_findings {
        if let Some(algo) = finding.meta.get("encryption.algorithm") {
            profile.encryption_algorithm = Some(algo.clone());

            if algo.contains("RC4") || algo.contains("DES") || algo.contains("MD5") {
                profile.weak_encryption = true;
                profile.risk_score += 0.4;
            }
        }

        if finding.kind.contains("certificate") {
            profile.certificate_issues += 1;
            profile.risk_score += 0.2;
        }

        if finding.kind.contains("signature") && finding.kind.contains("anomaly") {
            profile.signature_anomalies += 1;
            profile.risk_score += 0.3;
        }
    }

    profile.risk_score = profile.risk_score.min(1.0);
    profile
}

// ============================================================================
// Graph Path Extraction
// ============================================================================

/// Extract suspicious paths from the PDF object graph
///
/// This function analyzes action chains in the TypedGraph to identify
/// suspicious execution paths, score them by risk, and generate explanations.
pub fn extract_suspicious_paths(
    action_chains: &[sis_pdf_pdf::path_finder::ActionChain<'_>],
    findings: &[Finding],
    _node_scores: Option<&[f32]>, // Reserved for future GNN integration
) -> GraphPathExplanation {
    let mut scored_paths = Vec::new();

    for chain in action_chains {
        // Build PathNode sequence from action chain
        let path_nodes = build_path_nodes_from_chain(chain, findings);

        if path_nodes.is_empty() {
            continue;
        }

        // Compute path risk score
        let risk_score = compute_path_risk_score(&path_nodes, findings, chain);

        // Classify attack pattern
        let attack_pattern = classify_path_pattern(&path_nodes, chain);

        // Generate explanation
        let explanation = generate_path_explanation(&path_nodes, &attack_pattern, chain);

        scored_paths.push(SuspiciousPath {
            path: path_nodes,
            risk_score,
            explanation,
            attack_pattern,
        });
    }

    // Sort by risk score (highest first)
    scored_paths.sort_by(|a, b| {
        b.risk_score.partial_cmp(&a.risk_score).unwrap_or(std::cmp::Ordering::Equal)
    });

    let max_path_risk = scored_paths.first().map(|p| p.risk_score).unwrap_or(0.0);
    let avg_path_risk = if !scored_paths.is_empty() {
        scored_paths.iter().map(|p| p.risk_score).sum::<f32>() / scored_paths.len() as f32
    } else {
        0.0
    };

    GraphPathExplanation {
        suspicious_paths: scored_paths.into_iter().take(10).collect(), // Top 10
        max_path_risk,
        avg_path_risk,
    }
}

/// Build PathNode sequence from an ActionChain
fn build_path_nodes_from_chain(
    chain: &sis_pdf_pdf::path_finder::ActionChain<'_>,
    findings: &[Finding],
) -> Vec<PathNode> {
    use sis_pdf_pdf::typed_graph::EdgeType;

    let mut nodes = Vec::new();
    let mut visited_objs = std::collections::HashSet::new();

    // Add source node
    if let Some(first_edge) = chain.edges.first() {
        let src = first_edge.src;
        if visited_objs.insert(src) {
            let obj_str = format!("{} {} obj", src.0, src.1);
            let obj_findings: Vec<_> = findings
                .iter()
                .filter(|f| f.objects.contains(&obj_str))
                .map(|f| f.kind.clone())
                .collect();

            nodes.push(PathNode {
                obj_ref: src,
                node_type: classify_node_type(first_edge),
                edge_to_next: Some(EdgeInfo {
                    edge_type: format!("{:?}", first_edge.edge_type),
                    key: extract_edge_key(&first_edge.edge_type),
                    suspicious: first_edge.suspicious,
                }),
                findings: obj_findings,
            });
        }
    }

    // Add intermediate and destination nodes
    for (i, edge) in chain.edges.iter().enumerate() {
        let dst = edge.dst;
        if !visited_objs.insert(dst) {
            continue; // Skip cycles
        }

        let obj_str = format!("{} {} obj", dst.0, dst.1);
        let obj_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.objects.contains(&obj_str))
            .map(|f| f.kind.clone())
            .collect();

        let edge_to_next = if i + 1 < chain.edges.len() {
            let next_edge = &chain.edges[i + 1];
            Some(EdgeInfo {
                edge_type: format!("{:?}", next_edge.edge_type),
                key: extract_edge_key(&next_edge.edge_type),
                suspicious: next_edge.suspicious,
            })
        } else {
            None
        };

        let node_type = match edge.edge_type {
            EdgeType::JavaScriptPayload => "JavaScript",
            EdgeType::UriTarget => "URI",
            EdgeType::LaunchTarget => "Launch",
            EdgeType::SubmitFormTarget => "SubmitForm",
            _ => "Action",
        }
        .to_string();

        nodes.push(PathNode { obj_ref: dst, node_type, edge_to_next, findings: obj_findings });
    }

    nodes
}

/// Classify the node type based on the edge leading to it
fn classify_node_type(edge: &sis_pdf_pdf::typed_graph::TypedEdge) -> String {
    use sis_pdf_pdf::typed_graph::EdgeType;

    match edge.edge_type {
        EdgeType::OpenAction => "Catalog",
        EdgeType::PageAction { .. } => "Page",
        EdgeType::AnnotationAction => "Annotation",
        _ => "Object",
    }
    .to_string()
}

/// Extract key information from EdgeType
fn extract_edge_key(edge_type: &sis_pdf_pdf::typed_graph::EdgeType) -> String {
    use sis_pdf_pdf::typed_graph::EdgeType;

    match edge_type {
        EdgeType::DictReference { key } => key.clone(),
        EdgeType::ArrayElement { index } => format!("[{}]", index),
        EdgeType::OpenAction => "/OpenAction".to_string(),
        EdgeType::PageAction { event } => event.clone(),
        EdgeType::AnnotationAction => "/A".to_string(),
        EdgeType::AdditionalAction { event } => event.clone(),
        EdgeType::JavaScriptPayload => "/JS".to_string(),
        EdgeType::JavaScriptNames => "/Names/JavaScript".to_string(),
        EdgeType::UriTarget => "/URI".to_string(),
        EdgeType::LaunchTarget => "/Launch".to_string(),
        EdgeType::SubmitFormTarget => "/SubmitForm".to_string(),
        EdgeType::GoToRTarget => "/GoToR".to_string(),
        _ => String::new(),
    }
}

/// Compute risk score for a path
fn compute_path_risk_score(
    path: &[PathNode],
    findings: &[Finding],
    chain: &sis_pdf_pdf::path_finder::ActionChain<'_>,
) -> f32 {
    let mut risk = 0.0;

    // Base risk from chain characteristics
    if chain.automatic {
        risk += 0.3;
    }
    if chain.involves_js {
        risk += 0.4;
    }
    if chain.involves_external {
        risk += 0.3;
    }

    // Node contribution (findings)
    for node in path {
        if node.findings.is_empty() {
            continue;
        }

        let node_findings: Vec<_> =
            findings.iter().filter(|f| node.findings.contains(&f.kind)).collect();

        for f in node_findings {
            risk += match f.severity {
                Severity::Critical => 0.2,
                Severity::High => 0.15,
                Severity::Medium => 0.08,
                Severity::Low => 0.03,
                Severity::Info => 0.0,
            };
        }
    }

    // Edge contribution (suspicious edges)
    let suspicious_edge_count =
        path.iter().filter_map(|n| n.edge_to_next.as_ref()).filter(|e| e.suspicious).count();
    risk += suspicious_edge_count as f32 * 0.1;

    // Path length bonus (longer chains are more suspicious)
    if path.len() > 2 {
        risk += ((path.len() - 2) as f32) * 0.05;
    }

    risk.min(1.0)
}

/// Classify the attack pattern of a path
fn classify_path_pattern(
    path: &[PathNode],
    chain: &sis_pdf_pdf::path_finder::ActionChain<'_>,
) -> Option<String> {
    let has_openaction = path
        .iter()
        .any(|n| n.edge_to_next.as_ref().map(|e| e.key == "/OpenAction").unwrap_or(false));

    let has_js = path.iter().any(|n| n.node_type == "JavaScript");
    let has_uri = path.iter().any(|n| n.node_type == "URI");
    let has_launch = path.iter().any(|n| n.node_type == "Launch");

    match (has_openaction, has_js, has_uri || has_launch) {
        (true, true, true) => Some("automatic_js_with_external_action".to_string()),
        (true, true, false) => Some("automatic_js_trigger".to_string()),
        (false, true, true) => Some("js_to_external_resource".to_string()),
        (true, false, true) => Some("automatic_external_action".to_string()),
        _ if chain.automatic && chain.involves_js => Some("automatic_js_chain".to_string()),
        _ if chain.automatic => Some("automatic_action_chain".to_string()),
        _ if chain.involves_js && chain.involves_external => Some("js_external_chain".to_string()),
        _ => None,
    }
}

/// Generate natural language explanation for a path
fn generate_path_explanation(
    path: &[PathNode],
    pattern: &Option<String>,
    chain: &sis_pdf_pdf::path_finder::ActionChain<'_>,
) -> String {
    if path.is_empty() {
        return "Empty path".to_string();
    }

    let mut parts = vec![];

    // Path description
    let Some(first) = path.first() else {
        return "Empty path".to_string();
    };
    let first_obj = first.obj_ref;
    parts.push(format!("Path from object {} {}", first_obj.0, first_obj.1));

    // Length description
    if path.len() > 1 {
        parts.push(format!("through {} objects", path.len()));
    }

    // Pattern description
    if let Some(pat) = pattern {
        parts.push(format!(": {}", humanize_pattern(pat)));
    } else if chain.is_multi_stage() {
        parts.push(": Multi-stage action chain".to_string());
    }

    // Finding highlights
    let total_findings: usize = path.iter().map(|n| n.findings.len()).sum();
    if total_findings > 0 {
        parts.push(format!("({} findings)", total_findings));
    }

    parts.join(" ")
}

/// Convert pattern ID to human-readable description
fn humanize_pattern(pattern: &str) -> String {
    match pattern {
        "automatic_js_with_external_action" => {
            "Automatic JavaScript execution with external action".to_string()
        }
        "automatic_js_trigger" => "Automatic JavaScript execution via OpenAction".to_string(),
        "js_to_external_resource" => "JavaScript triggers external resource".to_string(),
        "automatic_external_action" => "Automatic external action".to_string(),
        "automatic_js_chain" => "Automatic JavaScript action chain".to_string(),
        "automatic_action_chain" => "Automatic action chain".to_string(),
        "js_external_chain" => "JavaScript with external action".to_string(),
        _ => pattern.replace('_', " "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, Impact};

    #[test]
    fn test_percentile_computation() {
        let percentiles = vec![10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0];

        assert_eq!(compute_percentile(5.0, &percentiles), 10.0); // Below P10
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
            "unknown feature" // Underscores replaced with spaces
        );
        assert_eq!(
            humanize_feature_name("group.feature_name"),
            "group: feature name" // Both dots and underscores replaced
        );
    }

    #[test]
    fn test_explanation_text_generation() {
        let features = vec![FeatureAttribution {
            feature_name: "js_signals.max_obfuscation_score".to_string(),
            value: 0.95,
            contribution: 0.18,
            baseline: 0.0,
            percentile: 99.5,
        }];

        let findings = vec![];
        let summary = generate_explanation_text(0.87, &features, &findings);

        assert!(summary.contains("highly suspicious"));
        assert!(summary.contains("obfuscated JavaScript"));
        assert!(summary.contains("Block and investigate"));
    }

    #[test]
    fn test_compute_permutation_importance() {
        // Mock model that returns sum of features
        let model =
            |features: &[f32]| -> f32 { features.iter().sum::<f32>() / features.len() as f32 };

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

        let attributions =
            compute_permutation_importance(&model, &feature_values, &feature_names, &baseline);

        assert_eq!(attributions.len(), 5);

        // All contributions should be positive since we're replacing with smaller values
        for attr in &attributions {
            assert!(
                attr.contribution >= 0.0,
                "Feature {} contribution should be positive: {}",
                attr.feature_name,
                attr.contribution
            );
        }

        // Should be sorted by absolute contribution
        for i in 0..attributions.len() - 1 {
            assert!(
                attributions[i].contribution.abs() >= attributions[i + 1].contribution.abs(),
                "Attributions should be sorted by absolute contribution"
            );
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
        assert_eq!(group_importance.get("js_signals"), Some(&0.25));
        assert_eq!(group_importance.get("uri_signals"), Some(&0.08));
        assert_eq!(group_importance.get("general"), Some(&0.02));
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

        let explanation = create_ml_explanation(0.85, attributions, &baseline, &findings);

        assert_eq!(explanation.prediction, 0.85);
        assert_eq!(explanation.top_positive_features.len(), 2);
        assert_eq!(explanation.top_negative_features.len(), 1);

        // Check positive features are sorted correctly
        assert_eq!(
            explanation.top_positive_features[0].feature_name,
            "js_signals.max_obfuscation_score"
        );
        assert_eq!(
            explanation.top_positive_features[1].feature_name,
            "uri_signals.ip_address_count"
        );

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
        assert_eq!(baseline.feature_means.get("feature_a"), Some(&3.0)); // (1+3+5)/3
        assert_eq!(baseline.feature_means.get("feature_b"), Some(&4.0)); // (2+4+6)/3
        assert_eq!(baseline.feature_means.get("feature_c"), Some(&5.0)); // (3+5+7)/3

        // Check stddevs exist
        assert!(baseline.feature_stddevs.contains_key("feature_a"));
        assert!(baseline
            .feature_stddevs
            .get("feature_a")
            .map(|value| *value > 0.0)
            .unwrap_or(false));

        // Check percentiles
        assert!(baseline.feature_percentiles.contains_key("feature_a"));
        assert_eq!(
            baseline.feature_percentiles.get("feature_a").map(|values| values.len()),
            Some(7)
        );
    }

    #[test]
    fn test_compute_nth_percentile() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];

        assert_eq!(compute_nth_percentile(&values, 0.0), 1.0); // Min (index 0)
        assert_eq!(compute_nth_percentile(&values, 50.0), 6.0); // Median (index 5 after rounding 4.5)
        assert_eq!(compute_nth_percentile(&values, 100.0), 10.0); // Max (index 9)

        // Test with smaller array
        let small = vec![1.0, 5.0, 10.0];
        assert_eq!(compute_nth_percentile(&small, 50.0), 5.0); // Index 1
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

        let dir = match tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("failed to create temp dir: {}", err),
        };
        let file_path = dir.path().join("baseline.json");

        let mut baseline = BenignBaseline::default();
        baseline.feature_means.insert("test_feature".to_string(), 1.5);
        baseline.feature_stddevs.insert("test_feature".to_string(), 0.5);
        baseline
            .feature_percentiles
            .insert("test_feature".to_string(), vec![0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 3.5]);

        // Save
        if let Err(err) = baseline.save_to_file(&file_path) {
            panic!("failed to save baseline: {:?}", err);
        }

        // Load
        let loaded = match BenignBaseline::load_from_file(&file_path) {
            Ok(value) => value,
            Err(err) => panic!("failed to load baseline: {:?}", err),
        };

        assert_eq!(loaded.feature_means.get("test_feature"), Some(&1.5));
        assert_eq!(loaded.feature_stddevs.get("test_feature"), Some(&0.5));
        assert_eq!(
            loaded.feature_percentiles.get("test_feature").map(|values| values.len()),
            Some(7)
        );
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
        assert_eq!(group_importance.get("js_signals"), Some(&0.25));
    }

    // ========================================================================
    // Graph Path Tests
    // ========================================================================

    #[test]
    fn test_humanize_pattern() {
        assert_eq!(
            humanize_pattern("automatic_js_trigger"),
            "Automatic JavaScript execution via OpenAction"
        );
        assert_eq!(humanize_pattern("automatic_action_chain"), "Automatic action chain");
        assert_eq!(humanize_pattern("custom_pattern_name"), "custom pattern name");
    }

    #[test]
    fn test_extract_edge_key() {
        use sis_pdf_pdf::typed_graph::EdgeType;

        assert_eq!(
            extract_edge_key(&EdgeType::DictReference { key: "/Type".to_string() }),
            "/Type"
        );
        assert_eq!(extract_edge_key(&EdgeType::ArrayElement { index: 5 }), "[5]");
        assert_eq!(extract_edge_key(&EdgeType::OpenAction), "/OpenAction");
        assert_eq!(extract_edge_key(&EdgeType::PageAction { event: "/O".to_string() }), "/O");
        assert_eq!(extract_edge_key(&EdgeType::JavaScriptPayload), "/JS");
        assert_eq!(extract_edge_key(&EdgeType::UriTarget), "/URI");
    }

    #[test]
    fn test_path_node_creation() {
        let node = PathNode {
            obj_ref: (1, 0),
            node_type: "JavaScript".to_string(),
            edge_to_next: Some(EdgeInfo {
                edge_type: "JavaScriptPayload".to_string(),
                key: "/JS".to_string(),
                suspicious: true,
            }),
            findings: vec!["js_eval".to_string(), "js_obfuscated".to_string()],
        };

        assert_eq!(node.obj_ref, (1, 0));
        assert_eq!(node.node_type, "JavaScript");
        assert_eq!(node.findings.len(), 2);
        assert!(node.edge_to_next.is_some());
        match node.edge_to_next.as_ref() {
            Some(edge) => assert!(edge.suspicious),
            None => panic!("expected edge information"),
        };
    }

    #[test]
    fn test_suspicious_path_creation() {
        let path = SuspiciousPath {
            path: vec![
                PathNode {
                    obj_ref: (1, 0),
                    node_type: "Catalog".to_string(),
                    edge_to_next: None,
                    findings: vec![],
                },
                PathNode {
                    obj_ref: (2, 0),
                    node_type: "JavaScript".to_string(),
                    edge_to_next: None,
                    findings: vec!["js_eval".to_string()],
                },
            ],
            risk_score: 0.75,
            explanation: "Test path".to_string(),
            attack_pattern: Some("automatic_js_trigger".to_string()),
        };

        assert_eq!(path.path.len(), 2);
        assert_eq!(path.risk_score, 0.75);
        assert!(path.attack_pattern.is_some());
    }

    #[test]
    fn test_graph_path_explanation_creation() {
        let explanation = GraphPathExplanation {
            suspicious_paths: vec![
                SuspiciousPath {
                    path: vec![],
                    risk_score: 0.8,
                    explanation: "High risk path".to_string(),
                    attack_pattern: Some("automatic_js_trigger".to_string()),
                },
                SuspiciousPath {
                    path: vec![],
                    risk_score: 0.5,
                    explanation: "Medium risk path".to_string(),
                    attack_pattern: None,
                },
            ],
            max_path_risk: 0.8,
            avg_path_risk: 0.65,
        };

        assert_eq!(explanation.suspicious_paths.len(), 2);
        assert_eq!(explanation.max_path_risk, 0.8);
        assert_eq!(explanation.avg_path_risk, 0.65);
    }

    #[test]
    fn test_graph_path_explanation_empty() {
        let explanation = GraphPathExplanation {
            suspicious_paths: vec![],
            max_path_risk: 0.0,
            avg_path_risk: 0.0,
        };

        assert_eq!(explanation.suspicious_paths.len(), 0);
        assert_eq!(explanation.max_path_risk, 0.0);
        assert_eq!(explanation.avg_path_risk, 0.0);
    }

    #[test]
    fn test_graph_path_serialization() -> serde_json::Result<()> {
        let node = PathNode {
            obj_ref: (1, 0),
            node_type: "JavaScript".to_string(),
            edge_to_next: Some(EdgeInfo {
                edge_type: "JavaScriptPayload".to_string(),
                key: "/JS".to_string(),
                suspicious: true,
            }),
            findings: vec!["js_eval".to_string()],
        };

        let json = serde_json::to_string(&node)?;
        let deserialized: PathNode = serde_json::from_str(&json)?;

        assert_eq!(deserialized.obj_ref, (1, 0));
        assert_eq!(deserialized.node_type, "JavaScript");
        assert_eq!(deserialized.findings.len(), 1);
        Ok(())
    }

    // ========================================================================
    // Risk Profile and Calibration Tests
    // ========================================================================

    #[test]
    fn test_platt_scaling_calibration() {
        let calibrator = CalibrationModel::platt_scaling(1.0, 0.0);

        // Test sigmoid behavior
        let calibrated = calibrator.calibrate(0.0);
        assert!((calibrated - 0.5).abs() < 0.01); // Should be ~0.5 at 0

        let calibrated = calibrator.calibrate(5.0);
        assert!(calibrated > 0.99); // Should be close to 1 for large positive

        let calibrated = calibrator.calibrate(-5.0);
        assert!(calibrated < 0.01); // Should be close to 0 for large negative
    }

    #[test]
    fn test_isotonic_regression_calibration() {
        let x = vec![0.0, 0.2, 0.5, 0.8, 1.0];
        let y = vec![0.0, 0.15, 0.4, 0.7, 1.0];
        let calibrator = CalibrationModel::isotonic_regression(x, y);

        // Test interpolation
        let calibrated = calibrator.calibrate(0.5);
        assert!((calibrated - 0.4).abs() < 0.01);

        let calibrated = calibrator.calibrate(0.35); // Between 0.2 and 0.5
        assert!(calibrated > 0.15 && calibrated < 0.4);

        // Test extrapolation (should clip)
        let calibrated = calibrator.calibrate(1.5);
        assert!((calibrated - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_calibrate_prediction() {
        let calibrator = CalibrationModel::platt_scaling(1.0, 0.0);
        let prediction = calibrate_prediction(0.8, &calibrator);

        // Check that calibration was applied
        assert!(prediction.calibrated_score >= 0.0 && prediction.calibrated_score <= 1.0);
        assert!(prediction.confidence_interval.0 < prediction.calibrated_score);
        assert!(prediction.confidence_interval.1 > prediction.calibrated_score);
        assert!(prediction.interpretation.contains("%"));
        assert_eq!(prediction.raw_score, 0.8);
    }

    #[test]
    fn test_calibration_model_save_load() {
        use tempfile::tempdir;

        let dir = match tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("failed to create temp dir: {}", err),
        };
        let file_path = dir.path().join("calibration.json");

        let calibrator = CalibrationModel::platt_scaling(2.5, -1.0);
        if let Err(err) = calibrator.save_to_file(&file_path) {
            panic!("failed to save calibrator: {:?}", err);
        }

        let loaded = match CalibrationModel::load_from_file(&file_path) {
            Ok(value) => value,
            Err(err) => panic!("failed to load calibrator: {:?}", err),
        };

        // Verify it works the same
        let score1 = calibrator.calibrate(0.5);
        let score2 = loaded.calibrate(0.5);
        assert!((score1 - score2).abs() < 0.001);
    }

    #[test]
    fn test_js_risk_profile_extraction() {
        let mut findings = vec![];

        // Add JS finding with metadata
        let mut meta = HashMap::new();
        meta.insert("js.obfuscation_score".to_string(), "0.85".to_string());
        meta.insert("js.time_evasion".to_string(), "true".to_string());

        findings.push(Finding {
            id: "js-1".to_string(),
            kind: "js_eval".to_string(),
            severity: Severity::High,
            confidence: Confidence::Strong,
            impact: Impact::Unknown,
            surface: AttackSurface::JavaScript,
            title: "JavaScript eval usage".to_string(),
            description: "test".to_string(),
            objects: vec!["1 0 obj".to_string()],
            evidence: vec![],
            remediation: None,
            meta,
            yara: None,
            positions: Vec::new(),
            ..Finding::default()
        });

        let profile = extract_js_risk_profile(&findings);

        assert!(profile.present);
        assert_eq!(profile.count, 1);
        assert!(profile.max_obfuscation > 0.8);
        assert!(profile.eval_usage);
        assert!(!profile.evasion_techniques.is_empty());
        assert!(profile.risk_score > 0.0);
    }

    #[test]
    fn test_uri_risk_profile_extraction() {
        let mut findings = vec![];

        let mut meta = HashMap::new();
        meta.insert("uri.domain".to_string(), "malicious.com".to_string());
        meta.insert("uri.scheme".to_string(), "javascript".to_string());

        findings.push(Finding {
            id: "uri-1".to_string(),
            kind: "aa_uri_suspicious".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            impact: Impact::Unknown,
            surface: AttackSurface::Actions,
            title: "Suspicious URI".to_string(),
            description: "test".to_string(),
            objects: vec!["2 0 obj".to_string()],
            evidence: vec![],
            remediation: None,
            meta,
            yara: None,
            positions: Vec::new(),
            ..Finding::default()
        });

        let profile = extract_uri_risk_profile(&findings);

        assert!(profile.present);
        assert_eq!(profile.count, 1);
        assert!(!profile.suspicious_domains.is_empty());
        assert!(!profile.suspicious_schemes.is_empty());
        assert!(profile.risk_score > 0.0);
    }

    #[test]
    fn test_structural_risk_profile_extraction() {
        let findings = vec![
            Finding {
                id: "xref-1".to_string(),
                kind: "xref_conflict".to_string(),
                severity: Severity::High,
                confidence: Confidence::Strong,
                impact: Impact::Unknown,
                surface: AttackSurface::XRefTrailer,
                title: "XRef conflict".to_string(),
                description: "test".to_string(),
                objects: vec!["3 0 obj".to_string()],
                evidence: vec![],
                remediation: None,
                meta: HashMap::new(),
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                positions: Vec::new(),
            },
            Finding {
                id: "struct-1".to_string(),
                kind: "invalid_structure".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                impact: Impact::Unknown,
                surface: AttackSurface::FileStructure,
                title: "Invalid structure".to_string(),
                description: "test".to_string(),
                objects: vec!["4 0 obj".to_string()],
                evidence: vec![],
                remediation: None,
                meta: HashMap::new(),
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                positions: Vec::new(),
            },
        ];

        let profile = extract_structural_risk_profile(&findings);

        assert_eq!(profile.spec_violations, 1);
        assert_eq!(profile.xref_issues, 1);
        assert!(profile.risk_score > 0.0);
    }

    #[test]
    fn test_generate_document_risk_profile() {
        let findings = vec![
            Finding {
                id: "js-1".to_string(),
                kind: "js_eval".to_string(),
                severity: Severity::High,
                confidence: Confidence::Strong,
                impact: Impact::Unknown,
                surface: AttackSurface::JavaScript,
                title: "JavaScript eval".to_string(),
                description: "test".to_string(),
                objects: vec!["1 0 obj".to_string()],
                evidence: vec![],
                remediation: None,
                meta: HashMap::new(),
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                positions: Vec::new(),
            },
            Finding {
                id: "xref-1".to_string(),
                kind: "xref_conflict".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::Strong,
                impact: Impact::Unknown,
                surface: AttackSurface::XRefTrailer,
                title: "XRef conflict".to_string(),
                description: "test".to_string(),
                objects: vec!["2 0 obj".to_string()],
                evidence: vec![],
                remediation: None,
                meta: HashMap::new(),
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                positions: Vec::new(),
            },
        ];

        let calibrator = CalibrationModel::platt_scaling(1.0, 0.0);
        let prediction = calibrate_prediction(0.8, &calibrator);

        let explanation = MlExplanation {
            prediction: 0.8,
            baseline_score: 0.1,
            top_positive_features: vec![],
            top_negative_features: vec![],
            feature_group_importance: HashMap::new(),
            summary: "High risk document".to_string(),
        };

        let profile = generate_document_risk_profile(
            &findings,
            prediction,
            explanation,
            vec![],
            None,
            vec![],
        );

        assert_eq!(profile.total_findings, 2);
        assert_eq!(profile.critical_count, 1);
        assert_eq!(profile.high_severity_count, 1);
        assert_eq!(profile.attack_surface_diversity, 2);
        assert!(profile.js_risk.present);
        assert!(profile.structural_risk.xref_issues > 0);
    }

    #[test]
    fn test_category_risk_profiles_default() {
        let js_profile = JsRiskProfile::default();
        assert!(!js_profile.present);
        assert_eq!(js_profile.count, 0);

        let uri_profile = UriRiskProfile::default();
        assert!(!uri_profile.present);

        let structural_profile = StructuralRiskProfile::default();
        assert_eq!(structural_profile.spec_violations, 0);
    }

    #[test]
    fn test_calibrated_prediction_interpretation() {
        let calibrator = CalibrationModel::platt_scaling(1.0, 0.0);

        let pred_high = calibrate_prediction(5.0, &calibrator);
        assert!(pred_high.interpretation.contains("Very high confidence"));

        let pred_low = calibrate_prediction(-5.0, &calibrator);
        assert!(pred_low.interpretation.contains("Very low risk"));

        let pred_medium = calibrate_prediction(0.5, &calibrator);
        assert!(
            pred_medium.interpretation.contains("Possibly")
                || pred_medium.interpretation.contains("Likely")
        );
    }

    #[test]
    fn test_generate_counterfactual_linear() {
        let model = LinearModel { bias: 0.0, weights: vec![1.0, 0.5, -0.2] };
        let feature_names =
            vec!["feature_a".to_string(), "feature_b".to_string(), "feature_c".to_string()];
        let feature_values = vec![2.0, 1.0, 0.0];

        let mut baseline = BenignBaseline::default();
        baseline.feature_means.insert("feature_a".to_string(), 0.0);
        baseline.feature_means.insert("feature_b".to_string(), 0.0);

        let cf = generate_counterfactual_linear(
            &model,
            &feature_values,
            &feature_names,
            0.2,
            2,
            Some(&baseline),
        );

        assert!(cf.achieved_score <= cf.original_score);
        assert!(!cf.changes.is_empty());
    }

    #[test]
    fn test_analyse_temporal_risk() {
        let samples = vec![
            TemporalSnapshot {
                version_label: "v1".to_string(),
                score: 0.2,
                high_severity_count: 1,
                finding_count: 5,
            },
            TemporalSnapshot {
                version_label: "v2".to_string(),
                score: 0.45,
                high_severity_count: 2,
                finding_count: 8,
            },
            TemporalSnapshot {
                version_label: "v3".to_string(),
                score: 0.6,
                high_severity_count: 3,
                finding_count: 10,
            },
        ];

        let explanation = analyse_temporal_risk(&samples);
        assert_eq!(explanation.trend, "increasing");
        assert!(explanation.score_delta > 0.0);
    }

    #[test]
    fn test_detect_feature_interactions() {
        let mut baseline = BenignBaseline::default();
        baseline.feature_means.insert("feature_a".to_string(), 0.0);
        baseline.feature_stddevs.insert("feature_a".to_string(), 1.0);
        baseline.feature_means.insert("feature_b".to_string(), 0.0);
        baseline.feature_stddevs.insert("feature_b".to_string(), 1.0);

        let mut feature_map = HashMap::new();
        feature_map.insert("feature_a".to_string(), 3.0);
        feature_map.insert("feature_b".to_string(), 2.5);

        let interactions = detect_feature_interactions(&feature_map, &baseline, 5);
        assert_eq!(interactions.len(), 1);
        assert!(interactions[0].interaction_score > 0.0);
    }
}
