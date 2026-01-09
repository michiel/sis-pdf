use std::collections::HashMap;
use std::path::{Path, PathBuf};
use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::explainability::{
    BenignBaseline, FeatureAttribution, EvidenceChain,
    compute_permutation_importance, generate_explanation_text, build_evidence_chains,
    compute_comparative_explanation, ComparativeFeature,
};
use crate::features_extended::ExtendedFeatureVector;
use crate::ml::LinearModel;
use crate::model::Finding;
use crate::scan::ScanContext;

/// Configuration for ML inference
#[derive(Debug, Clone)]
pub struct MlInferenceConfig {
    pub model_path: PathBuf,
    pub baseline_path: Option<PathBuf>,
    pub calibration_path: Option<PathBuf>,
    pub threshold: f32,
    pub explain: bool,
    pub use_extended_features: bool,
}

/// Result of ML inference with optional explanation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlInferenceResult {
    pub prediction: CalibratedPrediction,
    pub explanation: Option<ComprehensiveExplanation>,
}

/// Calibrated prediction with confidence interval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibratedPrediction {
    pub raw_score: f32,
    pub calibrated_score: f32,
    pub confidence_interval: Option<(f32, f32)>,
    pub calibration_method: String,
    pub interpretation: String,
    pub label: bool,
    pub threshold: f32,
}

/// Comprehensive explanation combining all explainability components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveExplanation {
    pub summary: String,
    pub feature_attribution: Vec<FeatureAttribution>,
    pub feature_group_importance: HashMap<String, f32>,
    pub comparative_analysis: Vec<ComparativeFeature>,
    pub evidence_chains: Vec<EvidenceChain>,
    pub decision_factors: Vec<String>,
}

/// Calibration model for score calibration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationModel {
    pub method: CalibrationMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum CalibrationMethod {
    PlattScaling { coef: Vec<f32>, intercept: Vec<f32> },
    IsotonicRegression { x_thresholds: Vec<f32>, y_thresholds: Vec<f32> },
}

impl CalibrationModel {
    /// Load calibration model from JSON file
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let cal: CalibrationModel = serde_json::from_str(&data)?;
        Ok(cal)
    }

    /// Calibrate a raw score
    pub fn calibrate(&self, raw_score: f32) -> f32 {
        match &self.method {
            CalibrationMethod::PlattScaling { coef, intercept } => {
                // Logistic function: 1 / (1 + exp(-(coef * x + intercept)))
                let logit = coef[0] * raw_score + intercept[0];
                1.0 / (1.0 + (-logit).exp())
            }
            CalibrationMethod::IsotonicRegression { x_thresholds, y_thresholds } => {
                // Piecewise constant interpolation
                if raw_score <= x_thresholds[0] {
                    return y_thresholds[0];
                }
                if raw_score >= *x_thresholds.last().unwrap() {
                    return *y_thresholds.last().unwrap();
                }

                // Find the bin
                for i in 0..x_thresholds.len() - 1 {
                    if raw_score >= x_thresholds[i] && raw_score < x_thresholds[i + 1] {
                        // Linear interpolation within bin
                        let ratio = (raw_score - x_thresholds[i]) / (x_thresholds[i + 1] - x_thresholds[i]);
                        return y_thresholds[i] + ratio * (y_thresholds[i + 1] - y_thresholds[i]);
                    }
                }

                // Fallback
                y_thresholds[y_thresholds.len() / 2]
            }
        }
    }
}

/// Run ML inference with extended features and optional explanation
pub fn run_ml_inference(
    ctx: &ScanContext,
    findings: &[Finding],
    config: &MlInferenceConfig,
) -> Result<MlInferenceResult> {
    // 1. Load model
    let model = load_model(&config.model_path)?;

    // 2. Load baseline (only required for explanations)
    let baseline = if config.explain {
        let baseline_path = config.baseline_path.as_ref().ok_or_else(|| {
            anyhow::anyhow!("ML explanations require --ml-baseline")
        })?;
        Some(BenignBaseline::load_from_file(baseline_path)
            .map_err(|e| anyhow::anyhow!("Failed to load baseline: {}", e))?)
    } else {
        None
    };

    // 3. Extract features
    let features = if config.use_extended_features {
        crate::features_extended::extract_extended_features(ctx, findings)
    } else {
        // Fallback: extract legacy features and convert to extended
        let legacy = crate::features::FeatureExtractor::extract(ctx);
        ExtendedFeatureVector::from_legacy(legacy)
    };

    // 4. Run model prediction
    let feature_vec = features.as_f32_vec();
    let raw_score = model.predict_vec(&feature_vec);

    // 5. Calibrate prediction
    let calibrated = if let Some(cal_path) = &config.calibration_path {
        let calibrator = CalibrationModel::load_from_file(cal_path)
            .map_err(|e| anyhow::anyhow!("Failed to load calibration model: {}", e))?;
        let calibrated_score = calibrator.calibrate(raw_score);

        // Estimate confidence interval (simplified)
        let ci_width = 0.1 * (1.0 - calibrated_score) * calibrated_score;
        let confidence_interval = Some((
            (calibrated_score - ci_width).max(0.0),
            (calibrated_score + ci_width).min(1.0),
        ));

        let interpretation = format!(
            "{:.0}% probability of being malicious ({:.0}%-{:.0}% with 95% confidence)",
            calibrated_score * 100.0,
            confidence_interval.unwrap().0 * 100.0,
            confidence_interval.unwrap().1 * 100.0
        );

        CalibratedPrediction {
            raw_score,
            calibrated_score,
            confidence_interval,
            calibration_method: format!("{:?}", calibrator.method).split('(').next().unwrap().to_string(),
            interpretation,
            label: calibrated_score >= config.threshold,
            threshold: config.threshold,
        }
    } else {
        // No calibration
        CalibratedPrediction {
            raw_score,
            calibrated_score: raw_score,
            confidence_interval: None,
            calibration_method: "none".to_string(),
            interpretation: format!("{:.0}% risk (uncalibrated)", raw_score * 100.0),
            label: raw_score >= config.threshold,
            threshold: config.threshold,
        }
    };

    // 6. Generate explanation (if requested)
    let explanation = if config.explain {
        Some(generate_comprehensive_explanation(
            &features,
            baseline.as_ref().expect("baseline required for explanation"),
            findings,
            &calibrated,
            &model,
        )?)
    } else {
        None
    };

    Ok(MlInferenceResult {
        prediction: calibrated,
        explanation,
    })
}

/// Generate comprehensive explanation
fn generate_comprehensive_explanation(
    features: &ExtendedFeatureVector,
    baseline: &BenignBaseline,
    findings: &[Finding],
    prediction: &CalibratedPrediction,
    model: &LinearModel,
) -> Result<ComprehensiveExplanation> {
    // Feature attribution via permutation importance
    let feature_vec = features.as_f32_vec();
    let feature_names = ExtendedFeatureVector::feature_names();
    let model_fn = |fv: &[f32]| -> f32 {
        model.predict_vec(fv)
    };
    let attribution = compute_permutation_importance(&model_fn, &feature_vec, &feature_names, baseline);

    // Natural language summary
    let summary = generate_explanation_text(
        prediction.calibrated_score,
        &attribution,
        findings,
    );

    // Feature group importance
    let mut group_importance = HashMap::new();
    for attr in &attribution {
        let group = attr.feature_name
            .split('.')
            .next()
            .unwrap_or("other")
            .to_string();
        *group_importance.entry(group).or_insert(0.0) += attr.contribution.abs();
    }

    // Comparative analysis
    let feature_map: HashMap<String, f32> = feature_names
        .iter()
        .zip(&feature_vec)
        .map(|(name, &val)| (name.clone(), val))
        .collect();
    let comparative = compute_comparative_explanation(&feature_map, baseline, 10);

    // Evidence chains
    let evidence_chains = build_evidence_chains(&attribution, findings);

    // Decision factors (bullet points)
    let decision_factors = generate_decision_factors(
        &attribution,
        &comparative,
        findings,
    );

    Ok(ComprehensiveExplanation {
        summary,
        feature_attribution: attribution.into_iter().take(10).collect(),
        feature_group_importance: group_importance,
        comparative_analysis: comparative,
        evidence_chains: evidence_chains.into_iter().take(10).collect(),
        decision_factors,
    })
}

/// Generate decision factor bullet points
fn generate_decision_factors(
    attribution: &[FeatureAttribution],
    comparative: &[ComparativeFeature],
    findings: &[Finding],
) -> Vec<String> {
    let mut factors = Vec::new();

    // Top contributing features
    for attr in attribution.iter().take(3) {
        if attr.contribution.abs() > 0.01 {
            factors.push(format!(
                "{} (value: {:.2}, contribution: {:+.2})",
                crate::explainability::humanize_feature_name(&attr.feature_name),
                attr.value,
                attr.contribution
            ));
        }
    }

    // Extreme outliers
    for comp in comparative.iter().take(2) {
        if comp.z_score > 3.0 {
            factors.push(format!(
                "{} is extremely high ({:.1}σ above benign average)",
                crate::explainability::humanize_feature_name(&comp.feature_name),
                comp.z_score
            ));
        }
    }

    // High-severity findings
    let high_count = findings
        .iter()
        .filter(|f| {
            matches!(f.severity, crate::model::Severity::High | crate::model::Severity::Critical)
        })
        .count();
    if high_count > 0 {
        factors.push(format!("{} high/critical severity findings", high_count));
    }

    // Attack surface diversity
    let surfaces: std::collections::HashSet<_> = findings
        .iter()
        .map(|f| format!("{:?}", f.surface))
        .collect();
    if surfaces.len() >= 3 {
        factors.push(format!(
            "Multiple attack surfaces detected: {}",
            surfaces.len()
        ));
    }

    factors
}

/// Load ML model from file
fn load_model(path: &Path) -> Result<LinearModel> {
    let data = std::fs::read_to_string(path)?;
    let model: LinearModel = serde_json::from_str(&data)?;
    Ok(model)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platt_scaling_calibration() {
        let cal = CalibrationModel {
            method: CalibrationMethod::PlattScaling {
                coef: vec![2.0],
                intercept: vec![-1.0],
            },
        };

        let calibrated = cal.calibrate(0.5);
        assert!(calibrated > 0.0 && calibrated < 1.0);
    }

    #[test]
    fn test_isotonic_regression_calibration() {
        let cal = CalibrationModel {
            method: CalibrationMethod::IsotonicRegression {
                x_thresholds: vec![0.0, 0.5, 1.0],
                y_thresholds: vec![0.0, 0.6, 1.0],
            },
        };

        let calibrated = cal.calibrate(0.5);
        assert_eq!(calibrated, 0.6);

        let calibrated2 = cal.calibrate(0.25);
        assert!(calibrated2 > 0.0 && calibrated2 < 0.6);
    }

    #[test]
    fn test_calibrated_prediction_interpretation() {
        let pred = CalibratedPrediction {
            raw_score: 0.73,
            calibrated_score: 0.68,
            confidence_interval: Some((0.60, 0.76)),
            calibration_method: "PlattScaling".to_string(),
            interpretation: "68% probability of being malicious (60%-76% with 95% confidence)".to_string(),
            label: true,
            threshold: 0.5,
        };

        assert!(pred.label);
        assert!(pred.calibrated_score >= pred.threshold);
    }
}
