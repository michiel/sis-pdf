use crate::features::FeatureVector;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdversarialAttempt {
    pub score: f32,
    pub reason: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StabilityScore {
    pub score: f32,
}

pub struct AdversarialDefense;

impl AdversarialDefense {
    pub fn detect_adversarial(&self, features: &FeatureVector) -> Option<AdversarialAttempt> {
        let mut score: f32 = 0.0;
        let mut reasons: Vec<String> = Vec::new();
        if features.general.file_entropy > 7.5 && features.general.object_count < 20 {
            score += 0.5;
            reasons.push("high entropy with low object count".into());
        }
        if features.general.binary_ratio > 0.95 {
            score += 0.4;
            reasons.push("high binary ratio".into());
        }
        if features.structural.objstm_count > 2000 {
            score += 0.3;
            reasons.push("excessive object streams".into());
        }
        if score >= 0.6 {
            return Some(AdversarialAttempt {
                score,
                reason: reasons.join("; "),
            });
        }
        None
    }

    pub fn apply_gradient_masking(&mut self) {
        // Placeholder: model-side mitigation handled in training pipeline.
    }

    pub fn validate_prediction_stability(&self, features: &FeatureVector) -> StabilityScore {
        let mut penalty: f32 = 0.0;
        if features.behavioral.js_object_count > 20 {
            penalty += 0.2;
        }
        if features.structural.max_object_id > 500_000 {
            penalty += 0.2;
        }
        StabilityScore {
            score: (1.0 - penalty).max(0.0),
        }
    }
}
