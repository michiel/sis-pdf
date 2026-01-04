use std::path::PathBuf;

use crate::features::FeatureVector;

#[derive(Debug, Clone)]
pub struct MlConfig {
    pub model_path: PathBuf,
    pub threshold: f32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MalwarePrediction {
    pub score: f32,
    pub label: bool,
    pub threshold: f32,
    pub base_scores: Vec<f32>,
}

pub trait BaseClassifier: Send + Sync {
    fn predict(&self, fv: &FeatureVector) -> f32;
}

pub trait MetaClassifier: Send + Sync {
    fn predict_from_base(&self, base_scores: &[f32]) -> f32;
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LinearModel {
    pub bias: f32,
    pub weights: Vec<f32>,
}

impl LinearModel {
    pub fn predict_vec(&self, input: &[f32]) -> f32 {
        let mut sum = self.bias;
        for (w, x) in self.weights.iter().zip(input.iter()) {
            sum += w * x;
        }
        sigmoid(sum)
    }
}

impl BaseClassifier for LinearModel {
    fn predict(&self, fv: &FeatureVector) -> f32 {
        let input = fv.as_f32_vec();
        self.predict_vec(&input)
    }
}

impl MetaClassifier for LinearModel {
    fn predict_from_base(&self, base_scores: &[f32]) -> f32 {
        self.predict_vec(base_scores)
    }
}

pub struct StackingClassifier {
    pub base: Vec<Box<dyn BaseClassifier>>,
    pub meta: Box<dyn MetaClassifier>,
}

impl StackingClassifier {
    pub fn predict(&self, fv: &FeatureVector, threshold: f32) -> MalwarePrediction {
        let base_scores: Vec<f32> = self.base.iter().map(|b| b.predict(fv)).collect();
        let score = self.meta.predict_from_base(&base_scores);
        MalwarePrediction {
            score,
            label: score >= threshold,
            threshold,
            base_scores,
        }
    }
}

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}
