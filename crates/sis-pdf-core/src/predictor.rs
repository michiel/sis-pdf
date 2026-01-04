use crate::behavior::ThreatPattern;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FutureThreat {
    pub label: String,
    pub confidence: f32,
}

pub struct BehavioralPredictor;

impl BehavioralPredictor {
    pub fn predict_evolution(&self, patterns: &[ThreatPattern]) -> Vec<FutureThreat> {
        let mut out = Vec::new();
        for pattern in patterns {
            if pattern.kinds.iter().any(|k| k.contains("js"))
                && pattern.kinds.iter().any(|k| k.contains("embedded"))
            {
                out.push(FutureThreat {
                    label: "payload_dropper".into(),
                    confidence: 0.7,
                });
            } else if pattern.kinds.iter().any(|k| k.contains("launch")) {
                out.push(FutureThreat {
                    label: "external_execution".into(),
                    confidence: 0.6,
                });
            }
        }
        out
    }
}
