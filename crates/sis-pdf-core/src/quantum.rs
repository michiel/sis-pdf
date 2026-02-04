#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CryptoUsage {
    pub algorithms: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuantumRisk {
    pub score: f32,
    pub details: Vec<String>,
}

pub struct QuantumThreatAnalyzer;

impl QuantumThreatAnalyzer {
    pub fn assess_quantum_vulnerability(&self, usage: &CryptoUsage) -> QuantumRisk {
        let mut score: f32 = 0.0;
        let mut details = Vec::new();
        for alg in &usage.algorithms {
            if alg.contains("RSA") || alg.contains("DSA") || alg.contains("ECDSA") {
                score = score.max(0.7);
                details.push(format!("{} vulnerable to quantum attacks", alg));
            }
        }
        QuantumRisk { score, details }
    }

    pub fn recommend_pq_alternatives(&self, risk: &QuantumRisk) -> Vec<String> {
        if risk.score < 0.5 {
            return Vec::new();
        }
        vec!["CRYSTALS-Kyber".into(), "CRYSTALS-Dilithium".into(), "Falcon".into()]
    }
}
