use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::quantum::{CryptoUsage, QuantumThreatAnalyzer};
use sis_pdf_pdf::object::PdfAtom;

use crate::entry_dict;

pub struct QuantumRiskDetector;

impl Detector for QuantumRiskDetector {
    fn id(&self) -> &'static str {
        "quantum_risk"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::CryptoSignatures
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Cheap
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut algos = Vec::new();
        for entry in &ctx.graph.objects {
            let Some(dict) = entry_dict(entry) else { continue };
            if dict.has_name(b"/Type", b"/Sig") || dict.get_first(b"/ByteRange").is_some() {
                if let Some((_, v)) = dict.get_first(b"/SubFilter") {
                    if let PdfAtom::Name(n) = &v.atom {
                        let val = String::from_utf8_lossy(&n.decoded).to_string();
                        if val.contains("RSA") || val.contains("ECDSA") || val.contains("DSA") {
                            algos.push(val);
                        } else if val.contains("pkcs7") {
                            algos.push("RSA".into());
                        }
                    }
                }
            }
        }
        if algos.is_empty() {
            return Ok(Vec::new());
        }
        let analyzer = QuantumThreatAnalyzer;
        let usage = CryptoUsage { algorithms: algos.clone() };
        let risk = analyzer.assess_quantum_vulnerability(&usage);
        if risk.score < 0.5 {
            return Ok(Vec::new());
        }
        let mut meta = std::collections::HashMap::new();
        meta.insert("quantum.algorithms".into(), algos.join(","));
        meta.insert("quantum.score".into(), format!("{:.2}", risk.score));
        let recs = analyzer.recommend_pq_alternatives(&risk);
        if !recs.is_empty() {
            meta.insert("quantum.recommendations".into(), recs.join(","));
        }
        Ok(vec![Finding {
            id: String::new(),
            surface: self.surface(),
            kind: "quantum_vulnerable_crypto".into(),
            severity: Severity::Low,
            confidence: Confidence::Heuristic,
            title: "Quantum-vulnerable cryptography".into(),
            description: "Signature algorithms are vulnerable to post-quantum attacks.".into(),
            objects: vec!["signature".into()],
            evidence: Vec::new(),
            remediation: Some("Plan migration to post-quantum algorithms.".into()),
            meta,
            yara: None,
        position: None,
        positions: Vec::new(),
        }])
    }
}
