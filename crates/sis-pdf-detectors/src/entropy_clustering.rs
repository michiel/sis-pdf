use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::entropy::shannon_entropy;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_pdf::object::PdfAtom;

/// Entropy threshold above typical FlateDecode output (~7.3–7.8).
/// Near-8.0 entropy indicates truly random/encrypted/packed binary content.
const HIGH_ENTROPY_THRESHOLD: f64 = 7.9;
const MIN_STREAM_COUNT: usize = 2;
const HIGH_ENTROPY_RATIO_THRESHOLD: f64 = 0.30;

pub struct EntropyClusteringDetector;

impl Detector for EntropyClusteringDetector {
    fn id(&self) -> &'static str {
        "entropy_clustering"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::StreamsAndFilters
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Expensive
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut high_entropy_count = 0usize;
        let mut total_stream_count = 0usize;

        for entry in &ctx.graph.objects {
            let PdfAtom::Stream(stream) = &entry.atom else {
                continue;
            };
            let span = stream.data_span;
            let raw = ctx.bytes.get(span.start as usize..span.end as usize).unwrap_or(&[]);
            if raw.is_empty() {
                continue;
            }
            total_stream_count += 1;
            let entropy = shannon_entropy(raw);
            if entropy >= HIGH_ENTROPY_THRESHOLD {
                high_entropy_count += 1;
            }
        }

        if total_stream_count < MIN_STREAM_COUNT {
            return Ok(Vec::new());
        }

        let ratio = high_entropy_count as f64 / total_stream_count as f64;
        if ratio <= HIGH_ENTROPY_RATIO_THRESHOLD {
            return Ok(Vec::new());
        }

        let ratio_pct = (ratio * 100.0).round() as u32;
        let mut meta = std::collections::HashMap::new();
        meta.insert("entropy.high_object_count".into(), high_entropy_count.to_string());
        meta.insert("entropy.total_objects".into(), total_stream_count.to_string());
        meta.insert("entropy.ratio".into(), format!("{:.2}", ratio));

        Ok(vec![Finding {
            id: String::new(),
            surface: self.surface(),
            kind: "entropy_high_object_ratio".into(),
            severity: Severity::Low,
            confidence: Confidence::Probable,
            impact: Impact::Unknown,
            title: format!("High proportion of high-entropy stream objects ({ratio_pct}%)"),
            description: format!(
                "{high_entropy_count} of {total_stream_count} stream objects have Shannon entropy \
                 >= {HIGH_ENTROPY_THRESHOLD:.1} (ratio {ratio:.2}), indicating packed or \
                 encrypted payload hiding."
            ),
            objects: Vec::new(),
            evidence: Vec::new(),
            remediation: Some(
                "Inspect high-entropy streams for encrypted or packed payloads.".into(),
            ),
            meta,
            yara: None,
            positions: Vec::new(),
            ..Finding::default()
        }])
    }
}
