use crate::{extract_js_signals_with_ast, run_sandbox, DynamicOptions, DynamicOutcome};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const MALICIOUS_STATIC_SIGNALS: &[&str] = &[
    "js.contains_eval",
    "js.jsfuck_encoding",
    "js.jjencode_encoding",
    "js.aaencode_encoding",
    "js.control_flow_flattening",
    "js.dead_code_injection",
    "js.array_rotation_decode",
    "js.heap_grooming",
    "js.lfh_priming",
    "js.rop_chain_construction",
    "js.info_leak_primitive",
    "js.semantic_source_to_sink_flow",
];

const HIGH_RISK_STATIC_SIGNALS: &[&str] = &[
    "js.contains_eval",
    "js.jsfuck_encoding",
    "js.jjencode_encoding",
    "js.aaencode_encoding",
    "js.control_flow_flattening",
    "js.dead_code_injection",
    "js.array_rotation_decode",
    "js.heap_grooming",
    "js.lfh_priming",
    "js.rop_chain_construction",
    "js.info_leak_primitive",
];

const HIGH_RISK_BEHAVIOURAL_PATTERNS: &[&str] = &[
    "api_call_sequence_malicious",
    "source_sink_complexity",
    "entropy_at_sink",
    "dynamic_string_materialisation_sink",
    "dynamic_code_generation",
    "indirect_dynamic_eval_dispatch",
    "multi_pass_decode_pipeline",
    "covert_beacon_exfil",
    "credential_harvest_form_emulation",
    "chunked_data_exfil_pipeline",
    "lotl_api_chain_execution",
];

#[derive(Debug, Clone, Copy)]
pub struct CorpusThresholds {
    pub min_execution_rate: f64,
    pub min_true_positive_rate: f64,
    pub max_false_positive_rate: f64,
}

impl Default for CorpusThresholds {
    fn default() -> Self {
        Self {
            min_execution_rate: 0.75,
            min_true_positive_rate: 0.85,
            max_false_positive_rate: 0.05,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CorpusSummary {
    pub samples_total: usize,
    pub malicious_total: usize,
    pub benign_total: usize,
    pub executed_total: usize,
    pub malicious_detected: usize,
    pub benign_false_positives: usize,
    pub execution_rate: f64,
    pub true_positive_rate: f64,
    pub false_positive_rate: f64,
}

#[derive(Debug, Clone)]
pub struct CorpusSampleResult {
    pub path: String,
    pub label: String,
    pub executed: bool,
    pub detected: bool,
    pub false_positive: bool,
    pub static_hits: Vec<String>,
    pub behavioural_hits: Vec<String>,
    pub error_count: usize,
}

#[derive(Debug, Clone)]
pub struct CorpusReport {
    pub summary: CorpusSummary,
    pub samples: Vec<CorpusSampleResult>,
    pub thresholds: CorpusThresholds,
}

impl CorpusReport {
    pub fn passes_thresholds(&self) -> bool {
        self.summary.execution_rate >= self.thresholds.min_execution_rate
            && self.summary.true_positive_rate >= self.thresholds.min_true_positive_rate
            && self.summary.false_positive_rate < self.thresholds.max_false_positive_rate
    }

    pub fn to_json_value(&self) -> Value {
        json!({
            "summary": {
                "samples_total": self.summary.samples_total,
                "malicious_total": self.summary.malicious_total,
                "benign_total": self.summary.benign_total,
                "executed_total": self.summary.executed_total,
                "malicious_detected": self.summary.malicious_detected,
                "benign_false_positives": self.summary.benign_false_positives,
                "execution_rate": self.summary.execution_rate,
                "true_positive_rate": self.summary.true_positive_rate,
                "false_positive_rate": self.summary.false_positive_rate,
            },
            "thresholds": {
                "min_execution_rate": self.thresholds.min_execution_rate,
                "min_true_positive_rate": self.thresholds.min_true_positive_rate,
                "max_false_positive_rate": self.thresholds.max_false_positive_rate,
            },
            "passes_thresholds": self.passes_thresholds(),
            "samples": self.samples.iter().map(|sample| {
                json!({
                    "path": sample.path,
                    "label": sample.label,
                    "executed": sample.executed,
                    "detected": sample.detected,
                    "false_positive": sample.false_positive,
                    "static_hits": sample.static_hits,
                    "behavioural_hits": sample.behavioural_hits,
                    "error_count": sample.error_count,
                })
            }).collect::<Vec<_>>(),
        })
    }
}

pub fn evaluate_corpus(
    corpus_root: &Path,
    thresholds: CorpusThresholds,
) -> Result<CorpusReport, String> {
    let adversarial_dir = corpus_root.join("adversarial");
    let benign_dir = corpus_root.join("benign");
    if !adversarial_dir.is_dir() {
        return Err(format!("missing adversarial corpus directory: {}", adversarial_dir.display()));
    }
    if !benign_dir.is_dir() {
        return Err(format!("missing benign corpus directory: {}", benign_dir.display()));
    }

    let mut adversarial = Vec::new();
    let mut benign = Vec::new();
    collect_js_files(&adversarial_dir, &mut adversarial).map_err(|error| error.to_string())?;
    collect_js_files(&benign_dir, &mut benign).map_err(|error| error.to_string())?;

    adversarial.sort();
    benign.sort();

    let mut samples = Vec::new();
    let mut executed_total = 0usize;
    let mut malicious_detected = 0usize;
    let mut benign_false_positives = 0usize;

    let options = DynamicOptions::default();

    for path in &adversarial {
        let bytes =
            fs::read(path).map_err(|error| format!("read {} failed: {error}", path.display()))?;
        let signals = extract_js_signals_with_ast(&bytes, true);
        let static_hits = signal_hits(&signals, MALICIOUS_STATIC_SIGNALS);
        let (executed, behavioural_hits, error_count) =
            behavioural_hits_for_payload(&bytes, &options);
        if executed {
            executed_total += 1;
        }
        let detected = !static_hits.is_empty() || !behavioural_hits.is_empty();
        if detected {
            malicious_detected += 1;
        }

        samples.push(CorpusSampleResult {
            path: path.display().to_string(),
            label: "adversarial".to_string(),
            executed,
            detected,
            false_positive: false,
            static_hits,
            behavioural_hits,
            error_count,
        });
    }

    for path in &benign {
        let bytes =
            fs::read(path).map_err(|error| format!("read {} failed: {error}", path.display()))?;
        let signals = extract_js_signals_with_ast(&bytes, true);
        let static_hits = signal_hits(&signals, HIGH_RISK_STATIC_SIGNALS);
        let (executed, behavioural_hits, error_count) =
            behavioural_hits_for_payload(&bytes, &options);
        if executed {
            executed_total += 1;
        }
        let false_positive = !static_hits.is_empty() || !behavioural_hits.is_empty();
        if false_positive {
            benign_false_positives += 1;
        }

        samples.push(CorpusSampleResult {
            path: path.display().to_string(),
            label: "benign".to_string(),
            executed,
            detected: false_positive,
            false_positive,
            static_hits,
            behavioural_hits,
            error_count,
        });
    }

    let samples_total = adversarial.len() + benign.len();
    let malicious_total = adversarial.len();
    let benign_total = benign.len();

    let execution_rate = ratio(executed_total, samples_total);
    let true_positive_rate = ratio(malicious_detected, malicious_total);
    let false_positive_rate = ratio(benign_false_positives, benign_total);

    Ok(CorpusReport {
        summary: CorpusSummary {
            samples_total,
            malicious_total,
            benign_total,
            executed_total,
            malicious_detected,
            benign_false_positives,
            execution_rate,
            true_positive_rate,
            false_positive_rate,
        },
        samples,
        thresholds,
    })
}

fn collect_js_files(root: &Path, output: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_js_files(&path, output)?;
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) == Some("js") {
            output.push(path);
        }
    }
    Ok(())
}

fn behavioural_hits_for_payload(
    bytes: &[u8],
    options: &DynamicOptions,
) -> (bool, Vec<String>, usize) {
    match run_sandbox(bytes, options) {
        DynamicOutcome::Executed(signals) => {
            let mut hits = BTreeSet::new();
            for pattern in &signals.behavioral_patterns {
                if HIGH_RISK_BEHAVIOURAL_PATTERNS.iter().any(|name| *name == pattern.name) {
                    hits.insert(pattern.name.clone());
                }
            }
            (true, hits.into_iter().collect(), signals.errors.len())
        }
        DynamicOutcome::TimedOut { .. } => (false, Vec::new(), 1),
        DynamicOutcome::Skipped { .. } => (false, Vec::new(), 0),
    }
}

fn signal_hits(signals: &std::collections::HashMap<String, String>, keys: &[&str]) -> Vec<String> {
    let mut out = BTreeSet::new();
    for key in keys {
        if matches!(signals.get(*key).map(String::as_str), Some("true")) {
            out.insert((*key).to_string());
        }
    }
    out.into_iter().collect()
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    numerator as f64 / denominator as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratio_handles_zero_denominator() {
        assert_eq!(ratio(0, 0), 0.0);
    }
}
