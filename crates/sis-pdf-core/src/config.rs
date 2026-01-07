use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::scan::ScanOptions;

const MAX_CONFIG_BYTES: u64 = 1 * 1024 * 1024;
const MAX_OBJECTS: usize = 10_000_000;
const MAX_DECODE_BYTES: usize = 512 * 1024 * 1024;
const MAX_TOTAL_DECODE_BYTES: usize = 2 * 1024 * 1024 * 1024;
const MAX_RECURSION_DEPTH: usize = 512;
const MAX_FOCUS_DEPTH: usize = 64;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub profiles: Option<HashMap<String, Profile>>,
    pub scan: Option<ScanConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Profile {
    pub scan: Option<ScanConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ScanConfig {
    pub deep: Option<bool>,
    pub max_decode_bytes: Option<usize>,
    pub max_total_decoded_bytes: Option<usize>,
    pub recover_xref: Option<bool>,
    pub parallel: Option<bool>,
    pub batch_parallel: Option<bool>,
    pub diff_parser: Option<bool>,
    pub max_objects: Option<usize>,
    pub max_recursion_depth: Option<usize>,
    pub fast: Option<bool>,
    pub focus_trigger: Option<String>,
    pub focus_depth: Option<usize>,
    pub yara_scope: Option<String>,
    pub strict: Option<bool>,
    pub ir: Option<bool>,
    pub ml_model: Option<String>,
    pub ml_threshold: Option<f32>,
    pub ml_mode: Option<String>,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if let Ok(meta) = fs::metadata(path) {
            if meta.len() > MAX_CONFIG_BYTES {
                return Err(anyhow::anyhow!(
                    "config {} exceeds {} bytes",
                    path.display(),
                    MAX_CONFIG_BYTES
                ));
            }
        }
        let data = fs::read_to_string(path)?;
        let cfg = serde_yaml::from_str::<Config>(&data)?;
        Ok(cfg)
    }

    pub fn apply(&self, opts: &mut ScanOptions, profile: Option<&str>) {
        if let Some(scan) = &self.scan {
            apply_scan(scan, opts);
        }
        if let Some(p) = profile {
            if let Some(profiles) = &self.profiles {
                if let Some(profile_cfg) = profiles.get(p) {
                    if let Some(scan) = &profile_cfg.scan {
                        apply_scan(scan, opts);
                    }
                }
            }
        }
    }
}

fn apply_scan(scan: &ScanConfig, opts: &mut ScanOptions) {
    if let Some(v) = scan.deep {
        opts.deep = v;
    }
    if let Some(v) = scan.max_decode_bytes {
        if v == 0 || v > MAX_DECODE_BYTES {
            eprintln!(
                "security_boundary: invalid max_decode_bytes {} (limit {})",
                v, MAX_DECODE_BYTES
            );
        } else {
            eprintln!(
                "security_boundary: config override max_decode_bytes {}",
                v
            );
            opts.max_decode_bytes = v;
        }
    }
    if let Some(v) = scan.max_total_decoded_bytes {
        if v == 0 || v > MAX_TOTAL_DECODE_BYTES {
            eprintln!(
                "security_boundary: invalid max_total_decoded_bytes {} (limit {})",
                v, MAX_TOTAL_DECODE_BYTES
            );
        } else {
            eprintln!(
                "security_boundary: config override max_total_decoded_bytes {}",
                v
            );
            opts.max_total_decoded_bytes = v;
        }
    }
    if let Some(v) = scan.recover_xref {
        opts.recover_xref = v;
    }
    if let Some(v) = scan.parallel {
        opts.parallel = v;
    }
    if let Some(v) = scan.batch_parallel {
        opts.batch_parallel = v;
    }
    if let Some(v) = scan.diff_parser {
        opts.diff_parser = v;
    }
    if let Some(v) = scan.max_objects {
        if v == 0 || v > MAX_OBJECTS {
            eprintln!(
                "security_boundary: invalid max_objects {} (limit {})",
                v, MAX_OBJECTS
            );
        } else {
            eprintln!(
                "security_boundary: config override max_objects {}",
                v
            );
            opts.max_objects = v;
        }
    }
    if let Some(v) = scan.max_recursion_depth {
        if v == 0 || v > MAX_RECURSION_DEPTH {
            eprintln!(
                "security_boundary: invalid max_recursion_depth {} (limit {})",
                v, MAX_RECURSION_DEPTH
            );
        } else {
            eprintln!(
                "security_boundary: config override max_recursion_depth {}",
                v
            );
            opts.max_recursion_depth = v;
        }
    }
    if let Some(v) = scan.fast {
        opts.fast = v;
    }
    if let Some(v) = &scan.focus_trigger {
        opts.focus_trigger = Some(v.clone());
    }
    if let Some(v) = scan.focus_depth {
        if v > MAX_FOCUS_DEPTH {
            eprintln!(
                "security_boundary: invalid focus_depth {} (limit {})",
                v, MAX_FOCUS_DEPTH
            );
        } else {
            opts.focus_depth = v;
        }
    }
    if let Some(v) = &scan.yara_scope {
        opts.yara_scope = Some(v.clone());
    }
    if let Some(v) = scan.strict {
        opts.strict = v;
    }
    if let Some(v) = scan.ir {
        opts.ir = v;
    }
    if let Some(model) = &scan.ml_model {
        let threshold = scan.ml_threshold.unwrap_or(0.9);
        if !(0.0..=1.0).contains(&threshold) {
            eprintln!(
                "security_boundary: invalid ml_threshold {} (expected 0.0..=1.0)",
                threshold
            );
        }
        let mode = scan
            .ml_mode
            .as_deref()
            .map(parse_ml_mode)
            .unwrap_or(crate::ml::MlMode::Traditional);
        opts.ml_config = Some(crate::ml::MlConfig {
            model_path: model.into(),
            threshold,
            mode,
        });
    } else if let Some(v) = scan.ml_threshold {
        if !(0.0..=1.0).contains(&v) {
            eprintln!(
                "security_boundary: invalid ml_threshold {} (expected 0.0..=1.0)",
                v
            );
        } else if let Some(cfg) = &mut opts.ml_config {
            cfg.threshold = v;
        }
    }
}

fn parse_ml_mode(value: &str) -> crate::ml::MlMode {
    match value.to_lowercase().as_str() {
        "graph" => crate::ml::MlMode::Graph,
        _ => crate::ml::MlMode::Traditional,
    }
}
