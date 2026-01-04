use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::scan::ScanOptions;

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
    pub diff_parser: Option<bool>,
    pub max_objects: Option<usize>,
    pub max_recursion_depth: Option<usize>,
    pub fast: Option<bool>,
    pub focus_trigger: Option<String>,
    pub focus_depth: Option<usize>,
    pub yara_scope: Option<String>,
    pub strict: Option<bool>,
    pub ml_model: Option<String>,
    pub ml_threshold: Option<f32>,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
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
        opts.max_decode_bytes = v;
    }
    if let Some(v) = scan.max_total_decoded_bytes {
        opts.max_total_decoded_bytes = v;
    }
    if let Some(v) = scan.recover_xref {
        opts.recover_xref = v;
    }
    if let Some(v) = scan.parallel {
        opts.parallel = v;
    }
    if let Some(v) = scan.diff_parser {
        opts.diff_parser = v;
    }
    if let Some(v) = scan.max_objects {
        opts.max_objects = v;
    }
    if let Some(v) = scan.max_recursion_depth {
        opts.max_recursion_depth = v;
    }
    if let Some(v) = scan.fast {
        opts.fast = v;
    }
    if let Some(v) = &scan.focus_trigger {
        opts.focus_trigger = Some(v.clone());
    }
    if let Some(v) = scan.focus_depth {
        opts.focus_depth = v;
    }
    if let Some(v) = &scan.yara_scope {
        opts.yara_scope = Some(v.clone());
    }
    if let Some(v) = scan.strict {
        opts.strict = v;
    }
    if let Some(model) = &scan.ml_model {
        let threshold = scan.ml_threshold.unwrap_or(0.9);
        opts.ml_config = Some(crate::ml::MlConfig {
            model_path: model.into(),
            threshold,
        });
    } else if let Some(v) = scan.ml_threshold {
        if let Some(cfg) = &mut opts.ml_config {
            cfg.threshold = v;
        }
    }
}
