use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::filter_allowlist::load_filter_allowlist;
use crate::scan::ScanOptions;
use crate::security_log::{SecurityDomain, SecurityEvent};
use tracing::{info, warn, Level};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_OBJECTS: usize = 10_000_000;
const MAX_DECODE_BYTES: usize = 512 * 1024 * 1024;
const MAX_TOTAL_DECODE_BYTES: usize = 2 * 1024 * 1024 * 1024;
const MAX_RECURSION_DEPTH: usize = 512;
const MAX_FOCUS_DEPTH: usize = 64;
const MAX_FONTS: usize = 10_000;
const MAX_FONT_DYNAMIC_TIMEOUT_MS: u64 = 10_000;
const MAX_IMAGE_PIXELS: u64 = 1_000_000_000;
const MAX_IMAGE_DECODE_BYTES: usize = 512 * 1024 * 1024;
const MAX_IMAGE_TIMEOUT_MS: u64 = 10_000;
const MAX_IMAGE_HEADER_BYTES: usize = 1024 * 1024;
const MAX_IMAGE_DIMENSION: u32 = 100_000;
const MAX_IMAGE_XFA_DECODE_BYTES: usize = 64 * 1024 * 1024;
const MAX_IMAGE_FILTER_CHAIN_DEPTH: usize = 32;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub profiles: Option<HashMap<String, Profile>>,
    pub scan: Option<ScanConfig>,
    pub logging: Option<LoggingConfig>,
    pub query: Option<QueryConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Profile {
    pub scan: Option<ScanConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    pub level: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct QueryConfig {
    #[serde(alias = "color")]
    pub colour: Option<bool>,
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
    pub group_chains: Option<bool>,
    pub ml_model: Option<String>,
    pub ml_threshold: Option<f32>,
    pub ml_mode: Option<String>,
    pub ml_provider: Option<String>,
    pub ml_provider_order: Option<Vec<String>>,
    pub ml_ort_dylib: Option<String>,
    pub ml_quantized: Option<bool>,
    pub ml_batch_size: Option<usize>,
    pub ml_provider_info: Option<bool>,
    pub filter_allowlist: Option<String>,
    pub filter_allowlist_strict: Option<bool>,
    #[serde(rename = "font-analysis")]
    pub font_analysis: Option<FontAnalysisConfig>,
    #[serde(rename = "image-analysis")]
    pub image_analysis: Option<ImageAnalysisConfig>,
    pub correlation: Option<CorrelationConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct FontAnalysisConfig {
    pub enabled: Option<bool>,
    pub dynamic_enabled: Option<bool>,
    pub dynamic_timeout_ms: Option<u64>,
    pub max_fonts: Option<usize>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ImageAnalysisConfig {
    pub enabled: Option<bool>,
    pub dynamic_enabled: Option<bool>,
    pub max_pixels: Option<u64>,
    pub max_decode_bytes: Option<usize>,
    pub timeout_ms: Option<u64>,
    pub max_header_bytes: Option<usize>,
    pub max_dimension: Option<u32>,
    pub max_xfa_decode_bytes: Option<usize>,
    pub max_filter_chain_depth: Option<usize>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CorrelationConfig {
    pub enabled: Option<bool>,
    pub launch_obfuscated: Option<bool>,
    pub action_chain_malicious: Option<bool>,
    pub xfa_data_exfiltration: Option<bool>,
    pub encrypted_payload_delivery: Option<bool>,
    pub obfuscated_payload: Option<bool>,
    pub high_entropy_threshold: Option<f64>,
    pub action_chain_depth: Option<usize>,
    pub xfa_sensitive_field_threshold: Option<usize>,
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
        let cfg = match path.extension().and_then(|s| s.to_str()) {
            Some("toml") => toml::from_str::<Config>(&data)?,
            Some("yaml") | Some("yml") => serde_yaml::from_str::<Config>(&data)?,
            _ => toml::from_str::<Config>(&data)
                .or_else(|_| serde_yaml::from_str::<Config>(&data))?,
        };
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
            SecurityEvent {
                level: Level::WARN,
                domain: SecurityDomain::Detection,
                severity: crate::model::Severity::Low,
                kind: "invalid_max_decode_bytes",
                policy: None,
                object_id: None,
                object_type: None,
                vector: None,
                technique: None,
                confidence: None,
                message: "Invalid max_decode_bytes in config",
            }
            .emit();
            warn!(value = v, limit = MAX_DECODE_BYTES, "Invalid max_decode_bytes in config");
        } else {
            info!(value = v, "Config override max_decode_bytes");
            opts.max_decode_bytes = v;
        }
    }
    if let Some(v) = scan.max_total_decoded_bytes {
        if v == 0 || v > MAX_TOTAL_DECODE_BYTES {
            SecurityEvent {
                level: Level::WARN,
                domain: SecurityDomain::Detection,
                severity: crate::model::Severity::Low,
                kind: "invalid_max_total_decoded_bytes",
                policy: None,
                object_id: None,
                object_type: None,
                vector: None,
                technique: None,
                confidence: None,
                message: "Invalid max_total_decoded_bytes in config",
            }
            .emit();
            warn!(
                value = v,
                limit = MAX_TOTAL_DECODE_BYTES,
                "Invalid max_total_decoded_bytes in config"
            );
        } else {
            info!(value = v, "Config override max_total_decoded_bytes");
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
            SecurityEvent {
                level: Level::WARN,
                domain: SecurityDomain::Detection,
                severity: crate::model::Severity::Low,
                kind: "invalid_max_objects",
                policy: None,
                object_id: None,
                object_type: None,
                vector: None,
                technique: None,
                confidence: None,
                message: "Invalid max_objects in config",
            }
            .emit();
            warn!(value = v, limit = MAX_OBJECTS, "Invalid max_objects in config");
        } else {
            info!(value = v, "Config override max_objects");
            opts.max_objects = v;
        }
    }
    if let Some(v) = scan.max_recursion_depth {
        if v == 0 || v > MAX_RECURSION_DEPTH {
            SecurityEvent {
                level: Level::WARN,
                domain: SecurityDomain::Detection,
                severity: crate::model::Severity::Low,
                kind: "invalid_max_recursion_depth",
                policy: None,
                object_id: None,
                object_type: None,
                vector: None,
                technique: None,
                confidence: None,
                message: "Invalid max_recursion_depth in config",
            }
            .emit();
            warn!(value = v, limit = MAX_RECURSION_DEPTH, "Invalid max_recursion_depth in config");
        } else {
            info!(value = v, "Config override max_recursion_depth");
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
            SecurityEvent {
                level: Level::WARN,
                domain: SecurityDomain::Detection,
                severity: crate::model::Severity::Low,
                kind: "invalid_focus_depth",
                policy: None,
                object_id: None,
                object_type: None,
                vector: None,
                technique: None,
                confidence: None,
                message: "Invalid focus_depth in config",
            }
            .emit();
            warn!(value = v, limit = MAX_FOCUS_DEPTH, "Invalid focus_depth in config");
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
    if let Some(v) = scan.group_chains {
        opts.group_chains = v;
    }
    if let Some(model) = &scan.ml_model {
        let threshold = scan.ml_threshold.unwrap_or(0.9);
        if !(0.0..=1.0).contains(&threshold) {
            SecurityEvent {
                level: Level::WARN,
                domain: SecurityDomain::Ml,
                severity: crate::model::Severity::Low,
                kind: "invalid_ml_threshold",
                policy: None,
                object_id: None,
                object_type: None,
                vector: None,
                technique: None,
                confidence: None,
                message: "Invalid ML threshold in config",
            }
            .emit();
            warn!(value = threshold, "Invalid ml_threshold in config (expected 0.0..=1.0)");
        }
        let mode =
            scan.ml_mode.as_deref().map(parse_ml_mode).unwrap_or(crate::ml::MlMode::Traditional);
        opts.ml_config = Some(crate::ml::MlConfig {
            model_path: model.into(),
            threshold,
            mode,
            runtime: crate::ml::MlRuntimeConfig::default(),
        });
    } else if let Some(v) = scan.ml_threshold {
        if !(0.0..=1.0).contains(&v) {
            SecurityEvent {
                level: Level::WARN,
                domain: SecurityDomain::Ml,
                severity: crate::model::Severity::Low,
                kind: "invalid_ml_threshold",
                policy: None,
                object_id: None,
                object_type: None,
                vector: None,
                technique: None,
                confidence: None,
                message: "Invalid ML threshold in config",
            }
            .emit();
            warn!(value = v, "Invalid ml_threshold in config (expected 0.0..=1.0)");
        } else if let Some(cfg) = &mut opts.ml_config {
            cfg.threshold = v;
        }
    }

    if let Some(cfg) = opts.ml_config.as_mut() {
        if let Some(provider) = &scan.ml_provider {
            cfg.runtime.provider = Some(provider.clone());
        }
        if let Some(order) = &scan.ml_provider_order {
            cfg.runtime.provider_order = Some(order.clone());
        }
        if let Some(path) = &scan.ml_ort_dylib {
            cfg.runtime.ort_dylib_path = Some(path.into());
        }
        if let Some(prefer) = scan.ml_quantized {
            cfg.runtime.prefer_quantized = prefer;
        }
        if let Some(size) = scan.ml_batch_size {
            cfg.runtime.max_embedding_batch_size = Some(size);
        }
        if let Some(print) = scan.ml_provider_info {
            cfg.runtime.print_provider = print;
        }
    }

    if let Some(strict) = scan.filter_allowlist_strict {
        opts.filter_allowlist_strict = strict;
    }
    if let Some(path) = scan.filter_allowlist.as_deref() {
        match load_filter_allowlist(std::path::Path::new(path)) {
            Ok(allowlist) => opts.filter_allowlist = Some(allowlist),
            Err(err) => {
                warn!(
                    security = true,
                    domain = %SecurityDomain::Detection,
                    kind = "filter_allowlist_load_failed",
                    error = %err,
                    path = path,
                    "Failed to load filter allowlist"
                );
            }
        }
    }

    if let Some(font_cfg) = &scan.font_analysis {
        if let Some(enabled) = font_cfg.enabled {
            opts.font_analysis.enabled = enabled;
        }
        if let Some(enabled) = font_cfg.dynamic_enabled {
            opts.font_analysis.dynamic_enabled = enabled;
        }
        if let Some(timeout) = font_cfg.dynamic_timeout_ms {
            if timeout == 0 || timeout > MAX_FONT_DYNAMIC_TIMEOUT_MS {
                SecurityEvent {
                    level: Level::WARN,
                    domain: SecurityDomain::Detection,
                    severity: crate::model::Severity::Low,
                    kind: "invalid_font_dynamic_timeout",
                    policy: None,
                    object_id: None,
                    object_type: None,
                    vector: None,
                    technique: None,
                    confidence: None,
                    message: "Invalid font dynamic timeout in config",
                }
                .emit();
                warn!(
                    value = timeout,
                    limit = MAX_FONT_DYNAMIC_TIMEOUT_MS,
                    "Invalid font dynamic timeout in config"
                );
            } else {
                opts.font_analysis.dynamic_timeout_ms = timeout;
            }
        }
        if let Some(max_fonts) = font_cfg.max_fonts {
            if max_fonts == 0 || max_fonts > MAX_FONTS {
                SecurityEvent {
                    level: Level::WARN,
                    domain: SecurityDomain::Detection,
                    severity: crate::model::Severity::Low,
                    kind: "invalid_font_max_fonts",
                    policy: None,
                    object_id: None,
                    object_type: None,
                    vector: None,
                    technique: None,
                    confidence: None,
                    message: "Invalid max_fonts in config",
                }
                .emit();
                warn!(value = max_fonts, limit = MAX_FONTS, "Invalid max_fonts in config");
            } else {
                opts.font_analysis.max_fonts = max_fonts;
            }
        }
    }

    if let Some(image_cfg) = &scan.image_analysis {
        if let Some(enabled) = image_cfg.enabled {
            opts.image_analysis.enabled = enabled;
        }
        if let Some(enabled) = image_cfg.dynamic_enabled {
            opts.image_analysis.dynamic_enabled = enabled;
        }
        if let Some(max_pixels) = image_cfg.max_pixels {
            if max_pixels == 0 || max_pixels > MAX_IMAGE_PIXELS {
                SecurityEvent {
                    level: Level::WARN,
                    domain: SecurityDomain::Detection,
                    severity: crate::model::Severity::Low,
                    kind: "invalid_image_max_pixels",
                    policy: None,
                    object_id: None,
                    object_type: None,
                    vector: None,
                    technique: None,
                    confidence: None,
                    message: "Invalid image max_pixels in config",
                }
                .emit();
                warn!(
                    value = max_pixels,
                    limit = MAX_IMAGE_PIXELS,
                    "Invalid image max_pixels in config"
                );
            } else {
                opts.image_analysis.max_pixels = max_pixels;
            }
        }
        if let Some(max_bytes) = image_cfg.max_decode_bytes {
            if max_bytes == 0 || max_bytes > MAX_IMAGE_DECODE_BYTES {
                SecurityEvent {
                    level: Level::WARN,
                    domain: SecurityDomain::Detection,
                    severity: crate::model::Severity::Low,
                    kind: "invalid_image_max_decode_bytes",
                    policy: None,
                    object_id: None,
                    object_type: None,
                    vector: None,
                    technique: None,
                    confidence: None,
                    message: "Invalid image max_decode_bytes in config",
                }
                .emit();
                warn!(
                    value = max_bytes,
                    limit = MAX_IMAGE_DECODE_BYTES,
                    "Invalid image max_decode_bytes in config"
                );
            } else {
                opts.image_analysis.max_decode_bytes = max_bytes;
            }
        }
        if let Some(timeout) = image_cfg.timeout_ms {
            if timeout == 0 || timeout > MAX_IMAGE_TIMEOUT_MS {
                SecurityEvent {
                    level: Level::WARN,
                    domain: SecurityDomain::Detection,
                    severity: crate::model::Severity::Low,
                    kind: "invalid_image_timeout_ms",
                    policy: None,
                    object_id: None,
                    object_type: None,
                    vector: None,
                    technique: None,
                    confidence: None,
                    message: "Invalid image timeout_ms in config",
                }
                .emit();
                warn!(
                    value = timeout,
                    limit = MAX_IMAGE_TIMEOUT_MS,
                    "Invalid image timeout_ms in config"
                );
            } else {
                opts.image_analysis.timeout_ms = timeout;
            }
        }
        if let Some(max_header_bytes) = image_cfg.max_header_bytes {
            if max_header_bytes == 0 || max_header_bytes > MAX_IMAGE_HEADER_BYTES {
                SecurityEvent {
                    level: Level::WARN,
                    domain: SecurityDomain::Detection,
                    severity: crate::model::Severity::Low,
                    kind: "invalid_image_max_header_bytes",
                    policy: None,
                    object_id: None,
                    object_type: None,
                    vector: None,
                    technique: None,
                    confidence: None,
                    message: "Invalid image max_header_bytes in config",
                }
                .emit();
                warn!(
                    value = max_header_bytes,
                    limit = MAX_IMAGE_HEADER_BYTES,
                    "Invalid image max_header_bytes in config"
                );
            } else {
                opts.image_analysis.max_header_bytes = max_header_bytes;
            }
        }
        if let Some(max_dimension) = image_cfg.max_dimension {
            if max_dimension == 0 || max_dimension > MAX_IMAGE_DIMENSION {
                SecurityEvent {
                    level: Level::WARN,
                    domain: SecurityDomain::Detection,
                    severity: crate::model::Severity::Low,
                    kind: "invalid_image_max_dimension",
                    policy: None,
                    object_id: None,
                    object_type: None,
                    vector: None,
                    technique: None,
                    confidence: None,
                    message: "Invalid image max_dimension in config",
                }
                .emit();
                warn!(
                    value = max_dimension,
                    limit = MAX_IMAGE_DIMENSION,
                    "Invalid image max_dimension in config"
                );
            } else {
                opts.image_analysis.max_dimension = max_dimension;
            }
        }
        if let Some(max_bytes) = image_cfg.max_xfa_decode_bytes {
            if max_bytes == 0 || max_bytes > MAX_IMAGE_XFA_DECODE_BYTES {
                SecurityEvent {
                    level: Level::WARN,
                    domain: SecurityDomain::Detection,
                    severity: crate::model::Severity::Low,
                    kind: "invalid_image_max_xfa_decode_bytes",
                    policy: None,
                    object_id: None,
                    object_type: None,
                    vector: None,
                    technique: None,
                    confidence: None,
                    message: "Invalid image max_xfa_decode_bytes in config",
                }
                .emit();
                warn!(
                    value = max_bytes,
                    limit = MAX_IMAGE_XFA_DECODE_BYTES,
                    "Invalid image max_xfa_decode_bytes in config"
                );
            } else {
                opts.image_analysis.max_xfa_decode_bytes = max_bytes;
            }
        }
        if let Some(depth) = image_cfg.max_filter_chain_depth {
            if depth == 0 || depth > MAX_IMAGE_FILTER_CHAIN_DEPTH {
                SecurityEvent {
                    level: Level::WARN,
                    domain: SecurityDomain::Detection,
                    severity: crate::model::Severity::Low,
                    kind: "invalid_image_max_filter_chain_depth",
                    policy: None,
                    object_id: None,
                    object_type: None,
                    vector: None,
                    technique: None,
                    confidence: None,
                    message: "Invalid image max_filter_chain_depth in config",
                }
                .emit();
                warn!(
                    value = depth,
                    limit = MAX_IMAGE_FILTER_CHAIN_DEPTH,
                    "Invalid image max_filter_chain_depth in config"
                );
            } else {
                opts.image_analysis.max_filter_chain_depth = depth;
            }
        }
        if !opts.image_analysis.enabled {
            opts.image_analysis.dynamic_enabled = false;
        }
    }
    if let Some(corr_cfg) = &scan.correlation {
        let corr = &mut opts.correlation;
        if let Some(enabled) = corr_cfg.enabled {
            corr.enabled = enabled;
        }
        if let Some(value) = corr_cfg.launch_obfuscated {
            corr.launch_obfuscated_enabled = value;
        }
        if let Some(value) = corr_cfg.action_chain_malicious {
            corr.action_chain_malicious_enabled = value;
        }
        if let Some(value) = corr_cfg.xfa_data_exfiltration {
            corr.xfa_data_exfiltration_enabled = value;
        }
        if let Some(value) = corr_cfg.encrypted_payload_delivery {
            corr.encrypted_payload_delivery_enabled = value;
        }
        if let Some(value) = corr_cfg.obfuscated_payload {
            corr.obfuscated_payload_enabled = value;
        }
        if let Some(threshold) = corr_cfg.high_entropy_threshold {
            corr.high_entropy_threshold = threshold;
        }
        if let Some(depth) = corr_cfg.action_chain_depth {
            corr.action_chain_depth_threshold = depth;
        }
        if let Some(fields) = corr_cfg.xfa_sensitive_field_threshold {
            corr.xfa_sensitive_field_threshold = fields;
        }
    }
}

fn parse_ml_mode(value: &str) -> crate::ml::MlMode {
    match value.to_lowercase().as_str() {
        "graph" => crate::ml::MlMode::Graph,
        _ => crate::ml::MlMode::Traditional,
    }
}
