#![forbid(unsafe_code)]

pub mod colour_space;
pub mod dynamic;
pub mod pixel_buffer;
pub mod static_analysis;
mod timeout;
pub(crate) mod util;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageStaticOptions {
    pub max_header_bytes: usize,
    pub max_dimension: u32,
    pub max_pixels: u64,
    pub max_xfa_decode_bytes: usize,
    pub max_filter_chain_depth: usize,
}

impl Default for ImageStaticOptions {
    fn default() -> Self {
        Self {
            max_header_bytes: 4096,
            max_dimension: 10_000,
            max_pixels: 100_000_000,
            max_xfa_decode_bytes: 8 * 1024 * 1024,
            max_filter_chain_depth: 8,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageDynamicOptions {
    pub max_pixels: u64,
    pub max_decode_bytes: usize,
    pub timeout_ms: u64,
    pub total_budget_ms: u64,
    pub skip_threshold: usize,
}

impl Default for ImageDynamicOptions {
    fn default() -> Self {
        Self {
            max_pixels: 100_000_000,
            max_decode_bytes: 256 * 1024 * 1024,
            timeout_ms: 250,
            total_budget_ms: 5_000,
            skip_threshold: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageFinding {
    pub kind: String,
    pub obj: u32,
    pub gen: u16,
    pub meta: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImageStaticResult {
    pub findings: Vec<ImageFinding>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImageDynamicResult {
    pub findings: Vec<ImageFinding>,
}
