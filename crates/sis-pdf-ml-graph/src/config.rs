use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use serde::Deserialize;
use prost::Message;
use tract_onnx::pb;

#[derive(Debug, Clone, Deserialize)]
pub struct GraphModelConfig {
    pub schema_version: u32,
    pub name: String,
    pub version: Option<String>,
    pub embedding: EmbeddingConfig,
    pub graph: GraphConfig,
    pub threshold: f32,
    pub edge_index: EdgeIndexConfig,
    pub integrity: Option<IntegrityConfig>,
    pub limits: Option<ResourceLimits>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmbeddingConfig {
    pub backend: String,
    pub model_path: String,
    pub tokenizer_path: String,
    pub max_length: usize,
    pub pooling: String,
    pub output_dim: usize,
    pub normalize: NormalizeConfig,
    pub input_names: Option<EmbeddingInputNames>,
    pub output_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmbeddingInputNames {
    pub input_ids: Option<String>,
    pub attention_mask: Option<String>,
    pub token_type_ids: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NormalizeConfig {
    pub normalize_numbers: bool,
    pub normalize_strings: bool,
    pub collapse_obj_refs: bool,
    pub preserve_keywords: Vec<String>,
    pub hash_strings: bool,
    pub include_deviation_markers: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GraphConfig {
    pub backend: String,
    pub model_path: String,
    pub input_dim: usize,
    pub output: GraphOutput,
    pub input_names: Option<GraphInputNames>,
    pub output_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GraphInputNames {
    pub node_features: Option<String>,
    pub edge_index: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GraphOutput {
    pub kind: String,
    pub apply_sigmoid: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EdgeIndexConfig {
    pub directed: bool,
    pub add_reverse_edges: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IntegrityConfig {
    pub embedding_sha256: Option<String>,
    pub graph_sha256: Option<String>,
    pub tokenizer_sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResourceLimits {
    pub max_ir_string_length: Option<usize>,
    pub max_embedding_batch_size: Option<usize>,
    pub embedding_timeout_ms: Option<u64>,
    pub inference_timeout_ms: Option<u64>,
}

pub struct ResolvedModelPaths {
    pub embedding_model: PathBuf,
    pub graph_model: PathBuf,
    pub tokenizer: PathBuf,
}

impl GraphModelConfig {
    pub fn load(model_dir: &Path) -> Result<Self> {
        let path = model_dir.join("graph_model.json");
        let data = std::fs::read(&path)
            .map_err(|e| anyhow!("failed to read {}: {}", path.display(), e))?;
        let cfg: GraphModelConfig = serde_json::from_slice(&data)
            .map_err(|e| anyhow!("invalid graph_model.json: {}", e))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn resolve_paths(&self, model_dir: &Path) -> Result<ResolvedModelPaths> {
        let embedding_model = resolve_model_path(model_dir, &self.embedding.model_path)?;
        let graph_model = resolve_model_path(model_dir, &self.graph.model_path)?;
        let tokenizer = resolve_model_path(model_dir, &self.embedding.tokenizer_path)?;
        Ok(ResolvedModelPaths {
            embedding_model,
            graph_model,
            tokenizer,
        })
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(anyhow!(
                "unsupported schema version {} (expected 1)",
                self.schema_version
            ));
        }
        if self.embedding.output_dim != self.graph.input_dim {
            return Err(anyhow!(
                "dimension mismatch: embedding.output_dim {} != graph.input_dim {}",
                self.embedding.output_dim,
                self.graph.input_dim
            ));
        }
        if self.embedding.backend != "onnx" {
            return Err(anyhow!("unsupported embedding backend {}", self.embedding.backend));
        }
        if self.graph.backend != "onnx" {
            return Err(anyhow!("unsupported graph backend {}", self.graph.backend));
        }
        if self.embedding.pooling != "cls" && self.embedding.pooling != "mean" {
            return Err(anyhow!(
                "unsupported embedding pooling {}",
                self.embedding.pooling
            ));
        }
        if self.graph.output.kind != "logit" && self.graph.output.kind != "probability" {
            return Err(anyhow!(
                "unsupported graph output kind {}",
                self.graph.output.kind
            ));
        }
        Ok(())
    }
}

fn resolve_model_path(base_dir: &Path, relative: &str) -> Result<PathBuf> {
    if relative.contains("..") || relative.starts_with('/') {
        return Err(anyhow!("invalid model path: {}", relative));
    }
    let path = base_dir.join(relative);
    let canonical = path.canonicalize()
        .map_err(|e| anyhow!("cannot resolve model path {}: {}", relative, e))?;
    let canonical_base = base_dir
        .canonicalize()
        .map_err(|e| anyhow!("cannot resolve model dir {}: {}", base_dir.display(), e))?;
    if !canonical.starts_with(&canonical_base) {
        return Err(anyhow!("model path escapes ml_model_dir: {}", relative));
    }
    Ok(canonical)
}

pub fn max_batch_size(cfg: &GraphModelConfig) -> usize {
    cfg.limits
        .as_ref()
        .and_then(|l| l.max_embedding_batch_size)
        .unwrap_or(32)
}

pub fn max_ir_string_len(cfg: &GraphModelConfig) -> Option<usize> {
    cfg.limits.as_ref().and_then(|l| l.max_ir_string_length)
}

pub fn embedding_timeout_ms(cfg: &GraphModelConfig) -> u64 {
    cfg.limits
        .as_ref()
        .and_then(|l| l.embedding_timeout_ms)
        .unwrap_or(30_000)
}

pub fn inference_timeout_ms(cfg: &GraphModelConfig) -> u64 {
    cfg.limits
        .as_ref()
        .and_then(|l| l.inference_timeout_ms)
        .unwrap_or(30_000)
}

pub fn embedding_input_names(cfg: &GraphModelConfig) -> EmbeddingInputNames {
    cfg.embedding.input_names.clone().unwrap_or_else(|| EmbeddingInputNames {
        input_ids: Some("input_ids".into()),
        attention_mask: Some("attention_mask".into()),
        token_type_ids: Some("token_type_ids".into()),
    })
}

pub fn graph_input_names(cfg: &GraphModelConfig) -> GraphInputNames {
    cfg.graph.input_names.clone().unwrap_or_else(|| GraphInputNames {
        node_features: Some("node_features".into()),
        edge_index: Some("edge_index".into()),
    })
}

pub fn validate_onnx_safety(path: &Path) -> Result<()> {
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow!("failed to read {}: {}", path.display(), e))?;
    let model = pb::ModelProto::decode(bytes.as_slice())
        .map_err(|e| anyhow!("invalid ONNX model {}: {}", path.display(), e))?;
    for opset in &model.opset_import {
        let domain = opset.domain.as_str();
        if !domain.is_empty() && domain != "ai.onnx" {
            return Err(anyhow!(
                "unsupported ONNX domain in {}: {}",
                path.display(),
                domain
            ));
        }
    }
    if let Some(graph) = &model.graph {
        for init in &graph.initializer {
            if let Some(loc) = init.data_location {
                if loc == pb::tensor_proto::DataLocation::External as i32 {
                    return Err(anyhow!(
                        "external tensor data not allowed in {}: {}",
                        path.display(),
                        init.name
                    ));
                }
            }
        }
    }
    Ok(())
}
