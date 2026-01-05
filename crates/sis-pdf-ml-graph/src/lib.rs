use std::path::Path;

use anyhow::{anyhow, Result};

mod config;
mod normalize;
mod onnx;
mod tokenizer;

pub use config::{
    embedding_input_names, embedding_timeout_ms, graph_input_names, inference_timeout_ms,
    max_batch_size, max_ir_string_len, GraphModelConfig,
};

use config::ResolvedModelPaths;
use config::validate_onnx_safety;
use onnx::{OnnxEmbedder, OnnxGnn, OutputKind, PoolingStrategy};
use tokenizer::TokenizerWrapper;

#[derive(Debug, Clone)]
pub struct GraphPrediction {
    pub score: f32,
    pub label: bool,
    pub threshold: f32,
}

pub struct GraphModelRunner {
    config: GraphModelConfig,
    _paths: ResolvedModelPaths,
    tokenizer: TokenizerWrapper,
    embedder: OnnxEmbedder,
    gnn: OnnxGnn,
}

impl GraphModelRunner {
    pub fn load(model_dir: &Path) -> Result<Self> {
        let config = GraphModelConfig::load(model_dir)?;
        let paths = config.resolve_paths(model_dir)?;
        validate_onnx_safety(&paths.embedding_model)?;
        validate_onnx_safety(&paths.graph_model)?;
        let tokenizer = TokenizerWrapper::from_path(&paths.tokenizer, config.embedding.max_length)?;
        let pooling = match config.embedding.pooling.as_str() {
            "cls" => PoolingStrategy::Cls,
            "mean" => PoolingStrategy::Mean,
            other => return Err(anyhow!("unsupported pooling strategy {}", other)),
        };
        let embedder = OnnxEmbedder::from_path(
            &paths.embedding_model,
            embedding_input_names(&config),
            config.embedding.output_name.clone(),
            pooling,
            embedding_timeout_ms(&config),
        )?;
        let output_kind = match config.graph.output.kind.as_str() {
            "logit" => OutputKind::Logit,
            "probability" => OutputKind::Probability,
            other => return Err(anyhow!("unsupported graph output kind {}", other)),
        };
        let gnn = OnnxGnn::from_path(
            &paths.graph_model,
            graph_input_names(&config),
            config.graph.output_name.clone(),
            output_kind,
            config.graph.output.apply_sigmoid,
            inference_timeout_ms(&config),
        )?;
        Ok(Self {
            config,
            _paths: paths,
            tokenizer,
            embedder,
            gnn,
        })
    }

    pub fn predict(
        &self,
        node_texts: &[String],
        edge_index: &[(usize, usize)],
        threshold_override: f32,
    ) -> Result<GraphPrediction> {
        if node_texts.is_empty() {
            return Err(anyhow!("no node texts provided"));
        }
        let normalized = normalize::normalize_ir_texts(
            node_texts,
            &self.config.embedding.normalize,
            max_ir_string_len(&self.config),
        );
        let batch_size = max_batch_size(&self.config);
        let embeddings = embed_in_batches(&self.tokenizer, &self.embedder, &normalized, batch_size)?;
        let mut edges = edge_index.to_vec();
        if self.config.edge_index.add_reverse_edges {
            edges.extend(edge_index.iter().map(|(s, t)| (*t, *s)));
        }
        let score = self.gnn.infer(&embeddings, &edges)?;
        let threshold = if threshold_override > 0.0 {
            threshold_override
        } else {
            self.config.threshold
        };
        Ok(GraphPrediction {
            score,
            label: score >= threshold,
            threshold,
        })
    }
}

pub fn load_and_predict(
    model_dir: &Path,
    node_texts: &[String],
    edge_index: &[(usize, usize)],
    threshold: f32,
) -> Result<GraphPrediction> {
    let runner = GraphModelRunner::load(model_dir)?;
    runner.predict(node_texts, edge_index, threshold)
}

fn embed_in_batches(
    tokenizer: &TokenizerWrapper,
    embedder: &OnnxEmbedder,
    texts: &[String],
    batch_size: usize,
) -> Result<Vec<Vec<f32>>> {
    if batch_size == 0 {
        return Err(anyhow!("batch_size must be > 0"));
    }
    let mut out = Vec::with_capacity(texts.len());
    for chunk in texts.chunks(batch_size) {
        let batch = tokenizer.encode_batch(chunk)?;
        let mut embeddings = embedder.embed_batch(&batch)?;
        out.append(&mut embeddings);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_and_batch_flow() {
        let cfg = GraphModelConfig {
            schema_version: 1,
            name: "test".into(),
            version: None,
            embedding: config::EmbeddingConfig {
                backend: "onnx".into(),
                model_path: "embedding.onnx".into(),
                tokenizer_path: "tokenizer.json".into(),
                max_length: 4,
                pooling: "cls".into(),
                output_dim: 4,
                normalize: config::NormalizeConfig {
                    normalize_numbers: true,
                    normalize_strings: true,
                    collapse_obj_refs: true,
                    preserve_keywords: vec!["/JS".into()],
                    hash_strings: false,
                    include_deviation_markers: false,
                },
                input_names: None,
                output_name: None,
            },
            graph: config::GraphConfig {
                backend: "onnx".into(),
                model_path: "graph.onnx".into(),
                input_dim: 4,
                output: config::GraphOutput {
                    kind: "logit".into(),
                    apply_sigmoid: true,
                },
                input_names: None,
                output_name: None,
            },
            threshold: 0.9,
            edge_index: config::EdgeIndexConfig {
                directed: true,
                add_reverse_edges: true,
            },
            integrity: None,
            limits: None,
        };
        let texts = vec!["/OpenAction name /JS ; $ num 12".into()];
        let normalized = normalize::normalize_ir_texts(&texts, &cfg.embedding.normalize, None);
        assert!(normalized[0].contains("/JS"));
    }
}
