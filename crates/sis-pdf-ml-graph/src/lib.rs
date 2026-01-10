use std::path::Path;

use anyhow::{anyhow, Result};
use tracing::{error, warn};

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
    pub node_scores: Option<Vec<f32>>,
}

pub struct GraphModelRunner {
    config: GraphModelConfig,
    _paths: ResolvedModelPaths,
    tokenizer: TokenizerWrapper,
    embedder: OnnxEmbedder,
    gnn: OnnxGnn,
}

const CHARS_PER_TOKEN: usize = 4;
const TAIL_MARKER: &str = " <TAIL> ";

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
            config.graph.node_scores_name.clone(),
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
        let mut texts = node_texts.to_vec();
        let original_node_count = texts.len();
        let mut unresolved_edges = 0usize;
        let mut sentinel_idx: Option<usize> = None;
        let mut edges: Vec<(usize, usize)> = Vec::with_capacity(edge_index.len());
        for (s, t) in edge_index.iter().cloned() {
            let mut src = s;
            let mut dst = t;
            if src >= original_node_count || dst >= original_node_count {
                unresolved_edges += 1;
                if sentinel_idx.is_none() {
                    sentinel_idx = Some(texts.len());
                    texts.push("path=$meta\tvalue_type=unresolved_edges\tvalue=1".into());
                }
                let sentinel = sentinel_idx.unwrap();
                if src >= original_node_count {
                    src = sentinel;
                }
                if dst >= original_node_count {
                    dst = sentinel;
                }
            }
            edges.push((src, dst));
        }
        if unresolved_edges > 0 {
            if let Some(idx) = sentinel_idx {
                texts[idx] = format!(
                    "path=$meta\tvalue_type=unresolved_edges\tvalue={}",
                    unresolved_edges
                );
            }
            warn!(
                unresolved_edges = unresolved_edges,
                nodes = original_node_count,
                "ML graph remapped edges with out-of-range nodes"
            );
        }
        if edges.is_empty() {
            let marker = "path=$meta\tvalue_type=edge_count\tvalue=0";
            if let Some(first) = texts.first_mut() {
                first.push_str(" ; ");
                first.push_str(marker);
            }
        }
        let normalized = normalize::normalize_ir_texts(
            &texts,
            &self.config.embedding.normalize,
            max_ir_string_len(&self.config),
        );
        let compressed = compress_texts_for_max_tokens(
            &normalized,
            self.tokenizer.max_length(),
        );
        let batch_size = max_batch_size(&self.config);
        let embeddings = embed_in_batches(&self.tokenizer, &self.embedder, &compressed, batch_size)?;
        let node_count = embeddings.len();
        edges.retain(|(s, t)| *s < node_count && *t < node_count);
        if self.config.edge_index.add_reverse_edges {
            let mut reversed = edges.iter().map(|(s, t)| (*t, *s)).collect::<Vec<_>>();
            edges.append(&mut reversed);
        }
        if edges.is_empty() {
            edges.push((0, 0));
        }
        let edge_count = edges.len();
        let feature_dim = embeddings.get(0).map(|v| v.len()).unwrap_or(0);
        let max_node = edges
            .iter()
            .flat_map(|(s, t)| [*s, *t])
            .max()
            .unwrap_or(0);
        let inference = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.gnn.infer(&embeddings, &edges)
        })) {
            Ok(result) => match result {
                Ok(result) => result,
                Err(err) => {
                    error!(
                        nodes = node_count,
                        feat_dim = feature_dim,
                        edges = edge_count,
                        max_edge_node = max_node,
                        error = %err,
                        "ML graph GNN inference failed"
                    );
                    return Err(err);
                }
            },
            Err(_) => {
                error!(
                    nodes = node_count,
                    feat_dim = feature_dim,
                    edges = edge_count,
                    max_edge_node = max_node,
                    "ML graph GNN inference panicked"
                );
                return Err(anyhow!("gnn inference panicked"));
            }
        };
        let threshold = if threshold_override > 0.0 {
            threshold_override
        } else {
            self.config.threshold
        };
        Ok(GraphPrediction {
            score: inference.score,
            label: inference.score >= threshold,
            threshold,
            node_scores: inference.node_scores,
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

fn compress_texts_for_max_tokens(texts: &[String], max_length: usize) -> Vec<String> {
    texts
        .iter()
        .map(|text| compress_text_for_max_tokens(text, max_length))
        .collect()
}

fn compress_text_for_max_tokens(text: &str, max_length: usize) -> String {
    let max_chars = max_length.saturating_mul(CHARS_PER_TOKEN);
    if text.len() <= max_chars {
        return text.to_string();
    }
    if max_chars <= TAIL_MARKER.len() + 2 {
        return text.chars().take(max_chars).collect();
    }
    let head_len = (max_chars - TAIL_MARKER.len()) / 2;
    let tail_len = max_chars - TAIL_MARKER.len() - head_len;
    if tail_len == 0 {
        return text.chars().take(max_chars).collect();
    }
    let head: String = text.chars().take(head_len).collect();
    let tail: String = text.chars().rev().take(tail_len).collect::<Vec<_>>().into_iter().rev().collect();
    format!("{}{}{}", head, TAIL_MARKER, tail)
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
                node_scores_name: None,
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
