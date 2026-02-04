use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use ort::session::Session;
use ort::value::Tensor;

use crate::config::{EmbeddingInputNames, GraphInputNames};
use crate::runtime::{ensure_ort_initialised, execution_providers, RuntimeSettings};
use crate::tokenizer::TokenizedBatch;

#[derive(Debug, Clone, Copy)]
pub enum PoolingStrategy {
    Cls,
    Mean,
}

#[derive(Debug, Clone, Copy)]
pub enum OutputKind {
    Logit,
    Probability,
}

pub struct OnnxEmbedder {
    session: Mutex<Session>,
    input_names: EmbeddingInputNames,
    output_name: Option<String>,
    pooling: PoolingStrategy,
    timeout: Duration,
}

pub struct OnnxGnn {
    session: Mutex<Session>,
    input_names: GraphInputNames,
    output_name: Option<String>,
    node_scores_name: Option<String>,
    output_kind: OutputKind,
    apply_sigmoid: bool,
    timeout: Duration,
}

impl OnnxEmbedder {
    pub fn from_path(
        path: &std::path::Path,
        input_names: EmbeddingInputNames,
        output_name: Option<String>,
        pooling: PoolingStrategy,
        timeout_ms: u64,
        runtime: &RuntimeSettings,
    ) -> Result<Self> {
        ensure_ort_initialised(runtime)?;
        let session = build_session(path, runtime)?;
        Ok(Self {
            session: Mutex::new(session),
            input_names,
            output_name,
            pooling,
            timeout: Duration::from_millis(timeout_ms),
        })
    }

    pub fn embed_batch(&self, batch: &TokenizedBatch) -> Result<Vec<Vec<f32>>> {
        let start = Instant::now();
        let inputs = self.build_inputs(batch)?;
        let mut guard =
            self.session.lock().map_err(|_| anyhow!("embedding session lock poisoned"))?;
        let outputs = guard.run(inputs)?;
        if start.elapsed() > self.timeout {
            return Err(anyhow!("embedding timeout exceeded"));
        }
        let output = match self.output_name.as_deref() {
            Some(name) => outputs.get(name).ok_or_else(|| anyhow!("output {} not found", name))?,
            None => {
                if outputs.len() == 0 {
                    return Err(anyhow!("no outputs found"));
                }
                &outputs[0]
            }
        };
        let (shape, data) = output.try_extract_tensor::<f32>()?;
        let shape = &shape[..];
        if shape.len() == 2 {
            let dim = shape[1] as usize;
            let mut out = Vec::with_capacity(batch.batch);
            for b in 0..batch.batch {
                let offset = b * dim;
                out.push(data[offset..offset + dim].to_vec());
            }
            return Ok(out);
        }
        if shape.len() != 3 {
            return Err(anyhow!("unexpected embedding output shape: {:?}", shape));
        }
        let seq_len = shape[1] as usize;
        let dim = shape[2] as usize;
        let mut out = Vec::with_capacity(batch.batch);
        for b in 0..batch.batch {
            let mut row = vec![0.0f32; dim];
            match self.pooling {
                PoolingStrategy::Cls => {
                    let base = b * seq_len * dim;
                    for d in 0..dim {
                        row[d] = data[base + d];
                    }
                }
                PoolingStrategy::Mean => {
                    let mut count = 0.0f32;
                    for t in 0..batch.seq_len {
                        let mask = batch.attention_mask[b * batch.seq_len + t];
                        if mask == 0 {
                            continue;
                        }
                        count += 1.0;
                        let base = (b * seq_len + t) * dim;
                        for d in 0..dim {
                            row[d] += data[base + d];
                        }
                    }
                    if count > 0.0 {
                        for item in row.iter_mut().take(dim) {
                            *item /= count;
                        }
                    }
                }
            }
            out.push(row);
        }
        Ok(out)
    }

    fn build_inputs(
        &self,
        batch: &TokenizedBatch,
    ) -> Result<Vec<(std::borrow::Cow<'static, str>, ort::session::SessionInputValue<'_>)>> {
        let shape = vec![batch.batch, batch.seq_len];
        let mut inputs = Vec::new();
        if let Some(name) = &self.input_names.input_ids {
            let tensor = Tensor::<i64>::from_array((
                shape.clone(),
                batch.input_ids.clone().into_boxed_slice(),
            ))?;
            inputs.push((name.clone().into(), tensor.into()));
        }
        if let Some(name) = &self.input_names.attention_mask {
            let tensor = Tensor::<i64>::from_array((
                shape.clone(),
                batch.attention_mask.clone().into_boxed_slice(),
            ))?;
            inputs.push((name.clone().into(), tensor.into()));
        }
        if let Some(name) = &self.input_names.token_type_ids {
            let tensor = Tensor::<i64>::from_array((
                shape.clone(),
                batch.token_type_ids.clone().into_boxed_slice(),
            ))?;
            inputs.push((name.clone().into(), tensor.into()));
        }
        Ok(inputs)
    }
}

impl OnnxGnn {
    pub fn from_path(
        path: &std::path::Path,
        input_names: GraphInputNames,
        output_name: Option<String>,
        node_scores_name: Option<String>,
        output_kind: OutputKind,
        apply_sigmoid: bool,
        timeout_ms: u64,
        runtime: &RuntimeSettings,
    ) -> Result<Self> {
        ensure_ort_initialised(runtime)?;
        let session = build_session(path, runtime)?;
        Ok(Self {
            session: Mutex::new(session),
            input_names,
            output_name,
            node_scores_name,
            output_kind,
            apply_sigmoid,
            timeout: Duration::from_millis(timeout_ms),
        })
    }

    pub fn infer(
        &self,
        node_features: &[Vec<f32>],
        edge_index: &[(usize, usize)],
    ) -> Result<GraphInference> {
        let start = Instant::now();
        let inputs = self.build_inputs(node_features, edge_index)?;
        let mut guard = self.session.lock().map_err(|_| anyhow!("gnn session lock poisoned"))?;
        let outputs = guard.run(inputs)?;
        if start.elapsed() > self.timeout {
            return Err(anyhow!("gnn inference timeout exceeded"));
        }
        let output = match self.output_name.as_deref() {
            Some(name) => outputs.get(name).ok_or_else(|| anyhow!("output {} not found", name))?,
            None => {
                if outputs.len() == 0 {
                    return Err(anyhow!("no outputs found"));
                }
                &outputs[0]
            }
        };
        let (shape, data) = output.try_extract_tensor::<f32>()?;
        let shape = &shape[..];
        let score =
            data.first().copied().ok_or_else(|| anyhow!("empty gnn output (shape={:?})", shape))?;
        let mut out = match self.output_kind {
            OutputKind::Logit => score,
            OutputKind::Probability => score,
        };
        if self.apply_sigmoid {
            out = 1.0 / (1.0 + (-out).exp());
        }
        let node_scores = if let Some(name) = &self.node_scores_name {
            let node_tensor =
                outputs.get(name).ok_or_else(|| anyhow!("output {} not found", name))?;
            Some(extract_node_scores(node_tensor)?)
        } else {
            None
        };
        Ok(GraphInference { score: out, node_scores })
    }

    fn build_inputs(
        &self,
        node_features: &[Vec<f32>],
        edge_index: &[(usize, usize)],
    ) -> Result<Vec<(std::borrow::Cow<'static, str>, ort::session::SessionInputValue<'_>)>> {
        if node_features.is_empty() {
            return Err(anyhow!("empty graph: no nodes"));
        }
        let feat_dim = node_features[0].len();
        for (idx, n) in node_features.iter().enumerate() {
            if n.len() != feat_dim {
                return Err(anyhow!("node {} feature dim {} != {}", idx, n.len(), feat_dim));
            }
        }
        let mut features_flat = Vec::with_capacity(node_features.len() * feat_dim);
        for n in node_features {
            features_flat.extend_from_slice(n);
        }
        let node_shape = vec![node_features.len(), feat_dim];
        let node_tensor =
            Tensor::<f32>::from_array((node_shape, features_flat.into_boxed_slice()))?;
        let mut edges_flat = Vec::with_capacity(edge_index.len() * 2);
        for (s, t) in edge_index {
            edges_flat.push(*s as i64);
            edges_flat.push(*t as i64);
        }
        let edge_shape = vec![2usize, edge_index.len()];
        let edge_tensor = Tensor::<i64>::from_array((edge_shape, edges_flat.into_boxed_slice()))?;
        let mut inputs = Vec::new();
        if let Some(name) = &self.input_names.node_features {
            inputs.push((name.clone().into(), node_tensor.into()));
        }
        if let Some(name) = &self.input_names.edge_index {
            inputs.push((name.clone().into(), edge_tensor.into()));
        }
        Ok(inputs)
    }
}

pub struct GraphInference {
    pub score: f32,
    pub node_scores: Option<Vec<f32>>,
}

fn build_session(path: &std::path::Path, runtime: &RuntimeSettings) -> Result<Session> {
    let mut builder = Session::builder()?;
    let providers = execution_providers(runtime);
    if !providers.is_empty() {
        builder = builder.with_execution_providers(providers)?;
    }
    builder.commit_from_file(path).map_err(|e| anyhow!("failed to load {}: {}", path.display(), e))
}

fn extract_node_scores(output: &ort::value::DynValue) -> Result<Vec<f32>> {
    let (_, data) = output.try_extract_tensor::<f32>()?;
    Ok(data.to_vec())
}
