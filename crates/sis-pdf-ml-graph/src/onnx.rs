use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use tract_onnx::prelude::*;

use crate::config::{EmbeddingInputNames, GraphInputNames};
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
    model: TypedSimplePlan<TypedModel>,
    input_names: EmbeddingInputNames,
    output_name: Option<String>,
    pooling: PoolingStrategy,
    timeout: Duration,
}

pub struct OnnxGnn {
    model: TypedSimplePlan<TypedModel>,
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
    ) -> Result<Self> {
        let model = tract_onnx::onnx()
            .model_for_path(path)?
            .into_optimized()?
            .into_runnable()?;
        Ok(Self {
            model,
            input_names,
            output_name,
            pooling,
            timeout: Duration::from_millis(timeout_ms),
        })
    }

    #[cfg(test)]
    pub fn from_plan(
        model: TypedSimplePlan<TypedModel>,
        input_names: EmbeddingInputNames,
        output_name: Option<String>,
        pooling: PoolingStrategy,
    ) -> Self {
        Self {
            model,
            input_names,
            output_name,
            pooling,
            timeout: Duration::from_millis(1_000),
        }
    }

    pub fn embed_batch(&self, batch: &TokenizedBatch) -> Result<Vec<Vec<f32>>> {
        let start = Instant::now();
        let inputs = self.build_inputs(batch)?;
        let outputs = self.model.run(inputs)?;
        if start.elapsed() > self.timeout {
            return Err(anyhow!("embedding timeout exceeded"));
        }
        self.extract_embeddings(&outputs, batch)
    }

    fn build_inputs(&self, batch: &TokenizedBatch) -> Result<TVec<TValue>> {
        let mut ordered: Vec<(String, Tensor)> = Vec::new();
        if let Some(name) = &self.input_names.input_ids {
            ordered.push((
                name.clone(),
                Tensor::from_shape(&[batch.batch, batch.seq_len], &batch.input_ids)?,
            ));
        }
        if let Some(name) = &self.input_names.attention_mask {
            ordered.push((
                name.clone(),
                Tensor::from_shape(&[batch.batch, batch.seq_len], &batch.attention_mask)?,
            ));
        }
        if let Some(name) = &self.input_names.token_type_ids {
            ordered.push((
                name.clone(),
                Tensor::from_shape(&[batch.batch, batch.seq_len], &batch.token_type_ids)?,
            ));
        }
        build_inputs_for_model(&self.model, &ordered)
    }

    fn extract_embeddings(&self, outputs: &TVec<TValue>, batch: &TokenizedBatch) -> Result<Vec<Vec<f32>>> {
        let output = pick_output_tensor(&self.model, outputs, self.output_name.as_deref())?;
        let view = output.to_array_view::<f32>()?;
        let shape = view.shape();
        if shape.len() == 2 {
            let dim = shape[1];
            let mut out = Vec::with_capacity(batch.batch);
            for b in 0..batch.batch {
                let mut row = Vec::with_capacity(dim);
                for d in 0..dim {
                    row.push(view[[b, d]]);
                }
                out.push(row);
            }
            return Ok(out);
        }
        if shape.len() != 3 {
            return Err(anyhow!("unexpected embedding output shape: {:?}", shape));
        }
        let dim = shape[2];
        let mut out = Vec::with_capacity(batch.batch);
        for b in 0..batch.batch {
            let mut row = vec![0.0f32; dim];
            match self.pooling {
                PoolingStrategy::Cls => {
                    for d in 0..dim {
                        row[d] = view[[b, 0, d]];
                    }
                }
                PoolingStrategy::Mean => {
                    let mut count = 0.0f32;
                    for t in 0..batch.seq_len {
                        let m = batch.attention_mask[b * batch.seq_len + t];
                        if m == 0 {
                            continue;
                        }
                        count += 1.0;
                        for d in 0..dim {
                            row[d] += view[[b, t, d]];
                        }
                    }
                    if count > 0.0 {
                        for d in 0..dim {
                            row[d] /= count;
                        }
                    }
                }
            }
            out.push(row);
        }
        Ok(out)
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
    ) -> Result<Self> {
        let model = tract_onnx::onnx()
            .model_for_path(path)?
            .into_optimized()?
            .into_runnable()?;
        Ok(Self {
            model,
            input_names,
            output_name,
            node_scores_name,
            output_kind,
            apply_sigmoid,
            timeout: Duration::from_millis(timeout_ms),
        })
    }

    #[cfg(test)]
    pub fn from_plan(
        model: TypedSimplePlan<TypedModel>,
        input_names: GraphInputNames,
        output_name: Option<String>,
        node_scores_name: Option<String>,
        output_kind: OutputKind,
        apply_sigmoid: bool,
    ) -> Self {
        Self {
            model,
            input_names,
            output_name,
            node_scores_name,
            output_kind,
            apply_sigmoid,
            timeout: Duration::from_millis(1_000),
        }
    }

    pub fn infer(
        &self,
        node_features: &[Vec<f32>],
        edge_index: &[(usize, usize)],
    ) -> Result<GraphInference> {
        let start = Instant::now();
        let inputs = self.build_inputs(node_features, edge_index)?;
        let outputs = self.model.run(inputs)?;
        if start.elapsed() > self.timeout {
            return Err(anyhow!("gnn inference timeout exceeded"));
        }
        let output = pick_output_tensor(&self.model, &outputs, self.output_name.as_deref())?;
        let view = output.to_array_view::<f32>()?;
        let shape = view.shape().to_vec();
        let score = match view.iter().next() {
            Some(v) => *v,
            None => return Err(anyhow!("empty gnn output (shape={:?})", shape)),
        };
        let mut out = match self.output_kind {
            OutputKind::Logit => score,
            OutputKind::Probability => score,
        };
        if self.apply_sigmoid {
            out = 1.0 / (1.0 + (-out).exp());
        }
        let node_scores = if let Some(name) = &self.node_scores_name {
            let node_tensor = pick_output_tensor(&self.model, &outputs, Some(name))?;
            Some(extract_node_scores(&node_tensor)?)
        } else {
            None
        };
        Ok(GraphInference {
            score: out,
            node_scores,
        })
    }

    fn build_inputs(&self, node_features: &[Vec<f32>], edge_index: &[(usize, usize)]) -> Result<TVec<TValue>> {
        if node_features.is_empty() {
            return Err(anyhow!("empty graph: no nodes"));
        }
        let feat_dim = node_features[0].len();
        for (idx, n) in node_features.iter().enumerate() {
            if n.len() != feat_dim {
                return Err(anyhow!(
                    "node {} feature dim {} != {}",
                    idx,
                    n.len(),
                    feat_dim
                ));
            }
        }
        let mut features_flat = Vec::with_capacity(node_features.len() * feat_dim);
        for n in node_features {
            features_flat.extend_from_slice(n);
        }
        let edges_flat: Vec<i64> = edge_index
            .iter()
            .flat_map(|(s, t)| vec![*s as i64, *t as i64])
            .collect();
        let mut ordered: Vec<(String, Tensor)> = Vec::new();
        if let Some(name) = &self.input_names.node_features {
            ordered.push((
                name.clone(),
                Tensor::from_shape(&[node_features.len(), feat_dim], &features_flat)?,
            ));
        }
        if let Some(name) = &self.input_names.edge_index {
            let edge_count = edge_index.len();
            ordered.push((name.clone(), Tensor::from_shape(&[2, edge_count], &edges_flat)?));
        }
        build_inputs_for_model(&self.model, &ordered)
    }
}

fn pick_output_tensor(
    model: &TypedSimplePlan<TypedModel>,
    outputs: &TVec<TValue>,
    output_name: Option<&str>,
) -> Result<Tensor> {
    if let Some(name) = output_name {
        let model_ref = model.model();
        let output_outlets = model_ref.output_outlets()?;
        for (idx, outlet) in output_outlets.iter().enumerate() {
            let node = &model_ref.node(outlet.node);
            if node.name == name {
                return Ok(outputs[idx].clone().into_tensor());
            }
        }
        return Err(anyhow!("output name not found: {}", name));
    }
    outputs
        .get(0)
        .cloned()
        .map(|v| v.into_tensor())
        .ok_or_else(|| anyhow!("missing model output"))
}

fn extract_node_scores(output: &Tensor) -> Result<Vec<f32>> {
    let view = output.to_array_view::<f32>()?;
    let shape = view.shape();
    match shape.len() {
        1 => Ok(view.iter().copied().collect()),
        2 if shape[1] == 1 => Ok(view
            .outer_iter()
            .map(|row| row[0])
            .collect::<Vec<f32>>()),
        2 if shape[0] == 1 => Ok(view
            .index_axis(tract_onnx::prelude::tract_ndarray::Axis(0), 0)
            .iter()
            .copied()
            .collect::<Vec<f32>>()),
        _ => Err(anyhow!("unexpected node_scores shape: {:?}", shape)),
    }
}

pub struct GraphInference {
    pub score: f32,
    pub node_scores: Option<Vec<f32>>,
}

fn build_inputs_for_model(
    model: &TypedSimplePlan<TypedModel>,
    ordered: &[(String, Tensor)],
) -> Result<TVec<TValue>> {
    let model_ref = model.model();
    let input_outlets = model_ref.input_outlets()?;
    let mut ordered_inputs: TVec<TValue> = tvec!();
    let mut by_name = true;
    for outlet in input_outlets {
        let node = &model_ref.node(outlet.node);
        if node.name.is_empty() {
            by_name = false;
            break;
        }
        let Some((_, tensor)) = ordered.iter().find(|(name, _)| name == &node.name) else {
            return Err(anyhow!("missing model input: {}", node.name));
        };
        ordered_inputs.push(tensor.clone().into());
    }
    if by_name {
        return Ok(ordered_inputs);
    }
    let mut fallback: TVec<TValue> = tvec!();
    for (_, tensor) in ordered.iter() {
        fallback.push(tensor.clone().into());
    }
    if fallback.len() != input_outlets.len() {
        return Err(anyhow!(
            "model input count mismatch (model={}, provided={})",
            input_outlets.len(),
            fallback.len()
        ));
    }
    Ok(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EmbeddingInputNames, GraphInputNames};
    use crate::tokenizer::TokenizedBatch;

    #[test]
    fn embedder_runs_with_constant_output() -> Result<()> {
        let mut model = TypedModel::default();
        let input_fact = TypedFact::dt_shape(i64::datum_type(), tvec!(1, 1));
        let _input = model.add_source("input_ids", input_fact)?;
        let out_tensor = Tensor::from_shape(&[1usize, 1, 4], &[0.1f32, 0.2, 0.3, 0.4])?;
        let out = model.add_const("embed_out", out_tensor)?;
        model.set_output_outlets(&[out])?;
        let plan = TypedSimplePlan::new(model)?;

        let embedder = OnnxEmbedder::from_plan(
            plan,
            EmbeddingInputNames {
                input_ids: Some("input_ids".into()),
                attention_mask: None,
                token_type_ids: None,
            },
            Some("embed_out".into()),
            PoolingStrategy::Cls,
        );
        let batch = TokenizedBatch {
            input_ids: vec![1],
            attention_mask: vec![1],
            token_type_ids: vec![0],
            batch: 1,
            seq_len: 1,
        };
        let embeddings = embedder.embed_batch(&batch)?;
        assert_eq!(embeddings.len(), 1);
        assert_eq!(embeddings[0].len(), 4);
        Ok(())
    }

    #[test]
    fn gnn_runs_with_constant_output() -> Result<()> {
        let mut model = TypedModel::default();
        let input_fact = TypedFact::dt_shape(f32::datum_type(), tvec!(1, 4));
        let _input = model.add_source("node_features", input_fact)?;
        let out_tensor = Tensor::from_shape(&[1usize], &[0.7f32])?;
        let out = model.add_const("score", out_tensor)?;
        model.set_output_outlets(&[out])?;
        let plan = TypedSimplePlan::new(model)?;

        let gnn = OnnxGnn::from_plan(
            plan,
            GraphInputNames {
                node_features: Some("node_features".into()),
                edge_index: None,
            },
            Some("score".into()),
            None,
            OutputKind::Probability,
            false,
        );
        let result = gnn.infer(&vec![vec![0.5, 0.5, 0.5, 0.5]], &[])?;
        assert!((result.score - 0.7).abs() < 1e-6);
        Ok(())
    }
}
