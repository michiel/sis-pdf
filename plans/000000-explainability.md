# Model-Side Explainability Plan (Graph ML)

## Goals
- Provide analyst-facing evidence for *why* a graph ML score is high.
- Keep explanations tied to PDF IR objects and edges to support triage.
- Preserve portability: outputs must be ONNX-friendly and runtime-safe.

## Non-Goals
- Full causal explainability or certified robustness.
- Training pipeline inside SIS-PDF (remains external).
- Perfect faithfulness for every model architecture.

## Current State
- Graph ML inference returns only `score/threshold/label`.
- No per-node or per-edge attribution is exported by the GNN.
- Reports cannot justify scores beyond threshold status.

## Approach Overview
Add a model-side explainability head that emits per-node attribution scores and
expose those at inference time. Map attributions back to IR objects and
surface a concise “Top contributing nodes” section in reports.

## Design Options

### Option A: Per-node logits (recommended)
- Modify GNN to output:
  - `graph_logit`: scalar (current score)
  - `node_logits`: vector of length `num_nodes`
- Attribution: sort `node_logits` by absolute value or positive contribution.
- Pros: simple, stable, ONNX-friendly, no gradient requirement.
- Cons: requires model changes; may be less faithful than gradients.

### Option B: Attention/edge weights
- Use attention-based GNN (GAT/Transformer) and export attention weights.
- Pros: direct “edge importance”.
- Cons: attention != explanation; ONNX export of attention weights can be brittle.

### Option C: Gradient-based attribution (IG/Grad-CAM)
- Compute gradients at inference time against node features.
- Pros: more faithful.
- Cons: requires autograd or ONNX Runtime training APIs; heavy and complex.

## Chosen Path (Phase 1)
Implement Option A (per-node logits) and plumb through the pipeline.
Keep model interfaces backward-compatible by allowing both old and new outputs.

## Model Changes (Training Side)
- Update GNN to return `(graph_logit, node_logits)`:
  - `graph_logit`: `global_add_pool(x)` -> MLP -> scalar
  - `node_logits`: apply MLP before pooling or a parallel head.
- Export ONNX with two outputs:
  - `graph_score` (scalar)
  - `node_scores` (shape `[num_nodes]`)
- Ensure dynamic axes:
  - `node_features`: `{0: "num_nodes"}`
  - `edge_index`: `{1: "num_edges"}`
  - `node_scores`: `{0: "num_nodes"}`

## Runtime Changes (SIS-PDF)
- Extend `GraphModelConfig` to support `graph.output.node_scores_name` (optional).
- Update `OnnxGnn::infer` to optionally return node scores.
- Add a new ML metadata payload:
  - `ml.graph.node_scores_top`: list of top-K `(node_index, score)`.
- Map `node_index` to IR object refs:
  - Use `ir_graph` index mapping to `(obj, gen)` or path summary.

## Report Changes
- Add “ML Details” section with:
  - Graph score/threshold/label
  - Top-K contributing nodes:
    - `obj_ref`, short IR path summary, node score
- Keep summary concise; detailed list only when node scores are available.

## Backward Compatibility
- If node scores output is missing, fall back to current behavior.
- Do not fail inference when `node_scores_name` is absent.

## Data Requirements
- Ensure consistent mapping between:
  - IR object order -> node index -> node score
- Store the mapping in `IrGraphArtifacts` for reuse in reporting.

## Validation
- Unit test: mock ONNX graph with `node_scores` output, ensure mapping and sorting.
- Integration: run a sample with known model to verify:
  - node scores list length equals node count
  - report includes top-K entries
- Stability check: confirm scores are deterministic for same input.

## Risks / Open Questions
- Node scores may not be well-calibrated; define whether to sort by absolute or positive.
- Some GNNs might not support a clean per-node head without retraining.
- Analysts may need IR path/summary length limits for readability.

## Milestones
1) Prototype: update training script + ONNX export for node scores.
2) Runtime: load optional `node_scores` output and surface top-K.
3) Reporting: add ML Details with node attribution.
4) Docs: update `docs/modeling.md` with explainability artifacts.
