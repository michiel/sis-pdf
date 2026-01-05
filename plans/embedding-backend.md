# Embedding Backend + GNN Loader Plan

This plan describes how to add a real embedding backend (ONNX/transformers), a GNN model loader, and a `graph_model.json` schema for the IR/ORG pipeline.

## Goals
- Provide a production-grade embedding backend that turns PDFObj IR into vectors.
- Load and run a graph model (GIN or similar) on ORG + embeddings.
- Define a clear `graph_model.json` schema for model packaging and inference configuration.
- Keep ML optional and gated behind the `ml-graph` feature.

## Scope
- Inference only (training stays external).
- ONNXRuntime as the primary backend (CPU by default, optional GPU via runtime config).
- Tokenization using `tokenizers` with HF-compatible vocab/merges.
- Graph inference: ONNX model input signature takes `node_features` and `edge_index`.

## Architecture
- `sis-pdf-ml-graph`
  - `embedding/`
    - `onnx.rs`: ONNX embedding model loader + inference.
    - `tokenizer.rs`: wrapper around HF tokenizers.
    - `normalize.rs`: token normalization for IR (path compression, type/value normalization).
  - `graph/`
    - `onnx.rs`: ONNX graph model loader + inference.
    - `inputs.rs`: edge index + node feature assembly.
  - `model_config.rs`: `graph_model.json` parser + validation.
- `sis-pdf-core`
  - `ir_pipeline.rs`: provide normalized IR strings + per-object token lists (new helper).
  - `runner.rs`: when `ml_mode == graph`, call embed -> gnn pipeline.

## Implementation Steps
1. **Define `graph_model.json` schema + parser**
   - Create `sis-pdf-ml-graph/src/model_config.rs` with a strongly typed config struct.
   - Add strict validation: required fields, path existence, dimension checks.
   - Add unit tests for config parsing and validation errors.

2. **Tokenizer integration**
   - Add `tokenizers` crate (feature gated) for HF tokenizer files.
   - Support `tokenizer.json` OR `vocab.json` + `merges.txt`.
   - Provide a deterministic tokenization mode for IR (no randomization).
   - Implement max sequence length (truncate with `attention_mask`).

3. **IR normalization for embeddings**
   - Add a reusable function in `sis-pdf-core` to produce normalized IR strings.
   - Normalize object IDs to placeholders (e.g., `obj:ID`).
   - Normalize numeric values and byte strings to reduce entropy.
   - Keep a separate raw string path for debugging.

4. **ONNX embedding backend**
   - Add `onnxruntime` dependency in `sis-pdf-ml-graph` (feature gated).
   - Load the embedding ONNX model once and reuse across scans.
   - Input: token IDs, attention mask, segment IDs (if needed).
   - Output: pooled vector per object (CLS or mean pooling).
   - Expose a `fn embed_ir_objects(&[String]) -> Vec<Vec<f32>>`.

5. **ONNX GNN backend**
   - Load graph model from ONNX using the same runtime.
   - Input tensors:
     - `node_features`: `[N, D]` float32
     - `edge_index`: `[2, E]` int64
     - Optional `node_mask` for padding, if model expects fixed N.
   - Output: graph score `[1]` float32 (probability or logit).
   - Add a fallback adapter to apply sigmoid if model returns logit.

6. **Inference pipeline wiring**
   - In `sis-pdf-ml-graph`, create a `GraphModelRunner` that owns both models.
   - Add a single `predict_graph_score(ir_graph: &IrGraphArtifacts) -> f32` entry point.
   - Extend `sis-pdf-core::ml` integration to call this runner when `ml_mode == graph`.

7. **CLI + UX**
   - Update `USAGE.md` with model packaging requirements for `graph_model.json`.
   - Add errors that explain missing model files or tokenizer problems clearly.

8. **Testing + validation**
   - Add a small synthetic ONNX model for embedding and graph tests.
   - Add golden tests for input/output shapes and expected score.
   - Add a config validation test (missing `embedding.model_path`, mismatched dims).

## `graph_model.json` Schema (Proposed)

```json
{
  "schema_version": 1,
  "name": "pdfobj2vec_gin_v1",
  "embedding": {
    "backend": "onnx",
    "model_path": "embedding.onnx",
    "tokenizer_path": "tokenizer.json",
    "max_length": 256,
    "pooling": "cls",
    "output_dim": 768,
    "normalize": {
      "normalize_numbers": true,
      "normalize_strings": true,
      "collapse_obj_refs": true
    }
  },
  "graph": {
    "backend": "onnx",
    "model_path": "graph.onnx",
    "input_dim": 768,
    "output": {
      "kind": "logit",
      "apply_sigmoid": true
    }
  },
  "threshold": 0.9,
  "edge_index": {
    "directed": true,
    "add_reverse_edges": true
  }
}
```

### Field Notes
- `schema_version`: Integer for migrations.
- `embedding.backend`: `onnx` (future: `candle`, `ggml`).
- `embedding.tokenizer_path`: HF tokenizer file; if missing, allow `vocab.json` + `merges.txt`.
- `embedding.pooling`: `cls` or `mean`.
- `embedding.output_dim`: Must match `graph.input_dim`.
- `graph.output.kind`: `logit` or `probability`.
- `edge_index.add_reverse_edges`: If true, add symmetric edges for GNN.

## Packaging Expectations
- Model directory contains:
  - `graph_model.json`
  - `embedding.onnx`
  - `graph.onnx`
  - `tokenizer.json` (or `vocab.json` + `merges.txt`)
- All file paths in `graph_model.json` are relative to the model dir.

## Open Questions
- Should we support byte-level BPE tokenizers for robustness?
- Do we need configurable batch size for embedding inference?
- Do we allow per-model custom IR normalization rules?
