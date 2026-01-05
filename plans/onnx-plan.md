# ONNX IR/ORG + GNN Inference Plan

This plan merges the IR/ORG pipeline work and the ONNX embedding/GNN backend into one end-to-end implementation plan, including ergonomics needed for real-world use.

## Goals
- Produce PDFObj IR and ORG reliably for malformed PDFs.
- Embed IR into vectors using an ONNX-backed language model (tokenizer + model).
- Run a GNN (GIN-style) on ORG + embeddings to produce a score.
- Provide a usable operator workflow: clear CLI flags, good errors, consistent reports, and export tools.
- Keep default scans fast; all heavy ML is behind `--ml --ml-mode graph` and `ml-graph` feature.

## Scope
- Inference only (training stays external).
- ONNXRuntime is the primary backend (CPU by default; optional GPU if runtime supports it).
- Tokenizers from HuggingFace format (`tokenizer.json` or `vocab.json` + `merges.txt`).
- IR/ORG export remains available without ML.
- No raw stream bytes inside IR text.

## Architecture Overview

### Crates and Modules
- `sis-pdf-pdf`
  - `ir.rs`: IR generation from parsed objects.
- `sis-pdf-core`
  - `org.rs`: ORG builder.
  - `ir_pipeline.rs`: orchestrates IR + ORG + normalized IR text output.
  - `ir_export.rs`: export IR (text/json).
  - `report.rs`: includes IR/ORG summary in reports.
- `sis-pdf-ml-graph` (feature `ml-graph`)
  - `embedding/onnx.rs`: ONNX embedding runtime.
  - `embedding/tokenizer.rs`: HF tokenizer wrapper.
  - `embedding/normalize.rs`: IR normalization.
  - `graph/onnx.rs`: ONNX GNN runtime.
  - `graph/inputs.rs`: edge index + node feature assembly.
  - `model_config.rs`: `graph_model.json` parser and validation.
- `sis-pdf` (CLI)
  - `--ml --ml-mode graph` enables graph inference.
  - `export-ir` and `export-org` for offline workflows.

## Detailed Implementation Steps

### 1) IR Extraction (PDFObj IR)
- Add or refine `sis-pdf-pdf/src/ir.rs`:
  - Stable IR line ordering and path encoding.
  - Nested dicts emit placeholder line + expanded paths.
  - Streams emit metadata only (length, filters, optional ratio).
  - Arrays summarize with type lists and truncated values.
- Add `IrOptions` for limits (max lines, max string length, max array elems).
- Malformed handling:
  - Unterminated strings: auto-close and record deviation.
  - Missing `endobj`: treat next `obj` or EOF as end; record deviation.
  - Incomplete dict/array: auto-close; record deviation.
  - Missing references: emit `ref` anyway and allow placeholder ORG nodes.
- Add unit tests for nested dicts, arrays, refs, streams, deviations.

### 2) ORG Construction
- Implement `OrgGraph::from_object_graph` in `sis-pdf-core/src/org.rs`:
  - Traverse each `ObjEntry` for `PdfAtom::Ref` and add edges.
  - Ensure `ObjRef` nodes are unique.
  - Optional reverse adjacency for quick reachability.
- Add `edge_index()` helper for `[2, E]` output (usize indices).
- Add JSON/DOT export helpers in `org_export.rs`.

### 3) IR Normalization for ML
- Add `normalize_ir_text()` in `sis-pdf-ml-graph/embedding/normalize.rs`:
  - Collapse object refs to placeholders (e.g., `ref:OBJ`).
  - Normalize numbers to `num:<N>` buckets or `num` token.
  - Normalize strings to `str:<len>` or `str` token.
  - Preserve key paths and value types.
- Add a `NormalizedIr` helper in `sis-pdf-core/ir_pipeline.rs`:
  - Returns both raw IR lines and normalized strings per object.
  - Keep a debug option to export raw + normalized per object.

### 4) `graph_model.json` Schema + Validation
- Implement `model_config.rs` with strict validation:
  - Required fields: `embedding.backend`, `embedding.model_path`, `graph.model_path`, `embedding.output_dim`, `graph.input_dim`.
  - Validate `embedding.output_dim == graph.input_dim`.
  - Resolve paths relative to `ml_model_dir`.
  - Ensure tokenizer file(s) exist.
- Provide clear error messages for missing or mismatched files.

### 5) Tokenizer Integration
- Add `tokenizers` crate (feature-gated under `ml-graph`).
- Load from `tokenizer.json` or `vocab.json` + `merges.txt`.
- Deterministic settings: no randomization, fixed max length, truncation.
- Output tensors: `input_ids`, `attention_mask`, `token_type_ids` if model requires.

### 6) ONNX Embedding Backend
- Add `onnxruntime` dependency (feature-gated under `ml-graph`).
- Load embedding model once per run (store in `GraphModelRunner`).
- Implement pooling:
  - `cls`: take first token embedding.
  - `mean`: average of token embeddings with attention mask.
- Provide `embed_ir_objects(texts: &[String]) -> Vec<Vec<f32>>`.
- Add batching to reduce runtime overhead.

### 7) ONNX GNN Backend
- Load GNN model (`graph.onnx`) once per run.
- Input signature:
  - `node_features`: `[N, D]` float32.
  - `edge_index`: `[2, E]` int64.
  - Optional `node_mask` for padded inputs.
- Output:
  - Single score or logit. Apply sigmoid if config says `apply_sigmoid`.

### 8) Inference Wiring in `sis-pdf-core`
- Extend ML integration to:
  1) Build IR and ORG.
  2) Normalize IR strings.
  3) Embed IR to node features.
  4) Build `edge_index`.
  5) Run GNN for a score.
- Emit ML summary in report JSON/Markdown.
- Emit finding `ml_graph_score_high` when score >= threshold.

### 9) CLI and Ergonomics
- Keep `--ml` and add `--ml-mode graph` for graph inference.
- Fail fast with clear errors if:
  - `ml_model_dir` is missing or incomplete.
  - `graph_model.json` is invalid.
  - Tokenizer files are missing.
- Provide `sis export-ir` and `sis export-org` for offline debug.
- Add `--ir` flag to enable static IR/ORG detectors (no ML) and report summary.

### 10) Reporting and UX
- Extend `structural_summary` with IR/ORG counts.
- Add ML summary fields:
  - `ml_summary.graph.score`, `ml_summary.graph.threshold`, `ml_summary.graph.label`.
- Ensure JSON, Markdown, and SARIF remain consistent.

### 11) Testing and Validation
- IR/ORG unit tests for correctness and stability.
- Tokenizer tests for deterministic output and max length handling.
- ONNX tests with a tiny synthetic model to validate shapes and outputs.
- Integration test: run `--ml-mode graph` with dummy model and assert `ml_summary`.

## Operator Workflow Example

```
# Build with graph ML support
cargo build -p sis-pdf --features ml-graph

# Run graph ML scan
sis scan file.pdf --ml --ml-mode graph --ml-model-dir models

# Export IR/ORG for debugging
sis export-ir file.pdf --format json -o ir.json
sis export-org file.pdf --format json -o org.json
```

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

## Packaging Requirements
- `ml_model_dir/graph_model.json`
- `ml_model_dir/embedding.onnx`
- `ml_model_dir/graph.onnx`
- `ml_model_dir/tokenizer.json` (or `vocab.json` + `merges.txt`)

## Milestones
1) IR extraction + ORG build stable under malformed inputs.
2) Model config parsing + tokenizer integration.
3) ONNX embedding backend + pooling.
4) ONNX GNN backend + graph input assembly.
5) Full inference wiring + report output.
6) UX and documentation updates with clear operator guidance.
