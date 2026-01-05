# Graph Model Schema

This document defines the `graph_model.json` schema used by graph ML inference. It describes required fields, validation rules, and packaging expectations.

## Overview

`graph_model.json` is a model manifest that describes:
- how to embed PDFObj IR (tokenizer + embedding model),
- how to run the GNN graph classifier,
- thresholds, limits, and optional integrity checks.

All paths are resolved relative to the model directory passed via `--ml-model-dir`.

## Required Fields

### schema_version
- Type: integer
- Required: yes
- Notes: current version is `1`.

### name
- Type: string
- Required: yes
- Notes: human-readable model name.

### embedding
- Type: object
- Required: yes
- Notes: embedding backend configuration.

#### embedding.backend
- Type: string
- Required: yes
- Values: `onnx` (future: `candle`, `ggml`)

#### embedding.model_path
- Type: string
- Required: yes
- Notes: relative path to embedding model (e.g., `embedding.onnx`).

#### embedding.tokenizer_path
- Type: string
- Required: yes
- Notes: relative path to `tokenizer.json` (or a `vocab.json` + `merges.txt` pair).

#### embedding.max_length
- Type: integer
- Required: yes
- Notes: max token length for embedding input.

#### embedding.pooling
- Type: string
- Required: yes
- Values: `cls`, `mean`.

#### embedding.output_dim
- Type: integer
- Required: yes
- Notes: output vector size; must match `graph.input_dim`.

#### embedding.normalize
- Type: object
- Required: yes
- Notes: normalization rules for IR before tokenization.

### graph
- Type: object
- Required: yes
- Notes: graph inference configuration.

#### graph.backend
- Type: string
- Required: yes
- Values: `onnx`.

#### graph.model_path
- Type: string
- Required: yes
- Notes: relative path to GNN model (e.g., `graph.onnx`).

#### graph.input_dim
- Type: integer
- Required: yes
- Notes: must match `embedding.output_dim`.

#### graph.output
- Type: object
- Required: yes

##### graph.output.kind
- Type: string
- Required: yes
- Values: `logit`, `probability`.

##### graph.output.apply_sigmoid
- Type: boolean
- Required: yes
- Notes: if `kind` is `logit`, apply sigmoid when true.

### threshold
- Type: number
- Required: yes
- Notes: threshold for malicious label.

### edge_index
- Type: object
- Required: yes

#### edge_index.directed
- Type: boolean
- Required: yes
- Notes: whether edges are directed.

#### edge_index.add_reverse_edges
- Type: boolean
- Required: yes
- Notes: if true, add reverse edges for GNN.

## Optional Fields

### integrity
- Type: object
- Notes: optional SHA256 hashes for model files.

#### integrity.embedding_sha256
- Type: string

#### integrity.graph_sha256
- Type: string

#### integrity.tokenizer_sha256
- Type: string

### adversarial
- Type: object
- Notes: optional OOD/evasion detection settings.

#### adversarial.enable_ood_detection
- Type: boolean

#### adversarial.ood_threshold
- Type: number

#### adversarial.enable_evasion_detection
- Type: boolean

#### adversarial.evasion_deviation_threshold
- Type: integer

### limits
- Type: object
- Notes: resource limits for IR/ORG/ML.

#### limits.max_ir_lines_per_object
- Type: integer

#### limits.max_ir_string_length
- Type: integer

#### limits.max_ir_nesting_depth
- Type: integer

#### limits.max_org_nodes
- Type: integer

#### limits.max_org_edges
- Type: integer

#### limits.max_embedding_batch_size
- Type: integer

#### limits.embedding_timeout_ms
- Type: integer

#### limits.inference_timeout_ms
- Type: integer

#### limits.max_graph_memory_mb
- Type: integer

## Validation Rules

- `schema_version` must be `1`.
- `embedding.output_dim` must equal `graph.input_dim`.
- All referenced paths must exist within `ml_model_dir`.
- Optional integrity hashes must match file content when present.
- ONNX models must not use external tensor data.
- ONNX opsets must be in the `ai.onnx` domain.

## Example

```json
{
  "schema_version": 1,
  "name": "pdfobj2vec_gin_v1",
  "version": "1.0.0",
  "description": "PDFObj IR + GNN classifier for malicious PDF detection",
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
      "collapse_obj_refs": true,
      "preserve_keywords": [
        "/JS", "/JavaScript", "/OpenAction", "/AA",
        "/Launch", "/GoToR", "/URI", "/SubmitForm",
        "/RichMedia", "/EmbeddedFile", "/ObjStm"
      ],
      "hash_strings": true,
      "include_deviation_markers": true
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
  },
  "integrity": {
    "embedding_sha256": "a1b2c3d4e5f6...",
    "graph_sha256": "f6e5d4c3b2a1...",
    "tokenizer_sha256": "123456789abc..."
  },
  "adversarial": {
    "enable_ood_detection": true,
    "ood_threshold": 0.8,
    "enable_evasion_detection": true,
    "evasion_deviation_threshold": 50
  },
  "limits": {
    "max_ir_lines_per_object": 1000,
    "max_ir_string_length": 10000,
    "max_ir_nesting_depth": 32,
    "max_org_nodes": 10000,
    "max_org_edges": 50000,
    "max_embedding_batch_size": 32,
    "embedding_timeout_ms": 30000,
    "inference_timeout_ms": 30000,
    "max_graph_memory_mb": 512
  }
}
```

## Packaging Expectations

The model directory should include:
- `graph_model.json`
- `embedding.onnx`
- `graph.onnx`
- `tokenizer.json` (or `vocab.json` + `merges.txt`)
- Optional `README.md` and `LICENSE`
