# Model Creation and Use (Evasive-PDFMal2022)

This guide explains how to create a graph ML model package from the Evasive-PDFMal2022 dataset and use it to scan unknown PDFs with SIS-PDF.

## 1) Prepare the dataset

Organize samples into two folders:
- `data/benign/` for clean PDFs
- `data/malicious/` for malicious PDFs

Keep filenames stable; they will be used as labels in dataset exports.

## 2) Export IR/ORG datasets

Use SIS-PDF to export IR and ORG so you can build training data externally.

Examples:
```
sis export-ir data/benign/sample.pdf --format json -o out/ir/benign/sample.json
sis export-org data/benign/sample.pdf --format json -o out/org/benign/sample.json
```

For large datasets, write a small batch script that iterates over your sample directories.

Example batch script:

```bash
#!/usr/bin/env bash
set -euo pipefail

BASE_OUT="out"
mkdir -p "${BASE_OUT}/ir/benign" "${BASE_OUT}/ir/malicious"
mkdir -p "${BASE_OUT}/org/benign" "${BASE_OUT}/org/malicious"

scan_dir() {
  local label="$1"
  local src_dir="$2"
  for pdf in "${src_dir}"/*.pdf; do
    [ -e "$pdf" ] || continue
    local name
    name="$(basename "$pdf" .pdf)"
    sis export-ir "$pdf" --format json -o "${BASE_OUT}/ir/${label}/${name}.json"
    sis export-org "$pdf" --format json -o "${BASE_OUT}/org/${label}/${name}.json"
  done
}

scan_dir benign data/benign
scan_dir malicious data/malicious
```

Example dataset manifest (JSONL):

```bash
#!/usr/bin/env bash
set -euo pipefail

OUT="out"
MANIFEST="${OUT}/dataset.jsonl"
mkdir -p "${OUT}"
rm -f "${MANIFEST}"

emit() {
  local label="$1"
  local name="$2"
  printf '{"label":"%s","ir":"%s","org":"%s"}\n' \
    "$label" "${OUT}/ir/${label}/${name}.json" "${OUT}/org/${label}/${name}.json" >> "${MANIFEST}"
}

for label in benign malicious; do
  for ir in "${OUT}/ir/${label}"/*.json; do
    [ -e "$ir" ] || continue
    name="$(basename "$ir" .json)"
    emit "$label" "$name"
  done
done
```

## 3) Train the model (external pipeline)

Training is done outside of SIS-PDF. A typical pipeline is:
1) Convert IR to embeddings (transformer encoder).
2) Build ORG edges for each sample.
3) Train a GNN classifier on the graph data.

The training output should include:
- `embedding.onnx` (text encoder)
- `graph.onnx` (GNN classifier)
- `tokenizer.json` (tokenizer for the encoder)
- `graph_model.json` (model manifest)

Example pipeline (external):
1) Build per-sample graph datasets:
   - Parse IR JSON and ORG JSON into:
     - `node_texts`: list of normalized IR strings (one per object).
     - `edge_index`: list of `(src, dst)` edges from ORG.
   - Store as a training dataset (e.g., JSONL with `{label, node_texts, edge_index}`).

2) Train the embedding model:
   - Option A: Use a pre-trained transformer (BERT/CodeT5) and export to ONNX.
   - Option B: Fine-tune a transformer on IR texts and export to ONNX.

3) Train the GNN:
   - Use `node_embeddings` from the embedding model as node features.
   - Train a GIN (or similar) on ORG graphs for binary classification.
   - Export the trained graph model to ONNX.

Example Python sketch:
```python
# Pseudocode: build graphs -> embed -> train GNN -> export ONNX
from pathlib import Path
import json

def load_sample(ir_path, org_path):
    ir = json.load(open(ir_path))
    org = json.load(open(org_path))
    node_texts = []
    for obj in ir["objects"]:
        lines = []
        for line in obj["lines"]:
            lines.append(f'{line["path"]} {line["type"]} {line["value"]}')
        node_texts.append(" ; ".join(lines))
    edge_index = [
        (e["src"], e["dst"]) if "src" in e else (e["from"], e["to"])
        for e in org["edges"]
    ]
    return node_texts, edge_index

# Step 1: Build dataset
dataset = []
for label, base in [("benign", "data/benign"), ("malicious", "data/malicious")]:
    for ir_path in Path(f"out/ir/{label}").glob("*.json"):
        org_path = Path(f"out/org/{label}/{ir_path.stem}.json")
        node_texts, edge_index = load_sample(ir_path, org_path)
        dataset.append({"label": label, "node_texts": node_texts, "edge_index": edge_index})

# Step 2: Embed IR texts with a transformer, then train GNN on graphs.
# Example: embed IR texts to vectors (Linux + AMD Radeon ROCm)
#
# from transformers import AutoTokenizer, AutoModel
# import torch
#
# device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
#
# tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
# model = AutoModel.from_pretrained("bert-base-uncased").to(device)
# model.eval()
#
# def embed_texts(texts, batch_size=32):
#     vectors = []
#     for i in range(0, len(texts), batch_size):
#         chunk = texts[i:i + batch_size]
#         batch = tokenizer(
#             chunk,
#             padding=True,
#             truncation=True,
#             max_length=256,
#             return_tensors="pt",
#         )
#         batch = {k: v.to(device) for k, v in batch.items()}
#         with torch.no_grad():
#             outputs = model(**batch)
#         vectors.append(outputs.last_hidden_state[:, 0, :].cpu())
#     return torch.cat(vectors, dim=0).numpy()
#
# node_features = embed_texts(node_texts, batch_size=64)
#
# Example: train a GIN on graph data (PyTorch Geometric style, ROCm)
#
# from torch_geometric.data import Data
# from torch_geometric.nn import GINConv, global_add_pool
#
# class GIN(torch.nn.Module):
#     def __init__(self, in_dim, hidden_dim):
#         super().__init__()
#         self.conv1 = GINConv(torch.nn.Sequential(
#             torch.nn.Linear(in_dim, hidden_dim),
#             torch.nn.ReLU(),
#             torch.nn.Linear(hidden_dim, hidden_dim),
#         ))
#         self.lin = torch.nn.Linear(hidden_dim, 1)
#
#     def forward(self, x, edge_index, batch):
#         x = self.conv1(x, edge_index)
#         x = global_add_pool(x, batch)
#         return self.lin(x)
#
# data = Data(x=torch.tensor(node_features), edge_index=edge_index, y=label)
# data = data.to(device)
# loss = torch.nn.BCEWithLogitsLoss()
# logits = model(data.x, data.edge_index, data.batch)
# loss(logits.view(-1), data.y.float())
#
# Step 3: Export embedding and GNN models to ONNX.
# Example: export encoder to ONNX
#
# torch.onnx.export(
#     model,
#     (batch["input_ids"].to(device), batch["attention_mask"].to(device)),
#     "embedding.onnx",
#     input_names=["input_ids", "attention_mask"],
#     output_names=["last_hidden_state"],
#     dynamic_axes={"input_ids": {0: "batch", 1: "seq"}, "attention_mask": {0: "batch", 1: "seq"}},
#     opset_version=17,
# )
#
# Example: export GNN to ONNX (fixed-size example)
#
# dummy_x = torch.randn(10, 768, device=device)
# dummy_edge_index = torch.zeros(2, 20, dtype=torch.long, device=device)
# dummy_batch = torch.zeros(10, dtype=torch.long, device=device)
# torch.onnx.export(
#     gnn_model,
#     (dummy_x, dummy_edge_index, dummy_batch),
#     "graph.onnx",
#     input_names=["node_features", "edge_index", "batch"],
#     output_names=["score"],
#     opset_version=17,
# )
```

Example training outline (Python, high level):
```python
# 1) Load dataset.jsonl and build graph objects.
# 2) Encode node_texts with a transformer (e.g., HuggingFace model).
# 3) Train a GNN (e.g., GIN) for binary classification.
# 4) Export encoder + GNN to ONNX.
```

Note: SIS-PDF does not currently include a training pipeline. It is possible to add training support, but it would bring heavyweight ML dependencies and a more complex build. The recommended approach is to keep training external and only perform inference in SIS-PDF.

## 4) Create `graph_model.json`

Use the schema in `docs/graph-model-schema.md`. A minimal example:

```json
{
  "schema_version": 1,
  "name": "pdfobj2vec_gin_v1",
  "version": "1.0.0",
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
  }
}
```

## 5) Package the model directory

The model directory should look like:

```
models/pdfobj2vec_v1/
  graph_model.json
  embedding.onnx
  graph.onnx
  tokenizer.json
```

## 6) Run classification on unknown PDFs

Build with graph ML support:

```
cargo build -p sis-pdf --features ml-graph
```

Scan an unknown file:

```
sis scan unknown.pdf --ml --ml-mode graph --ml-model-dir models/pdfobj2vec_v1
```

JSON output with ML summary:

```
sis scan unknown.pdf --ml --ml-mode graph --ml-model-dir models/pdfobj2vec_v1 --json
```

## 7) Validate results

Recommended checks:
- Confirm the model directory passes schema validation.
- Compare `ml_graph_score_high` findings against manual triage.
- Spot-check false positives and retrain if needed.

## 8) Iterate

As new samples arrive:
- Re-run IR/ORG export on the new samples.
- Fine-tune the embedding model or retrain the GNN.
- Update the model directory and version in `graph_model.json`.
