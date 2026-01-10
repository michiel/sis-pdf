# Pipeline Fix Proposals (Info Loss)

Goal: eliminate or minimize information loss across `scripts/scan-dir.sh`,
`scripts/generate-manifest.sh`, and `scripts/modeling-training-amd.py`, while
keeping the exported artifacts compatible with the Rust SIS runtime.

## 1) Pooling/ONNX Mismatch (High)

**Issue**: Training pools encoder outputs in Python, but `embedding.onnx` only
exports `last_hidden_state`. If inference does not re-apply identical pooling,
the model consumes a different representation than training.

**Concrete fixes**:
- Export the pooling step inside ONNX so inference always matches training.
  - Add a small wrapper module around the encoder that returns pooled embeddings
    (CLS or mean) instead of raw `last_hidden_state`.
  - Export that wrapper as `embedding.onnx` and update `graph_model.json` to
    reflect the new output name (e.g., `pooled_embedding`).
- If you want to keep `last_hidden_state` for debugging, export it as a second
  output and update the Rust runtime to ignore it by default.
- Add a metadata flag that records `pooling` and make the Rust runtime enforce
  the same pooling method when embedding is not pooled in ONNX.

**Runtime changes (Rust)**:
- Ensure the Rust inference path applies the same pooling and `max_length`
  truncation as training when it consumes `embedding.onnx`.

## 2) Max-Length Truncation (High)

**Issue**: `embed_texts` truncates to `--max-length` (default 256), discarding
tokens beyond that. Malicious payloads can be late in content.

**Concrete fixes**:
- Increase `--max-length` and record it in the manifest/metadata.
- Implement a sliding-window strategy in training:
  - For each node text, chunk into windows of `max_length` with overlap.
  - Pool across windows (mean or max) to keep late content signal.
  - Save the windowing strategy in `graph_model.json` so Rust inference matches.
- For long objects, add a fallback heuristic in the pipeline to record a hash of
  the full text (or an n-gram sketch) into the node features so the model can
  learn signals beyond the truncation window.

**Runtime changes (Rust)**:
- Mirror the same chunking/pooling strategy if used in training.
- Enforce `max_length` and window overlap from metadata.

## 3) IR Line Flattening (Medium)

**Issue**: Each IR object's lines are flattened to `"path type value"` and
joined with `" ; "`, losing structure and any other fields.

**Concrete fixes**:
- Preserve structured fields in the text serialization:
  - Encode line boundaries and keys explicitly (e.g., `PATH=... TYPE=... VALUE=...`).
  - Include additional fields if present (e.g., `offset`, `length`, `flags`).
- Store the raw IR line JSON for each node in an auxiliary file and include a
  reference in the manifest. This lets you evolve featurization without losing
  raw content.
- Consider adding a `line_index` token to preserve order more clearly.

**Pipeline changes**:
- Update `scripts/modeling-training-amd.py` to include all IR line fields or a
  stable, loss-minimized serialization (explicit key/value tags).
- Update manifest generation to include a schema version for line encoding.

## 4) Unresolved Edge Drop (Medium)

**Issue**: Edges that don't map to IR nodes are dropped.

**Concrete fixes**:
- Add a sentinel node per sample (e.g., `/UNRESOLVED`) and route unresolved
  edges to that node. This preserves the presence and count of unresolved edges.
- Track a per-graph feature (or node feature) with the number of unresolved
  edges; include it in the node text or as a separate numeric feature.
- Emit a separate list of unresolved edges in a sidecar file to allow auditing.

**Pipeline changes**:
- Modify `load_sample` to create a sentinel node and rewire unresolved edges.
- Record `unresolved_edge_count` in metadata for each sample.

## 5) Empty Graphs Forced Self-Loop (Medium)

**Issue**: Graphs without edges are given a fake self-loop, which can blur the
signal of "no edges" vs. "self-connected".

**Concrete fixes**:
- Represent empty graphs explicitly:
  - Allow `edge_index` to be empty and handle it in the GNN (skip conv or use
    a dedicated code path for empty edges).
  - Add a graph-level feature `has_edges` so the model can learn the distinction.
- If a self-loop is required by the framework, add a boolean flag to indicate
  it was synthetic.

**Runtime changes (Rust)**:
- Ensure inference accepts empty `edge_index` without injecting edges, or match
  training behavior exactly if a synthetic edge is retained.

## 6) Label Collapsing (Low)

**Issue**: Non-`malicious` labels are treated as benign, losing multi-class info.

**Concrete fixes**:
- Preserve label strings and store them in the manifest.
- If you intend binary classification, validate the manifest schema and error
  on unknown labels rather than silently collapsing.
- If multi-class is needed later, change the model head to multi-class and
  record the label map in metadata.

## Additional Pipeline Enhancements

- Add a manifest schema version and validate it in `modeling-training-amd.py`.
- Record normalization steps (e.g., string hashing, keyword preservation) in
  metadata and enforce them in Rust inference.
- Emit a per-sample summary (`node_count`, `edge_count`, `unresolved_edges`) to
  catch pipeline regressions.

## Suggested Order of Implementation

1) Fix pooling/ONNX mismatch.
2) Add explicit handling for empty graphs and unresolved edges.
3) Improve text serialization to preserve structure.
4) Address truncation with chunking/pooling.
5) Add label schema validation.
