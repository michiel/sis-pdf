# ONNX IR/ORG + GNN Inference Plan

This plan merges the IR/ORG pipeline work and the ONNX embedding/GNN backend into one end-to-end implementation plan, including ergonomics, security hardening, and adversarial ML robustness for production deployment.

## Goals

- Produce PDFObj IR and ORG reliably for malformed PDFs.
- Embed IR into vectors using an ONNX-backed language model (tokenizer + model).
- Run a GNN (GIN-style) on ORG + embeddings to produce a score.
- Provide a usable operator workflow: clear CLI flags, good errors, consistent reports, and export tools.
- Keep default scans fast; all heavy ML is behind `--ml --ml-mode graph` and `ml-graph` feature.
- **Harden against adversarial ML attacks:** resource exhaustion, evasion, and supply chain compromise.
- **Integrate with existing security review findings** and the mitigations captured in this plan.

## Scope

- Inference only (training stays external).
- ONNXRuntime is the primary backend (CPU by default; optional GPU if runtime supports it).
- Tokenizers from HuggingFace format (`tokenizer.json` or `vocab.json` + `merges.txt`).
- IR/ORG export remains available without ML.
- No raw stream bytes inside IR text.
- **Model integrity validation** via SHA256 checksums.
- **Resource limits** enforced at all stages (IR, ORG, embedding, GNN).
- **Adversarial detection** via out-of-distribution (OOD) and evasion markers.

## Security Principles

**Defense in Depth:**
1. **Input validation** - Sanitize IR paths, limit nesting depth, pre-truncate strings.
2. **Resource budgets** - Hard limits on nodes, edges, inference time, memory.
3. **Supply chain integrity** - Verify model checksums, restrict paths, validate ONNX safety.
4. **Adversarial awareness** - Detect OOD inputs, normalize suspicious keywords differently, flag evasion attempts.
5. **Fail-safe defaults** - Conservative limits, require explicit opt-in for heavy operations.

## Architecture Overview

### Crates and Modules

- `sis-pdf-pdf`
  - `ir.rs`: IR generation from parsed objects with security hardening.
- `sis-pdf-core`
  - `org.rs`: ORG builder with cycle detection and size limits.
  - `ir_pipeline.rs`: orchestrates IR + ORG + normalized IR text output.
  - `ir_export.rs`: export IR (text/json).
  - `report.rs`: includes IR/ORG summary + adversarial markers in reports.
- `sis-pdf-ml-graph` (feature `ml-graph`)
  - `embedding/onnx.rs`: ONNX embedding runtime with timeout and batching.
  - `embedding/tokenizer.rs`: HF tokenizer wrapper with truncation.
  - `embedding/normalize.rs`: IR normalization with adversarial robustness.
  - `graph/onnx.rs`: ONNX GNN runtime with size validation and timeout.
  - `graph/inputs.rs`: edge index + node feature assembly with overflow checks.
  - `model_config.rs`: `graph_model.json` parser with integrity validation.
  - `security/model_validator.rs`: ONNX safety checks (banned ops, path restrictions).
  - `security/ood_detector.rs`: Out-of-distribution detection.
- `sis-pdf` (CLI)
  - `--ml --ml-mode graph` enables graph inference.
  - `export-ir` and `export-org` for offline workflows.

### Resource Limits (Default Values)

```rust
pub struct GraphMlLimits {
    // IR extraction
    pub max_ir_lines_per_object: usize,     // 1,000
    pub max_ir_string_length: usize,        // 10,000 (10 KB)
    pub max_ir_nesting_depth: usize,        // 32
    pub max_ir_array_elements: usize,       // 1,000

    // ORG construction
    pub max_org_nodes: usize,               // 10,000
    pub max_org_edges: usize,               // 50,000
    pub max_org_traversal_depth: usize,     // 100

    // Tokenization & Embedding
    pub max_tokenize_length: usize,         // 10,000 chars (pre-truncate)
    pub max_embedding_batch_size: usize,    // 32
    pub embedding_timeout_ms: u64,          // 30,000 (30 sec)

    // GNN Inference
    pub gnn_inference_timeout_ms: u64,      // 30,000 (30 sec)
    pub max_graph_memory_mb: usize,         // 512 MB

    // Adversarial detection
    pub ood_threshold: f32,                 // 0.8
    pub evasion_deviation_threshold: usize, // 50
}
```

## Detailed Implementation Steps

### 1) IR Extraction (PDFObj IR) - Security Hardened

**Core functionality:**
- Add or refine `sis-pdf-pdf/src/ir.rs`:
  - Stable IR line ordering and path encoding.
  - Nested dicts emit placeholder line + expanded paths.
  - Streams emit metadata only (length, filters, optional ratio).
  - Arrays summarize with type lists and truncated values.

**Security enhancements:**

```rust
pub struct IrOptions {
    pub max_lines: usize,           // 1,000 per object
    pub max_string_length: usize,   // 10,000 chars
    pub max_array_elems: usize,     // 1,000 elements
    pub max_nesting_depth: usize,   // 32 levels
    pub sanitize_paths: bool,       // true - remove .. and non-alphanumeric
}

pub struct IrObject {
    pub object_ref: ObjRef,
    pub lines: Vec<String>,
    pub deviations: Vec<String>,    // Include malformed markers
    pub truncated: bool,            // True if limits hit
    pub nesting_depth: usize,       // Track max depth reached
}
```

**Path sanitization (encode, don’t erase):**
```rust
fn escape_ir_path(path: &[u8]) -> String {
    // Preserve uniqueness by percent-encoding non-safe bytes.
    // This keeps distinct PDF names distinct while still being ASCII-safe.
    let mut out = String::new();
    for &b in path {
        let c = b as char;
        if c.is_ascii_alphanumeric() || c == '/' || c == '_' || c == '-' {
            out.push(c);
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", b));
        }
    }
    out
}
```
Keep both the raw bytes and the escaped form so detectors can preserve full signal while keeping ASCII-safe output.

**Nesting depth enforcement:**
```rust
fn generate_ir_recursive(
    obj: &PdfObj,
    path: &str,
    depth: usize,
    options: &IrOptions,
    lines: &mut Vec<String>,
) -> Result<()> {
    if depth > options.max_nesting_depth {
        lines.push(format!("{} TRUNCATED_DEPTH", path));
        return Ok(());
    }
    // ... continue recursion with depth + 1
}
```

**Malformed handling:**
- Unterminated strings: auto-close and record deviation `"unterminated_string"`.
- Missing `endobj`: treat next `obj` or EOF as end; record deviation `"missing_endobj"`.
- Incomplete dict/array: auto-close; record deviation `"incomplete_container"`.
- Missing references: emit `ref` anyway; record deviation `"dangling_ref"`.

**Unit tests:**
- Nested dicts at depth 33 (should truncate at 32).
- 10 MB string in object (should truncate to 10 KB).
- Arrays with 10,000 elements (should truncate to 1,000).
- All deviation types and IR stability.

---

### 2) ORG Construction - With Cycle Detection

**Core functionality:**
- Implement `OrgGraph::from_object_graph` in `sis-pdf-core/src/org.rs`:
  - Traverse each `ObjEntry` for `PdfAtom::Ref` and add edges.
  - Ensure `ObjRef` nodes are unique.
  - Build reverse adjacency for quick reachability.

**Security enhancements:**

```rust
pub struct OrgGraph {
    pub nodes: Vec<ObjRef>,
    pub edges: Vec<(usize, usize)>,  // (from_idx, to_idx)
    pub has_cycles: bool,
    pub max_depth: usize,
    pub avg_degree: f32,
}

pub struct OrgBuildOptions {
    pub max_nodes: usize,           // 10,000
    pub max_edges: usize,           // 50,000
    pub max_traversal_depth: usize, // 100
    pub detect_cycles: bool,        // true
}
```

**Cycle detection:**
```rust
fn build_org_with_cycle_detection(
    objects: &[ObjEntry],
    options: &OrgBuildOptions,
) -> Result<OrgGraph> {
    let mut graph = OrgGraph::new();
    let mut visited = HashSet::new();
    let mut rec_stack = HashSet::new();

    for entry in objects {
        if graph.nodes.len() >= options.max_nodes {
            return Err(anyhow!("ORG node limit exceeded: {}", options.max_nodes));
        }

        // DFS with cycle detection
        if has_cycle_dfs(entry, &mut visited, &mut rec_stack, &objects) {
            graph.has_cycles = true;
        }
    }

    if graph.edges.len() > options.max_edges {
        return Err(anyhow!("ORG edge limit exceeded: {}", options.max_edges));
    }

    Ok(graph)
}
```

**Size validation:**
```rust
fn validate_graph_size(graph: &OrgGraph, limits: &GraphMlLimits) -> Result<()> {
    if graph.nodes.len() > limits.max_org_nodes {
        return Err(anyhow!(
            "Graph too large: {} nodes (max {})",
            graph.nodes.len(),
            limits.max_org_nodes
        ));
    }

    if graph.edges.len() > limits.max_org_edges {
        return Err(anyhow!(
            "Graph too large: {} edges (max {})",
            graph.edges.len(),
            limits.max_org_edges
        ));
    }

    Ok(())
}
```

**Large graph sampling (fallback):**
```rust
fn sample_large_graph(org: &OrgGraph, max_nodes: usize) -> OrgGraph {
    // Sample strategy:
    // 1. Always include root object (obj 1 0)
    // 2. Include high-degree nodes (hubs)
    // 3. Include nodes with suspicious IR keywords
    // 4. Random sample of remainder

    sample_by_importance(org, max_nodes)
}
```

**Export helpers:**
- `edge_index()` helper for `[2, E]` format (usize indices).
- JSON export in `org_export.rs`.
- DOT export for Graphviz visualization.

**Unit tests:**
- Recursive references (A → B → C → A).
- Graph with 10,001 nodes (should error).
- Graph with 50,001 edges (should error).
- Disconnected components and isolated nodes.

---

### 3) IR Normalization for ML - Adversarial Robustness

**Core normalization:**
- Add `normalize_ir_text()` in `sis-pdf-ml-graph/embedding/normalize.rs`:
  - Collapse object refs to placeholders (e.g., `ref:OBJ`).
  - Normalize numbers to `num:<bucket>` or `num` token.
  - Normalize strings to `str:HASH` with SHA256 prefix.
  - Preserve key paths and value types.

**Adversarial enhancements:**

```rust
pub struct NormalizeOptions {
    pub normalize_numbers: bool,             // true
    pub normalize_strings: bool,             // true
    pub collapse_obj_refs: bool,             // true
    pub preserve_keywords: Vec<String>,      // ["/JS", "/JavaScript", "/OpenAction", ...]
    pub hash_strings: bool,                  // true - hash instead of length
    pub include_deviation_markers: bool,     // true
}

pub fn normalize_ir_text(ir: &IrObject, options: &NormalizeOptions) -> String {
    let mut normalized = Vec::new();

    for line in &ir.lines {
        let norm_line = if is_suspicious_keyword(line, &options.preserve_keywords) {
            // Don't normalize suspicious keywords - preserve signal
            line.clone()
        } else {
            apply_normalization(line, options)
        };
        normalized.push(norm_line);
    }

    // Append deviation markers for adversarial detection
    if options.include_deviation_markers && !ir.deviations.is_empty() {
        normalized.push(format!("DEVIATIONS:{}", ir.deviations.len()));
        for dev in &ir.deviations {
            normalized.push(format!("DEV:{}", dev));
        }
    }

    normalized.join("\n")
}
```

**String hashing (prevents exact matching):**
```rust
fn normalize_string_value(s: &str) -> String {
    if s.len() < 32 {
        "str:SHORT".to_string()
    } else {
        // Hash to prevent exact fingerprinting
        let hash = sha256::digest(s.as_bytes());
        format!("str:HASH_{}", &hash[..8])
    }
}
```

**Number bucketing:**
```rust
fn normalize_number(n: i64) -> String {
    match n {
        0 => "num:ZERO",
        1..=10 => "num:SMALL",
        11..=100 => "num:MED",
        101..=1000 => "num:LARGE",
        _ => "num:HUGE",
    }.to_string()
}
```

**Preserved keywords (don't normalize):**
```
/JS, /JavaScript, /OpenAction, /AA, /Launch, /GoToR, /URI,
/SubmitForm, /RichMedia, /EmbeddedFile, /ObjStm, /XObject
```

**Anti-collision detection:**
```rust
fn compute_feature_entropy(normalized_irs: &[String]) -> f32 {
    // Compute Shannon entropy of normalized features
    // Low entropy = many objects normalized identically = potential collision attack

    let mut freq = HashMap::new();
    for ir in normalized_irs {
        *freq.entry(ir).or_insert(0) += 1;
    }

    let total = normalized_irs.len() as f32;
    let mut entropy = 0.0;
    for count in freq.values() {
        let p = *count as f32 / total;
        entropy -= p * p.log2();
    }

    entropy
}
```

**Unit tests:**
- Normalization preserves `/JavaScript` but normalizes `/CustomKey`.
- String hashing produces consistent output.
- High deviation count included in normalized output.
- Entropy detection for collision attacks.

---

### 4) `graph_model.json` Schema + Security Validation

**Core validation:**
- Implement `model_config.rs` with strict validation:
  - Required fields: `schema_version`, `embedding`, `graph`, `threshold`.
  - Validate `embedding.output_dim == graph.input_dim`.
  - Resolve paths relative to `ml_model_dir`.
  - Ensure tokenizer and model files exist.

**Security validation:**

```rust
pub struct ModelConfig {
    pub schema_version: u32,
    pub name: String,
    pub version: String,
    pub embedding: EmbeddingConfig,
    pub graph: GraphConfig,
    pub threshold: f32,
    pub edge_index: EdgeIndexConfig,
    pub integrity: Option<IntegrityChecks>,
    pub adversarial: Option<AdversarialConfig>,
    pub limits: Option<ResourceLimits>,
}

pub struct IntegrityChecks {
    pub embedding_sha256: Option<String>,
    pub graph_sha256: Option<String>,
    pub tokenizer_sha256: Option<String>,
}

pub struct AdversarialConfig {
    pub enable_ood_detection: bool,
    pub ood_threshold: f32,
    pub enable_evasion_detection: bool,
    pub evasion_deviation_threshold: usize,
}

pub struct ResourceLimits {
    pub max_nodes: usize,
    pub max_edges: usize,
    pub embedding_timeout_ms: u64,
    pub inference_timeout_ms: u64,
}
```

**Path validation (prevent traversal):**
```rust
fn resolve_model_path(base_dir: &Path, relative: &str) -> Result<PathBuf> {
    // Reject obvious path traversal
    if relative.contains("..") || relative.starts_with('/') {
        return Err(anyhow!("Invalid model path: {}", relative));
    }

    let path = base_dir.join(relative);
    let canonical = path.canonicalize()
        .map_err(|e| anyhow!("Cannot resolve model path {}: {}", relative, e))?;

    // Must be inside ml_model_dir
    let canonical_base = base_dir.canonicalize()?;
    if !canonical.starts_with(&canonical_base) {
        return Err(anyhow!("Model path escapes ml_model_dir: {}", relative));
    }

    Ok(canonical)
}
```

**Integrity verification:**
```rust
fn validate_file_integrity(path: &Path, expected_hash: Option<&str>) -> Result<()> {
    if let Some(expected) = expected_hash {
        let actual = compute_sha256(path)?;
        if actual != expected {
            return Err(anyhow!(
                "Integrity check failed for {}: expected {}, got {}",
                path.display(),
                expected,
                actual
            ));
        }
        eprintln!("✓ Verified integrity: {}", path.display());
    } else {
        eprintln!("⚠ Integrity check not configured for {}", path.display());
    }
    Ok(())
}
```

**ONNX safety validation (inspectable checks):**
```rust
fn validate_onnx_safety(path: &Path) -> Result<()> {
    // Parse ONNX model and enforce checks we can actually inspect.
    let model_bytes = fs::read(path)?;
    let model = onnx::ModelProto::parse_from_bytes(&model_bytes)
        .map_err(|e| anyhow!("Invalid ONNX model: {}", e))?;

    // 1) Disallow custom domains.
    for opset in &model.opset_import {
        let domain = opset.domain.as_str();
        if !domain.is_empty() && domain != "ai.onnx" {
            return Err(anyhow!(
                "Unsupported ONNX domain in {}: {}",
                path.display(),
                domain
            ));
        }
    }

    // 2) Disallow external data tensors.
    for init in &model.graph.initializer {
        if init.data_location == onnx::tensor_proto::DataLocation::EXTERNAL as i32 {
            return Err(anyhow!(
                "External tensor data not allowed in {}: {}",
                path.display(),
                init.name
            ));
        }
    }

    // 3) Optional: enforce an op allowlist for ai.onnx.
    // (Keep this list short and audited; otherwise skip.)
    // for node in &model.graph.node {
    //     if !ALLOWED_OPS.contains(&node.op_type.as_str()) {
    //         return Err(anyhow!("Unsupported ONNX op: {}", node.op_type));
    //     }
    // }

    eprintln!("✓ ONNX safety validated: {}", path.display());
    Ok(())
}
```

**Clear error messages:**
```rust
impl ModelConfig {
    pub fn load_and_validate(ml_model_dir: &Path) -> Result<Self> {
        let config_path = ml_model_dir.join("graph_model.json");

        if !config_path.exists() {
            return Err(anyhow!(
                "graph_model.json not found in {}. \
                 Run `sis --help` for model packaging instructions.",
                ml_model_dir.display()
            ));
        }

        let config: ModelConfig = serde_json::from_str(&fs::read_to_string(&config_path)?)
            .map_err(|e| anyhow!("Invalid graph_model.json: {}", e))?;

        // Validate schema version
        if config.schema_version != 1 {
            return Err(anyhow!(
                "Unsupported schema version: {}. Expected 1.",
                config.schema_version
            ));
        }

        // Validate dimension matching
        if config.embedding.output_dim != config.graph.input_dim {
            return Err(anyhow!(
                "Dimension mismatch: embedding output {} != graph input {}",
                config.embedding.output_dim,
                config.graph.input_dim
            ));
        }

        // Resolve and validate all paths
        let emb_path = resolve_model_path(ml_model_dir, &config.embedding.model_path)?;
        let graph_path = resolve_model_path(ml_model_dir, &config.graph.model_path)?;
        let tok_path = resolve_model_path(ml_model_dir, &config.embedding.tokenizer_path)?;

        // Validate integrity
        validate_file_integrity(&emb_path, config.integrity.as_ref()
            .and_then(|i| i.embedding_sha256.as_deref()))?;
        validate_file_integrity(&graph_path, config.integrity.as_ref()
            .and_then(|i| i.graph_sha256.as_deref()))?;
        validate_file_integrity(&tok_path, config.integrity.as_ref()
            .and_then(|i| i.tokenizer_sha256.as_deref()))?;

        // Validate ONNX safety
        validate_onnx_safety(&emb_path)?;
        validate_onnx_safety(&graph_path)?;

        Ok(config)
    }
}
```

---

### 5) Tokenizer Integration - With Resource Limits

**Core functionality:**
- Add `tokenizers` crate (feature-gated under `ml-graph`).
- Load from `tokenizer.json` or `vocab.json` + `merges.txt`.
- Deterministic settings: no randomization, fixed max length, truncation.
- Output tensors: `input_ids`, `attention_mask`, `token_type_ids` if needed.

**Resource protections:**

```rust
const MAX_TOKENIZE_LENGTH: usize = 10_000;  // Pre-truncate input strings

pub struct TokenizerWrapper {
    tokenizer: Tokenizer,
    max_length: usize,
}

impl TokenizerWrapper {
    pub fn from_config(path: &Path, max_length: usize) -> Result<Self> {
        let tokenizer = Tokenizer::from_file(path)
            .map_err(|e| anyhow!("Failed to load tokenizer: {}", e))?;

        Ok(Self {
            tokenizer,
            max_length: max_length.min(MAX_TOKENIZE_LENGTH),
        })
    }

    pub fn encode(&self, text: &str) -> Result<Encoding> {
        // Pre-truncate to prevent tokenization DoS
        let truncated = if text.len() > MAX_TOKENIZE_LENGTH {
            &text[..MAX_TOKENIZE_LENGTH]
        } else {
            text
        };

        self.tokenizer
            .encode(truncated, true)
            .map_err(|e| anyhow!("Tokenization failed: {}", e))
    }

    pub fn encode_batch(&self, texts: &[String]) -> Result<Vec<Encoding>> {
        let truncated: Vec<&str> = texts
            .iter()
            .map(|s| {
                if s.len() > MAX_TOKENIZE_LENGTH {
                    &s[..MAX_TOKENIZE_LENGTH]
                } else {
                    s.as_str()
                }
            })
            .collect();

        self.tokenizer
            .encode_batch(truncated, true)
            .map_err(|e| anyhow!("Batch tokenization failed: {}", e))
    }
}
```

**Unit tests:**
- Tokenize string of 100,000 chars (should truncate to 10,000).
- Deterministic output for same input.
- Max length handling and padding.

---

### 6) ONNX Embedding Backend - With Timeout

**Core functionality:**
- Add `onnxruntime` dependency (feature-gated under `ml-graph`).
- Load embedding model once per run (store in `GraphModelRunner`).
- Implement pooling: `cls` (first token) and `mean` (average with mask).
- Batching to reduce overhead.

**Security enhancements:**

```rust
pub struct OnnxEmbedder {
    session: ort::Session,
    max_batch_size: usize,
    timeout: Duration,
    pooling: PoolingStrategy,
}

impl OnnxEmbedder {
    pub fn new(
        model_path: &Path,
        pooling: PoolingStrategy,
        max_batch_size: usize,
        timeout_ms: u64,
    ) -> Result<Self> {
        let session = ort::Session::builder()?
            .with_optimization_level(ort::GraphOptimizationLevel::Level3)?
            .with_intra_threads(4)?  // Limit parallelism
            .with_model_from_file(model_path)?;

        Ok(Self {
            session,
            max_batch_size,
            timeout: Duration::from_millis(timeout_ms),
            pooling,
        })
    }

    pub fn embed_ir_objects(&self, texts: &[String]) -> Result<Vec<Vec<f32>>> {
        // Enforce batch size limit
        if texts.len() > self.max_batch_size {
            return Err(anyhow!(
                "Batch size {} exceeds limit {}",
                texts.len(),
                self.max_batch_size
            ));
        }

        let start = Instant::now();

        // Prepare inputs (tokenized tensors)
        let inputs = self.prepare_inputs(texts)?;

        // Run inference with timeout check
        let outputs = self.session.run(inputs)?;

        if start.elapsed() > self.timeout {
            return Err(anyhow!(
                "Embedding timeout exceeded: {}ms",
                start.elapsed().as_millis()
            ));
        }

        // Apply pooling
        let embeddings = self.apply_pooling(&outputs)?;

        Ok(embeddings)
    }

    fn apply_pooling(&self, outputs: &ort::SessionOutputs) -> Result<Vec<Vec<f32>>> {
        match self.pooling {
            PoolingStrategy::Cls => {
                // Take first token embedding
                extract_cls_embeddings(outputs)
            }
            PoolingStrategy::Mean => {
                // Average all token embeddings with attention mask
                extract_mean_embeddings(outputs)
            }
        }
    }
}
```

**Batching strategy:**
```rust
pub fn embed_all_objects(
    embedder: &OnnxEmbedder,
    normalized_irs: Vec<String>,
) -> Result<Vec<Vec<f32>>> {
    let mut all_embeddings = Vec::new();

    // Process in batches
    for batch in normalized_irs.chunks(embedder.max_batch_size) {
        let batch_embeddings = embedder.embed_ir_objects(batch)?;
        all_embeddings.extend(batch_embeddings);
    }

    Ok(all_embeddings)
}
```

**Unit tests:**
- Batch size 33 (should error with max 32).
- Timeout enforcement with slow mock model.
- CLS vs Mean pooling correctness.

---

### 7) ONNX GNN Backend - With Size Validation

**Core functionality:**
- Load GNN model (`graph.onnx`) once per run.
- Input signature: `node_features [N, D]`, `edge_index [2, E]`, optional `node_mask`.
- Output: single score or logit with optional sigmoid.

**Security enhancements:**

```rust
pub struct OnnxGnn {
    session: ort::Session,
    timeout: Duration,
    apply_sigmoid: bool,
}

impl OnnxGnn {
    pub fn new(
        model_path: &Path,
        apply_sigmoid: bool,
        timeout_ms: u64,
    ) -> Result<Self> {
        let session = ort::Session::builder()?
            .with_optimization_level(ort::GraphOptimizationLevel::Level3)?
            .with_intra_threads(4)?
            .with_model_from_file(model_path)?;

        Ok(Self {
            session,
            timeout: Duration::from_millis(timeout_ms),
            apply_sigmoid,
        })
    }

    pub fn infer(
        &self,
        node_features: &[Vec<f32>],
        edge_index: &[(usize, usize)],
    ) -> Result<f32> {
        let start = Instant::now();

        // Validate inputs
        self.validate_inputs(node_features, edge_index)?;

        // Prepare tensors
        let inputs = self.prepare_graph_inputs(node_features, edge_index)?;

        // Run inference
        let outputs = self.session.run(inputs)?;

        if start.elapsed() > self.timeout {
            return Err(anyhow!(
                "GNN inference timeout exceeded: {}ms",
                start.elapsed().as_millis()
            ));
        }

        // Extract score
        let mut score = extract_score(&outputs)?;

        if self.apply_sigmoid {
            score = 1.0 / (1.0 + (-score).exp());
        }

        Ok(score)
    }

    fn validate_inputs(
        &self,
        node_features: &[Vec<f32>],
        edge_index: &[(usize, usize)],
    ) -> Result<()> {
        let num_nodes = node_features.len();

        // Check for empty graph
        if num_nodes == 0 {
            return Err(anyhow!("Empty graph: no nodes"));
        }

        // Validate edge indices are within bounds
        for (from, to) in edge_index {
            if *from >= num_nodes || *to >= num_nodes {
                return Err(anyhow!(
                    "Edge index out of bounds: ({}, {}) with {} nodes",
                    from, to, num_nodes
                ));
            }
        }

        // Validate all node features have same dimension
        let expected_dim = node_features[0].len();
        for (i, feat) in node_features.iter().enumerate() {
            if feat.len() != expected_dim {
                return Err(anyhow!(
                    "Node {} feature dim {} != expected {}",
                    i, feat.len(), expected_dim
                ));
            }
        }

        Ok(())
    }

    fn prepare_graph_inputs(
        &self,
        node_features: &[Vec<f32>],
        edge_index: &[(usize, usize)],
    ) -> Result<ort::SessionInputs> {
        let num_nodes = node_features.len();
        let num_edges = edge_index.len();
        let feat_dim = node_features[0].len();

        // Flatten node features to [N, D] tensor
        let mut features_flat = Vec::with_capacity(num_nodes * feat_dim);
        for feat in node_features {
            features_flat.extend_from_slice(feat);
        }

        // Build edge_index [2, E] tensor with overflow check
        let edge_count_doubled = num_edges.checked_mul(2)
            .ok_or_else(|| anyhow!("Edge count overflow"))?;

        let mut edges_flat = Vec::with_capacity(edge_count_doubled);
        for (from, to) in edge_index {
            edges_flat.push(*from as i64);
            edges_flat.push(*to as i64);
        }

        // Create ONNX tensors
        let node_features_tensor = ort::Value::from_array(
            ([num_nodes, feat_dim], features_flat.as_slice())
        )?;

        let edge_index_tensor = ort::Value::from_array(
            ([2, num_edges], edges_flat.as_slice())
        )?;

        Ok(ort::SessionInputs::new()
            .with_value("node_features", node_features_tensor)?
            .with_value("edge_index", edge_index_tensor)?)
    }
}
```

**Overflow checks:**
```rust
// When computing tensor sizes:
let total_elements = num_nodes.checked_mul(feat_dim)
    .ok_or_else(|| anyhow!("Tensor size overflow: {} * {}", num_nodes, feat_dim))?;

let size_bytes = total_elements.checked_mul(std::mem::size_of::<f32>())
    .ok_or_else(|| anyhow!("Memory size overflow"))?;

if size_bytes > MAX_GRAPH_MEMORY_BYTES {
    return Err(anyhow!("Graph requires {} MB (limit {} MB)",
        size_bytes / 1_000_000,
        MAX_GRAPH_MEMORY_BYTES / 1_000_000));
}
```

---

### 8) Adversarial Detection - OOD and Evasion Markers

**Out-of-Distribution (OOD) Detection:**

```rust
pub struct OodDetector {
    threshold: f32,
}

impl OodDetector {
    pub fn detect(
        &self,
        normalized_irs: &[String],
        node_features: &[Vec<f32>],
        org: &OrgGraph,
    ) -> OodResult {
        // Compute multiple anomaly signals
        let feature_entropy = compute_feature_entropy(normalized_irs);
        let embedding_variance = compute_embedding_variance(node_features);
        let graph_complexity = compute_graph_complexity(org);

        // Combined OOD score
        let ood_score = (feature_entropy + embedding_variance + graph_complexity) / 3.0;

        OodResult {
            is_ood: ood_score > self.threshold,
            ood_score,
            feature_entropy,
            embedding_variance,
            graph_complexity: GraphComplexity {
                node_count: org.nodes.len(),
                edge_count: org.edges.len(),
                avg_degree: org.avg_degree,
                max_depth: org.max_depth,
                has_cycles: org.has_cycles,
                normalized_features_entropy: feature_entropy,
            },
        }
    }
}

fn compute_embedding_variance(embeddings: &[Vec<f32>]) -> f32 {
    // Low variance across all embeddings = potential adversarial attack
    // (all objects look identical after embedding)

    if embeddings.is_empty() {
        return 0.0;
    }

    let dim = embeddings[0].len();
    let mut variances = Vec::new();

    for d in 0..dim {
        let values: Vec<f32> = embeddings.iter().map(|e| e[d]).collect();
        let mean = values.iter().sum::<f32>() / values.len() as f32;
        let variance = values.iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f32>() / values.len() as f32;
        variances.push(variance);
    }

    variances.iter().sum::<f32>() / dim as f32
}
```

**Evasion Detection:**

```rust
pub fn detect_evasion_attempt(
    irs: &[IrObject],
    ml_score: f32,
    threshold: f32,
    deviation_threshold: usize,
) -> Option<Finding> {
    let total_deviations: usize = irs.iter().map(|ir| ir.deviations.len()).sum();

    // High deviations + low ML score = potential evasion
    if total_deviations > deviation_threshold && ml_score < threshold {
        Some(Finding {
            id: String::new(),
            surface: AttackSurface::FileStructure,
            kind: "ml_graph_evasion_attempt".into(),
            severity: Severity::High,
            confidence: Confidence::Probable,
            title: "Potential ML Evasion Attempt Detected".into(),
            description: format!(
                "PDF has {} parser deviations but ML graph score {} is below threshold {}. \
                 This pattern suggests adversarial manipulation to evade detection.",
                total_deviations, ml_score, threshold
            ),
            objects: vec!["ml_pipeline".into()],
            evidence: vec![],
            remediation: Some("Manual review recommended. PDF may be crafted to evade ML detection.".into()),
            meta: {
                let mut meta = HashMap::new();
                meta.insert("ml.deviations".into(), total_deviations.to_string());
                meta.insert("ml.score".into(), ml_score.to_string());
                meta.insert("ml.threshold".into(), threshold.to_string());
                meta
            },
            yara: None,
        })
    } else {
        None
    }
}
```

---

### 9) Inference Wiring in `sis-pdf-core` - Full Pipeline

```rust
pub fn run_graph_ml_inference(
    ctx: &ScanContext,
    config: &ModelConfig,
) -> Result<MlGraphResult> {
    eprintln!("Building object graph IR...");

    // 1) Build IR and ORG
    let ir_options = IrOptions::from_config(config);
    let irs: Vec<IrObject> = ctx.graph.objects.iter()
        .map(|obj| generate_ir(obj, &ir_options))
        .collect::<Result<Vec<_>>>()?;

    let org_options = OrgBuildOptions::from_config(config);
    let org = OrgGraph::from_object_graph(&ctx.graph.objects, &org_options)?;

    eprintln!("Generated {} IR objects, {} ORG nodes, {} edges",
        irs.len(), org.nodes.len(), org.edges.len());

    // 2) Validate graph size before ML
    validate_graph_size(&org, &config.limits)?;

    // 3) Normalize IR strings
    let normalize_options = NormalizeOptions::from_config(&config.embedding.normalize);
    let normalized_irs: Vec<String> = irs.iter()
        .map(|ir| normalize_ir_text(ir, &normalize_options))
        .collect();

    // 4) Tokenize and embed
    eprintln!("Embedding {} objects...", normalized_irs.len());
    let tokenizer = TokenizerWrapper::from_config(
        &config.embedding.tokenizer_path,
        config.embedding.max_length,
    )?;

    let embedder = OnnxEmbedder::new(
        &config.embedding.model_path,
        config.embedding.pooling,
        config.limits.max_embedding_batch_size,
        config.limits.embedding_timeout_ms,
    )?;

    let node_features = embed_all_objects(&embedder, normalized_irs.clone())?;

    // 5) Build edge_index
    let edge_index = org.edge_index();

    // 6) Run GNN
    eprintln!("Running GNN inference...");
    let gnn = OnnxGnn::new(
        &config.graph.model_path,
        config.graph.output.apply_sigmoid,
        config.limits.inference_timeout_ms,
    )?;

    let score = gnn.infer(&node_features, &edge_index)?;

    // 7) Adversarial detection
    let ood_detector = OodDetector::new(config.adversarial.ood_threshold);
    let ood_result = ood_detector.detect(&normalized_irs, &node_features, &org);

    let evasion_finding = if config.adversarial.enable_evasion_detection {
        detect_evasion_attempt(
            &irs,
            score,
            config.threshold,
            config.adversarial.evasion_deviation_threshold,
        )
    } else {
        None
    };

    eprintln!("ML Graph Score: {:.4} (threshold: {:.2})", score, config.threshold);
    if ood_result.is_ood {
        eprintln!("⚠ OOD detected: score {:.4}", ood_result.ood_score);
    }

    Ok(MlGraphResult {
        score,
        threshold: config.threshold,
        label: if score >= config.threshold { "malicious" } else { "benign" }.into(),
        confidence: Some(score),
        ood_result: Some(ood_result),
        evasion_finding,
        graph_complexity: GraphComplexity::from_org(&org, ood_result.feature_entropy),
        model_version: config.version.clone(),
    })
}
```

**Emit findings:**
```rust
let mut findings = Vec::new();

// High score finding
if ml_result.score >= ml_result.threshold {
    findings.push(Finding {
        kind: "ml_graph_score_high".into(),
        severity: Severity::High,
        title: "ML Graph Model: High Malicious Score".into(),
        description: format!(
            "Graph neural network assigned score {:.4} (threshold {:.2})",
            ml_result.score, ml_result.threshold
        ),
        meta: ml_result.to_meta_map(),
        // ...
    });
}

// OOD finding
if let Some(ood) = &ml_result.ood_result {
    if ood.is_ood {
        findings.push(Finding {
            kind: "ml_graph_ood".into(),
            severity: Severity::Medium,
            title: "ML Graph Model: Out-of-Distribution Input".into(),
            description: format!(
                "PDF exhibits anomalous structure (OOD score {:.4}). \
                 Model predictions may be unreliable.",
                ood.ood_score
            ),
            // ...
        });
    }
}

// Evasion finding
if let Some(evasion) = ml_result.evasion_finding {
    findings.push(evasion);
}
```

---

### 10) CLI and Ergonomics - Progress & Errors

**CLI flags (proposed UX):**
```bash
sis scan file.pdf --ml --ml-mode graph --ml-model-dir models

# Additional options:
--ml-graph-max-nodes 5000        # Override default 10k
--ml-graph-timeout 60000          # 60 sec timeout
--ml-graph-no-integrity           # Skip integrity checks (not recommended)
```

**Progress reporting:**
```rust
fn run_scan_with_progress(path: &Path, options: &ScanOptions) -> Result<Report> {
    eprintln!("Scanning: {}", path.display());

    // File size check
    let size = fs::metadata(path)?.len();
    eprintln!("File size: {} MB", size / 1_000_000);

    // Parsing
    eprintln!("Parsing PDF...");
    let graph = parse_pdf(bytes, parse_options)?;
    eprintln!("Parsed {} objects", graph.objects.len());

    // ML pipeline
    if options.ml && options.ml_mode == MlMode::Graph {
        eprintln!("\nML Graph Pipeline:");
        eprintln!("├─ Building IR...");
        // ... IR generation
        eprintln!("├─ Building ORG ({} nodes, {} edges)...", nodes, edges);
        // ... ORG construction
        eprintln!("├─ Normalizing IR...");
        // ... normalization
        eprintln!("├─ Embedding objects (batches: {})...", batches);
        // ... embedding
        eprintln!("└─ Running GNN inference...");
        // ... GNN
        eprintln!("\n✓ ML inference complete: score {:.4}", score);
    }

    Ok(report)
}
```

**Error messages:**
```rust
// Missing model dir
"Error: ML model directory not found: models/

  Graph ML requires a complete model package:
  - graph_model.json (configuration)
  - embedding.onnx (text encoder)
  - graph.onnx (GNN model)
  - tokenizer.json (tokenizer)

  Run `sis --help` for model packaging instructions."

// Invalid config
"Error: Invalid graph_model.json: missing field `embedding.output_dim`

  Expected schema version 1. See docs/graph-model-schema.md."

// Integrity failure
"Error: Integrity check failed for embedding.onnx
  Expected SHA256: abc123...
  Actual SHA256:   def456...

  Model may be corrupted or tampered. Re-download from trusted source."

// Graph too large
"Error: Graph too large: 15,000 nodes (max 10,000)

  This PDF exceeds safety limits for graph ML inference.
  Options:
  - Use --ml-graph-max-nodes 15000 to override (not recommended)
  - Use --ml-mode feature for traditional ML (no graph)
  - Analyze with --ir flag for structural analysis without ML"

// Timeout
"Error: GNN inference timeout exceeded: 35,000ms (limit 30,000ms)

  This PDF's graph is too complex for real-time analysis.
  Consider increasing timeout with --ml-graph-timeout 60000"
```

**Export commands (proposed UX for normalized IR):**
```bash
# Export IR for debugging
sis export-ir file.pdf --format json -o ir.json
sis export-ir file.pdf --format text -o ir.txt

# Export ORG
sis export-org file.pdf --format json -o org.json
sis export-org file.pdf --format dot -o org.dot
dot -Tpng org.dot -o org.png  # Visualize with Graphviz

# Export normalized IR (requires --ml) - proposed UX
sis export-ir file.pdf --ml --normalized -o ir_normalized.txt
```

---

### 11) Reporting and UX - Extended Summaries

**ML Summary in JSON:**
```json
{
  "ml_summary": {
    "graph": {
      "score": 0.9234,
      "threshold": 0.9,
      "label": "malicious",
      "confidence": 0.9234,
      "model_version": "1.0.0",
      "inference_time_ms": 1234,
      "ood": {
        "is_ood": false,
        "ood_score": 0.65,
        "feature_entropy": 4.2,
        "embedding_variance": 0.35
      },
      "graph_complexity": {
        "node_count": 1234,
        "edge_count": 5678,
        "avg_degree": 4.6,
        "max_depth": 12,
        "has_cycles": true,
        "normalized_features_entropy": 4.2
      }
    }
  },
  "structural_summary": {
    "ir": {
      "total_objects": 1234,
      "total_lines": 45678,
      "avg_lines_per_object": 37,
      "max_nesting_depth": 8,
      "total_deviations": 12
    },
    "org": {
      "nodes": 1234,
      "edges": 5678,
      "has_cycles": true,
      "max_depth": 12,
      "avg_degree": 4.6
    }
  }
}
```

**Markdown report:**
```markdown
## ML Graph Analysis

**Score:** 0.9234 (threshold: 0.90)
**Label:** malicious
**Model:** pdfobj2vec_gin_v1 (v1.0.0)
**Inference Time:** 1.2s

### Graph Structure
- **Nodes:** 1,234 objects
- **Edges:** 5,678 references
- **Average Degree:** 4.6
- **Max Depth:** 12
- **Contains Cycles:** Yes

### Anomaly Detection
- **OOD Score:** 0.65 (normal)
- **Feature Entropy:** 4.2
- **Embedding Variance:** 0.35

### Findings
- [HIGH] ML Graph Model: High Malicious Score (0.9234)
```

---

### 12) Testing and Validation - Comprehensive Suite

**IR/ORG Tests:**
```rust
#[test]
fn test_ir_nesting_depth_limit() {
    let pdf = create_deeply_nested_pdf(50); // 50 levels deep
    let ir = generate_ir(&pdf, &IrOptions { max_nesting_depth: 32, .. });

    assert!(ir.lines.iter().any(|l| l.contains("TRUNCATED_DEPTH")));
    assert_eq!(ir.nesting_depth, 32);
}

#[test]
fn test_org_cycle_detection() {
    let pdf = create_cyclic_pdf(); // A → B → C → A
    let org = OrgGraph::from_object_graph(&pdf.objects, &default_options());

    assert!(org.has_cycles);
}

#[test]
fn test_org_size_limit() {
    let pdf = create_large_pdf(15_000); // 15k objects
    let result = OrgGraph::from_object_graph(
        &pdf.objects,
        &OrgBuildOptions { max_nodes: 10_000, .. }
    );

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("node limit exceeded"));
}
```

**Normalization Tests:**
```rust
#[test]
fn test_normalize_preserves_keywords() {
    let ir = IrObject {
        lines: vec!["/JavaScript (malicious_code)".into()],
        deviations: vec![],
        ..
    };

    let normalized = normalize_ir_text(&ir, &NormalizeOptions {
        preserve_keywords: vec!["/JavaScript".into()],
        normalize_strings: true,
        ..
    });

    assert!(normalized.contains("/JavaScript"));
    assert!(normalized.contains("str:HASH"));
}

#[test]
fn test_normalize_collision_detection() {
    let irs: Vec<String> = (0..100).map(|_| "dict /Type /Font".into()).collect();
    let entropy = compute_feature_entropy(&irs);

    assert!(entropy < 1.0); // Low entropy = all identical
}
```

**Tokenizer Tests:**
```rust
#[test]
fn test_tokenize_long_string() {
    let tokenizer = TokenizerWrapper::new("tokenizer.json", 512)?;
    let long_string = "A".repeat(100_000);

    let encoding = tokenizer.encode(&long_string)?;

    // Should be truncated to 10k chars before tokenization
    assert!(encoding.get_ids().len() <= 512);
}

#[test]
fn test_tokenize_deterministic() {
    let tokenizer = TokenizerWrapper::new("tokenizer.json", 512)?;
    let text = "Test string";

    let enc1 = tokenizer.encode(text)?;
    let enc2 = tokenizer.encode(text)?;

    assert_eq!(enc1.get_ids(), enc2.get_ids());
}
```

**ONNX Tests:**
```rust
#[test]
fn test_embedding_timeout() {
    // Use a mock slow model or sleep in test
    let embedder = OnnxEmbedder::new(
        "slow_model.onnx",
        PoolingStrategy::Cls,
        32,
        100, // 100ms timeout
    )?;

    let result = embedder.embed_ir_objects(&vec!["test".into(); 1000]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("timeout"));
}

#[test]
fn test_gnn_edge_index_validation() {
    let gnn = OnnxGnn::new("graph.onnx", true, 30_000)?;

    let features = vec![vec![1.0; 768]; 100]; // 100 nodes
    let bad_edges = vec![(0, 200)]; // Edge to node 200 (out of bounds)

    let result = gnn.infer(&features, &bad_edges);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("out of bounds"));
}
```

**Adversarial Tests:**
```rust
#[test]
fn test_ood_detection() {
    let detector = OodDetector::new(0.8);

    // All objects normalize to same string
    let normalized_irs = vec!["dict /Type /Font".into(); 100];
    let features = vec![vec![1.0; 768]; 100];
    let org = OrgGraph::simple(100, 0);

    let result = detector.detect(&normalized_irs, &features, &org);

    assert!(result.is_ood); // Low entropy should trigger OOD
}

#[test]
fn test_evasion_detection() {
    let irs = vec![
        IrObject {
            deviations: vec!["unterminated_string".into(); 60],
            ..
        };
        10
    ];

    let finding = detect_evasion_attempt(&irs, 0.3, 0.9, 50);

    assert!(finding.is_some());
    assert_eq!(finding.unwrap().kind, "ml_graph_evasion_attempt");
}
```

**Integration Tests:**
```rust
#[test]
fn test_full_graph_ml_pipeline() {
    let pdf_path = "tests/data/malicious_sample.pdf";
    let model_dir = "tests/models/dummy";

    let result = run_scan_with_ml(pdf_path, model_dir, &ScanOptions {
        ml: true,
        ml_mode: MlMode::Graph,
        ..
    })?;

    assert!(result.ml_summary.is_some());
    let ml = result.ml_summary.unwrap().graph.unwrap();
    assert!(ml.score >= 0.0 && ml.score <= 1.0);
    assert_eq!(ml.model_version, "1.0.0");
}
```

**Supply Chain Tests:**
```rust
#[test]
fn test_reject_invalid_sha256() {
    let config = ModelConfig {
        integrity: Some(IntegrityChecks {
            embedding_sha256: Some("invalid_hash".into()),
            ..
        }),
        ..
    };

    let result = config.load_and_validate(&PathBuf::from("models"));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Integrity check failed"));
}

#[test]
fn test_reject_banned_onnx_ops() {
    let model_with_exec = create_onnx_model_with_op("Exec");
    write_temp_model(&model_with_exec, "bad_model.onnx");

    let result = validate_onnx_safety(Path::new("bad_model.onnx"));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Unsafe ONNX op: Exec"));
}

#[test]
fn test_reject_path_traversal() {
    let config = ModelConfig {
        embedding: EmbeddingConfig {
            model_path: "../../../etc/passwd".into(),
            ..
        },
        ..
    };

    let result = config.load_and_validate(&PathBuf::from("models"));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Invalid model path"));
}
```

---

## Updated `graph_model.json` Schema

Short summary:
- Required top-level fields: `schema_version`, `name`, `embedding`, `graph`, `threshold`, `edge_index`.
- `embedding.output_dim` must equal `graph.input_dim`.
- Paths are relative to `ml_model_dir` and must stay inside it.
- Optional sections: `integrity`, `adversarial`, `limits`.
- Full schema: `docs/graph-model-schema.md`.

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

---

## Packaging Requirements

**Required files in `ml_model_dir/`:**
- `graph_model.json` - Configuration with integrity hashes
- `embedding.onnx` - Text encoder model (BERT, RoBERTa, etc.)
- `graph.onnx` - GNN model (GIN, GAT, etc.)
- `tokenizer.json` - HuggingFace tokenizer (or `vocab.json` + `merges.txt`)

**Optional files:**
- `README.md` - Model documentation
- `LICENSE` - Model license
- `training_metadata.json` - Training stats, dataset info, etc.

**Integrity generation script:**
```bash
#!/bin/bash
# generate_checksums.sh

echo "Generating SHA256 checksums..."
sha256sum embedding.onnx | awk '{print $1}'
sha256sum graph.onnx | awk '{print $1}'
sha256sum tokenizer.json | awk '{print $1}'

echo ""
echo "Add these to graph_model.json under 'integrity' section"
```

---

## Operator Workflow Examples

**Standard scan with graph ML:**
```bash
# Build with ML support
cargo build --release --features ml-graph

# Run scan
sis scan suspicious.pdf \
  --ml \
  --ml-mode graph \
  --ml-model-dir ./models/pdfobj2vec_v1 \
  -o report.json

# View results
cat report.json | jq '.ml_summary.graph'
```

**Export IR/ORG for debugging:**
```bash
# Export IR (raw and normalized)
sis export-ir suspicious.pdf --format json -o ir.json
sis export-ir suspicious.pdf --ml --normalized -o ir_normalized.txt

# Export ORG
sis export-org suspicious.pdf --format dot -o org.dot
dot -Tpng org.dot -o org.png

# Visualize graph
open org.png
```

**Batch processing with resource limits:**
```bash
# Scan directory with custom limits
sis scan --path ./malware_samples \
  --ml --ml-mode graph \
  --ml-model-dir ./models \
  --ml-graph-max-nodes 5000 \
  --ml-graph-timeout 60000 \
  --output-format jsonl \
  -o results.jsonl

# Extract high-scoring samples
cat results.jsonl | jq 'select(.ml_summary.graph.score > 0.95) | .input_path'
```

**Verify model integrity (proposed UX):**
```bash
# Check model files
cd models/pdfobj2vec_v1
sha256sum -c <<EOF
a1b2c3d4... embedding.onnx
f6e5d4c3... graph.onnx
12345678... tokenizer.json
EOF

# Validate config (proposed UX)
sis validate-ml-config ./models/pdfobj2vec_v1
```

---

## Milestones

### Milestone 1: IR/ORG Foundation (2-3 weeks)
- [ ] IR extraction with security hardening
- [ ] Path sanitization and nesting limits
- [ ] Deviation tracking for malformed PDFs
- [ ] ORG construction with cycle detection
- [ ] Size validation and sampling
- [ ] Unit tests for all edge cases

### Milestone 2: Model Config & Security (1-2 weeks)
- [ ] `graph_model.json` schema implementation
- [ ] Path validation and integrity checks
- [ ] ONNX safety validation (banned ops)
- [ ] Clear error messages
- [ ] Integration tests

### Milestone 3: Tokenizer & Embedding (2 weeks)
- [ ] Tokenizer integration with truncation
- [ ] ONNX embedding backend
- [ ] Pooling strategies (cls, mean)
- [ ] Batching and timeout enforcement
- [ ] Resource limit tests

### Milestone 4: GNN Backend (2 weeks)
- [ ] ONNX GNN runtime
- [ ] Graph input assembly with overflow checks
- [ ] Size validation and timeout
- [ ] Edge index validation
- [ ] Performance benchmarks

### Milestone 5: Adversarial Detection (1-2 weeks)
- [ ] IR normalization with keyword preservation
- [ ] OOD detection implementation
- [ ] Evasion detection logic
- [ ] Entropy and variance metrics
- [ ] Adversarial test suite

### Milestone 6: Integration & UX (1-2 weeks)
- [ ] Full inference pipeline wiring
- [ ] Progress reporting
- [ ] Export commands (IR, ORG)
- [ ] Report formatting (JSON, Markdown, SARIF)
- [ ] Integration tests with real models

### Milestone 7: Documentation & Hardening (1 week)
- [ ] Operator documentation
- [ ] Model packaging guide
- [ ] Security best practices
- [ ] Performance tuning guide
- [ ] Final security review alignment

**Total Estimated Time:** 10-14 weeks

---

## Security Review Alignment

This plan addresses prior security review findings:

### CRIT-2: Cascading Object Stream Decompression Bomb
✅ **Addressed:** Pre-check ORG size before GNN inference; budget reservation for embeddings; hard limits on nodes/edges.

### CRIT-3: Integer Overflow in Size Calculations
✅ **Addressed:** Checked arithmetic throughout (edge_index computation, tensor sizes, memory calculations).

### HIGH-1: Parser Differential Attacks Enable Evasion
✅ **Addressed:** Deviation markers included in IR; evasion detector flags high-deviation + low-score patterns.

### HIGH-4: Resource Limit Check Timing Vulnerabilities
✅ **Addressed:** Pre-validation of all resource limits before expensive operations (tokenization, embedding, GNN).

### MED-1: Cache Poisoning via Hash Collision
✅ **Addressed:** Model integrity via SHA256; strict path validation; canonicalization checks.

### Additional Hardening
✅ Path sanitization, ONNX safety validation, timeout enforcement, OOD detection, adversarial test coverage.

---

## Performance Considerations

**Expected Inference Times (CPU):**
- IR extraction: <100ms for typical PDF (1-2k objects)
- ORG construction: <50ms
- Tokenization: ~10ms per batch (32 objects)
- Embedding: ~500ms per batch (768-dim BERT)
- GNN inference: ~200ms for 1k nodes, 5k edges

**Total per-file:** ~2-5 seconds for typical malicious PDF
**Batch throughput:** ~10-20 files/minute on 8-core CPU

**Optimization opportunities:**
- GPU acceleration for embedding/GNN (if available)
- Caching embeddings for repeated objects
- Larger batches on high-memory systems
- Parallel file processing

---

## Conclusion

This updated plan provides a **production-ready, security-hardened** implementation of graph ML inference for sis-pdf. Key enhancements:

1. **Resource limits** enforced at every stage
2. **Supply chain security** via integrity checks and ONNX validation
3. **Adversarial ML robustness** through OOD detection and evasion markers
4. **Comprehensive testing** including adversarial test cases
5. **Clear operator UX** with progress reporting and helpful errors
6. **Full alignment** with existing security review findings

The architecture is modular, extensible, and designed for real-world deployment in adversarial environments.
