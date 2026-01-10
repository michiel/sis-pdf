# ML Signal Enhancement Plan

## Overview

This plan extends the current ML implementation (which uses IR/ORG for graph-based learning and a small feature vector for traditional ML) to incorporate **all statically collected signals** from sis-pdf's 50+ detectors. The goal is to create a richer, more comprehensive dataset for both training and inference.

## Current State

### Existing ML Modes

#### 1. Traditional ML (Feature Vector)
**Location**: `crates/sis-pdf-core/src/features.rs`

**Current Features** (20 dimensions):
```rust
GeneralFeatures {
    file_size, file_entropy, binary_ratio, object_count
}

StructuralFeatures {
    startxref_count, trailer_count, objstm_count,
    linearized_present, max_object_id
}

BehavioralFeatures {
    action_count, js_object_count, js_entropy_avg,
    js_eval_count, js_suspicious_api_count,
    time_api_count, env_probe_count
}

ContentFeatures {
    embedded_file_count, rich_media_count,
    annotation_count, page_count
}
```

**Limitations**:
- Only 20 features, very coarse-grained
- Missing signals from 50+ detectors
- No severity/confidence information
- No metadata from findings
- No fine-grained detection signals

#### 2. Graph ML (IR/ORG)
**Location**: `crates/sis-pdf-pdf/src/ir.rs`, `crates/sis-pdf-core/src/ir_pipeline.rs`

**Current Approach**:
- IR (Intermediate Representation): Textual representation of PDF objects
- ORG (Object Reference Graph): Graph edges between objects
- Embedding model: Text encoder (BERT/CodeT5) → node embeddings
- GNN model: Graph classifier on object graph

**Limitations**:
- IR is purely structural (dict keys, array lengths, stream metadata)
- Does not include detector findings or semantic signals
- No behavioral analysis signals (JS patterns, evasion techniques)
- No content analysis signals (phishing, obfuscation, URI analysis)
- No attack surface categorization

## Available Static Signals

### Detector Inventory (70+ Finding Types)

Based on analysis of `crates/sis-pdf-detectors/src/`:

#### File Structure (10 signals)
- `xref_conflict` - Multiple conflicting xref tables
- `incremental_update_chain` - Document revision chain
- `object_id_shadowing` - Duplicate object IDs across revisions
- `polyglot_signature_conflict` - File header conflicts
- `missing_pdf_header` - No %PDF header
- `missing_eof_marker` - No %%EOF marker
- `eof_offset_unusual` - Suspicious EOF placement
- `header_offset_unusual` - Non-standard header offset
- `linearization_invalid` - Broken linearization
- `linearization_multiple` - Multiple linearization dicts

#### Object Streams (5 signals)
- `objstm_density_high` - High object stream usage
- `objstm_embedded_summary` - Object stream nesting
- `objstm_action_chain` - Actions hidden in ObjStm
- `orphan_payload_object` - Unreferenced objects
- `shadow_payload_chain` - Shadowed object chains

#### Stream/Filter Analysis (6 signals)
- `decoder_risk_present` - JBIG2/JPX decoders
- `decompression_ratio_suspicious` - Decompression bombs
- `filter_chain_depth_high` - Deep filter nesting
- `huge_image_dimensions` - Oversized images
- `stream_length_mismatch` - Stream length inconsistencies
- `icc_profile_oversized` - Large ICC profiles

#### Actions (8 signals)
- `open_action_present` - Document OpenAction
- `aa_present` - Additional Actions present
- `aa_event_present` - Specific AA event triggers
- `launch_action_present` - Launch actions
- `gotor_present` - GoToR actions
- `uri_present` - URI actions (legacy)
- `submitform_present` - Form submission
- `external_action_risk_context` - High-risk action context

#### JavaScript (10 signals)
- `js_present` - JavaScript detected
- `js_polymorphic` - Polymorphic JS patterns
- `js_obfuscation_deep` - Deep obfuscation
- `js_time_evasion` - Time-based evasion
- `js_env_probe` - Environment fingerprinting
- `js_multi_stage_decode` - Multi-stage deobfuscation
- `js_runtime_file_probe` - File system probing
- `js_runtime_network_intent` - Network requests
- `crypto_mining_js` - Cryptocurrency mining
- `js_sandbox_exec/timeout/skipped` - Sandbox results

#### URI Classification (3 signals)
- `uri_content_analysis` - Content/obfuscation analysis
- `uri_presence_summary` - Document-level URI stats
- `action_payload_path` - Action payload extraction

#### Forms (2 signals)
- `acroform_present` - AcroForm detected
- `xfa_present` - XFA forms

#### Embedded Content (7 signals)
- `embedded_file_present` - Embedded file streams
- `richmedia_present` - RichMedia content
- `3d_present` - 3D content (U3D/PRC)
- `sound_movie_present` - Audio/video
- `filespec_present` - File specifications
- `font_payload_present` - Font-based payloads
- `fontmatrix_payload_present` - FontMatrix exploits

#### Crypto/Signatures (5 signals)
- `encryption_present` - Encryption dictionary
- `signature_present` - Digital signatures
- `dss_present` - Document Security Store
- `crypto_weak_algo` - Weak cryptographic algorithms
- `quantum_vulnerable_crypto` - Quantum-vulnerable crypto

#### Content Analysis (6 signals)
- `content_phishing` - Phishing indicators
- `content_html_payload` - HTML in content streams
- `content_invisible_text` - Hidden text layers
- `content_overlay_link` - Overlapping links
- `content_image_only_page` - Image-only pages
- `annotation_hidden` - Hidden annotations

#### Annotations (3 signals)
- `annotation_action_chain` - Annotation action chains
- `annotation_attack` - Annotation-based attacks
- `ocg_present` - Optional content groups

#### Page Tree (3 signals)
- `page_tree_cycle` - Circular page references
- `page_tree_mismatch` - Page count mismatches
- `page_tree_manipulation` - Page tree anomalies

#### Supply Chain (3 signals)
- `supply_chain_persistence` - Persistence mechanisms
- `supply_chain_staged_payload` - Staged payloads
- `supply_chain_update_vector` - Update mechanisms

#### Advanced Attacks (5 signals)
- `multi_stage_attack_chain` - Multi-stage attacks
- `parser_deviation_cluster` - Parser confusion
- `parser_deviation_in_action_context` - Contextual deviations
- `strict_parse_deviation` - Strict parser deviations
- `icc_profile_anomaly` - ICC profile anomalies

#### Font Exploits (2 signals)
- `font_table_anomaly` - Font table anomalies
- Font encoding exploits

### Finding Metadata

Each finding includes rich metadata in `meta: HashMap<String, String>`:

#### JavaScript Findings
```rust
meta: {
    "payload_key": "/JS",
    "payload.type": "stream",
    "payload.decoded_len": "1234",
    "payload.ref_chain": "5 0 R -> 10 0 R",
    "js.stream.filters": "FlateDecode",
    "js.decode_ratio": "12.34",
    "js.obfuscation_score": "0.85",
    "js.eval_count": "3",
    "js.suspicious_apis": "app.launchURL,this.exportDataObject",
    "js.string_concat_layers": "4",
    "js.unescape_layers": "2",
    // ... 30+ more JS-specific fields
}
```

#### URI Findings
```rust
meta: {
    "uri.url": "http://example.com/...",
    "uri.scheme": "http",
    "uri.domain": "example.com",
    "uri.obfuscation": "heavy",
    "uri.risk_score": "180",
    "uri.is_ip": "true",
    "uri.suspicious_tld": "true",
    "uri.data_exfil_pattern": "true",
    "uri.visibility": "hidden_rect",
    "uri.trigger": "javascript",
    "uri.automatic": "true",
    "uri.js_involved": "true",
    // ... 15+ more URI-specific fields
}
```

#### Embedded File Findings
```rust
meta: {
    "embedded.filename": "payload.exe",
    "embedded.sha256": "abc123...",
    "embedded.size": "524288",
    "embedded.magic": "pe",
    "embedded.encrypted_container": "true",
    "embedded.decode_ratio": "8.5",
    "embedded.double_extension": "true",
}
```

**Total Available Metadata Fields**: 200+ unique metadata keys across all detectors

### Finding Attributes

Every finding also includes:

```rust
Finding {
    surface: AttackSurface,      // 11 categories
    severity: Severity,           // Info/Low/Medium/High/Critical
    confidence: Confidence,       // Heuristic/Probable/Strong
    kind: String,                 // 70+ unique kinds
    objects: Vec<String>,         // Affected PDF objects
    evidence: Vec<EvidenceSpan>,  // Byte offsets
}
```

## Proposed Enhancement

### Extended Feature Vector (Traditional ML)

Expand from 20 features to **300+ features** organized into:

#### 1. Attack Surface Distributions (11 features)
Count of findings per attack surface:
- `surface.file_structure_count`
- `surface.xref_trailer_count`
- `surface.object_streams_count`
- `surface.streams_filters_count`
- `surface.actions_count`
- `surface.javascript_count`
- `surface.forms_count`
- `surface.embedded_files_count`
- `surface.richmedia_3d_count`
- `surface.crypto_signatures_count`
- `surface.metadata_count`

#### 2. Severity Distributions (15 features)
Count/max/mean severity per surface:
- `severity.total_high`
- `severity.total_medium`
- `severity.total_low`
- `severity.total_info`
- `severity.max_by_surface` (11 features)

#### 3. Confidence Distributions (9 features)
- `confidence.strong_count`
- `confidence.probable_count`
- `confidence.heuristic_count`
- Confidence scores per surface category

#### 4. Finding Type Presence (70 features - binary)
One-hot encoding for each finding type:
- `finding.xref_conflict_present`
- `finding.js_polymorphic_present`
- `finding.uri_content_analysis_present`
- ... (one per finding type)

#### 5. Finding Type Counts (70 features)
Count of each finding type:
- `finding.xref_conflict_count`
- `finding.js_polymorphic_count`
- ... (one per finding type)

#### 6. JavaScript-Specific Signals (30 features)
From JS detector metadata:
- `js.max_obfuscation_score`
- `js.total_eval_count`
- `js.unique_suspicious_apis`
- `js.max_string_concat_layers`
- `js.max_unescape_layers`
- `js.max_decode_ratio`
- `js.avg_entropy`
- `js.time_evasion_present`
- `js.env_probe_present`
- `js.polymorphic_present`
- `js.sandbox_executed`
- `js.sandbox_timeout`
- `js.runtime_file_probe`
- `js.runtime_network_intent`
- `js.crypto_mining_detected`
- ... (aggregated from JS metadata)

#### 7. URI-Specific Signals (20 features)
From URI classification metadata:
- `uri.total_count`
- `uri.unique_domains`
- `uri.max_risk_score`
- `uri.avg_risk_score`
- `uri.javascript_uri_count`
- `uri.file_uri_count`
- `uri.http_count`
- `uri.https_count`
- `uri.ip_address_count`
- `uri.suspicious_tld_count`
- `uri.obfuscated_count`
- `uri.data_exfil_pattern_count`
- `uri.hidden_annotation_count`
- `uri.automatic_trigger_count`
- `uri.js_triggered_count`
- `uri.tracking_params_count`
- ... (aggregated from URI metadata)

#### 8. Content Analysis Signals (15 features)
- `content.phishing_indicators`
- `content.invisible_text_pages`
- `content.overlay_link_count`
- `content.image_only_pages`
- `content.html_payload_present`
- `content.hidden_annotation_count`
- ... (from content detectors)

#### 9. Supply Chain Signals (10 features)
- `supply_chain.persistence_mechanisms`
- `supply_chain.staged_payload_count`
- `supply_chain.update_vectors`
- `supply_chain.multi_stage_chains`
- ... (from supply chain detectors)

#### 10. Structural Anomaly Signals (20 features)
- `structural.objstm_density`
- `structural.filter_chain_max_depth`
- `structural.decompression_max_ratio`
- `structural.page_tree_anomalies`
- `structural.linearization_anomalies`
- `structural.parser_deviations`
- ... (from structural detectors)

#### 11. Cryptographic Signals (10 features)
- `crypto.encryption_present`
- `crypto.signature_present`
- `crypto.weak_algo_count`
- `crypto.quantum_vulnerable`
- `crypto.cert_anomalies`
- ... (from crypto detectors)

#### 12. Embedded Content Signals (15 features)
- `embedded.file_count`
- `embedded.total_size`
- `embedded.max_decode_ratio`
- `embedded.pe_executable_count`
- `embedded.encrypted_container_count`
- `embedded.double_extension_count`
- `embedded.richmedia_count`
- `embedded.3d_content_count`
- ... (from embedded file detectors)

#### 13. Action Chain Signals (20 features)
- `actions.open_action_count`
- `actions.aa_event_count`
- `actions.launch_count`
- `actions.uri_count`
- `actions.submitform_count`
- `actions.automatic_trigger_count`
- `actions.js_involved_count`
- `actions.external_risk_context_count`
- `actions.max_chain_depth`
- ... (from action detectors)

#### 14. Annotation Signals (10 features)
- `annotations.total_count`
- `annotations.hidden_count`
- `annotations.action_chain_count`
- `annotations.attack_count`
- `annotations.uri_count`
- ... (from annotation detectors)

**Total Extended Feature Vector**: ~320 features

### Enhanced IR (Intermediate Representation)

Augment IR with detector findings to create **semantic IR**:

#### Current IR Format
```json
{
  "obj_ref": [5, 0],
  "lines": [
    {"path": "$.Type", "type": "name", "value": "/Action"},
    {"path": "$.S", "type": "name", "value": "/JavaScript"},
    {"path": "$", "type": "stream", "value": "len=1234 filters=FlateDecode"}
  ]
}
```

#### Enhanced IR Format
```json
{
  "obj_ref": [5, 0],
  "lines": [
    {"path": "$.Type", "type": "name", "value": "/Action"},
    {"path": "$.S", "type": "name", "value": "/JavaScript"},
    {"path": "$", "type": "stream", "value": "len=1234 filters=FlateDecode"}
  ],
  "findings": [
    {
      "kind": "js_polymorphic",
      "severity": "high",
      "confidence": "probable",
      "surface": "javascript",
      "signals": {
        "obfuscation_score": 0.85,
        "eval_count": 3,
        "string_concat_layers": 4,
        "suspicious_apis": ["app.launchURL", "this.exportDataObject"]
      }
    },
    {
      "kind": "js_time_evasion",
      "severity": "medium",
      "confidence": "probable",
      "surface": "javascript",
      "signals": {
        "delay_ms": 5000,
        "date_checks": 2
      }
    }
  ],
  "attack_surfaces": ["javascript", "actions"],
  "risk_score": 0.92
}
```

**Benefits**:
- Embedding model can learn semantic patterns from finding types
- Risk scores provide supervision signal
- Attack surfaces add categorization
- Signals provide fine-grained features

### Enhanced ORG (Object Reference Graph)

Add edge attributes and node features from findings:

#### Current ORG Format
```json
{
  "nodes": [
    {"obj": 1, "gen": 0},
    {"obj": 5, "gen": 0},
    {"obj": 10, "gen": 0}
  ],
  "edges": [
    {"src": 0, "dst": 1},
    {"src": 1, "dst": 2}
  ]
}
```

#### Enhanced ORG Format
```json
{
  "nodes": [
    {
      "obj": 1, "gen": 0,
      "type": "catalog",
      "has_findings": false,
      "attack_surfaces": []
    },
    {
      "obj": 5, "gen": 0,
      "type": "action",
      "has_findings": true,
      "attack_surfaces": ["javascript", "actions"],
      "max_severity": "high",
      "finding_count": 2,
      "risk_score": 0.92
    },
    {
      "obj": 10, "gen": 0,
      "type": "stream",
      "has_findings": false,
      "attack_surfaces": []
    }
  ],
  "edges": [
    {
      "src": 0, "dst": 1,
      "type": "reference",
      "key": "OpenAction",
      "suspicious": true
    },
    {
      "src": 1, "dst": 2,
      "type": "reference",
      "key": "JS",
      "suspicious": true
    }
  ]
}
```

**Benefits**:
- GNN can learn from node attributes (attack surface, risk score)
- Edge attributes indicate suspicious reference patterns
- Graph structure + semantic features = richer representation

### Finding Aggregation Features

Create document-level aggregated signals:

```json
{
  "document_risk_profile": {
    "total_findings": 15,
    "high_severity_count": 3,
    "attack_surface_diversity": 5,
    "max_confidence": "strong",

    "js_risk_profile": {
      "present": true,
      "obfuscation_max": 0.85,
      "evasion_techniques": ["time", "env"],
      "multi_stage": true,
      "sandbox_executed": true
    },

    "uri_risk_profile": {
      "total_uris": 8,
      "max_risk_score": 180,
      "suspicious_count": 2,
      "hidden_count": 1,
      "automatic_triggers": 1
    },

    "structural_risk_profile": {
      "objstm_density": 0.35,
      "incremental_updates": 3,
      "object_shadowing": true,
      "parser_deviations": 5
    },

    "supply_chain_risk_profile": {
      "persistence_present": true,
      "staged_payload": true,
      "multi_stage_chain": true
    }
  }
}
```

## Implementation Roadmap

### Phase 1: Extended Feature Vector for Traditional ML

**Goal**: Expand feature vector from 20 to 320+ dimensions

**Tasks**:
1. Create `ExtendedFeatureVector` struct in `features.rs`
2. Add feature extraction functions for each category
3. Implement metadata aggregation from findings
4. Add feature normalization/scaling
5. Update `as_f32_vec()` method
6. Create `extended_feature_names()` function

**Files to Modify**:
- `crates/sis-pdf-core/src/features.rs` - Core feature extraction
- `crates/sis-pdf-core/src/runner.rs` - Feature extraction pipeline
- `crates/sis-pdf-core/src/ml.rs` - Update ML interfaces

**New Functions**:
```rust
pub fn extract_extended_features(
    findings: &[Finding],
    graph: &ObjectGraph,
    bytes: &[u8],
) -> ExtendedFeatureVector

fn extract_attack_surface_features(findings: &[Finding]) -> AttackSurfaceFeatures
fn extract_severity_features(findings: &[Finding]) -> SeverityFeatures
fn extract_finding_type_features(findings: &[Finding]) -> FindingTypeFeatures
fn extract_js_features(findings: &[Finding]) -> JsFeatures
fn extract_uri_features(findings: &[Finding]) -> UriFeatures
fn extract_content_features(findings: &[Finding]) -> ContentFeatures
// ... more extraction functions
```

**Example**:
```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtendedFeatureVector {
    // Legacy features (20)
    pub legacy: FeatureVector,

    // New feature groups
    pub attack_surfaces: AttackSurfaceFeatures,      // 11
    pub severity_dist: SeverityFeatures,             // 15
    pub confidence_dist: ConfidenceFeatures,         // 9
    pub finding_presence: FindingPresenceFeatures,   // 70
    pub finding_counts: FindingCountFeatures,        // 70
    pub js_signals: JsSignalFeatures,                // 30
    pub uri_signals: UriSignalFeatures,              // 20
    pub content_signals: ContentSignalFeatures,      // 15
    pub supply_chain: SupplyChainFeatures,           // 10
    pub structural_anomalies: StructuralFeatures,    // 20
    pub crypto_signals: CryptoFeatures,              // 10
    pub embedded_content: EmbeddedContentFeatures,   // 15
    pub action_chains: ActionChainFeatures,          // 20
    pub annotations: AnnotationFeatures,             // 10
}

impl ExtendedFeatureVector {
    pub fn as_f32_vec(&self) -> Vec<f32> {
        let mut vec = self.legacy.as_f32_vec();
        vec.extend(self.attack_surfaces.as_f32_vec());
        vec.extend(self.severity_dist.as_f32_vec());
        // ... extend with all feature groups
        vec
    }
}
```

**Testing**:
- Unit tests for each feature extraction function
- Integration test with sample malicious/benign PDFs
- Validate feature vector dimensions
- Check for NaN/Inf values

### Phase 2: Enhanced IR with Finding Annotations

**Goal**: Augment IR with semantic information from findings

**Tasks**:
1. Modify `PdfIrObject` to include findings
2. Create finding-to-object mapping
3. Add attack surface annotations
4. Compute per-object risk scores
5. Export enhanced IR format

**Files to Modify**:
- `crates/sis-pdf-pdf/src/ir.rs` - IR data structures
- `crates/sis-pdf-core/src/ir_export.rs` - IR export
- `crates/sis-pdf-core/src/ir_pipeline.rs` - IR pipeline

**New Structures**:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedPdfIrObject {
    pub obj_ref: (u32, u16),
    pub lines: Vec<PdfIrLine>,
    pub deviations: Vec<String>,

    // New fields
    pub findings: Vec<IrFindingSummary>,
    pub attack_surfaces: Vec<AttackSurface>,
    pub max_severity: Option<Severity>,
    pub risk_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrFindingSummary {
    pub kind: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub surface: AttackSurface,
    pub signals: HashMap<String, serde_json::Value>,
}
```

**Implementation**:
```rust
pub fn enhanced_ir_for_object(
    entry: &ObjEntry<'_>,
    findings: &[Finding],
    opts: &IrOptions,
) -> EnhancedPdfIrObject {
    let basic_ir = ir_for_object(entry, opts);

    // Find all findings for this object
    let obj_str = format!("{} {} obj", entry.obj, entry.gen);
    let obj_findings: Vec<_> = findings.iter()
        .filter(|f| f.objects.contains(&obj_str))
        .collect();

    // Extract finding summaries
    let finding_summaries = obj_findings.iter()
        .map(|f| IrFindingSummary {
            kind: f.kind.clone(),
            severity: f.severity,
            confidence: f.confidence,
            surface: f.surface,
            signals: extract_signals_from_meta(&f.meta),
        })
        .collect();

    // Aggregate attack surfaces
    let attack_surfaces: HashSet<_> = obj_findings.iter()
        .map(|f| f.surface)
        .collect();

    // Compute max severity
    let max_severity = obj_findings.iter()
        .map(|f| f.severity)
        .max();

    // Compute risk score (0-1)
    let risk_score = compute_object_risk_score(&obj_findings);

    EnhancedPdfIrObject {
        obj_ref: basic_ir.obj_ref,
        lines: basic_ir.lines,
        deviations: basic_ir.deviations,
        findings: finding_summaries,
        attack_surfaces: attack_surfaces.into_iter().collect(),
        max_severity,
        risk_score,
    }
}

fn compute_object_risk_score(findings: &[&Finding]) -> f32 {
    if findings.is_empty() {
        return 0.0;
    }

    let severity_weight: f32 = findings.iter()
        .map(|f| match f.severity {
            Severity::Critical => 1.0,
            Severity::High => 0.8,
            Severity::Medium => 0.5,
            Severity::Low => 0.2,
            Severity::Info => 0.0,
        })
        .sum();

    let confidence_mult = findings.iter()
        .map(|f| match f.confidence {
            Confidence::Strong => 1.0,
            Confidence::Probable => 0.7,
            Confidence::Heuristic => 0.4,
        })
        .sum::<f32>() / findings.len() as f32;

    (severity_weight * confidence_mult / findings.len() as f32).min(1.0)
}
```

**Export Format**:
```bash
sis export-ir malicious.pdf --enhanced --format json -o malicious_enhanced_ir.json
```

**Testing**:
- Verify finding-to-object mapping correctness
- Test risk score computation
- Validate JSON schema
- Test with PDFs with no findings

### Phase 3: Enhanced ORG with Node/Edge Attributes

**Goal**: Add semantic attributes to object reference graph

**Tasks**:
1. Add node attributes (risk score, attack surfaces, findings)
2. Add edge attributes (reference type, suspiciousness)
3. Classify edge types (OpenAction, JS, URI, etc.)
4. Export enhanced ORG format

**Files to Modify**:
- `crates/sis-pdf-core/src/ir_export.rs` - ORG export
- Graph export utilities

**New Structures**:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedOrgNode {
    pub obj: u32,
    pub gen: u16,
    pub node_type: String,              // "catalog", "action", "stream", etc.
    pub has_findings: bool,
    pub attack_surfaces: Vec<String>,
    pub max_severity: Option<String>,
    pub finding_count: usize,
    pub risk_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedOrgEdge {
    pub src: usize,
    pub dst: usize,
    pub edge_type: String,              // "reference", "action", "js", etc.
    pub key: Option<String>,            // PDF dict key ("/OpenAction", etc.)
    pub suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedOrg {
    pub nodes: Vec<EnhancedOrgNode>,
    pub edges: Vec<EnhancedOrgEdge>,
}
```

**Implementation**:
```rust
pub fn build_enhanced_org(
    graph: &ObjectGraph,
    findings: &[Finding],
) -> EnhancedOrg {
    // Build node attributes
    let nodes = graph.objects.iter()
        .enumerate()
        .map(|(idx, entry)| {
            let obj_str = format!("{} {} obj", entry.obj, entry.gen);
            let obj_findings: Vec<_> = findings.iter()
                .filter(|f| f.objects.contains(&obj_str))
                .collect();

            EnhancedOrgNode {
                obj: entry.obj,
                gen: entry.gen,
                node_type: classify_object_type(entry),
                has_findings: !obj_findings.is_empty(),
                attack_surfaces: obj_findings.iter()
                    .map(|f| format!("{:?}", f.surface))
                    .collect(),
                max_severity: obj_findings.iter()
                    .map(|f| format!("{:?}", f.severity))
                    .max(),
                finding_count: obj_findings.len(),
                risk_score: compute_object_risk_score(&obj_findings),
            }
        })
        .collect();

    // Build edge attributes
    let edges = extract_edges_with_attributes(graph, findings);

    EnhancedOrg { nodes, edges }
}

fn classify_object_type(entry: &ObjEntry) -> String {
    match &entry.atom {
        PdfAtom::Dict(d) => {
            if d.has_name(b"/Type", b"/Catalog") { "catalog" }
            else if d.has_name(b"/Type", b"/Page") { "page" }
            else if d.has_name(b"/Type", b"/Action") { "action" }
            else if d.has_name(b"/S", b"/JavaScript") { "js_action" }
            else { "dict" }
        }
        PdfAtom::Stream(_) => "stream",
        PdfAtom::Array(_) => "array",
        _ => "other"
    }.to_string()
}

fn extract_edges_with_attributes(
    graph: &ObjectGraph,
    findings: &[Finding],
) -> Vec<EnhancedOrgEdge> {
    let mut edges = Vec::new();

    for (src_idx, entry) in graph.objects.iter().enumerate() {
        if let Some(dict) = entry_dict(entry) {
            // Check for OpenAction
            if let Some((_, target)) = dict.get_first(b"/OpenAction") {
                if let Some(dst_idx) = resolve_target_index(graph, target) {
                    edges.push(EnhancedOrgEdge {
                        src: src_idx,
                        dst: dst_idx,
                        edge_type: "action".to_string(),
                        key: Some("/OpenAction".to_string()),
                        suspicious: true,  // OpenAction is suspicious
                    });
                }
            }

            // Check for JS references
            if let Some((_, target)) = dict.get_first(b"/JS") {
                if let Some(dst_idx) = resolve_target_index(graph, target) {
                    edges.push(EnhancedOrgEdge {
                        src: src_idx,
                        dst: dst_idx,
                        edge_type: "js".to_string(),
                        key: Some("/JS".to_string()),
                        suspicious: true,  // JS is suspicious
                    });
                }
            }

            // Add more edge types...
        }
    }

    edges
}
```

**Export Format**:
```bash
sis export-org malicious.pdf --enhanced --format json -o malicious_enhanced_org.json
```

### Phase 4: Document-Level Risk Profile

**Goal**: Create comprehensive document risk profile for ML

**Tasks**:
1. Aggregate all findings into risk profile
2. Create category-specific risk scores
3. Export as standalone feature set
4. Integrate with training pipeline

**New Structure**:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentRiskProfile {
    pub total_findings: usize,
    pub high_severity_count: usize,
    pub medium_severity_count: usize,
    pub attack_surface_diversity: usize,
    pub max_confidence: Confidence,

    pub js_risk: JsRiskProfile,
    pub uri_risk: UriRiskProfile,
    pub structural_risk: StructuralRiskProfile,
    pub supply_chain_risk: SupplyChainRiskProfile,
    pub content_risk: ContentRiskProfile,
    pub crypto_risk: CryptoRiskProfile,

    pub overall_risk_score: f32,  // 0.0 - 1.0
}

pub fn build_risk_profile(
    findings: &[Finding],
    graph: &ObjectGraph,
) -> DocumentRiskProfile {
    // Aggregate findings by category
    // Compute risk scores
    // Return comprehensive profile
}
```

**Export**:
```bash
sis export-risk-profile malicious.pdf --format json -o risk_profile.json
```

### Phase 5: ML Training Pipeline Integration

**Goal**: Update training scripts to use enhanced signals

**Tasks**:
1. Update dataset export to include enhanced IR/ORG
2. Modify embedding model to use finding annotations
3. Update GNN to use node/edge attributes
4. Train with extended feature vectors
5. Evaluate performance improvements

**Training Script Updates**:
```python
# Load enhanced IR/ORG
def load_enhanced_sample(ir_path, org_path):
    ir = json.load(open(ir_path))
    org = json.load(open(org_path))

    node_texts = []
    node_features = []
    for obj in ir["objects"]:
        # Text for embedding
        lines = [f'{l["path"]} {l["type"]} {l["value"]}' for l in obj["lines"]]

        # Add finding information to text
        if obj.get("findings"):
            for finding in obj["findings"]:
                lines.append(f'FINDING {finding["kind"]} {finding["severity"]}')

        node_texts.append(" ; ".join(lines))

        # Numeric features for GNN
        node_features.append([
            obj.get("risk_score", 0.0),
            len(obj.get("findings", [])),
            len(obj.get("attack_surfaces", [])),
            severity_to_numeric(obj.get("max_severity")),
        ])

    # Edge features from enhanced ORG
    edge_index = [(e["src"], e["dst"]) for e in org["edges"]]
    edge_attr = [
        [
            1.0 if e["suspicious"] else 0.0,
            edge_type_to_numeric(e["edge_type"])
        ]
        for e in org["edges"]
    ]

    return node_texts, node_features, edge_index, edge_attr
```

**GNN Model with Node Attributes**:
```python
class EnhancedGIN(torch.nn.Module):
    def __init__(self, text_dim, node_feat_dim, hidden_dim):
        super().__init__()
        # Combine text embeddings + node features
        self.node_encoder = nn.Linear(text_dim + node_feat_dim, hidden_dim)
        self.conv1 = GINConv(nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
        ))
        # Edge attribute support
        self.edge_encoder = nn.Linear(2, hidden_dim)
        self.lin = nn.Linear(hidden_dim, 1)

    def forward(self, text_emb, node_feat, edge_index, edge_attr, batch):
        # Combine text embeddings with node features
        x = torch.cat([text_emb, node_feat], dim=-1)
        x = self.node_encoder(x)

        # GNN layers with edge attributes
        edge_emb = self.edge_encoder(edge_attr)
        x = self.conv1(x, edge_index, edge_emb)

        # Global pooling
        x = global_add_pool(x, batch)
        return self.lin(x)
```

### Phase 6: Inference Integration

**Goal**: Use enhanced signals during inference

**Tasks**:
1. Update scan pipeline to collect all findings
2. Extract extended features
3. Pass to ML models
4. Generate enhanced predictions

**Scan Pipeline**:
```rust
pub fn scan_with_ml(
    bytes: &[u8],
    ml_config: &MlConfig,
) -> Result<ScanResult> {
    // Run all detectors
    let findings = run_all_detectors(bytes)?;

    // Extract extended features for traditional ML
    let extended_fv = extract_extended_features(&findings, &graph, bytes);

    // Build enhanced IR/ORG for graph ML
    let enhanced_ir = build_enhanced_ir(&graph, &findings);
    let enhanced_org = build_enhanced_org(&graph, &findings);

    // Run ML inference
    let prediction = match ml_config.mode {
        MlMode::Traditional => {
            traditional_classifier.predict(&extended_fv, ml_config.threshold)
        }
        MlMode::Graph => {
            graph_classifier.predict(&enhanced_ir, &enhanced_org, ml_config.threshold)
        }
    };

    Ok(ScanResult {
        findings,
        ml_prediction: Some(prediction),
        risk_profile: build_risk_profile(&findings, &graph),
    })
}
```

## Benefits

### Improved Detection Accuracy
- **Traditional ML**: 20 features → 320+ features (16x increase)
- **Graph ML**: Structural + semantic information
- **Richer supervision**: Risk scores, severity, confidence

### Better Interpretability
- Per-object risk scores
- Attack surface categorization
- Finding-level explanations
- Metadata for manual review

### Reduced False Positives
- Fine-grained signals reduce noise
- Confidence scores filter heuristics
- Multiple corroborating signals

### Adaptability
- Easy to add new detector signals
- Modular feature extraction
- Extensible for new attack types

## Testing Strategy

### Unit Tests
- Feature extraction functions
- Metadata aggregation
- Risk score computation
- Finding-to-object mapping

### Integration Tests
- End-to-end enhanced IR/ORG export
- Feature vector dimension validation
- Edge case handling (no findings, many findings)

### Performance Tests
- Feature extraction overhead
- Memory usage with 320+ features
- Inference latency

### Accuracy Tests
- Benchmark on Evasive-PDFMal2022 dataset
- Compare traditional ML (20 features) vs extended (320 features)
- Compare graph ML (basic IR) vs enhanced (semantic IR)
- Measure precision/recall/F1 improvements

### Ablation Studies
- Test contribution of each feature group
- Identify most predictive signals
- Validate feature importance

## Migration Path

### Backward Compatibility
- Keep existing `FeatureVector` for legacy models
- Add `ExtendedFeatureVector` as opt-in
- Maintain basic IR/ORG export formats
- New formats use `--enhanced` flag

### Gradual Rollout
1. **Phase 1**: Deploy extended feature vector (no breaking changes)
2. **Phase 2**: Deploy enhanced IR export (new format, old format still works)
3. **Phase 3**: Deploy enhanced ORG export
4. **Phase 4**: Train new models on enhanced data
5. **Phase 5**: Default to enhanced formats (old formats deprecated)

## Implementation Checklist

### Code Changes
- [ ] Create `ExtendedFeatureVector` struct
- [ ] Implement feature extraction for all 14 categories
- [ ] Add metadata aggregation functions
- [ ] Modify IR structures for finding annotations
- [ ] Modify ORG structures for node/edge attributes
- [ ] Create `DocumentRiskProfile` struct
- [ ] Update export commands with `--enhanced` flag
- [ ] Update ML inference pipeline
- [ ] Add comprehensive unit tests
- [ ] Add integration tests

### Documentation
- [ ] Update `docs/modeling.md` with enhanced signals
- [ ] Document extended feature vector schema
- [ ] Document enhanced IR/ORG schemas
- [ ] Create training guide for enhanced data
- [ ] Add example notebooks/scripts

### Training Infrastructure
- [ ] Update dataset export scripts
- [ ] Modify embedding model training
- [ ] Modify GNN model architecture
- [ ] Create ablation study scripts
- [ ] Benchmark performance

## Success Metrics

### Quantitative
- **Detection Rate**: Increase TPR by 10-20%
- **False Positives**: Reduce FPR by 15-25%
- **F1 Score**: Improve by 12-18%
- **AUC-ROC**: Improve by 0.05-0.10

### Qualitative
- Better explanations (risk profiles, finding summaries)
- Easier debugging (per-object risk scores)
- More comprehensive coverage (320 features vs 20)

## Future Enhancements

### Dynamic Signals (Phase 7+)
- JavaScript sandbox execution results
- Runtime behavior analysis
- Dynamic taint tracking
- Execution traces

### External Intelligence (Phase 8+)
- VirusTotal integration
- URL reputation services
- Domain age/registration data
- Certificate transparency logs

### Attention Mechanisms (Phase 9+)
- Graph attention networks (GAT)
- Cross-attention between IR and findings
- Hierarchical attention over attack surfaces

## Conclusion

This plan extends sis-pdf's ML capabilities from basic structural features (20 dimensions) to comprehensive multi-modal signals (320+ dimensions) including all detector findings, metadata, and semantic annotations. By enriching both the traditional feature vector and graph-based IR/ORG representations, we create a much richer dataset for ML models to learn from, leading to improved detection accuracy and better interpretability.

The phased implementation approach allows for gradual rollout while maintaining backward compatibility, and the modular design makes it easy to add new signals as detectors are enhanced.
