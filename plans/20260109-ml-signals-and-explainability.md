# ML Signals and Explainability - Integrated Implementation Plan

**Date**: 2026-01-09
**Status**: Planning
**Prerequisite**: ✅ Graph integration (all 7 sprints complete)

---

## Executive Summary

This plan merges two complementary initiatives:
1. **ML Signal Enhancement** (from `plans/ml-signals.md`) - Expand from 35 to 320+ features, enhance IR/ORG
2. **Explainability** (from `plans/ml-signals-explainability-review.md`) - Make predictions interpretable

**Strategic Approach**: Build explainability into each phase from the start, not as an afterthought.

**Outcome**: Rich ML signals + comprehensive explanations = operationally useful predictions

---

## Current State (Post Graph Integration)

### Traditional ML
- **Features**: 35 dimensions (general=3, structural=5, content=4, behavioral=7, graph=15)
- **Location**: `crates/sis-pdf-core/src/features.rs`
- **Limitation**: Only coarse-grained features, no detector findings integration

### Graph ML
- **IR**: Structural representation (dict keys, array lengths, stream metadata)
- **ORG**: Basic graph edges between objects
- **Explainability**: Per-node logits (from `plans/explainability.md`)
- **Limitation**: No semantic annotations from detector findings

### Detectors
- **70+ finding types** across 11 attack surfaces
- **200+ metadata fields** (JS obfuscation, URI risk scores, etc.)
- **Not integrated with ML**: Findings collected but not used for ML training/inference

---

## Integrated Goals

### ML Signal Enhancement
1. ✅ Expand feature vector: 35 → 320+ dimensions
2. ✅ Integrate all 70+ detector findings as features
3. ✅ Add semantic annotations to IR (findings, attack surfaces, risk scores)
4. ✅ Add node/edge attributes to ORG (types, roles, suspiciousness)
5. ✅ Create document-level risk profiles

### Explainability
6. ✅ Feature attribution for 320+ features (SHAP/permutation importance)
7. ✅ Natural language explanation generation
8. ✅ Graph path explanations (suspicious reference chains)
9. ✅ Evidence linking (feature → finding → byte offset)
10. ✅ Comparative explanations (vs. benign baseline)
11. ✅ Risk score calibration (confidence intervals)
12. ✅ Counterfactual explanations (what-if analysis)

---

## Phase 1: Extended Feature Vector with Attribution (3 weeks)

**Goal**: Expand from 35 to 320+ features AND add feature attribution

### 1.1: Core Feature Extraction

**New Structures**:

```rust
// crates/sis-pdf-core/src/features.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedFeatureVector {
    // Legacy features (35)
    pub legacy: FeatureVector,

    // New feature groups (285 new features)
    pub attack_surfaces: AttackSurfaceFeatures,      // 11
    pub severity_dist: SeverityFeatures,             // 15
    pub confidence_dist: ConfidenceFeatures,         // 9
    pub finding_presence: FindingPresenceFeatures,   // 70 (binary)
    pub finding_counts: FindingCountFeatures,        // 70 (counts)
    pub js_signals: JsSignalFeatures,                // 30
    pub uri_signals: UriSignalFeatures,              // 20
    pub content_signals: ContentSignalFeatures,      // 15
    pub supply_chain: SupplyChainFeatures,           // 10
    pub structural_anomalies: StructuralAnomalyFeatures, // 20
    pub crypto_signals: CryptoFeatures,              // 10
    pub embedded_content: EmbeddedContentFeatures,   // 15
}

impl ExtendedFeatureVector {
    pub fn as_f32_vec(&self) -> Vec<f32> {
        let mut vec = self.legacy.as_f32_vec();
        vec.extend(self.attack_surfaces.as_f32_vec());
        vec.extend(self.severity_dist.as_f32_vec());
        // ... extend with all feature groups
        vec
    }

    pub fn feature_names() -> Vec<String> {
        let mut names = FeatureVector::feature_names();
        names.extend(AttackSurfaceFeatures::feature_names());
        // ... extend with all feature group names
        names
    }

    pub fn to_named_map(&self) -> HashMap<String, f32> {
        Self::feature_names()
            .into_iter()
            .zip(self.as_f32_vec())
            .collect()
    }
}
```

**Feature Group Details**:

```rust
// Attack surface distribution (11 features)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceFeatures {
    pub file_structure_count: f32,
    pub xref_trailer_count: f32,
    pub object_streams_count: f32,
    pub streams_filters_count: f32,
    pub actions_count: f32,
    pub javascript_count: f32,
    pub forms_count: f32,
    pub embedded_files_count: f32,
    pub richmedia_3d_count: f32,
    pub crypto_signatures_count: f32,
    pub metadata_count: f32,
}

// Severity distribution (15 features)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityFeatures {
    pub total_critical: f32,
    pub total_high: f32,
    pub total_medium: f32,
    pub total_low: f32,
    pub total_info: f32,
    pub max_severity_score: f32,  // 0-4 scale
    pub avg_severity_score: f32,
    pub weighted_severity: f32,   // Weighted by confidence
    // Per-surface max severity (7 key surfaces)
    pub max_severity_actions: f32,
    pub max_severity_js: f32,
    pub max_severity_streams: f32,
    pub max_severity_embedded: f32,
    pub max_severity_structural: f32,
    pub max_severity_uri: f32,
    pub max_severity_forms: f32,
}

// JavaScript signals (30 features)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsSignalFeatures {
    pub max_obfuscation_score: f32,
    pub avg_obfuscation_score: f32,
    pub total_eval_count: f32,
    pub max_eval_count: f32,
    pub unique_suspicious_apis: f32,
    pub max_string_concat_layers: f32,
    pub max_unescape_layers: f32,
    pub max_decode_ratio: f32,
    pub avg_entropy: f32,
    pub max_entropy: f32,
    pub time_evasion_present: f32,      // Binary
    pub env_probe_present: f32,         // Binary
    pub polymorphic_present: f32,       // Binary
    pub multi_stage_decode: f32,        // Binary
    pub sandbox_executed: f32,          // Binary
    pub sandbox_timeout: f32,           // Binary
    pub runtime_file_probe: f32,        // Binary
    pub runtime_network_intent: f32,    // Binary
    pub crypto_mining_detected: f32,    // Binary
    pub total_js_objects: f32,
    pub max_js_size: f32,
    pub avg_js_size: f32,
    pub js_in_openaction: f32,          // Binary
    pub js_in_aa: f32,                  // Binary
    pub js_in_annotation: f32,          // Binary
    pub js_in_field: f32,               // Binary
    pub fromcharcode_count: f32,
    pub multiple_keys_present: f32,     // Binary
    pub ref_chain_depth: f32,
    pub array_fragment_count: f32,
}

// URI signals (20 features)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UriSignalFeatures {
    pub total_count: f32,
    pub unique_domains: f32,
    pub max_risk_score: f32,
    pub avg_risk_score: f32,
    pub javascript_uri_count: f32,
    pub file_uri_count: f32,
    pub http_count: f32,
    pub https_count: f32,
    pub ip_address_count: f32,
    pub suspicious_tld_count: f32,
    pub obfuscated_count: f32,
    pub data_exfil_pattern_count: f32,
    pub hidden_annotation_count: f32,
    pub automatic_trigger_count: f32,
    pub js_triggered_count: f32,
    pub tracking_params_count: f32,
    pub max_url_length: f32,
    pub phishing_indicators: f32,
    pub external_dependency_count: f32,
    pub mixed_content_present: f32,     // HTTP in HTTPS context
}

// Finding presence (70 binary features - one per finding type)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingPresenceFeatures {
    pub xref_conflict: f32,
    pub incremental_update_chain: f32,
    pub object_id_shadowing: f32,
    pub js_polymorphic: f32,
    pub js_obfuscation_deep: f32,
    pub uri_content_analysis: f32,
    pub multi_stage_attack_chain: f32,
    pub supply_chain_persistence: f32,
    // ... all 70 finding types as binary flags
}

// Finding counts (70 count features)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingCountFeatures {
    pub xref_conflict_count: f32,
    pub incremental_update_chain_count: f32,
    pub object_id_shadowing_count: f32,
    pub js_polymorphic_count: f32,
    // ... all 70 finding types as counts
}

// Additional feature groups (similar structure):
// - ContentSignalFeatures (15)
// - SupplyChainFeatures (10)
// - StructuralAnomalyFeatures (20)
// - CryptoFeatures (10)
// - EmbeddedContentFeatures (15)
```

**Extraction Function**:

```rust
pub fn extract_extended_features(
    ctx: &ScanContext,
    findings: &[Finding],
) -> ExtendedFeatureVector {
    // Extract legacy features (35)
    let legacy = FeatureExtractor::extract(ctx);

    // Extract new feature groups
    let attack_surfaces = extract_attack_surface_features(findings);
    let severity_dist = extract_severity_features(findings);
    let confidence_dist = extract_confidence_features(findings);
    let finding_presence = extract_finding_presence_features(findings);
    let finding_counts = extract_finding_count_features(findings);
    let js_signals = extract_js_features(findings);
    let uri_signals = extract_uri_features(findings);
    let content_signals = extract_content_features(findings);
    let supply_chain = extract_supply_chain_features(findings);
    let structural_anomalies = extract_structural_features(findings);
    let crypto_signals = extract_crypto_features(findings);
    let embedded_content = extract_embedded_features(findings);

    ExtendedFeatureVector {
        legacy,
        attack_surfaces,
        severity_dist,
        confidence_dist,
        finding_presence,
        finding_counts,
        js_signals,
        uri_signals,
        content_signals,
        supply_chain,
        structural_anomalies,
        crypto_signals,
        embedded_content,
    }
}

fn extract_js_features(findings: &[Finding]) -> JsSignalFeatures {
    let js_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.surface == AttackSurface::JavaScript)
        .collect();

    if js_findings.is_empty() {
        return JsSignalFeatures::default();
    }

    // Extract from metadata
    let obfuscation_scores: Vec<f32> = js_findings
        .iter()
        .filter_map(|f| f.meta.get("js.obfuscation_score"))
        .filter_map(|s| s.parse().ok())
        .collect();

    let max_obfuscation_score = obfuscation_scores.iter()
        .copied()
        .max_by(|a, b| a.partial_cmp(b).unwrap())
        .unwrap_or(0.0);

    // ... extract all 30 JS features from metadata

    JsSignalFeatures {
        max_obfuscation_score,
        // ... populate all fields
        ..Default::default()
    }
}

// Similar extraction functions for other feature groups
```

### 1.2: Feature Attribution (EXPLAINABILITY)

**Attribution Structures**:

```rust
// crates/sis-pdf-core/src/explainability.rs (NEW FILE)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureAttribution {
    pub feature_name: String,
    pub value: f32,
    pub contribution: f32,      // SHAP value or permutation importance
    pub baseline: f32,          // Expected value for benign files
    pub percentile: f32,        // Percentile in benign distribution (0-100)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlExplanation {
    pub prediction: f32,
    pub baseline_score: f32,
    pub top_positive_features: Vec<FeatureAttribution>,  // Top 10
    pub top_negative_features: Vec<FeatureAttribution>,  // Top 10
    pub feature_group_importance: HashMap<String, f32>,   // Per-category
    pub summary: String,                                  // Natural language
}

pub trait ExplainableModel {
    fn predict_with_explanation(
        &self,
        features: &ExtendedFeatureVector,
        baseline: &BenignBaseline,
    ) -> Result<(f32, MlExplanation)>;
}

// Benign baseline statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenignBaseline {
    pub feature_means: HashMap<String, f32>,
    pub feature_stddevs: HashMap<String, f32>,
    pub feature_percentiles: HashMap<String, Vec<f32>>,  // [P10, P25, P50, P75, P90, P95, P99]
}

impl BenignBaseline {
    pub fn from_training_data(benign_samples: &[ExtendedFeatureVector]) -> Self {
        // Compute mean, stddev, percentiles for each feature
        // Store in baseline
    }

    pub fn load_from_file(path: &Path) -> Result<Self> {
        // Load precomputed baseline
    }
}
```

**SHAP Integration** (for tree-based models):

```rust
// Permutation-based importance (model-agnostic)
pub fn compute_permutation_importance(
    model: &dyn Fn(&ExtendedFeatureVector) -> f32,
    features: &ExtendedFeatureVector,
    baseline: &BenignBaseline,
    n_samples: usize,
) -> Vec<FeatureAttribution> {
    let original_pred = model(features);
    let feature_names = ExtendedFeatureVector::feature_names();
    let feature_values = features.as_f32_vec();

    let mut attributions = Vec::new();

    for (idx, (name, &value)) in feature_names.iter().zip(&feature_values).enumerate() {
        // Permute this feature to baseline
        let mut permuted = features.clone();
        let baseline_value = baseline.feature_means.get(&name).copied().unwrap_or(0.0);

        // Set feature to baseline (simplified - real SHAP uses multiple samples)
        // This is a simplified permutation importance
        let permuted_values = permuted.as_f32_vec();
        let mut modified = features.clone();
        // TODO: Set modified feature at idx to baseline_value

        let permuted_pred = model(&modified);
        let contribution = original_pred - permuted_pred;

        attributions.push(FeatureAttribution {
            feature_name: name.clone(),
            value,
            contribution,
            baseline: baseline_value,
            percentile: compute_percentile(value, &baseline.feature_percentiles[&name]),
        });
    }

    // Sort by absolute contribution
    attributions.sort_by(|a, b| b.contribution.abs().partial_cmp(&a.contribution.abs()).unwrap());
    attributions
}

fn compute_percentile(value: f32, percentiles: &[f32]) -> f32 {
    // Binary search in percentile array
    // Return interpolated percentile value
    if value <= percentiles[0] { return 10.0; }
    if value >= percentiles[6] { return 99.0; }
    // Linear interpolation
    for i in 0..percentiles.len()-1 {
        if value >= percentiles[i] && value <= percentiles[i+1] {
            let pct_low = [10.0, 25.0, 50.0, 75.0, 90.0, 95.0, 99.0][i];
            let pct_high = [10.0, 25.0, 50.0, 75.0, 90.0, 95.0, 99.0][i+1];
            let ratio = (value - percentiles[i]) / (percentiles[i+1] - percentiles[i]);
            return pct_low + ratio * (pct_high - pct_low);
        }
    }
    50.0
}
```

### 1.3: Natural Language Summaries (EXPLAINABILITY)

```rust
pub fn generate_explanation_text(
    prediction: f32,
    top_features: &[FeatureAttribution],
    findings: &[Finding],
) -> String {
    let severity_level = match prediction {
        p if p > 0.8 => "highly",
        p if p > 0.6 => "moderately",
        _ => "somewhat",
    };

    let mut summary = format!(
        "This PDF is {} suspicious (ML risk score: {:.2}). ",
        severity_level, prediction
    );

    // Primary threat vector
    if let Some(top) = top_features.first() {
        summary.push_str(&format!(
            "The strongest indicator is {} (value: {:.2}, contribution: {:+.2}, baseline: {:.2}). ",
            humanize_feature_name(&top.feature_name),
            top.value,
            top.contribution,
            top.baseline
        ));
    }

    // High-severity findings
    let high_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::High || f.severity == Severity::Critical)
        .collect();

    if !high_findings.is_empty() {
        summary.push_str(&format!(
            "Found {} high-severity issues: ",
            high_findings.len()
        ));

        for (i, f) in high_findings.iter().take(3).enumerate() {
            if i > 0 { summary.push_str(", "); }
            summary.push_str(&humanize_finding_kind(&f.kind));
        }

        if high_findings.len() > 3 {
            summary.push_str(&format!(", and {} more", high_findings.len() - 3));
        }
        summary.push_str(". ");
    }

    // Attack pattern recognition
    let attack_pattern = recognize_attack_pattern(findings);
    if let Some(pattern) = attack_pattern {
        summary.push_str(&format!("This appears to be a {}. ", pattern));
    }

    // Recommendation
    let recommendation = match prediction {
        p if p > 0.8 => "Recommend: Block and investigate in sandbox environment.",
        p if p > 0.6 => "Recommend: Flag for manual review before allowing.",
        p if p > 0.4 => "Recommend: Monitor and log for security audit.",
        _ => "Recommend: Allow with standard monitoring.",
    };
    summary.push_str(recommendation);

    summary
}

fn humanize_feature_name(name: &str) -> String {
    match name {
        "js_signals.max_obfuscation_score" => "highly obfuscated JavaScript",
        "finding.js_polymorphic_count" => "polymorphic JavaScript patterns",
        "action_chains.automatic_trigger_count" => "automatic action triggers",
        "uri_signals.ip_address_count" => "URIs with direct IP addresses",
        "js_signals.time_evasion_present" => "time-based evasion in JavaScript",
        "supply_chain.multi_stage_chains" => "multi-stage attack chains",
        // ... map all 320 features
        _ => name.replace("_", " ").replace(".", ": ")
    }
}

fn recognize_attack_pattern(findings: &[Finding]) -> Option<String> {
    let has_js = findings.iter().any(|f| f.surface == AttackSurface::JavaScript);
    let has_obf = findings.iter().any(|f| f.kind.contains("obfuscation"));
    let has_auto = findings.iter().any(|f| f.kind.contains("open_action"));
    let has_uri = findings.iter().any(|f| f.surface == AttackSurface::Actions && f.kind.contains("uri"));
    let has_embed = findings.iter().any(|f| f.surface == AttackSurface::EmbeddedFiles);
    let has_multi = findings.iter().any(|f| f.kind.contains("multi_stage"));

    if has_js && has_obf && has_auto && has_uri {
        Some("sophisticated phishing attack with automatic JavaScript execution".to_string())
    } else if has_js && has_multi && has_embed {
        Some("multi-stage malware delivery via embedded payloads".to_string())
    } else if has_js && has_obf {
        Some("JavaScript-based attack with obfuscation".to_string())
    } else if has_auto && has_uri {
        Some("automatic external resource loading".to_string())
    } else {
        None
    }
}
```

### 1.4: Evidence Linking (EXPLAINABILITY)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceChain {
    pub feature_name: String,
    pub feature_value: f32,
    pub contribution: f32,
    pub derived_from_findings: Vec<String>,  // Finding IDs or kinds
    pub evidence_spans: Vec<EvidenceSpan>,
}

pub fn build_evidence_chains(
    attribution: &[FeatureAttribution],
    findings: &[Finding],
) -> Vec<EvidenceChain> {
    let mut chains = Vec::new();

    for attr in attribution.iter().take(20) {  // Top 20 features
        let relevant_findings = find_contributing_findings(&attr.feature_name, findings);
        let evidence_spans: Vec<_> = relevant_findings
            .iter()
            .flat_map(|f| f.evidence.clone())
            .collect();

        if !relevant_findings.is_empty() {
            chains.push(EvidenceChain {
                feature_name: attr.feature_name.clone(),
                feature_value: attr.value,
                contribution: attr.contribution,
                derived_from_findings: relevant_findings.iter()
                    .map(|f| f.kind.clone())
                    .collect(),
                evidence_spans,
            });
        }
    }

    chains
}

fn find_contributing_findings(feature_name: &str, findings: &[Finding]) -> Vec<&Finding> {
    // Map feature names to finding types
    match feature_name {
        name if name.starts_with("js_signals.") => {
            findings.iter().filter(|f| f.surface == AttackSurface::JavaScript).collect()
        }
        name if name.starts_with("uri_signals.") => {
            findings.iter().filter(|f| f.kind.contains("uri")).collect()
        }
        name if name.starts_with("finding.") => {
            let kind = name.strip_prefix("finding.").unwrap()
                .strip_suffix("_count").or_else(|| name.strip_suffix("_present"))
                .unwrap_or(name);
            findings.iter().filter(|f| f.kind == kind).collect()
        }
        _ => Vec::new()
    }
}
```

### 1.5: Files to Create/Modify

**New Files**:
- `crates/sis-pdf-core/src/explainability.rs` - Explanation structures and attribution
- `crates/sis-pdf-core/src/features_extended.rs` - Extended feature groups (or extend existing features.rs)

**Modified Files**:
- `crates/sis-pdf-core/src/features.rs` - Add ExtendedFeatureVector, extraction functions
- `crates/sis-pdf-core/src/runner.rs` - Use extended features in scan pipeline
- `crates/sis-pdf-core/src/lib.rs` - Export new modules

### 1.6: Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extended_feature_vector_dimensions() {
        let features = ExtendedFeatureVector::default();
        let vec = features.as_f32_vec();
        assert_eq!(vec.len(), 320, "Expected 320 features");
    }

    #[test]
    fn test_feature_names_match_values() {
        let names = ExtendedFeatureVector::feature_names();
        let features = ExtendedFeatureVector::default();
        let values = features.as_f32_vec();
        assert_eq!(names.len(), values.len(), "Feature names and values must match");
    }

    #[test]
    fn test_js_feature_extraction() {
        let findings = vec![
            Finding {
                kind: "js_polymorphic".to_string(),
                surface: AttackSurface::JavaScript,
                meta: hashmap!{
                    "js.obfuscation_score".to_string() => "0.85".to_string(),
                    "js.eval_count".to_string() => "3".to_string(),
                },
                ..Default::default()
            }
        ];

        let js_features = extract_js_features(&findings);
        assert_eq!(js_features.max_obfuscation_score, 0.85);
        assert_eq!(js_features.max_eval_count, 3.0);
    }

    #[test]
    fn test_attribution_sums_approximately_to_prediction() {
        // Mock model
        let model = |_: &ExtendedFeatureVector| 0.87;
        let features = ExtendedFeatureVector::default();
        let baseline = BenignBaseline::default();

        let attributions = compute_permutation_importance(&model, &features, &baseline, 100);
        let total_contribution: f32 = attributions.iter().map(|a| a.contribution).sum();

        // Should be close to (prediction - baseline)
        assert!((total_contribution - 0.87).abs() < 0.2, "Attribution should approximate prediction");
    }

    #[test]
    fn test_evidence_chain_linking() {
        let findings = vec![
            Finding {
                kind: "js_polymorphic".to_string(),
                evidence: vec![EvidenceSpan { start: 100, end: 200, preview: "...".to_string() }],
                ..Default::default()
            }
        ];

        let attribution = vec![
            FeatureAttribution {
                feature_name: "finding.js_polymorphic_count".to_string(),
                value: 1.0,
                contribution: 0.15,
                baseline: 0.0,
                percentile: 99.0,
            }
        ];

        let chains = build_evidence_chains(&attribution, &findings);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].evidence_spans.len(), 1);
        assert_eq!(chains[0].evidence_spans[0].start, 100);
    }

    #[test]
    fn test_natural_language_summary_generation() {
        let findings = vec![
            Finding {
                kind: "js_polymorphic".to_string(),
                severity: Severity::High,
                ..Default::default()
            }
        ];

        let attribution = vec![
            FeatureAttribution {
                feature_name: "js_signals.max_obfuscation_score".to_string(),
                value: 0.95,
                contribution: 0.18,
                baseline: 0.0,
                percentile: 99.5,
            }
        ];

        let summary = generate_explanation_text(0.87, &attribution, &findings);
        assert!(summary.contains("highly suspicious"));
        assert!(summary.contains("obfuscated JavaScript"));
        assert!(summary.contains("Block and investigate"));
    }
}
```

### 1.7: Deliverables

- [ ] ExtendedFeatureVector struct with 320 features
- [ ] Feature extraction from findings metadata
- [ ] Feature attribution (permutation importance)
- [ ] Natural language summary generation
- [ ] Evidence chain linking
- [ ] Comprehensive unit tests
- [ ] Benign baseline computation utilities

---

## Phase 2: Enhanced IR with Semantic Annotations (2 weeks)

**Goal**: Augment IR with findings, attack surfaces, risk scores, and natural language summaries

### 2.1: Enhanced IR Structures

```rust
// crates/sis-pdf-pdf/src/ir.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedPdfIrObject {
    // Existing fields
    pub obj_ref: (u32, u16),
    pub lines: Vec<PdfIrLine>,
    pub deviations: Vec<String>,

    // NEW: Semantic annotations
    pub findings: Vec<IrFindingSummary>,
    pub attack_surfaces: Vec<String>,
    pub max_severity: Option<String>,
    pub risk_score: f32,
    pub explanation: Option<String>,  // Natural language for this object
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrFindingSummary {
    pub kind: String,
    pub severity: String,
    pub confidence: String,
    pub surface: String,
    pub signals: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedIrExport {
    pub objects: Vec<EnhancedPdfIrObject>,
    pub document_summary: DocumentSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentSummary {
    pub total_objects: usize,
    pub objects_with_findings: usize,
    pub max_object_risk: f32,
    pub attack_surface_diversity: usize,
    pub explanation: String,  // Document-level natural language
}
```

### 2.2: Enhanced IR Generation

```rust
// crates/sis-pdf-core/src/ir_export.rs (modify existing)

pub fn enhanced_ir_for_object(
    entry: &ObjEntry<'_>,
    findings: &[Finding],
    opts: &IrOptions,
) -> EnhancedPdfIrObject {
    // Generate basic IR
    let basic_ir = ir_for_object(entry, opts);

    // Find findings for this object
    let obj_str = format!("{} {} obj", entry.obj, entry.gen);
    let obj_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.objects.contains(&obj_str))
        .collect();

    // Extract finding summaries
    let finding_summaries = obj_findings
        .iter()
        .map(|f| IrFindingSummary {
            kind: f.kind.clone(),
            severity: format!("{:?}", f.severity),
            confidence: format!("{:?}", f.confidence),
            surface: format!("{:?}", f.surface),
            signals: extract_signals_from_meta(&f.meta),
        })
        .collect();

    // Aggregate attack surfaces
    let attack_surfaces: HashSet<_> = obj_findings
        .iter()
        .map(|f| format!("{:?}", f.surface))
        .collect();

    // Compute max severity
    let max_severity = obj_findings
        .iter()
        .map(|f| format!("{:?}", f.severity))
        .max();

    // Compute risk score
    let risk_score = compute_object_risk_score(&obj_findings);

    // Generate explanation for this object
    let explanation = if !obj_findings.is_empty() {
        Some(generate_object_explanation(&obj_findings))
    } else {
        None
    };

    EnhancedPdfIrObject {
        obj_ref: basic_ir.obj_ref,
        lines: basic_ir.lines,
        deviations: basic_ir.deviations,
        findings: finding_summaries,
        attack_surfaces: attack_surfaces.into_iter().collect(),
        max_severity,
        risk_score,
        explanation,
    }
}

fn compute_object_risk_score(findings: &[&Finding]) -> f32 {
    if findings.is_empty() {
        return 0.0;
    }

    let severity_weight: f32 = findings
        .iter()
        .map(|f| match f.severity {
            Severity::Critical => 1.0,
            Severity::High => 0.8,
            Severity::Medium => 0.5,
            Severity::Low => 0.2,
            Severity::Info => 0.0,
        })
        .sum();

    let confidence_mult = findings
        .iter()
        .map(|f| match f.confidence {
            Confidence::Strong => 1.0,
            Confidence::Probable => 0.7,
            Confidence::Heuristic => 0.4,
        })
        .sum::<f32>()
        / findings.len() as f32;

    (severity_weight * confidence_mult / findings.len() as f32).min(1.0)
}

fn generate_object_explanation(findings: &[&Finding]) -> String {
    if findings.is_empty() {
        return String::new();
    }

    let high_count = findings.iter().filter(|f| f.severity == Severity::High).count();
    let kinds: Vec<_> = findings.iter().take(3).map(|f| humanize_finding_kind(&f.kind)).collect();

    if high_count > 0 {
        format!(
            "This object has {} high-severity issues: {}",
            high_count,
            kinds.join(", ")
        )
    } else {
        format!("This object has issues: {}", kinds.join(", "))
    }
}

fn extract_signals_from_meta(meta: &HashMap<String, String>) -> HashMap<String, serde_json::Value> {
    meta.iter()
        .map(|(k, v)| {
            let value = if let Ok(n) = v.parse::<f64>() {
                serde_json::Value::Number(serde_json::Number::from_f64(n).unwrap())
            } else if let Ok(b) = v.parse::<bool>() {
                serde_json::Value::Bool(b)
            } else {
                serde_json::Value::String(v.clone())
            };
            (k.clone(), value)
        })
        .collect()
}
```

### 2.3: Export Command

```bash
# Export enhanced IR
sis export-ir malicious.pdf --enhanced --format json -o enhanced_ir.json

# With document summary
sis export-ir malicious.pdf --enhanced --with-summary --format json -o enhanced_ir.json
```

### 2.4: Deliverables

- [ ] EnhancedPdfIrObject structure
- [ ] Enhanced IR generation from findings
- [ ] Per-object risk score computation
- [ ] Per-object explanations
- [ ] Document-level summary
- [ ] CLI integration with --enhanced flag
- [ ] Tests for IR enhancement

---

## Phase 3: Enhanced ORG with Graph Paths (2 weeks)

**Goal**: Add node/edge attributes to ORG AND extract suspicious graph paths

### 3.1: Graph Path Explanation (EXPLAINABILITY)

```rust
// crates/sis-pdf-core/src/explainability.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphPathExplanation {
    pub suspicious_paths: Vec<SuspiciousPath>,
    pub max_path_risk: f32,
    pub avg_path_risk: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousPath {
    pub path: Vec<PathNode>,
    pub risk_score: f32,
    pub explanation: String,
    pub attack_pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathNode {
    pub obj_ref: (u32, u16),
    pub node_type: String,
    pub edge_to_next: Option<EdgeInfo>,
    pub findings: Vec<String>,  // Finding kinds at this node
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeInfo {
    pub edge_type: String,
    pub key: String,
    pub suspicious: bool,
}

pub fn extract_suspicious_paths(
    typed_graph: &TypedGraph,
    findings: &[Finding],
    node_scores: Option<&[f32]>,  // From GNN if available
) -> GraphPathExplanation {
    let path_finder = typed_graph.path_finder();

    // Find action chains
    let action_chains = path_finder.find_all_action_chains();

    // Score each path
    let mut scored_paths = Vec::new();

    for chain in action_chains {
        let path_nodes = chain.objects.iter().map(|&obj_ref| {
            // Find findings for this object
            let obj_str = format!("{} {} obj", obj_ref.0, obj_ref.1);
            let obj_findings: Vec<_> = findings
                .iter()
                .filter(|f| f.objects.contains(&obj_str))
                .map(|f| f.kind.clone())
                .collect();

            PathNode {
                obj_ref,
                node_type: classify_node_type(&typed_graph, obj_ref),
                edge_to_next: None,  // Will be filled
                findings: obj_findings,
            }
        }).collect::<Vec<_>>();

        // Add edge information
        let mut path_with_edges = Vec::new();
        for (i, mut node) in path_nodes.into_iter().enumerate() {
            if i < chain.objects.len() - 1 {
                let edge = find_edge_between(
                    &typed_graph,
                    chain.objects[i],
                    chain.objects[i + 1]
                );
                node.edge_to_next = edge;
            }
            path_with_edges.push(node);
        }

        // Compute path risk score
        let path_risk = compute_path_risk_score(&path_with_edges, findings, node_scores);

        // Classify attack pattern
        let attack_pattern = classify_path_pattern(&path_with_edges, &chain.chain_type);

        // Generate explanation
        let explanation = generate_path_explanation(&path_with_edges, &attack_pattern);

        scored_paths.push(SuspiciousPath {
            path: path_with_edges,
            risk_score: path_risk,
            explanation,
            attack_pattern,
        });
    }

    // Sort by risk score
    scored_paths.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap());

    let max_path_risk = scored_paths.first().map(|p| p.risk_score).unwrap_or(0.0);
    let avg_path_risk = if !scored_paths.is_empty() {
        scored_paths.iter().map(|p| p.risk_score).sum::<f32>() / scored_paths.len() as f32
    } else {
        0.0
    };

    GraphPathExplanation {
        suspicious_paths: scored_paths.into_iter().take(10).collect(),  // Top 10
        max_path_risk,
        avg_path_risk,
    }
}

fn compute_path_risk_score(
    path: &[PathNode],
    findings: &[Finding],
    node_scores: Option<&[f32]>,
) -> f32 {
    let mut risk = 0.0;

    // Node contribution (findings)
    for node in path {
        let node_findings: Vec<_> = findings
            .iter()
            .filter(|f| node.findings.contains(&f.kind))
            .collect();

        for f in node_findings {
            risk += match f.severity {
                Severity::Critical => 0.3,
                Severity::High => 0.2,
                Severity::Medium => 0.1,
                Severity::Low => 0.05,
                Severity::Info => 0.0,
            };
        }
    }

    // Edge contribution (suspicious edges)
    let suspicious_edge_count = path
        .iter()
        .filter_map(|n| n.edge_to_next.as_ref())
        .filter(|e| e.suspicious)
        .count();
    risk += suspicious_edge_count as f32 * 0.15;

    // Path length bonus (longer chains are more suspicious)
    risk += (path.len() as f32 - 1.0) * 0.05;

    risk.min(1.0)
}

fn classify_path_pattern(path: &[PathNode], chain_type: &ChainType) -> Option<String> {
    let has_openaction = path.iter().any(|n| {
        n.edge_to_next.as_ref()
            .map(|e| e.key == "/OpenAction")
            .unwrap_or(false)
    });

    let has_js = path.iter().any(|n| n.node_type == "Action" && n.edge_to_next.as_ref()
        .map(|e| e.edge_type == "JavaScriptPayload")
        .unwrap_or(false));

    let has_uri = path.iter().any(|n| n.edge_to_next.as_ref()
        .map(|e| e.edge_type == "UriTarget")
        .unwrap_or(false));

    match (has_openaction, has_js, has_uri) {
        (true, true, true) => Some("automatic_js_with_external_uri".to_string()),
        (true, true, false) => Some("automatic_js_trigger".to_string()),
        (false, true, true) => Some("js_to_external_resource".to_string()),
        (true, false, true) => Some("automatic_external_resource".to_string()),
        _ => match chain_type {
            ChainType::Automatic => Some("automatic_action_chain".to_string()),
            ChainType::JavaScript => Some("js_action_chain".to_string()),
            ChainType::External => Some("external_action_chain".to_string()),
        }
    }
}

fn generate_path_explanation(path: &[PathNode], pattern: &Option<String>) -> String {
    let mut explanation = format!(
        "Path from {} through {} objects",
        format_obj_ref(path.first().unwrap().obj_ref),
        path.len()
    );

    if let Some(pat) = pattern {
        explanation.push_str(&format!(": {}", humanize_pattern(pat)));
    }

    explanation
}

fn humanize_pattern(pattern: &str) -> String {
    match pattern {
        "automatic_js_with_external_uri" => "Automatic JavaScript execution with external URI",
        "automatic_js_trigger" => "Automatic JavaScript execution via OpenAction",
        "js_to_external_resource" => "JavaScript triggers external resource loading",
        "automatic_external_resource" => "Automatic external resource loading",
        _ => pattern.replace("_", " ")
    }
}
```

### 3.2: Enhanced ORG Integration

The enhanced ORG export was already implemented in Sprint 6, but now we add graph path information:

```rust
// crates/sis-pdf-core/src/org_export.rs

pub fn export_org_with_paths(
    ctx: &ScanContext,
    findings: &[Finding],
    enhanced: bool,
) -> Result<OrgExportWithPaths> {
    let graph = ctx.graph();
    let basic_org = OrgGraph::from_object_graph(graph);

    let enhanced_org = if enhanced {
        let typed_graph = ctx.build_typed_graph();
        let classifications = ctx.classifications();
        Some(OrgGraph::from_object_graph_enhanced(
            graph,
            &typed_graph,
            classifications
        ))
    } else {
        None
    };

    // Add graph path explanations
    let path_explanation = if enhanced {
        let typed_graph = ctx.build_typed_graph();
        Some(extract_suspicious_paths(&typed_graph, findings, None))
    } else {
        None
    };

    Ok(OrgExportWithPaths {
        org: enhanced_org.unwrap_or(basic_org),
        paths: path_explanation,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgExportWithPaths {
    pub org: OrgGraph,
    pub paths: Option<GraphPathExplanation>,
}
```

### 3.3: Deliverables

- [ ] GraphPathExplanation structure
- [ ] extract_suspicious_paths() implementation
- [ ] Path risk scoring
- [ ] Attack pattern classification for paths
- [ ] Path explanation generation
- [ ] Integration with ORG export
- [ ] Tests for path extraction

---

## Phase 4: Document-Level Risk Profile with Calibration (2 weeks)

**Goal**: Aggregate all signals + calibrate risk scores + comparative explanations

### 4.1: Risk Profile Structure

```rust
// crates/sis-pdf-core/src/explainability.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentRiskProfile {
    pub prediction: CalibratedPrediction,
    pub total_findings: usize,
    pub high_severity_count: usize,
    pub medium_severity_count: usize,
    pub attack_surface_diversity: usize,
    pub max_confidence: String,

    // Category-specific risk
    pub js_risk: JsRiskProfile,
    pub uri_risk: UriRiskProfile,
    pub structural_risk: StructuralRiskProfile,
    pub supply_chain_risk: SupplyChainRiskProfile,
    pub content_risk: ContentRiskProfile,
    pub crypto_risk: CryptoRiskProfile,

    // Explanation
    pub explanation: MlExplanation,
    pub comparative_analysis: Vec<ComparativeFeature>,
    pub graph_paths: Option<GraphPathExplanation>,
    pub evidence_chains: Vec<EvidenceChain>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsRiskProfile {
    pub present: bool,
    pub count: usize,
    pub max_obfuscation: f32,
    pub evasion_techniques: Vec<String>,
    pub multi_stage: bool,
    pub sandbox_executed: bool,
    pub risk_score: f32,
}

// Similar structures for other risk categories
```

### 4.2: Risk Score Calibration (EXPLAINABILITY)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibratedPrediction {
    pub raw_score: f32,
    pub calibrated_score: f32,
    pub confidence_interval: (f32, f32),  // 95% CI
    pub calibration_method: String,
    pub interpretation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationModel {
    pub method: CalibrationMethod,
    pub curve_points: Vec<(f32, f32)>,  // (predicted, observed)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CalibrationMethod {
    PlattScaling { a: f32, b: f32 },
    IsotonicRegression { x: Vec<f32>, y: Vec<f32> },
}

impl CalibrationModel {
    pub fn calibrate(&self, raw_score: f32) -> f32 {
        match &self.method {
            CalibrationMethod::PlattScaling { a, b } => {
                1.0 / (1.0 + (-a * raw_score - b).exp())
            }
            CalibrationMethod::IsotonicRegression { x, y } => {
                // Linear interpolation in isotonic curve
                for i in 0..x.len()-1 {
                    if raw_score >= x[i] && raw_score <= x[i+1] {
                        let ratio = (raw_score - x[i]) / (x[i+1] - x[i]);
                        return y[i] + ratio * (y[i+1] - y[i]);
                    }
                }
                if raw_score < x[0] { y[0] } else { *y.last().unwrap() }
            }
        }
    }

    pub fn load_from_file(path: &Path) -> Result<Self> {
        // Load precomputed calibration model
    }
}

pub fn calibrate_prediction(
    raw_score: f32,
    calibrator: &CalibrationModel,
) -> CalibratedPrediction {
    let calibrated_score = calibrator.calibrate(raw_score);

    // Estimate confidence interval (simplified - real implementation would use bootstrap)
    let ci_width = 0.1 * (1.0 - calibrated_score) * calibrated_score;  // Wider near 0.5
    let confidence_interval = (
        (calibrated_score - ci_width).max(0.0),
        (calibrated_score + ci_width).min(1.0)
    );

    let interpretation = format!(
        "{:.0}% probability of being malicious ({:.0}%-{:.0}% with 95% confidence)",
        calibrated_score * 100.0,
        confidence_interval.0 * 100.0,
        confidence_interval.1 * 100.0
    );

    CalibratedPrediction {
        raw_score,
        calibrated_score,
        confidence_interval,
        calibration_method: format!("{:?}", calibrator.method),
        interpretation,
    }
}
```

### 4.3: Comparative Explanations (EXPLAINABILITY)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparativeFeature {
    pub feature_name: String,
    pub value: f32,
    pub benign_mean: f32,
    pub benign_stddev: f32,
    pub z_score: f32,
    pub percentile: f32,
    pub interpretation: String,
}

pub fn compute_comparative_explanation(
    features: &ExtendedFeatureVector,
    baseline: &BenignBaseline,
    top_n: usize,
) -> Vec<ComparativeFeature> {
    let feature_map = features.to_named_map();
    let mut comparisons = Vec::new();

    for (name, value) in feature_map {
        let mean = baseline.feature_means.get(&name).copied().unwrap_or(0.0);
        let stddev = baseline.feature_stddevs.get(&name).copied().unwrap_or(1.0);
        let z_score = if stddev > 0.0 {
            (value - mean) / stddev
        } else {
            0.0
        };

        if z_score.abs() > 1.5 {  // More than 1.5 standard deviations
            let percentiles = baseline.feature_percentiles.get(&name);
            let percentile = if let Some(pcts) = percentiles {
                compute_percentile(value, pcts)
            } else {
                50.0
            };

            let interpretation = if z_score > 0.0 {
                if z_score > 3.0 {
                    format!("Extremely high ({:.1}σ above benign average) - highly unusual", z_score)
                } else if z_score > 2.0 {
                    format!("Very high ({:.1}σ above benign average) - suspicious", z_score)
                } else {
                    format!("Higher than typical ({:.1}σ above benign average)", z_score)
                }
            } else {
                format!("Lower than typical ({:.1}σ below benign average)", z_score.abs())
            };

            comparisons.push(ComparativeFeature {
                feature_name: name,
                value,
                benign_mean: mean,
                benign_stddev: stddev,
                z_score,
                percentile,
                interpretation,
            });
        }
    }

    // Sort by absolute z-score
    comparisons.sort_by(|a, b| b.z_score.abs().partial_cmp(&a.z_score.abs()).unwrap());
    comparisons.truncate(top_n);
    comparisons
}
```

### 4.4: Deliverables

- [ ] DocumentRiskProfile structure
- [ ] Category-specific risk profiles
- [ ] CalibrationModel and calibration logic
- [ ] Comparative explanation generation
- [ ] Integration of all explanation components
- [ ] Tests for risk profiling and calibration

---

## Phase 5: ML Training Pipeline Integration (2 weeks)

**Goal**: Update training scripts to use enhanced signals and train with explainability support

### 5.1: Training Data Export

```bash
# Export extended features with findings
sis export-features --path dataset/ --glob "*.pdf" \
  --extended \
  --with-findings \
  --format jsonl \
  -o dataset_extended.jsonl

# Export enhanced IR/ORG for graph ML
sis export-ir --path dataset/ --glob "*.pdf" \
  --enhanced \
  --with-summary \
  --format jsonl \
  -o dataset_ir_enhanced.jsonl

sis export-org --path dataset/ --glob "*.pdf" \
  --enhanced \
  --with-paths \
  --format jsonl \
  -o dataset_org_enhanced.jsonl
```

### 5.2: Baseline Computation

```rust
// Utility to compute benign baseline from training set

pub fn compute_benign_baseline(
    benign_samples: &[ExtendedFeatureVector],
) -> BenignBaseline {
    let n = benign_samples.len() as f32;
    let feature_names = ExtendedFeatureVector::feature_names();
    let n_features = feature_names.len();

    // Collect all feature values
    let mut feature_values: Vec<Vec<f32>> = vec![Vec::new(); n_features];
    for sample in benign_samples {
        for (i, value) in sample.as_f32_vec().iter().enumerate() {
            feature_values[i].push(*value);
        }
    }

    // Compute statistics
    let mut feature_means = HashMap::new();
    let mut feature_stddevs = HashMap::new();
    let mut feature_percentiles = HashMap::new();

    for (i, name) in feature_names.iter().enumerate() {
        let values = &mut feature_values[i];

        // Mean
        let mean = values.iter().sum::<f32>() / n;

        // Stddev
        let variance = values.iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f32>() / n;
        let stddev = variance.sqrt();

        // Percentiles
        values.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let percentiles = vec![
            values[(n * 0.10) as usize],  // P10
            values[(n * 0.25) as usize],  // P25
            values[(n * 0.50) as usize],  // P50
            values[(n * 0.75) as usize],  // P75
            values[(n * 0.90) as usize],  // P90
            values[(n * 0.95) as usize],  // P95
            values[(n * 0.99) as usize],  // P99
        ];

        feature_means.insert(name.clone(), mean);
        feature_stddevs.insert(name.clone(), stddev);
        feature_percentiles.insert(name.clone(), percentiles);
    }

    BenignBaseline {
        feature_means,
        feature_stddevs,
        feature_percentiles,
    }
}

// CLI command
pub fn run_compute_baseline(
    input_path: &Path,
    output_path: &Path,
) -> Result<()> {
    // Load benign samples
    let samples = load_feature_vectors(input_path)?;

    // Compute baseline
    let baseline = compute_benign_baseline(&samples);

    // Save to file
    let json = serde_json::to_string_pretty(&baseline)?;
    std::fs::write(output_path, json)?;

    println!("Benign baseline saved to {}", output_path.display());
    Ok(())
}
```

### 5.3: Calibration Model Training

```python
# Python training script (external)

import json
import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression

def train_calibration_model(y_true, y_pred_raw, method='isotonic'):
    """
    Train calibration model on validation set

    Args:
        y_true: Ground truth labels (0/1)
        y_pred_raw: Raw model predictions (0-1)
        method: 'isotonic' or 'platt'

    Returns:
        calibration_model: Dict with calibration parameters
    """
    if method == 'platt':
        # Platt scaling: fit logistic regression
        lr = LogisticRegression()
        lr.fit(y_pred_raw.reshape(-1, 1), y_true)

        return {
            'method': 'PlattScaling',
            'a': float(lr.coef_[0][0]),
            'b': float(lr.intercept_[0])
        }

    elif method == 'isotonic':
        # Isotonic regression
        iso = IsotonicRegression(out_of_bounds='clip')
        iso.fit(y_pred_raw, y_true)

        return {
            'method': 'IsotonicRegression',
            'x': iso.X_.tolist(),
            'y': iso.y_.tolist()
        }

# Usage
y_true = np.array([0, 0, 1, 1, 0, 1, ...])  # Validation labels
y_pred = np.array([0.1, 0.2, 0.8, 0.9, ...])  # Raw predictions

calibration_model = train_calibration_model(y_true, y_pred, method='isotonic')

# Save
with open('calibration_model.json', 'w') as f:
    json.dump(calibration_model, f)
```

### 5.4: Deliverables

- [ ] Export commands for extended features, enhanced IR/ORG
- [ ] Benign baseline computation utility
- [ ] Calibration model training scripts (Python)
- [ ] Documentation for training pipeline
- [ ] Example notebooks for model training

---

## Phase 6: Inference Integration with Comprehensive Explanations (2 weeks)

**Goal**: Use all enhanced signals during inference and generate complete explanations

### 6.1: Unified Inference Pipeline

```rust
// crates/sis-pdf-core/src/ml_inference.rs (new or extend existing)

pub struct MlInferenceConfig {
    pub model_path: PathBuf,
    pub baseline_path: PathBuf,
    pub calibration_path: Option<PathBuf>,
    pub threshold: f32,
    pub explain: bool,
}

pub struct MlInferenceResult {
    pub prediction: CalibratedPrediction,
    pub risk_profile: DocumentRiskProfile,
    pub explanation: Option<ComprehensiveExplanation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveExplanation {
    pub summary: String,
    pub feature_attribution: Vec<FeatureAttribution>,
    pub feature_group_importance: HashMap<String, f32>,
    pub comparative_analysis: Vec<ComparativeFeature>,
    pub graph_paths: Option<GraphPathExplanation>,
    pub evidence_chains: Vec<EvidenceChain>,
    pub decision_factors: Vec<String>,  // Bullet points
}

pub fn run_ml_inference(
    ctx: &ScanContext,
    findings: &[Finding],
    config: &MlInferenceConfig,
) -> Result<MlInferenceResult> {
    // 1. Extract extended features
    let features = extract_extended_features(ctx, findings);

    // 2. Load baseline
    let baseline = BenignBaseline::load_from_file(&config.baseline_path)?;

    // 3. Run model prediction
    // (Simplified - actual implementation would load ONNX/model)
    let raw_prediction = 0.87;  // Placeholder

    // 4. Calibrate prediction
    let calibrated = if let Some(cal_path) = &config.calibration_path {
        let calibrator = CalibrationModel::load_from_file(cal_path)?;
        calibrate_prediction(raw_prediction, &calibrator)
    } else {
        CalibratedPrediction {
            raw_score: raw_prediction,
            calibrated_score: raw_prediction,
            confidence_interval: (raw_prediction - 0.05, raw_prediction + 0.05),
            calibration_method: "none".to_string(),
            interpretation: format!("{:.0}% risk", raw_prediction * 100.0),
        }
    };

    // 5. Generate explanation (if requested)
    let explanation = if config.explain {
        // Feature attribution
        let model_fn = |f: &ExtendedFeatureVector| -> f32 {
            // Run model on features
            0.87  // Placeholder
        };
        let attribution = compute_permutation_importance(&model_fn, &features, &baseline, 100);

        // Natural language summary
        let summary = generate_explanation_text(
            calibrated.calibrated_score,
            &attribution,
            findings
        );

        // Feature group importance
        let mut group_importance = HashMap::new();
        for attr in &attribution {
            let group = attr.feature_name.split('.').next().unwrap_or("other");
            *group_importance.entry(group.to_string()).or_insert(0.0) += attr.contribution.abs();
        }

        // Comparative analysis
        let comparative = compute_comparative_explanation(&features, &baseline, 10);

        // Graph paths
        let graph_paths = if findings.iter().any(|f| f.surface == AttackSurface::Actions) {
            let typed_graph = ctx.build_typed_graph();
            Some(extract_suspicious_paths(&typed_graph, findings, None))
        } else {
            None
        };

        // Evidence chains
        let evidence_chains = build_evidence_chains(&attribution, findings);

        // Decision factors (bullet points)
        let decision_factors = generate_decision_factors(
            &attribution,
            &comparative,
            &graph_paths,
            findings
        );

        Some(ComprehensiveExplanation {
            summary,
            feature_attribution: attribution.into_iter().take(10).collect(),
            feature_group_importance: group_importance,
            comparative_analysis: comparative,
            graph_paths,
            evidence_chains: evidence_chains.into_iter().take(10).collect(),
            decision_factors,
        })
    } else {
        None
    };

    // 6. Build risk profile
    let risk_profile = build_document_risk_profile(ctx, findings, &features, &explanation);

    Ok(MlInferenceResult {
        prediction: calibrated,
        risk_profile,
        explanation,
    })
}

fn generate_decision_factors(
    attribution: &[FeatureAttribution],
    comparative: &[ComparativeFeature],
    graph_paths: &Option<GraphPathExplanation>,
    findings: &[Finding],
) -> Vec<String> {
    let mut factors = Vec::new();

    // Top features
    for attr in attribution.iter().take(3) {
        factors.push(format!(
            "{} (value: {:.2}, contribution: {:+.2})",
            humanize_feature_name(&attr.feature_name),
            attr.value,
            attr.contribution
        ));
    }

    // Extreme outliers
    for comp in comparative.iter().take(2) {
        if comp.z_score > 3.0 {
            factors.push(format!(
                "{} is extremely high ({:.1}σ above benign average)",
                humanize_feature_name(&comp.feature_name),
                comp.z_score
            ));
        }
    }

    // Graph paths
    if let Some(paths) = graph_paths {
        if let Some(top_path) = paths.suspicious_paths.first() {
            factors.push(format!(
                "Suspicious path detected: {}",
                top_path.explanation
            ));
        }
    }

    // High-severity findings
    let high_count = findings.iter()
        .filter(|f| f.severity == Severity::High || f.severity == Severity::Critical)
        .count();
    if high_count > 0 {
        factors.push(format!("{} high/critical severity findings", high_count));
    }

    factors
}
```

### 6.2: CLI Integration

```bash
# Scan with ML and explanations
sis scan malicious.pdf --ml --explain --json -o result.json

# Export comprehensive explanation
sis explain-ml malicious.pdf \
  --model models/classifier.onnx \
  --baseline models/benign_baseline.json \
  --calibration models/calibration.json \
  --format json \
  -o explanation.json

# Generate decision path visualization
sis explain-ml malicious.pdf \
  --model models/classifier.onnx \
  --baseline models/benign_baseline.json \
  --decision-path \
  --format dot \
  -o decision_path.dot

# Render with GraphViz
dot -Tpng decision_path.dot -o decision_path.png
```

### 6.3: Report Integration

```rust
// Add ML explanation section to reports

pub fn format_ml_explanation_for_report(
    explanation: &ComprehensiveExplanation,
    prediction: &CalibratedPrediction,
) -> String {
    let mut report = String::new();

    report.push_str("## ML Analysis\n\n");

    // Prediction
    report.push_str(&format!(
        "**Prediction**: {:.2} ({})\n\n",
        prediction.calibrated_score,
        prediction.interpretation
    ));

    // Summary
    report.push_str(&format!("### Summary\n\n{}\n\n", explanation.summary));

    // Key Decision Factors
    report.push_str("### Key Decision Factors\n\n");
    for factor in &explanation.decision_factors {
        report.push_str(&format!("- {}\n", factor));
    }
    report.push_str("\n");

    // Feature Attribution
    report.push_str("### Top Contributing Features\n\n");
    report.push_str("| Feature | Value | Contribution | Baseline |\n");
    report.push_str("|---------|-------|--------------|----------|\n");
    for attr in explanation.feature_attribution.iter().take(10) {
        report.push_str(&format!(
            "| {} | {:.2} | {:+.2} | {:.2} |\n",
            humanize_feature_name(&attr.feature_name),
            attr.value,
            attr.contribution,
            attr.baseline
        ));
    }
    report.push_str("\n");

    // Comparative Analysis
    if !explanation.comparative_analysis.is_empty() {
        report.push_str("### Comparison with Benign Files\n\n");
        for comp in explanation.comparative_analysis.iter().take(5) {
            report.push_str(&format!(
                "- **{}**: {:.2} (benign average: {:.2}, z-score: {:.1}σ) - {}\n",
                humanize_feature_name(&comp.feature_name),
                comp.value,
                comp.benign_mean,
                comp.z_score,
                comp.interpretation
            ));
        }
        report.push_str("\n");
    }

    // Graph Paths
    if let Some(paths) = &explanation.graph_paths {
        report.push_str("### Suspicious Graph Paths\n\n");
        for path in paths.suspicious_paths.iter().take(3) {
            report.push_str(&format!(
                "- **{}** (risk: {:.2})\n",
                path.explanation,
                path.risk_score
            ));
            report.push_str("  Path: ");
            for (i, node) in path.path.iter().enumerate() {
                if i > 0 { report.push_str(" → "); }
                report.push_str(&format!("{} {}", node.obj_ref.0, node.obj_ref.1));
            }
            report.push_str("\n");
        }
        report.push_str("\n");
    }

    // Evidence Chains
    if !explanation.evidence_chains.is_empty() {
        report.push_str("### Evidence Chains\n\n");
        for chain in explanation.evidence_chains.iter().take(5) {
            report.push_str(&format!(
                "- **{}** → Findings: {} → Evidence spans: {}\n",
                humanize_feature_name(&chain.feature_name),
                chain.derived_from_findings.join(", "),
                chain.evidence_spans.len()
            ));
        }
    }

    report
}
```

### 6.4: Deliverables

- [ ] Unified ML inference pipeline
- [ ] Comprehensive explanation generation
- [ ] CLI commands for ML inference with explanations
- [ ] Report integration
- [ ] Decision path visualization
- [ ] Full end-to-end testing
- [ ] Documentation and usage examples

---

## Phase 7 (Optional): Advanced Explainability Features (2 weeks)

### 7.1: Counterfactual Explanations

```rust
pub fn generate_counterfactual(
    model: &dyn Fn(&ExtendedFeatureVector) -> f32,
    features: &ExtendedFeatureVector,
    target_score: f32,
    max_changes: usize,
) -> CounterfactualExplanation {
    // Gradient-based or genetic algorithm search
    // Find minimal feature changes to reach target score
}
```

### 7.2: Temporal Explanations

```rust
pub fn analyze_temporal_risk(
    incremental_updates: &[IncrementalUpdate],
    findings_by_version: &[Vec<Finding>],
) -> TemporalExplanation {
    // Track risk evolution across document versions
}
```

### 7.3: Feature Interaction Detection

```rust
pub fn detect_feature_interactions(
    features: &ExtendedFeatureVector,
    findings: &[Finding],
) -> Vec<FeatureInteraction> {
    // Detect synergistic feature combinations
}
```

---

## Testing Strategy

### Unit Tests

```rust
// Feature extraction
#[test] fn test_extended_feature_dimensions() { /* ... */ }
#[test] fn test_js_feature_extraction() { /* ... */ }
#[test] fn test_uri_feature_extraction() { /* ... */ }

// Explainability
#[test] fn test_feature_attribution_stability() { /* ... */ }
#[test] fn test_evidence_chain_completeness() { /* ... */ }
#[test] fn test_natural_language_generation() { /* ... */ }
#[test] fn test_calibration_correctness() { /* ... */ }

// Graph paths
#[test] fn test_suspicious_path_extraction() { /* ... */ }
#[test] fn test_path_risk_scoring() { /* ... */ }
#[test] fn test_attack_pattern_classification() { /* ... */ }
```

### Integration Tests

```rust
#[test]
fn test_end_to_end_ml_with_explanation() {
    let bytes = include_bytes!("fixtures/malicious.pdf");
    let ctx = ScanContext::new(bytes).unwrap();
    let findings = run_all_detectors(&ctx).unwrap();

    let config = MlInferenceConfig {
        model_path: "models/test.onnx".into(),
        baseline_path: "models/test_baseline.json".into(),
        calibration_path: Some("models/test_calibration.json".into()),
        threshold: 0.5,
        explain: true,
    };

    let result = run_ml_inference(&ctx, &findings, &config).unwrap();

    assert!(result.explanation.is_some());
    let explanation = result.explanation.unwrap();
    assert!(!explanation.summary.is_empty());
    assert!(!explanation.feature_attribution.is_empty());
    assert!(!explanation.evidence_chains.is_empty());
}
```

### Performance Tests

```rust
#[test]
fn bench_extended_feature_extraction() {
    // Measure extraction time
    // Target: <10ms per file
}

#[test]
fn bench_explanation_generation() {
    // Measure explanation overhead
    // Target: <100ms per file with full explanation
}
```

### Accuracy Validation

```python
# Python script for model validation

def validate_calibration(y_true, y_pred_calibrated):
    """Check calibration error"""
    from sklearn.calibration import calibration_curve

    prob_true, prob_pred = calibration_curve(y_true, y_pred_calibrated, n_bins=10)
    calibration_error = np.mean(np.abs(prob_true - prob_pred))

    assert calibration_error < 0.05, f"Calibration error {calibration_error} too high"

def validate_explanation_faithfulness(model, X, explanations):
    """Check if explanations accurately reflect model behavior"""
    for i, (x, explanation) in enumerate(zip(X, explanations)):
        # Perturb top features according to explanation
        # Verify prediction changes as expected
        pass
```

---

## Success Metrics

### Quantitative

**ML Performance**:
- Detection rate: Increase TPR by 10-20%
- False positives: Reduce FPR by 15-25%
- F1 Score: Improve by 12-18%
- AUC-ROC: Improve by 0.05-0.10

**Explainability**:
- Explanation coverage: >90% of predictions have ≥3 features
- Evidence linking: >95% of features link to evidence spans
- Calibration error: <0.05 on validation set
- Explanation overhead: <20% of inference time

### Qualitative

**Analyst Experience**:
- Can answer "Why is this suspicious?" in <30 seconds
- Reduce false positive investigation time by >30%
- Increase inter-analyst agreement on threat severity

**Operational**:
- Explanations cited in 80%+ of escalation reports
- Zero complaints about "black box" ML decisions
- Positive feedback from SOC analysts

---

## Implementation Checklist

### Code
- [ ] Phase 1: Extended features + attribution + summaries + evidence (3 weeks)
- [ ] Phase 2: Enhanced IR with semantic annotations (2 weeks)
- [ ] Phase 3: Enhanced ORG with graph paths (2 weeks)
- [ ] Phase 4: Risk profiles + calibration + comparative (2 weeks)
- [ ] Phase 5: Training pipeline integration (2 weeks)
- [ ] Phase 6: Inference integration (2 weeks)
- [ ] Phase 7 (Optional): Advanced explainability (2 weeks)

**Total**: 13-15 weeks

### Documentation
- [ ] Update `docs/modeling.md` with extended features and explainability
- [ ] Document all 320 features with descriptions
- [ ] Create explainability guide for analysts
- [ ] Add training pipeline documentation
- [ ] Create example notebooks

### Training Infrastructure
- [ ] Baseline computation scripts
- [ ] Calibration model training scripts
- [ ] Attribution validation scripts
- [ ] Performance benchmarking suite

---

## Migration Path

### Backward Compatibility

- Keep existing 35-feature FeatureVector (legacy mode)
- Add ExtendedFeatureVector as opt-in with `--extended` flag
- Maintain basic IR/ORG export formats
- Enhanced formats require `--enhanced` flag
- Explainability requires `--explain` flag

### Gradual Rollout

1. **Phase 1-2 (Months 1-2)**: Deploy extended features, no breaking changes
2. **Phase 3-4 (Months 2-3)**: Deploy enhanced IR/ORG, old formats still work
3. **Phase 5 (Month 4)**: Train new models on enhanced data
4. **Phase 6 (Month 4)**: Production inference with explanations
5. **Phase 7 (Month 5)**: Advanced explainability features

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| 320 features may overfit | High | Use regularization, feature selection, cross-validation |
| Explanation overhead slows inference | Medium | Make explanations opt-in, optimize attribution algorithms |
| Natural language summaries may be misleading | High | Template carefully, validate with analysts, add disclaimers |
| Calibration may not generalize | Medium | Use large validation set, monitor calibration in production |
| Evidence chains may break with detector changes | Low | Enforce evidence tracking in detector interface contracts |
| Attribution may be unstable | Medium | Use ensemble attribution methods, test stability |

---

## Dependencies

**Completed**:
- ✅ Graph integration (all 7 sprints)

**External**:
- Python environment for training scripts (scikit-learn, PyTorch/TF)
- GraphViz for decision path visualization
- ONNX Runtime for model inference (if using ONNX)

**Optional**:
- PyO3 for Rust-Python integration (for SHAP)
- Native SHAP implementation in Rust (TreeSHAP)

---

## Conclusion

This integrated plan combines ML signal enhancement (35→320 features, enhanced IR/ORG) with comprehensive explainability (attribution, natural language, graph paths, evidence linking, calibration) into a cohesive implementation strategy.

**Key Benefits**:
1. **Richer signals**: 320 features from all detectors + semantic annotations
2. **Interpretability**: Feature attribution, natural language explanations, evidence chains
3. **Actionability**: Graph paths, comparative analysis, calibrated probabilities
4. **Analyst-friendly**: Built for security operations, not just ML researchers
5. **Incremental**: Each phase delivers value independently

The phased approach allows for gradual rollout while maintaining backward compatibility. By building explainability into each phase from the start, we ensure ML predictions are operationally useful, not just accurate.

**Next Steps**: Begin Phase 1 implementation (Extended Features + Attribution + Summaries + Evidence).
