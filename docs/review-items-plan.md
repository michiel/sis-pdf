# sis-pdf Review Items Implementation Plan

This plan converts every review item, evasion technique, and detection capability from `docs/review-items.md` into concrete, technical implementation steps. It is written for the existing `sis-pdf` workspace layout.

## 0) Baseline Prep

- Add a dedicated tracking document section in `docs/plan.md` that references this plan.
- Ensure naming consistency: crate prefixes `sis-pdf-*`, CLI `sis`, finding IDs `sis-*`.
- Add feature flags for any heavy or optional components (ML, sandbox, dataset).

## 1) Machine Learning (Stacking Classifier)

### 1.1 Feature extraction layer

- Add a new module: `crates/sis-pdf-core/src/features.rs`.
- Implement `FeatureVector` with fields grouped as:
  - General (file size, entropy, % binary, object count)
  - Structural (xref count, objstm count, xref anomalies, linearization flags)
  - Behavioral (action counts, JS entropy, JS suspicious API counts)
  - Content (embedded file count, rich media presence, annotation counts)
- Implement `FeatureExtractor::extract(&ObjectGraph, &ScanContext) -> FeatureVector`.
- Add serialization: `serde` for JSON dumps and dataset export.

### 1.2 Model interface

- Add `crates/sis-pdf-core/src/ml.rs` with:
  - `trait BaseClassifier { fn predict(&self, fv: &FeatureVector) -> f32; }`
  - `trait MetaClassifier { fn predict(&self, base: &[f32]) -> f32; }`
  - `struct StackingClassifier { base: Vec<Box<dyn BaseClassifier>>, meta: Box<dyn MetaClassifier> }`
  - `fn predict(&self, fv: &FeatureVector) -> MalwarePrediction`
- Define `MalwarePrediction { score: f32, label: bool, threshold: f32 }`.

### 1.3 Model storage and loading

- Add `crates/sis-pdf-core/src/ml_models.rs` to load models from on-disk artifacts.
- Choose a portable format (e.g., JSON coefficients for LR, or ONNX if allowed).
- Add CLI flags:
  - `--ml`, `--ml-model-dir`, `--ml-threshold` in `crates/sis-pdf/src/main.rs`.
- Emit a new finding type when ML score exceeds threshold:
  - `kind = "ml_malware_score_high"`, `surface = AttackSurface::Meta`.

### 1.4 Training pipeline (offline)

- Add `tools/` or `scripts/` (new) for feature extraction to CSV/JSON.
- Implement `cargo run -p sis-pdf --bin sis -- export-features ...` subcommand.
- Document training workflow in `docs/review-items-plan.md` and `docs/plan.md`.

## 2) Missing Detection Capabilities

### 2.1 Linearization abuse detection

- Add `LinearizationDetector` in `crates/sis-pdf-detectors/src/linearization.rs`.
- Scan for `/Linearized` dictionary and suspicious values:
  - Invalid `L`, `H`, `O`, `E`, `N` values vs file length.
  - Multiple linearization dictionaries.
  - Linearized hint tables with malformed offsets.
- Add findings:
  - `linearization_invalid`, `linearization_multiple`, `linearization_hint_anomaly`.
- Add tests with synthetic linearized PDFs in `crates/sis-pdf-core/tests/fixtures/`.

### 2.2 Font embedding exploits

- Add `FontExploitDetector` in `crates/sis-pdf-detectors/src/font_exploits.rs`.
- Identify risky font patterns:
  - Suspicious /FontFile2 /FontFile3 sizes.
  - Known exploit signatures (CVE-2010-2883 patterns, malformed CFF).
  - Overlarge glyph tables or inconsistent lengths.
- Add `font_payload_present`, `font_table_anomaly` findings.

### 2.3 ICC profile / color space attacks

- Add `ICCProfileDetector` in `crates/sis-pdf-detectors/src/icc_profiles.rs`.
- Parse `/ICCBased` color spaces:
  - Validate profile length vs stream length.
  - Check for known exploit markers, oversized profiles, or invalid headers.
- Add findings: `icc_profile_anomaly`, `icc_profile_oversized`.

### 2.4 Advanced annotation attacks

- Add `AnnotationAttackDetector` in `crates/sis-pdf-detectors/src/annotations_advanced.rs`.
- Check annotations for:
  - `/AA` chains in widgets and links.
  - Hidden/invisible annotations (zero-size or outside page bounds).
  - Abnormal `/AP` (appearance streams) with scripts.
- Add findings: `annotation_hidden`, `annotation_action_chain`.

### 2.5 Page tree manipulations

- Add `PageTreeManipulationDetector` in `crates/sis-pdf-detectors/src/page_tree_anomalies.rs`.
- Detect:
  - Cycles in page tree.
  - Page count mismatches.
  - Orphaned pages or duplicate refs.
- Add findings: `page_tree_cycle`, `page_tree_mismatch`.

### 2.6 Polymorphic / metamorphic JavaScript

- Add `PolymorphicJSDetector` in `crates/sis-pdf-detectors/src/js_polymorphic.rs`.
- Techniques:
  - Detect dynamic string assembly patterns (concat chains, arithmetic char codes).
  - Track multiple encoding layers (hex, base64, escaped strings).
  - Detect code that self-modifies or rewrites via `eval` + `Function`.
- Add findings: `js_polymorphic`, `js_multi_stage_decode`.

## 3) Evasion Handling Enhancements

### 3.1 Time-based evasion

- Add `TimingEvasionDetector` in `crates/sis-pdf-detectors/src/evasion_time.rs`.
- JS heuristic detection:
  - `Date`, `performance.now`, `setTimeout`, `setInterval` loops.
  - Long or repeated delays before action execution.
- Tag finding meta with `time_threshold_ms` and `delay_count`.
- Finding: `js_time_evasion`.

### 3.2 Environment fingerprinting detection

- Add `EnvProbeDetector` in `crates/sis-pdf-detectors/src/evasion_env.rs`.
- Detect JS probing for:
  - Viewer name/version, platform, language.
  - Screen size or display settings.
  - Registry or filesystem probes (Acrobat APIs).
- Finding: `js_env_probe`.

### 3.3 Advanced obfuscation deobfuscation

- Extend JS analysis pipeline:
  - Add a decode/normalize pass in `crates/sis-pdf-detectors/src/js_signals.rs`.
  - Support multiple decode attempts with max size limits.
  - Emit `payload.decoded_preview` and `payload.decode_layers`.
- Finding: `js_obfuscation_deep`.

### 3.4 Parser differential attacks (beyond basic compare)

- Add multi-parser delta analysis:
  - Extend `crates/sis-pdf-core/src/diff.rs` to include structural deltas (xref, objstm, missing objects).
  - Add a finding for high divergence: `parser_diff_structural`.
- Include a compact diff summary in report meta.

## 4) Dynamic Analysis (Optional Feature)

### 4.1 JavaScript sandbox execution

- Add `sis-pdf-js-sandbox` optional crate or module with feature flag `js-sandbox`.
- Provide a minimal JS engine integration (e.g., `boa_engine`) with hooks:
  - Capture network intents (`app.launchURL`, `submitForm`, `getURL`).
  - Capture file/registry probes if exposed by the PDF JS API bindings.
- Add a `BehaviorTrace` object to record calls and timings.
- Add findings: `js_runtime_network_intent`, `js_runtime_file_probe`.

### 4.2 Safe runtime constraints

- Enforce execution limits: step count, time budget, memory cap.
- Disable or stub filesystem/network access by default.

## 5) Dataset Integration (Evasive-PDFMal2022)

- Add a `datasets/` entry in docs describing how to store the dataset locally.
- Add a feature extractor CLI to output dataset features:
  - `sis export-features --path <dataset> --glob "*.pdf"`.
- Add evaluation script (offline) to compute metrics:
  - Accuracy, precision/recall, ROC.
- Document data licensing requirements.

## 6) Performance Enhancements

### 6.1 Cached analysis

- Add `AnalysisCache` trait in `crates/sis-pdf-core/src/cache.rs` (existing file can be extended).
- Implement file-hash-based cache with:
  - Feature vectors
  - Report outputs
- Add CLI flags `--cache-dir` and `--cache-mode` (already exists in CLI, extend semantics).

### 6.2 Parallel batch scanning improvements

- In `crates/sis-pdf/src/main.rs`, apply per-file concurrency limits and reuse detectors.
- Avoid repeated parsing for report + extraction flows.

## 7) Behavioral Correlation Engine

- Add `crates/sis-pdf-core/src/behavior.rs`.
- Implement:
  - `BehaviorCorrelator::correlate(&[Finding]) -> Vec<ThreatPattern>`
  - `ThreatPattern` to group related findings across surfaces.
  - `score_exploit_chains` to use existing chain synthesis + new weights.
- Extend report to include a correlation summary section.

## 8) Reporting & UX Updates

- Add new finding kinds to:
  - `crates/sis-pdf-core/src/report.rs` descriptions
  - SARIF tags in `crates/sis-pdf-core/src/sarif.rs`
  - YARA metadata if relevant in `crates/sis-pdf-core/src/yara.rs`
- Update `README.md` and `USAGE.md` for new flags and capabilities.

## 9) Test Plan

- Add unit tests for each detector:
  - `crates/sis-pdf-core/tests/*.rs`
- Add fixtures:
  - Linearized PDF, ICC profiles, font payloads, annotation evasion, page tree anomalies.
- Add JS samples for evasion and polymorphic detection.
- Add integration tests for ML score path (mock models).

## 10) Delivery Phasing

1. **Phase 1 (Core coverage)**
   - Linearization, font, ICC, annotations, page tree.
   - Polymorphic JS detection.
2. **Phase 2 (Evasion + parser diff)**
   - Timing, env probes, deep obfuscation.
   - Structural parser differential checks.
3. **Phase 3 (ML + dataset)**
   - Feature extraction, model loading, CLI integration.
4. **Phase 4 (Dynamic analysis + correlation)**
   - JS sandbox, behavior correlation, performance enhancements.

## 11) Acceptance Criteria

- All new findings appear in JSON, SARIF, and Markdown reports.
- Feature extraction outputs stable JSON across runs.
- Evasion detectors trigger on fixtures with exact evidence spans.
- ML path can be toggled on/off without affecting baseline results.
- No regressions in existing tests.
