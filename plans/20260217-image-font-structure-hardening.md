# Image and Font Structural Hardening Plan

Date: 2026-02-17  
Status: Planned  
Scope: `sis-pdf-pdf`, `sis-pdf-detectors`, `sis-pdf-core`, `image-analysis`, `font-analysis`, fixtures, docs

## Objective

Close detection and safety gaps where image/font behaviour depends on PDF object graph structure, revision provenance, and resource-chain semantics, while preserving deterministic runtime and large-corpus throughput.

This plan complements `plans/20260217-image-robustness.md` (content-level hardening) with structure-level and correlation hardening.

## Security Priorities

1. Detect structure-driven evasions (incremental updates, resource indirection, object stream provenance).
2. Strengthen font/image dictionary-stream consistency validation.
3. Promote high-signal composite findings across structure + content anomalies.
4. Preserve bounded parsing and stable triage metadata.

## Confirmed Gaps

1. Provenance signals (incremental revision/object-stream/xref conflicts) are not first-class inputs to image/font risk scoring.
2. Page resource-chain semantics for image/font reachability are shallow (orphaned/hidden/nested paths under-analysed).
3. Font dictionary and stream consistency checks are incomplete for high-value keys (`/FontDescriptor`, `/ToUnicode`, `/CIDToGIDMap`, `/Encoding`, `/DescendantFonts`).
4. Image dictionary-stream consistency checks need stronger structural validation (`/Filter`, `/DecodeParms`, `/ColorSpace`, `/SMask`, `/ImageMask`).
5. External reference normalisation and protocol/path abuse detection should be centralised and reused across image/font contexts.
6. Composite findings that join structure and content signals are sparse.
7. Confidence/severity calibration for structural anomalies is not explicitly normalised.

## Implementation Stages

## Stage 1: Provenance Signal Extraction for Image/Font Objects

**Goal**: Track where image/font objects come from and surface suspicious provenance.

### Changes

- `crates/sis-pdf-pdf/src/typed_graph.rs`
  - Extend edge/object metadata extraction with provenance fields:
    - revision index/generation visibility
    - object stream origin markers
    - xref conflict markers affecting object identity
- `crates/sis-pdf-detectors/src/image_analysis.rs`
- `crates/sis-pdf-detectors/src/font_exploits.rs`
  - Attach provenance metadata to emitted findings when available.

### New Findings (proposed)

1. `image.provenance_incremental_override`
   - Severity: Medium
   - Impact: Medium
   - Confidence: Strong
2. `font.provenance_incremental_override`
   - Severity: Medium
   - Impact: Medium
   - Confidence: Strong
3. `resource.provenance_xref_conflict`
   - Severity: High
   - Impact: High
   - Confidence: Probable

### Tests

- Add fixtures with benign base revision plus suspicious later revision for image and font resources.
- Assert finding kind + severity + confidence + provenance metadata keys.

### Acceptance

- Provenance is queryable and reflected in image/font findings.
- Incremental override patterns are no longer silent.

## Stage 2: Resource-Chain Reachability and Hidden Resource Paths

**Goal**: Detect image/font resources reachable through suspicious indirection patterns.

### Changes

- `crates/sis-pdf-pdf/src/typed_graph.rs`
  - Add semantic path extraction for:
    - page -> resources -> xobject/font
    - nested Form XObject resources
    - descendant font chains (`/DescendantFonts`, `/FontDescriptor`)
- `crates/sis-pdf-detectors/src/passive_render_pipeline.rs`
  - Consume semantic path features and classify hidden/indirect render paths.

### New Findings (proposed)

1. `resource.hidden_render_path`
   - Severity: Medium
   - Impact: Medium
   - Confidence: Probable
2. `font.orphaned_but_reachable`
   - Severity: Low
   - Impact: Low
   - Confidence: Tentative
3. `image.orphaned_but_reachable`
   - Severity: Low
   - Impact: Low
   - Confidence: Tentative

### Tests

- Regression fixtures with nested form resources carrying image/font payloads.
- Queries asserting semantic edge presence and detector emission.

### Acceptance

- Reachability semantics are explicit and test-covered.
- Hidden render paths emit predictable findings.

## Stage 3: Font Structural Consistency Hardening

**Goal**: Detect malicious or contradictory font object structures even when raw font bytes appear valid.

### Changes

- `crates/sis-pdf-detectors/src/font_exploits.rs`
  - Add consistency validation across:
    - `/Subtype` vs embedded stream type
    - `/Encoding` compatibility
    - `/ToUnicode` stream sanity and mapping contradictions
    - `/CIDToGIDMap` anomalies
    - declared lengths vs decoded stream behaviour
- `crates/font-analysis/src/lib.rs`
- `crates/font-analysis/src/static_scan.rs`
  - Expose additional signals for detector correlation (not only format anomalies).

### New Findings (proposed)

1. `font.structure_subtype_mismatch`
   - Severity: High
   - Impact: High
   - Confidence: Probable
2. `font.structure_encoding_inconsistent`
   - Severity: Medium
   - Impact: Medium
   - Confidence: Strong
3. `font.structure_mapping_anomalous`
   - Severity: Medium
   - Impact: Medium
   - Confidence: Probable

### Tests

- Add font fixtures with controlled dictionary contradictions.
- Ensure benign fonts do not emit new findings.

### Acceptance

- Dictionary/stream contradictions are surfaced with stable metadata.

## Stage 4: Image Structural Consistency Hardening

**Goal**: Detect evasive image dictionary/stream contradictions tied to PDF semantics.

### Changes

- `crates/image-analysis/src/static_analysis.rs`
- `crates/image-analysis/src/dynamic.rs`
  - Add checks for:
    - `/Filter` and `/DecodeParms` plausibility vs decoded data
    - `/ColorSpace` indirection abuse across object graph
    - `/SMask` and `/ImageMask` consistency
    - impossible geometry/depth combinations used as stress signals
- `crates/sis-pdf-detectors/src/image_analysis.rs`
  - map new findings and remediation text.

### New Findings (proposed)

1. `image.structure_filter_chain_inconsistent`
   - Severity: Medium
   - Impact: Medium
   - Confidence: Strong
2. `image.structure_mask_inconsistent`
   - Severity: Medium
   - Impact: Medium
   - Confidence: Probable
3. `image.structure_geometry_improbable`
   - Severity: Low
   - Impact: Low
   - Confidence: Tentative

### Tests

- Fixtures for inconsistent mask/filter combinations.
- High-dimension edge cases bounded by safety limits.

### Acceptance

- Structure-level image anomalies are detected without substantial false-positive growth.

## Stage 5: External Reference Canonicalisation and Abuse Detection

**Goal**: Unify external target normalisation for image/font detectors and improve protocol/path abuse coverage.

### Changes

- `crates/sis-pdf-detectors/src/font_external_ref.rs`
- `crates/sis-pdf-detectors/src/passive_render_pipeline.rs`
  - Introduce shared normalisation helper for URI/path targets:
    - protocol canonicalisation
    - relative path and encoding normalisation
    - suspicious scheme/path pattern flags
- Reuse same normaliser in image-related external reference checks.

### New Findings (proposed)

1. `resource.external_reference_obfuscated`
   - Severity: Medium
   - Impact: Medium
   - Confidence: Probable
2. `resource.external_reference_high_risk_scheme`
   - Severity: High
   - Impact: High
   - Confidence: Strong

### Tests

- Parameterised tests for obfuscated equivalent URIs and path variants.
- Regression fixtures with benign HTTP/HTTPS and suspicious schemes.

### Acceptance

- Equivalent malicious targets normalise to consistent detector outcomes.

## Stage 6: Composite Correlation Findings (Structure + Content)

**Goal**: Raise confidence when multiple suspicious signals co-occur.

### Changes

- `crates/sis-pdf-core/src/correlation.rs`
  - Add composite correlators for:
    - suspicious provenance + font/image structural anomaly
    - hidden render path + content anomaly
    - external reference risk + trigger surface
- Ensure composite findings include source finding IDs in metadata.

### New Findings (proposed)

1. `composite.font_structure_with_provenance_evasion`
   - Severity: High
   - Impact: High
   - Confidence: Strong
2. `composite.image_structure_with_hidden_path`
   - Severity: High
   - Impact: High
   - Confidence: Strong
3. `composite.resource_external_with_trigger_surface`
   - Severity: High
   - Impact: High
   - Confidence: Strong

### Tests

- Integration tests in `crates/sis-pdf-core/tests/` asserting composite creation and metadata invariants.

### Acceptance

- Composite findings materially improve triage ordering for real malicious samples.

## Stage 7: Confidence and Severity Calibration Matrix

**Goal**: Make structural findings consistent and defensible across detectors.

### Changes

- Add/extend detector mapping tables with explicit calibration guidance for:
  - deterministic structural contradictions (`Strong`/`Certain`)
  - heuristic suspicious patterns (`Tentative`/`Probable`)
- Update docs:
  - `docs/findings.md`
  - any detector-specific docs under `docs/` for image/font coverage.

### Tests

- Mapping tests asserting expected severity/impact/confidence for each new finding ID.

### Acceptance

- New finding metadata aligns with repository guidance and remains stable over regressions.

## Stage 8: Corpus, Fuzzing, and Performance Validation

**Goal**: Validate robustness at scale and guard runtime SLOs.

### Changes

- Add corpus fixtures under:
  - `crates/sis-pdf-core/tests/fixtures/corpus_captured/`
  - update `manifest.json` with `sha256`, `source_path`, `regression_targets`
- Extend fuzz targets for:
  - semantic edge extraction
  - font/image structural dictionary parsers
  - external reference normalisation
- Capture runtime profile baseline using:
  - `sis scan <fixture> --deep --runtime-profile --runtime-profile-format json`

### Tests and Commands

1. `cargo test -p sis-pdf-pdf`
2. `cargo test -p image-analysis`
3. `cargo test -p font-analysis`
4. `cargo test -p sis-pdf-detectors`
5. `cargo test -p sis-pdf-core --test corpus_captured_regressions`
6. `cargo test -p sis-pdf batch_query_supports_findings_composite_predicate -- --nocapture`
7. `cargo test -p sis-pdf execute_query_supports_findings_composite_predicate -- --nocapture`

### Acceptance

- New findings are covered by deterministic tests and corpus fixtures.
- Runtime profile remains within documented SLO envelope or deltas are documented.

## Deliverables

1. New structure-aware image/font/resource finding coverage.
2. Composite correlation findings tied to provenance and reachability semantics.
3. Updated `docs/findings.md` entries for all added finding IDs.
4. Expanded fixture manifest and provenance documentation.
5. Performance baseline notes for added checks.

## Execution Order

1. Stage 1 (provenance extraction)
2. Stage 2 (resource-chain semantics)
3. Stage 3 (font consistency)
4. Stage 4 (image consistency)
5. Stage 5 (external reference normalisation)
6. Stage 6 (composite correlation)
7. Stage 7 (calibration + docs)
8. Stage 8 (fixtures/fuzz/performance)

## Risks and Controls

1. Risk: false-positive increase from heuristic structure checks.  
   Control: gate heuristic findings at lower confidence and require corroborating metadata.
2. Risk: throughput regression from deeper path analysis.  
   Control: strict traversal budgets and runtime profile checks per stage.
3. Risk: fixture drift or weak provenance tracking.  
   Control: enforce manifest updates with sha256 and regression target annotation.
