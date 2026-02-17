# Image and Font Structural Hardening Follow-up Plan

Date: 2026-02-17  
Status: In Progress  
Scope: `sis-pdf-pdf`, `sis-pdf-detectors`, `sis-pdf-core`, `image-analysis`, `font-analysis`, corpus fixtures, fuzz

## Objective

Close remaining high-value gaps after initial image/font structural hardening, with emphasis on render semantics, inheritance conflicts, signature-aware provenance, and cross-object chain scoring.

## Security Priorities

1. Detect structure + usage evasions (declared resources vs actual operator use).
2. Improve coverage for PDF-native payload carriers (inline images, Type 3 glyph programs, CMaps).
3. Strengthen high-confidence triage for signed/incremental override abuse.
4. Preserve deterministic limits and throughput under large corpora.

## Execution Progress

- Completed: Stage 1 (content stream resource semantics detector and findings)
- Completed: Stage 2 (inline image structural checks and findings)
- Completed: Stage 3 (Type 3 charproc risk detections)
- Completed: Stage 4 (ToUnicode/CMap consistency checks)
- Completed: Stage 5 (resource inheritance conflict detection)
- Completed: Stage 6 (signature-aware override findings for image/font/resource)
- Completed: Stage 7 (decode/provenance composite correlators)
- Completed: Stage 8 (calibration guardrail tests + findings calibration notes)
- In progress: Stage 9 (fuzz/performance/corpus validation)

## Stage 1: Content Stream Operator Semantics

**Goal**: Add detection based on actual invocation of image/font resources.

### Changes

- `crates/sis-pdf-pdf/src/` (content parser module)
  - Extract lightweight operator events: `Do`, `Tf`, `gs`, clipping, transform and visibility context.
- `crates/sis-pdf-detectors/src/`
  - Add detector for declared-vs-used mismatch and hidden invocation paths.

### New Findings (proposed)

1. `resource.declared_but_unused`
   - Severity: Low
   - Impact: Low
   - Confidence: Probable
2. `resource.hidden_invocation_pattern`
   - Severity: Medium
   - Impact: Medium
   - Confidence: Probable
3. `resource.operator_usage_anomalous`
   - Severity: Medium
   - Impact: Medium
   - Confidence: Tentative

### Tests

- Fixtures with declared but unused `/XObject` and `/Font` entries.
- Fixtures with zero-area/clipped-off invocations.
- Assertions on finding kind/severity/confidence and operator metadata keys.

## Stage 2: Inline Image (`BI/ID/EI`) Structural Analysis

**Goal**: Extend image structural checks to inline image payloads.

### Changes

- `crates/sis-pdf-pdf/src/` content token parsing: extract inline image dictionaries + stream bytes.
- `crates/image-analysis/src/static_analysis.rs` / dynamic path
  - Reuse existing image structure checks for inline image dictionaries.

### New Findings (proposed)

1. `image.inline_structure_filter_chain_inconsistent`
   - Severity: Medium
   - Impact: Medium
   - Confidence: Strong
2. `image.inline_decode_array_invalid`
   - Severity: Low
   - Impact: Low
   - Confidence: Strong
3. `image.inline_mask_inconsistent`
   - Severity: Medium
   - Impact: Medium
   - Confidence: Probable

### Tests

- Inline image fixtures with malformed filter/decode/mask combinations.
- Benign inline image fixture (no finding).

## Stage 3: Type 3 Font Glyph Program Risk

**Goal**: Detect malicious or evasive behaviour in Type 3 CharProcs and glyph resources.

### Changes

- `crates/font-analysis/src/` and `crates/sis-pdf-detectors/src/font_exploits.rs`
  - Parse Type 3 charproc streams with bounded operator accounting.
  - Track excessive complexity and suspicious glyph-level resource usage.

### New Findings (proposed)

1. `font.type3_charproc_complexity_high`
   - Severity: Medium
   - Impact: Medium
   - Confidence: Probable
2. `font.type3_charproc_resource_abuse`
   - Severity: High
   - Impact: High
   - Confidence: Probable
3. `font.type3_charproc_recursion_like_pattern`
   - Severity: Medium
   - Impact: Medium
   - Confidence: Tentative

### Tests

- Type 3 fixtures with normal and anomalous charproc behaviour.
- Assertions for complexity/resource metadata fields.

## Stage 4: ToUnicode/CMap Consistency Validation

**Goal**: Detect CMap mapping abuse and contradictions.

### Changes

- `crates/sis-pdf-detectors/src/font_exploits.rs`
  - Add bounded parser for key CMap structures and range overlap checks.
  - Cross-check map cardinality/subtype expectations.

### New Findings (proposed)

1. `font.cmap_range_overlap`
   - Severity: Medium
   - Impact: Medium
   - Confidence: Strong
2. `font.cmap_cardinality_anomalous`
   - Severity: Medium
   - Impact: Medium
   - Confidence: Probable
3. `font.cmap_subtype_inconsistent`
   - Severity: Medium
   - Impact: Medium
   - Confidence: Strong

### Tests

- Fixtures for overlapping ranges, oversized maps, and benign maps.

## Stage 5: Resource Inheritance Conflict Detection

**Goal**: Detect conflicting page-tree resource inheritance.

### Changes

- `crates/sis-pdf-pdf/src/typed_graph.rs` and/or page-tree helpers
  - Resolve effective resources per page with inheritance provenance.
- `crates/sis-pdf-detectors/src/`
  - Emit findings for contradictory inherited/local entries.

### New Findings (proposed)

1. `resource.inheritance_conflict_font`
   - Severity: Medium
   - Impact: Medium
   - Confidence: Strong
2. `resource.inheritance_conflict_xobject`
   - Severity: Medium
   - Impact: Medium
   - Confidence: Strong
3. `resource.inheritance_override_suspicious`
   - Severity: Medium
   - Impact: Medium
   - Confidence: Probable

### Tests

- Fixtures with ancestor/descendant resource conflicts.
- Query tests validating stable provenance metadata.

## Stage 6: Signature-Aware Incremental Resource Override

**Goal**: Prioritise risky overrides occurring outside signature coverage.

### Changes

- `crates/sis-pdf-core/src/revision_timeline.rs`
- `crates/sis-pdf-detectors/src/revision_forensics.rs`
  - Cross-link signature coverage boundaries with image/font override findings.

### New Findings (proposed)

1. `resource.override_outside_signature_scope`
   - Severity: High
   - Impact: High
   - Confidence: Strong
2. `font.override_outside_signature_scope`
   - Severity: High
   - Impact: High
   - Confidence: Strong
3. `image.override_outside_signature_scope`
   - Severity: High
   - Impact: High
   - Confidence: Strong

### Tests

- Signed baseline + unsigned incremental override fixtures.
- Assertions on revision/signature metadata invariants.

## Stage 7: Cross-Object Decode Amplification Chains

**Goal**: Detect aggregate resource-exhaustion chain patterns across image/font/ICC/metadata.

### Changes

- `crates/sis-pdf-core/src/correlation.rs`
  - Add aggregate correlators for decode amplification signals across domains.

### New Findings (proposed)

1. `composite.decode_amplification_chain`
   - Severity: High
   - Impact: High
   - Confidence: Strong
2. `composite.resource_overrides_with_decoder_pressure`
   - Severity: High
   - Impact: High
   - Confidence: Probable

### Tests

- Integration tests combining existing per-domain findings into composite assertions.

## Stage 8: Calibration Matrix and Confidence Policy

**Goal**: Formalise confidence/severity policy for new structural findings.

### Changes

- `crates/sis-pdf-detectors/src/*` mapping points
- `docs/findings.md`
  - Add calibration notes for deterministic vs heuristic cases.
  - Define escalation rule when provenance + structural contradiction co-occur.

### Tests

- Mapping tests for severity/impact/confidence on every added finding ID.

## Stage 9: Corpus, Fuzzing, and Performance Validation

**Goal**: Validate robustness and SLO impact of follow-up stages.

### Changes

- Add fixtures to `crates/sis-pdf-core/tests/fixtures/corpus_captured/` and update `manifest.json`.
- Extend fuzz targets for:
  - inline image dict parsing,
  - Type 3 charproc parsing,
  - CMap range parsing,
  - inheritance resolution.
- Capture runtime profile baselines:
  - `sis scan <fixture> --deep --runtime-profile --runtime-profile-format json`

### Tests and Commands

1. `cargo test -p sis-pdf-pdf`
2. `cargo test -p image-analysis`
3. `cargo test -p font-analysis`
4. `cargo test -p sis-pdf-detectors`
5. `cargo test -p sis-pdf-core --test corpus_captured_regressions`

### Stage 9 Progress Notes

- Added fuzz target: `fuzz/fuzz_targets/content_ops.rs` for hostile content stream operator parsing over raw data and decoded streams.
- Added fuzz target: `fuzz/fuzz_targets/page_tree.rs` for page-tree/inheritance resolution robustness.
- Registered new fuzz bins in `fuzz/Cargo.toml`; validated with `cd fuzz && cargo fuzz list`.
- Runtime profile baseline captured on 2026-02-17 with:
  `cargo run -p sis-pdf --bin sis -- scan crates/sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf --deep --runtime-profile --runtime-profile-format json`
  - `total_duration_ms: 4`
  - `parse: 0ms`
  - `detection: 1ms`
  - `resource_usage_semantics` detector runtime: `0ms` on the baseline fixture
- Runtime profile baseline captured on 2026-02-17 for new structural-positive fixture:
  `cargo run -p sis-pdf --bin sis -- scan crates/sis-pdf-core/tests/fixtures/corpus_captured/structural-unused-resource-c4afbb69.pdf --deep --runtime-profile --runtime-profile-format json`
  - `total_duration_ms: 3`
  - `parse: 0ms`
  - `detection: 1ms`
  - `resource_usage_semantics` detector runtime: `0ms` with `findings_count: 1`
- Runtime profile baseline captured on 2026-02-17 for modern corpus fixture:
  `cargo run -p sis-pdf --bin sis -- scan crates/sis-pdf-core/tests/fixtures/corpus_captured/modern-renderer-revision-8d42d425.pdf --deep --runtime-profile --runtime-profile-format json`
  - `total_duration_ms: 969`
  - `parse: 16ms`
  - `detection: 927ms`
  - Top detector by runtime remained `content_first_stage1` (`922ms`)
- Added corpus regression guardrails in `crates/sis-pdf-core/tests/corpus_captured_regressions.rs` asserting modern captured fixtures do not silently start emitting the new image/font structural follow-up kinds.
- Added positive corpus fixtures and provenance entries:
  - `structural-unused-resource-c4afbb69.pdf` for `resource.declared_but_unused`
  - `structural-inline-decode-invalid-eac2732d.pdf` for `image.inline_decode_array_invalid`
  - `structural-hidden-invocation-19004614.pdf` for `resource.hidden_invocation_pattern`
  - `structural-inheritance-conflict-font-4e033b8b.pdf` for `resource.inheritance_conflict_font` and `resource.inheritance_override_suspicious`
  - `structural-type3-charproc-abuse-f942b416.pdf` for `font.type3_charproc_resource_abuse` and `font.type3_charproc_recursion_like_pattern`
  - `structural-cmap-overlap-e51348dc.pdf` for `font.cmap_range_overlap` and `font.cmap_subtype_inconsistent`
  - `structural-inheritance-conflict-xobject-246bb53b.pdf` for `resource.inheritance_conflict_xobject`
  - `structural-inline-filter-mask-97762d41.pdf` for `image.inline_structure_filter_chain_inconsistent` and `image.inline_mask_inconsistent`
  - `structural-type3-complexity-b4c499af.pdf` for `font.type3_charproc_complexity_high`
  - `structural-cmap-cardinality-53ab048f.pdf` for `font.cmap_cardinality_anomalous`
- Verified corpus baseline suite with:
  `cargo test -p sis-pdf-core --test corpus_captured_regressions -- --nocapture`
- Remaining Stage 9 work:
  - Extend positive corpus fixture set to cover signature-scope override kinds (`resource.override_outside_signature_scope`, `font.override_outside_signature_scope`, `image.override_outside_signature_scope`) with deterministic signed-revision fixtures.
6. `cargo test -p sis-pdf batch_query_supports_findings_composite_predicate -- --nocapture`
7. `cargo test -p sis-pdf execute_query_supports_findings_composite_predicate -- --nocapture`

## Deliverables

1. New finding coverage for inline images, Type 3 glyph programs, CMap and inheritance conflicts.
2. Signature-aware override findings for image/font resources.
3. Composite decode-amplification and trigger-surface correlations.
4. Updated `docs/findings.md` and mapping tests.
5. Expanded corpus fixtures/fuzz targets with provenance manifest updates.

## Execution Order

1. Stage 1 (operator semantics)
2. Stage 2 (inline image)
3. Stage 3 (Type 3 charproc)
4. Stage 4 (CMap)
5. Stage 5 (inheritance conflicts)
6. Stage 6 (signature-aware overrides)
7. Stage 7 (cross-object composites)
8. Stage 8 (calibration)
9. Stage 9 (fixtures/fuzz/perf)

## Risks and Controls

1. Risk: false positives from usage heuristics.  
   Control: keep heuristic findings lower confidence unless corroborated by structural/provenance signals.
2. Risk: parser complexity increase in content/operator analysis.  
   Control: strict operator/event budgets and bounded parsing.
3. Risk: runtime regression at corpus scale.  
   Control: stage-by-stage runtime profile checkpoints against documented SLOs.
