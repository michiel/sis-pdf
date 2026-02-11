# Combined PR Checklist: JS Modernisation + Structural Evasion

Date: 2026-02-11  
Status: In progress  
Scope: `plans/20260211-modernisation-js.md` + `plans/20260211-structural-evasion-pdfjs.md`

## 1. Execution strategy

- Build shared JS decode foundations first.
- Deliver low-risk, high-signal structural PDF detectors second.
- Implement PDF.js attack-surface and cross-crate bridge next.
- Implement revision-diff and shadow/certified attack stack after extractor foundation.
- Complete advanced JS obfuscation/behavioural resilience after instrumentation is stable.
- Finish with corpus expansion and CI regression harness.

## 2. PR sequence (authoritative order)

## PR-01: Decode layer extension
- [x] Implement JS plan S2-4 (`decode_layers` extension).
- [x] Add bounded decode guards (size/iteration caps).
- [x] Add tests for nested decode layers.
- [x] Verify no regressions in existing decode tests.

## PR-02: Concatenation reconstruction
- [x] Implement JS plan S4-4 (AST path + regex fallback).
- [x] Emit `payload.concatenation_reconstructed`.
- [x] Add fixtures for literal concatenation and mixed expressions.
- [x] Validate deterministic output.

## PR-03: Esoteric encoding detectors
- [x] Implement JS plan S2-1 JSFuck detector.
- [x] Implement JS plan S2-2 JJEncode detector.
- [x] Implement JS plan S2-3 AAEncode detector.
- [x] Add static finding IDs and docs entries.
- [x] Add threshold calibration tests.

## PR-04: Encoded fixture pack
- [x] Implement JS plan S2-5 fixtures (benign + malicious).
- [x] Add decode-then-analyse integration tests.
- [x] Add false-positive controls.

## PR-05: Structural evasion primitives A
- [x] Implement PDF plan S1-2 `xref_phantom_entries`.
- [x] Implement PDF plan S1-4 `trailer_root_conflict`.
- [x] Implement PDF plan S1-5 `null_object_density`.
- [x] Add `evasion.*` metadata fields.
- [x] Add detector integration tests.

## PR-06: Structural evasion primitives B
- [x] Implement PDF plan S1-1 `empty_objstm_padding`.
- [x] Implement PDF plan S1-3 `structural_decoy_objects` with bounded reachability walk.
- [x] Add object-count caps and skip reasons for large documents.
- [x] Add performance-focused tests.

## PR-07: Structural evasion composite
- [x] Implement PDF plan S1-6 `structural_evasion_composite`.
- [x] Enforce “3+ indicators” composite threshold.
- [x] Add severity/confidence calibration tests.
- [x] Update findings documentation.

## PR-08: PDF.js font injection extension
- [x] Implement PDF plan S3-1 `pdfjs_font_injection` sub-signals.
- [x] Cover FontMatrix/FontBBox/CMap/Encoding cases.
- [x] Add `reader_impacts` metadata for affected PDF.js versions.
- [x] Add benign Type1 false-positive control.

## PR-09: Font-to-JS bridge correlation
- [x] Implement PDF plan S3-5 `font_js_exploitation_bridge`.
- [x] Correlate font-analysis + js-analysis findings in detector layer.
- [x] Add escalation rules (confidence uplift only on dual-signal match).
- [x] Add cross-crate integration tests.

## PR-10: PDF.js annotation/form/eval-path indicators
- [x] Implement PDF plan S3-2 `pdfjs_annotation_injection`.
- [x] Implement PDF plan S3-3 `pdfjs_form_injection`.
- [x] Implement PDF plan S3-4 `pdfjs_eval_path_risk`.
- [x] Add per-indicator fixtures.

## PR-11: Dynamic heap telemetry stubs
- [x] Implement JS plan S3-5 ArrayBuffer/TypedArray/DataView runtime stubs.
- [x] Track allocation/view/access telemetry.
- [x] Emit `js_runtime_heap_manipulation` runtime finding.
- [x] Add bounded telemetry caps and truncation tests.

## PR-12: Static modern heap exploitation detectors
- [x] Implement JS plan S3-1 `js.heap_grooming`.
- [x] Implement JS plan S3-2 `js.lfh_priming`.
- [x] Implement JS plan S3-3 `js.rop_chain_construction`.
- [x] Implement JS plan S3-4 `js.info_leak_primitive`.
- [x] Add CVE-derived sanitised fixtures.

## PR-13: Revision content extractor foundation
- [x] Implement PDF plan S2-1 revision content extractor.
- [x] Validate ByteRange bounds strictly.
- [x] Handle malformed/inconsistent `/Prev` chains safely.
- [x] Add extractor-focused tests.

## PR-14: Shadow attack detectors
- [x] Implement PDF plan S2-2 `shadow_hide_attack`.
- [x] Implement PDF plan S2-3 `shadow_replace_attack`.
- [x] Implement PDF plan S2-4 `shadow_hide_replace_attack`.
- [x] Add synthetic signed fixtures and benign signed controls.

## PR-15: Certified document attack detector + diff summary
- [x] Implement PDF plan S2-5 `certified_doc_manipulation`.
- [x] Implement PDF plan S2-6 cross-revision diff metadata.
- [x] Add permission-level logic (P1-P3) checks.
- [x] Add post-certification annotation/signature field tests.

## PR-16: Cross-revision forensic analysis
- [x] Implement PDF plan S4-1 revision timeline query.
- [x] Implement S4-2 page content changed indicator.
- [x] Implement S4-3 annotation diff indicator.
- [x] Implement S4-4 catalog diff indicator.
- [x] Implement S4-5 revision anomaly scoring.

## PR-17: Linearisation and parser divergence
- [x] Implement PDF plan S5-1 `linearization_integrity`.
- [x] Implement S5-2 `duplicate_stream_filters`.
- [x] Implement S5-3 `parser_divergence_risk`.
- [x] Implement S5-4 `content_stream_anomaly`.
- [x] Add known-divergence fixture tests.

## PR-18: Advanced obfuscation resilience
- [ ] Implement JS plan S4-1 enhanced CFF detection.
- [ ] Implement JS plan S4-2 dead code injection detector.
- [ ] Implement JS plan S4-3 array rotation decode detector.
- [ ] Implement JS plan S4-5 deeper multi-layer decode limits.
- [ ] Implement JS plan S4-6 fixture pack.

## PR-19: Behavioural resilience uplift
- [ ] Implement JS plan S5-1 API call sequence matching.
- [ ] Implement JS plan S5-2 data-flow complexity scoring.
- [ ] Implement JS plan S5-3 entropy-at-sink analysis.
- [ ] Implement JS plan S5-4 dynamic string materialisation tracking.
- [ ] Implement JS plan S5-5 semantic call graph extraction (`js-ast`).
- [ ] Implement JS plan S5-6 adversarial rewrite fixtures.

## PR-20: Corpus expansion + CI regression harness
- [ ] Implement JS plan S6-1 modern sample acquisition pipeline docs.
- [ ] Implement JS plan S6-2 synthetic adversarial corpus.
- [ ] Implement JS plan S6-3 benign corpus set.
- [ ] Implement JS plan S6-4 validation sweep metrics report.
- [ ] Implement JS plan S6-5 CI-compatible regression harness.

## 3. Dependency map

- PR-01 is prerequisite for PR-03 and PR-18.
- PR-02 is prerequisite for PR-18 and PR-19.
- PR-05 and PR-06 are prerequisites for PR-07.
- PR-08 is prerequisite for PR-09 and PR-10.
- PR-13 is prerequisite for PR-14, PR-15, and PR-16.
- PR-18 is prerequisite for PR-19.
- PR-20 depends on completion of PR-01..PR-19.

## 4. Per-PR validation standard

For every PR:
- [ ] `cargo fmt`
- [ ] relevant crate tests added/updated
- [ ] no unsafe, no unwrap
- [ ] deterministic output preserved
- [ ] metadata additive only (no breaking schema changes)
- [ ] docs updated for new finding IDs/fields

Minimum suite:
- [ ] `cargo test -p js-analysis --features js-sandbox --test dynamic_signals` (when JS touched)
- [ ] `cargo test -p sis-pdf-detectors --features js-sandbox --test js_sandbox_integration` (when detector touched)

## 5. Milestone gates

Gate A (after PR-07):
- [ ] Structural evasion stack complete (including composite).
- [ ] No regression on signed/benign PDF fixtures.

Gate B (after PR-12):
- [ ] Esoteric encoding + modern heap primitives complete.
- [ ] False-positive controls passing.

Gate C (after PR-16):
- [ ] Shadow/certified/revision stack complete.
- [ ] Revision timeline query stable.

Gate D (after PR-20):
- [ ] 2010-2025 coverage validated.
- [ ] CI harness producing trendable metrics.

## 6. Acceptance criteria (program-level)

- [ ] SETPA structural evasion coverage reaches 6/8 techniques.
- [ ] Shadow variants detected: 3/3.
- [ ] Certified document attacks detected: 2/2.
- [ ] PDF.js attack-surface detectors operational with low false positives on benign corpus.
- [ ] Modern JS encoding and heap exploitation detectors operational with bounded runtime costs.
- [ ] Behavioural resilience catches adversarial rewrite variants.
- [ ] Corpus regression metrics tracked and stable in CI.

## 7. Progress and handover notes

### Completed in this pass
- `PR-01`: `decode_layers` now enforces hard bounds (`MAX_DECODE_LAYERS_HARD=8`, `MAX_DECODE_BYTES_PER_LAYER=256KiB`) and includes `fromCharCode(...)` decode path.
- `PR-01`: nested decode test coverage added in `crates/js-analysis/tests/static_signals.rs`.
- `PR-02`: concatenation reconstruction implemented via AST-enabled path with regex-like literal joining heuristic in `reconstruct_concatenations_ast_and_regex`.
- `PR-02`: static signal assertions for `payload.concatenation_reconstructed` and `payload.concatenation_count` added.
- `PR-03`: static esoteric encoding signals added in `crates/js-analysis/src/static_analysis.rs`: `js.jsfuck_encoding`, `js.jjencode_encoding`, and `js.aaencode_encoding`.
- `PR-03`: targeted tests added in `crates/js-analysis/tests/static_signals.rs` for each encoding detector.
- `PR-03`: detector findings added in `crates/sis-pdf-detectors/src/js_polymorphic.rs`: `js_jsfuck_encoding`, `js_jjencode_encoding`, `js_aaencode_encoding`.
- `PR-03`: finding documentation added in `docs/findings.md` for all three new IDs.
- Validation completed: `cargo test -p js-analysis --test static_signals`, `cargo test -p js-analysis --features js-ast --test static_signals`, and `cargo test -p sis-pdf-detectors --test js_polymorphic_integration`.
- `PR-04`: encoded fixture pack added under `crates/js-analysis/tests/fixtures/encoded/` with malicious and benign esoteric samples plus nested-decode fixtures.
- `PR-04`: integration tests added in `crates/js-analysis/tests/encoded_fixtures.rs` covering decode-then-analyse and false-positive controls.
- Validation completed: `cargo test -p js-analysis --test encoded_fixtures`.
- `PR-05`: structural evasion findings implemented in `crates/sis-pdf-detectors/src/structural_anomalies.rs`: `xref_phantom_entries`, `trailer_root_conflict`, `null_object_density`.
- `PR-05`: `evasion.*` metadata fields added for the new structural indicators.
- `PR-05`: detector integration coverage added in `crates/sis-pdf-detectors/tests/structural_anomalies.rs`.
- `PR-05`: finding documentation added in `docs/findings.md` for the new IDs.
- Validation completed: `cargo test -p sis-pdf-detectors --test structural_anomalies`.
- `PR-06`: implemented `empty_objstm_padding`, `structural_decoy_objects`, and `structural_decoy_objects_scan_limited` in `crates/sis-pdf-detectors/src/structural_anomalies.rs` with bounded reachability analysis.
- `PR-06`: added object cap controls (`DECOY_SCAN_MAX_OBJECTS`) and explicit skip metadata (`evasion.decoy_scan_skip_reason=object_count_cap`).
- `PR-06`: added performance-focused tests in `crates/sis-pdf-detectors/tests/structural_anomalies.rs` for cap-exceeded behaviour and decoy detection.
- `PR-06`: finding documentation added in `docs/findings.md` for new structural evasion IDs.
- `PR-07`: composite finding `structural_evasion_composite` implemented in `crates/sis-pdf-detectors/src/structural_anomalies.rs` with a hard `3+` indicator threshold.
- `PR-07`: calibration logic added (`3 indicators => Medium/Probable`, `4+ indicators => High/Strong`).
- `PR-07`: calibration tests added in `crates/sis-pdf-detectors/tests/structural_anomalies.rs`.
- `PR-07`: finding documentation added in `docs/findings.md`.
- `PR-08`: added `PdfjsFontInjectionDetector` and `pdfjs_font_injection` finding in `crates/sis-pdf-detectors/src/lib.rs`.
- `PR-08`: implemented sub-signals `fontmatrix_non_numeric`, `fontbbox_non_numeric`, `encoding_string_values`, and `cmap_script_tokens`.
- `PR-08`: populated affected-version metadata (`pdfjs.affected_versions=<4.2.67`) and `reader_impacts` notes for browser rendering risk.
- `PR-08`: added integration coverage in `crates/sis-pdf-detectors/tests/pdfjs_font_injection.rs`, including benign Type1 false-positive control.
- `PR-08`: finding documentation added in `docs/findings.md`.
- `PR-09`: added `FontJsExploitationBridgeDetector` and `font_js_exploitation_bridge` correlation finding in `crates/sis-pdf-detectors/src/lib.rs`.
- `PR-09`: implemented dual-domain indicator correlation (font structural risk + JavaScript execution/obfuscation indicators) with confidence-only uplift.
- `PR-09`: added cross-crate integration coverage in `crates/sis-pdf-detectors/tests/font_js_bridge.rs`.
- `PR-09`: finding documentation added in `docs/findings.md`.
- `PR-10`: added `PdfjsRenderingIndicatorDetector` in `crates/sis-pdf-detectors/src/lib.rs` with findings `pdfjs_annotation_injection`, `pdfjs_form_injection`, and `pdfjs_eval_path_risk`.
- `PR-10`: added per-indicator fixture coverage in `crates/sis-pdf-detectors/tests/pdfjs_rendering_indicators.rs`, including a benign annotation/form control.
- `PR-10`: finding documentation added in `docs/findings.md`.
- `PR-11`: added constructable runtime stubs for `ArrayBuffer`, `SharedArrayBuffer`, `DataView`, and typed arrays in `crates/js-analysis/src/dynamic.rs`.
- `PR-11`: added bounded heap telemetry capture (`allocations`, `views`, `accesses`) with explicit truncation counters in `DynamicSignals` and `DynamicTruncationSummary`.
- `PR-11`: added detector finding `js_runtime_heap_manipulation` with metadata-backed stage scoring in `crates/sis-pdf-detectors/src/js_sandbox.rs`.
- `PR-11`: added focused tests in `crates/js-analysis/tests/dynamic_signals.rs` and `crates/sis-pdf-detectors/tests/js_sandbox_integration.rs`.
- Validation completed: `cargo test -p js-analysis --features js-sandbox --test dynamic_signals` and `cargo test -p sis-pdf-detectors --features js-sandbox --test js_sandbox_integration`.
- `PR-12`: added static heap exploitation signals in `crates/js-analysis/src/static_analysis.rs`: `js.heap_grooming`, `js.lfh_priming`, `js.rop_chain_construction`, and `js.info_leak_primitive`.
- `PR-12`: added corresponding detector findings in `crates/sis-pdf-detectors/src/js_polymorphic.rs`: `js_heap_grooming`, `js_lfh_priming`, `js_rop_chain_construction`, and `js_info_leak_primitive`.
- `PR-12`: added CVE-derived sanitised fixtures under `crates/js-analysis/tests/fixtures/modern_heap/` and wired static/integration coverage.
- `PR-12`: finding documentation added in `docs/findings.md`.
- Validation completed: `cargo test -p js-analysis --test static_signals` and `cargo test -p sis-pdf-detectors --test js_polymorphic_integration`.
- `PR-13`: added revision extraction utility in `crates/sis-pdf-core/src/revision_extract.rs` with signature `/ByteRange` parsing, revision snapshot extraction, and nearest `startxref` correlation.
- `PR-13`: added strict `/ByteRange` validation (shape, integer type, ordering, overlap, overflow, and bounds checks).
- `PR-13`: added `/Prev` chain integrity validator to safely handle malformed or inconsistent xref chains.
- `PR-13`: added extractor-focused unit tests for valid extraction, malformed `/ByteRange`, and `/Prev` mismatch handling.
- `PR-14`: added `ShadowAttackDetector` in `crates/sis-pdf-detectors/src/shadow_attacks.rs` and wired it into `default_detectors`.
- `PR-14`: implemented `shadow_hide_attack`, `shadow_replace_attack`, and `shadow_hide_replace_attack` findings by correlating signature boundary extraction with post-signature overlays and shadowed content replacements.
- `PR-14`: added synthetic incremental signed fixtures in `crates/sis-pdf-detectors/tests/shadow_attacks.rs` covering hide-only, replace-only, and combined cases.
- `PR-14`: finding documentation added in `docs/findings.md`.
- `PR-15`: extended `ShadowAttackDetector` with `certified_doc_manipulation` (DocMDP P1-P3 permission-aware) in `crates/sis-pdf-detectors/src/shadow_attacks.rs`.
- `PR-15`: added cross-revision diff summary metadata to shadow/certified findings (`shadow.diff.objects_added`, `shadow.diff.objects_modified`, `shadow.diff.annotations_added`, `shadow.diff.form_fields_added`, `shadow.diff.signature_fields_added`).
- `PR-15`: added certified document tests in `crates/sis-pdf-detectors/tests/shadow_attacks.rs` for disallowed (P1) and allowed-but-suspicious (P3) post-certification overlays.
- `PR-15`: finding documentation added in `docs/findings.md` for `certified_doc_manipulation`.
- `PR-16`: added shared revision timeline utility in `crates/sis-pdf-core/src/revision_timeline.rs` (capped analysis, signature coverage context, per-revision diff summaries).
- `PR-16`: added `RevisionForensicsDetector` in `crates/sis-pdf-detectors/src/revision_forensics.rs` with findings `revision_page_content_changed`, `revision_annotations_changed`, `revision_catalog_changed`, and `revision_anomaly_scoring`.
- `PR-16`: wired `revisions.detail` query in `crates/sis-pdf/src/commands/query.rs` using timeline data, and upgraded `revisions` output with anomaly and diff counters.
- `PR-16`: added detector integration tests in `crates/sis-pdf-detectors/tests/revision_forensics.rs` and query execution coverage for `revisions.detail`.
- `PR-16`: finding documentation added in `docs/findings.md`.
- `PR-17`: extended `LinearizationDetector` with `linearization_integrity` checks covering `/L` vs file length, `/H` structure and bounds, `/E` relation to `startxref`, and `/O` ordering.
- `PR-17`: added `ParserDivergenceDetector` in `crates/sis-pdf-detectors/src/parser_divergence.rs` with findings `duplicate_stream_filters`, `content_stream_anomaly`, and `parser_divergence_risk`.
- `PR-17`: wired parser-divergence detector into `default_detectors`.
- `PR-17`: added known-divergence synthetic fixture tests in `crates/sis-pdf-detectors/tests/parser_divergence.rs`.
- `PR-17`: finding documentation added in `docs/findings.md` for all new IDs.

### Pending follow-up for immediate next pass
- Start `PR-18` advanced obfuscation resilience.

### Constraints and decisions
- Concatenation reconstruction intentionally bounded to literal chains only to avoid high false-positive reconstruction of dynamic expressions.
- Decode bounds prioritise safety and determinism over maximum decode depth coverage.
- Esoteric encoding detection currently uses structural/statistical heuristics only; no decoder execution path has been added yet.
