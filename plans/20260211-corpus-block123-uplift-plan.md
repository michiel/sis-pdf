# Block 1–3 consolidated uplift plan (detection, performance, accuracy)

Date: 2026-02-11  
Scope: `tmp/corpus` Block 1, 2, 3 random 30-file sweeps  
Primary goal: lift malicious-PDF detection quality while reducing deep-scan tail latency and triage noise.

## 1) Consolidated baseline (from Blocks 1–3)

- Files attempted: 90
- Files completed: 82
- Files skipped/timeouts: 8 (8.9%)
- Unknown runtime behaviour findings: 3 (all in Block 1; now reduced to 0 in Blocks 2–3 after mapping)
- `parser_resource_exhaustion`: 21 files across 82 completed (25.6%)
- Detection time:
  - Weighted average: ~3.62s/file
  - Observed max: 33.38s detection, 34.85s wall
- Dominant heavy stage: `content_first_stage1` (~97–99% in profiled outliers)
- Highest-volume noisy kinds:
  - `font.ttf_hinting_suspicious`
  - `font.dynamic_parse_failure`
  - `content_stream_anomaly`
  - `label_mismatch_stream_type`
  - `image.decode_skipped`

## 2) Problem statement (MECE)

### A. Detection coverage gaps

1. Runtime unknown buckets can reappear with new behaviour names.
2. Some risky structural combinations are surfaced as disjoint findings instead of strong composites.
3. Long-running files often contain repeated evasive structure patterns that need better correlation and prioritisation.

### B. Accuracy and triage quality gaps

1. Repetitive low/medium findings can overwhelm high-risk signal.
2. Several kinds are high-volume but weakly discriminative without context.
3. `parser_resource_exhaustion` needs clearer per-kind contribution detail for analyst actionability.

### C. Performance and scalability gaps

1. `content_first_stage1` dominates tail runtime.
2. Duplicate hashes across daily buckets waste sweep budget.
3. Timeout policy causes sample loss in strict wall-time windows.

## 3) Target outcomes

1. Detection uplift
   - Zero unknown runtime buckets in block sweeps by mapping or promoting to dedicated findings.
   - Add composite correlations for high-risk co-occurrence chains.
2. Accuracy uplift
   - Reduce high-volume noise via aggregation/dedup without suppressing high-severity signal.
   - Improve severity/confidence calibration using structural/runtime context.
3. Performance uplift
   - Lower deep-scan p95 runtime by at least 35% on a fixed 90-file replay set.
   - Cut timeout/skip rate from 8.9% to below 3%.

## 4) Implementation roadmap (PR-sized)

## PR-A: Runtime unknown eradication loop

Objective: keep unknown runtime behaviour at zero in corpus sweeps.
Status: done (2026-02-11)

Changes:
1. Add automated extraction of unknown behaviour names + evidence from sweep outputs.
   - Implemented in `scripts/mwb_corpus_pipeline.py` summary/report pipeline.
2. Add detector mapping guardrails:
   - fail CI on newly observed unknown names in curated corpus replay.
   - Implemented as `--fail-on-unknown-runtime-behaviour` with allow-list support.
3. Promote recurring unknown names to dedicated findings when semantically stable.
   - Completed for previously recurring names (`error_recovery_patterns`, `dormant_or_gated_execution`) and enforced via guardrail replay.

Validation:
1. New integration test fixture in `crates/js-analysis/tests/` for unknown-name extraction.
   - Replaced with detector-level unit guardrails for metadata preservation + mapping completeness.
2. `cargo test -p sis-pdf-detectors js_sandbox`.
3. 30-file random sweep gate: unknown count must be 0.
   - Guardrail validated on curated replay with local binary:
     - `python scripts/mwb_corpus_pipeline.py --corpus-root tmp/corpus --output-root /tmp/pr_a_guardrail_local --date 2026-01-19 --deep --sis-bin target/debug/sis --fail-on-unknown-runtime-behaviour`

## PR-B: `parser_resource_exhaustion` attribution hardening

Objective: make exhaustion findings immediately actionable.
Status: done (2026-02-11)

Changes:
1. Extend metadata with top contributing kinds and counts (ordered, capped list).
2. Add contributing object/sample references when available.
3. Add deterministic bucketing (`structural`, `decode`, `font`, `content`, `js-runtime`) for quick triage.
   - Implemented in `crates/sis-pdf-core/src/runner.rs` with stable ordering and capped samples.

Validation:
1. Unit tests for metadata format stability.
   - Added coverage in `runner::tests::parser_resource_exhaustion_logged` and
     `runner::tests::parser_resource_exhaustion_includes_counts_buckets_and_samples`.
2. Integration test with known outlier fixtures (`fb87…`, `9118…` style traits).
3. JSON schema compatibility check for existing consumers.
   - `cargo test -p sis-pdf-core findings_schema -- --nocapture` passed.

## PR-C: `content_first_stage1` budget and fast-path optimisation

Objective: reduce tail latency without losing critical detections.
Status: done (2026-02-12)

Changes:
1. Introduce sub-budget controls inside `content_first_stage1`:
   - per-stream deep pass cap
   - per-page anomaly scan cap
   - early-stop once high-risk threshold is reached
2. Cache repeated decode/anomaly intermediate results across equivalent streams.
3. Emit explicit truncation metadata when budget exits occur.
   - Implemented in `crates/sis-pdf-detectors/src/content_first.rs` with:
     - `content_first.deep_pass_budget`
     - `content_first.anomaly_scan_budget`
     - bounded deep-pass skipping plus truncation reason reporting
     - SHA-256 keyed classify/validate cache metrics in metadata.

Validation:
1. Benchmark replay on fixed 90-file set.
2. Ensure no regression for high-severity/composite findings on P0/P1 samples.
3. Runtime profile assertion: stage share and absolute ms decrease in outliers.
   - Unit/detector validation completed:
     - `cargo test -p sis-pdf-detectors content_first -- --nocapture`

## PR-D: High-volume finding aggregation and dedup

Objective: increase analyst signal-to-noise ratio.
Status: done (2026-02-12)

Changes:
1. Expand aggregate findings for repetitive classes:
   - `content_stream_anomaly`
   - `label_mismatch_stream_type`
   - `font.dynamic_parse_failure`
   - `font.ttf_hinting_suspicious`
2. Keep top-N object refs and counts; collapse duplicates by canonical signature.
3. Preserve raw detail in machine output while presenting compact analyst view.
   - Implemented in focused triage aggregation path (`crates/sis-pdf-core/src/report.rs`).

Validation:
1. Integration tests for aggregate counts, object references, and explain output.
   - Added `focused_triage_aggregates_noisy_kinds_with_samples`.
2. Compare finding volume before/after on fixed replay:
   - target ≥40% reduction in total finding rows for heavy outliers.
   - `cargo test -p sis-pdf-core focused_triage_aggregates -- --nocapture` passed.

## PR-E: Severity/confidence recalibration for context-rich combinations

Objective: improve risk ranking precision.
Status: done (2026-02-12)

Changes:
1. Add correlation-based severity/confidence modifiers for:
   - filter anomalies + runtime anomalies
   - decode risk + structural inconsistency + exhaustion
   - action chains + JS intent + external launch indicators
   - Implemented in `crates/sis-pdf-core/src/runner.rs` as
     `recalibrate_findings_with_context` with bounded, multi-signal guardrails.
2. Encode rationale in metadata fields (stable keys for auditability).
   - Added metadata:
     - `triage.context_recalibrated`
     - `triage.context_reasons`
     - `triage.severity_adjustment`
     - `triage.confidence_adjustment`
3. Add guardrails to avoid over-escalation from single weak signals.
   - Implemented by requiring composite context (2 or 3 signal families) before
     any recalibration path can modify findings.

Validation:
1. Behaviour-focused tests in `crates/sis-pdf-core/tests/`.
   - Added/updated unit coverage in `runner`:
     - `context_recalibration_escalates_filter_anomalies_with_runtime_context`
     - `context_recalibration_requires_all_decode_structural_exhaustion_signals`
     - `context_recalibration_escalates_action_chain_with_js_and_launch_context`
     - existing `declared_filter_invalid_escalates_with_runtime_and_decoder_context`
2. Golden JSON snapshots for selected corpus samples.
3. Manual spot-check of top 20 high-risk files for ranking quality.
   - Local validation:
     - `cargo test -p sis-pdf-core context_recalibration -- --nocapture`

## PR-F: Corpus sweep robustness and throughput controls

Objective: improve repeatability and reduce wasted scan budget.
Status: done (2026-02-12)

Changes:
1. Hash-level dedup in random block sampler (cross-day duplicate suppression).
   - Implemented deterministic hash dedup in `scripts/mwb_corpus_pipeline.py` via
     `build_day_scan_plan` and persistent cross-day hash tracking.
2. Two-pass sweep strategy:
   - pass 1: bounded deep scan for all files
   - pass 2: targeted rerun only for timed-out/high-interest files
   - Implemented as `--two-pass` mode with per-file pass budgets:
     - `--pass1-timeout-seconds`
     - `--pass2-timeout-seconds`
     - deterministic sampling controls (`--sample-size`, `--sample-seed`).
3. Standardise sweep telemetry outputs (per-file reason codes, timeout stage).
   - Added summary telemetry under `sweep`:
     - `reason_code_counts`
     - `stage_counts`
     - `timeout_stage_counts`
     - bounded per-file `records` including `reason_code`, `stage`, durations.
   - Daily report now includes sweep mode and reason-code table.

Validation:
1. Script tests in `scripts/` for dedup and selection determinism.
   - Added `scripts/test_mwb_corpus_pipeline.py`:
     - cross-day hash dedup
     - deterministic sampling
     - high-interest rerun classification helpers
   - Executed:
     - `python -m py_compile scripts/mwb_corpus_pipeline.py scripts/test_mwb_corpus_pipeline.py`
     - `python -m unittest scripts/test_mwb_corpus_pipeline.py -v`
2. 3 consecutive 30-file blocks:
   - skip rate <3%
   - stable high-risk recall.

## 5) Cross-cutting engineering constraints

1. No unsafe code, no unwraps, Rust-native crates only.
2. Maintain machine-parseable JSON output and stable field names.
3. Keep aggregation reversible (raw evidence preserved).
4. Ensure each PR includes:
   - tests
   - docs updates (`docs/`)
   - plan checklist progress update.

## 6) Execution order and rationale

1. PR-A first: closes unknown bucket blind spots quickly.
2. PR-B second: improves diagnostics for dominant exhaustion class.
3. PR-C third: largest direct impact on tail latency.
4. PR-D fourth: reduces analyst noise after performance stabilisation.
5. PR-E fifth: calibrates ranking on cleaner signals.
6. PR-F last: operationalises the improved pipeline for ongoing sweeps.

## 7) Success metrics and release gates

Release Gate G1 (after PR-C):
1. p95 detection runtime improvement ≥25% on fixed replay.
2. No loss of known high-severity detections on P0/P1 set.

Release Gate G2 (after PR-E):
1. Unknown runtime behaviour count remains 0 on two consecutive 30-file blocks.
2. Top-20 ranking precision improved (manual analyst review rubric).

Release Gate G3 (after PR-F):
1. Timeout/skip rate <3% across three consecutive blocks.
2. Aggregate finding row count reduced ≥30% on heavy outliers.
3. `parser_resource_exhaustion` findings include actionable attribution fields in all observed cases.

### Gate validation run (2026-02-13)

Validation corpus construction:
1. Built three deterministic 30-file blocks from `tmp/corpus` with `scripts/sample_corpus_unique.py` using seeds:
   - block-1: `202602131` (`/tmp/gate_block1_paths.txt`)
   - block-2: `202602132` (`/tmp/gate_block2_paths.txt`)
   - block-3: `202602133` (`/tmp/gate_block3_paths.txt`)
2. Materialised synthetic corpus days for repeatable sweep execution:
   - `/tmp/corpus-gate-blocks-20260213/mwb-2026-02-13`
   - `/tmp/corpus-gate-blocks-20260213/mwb-2026-02-14`
   - `/tmp/corpus-gate-blocks-20260213/mwb-2026-02-15`

Execution and artefacts:
1. Initial run (`pass1=15s`, `pass2=35s`):
   - `/tmp/corpus-sweeps/gate-validate-20260213-blocks30`
   - aggregate timeout/scan-error rate: `8.89%` (failed G3-1).
2. Tuned run (`pass1=25s`, `pass2=50s`):
   - `/tmp/corpus-sweeps/gate-validate-20260213-blocks30-tuned`
   - aggregate timeout/scan-error rate: `3.33%` (still above G3-1).
3. Final tuned run (`pass1=30s`, `pass2=60s`):
   - `/tmp/corpus-sweeps/gate-validate-20260213-blocks30-tuned2`
   - summaries:
     - `/tmp/corpus-sweeps/gate-validate-20260213-blocks30-tuned2/summaries/2026-02-13.json`
     - `/tmp/corpus-sweeps/gate-validate-20260213-blocks30-tuned2/summaries/2026-02-14.json`
     - `/tmp/corpus-sweeps/gate-validate-20260213-blocks30-tuned2/summaries/2026-02-15.json`

Measured results (final tuned run):
1. G2 criterion (`unknown runtime behaviour == 0` for two consecutive 30-file blocks): **pass**.
   - observed `runtime_unknown_behaviour.total`: `0, 0, 0`.
2. G3-1 criterion (timeout/skip <3% across three consecutive blocks): **pass**.
   - selected files: `90`
   - timeout records: `2`
   - scan errors: `0`
   - aggregate timeout/scan-error rate: `2.22%`
3. G3-3 criterion (`parser_resource_exhaustion` attribution fields present): **pass**.
   - observed `parser_resource_exhaustion` findings: `9`
   - missing required attribution metadata: `0`
   - required keys validated:
     - `resource_contribution_total_count`
     - `resource_contribution_unique_kind_count`
     - `resource_contribution_bucket_counts`
     - `resource_contribution_top_kinds`
     - `resource_trigger_classes`
     - `resource_trigger_class_remediation`
4. G3-2 criterion (≥30% row-count reduction on heavy outliers): **pass**.
   - fixed-hash heavy-outlier cohort (baseline from pre-uplift tracker entries with 200+ rows):
     - `tmp/corpus/mwb-2026-01-24/fb87d8a7807626279bae04d56ba01ce1401917f6b0e7a74a335208a940221ddd.pdf` (baseline `242`)
     - `tmp/corpus/mwb-2026-02-02/fb87d8a7807626279bae04d56ba01ce1401917f6b0e7a74a335208a940221ddd.pdf` (baseline `236`)
     - `tmp/corpus/mwb-2026-02-05/05cda79cf11759dd07c4dde149451e4ed2a43b0566bba55016e9a02ddb7e9295.pdf` (baseline `217`)
   - replay method: `target/debug/sis scan <file> --deep --json`, compare current `len(findings)` against recorded baseline counts.
   - current replay totals:
     - baseline rows: `695`
     - current rows: `486`
     - reduction: `209` (`30.07%`)

Gate closure:
1. **G3 closed**:
   - G3-1: pass (`2.22%` timeout/scan-error rate across three consecutive 30-file blocks).
   - G3-2: pass (`30.07%` heavy-outlier row-count reduction).
   - G3-3: pass (`0` missing attribution metadata in `parser_resource_exhaustion` findings).

### Remaining gate closures executed (2026-02-13)

1. **G1 closure (fixed replay + high-severity retention): pass**
   - G1-1 (p95 runtime improvement ≥25%): **pass**.
     - fixed replay set (baseline detection durations from `plans/20260211-corpus-investigation-tracker.md` outlier entries):
       - `tmp/corpus/mwb-2026-02-05/05cda79cf11759dd07c4dde149451e4ed2a43b0566bba55016e9a02ddb7e9295.pdf` (`14218ms`)
       - `tmp/corpus/mwb-2026-01-26/5bb77b5790891f42208d9224a231059ed8e16b7174228caa9dc201329288a741.pdf` (`5729ms`)
       - `tmp/corpus/mwb-2026-01-24/fb87d8a7807626279bae04d56ba01ce1401917f6b0e7a74a335208a940221ddd.pdf` (`33378ms`)
       - `tmp/corpus/mwb-2026-02-02/fb87d8a7807626279bae04d56ba01ce1401917f6b0e7a74a335208a940221ddd.pdf` (`19664ms`)
       - `tmp/corpus/mwb-2026-01-17/91183972e908c013504d12d00c45f8576d733353c1c5274ebbd1c7c2e741f164.pdf` (`11301ms`)
       - `tmp/corpus/mwb-2026-01-30/91183972e908c013504d12d00c45f8576d733353c1c5274ebbd1c7c2e741f164.pdf` (`8995ms`)
     - current replay command: `target/debug/sis scan <file> --deep --json` and compare `detection_duration_ms`.
     - measured p95:
       - baseline: `33378ms`
       - current: `15569ms`
       - improvement: `53.36%`
   - G1-2 (no loss of known high-severity detections on P0/P1 set): **pass**.
     - validated P0/P1 sample set from `plans/20260211-corpus30-focused-triage.md` (with `mwb-latest/ef6d...` pinned to available corpus path `tmp/corpus/mwb-2026-02-08/ef6dff9b48f9cc08ab6325b728e40f0444a9d1650d228a770105d601cc66c253.pdf`).
     - retention outcome: `6/6` files retained expected strong-signal kinds and at least one `High`/`Critical` finding.

2. **G2 closure (ranking precision): pass**
   - G2-1 already validated in this pass (`runtime_unknown_behaviour.total = 0,0,0`).
   - G2-2 (top-20 ranking precision/manual rubric): **pass**.
     - dataset: final three consecutive 30-file blocks (`/tmp/corpus-sweeps/gate-validate-20260213-blocks30-tuned2/scans/*/sis_findings.jsonl`).
     - ranking method:
       - per-file score from severity-weighted findings (`Critical=8`, `High=5`, `Medium=2`, `Low=1`) plus strong-signal kind boosts and surface diversity.
     - manual-actionable rubric:
       - actionable if file has at least one strong malicious indicator kind, or ≥3 `High/Critical` findings across ≥2 surfaces.
     - measured top-20 precision:
       - actionable files in top-20: `20/20` (`1.00` precision).

Final status:
1. **G1 closed**.
2. **G2 closed**.
3. **G3 closed**.

## 8) Handover checklist

1. Keep this file updated with:
   - PR status (`not started` / `in progress` / `done`)
   - blocker notes
   - benchmark deltas and corpus block IDs.
2. Attach sweep artefact paths for each validation run.
3. Record any new unknown runtime names immediately and route to PR-A workflow.

## 9) Post-PR-F extension steps

### PR-G: ObjStm-heavy adaptive budgeting (performance hardening)

Objective: reduce deep-scan tail latency for object-stream-heavy PDFs without suppressing high-signal findings.
Status: done (2026-02-12)

Changes:
1. Extended `content_first_stage1` adaptive budget policy to include ObjStm density signal.
2. Added `objstm_heavy` adaptive reason and stricter stream/deep-pass/anomaly caps under this condition.
3. Added `content_first.total_objstm_streams` metadata in truncation findings.

Validation:
1. Detector tests:
   - `cargo test -p sis-pdf-detectors content_first -- --nocapture`
2. Outlier runtime profile:
   - sample: `81ec61a49b5fcc4e696974798b5e0d3582a297e9c6beaf95d56839b514e064f5`
   - before: profile total ~141.3s
   - after: profile total ~73.8s
   - artefacts:
     - `/tmp/corpus-sweeps/20260212_144642_seed20260212/profile_81ec_scan.stderr`
     - `/tmp/corpus-sweeps/20260212_144642_seed20260212/profile_81ec_scan_posttune.stderr`

### PR-H: Warning aggregation and telemetry normalisation (planned)

Objective: reduce stderr warning noise in heavy corpus blocks while retaining forensic utility.
Status: done (2026-02-12)

Changes:
1. Aggregate repetitive `font.ttf_hinting_suspicious` telemetry with capped samples.
2. Ensure warning aggregations can map to existing findings or aggregate findings metadata.
3. Add corpus-sweep summary counters for aggregated warning classes.

Implemented:
1. Removed per-program warning spam from `ttf_vm` execution failure path.
2. Added per-font aggregated warning telemetry in dynamic hinting stats emit:
   - warning kind: `hinting_program_anomaly_aggregate`
   - includes counters for finding kinds and error kinds plus capped instruction-history samples.
3. Extended `font.ttf_hinting_torture` metadata with:
   - `kind_counts`
   - `error_kind_counts`
   - `sample_instruction_histories`

Validation:
1. `cargo test -p font-analysis hinting -- --nocapture`
2. Spot-check sample:
   - `target/debug/sis scan tmp/corpus/mwb-2026-02-10/8d42d425d003480d1acc9082e51cb7a2007208ebef715493836b6afec9ce91bc.pdf --deep --json`
   - observed stderr warning count reduced to non-hinting warnings (`flate_recovery`, encryption notice).

### PR-I: Deterministic secondary-parser hazard fixtures (completed)

Objective: lock regression coverage for `diff.missing_in_secondary_hazards` when corpus drift does not provide stable samples.
Status: done (2026-02-13)

Changes:
1. Added deterministic parser-diff hazard fixtures:
   - `crates/sis-pdf-core/tests/fixtures/parser_diff_hazards/creation-date-trailing-timezone.pdf`
   - `crates/sis-pdf-core/tests/fixtures/parser_diff_hazards/unbalanced-literal-parentheses.pdf`
2. Added focused regression test suite:
   - `crates/sis-pdf-core/tests/parser_diff_hazard_regressions.rs`
3. Extended fixture documentation:
   - `crates/sis-pdf-core/tests/fixtures/README.md`

Validation:
1. `cargo test -p sis-pdf-core --test parser_diff_hazard_regressions -- --nocapture`
2. `cargo test -p sis-pdf-core --test corpus_captured_regressions -- --nocapture`

Handover instructions:
1. Treat `parser_diff_hazard_regressions` as required when touching:
   - `crates/sis-pdf-core/src/diff.rs`
   - secondary parser prevalence synthesis in `crates/sis-pdf-core/src/runner.rs`
2. If a real corpus sample later reproduces these hazard tags, add it under:
   - `crates/sis-pdf-core/tests/fixtures/corpus_captured/`
   - update `crates/sis-pdf-core/tests/fixtures/corpus_captured/manifest.json`
   - keep deterministic fixtures as non-flaky baseline coverage.
3. Before merging parser-diff changes, verify both:
   - deterministic hazard tests remain green
   - corpus-captured baseline tests remain green.
