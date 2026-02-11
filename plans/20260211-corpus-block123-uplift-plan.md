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
Status: in progress (2026-02-11)

Changes:
1. Add automated extraction of unknown behaviour names + evidence from sweep outputs.
   - Implemented in `scripts/mwb_corpus_pipeline.py` summary/report pipeline.
2. Add detector mapping guardrails:
   - fail CI on newly observed unknown names in curated corpus replay.
   - Implemented as `--fail-on-unknown-runtime-behaviour` with allow-list support.
3. Promote recurring unknown names to dedicated findings when semantically stable.
   - Pending.

Validation:
1. New integration test fixture in `crates/js-analysis/tests/` for unknown-name extraction.
   - Replaced with detector-level unit guardrails for metadata preservation + mapping completeness.
2. `cargo test -p sis-pdf-detectors js_sandbox`.
3. 30-file random sweep gate: unknown count must be 0.

## PR-B: `parser_resource_exhaustion` attribution hardening

Objective: make exhaustion findings immediately actionable.

Changes:
1. Extend metadata with top contributing kinds and counts (ordered, capped list).
2. Add contributing object/sample references when available.
3. Add deterministic bucketing (`structural`, `decode`, `font`, `content`, `js-runtime`) for quick triage.

Validation:
1. Unit tests for metadata format stability.
2. Integration test with known outlier fixtures (`fb87…`, `9118…` style traits).
3. JSON schema compatibility check for existing consumers.

## PR-C: `content_first_stage1` budget and fast-path optimisation

Objective: reduce tail latency without losing critical detections.

Changes:
1. Introduce sub-budget controls inside `content_first_stage1`:
   - per-stream deep pass cap
   - per-page anomaly scan cap
   - early-stop once high-risk threshold is reached
2. Cache repeated decode/anomaly intermediate results across equivalent streams.
3. Emit explicit truncation metadata when budget exits occur.

Validation:
1. Benchmark replay on fixed 90-file set.
2. Ensure no regression for high-severity/composite findings on P0/P1 samples.
3. Runtime profile assertion: stage share and absolute ms decrease in outliers.

## PR-D: High-volume finding aggregation and dedup

Objective: increase analyst signal-to-noise ratio.

Changes:
1. Expand aggregate findings for repetitive classes:
   - `content_stream_anomaly`
   - `label_mismatch_stream_type`
   - `font.dynamic_parse_failure`
   - `font.ttf_hinting_suspicious`
2. Keep top-N object refs and counts; collapse duplicates by canonical signature.
3. Preserve raw detail in machine output while presenting compact analyst view.

Validation:
1. Integration tests for aggregate counts, object references, and explain output.
2. Compare finding volume before/after on fixed replay:
   - target ≥40% reduction in total finding rows for heavy outliers.

## PR-E: Severity/confidence recalibration for context-rich combinations

Objective: improve risk ranking precision.

Changes:
1. Add correlation-based severity/confidence modifiers for:
   - filter anomalies + runtime anomalies
   - decode risk + structural inconsistency + exhaustion
   - action chains + JS intent + external launch indicators
2. Encode rationale in metadata fields (stable keys for auditability).
3. Add guardrails to avoid over-escalation from single weak signals.

Validation:
1. Behaviour-focused tests in `crates/sis-pdf-core/tests/`.
2. Golden JSON snapshots for selected corpus samples.
3. Manual spot-check of top 20 high-risk files for ranking quality.

## PR-F: Corpus sweep robustness and throughput controls

Objective: improve repeatability and reduce wasted scan budget.

Changes:
1. Hash-level dedup in random block sampler (cross-day duplicate suppression).
2. Two-pass sweep strategy:
   - pass 1: bounded deep scan for all files
   - pass 2: targeted rerun only for timed-out/high-interest files
3. Standardise sweep telemetry outputs (per-file reason codes, timeout stage).

Validation:
1. Script tests in `scripts/` for dedup and selection determinism.
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

## 8) Handover checklist

1. Keep this file updated with:
   - PR status (`not started` / `in progress` / `done`)
   - blocker notes
   - benchmark deltas and corpus block IDs.
2. Attach sweep artefact paths for each validation run.
3. Record any new unknown runtime names immediately and route to PR-A workflow.
