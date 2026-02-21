# Focused triage report: 30 random PDFs from `tmp/corpus`

Date: 2026-02-11  
Analyst: Codex CLI run  
Scope: random sample of 30 PDFs from 580 discovered under `tmp/corpus`

## 1. Objective

Prioritise findings that are most useful for:

1. Improving detection of potentially malicious PDFs.
2. Improving scan efficiency and throughput for large hostile corpora.

## 2. Method

- Random sampling file: `/tmp/corpus_sample_30.txt`
- Command per file:

```bash
cargo run -q -p sis-pdf --bin sis -- scan <pdf> --deep --json --runtime-profile --runtime-profile-format json
```

- Raw outputs:
  - report JSON: `/tmp/corpus30_scan_outputs/scan_<n>.jsonstream`
  - runtime profile JSON: `/tmp/corpus30_scan_outputs/scan_<n>.status`
- Aggregates:
  - overall stats: `/tmp/corpus30_analysis.json`
  - focused triage extraction: `/tmp/corpus30_focused_triage.json`

## 3. Executive summary

- 30/30 scans completed successfully.
- 1,287 findings total (mean 42.9/file).
- 17/30 files had at least one `High` finding.
- Detection profile is dominated by:
  - action-chain indicators (`uri_present`, `annotation_action_chain`, `pdfjs_eval_path_risk`)
  - parser/filter evasion indicators (`declared_filter_invalid`)
  - decode stress/risk indicators (`decompression_ratio_suspicious`, `decoder_risk_present`)
  - font/image exploit-oriented indicators (`font.multiple_vuln_signals`, `image.zero_click_jbig2`)
- Runtime is highly skewed by a few outliers; median is reasonable, but tail latency is severe.

## 4. Key metrics

### 4.1 Findings distribution

- Severity totals:
  - `High`: 105
  - `Medium`: 265
  - `Low`: 384
  - `Info`: 533
- Top kinds (count):
  - `font.ttf_hinting_suspicious` (250)
  - `label_mismatch_stream_type` (145)
  - `uri_present` (138)
  - `annotation_action_chain` (110)
  - `content_stream_anomaly` (107)
  - `declared_filter_invalid` (55)

### 4.2 Performance distribution

- Total runtime/file:
  - p50: 1,063.5 ms
  - p90: 5,497.2 ms
  - p95: 55,026.3 ms
  - max: 94,836 ms
- Dominant cost centre: `content_first_stage1` (218,386 ms cumulative across the 30 files).

## 5. Prioritised triage queue (high-value samples)

## P0: immediate manual review

1. `tmp/corpus/mwb-2026-02-10/8d42d425d003480d1acc9082e51cb7a2007208ebef715493836b6afec9ce91bc.pdf`
   - Strong maliciousness indicators:
     - `declared_filter_invalid` x47 (`High`)
     - `js_present` (`High` present in this file)
     - `js_emulation_breakpoint` + `js_runtime_unknown_behaviour_pattern`
   - Why this matters: likely evasive JS/filter stack with partial runtime coverage gaps.

2. `tmp/corpus/mwb-2026-02-05/1c8abb3abe62b99d85037f31c9e3cdc424cda2efe3ab8436062090fc1e9cb341.pdf`
   - Strong exploit-risk profile:
     - `image.zero_click_jbig2` x5 (`High`)
     - `decoder_risk_present` x5 (`High`)
     - `parser_resource_exhaustion` (`High`)
   - Why this matters: high-priority potential zero-click image exploit chain and decoder stress.

3. `tmp/corpus/mwb-latest/ef6dff9b48f9cc08ab6325b728e40f0444a9d1650d228a770105d601cc66c253.pdf`
   - Execution-chain profile:
     - `launch_external_program` (`High`)
     - `js_intent_user_interaction` (`High`)
     - `js_present` + `js_sandbox_exec`
   - Why this matters: direct external launch semantics plus JS intent is operationally high risk.

## P1: high-signal, lower certainty or broader campaign-like patterns

4. `tmp/corpus/mwb-2026-01-28/38851573fd1731b1bd94a38e35f5ea1bd1e4944821e08e27857d68a670c64105.pdf`
   - `supply_chain_staged_payload` (`High`), `embedded_file_present` (`High`), `js_runtime_file_probe` (`High`), plus unknown runtime patterns.

5. `tmp/corpus/mwb-2026-02-05/c95a10a176aa14143f738c3ab6f83fc7465cc98b33655312b9cf917f4b003ea9.pdf`
   - 397 findings, 94.6s runtime, large object/stream set.
   - Contains `parser_resource_exhaustion` + `decompression_ratio_suspicious` + heavy URI/annotation chaining.
   - Why this matters: both detection and performance stressor.

6. `tmp/corpus/mwb-2026-01-15/b509f6c92dd4661b2872b9d18ffc07dced17306b4bdf74df19932bd0f8b110d0.pdf`
   - Multiple `decompression_ratio_suspicious` (`High`) + parser exhaustion.

## 6. Findings quality and telemetry gaps

1. `js_runtime_unknown_behaviour_pattern` appears in the sample set.
   - Interpretation: behaviour engine is detecting patterns that are not mapped to dedicated finding IDs/titles.
   - Action: close mapping gaps in detector metadata to avoid opaque triage output.

2. `js_emulation_breakpoint` appears with high-filter/JS documents.
   - Interpretation: partial emulation coverage still blocks precise behavioural classification in some cases.
   - Action: prioritise unresolved callee/property telemetry and profile parity for these files.

3. Extremely high multiplicity in action-chain findings (`uri_present`, `annotation_action_chain`) on a few large PDFs.
   - Interpretation: detection is working, but operator-facing output becomes noisy and expensive.
   - Action: add aggregation mode (per file + per pattern + sample object references) to reduce duplication.

## 7. Performance bottlenecks and optimisation priorities

1. `content_first_stage1` dominates runtime, including outlier files (90s+).
2. Outliers correlate with very large object/page counts and many streams.

### Recommended optimisation backlog (concrete)

1. Add bounded early-stop heuristics for `content_first_stage1` under extreme object/stream density:
   - hard cap on expensive per-object deep decode when high-risk signal threshold already reached.
   - emit explicit `analysis_truncated` metadata with reason and counters.
2. Add per-detector budget controls (`max_ms_per_detector_per_file`) with deterministic fail-open semantics.
3. Aggregate repetitive action-chain findings:
   - e.g. one `annotation_action_chain` finding with count + top-N objects.
   - one `uri_present` finding with unique URI/domain counts + top-N samples.
4. Add scan-time de-duplication by file hash for corpus sweeps.
   - In this sample, duplicate hash filenames were selected across daily folders.

## 8. Detection uplift recommendations (targeted)

1. Promote `declared_filter_invalid` context-aware severity escalation when paired with:
   - JS presence/runtime anomalies, or
   - decoder-risk/high decompression indicators.
2. Introduce composite exploit finding for JBIG2 + decoder risk + parser exhaustion co-occurrence.
3. Add dedicated mapping for unknown runtime behaviours observed in this sample.
4. Add a focused integration test fixture set based on the top P0/P1 PDFs (or sanitised derivatives) to prevent regressions.

## 9. Immediate next actions

1. Create a “focused triage mode” output format for corpus sweeps:
   - high/critical only
   - runtime-gaps only
   - execution-chain composites
2. Implement finding aggregation for URI/annotation storms.
3. Implement `content_first_stage1` budget and truncation metadata.
4. Re-run the same 30-sample set and compare:
   - p95 runtime
   - total findings volume
   - high-risk recall (no drop in P0 signals)

## 10. Implementation status (2026-02-11)

Implemented:

1. Focused triage mode
   - Added `sis scan --focused-triage` for single and batch scans.
   - Mode keeps high/critical findings, runtime-gap findings, and key execution-chain findings.
   - Added focused aggregation findings for `uri_present` and `annotation_action_chain`:
     - `uri_present_aggregate`
     - `annotation_action_chain_aggregate`

2. Context-aware `declared_filter_invalid` escalation
   - Added post-detection escalation when `declared_filter_invalid` co-occurs with runtime anomalies and/or decode-pressure signals.
   - Escalation metadata now records:
     - `triage.severity_escalated=true`
     - `triage.escalation_reason=<reason>`

3. Composite exploit correlation
   - Added `image_decoder_exploit_chain` composite when:
     - `image.zero_click_jbig2`
     - `decoder_risk_present`
     - `parser_resource_exhaustion`
     co-occur in a file.

4. `content_first_stage1` bounded truncation
   - Added stream-budget early stop once high-risk signal threshold is reached.
   - Added truncation finding `content_first_analysis_truncated` with metadata:
     - `analysis_truncated`
     - `truncation_reason`
     - processed/total stream counters and budget fields

Validation completed:

- `cargo fmt`
- `cargo test -p sis-pdf-core correlation -- --nocapture`
- `cargo test -p sis-pdf-core focused_triage_aggregates_uri_and_keeps_runtime_gaps -- --nocapture`
- `cargo test -p sis-pdf-core declared_filter_invalid_escalates_with_runtime_and_decoder_context -- --nocapture`
- `cargo test -p sis-pdf-detectors content_first -- --nocapture`
- `cargo test -p sis-pdf --no-run`

Post-implementation mapping loop:

- Corpus telemetry extraction identified `error_recovery_patterns` as an unmapped behavioural name behind `js_runtime_unknown_behaviour_pattern`.
- Added dedicated mapping:
  - `js_runtime_error_recovery_patterns`
- Added detector unit coverage for the mapping in `crates/sis-pdf-detectors/src/js_sandbox.rs`.
- Rechecked the previously affected sample; unknown count dropped to zero and dedicated mapped findings were emitted.
