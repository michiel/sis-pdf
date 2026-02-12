# Corpus investigation tracker

Date: 2026-02-11
Scope: rolling 30-file random block sweeps over `tmp/corpus`

## Open investigation items

1. `parser_resource_exhaustion` hotspots:
   - recurring in long-runtime files; requires detector/runtime budget and structural trigger review.
2. High-volume noisy classes in deep scans:
   - `font.ttf_hinting_suspicious`
   - `content_stream_anomaly`
   - `label_mismatch_stream_type`
   - `image.decode_skipped`
3. Timeout/skip handling in corpus sweeps:
   - 30-file blocks still skip a minority of files under strict wall-time caps; keep collecting hash/path lists for targeted deep reruns.
4. Recurrent long-runtime duplicate hashes across daily buckets:
   - `fb87d8a7807626279bae04d56ba01ce1401917f6b0e7a74a335208a940221ddd`
   - `91183972e908c013504d12d00c45f8576d733353c1c5274ebbd1c7c2e741f164`
   - prioritise once-per-hash profiling and detector-stage timing attribution.
5. Elevated `font.dynamic_parse_failure` volume in block-3:
   - requires separation between malformed-font noise and exploitation-relevant signals.
6. Persistent deep-scan runtime outliers after PR-F:
   - observed in block-4 for hashes including:
     - `81ec61a49b5fcc4e696974798b5e0d3582a297e9c6beaf95d56839b514e064f5`
     - `bf724f5f19df9b2fdb0f45a79b6d9a88e8acf02843465ce891c6a4ad6c8d47a6`
     - `4a9a844dbf0a4fbaa6b33b9ccc5f8b773ca4b286d389e5d3483d56c5d7906cff`
   - dominant profiled stages remain `content_first_stage1` and `content_phishing`.
7. High-volume warning telemetry in heavy blocks:
   - `font.ttf_hinting_suspicious` warnings remain noisy in stderr and need aggregation strategy review.
8. Random sample composition quality:
   - ad-hoc random sweeps can still include duplicate hashes unless dedup is enforced in the sampler path.

## Concrete next-pass checklist (unresolved items)

1. [x] Outlier isolation for deep-scan tail latency
   - Scope: `81ec61a49b5fcc4e696974798b5e0d3582a297e9c6beaf95d56839b514e064f5`,
     `bf724f5f19df9b2fdb0f45a79b6d9a88e8acf02843465ce891c6a4ad6c8d47a6`,
     `4a9a844dbf0a4fbaa6b33b9ccc5f8b773ca4b286d389e5d3483d56c5d7906cff`.
   - Deliverables:
     - per-sample runtime profile breakdown (top 10 detectors)
     - repeated slow-stage attribution across at least 3 consecutive runs
     - candidate optimisation hypotheses ranked by expected gain/risk
  - Acceptance:
    - all three hashes have reproducible profile artefacts and a dominant-stage diagnosis.
  - Status:
    - completed; pass-1 and controlled 3-run pass artefacts collected with dominant-stage attribution.

2. [x] `parser_resource_exhaustion` trigger taxonomy completion
   - Deliverables:
     - grouped trigger classes from metadata (`structural`, `decode`, `font`, `content`, `js-runtime`)
     - per-class top finding kinds with counts and representative objects
     - remediation guidance per trigger class
  - Acceptance:
    - every observed exhaustion case in latest 2 blocks maps to a trigger class with remediation.
  - Status:
    - completed in core finding metadata; class-level counts, top kinds, representative objects, and remediation guidance now emitted per trigger class.

3. [x] `font.dynamic_parse_failure` signal split (noise vs exploit relevance)
   - Deliverables:
     - feature split criteria (magic, table layout, parser failure mode, corroborating findings)
     - confidence/severity adjustment rules with guardrails
  - Acceptance:
    - reduction in low-value `font.dynamic_parse_failure` triage rows without loss on known exploit fixtures.
  - Status:
    - completed with explicit triage taxonomy and guardrails in `font-analysis`; parse failures now emit exploit-relevance metadata, triage bucket, and class-specific remediation.

4. [x] Structural/content high-volume class disambiguation
   - Scope:
     - `content_stream_anomaly`
     - `label_mismatch_stream_type`
     - `image.decode_skipped`
   - Deliverables:
     - context-correlation rules (action/js/object-role aware)
     - aggregate metadata improvements for analyst pivoting
  - Acceptance:
    - ≥25% reduction in ambiguous medium/low rows on heavy files with no regression in high-risk recall.
  - Status:
    - completed with context-aware triage recalibration for `content_stream_anomaly`, `label_mismatch_stream_type`, and `image.decode_skipped`; each finding now carries pivot metadata (`triage.noisy_class_*`, `triage.context_signals`, object-overlap flag, bucket).

5. [ ] Secondary parser error-class prevalence baseline
   - Deliverables:
     - corpus summary of `secondary_parser.error_class` and hazard patterns
     - top malformed object signatures and affected object roles
   - Acceptance:
     - baseline report added with top classes and prioritised remediation candidates.

6. [ ] Sweep sampling dedup hardening for manual/ad-hoc workflows
   - Deliverables:
     - documented command path that enforces hash dedup by default
     - helper script or recipe used in triage loops
   - Acceptance:
     - random 30-file ad-hoc block contains zero duplicate content hashes.

## Resolved items

1. Unknown behavioural mapping for `dormant_or_gated_execution`:
   - mapped to `js_runtime_dormant_or_gated_execution`.
   - block-2 validation shows unknown count reduced to zero with mapped hits present.
2. ObjStm-aware adaptive content-first budget tightening:
   - implemented an additional adaptive budget clamp when ObjStm stream density is high.
   - new adaptive reason: `objstm_heavy`.
   - validation on `81ec...` reduced runtime profile total from ~141.3s to ~73.8s.
3. Hinting warning telemetry aggregation:
   - replaced per-program `font.ttf_hinting_*` warning spam with aggregated per-font telemetry.
   - aggregate warning includes kind/error counters and capped instruction-history samples.

## Block 1 (completed)

- Sample file: `/tmp/corpus_block30_parallel_1770802234.txt`
- Output dir: `/tmp/corpus_block30_parallel_outputs_1770802234`
- Attempted: 30
- Completed: 28
- Skipped (timeout): 2
- Unknown pattern findings: 3
- `parser_resource_exhaustion` findings: 12 (12 files)
- Detection duration: avg 4619.3ms, max 12083ms
- Wall clock: avg 5.707s, max 13.30s

### Block 1 unknown-pattern evidence

- `tmp/corpus/mwb-2026-01-19/9ff24c464780feb6425d0ab1f30a74401e228b9ad570bb25698e31b4b313a4f4.pdf`
  - `dormant_or_gated_execution`
  - evidence: large payload (55730 bytes) produced no runtime activity.
- `tmp/corpus/mwb-2026-01-24/9ff24c464780feb6425d0ab1f30a74401e228b9ad570bb25698e31b4b313a4f4.pdf`
  - `dormant_or_gated_execution`
  - evidence: large payload (55730 bytes) produced no runtime activity.
- `tmp/corpus/mwb-2026-02-09/38851573fd1731b1bd94a38e35f5ea1bd1e4944821e08e27857d68a670c64105.pdf`
  - `dormant_or_gated_execution`
  - evidence: large payload (112818 bytes) produced no runtime activity.

## Block 2 (completed)

- Sample file: `/tmp/corpus_block30_parallel_1770804839.txt`
- Output dir: `/tmp/corpus_block30_parallel_outputs_1770804839`
- Attempted: 30
- Completed: 26
- Skipped (timeout): 4
- Unknown pattern findings: 0
- `js_runtime_dormant_or_gated_execution`: 1
- `parser_resource_exhaustion` findings: 2 (2 files)
- Detection duration: avg 2180.6ms, max 14218ms
- Wall clock: avg 3.108s, max 14.72s

### Block 2 runtime outliers

- `tmp/corpus/mwb-2026-02-05/05cda79cf11759dd07c4dde149451e4ed2a43b0566bba55016e9a02ddb7e9295.pdf`
  - wall 14.72s, detection 14218ms, 217 findings, `parser_resource_exhaustion=1`.
- `tmp/corpus/mwb-2026-01-26/5bb77b5790891f42208d9224a231059ed8e16b7174228caa9dc201329288a741.pdf`
  - wall 6.17s, detection 5729ms, 86 findings, `parser_resource_exhaustion=1`.

## Block 3 (completed)

- Sample file: `/tmp/corpus_block30_parallel_1770840015.txt`
- Output dir: `/tmp/corpus_block30_parallel_outputs_1770840015`
- Attempted: 30
- Completed: 28
- Skipped (timeout): 2
- Unknown pattern findings: 0
- `js_runtime_dormant_or_gated_execution`: 1
- `parser_resource_exhaustion` findings: 7 (7 files)
- Detection duration: avg 3944.0ms, max 33378ms
- Wall clock: avg 4.462s, max 34.85s

### Block 3 runtime outliers

- `tmp/corpus/mwb-2026-01-24/fb87d8a7807626279bae04d56ba01ce1401917f6b0e7a74a335208a940221ddd.pdf`
  - wall 34.85s, detection 33378ms, 242 findings, `parser_resource_exhaustion=1`.
- `tmp/corpus/mwb-2026-02-02/fb87d8a7807626279bae04d56ba01ce1401917f6b0e7a74a335208a940221ddd.pdf`
  - wall 20.76s, detection 19664ms, 236 findings, `parser_resource_exhaustion=1`.
- `tmp/corpus/mwb-2026-01-17/91183972e908c013504d12d00c45f8576d733353c1c5274ebbd1c7c2e741f164.pdf`
  - wall 12.13s, detection 11301ms, 84 findings, `parser_resource_exhaustion=1`.
- `tmp/corpus/mwb-2026-01-30/91183972e908c013504d12d00c45f8576d733353c1c5274ebbd1c7c2e741f164.pdf`
  - wall 9.81s, detection 8995ms, 84 findings, `parser_resource_exhaustion=1`.

### Block 3 dominant finding classes

- `font.ttf_hinting_suspicious` (225)
- `uri_present` (142)
- `font.dynamic_parse_failure` (137)
- `annotation_action_chain` (103)
- `image.decode_skipped` (97)
- `label_mismatch_stream_type` (91)
- `content_stream_anomaly` (72)

### Block 3 targeted profiling notes

1. `fb87d8a7807626279bae04d56ba01ce1401917f6b0e7a74a335208a940221ddd` (2026-01-24 bucket)
   - Runtime profile:
     - `content_first_stage1` dominates (~97.3%, 18804ms).
     - `content_phishing` and image/vector detectors contribute secondary cost.
   - High-volume findings concentrated in:
     - `content_stream_anomaly`
     - `font.dynamic_parse_failure`
     - `font.ttf_hinting_suspicious`
   - `parser_resource_exhaustion` is driven mostly by repeated structural label mismatches plus trailer count inconsistencies.

2. `91183972e908c013504d12d00c45f8576d733353c1c5274ebbd1c7c2e741f164` (2026-01-17 bucket)
   - Runtime profile:
     - `content_first_stage1` dominates (~98.6%, 7100ms).
   - `parser_resource_exhaustion` tied to:
     - `objstm_embedded_summary`
     - `label_mismatch_stream_type`
     - `pdf.trailer_inconsistent`
     - `parser_trailer_count_diff`
   - Indicates resource pressure tracks repeated structural/ObjStm irregularity patterns rather than JS runtime unknowns.

## Immediate next investigation actions

1. Add per-kind contribution fields to `parser_resource_exhaustion` metadata:
   - include top contributing structural kinds with counts (already partial as list; add counts).
2. Add hash-level dedup in corpus block scripts:
   - avoid spending block budget on same payload hash across daily folders.
3. Add `content_first_stage1` micro-budgets for known heavy subpaths:
   - especially repeated stream anomaly scans and font dynamic parse loops.

## Block 4 (completed, 2026-02-12)

- Sample set:
  - deterministic seed: `20260212`
  - source list: `/tmp/corpus-sweeps/20260212_144642_seed20260212/sample_paths.txt`
- Artefacts:
  - batch summary: `/tmp/corpus-sweeps/20260212_144642_seed20260212/sweep_summary_postbuild.json`
  - batch raw output: `/tmp/corpus-sweeps/20260212_144642_seed20260212/scan_postbuild.json`
- Attempted: 30
- Completed: 30
- Scan errors: 0 hard failures (1 stderr error line observed)
- Findings total: 1347
- Severity totals:
  - High: 152
  - Medium: 309
  - Low: 324
  - Info: 562
- Detection duration (entry-level):
  - avg: 63.8s
  - median: 22.8s
  - p95: 194.9s
  - max: 218.7s
- Notable heavy files:
  - `81ec61a49b5fcc4e696974798b5e0d3582a297e9c6beaf95d56839b514e064f5` (218.7s)
  - `4a9a844dbf0a4fbaa6b33b9ccc5f8b773ca4b286d389e5d3483d56c5d7906cff` (196.3s)
  - `bf724f5f19df9b2fdb0f45a79b6d9a88e8acf02843465ce891c6a4ad6c8d47a6` (194.9s)
- JS runtime:
  - runtime error findings: 3
  - script timeout findings: 0
  - loop iteration limit hits: 0

## Outlier isolation (in progress, pass 1)

- Profiling artefacts:
  - `/tmp/corpus-sweeps/outlier-isolation-20260212/outlier_profiles_summary.json`
- Targets profiled:
  - `81ec61a49b5fcc4e696974798b5e0d3582a297e9c6beaf95d56839b514e064f5`
  - `bf724f5f19df9b2fdb0f45a79b6d9a88e8acf02843465ce891c6a4ad6c8d47a6`
  - `4a9a844dbf0a4fbaa6b33b9ccc5f8b773ca4b286d389e5d3483d56c5d7906cff`
- Initial diagnosis:
  - `81ec...`: `content_first_stage1` dominates (41.5s–88.9s), `content_phishing` is secondary but still material (14.8s–64.8s).
  - `bf724...`: `content_first_stage1` dominates (~60.3s), `content_phishing` secondary (~4.0s).
  - `4a9a...`: not an active outlier on current binary (~0.13s profile total); removed from immediate priority queue.
- Reproducibility note:
  - `81ec...` shows large run-to-run variance (profile total 43.4s to 90.0s), indicating cache/system-state sensitivity and need for multi-run baselining.
- Next outlier-isolation action:
  - run 3 consecutive profile passes for `81ec...` and `bf724...` under controlled conditions,
    then introduce detector-level timing counters in `content_phishing` subpaths to isolate the expensive branch(es).

## Outlier isolation (completed, pass 2 controlled 3-run)

- Profiling artefacts:
  - `/tmp/corpus-sweeps/outlier-isolation-20260212-pass2/pass2_rows.json`
  - `/tmp/corpus-sweeps/outlier-isolation-20260212-pass2/pass2_summary.json`
- `81ec61a49b5fcc4e696974798b5e0d3582a297e9c6beaf95d56839b514e064f5`
  - `profile_total_ms`: 38751, 45550, 42438 (spread 6799)
  - `content_first_stage1_ms`: 37572, 44421, 41129 (dominant)
  - `content_phishing_ms`: 15461, 15589, 14955 (stable secondary)
- `bf724f5f19df9b2fdb0f45a79b6d9a88e8acf02843465ce891c6a4ad6c8d47a6`
  - `profile_total_ms`: 61182, 72061, 75956 (spread 14774)
  - `content_first_stage1_ms`: 60717, 71460, 75341 (dominant)
  - `content_phishing_ms`: 3860, 7837, 8404 (secondary, variable)
- Conclusion:
  - tail latency remains driven by `content_first_stage1`; `content_phishing` is material but not primary for these outliers.
- Follow-on instrumentation:
  - added detector-level timing metadata + `content_phishing_runtime_hotspot` finding for expensive keyword/URI/HTML subpaths to support targeted optimisation loops.

## Parser exhaustion taxonomy validation (latest block outliers)

- Validation artefact:
  - `/tmp/parser_resource_taxonomy_validation.tsv`
- Samples replayed from recent heavy set:
  - `tmp/corpus/mwb-2026-02-05/05cda79cf11759dd07c4dde149451e4ed2a43b0566bba55016e9a02ddb7e9295.pdf`
    - classes: `font, structural, content, decode`
    - counts: `font=91, structural=27, content=17, decode=11`
  - `tmp/corpus/mwb-2026-01-24/fb87d8a7807626279bae04d56ba01ce1401917f6b0e7a74a335208a940221ddd.pdf`
    - classes: `font, content, decode, structural`
    - counts: `font=145, content=90, decode=21, structural=18`
  - `tmp/corpus/mwb-2026-01-26/5bb77b5790891f42208d9224a231059ed8e16b7174228caa9dc201329288a741.pdf`
    - no `parser_resource_exhaustion` emitted on current build (not a mapping failure).
- Metadata now emitted on `parser_resource_exhaustion`:
  - `resource_trigger_classes`
  - `resource_trigger_class_counts`
  - `resource_trigger.<class>.count`
  - `resource_trigger.<class>.top_kinds`
  - `resource_trigger.<class>.sample_objects`
  - `resource_trigger.<class>.remediation`
  - `resource_trigger_class_remediation`

## Font dynamic parse-failure split (completed)

- Implemented taxonomy in dynamic font parsing:
  - `unknown_magic_or_face_index` → low/weak, `noise_likely`
  - `truncated_tiny_font` → low/tentative, `noise_likely`
  - `malformed_structure` → medium/probable, `needs_correlation`
  - `parser_stress_signal` → high/strong, `exploit_relevant`
  - fallback `dynamic_runtime_failure` → medium/tentative
- Added metadata/guardrails on `font.dynamic_parse_failure`:
  - `parse_error_class`
  - `parse_error_exploit_relevance`
  - `parse_error_triage_bucket`
  - `parse_error_remediation`
  - `font.dynamic_data_len`
- Dynamic worker failures now mapped to low-relevance infrastructure class:
  - `parse_error_class=dynamic_worker_failure`
  - `parse_error_triage_bucket=runtime_infrastructure`
- Fixture-backed coverage added:
  - `crates/font-analysis/tests/fixtures/dynamic/unknown-magic-font.bin`
  - `crates/font-analysis/tests/fixtures/dynamic/truncated-sfnt-header.ttf`
- Validation:
  - `cargo test -p font-analysis -- --nocapture` (full pass)

## Structural/content disambiguation and pivot metadata (completed)

- Implemented in `recalibrate_findings_with_context`:
  - noisy class context-correlation for:
    - `content_stream_anomaly`
    - `label_mismatch_stream_type`
    - `image.decode_skipped`
  - bucketed triage outcomes:
    - `correlated_high_risk`
    - `correlated`
    - `likely_noise`
- Added per-finding analyst pivot metadata:
  - `triage.noisy_class_total_count`
  - `triage.noisy_class_kind_count`
  - `triage.noisy_class_counts`
  - `triage.context_signal_count`
  - `triage.context_signals`
  - `triage.object_overlap_with_risky_refs`
  - `triage.noisy_class_bucket`
- Added focused-triage aggregation for `image.decode_skipped`:
  - new aggregate finding kind: `image.decode_skipped_aggregate`
  - canonical signature keys include dynamic/image-format/source fields.
- Validation:
  - `cargo test -p sis-pdf-core noisy_class_disambiguation -- --nocapture`
  - `cargo test -p sis-pdf-core focused_triage_aggregates_noisy_kinds_with_samples -- --nocapture`
