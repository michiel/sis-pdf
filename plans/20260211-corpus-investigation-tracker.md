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

## Resolved items

1. Unknown behavioural mapping for `dormant_or_gated_execution`:
   - mapped to `js_runtime_dormant_or_gated_execution`.
   - block-2 validation shows unknown count reduced to zero with mapped hits present.

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
