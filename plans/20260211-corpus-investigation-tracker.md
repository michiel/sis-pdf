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
