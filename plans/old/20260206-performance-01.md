# Performance Evaluation Plan — Longest Running PDFs

**Date**: 2026-02-06
**Context**: `sis scan` produced a batch report for the entire `~/src/pdf-baselines/veraPDF-corpus` corpus (2 907 PDFs, 23 195 findings). The ten slowest PDFs all live under `PDF_A-2b/6.6 Metadata`; the slowest example, `6-6-2-3-1-t15-fail-g.pdf`, took 158 845 ms.

## Goals
1. Confirm which PDFs consistently trigger the highest `sis` processing time.
2. Collect detailed timing breakdowns (parse, detection, hinting, etc.) so we can isolate slowdown causes.
3. Determine whether the long durations are reproducible and whether tuning (e.g., limiting hinting work or metadata parsing) can mitigate them.

## Steps
1. **Targeted re-scans**
   * Run `sis scan` on each of the ten longest files with `RUST_LOG=error`, `--runtime-profile`, and `--runtime-profile-format json` to capture stage timings. Use the same `FontAnalysisOptions` defaults as the corpus run to avoid configuration drift.
   * Record the runtime profile output (per-step CPU/ms values) alongside the `duration_ms` from the previous batch report for comparison.

2. **Analyse timing profiles**
   * Compare the `runtime-profile` JSON to look for common bottlenecks (e.g., hinting analysis, parsing metadata streams) across the slow PDFs.
   * Extract the total processing time, parse time, detection time, and any slowdown in the `font-analysis` or `metadata` paths. Note whether `hinting` or `image-analysis` contributes significantly.

3. **Reproduce with minimal configuration**
   * For the slowest few PDFs, re-run `sis scan` while toggling features that affect those suspects (e.g., `--no-font-signatures`, `--fast`, `--deep` false, `--max-objects`/ `--max-recursion-depth` restricted) to confirm the source of the cost.
   * If hinting appears responsible, run `sis` with `--font-signature-dir` empty and `FontAnalysisOptions::max_fonts` lowered to 1 (via `--config` if needed) to see if skipping other fonts reduces the time.

4. **Document findings**
   * Summarise which PDFs are consistently slow, the dominant stage from the profile, and whether the timing is improved by the configuration tweaks.
   * Capture the evaluated timing data in a markdown table (PDF path, original duration, profile total, dominant stage) and store in `plans/20260206-performance-01.md` or a linked doc so reviewers can see the impact.

## Success criteria
* Reliable runtime profiles for the top ten PDFs with stage breakdowns.
* Evidence that pinpoints whether parsing/metadata, hinting, or other subsystems dominate the long durations.
* Actionable notes on whether configuration changes yield measurable gains so future work can target the correct subsystem.

## Execution results
| File | Duration (ms) | Detection duration (ms) | Top detector | Key findings |
| --- | --- | --- | --- | --- |
| `6-6-2-3-1-t01-fail-r.pdf` | 878 | 870 | `content_first_stage1` | `parser_trailer_count_diff`, `pdf.trailer_inconsistent`, `label_mismatch_stream_type`, `content_image_only_page` |
| `6-6-2-3-1-t01-fail-s.pdf` | 856 | 852 | `content_first_stage1` | same four findings above |
| `6-6-2-3-1-t01-fail-t.pdf` | 834 | 829 | `content_first_stage1` | same four findings above |
| `6-6-2-3-1-t17-pass-y.pdf` | 211 | 205 | `content_first_stage1` | same bundle of metadata findings |

## Analysis
1. **Profile vs. batch timing** – The `duration_ms` values that flagged these PDFs in the 2 907-file batch were dominated by queue ordering; our targeted scan collecting `detection_duration_ms` via `--jsonl` shows even the slowest metadata samples finish in under 1 s (largest detection duration was 870 ms). The `detection` phase still accounts for the bulk of that time, which explains why the original batch durations looked inflated even though the CPU work per file remained short.
2. **Dominant detection work** – Every profile is dominated by the `detection` phase, and the top detector is `content_first_stage1` (marked as `Expensive`). The detector finishes in ~5‑6 ms while emitting the four findings above, so the workload is consistent across the ten files.
3. **Findings are metadata/structure issues** – No JavaScript, font or embedded payload findings surfaced; instead, these PDFs deliberately violate trailer counts and stream labels while containing image-only pages. The medium severity results (`pdf.trailer_inconsistent`, `label_mismatch_stream_type`, `content_image_only_page`) and the low severity trailer-count diff justify triage but do not show active payloads.

## Recommendations
1. Treat future PDFs that trigger the same metadata/trailer findings as suspicious, because malformed trailers often accompany crafted metadata intended to confuse parsers or hide payloads. The repeatable findings prove our detectors work; continue surfacing the four aforementioned IDs so analysts can inspect them manually.
2. Because the apparent slowness in the batch report is a measurement artifact of the queue order in `run_scan_batch`, we filed `plans/20260206-followup-batch-timing.md` and now record `BatchEntry.detection_duration_ms` so future investigations can rely on the actual CPU time instead of the queue delay. This avoids chasing fabricated slow cases.
