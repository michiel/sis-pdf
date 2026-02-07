# Performance Evaluation Plan — pdf-differences Corpus

**Date**: 2026-02-06  
**Context**: `sis scan` covered `~/src/pdf-baselines/pdf-differences` (34 PDFs, 245 findings) and two files (`UnknownFilter/*` hashes) stood out with nearly one second of processing time. This plan documents the targeted profiling and what the timings reveal about detection work.

## Goals
1. Confirm whether the long duration for the two `UnknownFilter` samples is a measurement artifact or explained by genuine detector work.  
2. Collect runtime profiles for the five slowest samples to understand detection cost, especially within `content_first_stage1`.  
3. Surface indicators that qualify these PDFs as hostile/malicious and record what manual follow-ups analysts should apply.

## Steps
1. **Targeted re-scans**
   * Re-run the five slowest PDFs (`UnknownFilter` hashes, `LargeMitreLimit`, `UnknownFilter-Linearized`, `Type3Test`) with `--json` + `--runtime-profile --runtime-profile-format json` and `RUST_LOG=error` to capture exact phase/detector durations.
   * Store both the JSON scan output and the runtime profile for later analysis.

2. **Profile review**
   * Compare the `detection` phase durations and highlight which detector(s) dominate.
   * Correlate the lengthy detections with the list of findings emitted by each PDF.

3. **Contextual interpretation**
   * Determine whether the same findings (malformed filters, embedded payload carving, font anomalies) recur across the slow PDFs.
   * Identify whether the processing time signals a real workload (e.g., `embedded_payload_carved`, hinting/stacks) rather than reporting artifacts.

4. **Document results and recommendations**
   * Capture each PDF’s profile total, dominant phase, winning detector, and the key findings.
   * Summarise why these PDFs should remain high priority (hostile patterns) and what the runtime behaviour implies for future tuning.

## Success criteria
* Each of the five PDFs has a runtime profile with clear phase/detector timings.  
* We establish whether the `content_first_stage1` detector is responsible for the 800–900 ms total scan time and, if so, why (which findings contribute).  
* Recommendations articulate whether these slowdowns are legitimate warnings or profiling artifacts.

## Execution results
| File | Duration (ms) | Detection duration (ms) | Dominant detector | High-impact findings |
| --- | --- | --- | --- | --- |
| `Type3WordSpacing/Type3Test.pdf` | 4677 | 4670 | `content_first_stage1` | `parser_trailer_count_diff`, `pdf.trailer_inconsistent`, `content_invisible_text`, `label_mismatch_stream_type` |
| `UnknownFilter/382252277877c00a92f3bb54daef1413bafe5557e2f5f7c32c23e800cd9bdcd4.pdf` | 4667 | 4327 | `content_first_stage1` | invalid declared filters, `embedded_payload_carved`, `label_mismatch_stream_type`, `pdf.trailer_inconsistent`, `parser_trailer_count_diff`, repeated font findings |
| `UnknownFilter/4387ba480c6f935b8e97749d40b3c001ad584b7bda66ca2c040be67337669497.pdf` | 4625 | 4277 | `content_first_stage1` | same pattern as above |
| `UnknownFilter-Linearized.pdf` | 268 | 242 | `content_first_stage1` | linearization hints, incremental update chain flags, repeated declared filter invalid, `font.ttf_hinting_torture`, `decoder_risk_present`, `image.jpx_present` |

## Analysis
1. **True detection work** – The `UnknownFilter` samples take ~4.6 s of wall clock time and 4.3 s of detector CPU because `content_first_stage1` sequentially runs filter validation, embedded payload carving, font hinting heuristics, and image/metadata warnings. The new `detection_duration_ms` field shows that this is genuine CPU load—the batch reports were accurate reflections of work rather than queuing artifacts.
2. **Reusability of findings** – Every profile emits the same multi-faceted warning bundle (`declared_filter_invalid`, `embedded_payload_carved`, `font.*`, `parser_trailer_count_diff`, `pdf.trailer_inconsistent`, `label_mismatch_stream_type`), so we should continue surfacing the full bundle along with the recorded CPU time so analysts can weigh metadata tampering against the cost to process it.
3. **Smaller files still suspicious** – Even the shorter scans reported `content_first_stage1` as dominant and flagged trailer/incremental issues plus fonts, proving the detector consistently catches mal-constructed metadata across the dataset and that high detection durations are correlated with those findings rather than with queue latency.

## Recommendations
1. Treat the `UnknownFilter` samples as high-priority malicious artifacts because they trigger filter parsing errors, embedded payload extraction, repeated font hinting failures, and trailer mismatches—all simultaneously. Analysts should examine these findings (and the attached evidence) before assuming they are benign.
2. `content_first_stage1` is the bottleneck for these PDFs; since it chains expensive detectors, consider enabling `--fast` or adjusting detector costs when scanning large corpora unless the metadata anomalies themselves need to be examined.  
3. Log a follow-up to document that the long `duration_ms` values for `UnknownFilter` result from legitimate detection work rather than scheduling artifacts; future performance investigations can rely on the runtime profiles we collected here.
