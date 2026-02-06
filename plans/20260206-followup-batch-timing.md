# Follow-up Issue — Batch timing accuracy

**Date**: 2026-02-06

**Summary**: `run_scan_batch` currently reports `duration_ms` that include queuing and scheduling delays, which makes long-running jobs appear slow even when each file only spends milliseconds on detection. The VeraPDF metadata corpus flagged several PDFs solely because they happened to be near the end of the queue. To avoid chasing non-existent bottlenecks, we need to record each file’s actual CPU/detection time (and its contributing detection phases) alongside the existing total duration.

**Context and observations**

- The targeted VeraPDF scan now emits `detection_duration_ms` for each file, and our `jsonl` output shows the deliberate metadata manipulators finish in <1 s while still triggering `content_first_stage1`’s trailer/label detections. The long durations seen in the earlier batch report were artifacts of queue placement.
- The pdf-differences run produced ~4.6 s detection times for the UnknownFilter/Test files, confirming those slowdowns are real work. Capture 4.6 s in the profile, not the global batch elapsed time.
- The new `Report::detection_duration_ms` field and `BatchEntry.detection_duration_ms` already store these values, but we still need to document the requirement so future instrumentation and batch viewers rely on the CPU figure instead of the queue duration.

**Action items**

1. Emphasise in dashboards/logs and documentation that `BatchEntry.detection_duration_ms` is the field to use when investigating per-file performance; the existing `duration_ms` continues to capture end-to-end time.
2. Capture the detection phase breakdown (`Report::profiler`) when `--runtime-profile` is enabled so analysts can correlate `detection_duration_ms` with specific detectors (e.g., `content_first_stage1` for the UnknownFilter samples).
3. If future slowdowns are reported by operations staff, confirm they are backed by `detection_duration_ms` rather than the batch queue order before triggering a mitigation effort.

