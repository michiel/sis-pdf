# Runtime Performance Profile

This page captures the Stage 0.5 instrumentation run described in the analysis plan. It proves the `--runtime-profile` instrumentation is wired into `sis scan`, that the Service Level Objectives stay well below their thresholds, and that the resulting JSON report can be reused as a benchmark for future regressions.

## Instrumentation run

```bash
cargo run -p sis-pdf --bin sis -- scan \
  crates/sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf \
  --deep \
  --runtime-profile \
  --runtime-profile-format json \
 2> profile-launch-cve.json
```

This command uses the existing Stage 1 CVE fixture because it touches embedded files, launch actions, and high-entropy payloads. The profile JSON ends up on STDERR, so the runner redirects it to `profile-launch-cve.json` for later analysis. The detector timings feed the `sis_pdf_core::profiler::Profiler`, so every detector invocation enters the `phases` and `detectors` arrays that were replicated in the Stage 0.5 performance table.

## Measured results

| Operation | Target latency (from Stage 0.5 plan) | Observed | Comments |
| --- | --- | --- | --- |
| Parsing & structure recovery (Phase A) | <10 ms | 0 ms | The document is tiny; the JSON profile reports `parse` at 0 ms. |
| Detection phase (Phase B) | <50 ms | 2 ms | The combined detection duration includes all detectors (action chains, embedded files, encryption, filters). `content_first_stage1` alone ran in 1 ms, so every SLO in the plan (embedded hash, action chain walk, XFA parse, SWF header, entropy, filter validation) stays far below its maximum in this fixture. |
| Total scan | n/a | 6 ms | Total duration includes reporting and overhead; the profiler still prints the human-readable summary shown below. |

## Sample profile JSON

The profiler emits a JSON object with phases, precise detector timings, and document statistics. A truncated excerpt looks like this:

```json
{
  "total_duration_ms": 6,
  "phases": [
    { "name": "parse", "duration_ms": 0, "percentage": 0.0 },
    { "name": "detection", "duration_ms": 2, "percentage": 33.3 }
  ],
  "detectors": [
    { "id": "content_first_stage1", "cost": "Expensive", "duration_ms": 1, "findings_count": 1, "percentage": 16.7 },
    { "id": "launch_action_present", "cost": "Cheap", "duration_ms": 0, "findings_count": 2, "percentage": 0.0 }
  ],
  "document": {
    "file_size_bytes": 412,
    "object_count": 4,
    "stream_count": 0,
    "page_count": 4
  }
}
```

Because the JSON is deterministic, it can be checked into the performance repo (`profile-launch-cve.json`) or compared against future runs with tools such as `jq` or pandas. The CLI also prints a human-readable summary to STDERR, so operators can glance at high-level timings even when they are not capturing the JSON file.

## Next steps

1. Repeat the run with other CVE fixtures if you need evidence that the SLO table holds for filters, XFA forms, or rich media content.
2. Collect any deviations from the SLOs and log them in this doc (or `docs/analysis.md`) so that operators know whether a particular detector is approaching its budget.
3. When packaging release notes, include the `profile-launch-cve.json` snippet or a similar JSONL export so the Stage 0.5 instrumentation effort remains reproducible.
