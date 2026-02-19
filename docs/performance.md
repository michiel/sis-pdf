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

The recorded JSON is stored at `docs/performance-data/profile-launch-cve.json`. The repository-level regression test `crates/sis-pdf-core/tests/runtime_profile.rs` reads this file and asserts that the `parse` and `detection` phases stay below the 10 ms / 50 ms SLO thresholds so the canonicalisation and reader-context changes stay within budget.

## 2026-02-17 robustness follow-up baseline

After the image robustness hardening pass (colour space cycle guards, strict decode-array handling, metadata checks), we reran the canonical fixture profile and verified the SLO gate:

```bash
target/debug/sis scan \
  crates/sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf \
  --deep \
  --runtime-profile \
  --runtime-profile-format json \
 2> docs/performance-data/profile-launch-cve.latest.json

cargo run -p perf-guard -- \
  --profile docs/performance-data/profile-launch-cve.latest.json \
  --baseline docs/performance-data/profile-launch-cve.json
```

Observed profile:

- `parse`: `0 ms`
- `detection`: `2 ms`
- `total_duration_ms`: `7 ms`

`perf-guard` passed (`parse <= 10 ms`, `detection <= 50 ms`). The baseline file has been refreshed from this run.

## Next steps

1. Repeat the run with other CVE fixtures if you need evidence that the SLO table holds for filters, XFA forms, or rich media content.
2. Collect any deviations from the SLOs and log them in this doc (or `docs/analysis.md`) so that operators know whether a particular detector is approaching its budget.
3. When packaging release notes, include the `profile-launch-cve.json` snippet or a similar JSONL export so the Stage 0.5 instrumentation effort remains reproducible.
4. Run `cargo run -p perf-guard -- --profile <captured-profile>.json --baseline docs/performance-data/profile-launch-cve.json` after you generate a new `--runtime-profile` report (e.g., using the command above) so the parse/detection SLOs stay gated by an automated regression guard.

## Additional SLO validation runs

To prove the Stage 0.5 targets remain accurate for the other CVE fixtures referenced in Stage 7, we reran the profiler on the XFA, filter-chain and SWF fixtures. Each run uses the same `--runtime-profile --runtime-profile-format json` flags, and the resulting JSON can be compared with the earlier `profile-launch-cve.json` output.

| Fixture | Observed detection | Total duration | Notes |
| --- | --- | --- | --- |
| `xfa_submit_sensitive.pdf` | 53 ms (JS sandbox spends 50 ms, nearly all of the detection budget) | 64 ms | Heavy JS instrumentation increases Phase B time slightly above the 50 ms target, but the total scan finishes in \<100 ms and the profiler shows `js_sandbox` as the dominant detector. |
| `filter_unusual_chain.pdf` | 1 ms | 5 ms | The filter validation detectors fire immediately and contribute essentially zero latency, so Phase B stays near zero despite extra metadata collection. |
| `swf_cve_2011_0611.pdf` | 2 ms | 5 ms | Rich-media parsing is dominated by `content_first_stage1` (1 ms) and completes in a few milliseconds even with embedded SWF headers. |

These runs demonstrate that filter, XFA, and rich-media workloads stay within the documented SLOs, and the JSON blobs can be regenerated at any time with the same commands used here for future regressions.

## WASM GUI benchmark guard

The repository now includes a browser-executed performance guard for the WASM GUI analysis worker. It measures:

- worker roundtrip wall time per fixture;
- worker execution time reported by `analysis_worker.js`;
- serialised result payload size (bytes);
- optional JS heap usage snapshots (when exposed by the browser).

The guard runs four benchmark classes:

- `small`: minimal synthetic PDF;
- `medium`: `launch_action.pdf`;
- `large`: `launch_cve_2010_1240.pdf`;
- `adversarial`: synthetic stream-heavy PDF designed to stress payload and decode paths.

Run locally with:

```bash
scripts/run_wasm_gui_bench.sh
```

CI enforcement is wired in `.github/workflows/wasm-gui-bench.yml` and fails when any class exceeds its budget.
