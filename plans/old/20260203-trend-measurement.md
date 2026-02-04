# 20260203 Trend measurement plan

## Context

The nightly `scripts/mwb_corpus_pipeline.py` harvests new PDF samples. We now need to run `sis --deep` both on each new batch and against the growing historic corpus, and capture structured statistics (finding counts by severity/kind, runtime, errors, corpus width). The results must be exportable as CSV files consumable by Grafana SaaS for dashboards covering:

1. **Finding distribution snapshot** (per run): total finding counts, severity breakdown, top kinds.
2. **Temporal trends**:
   * Day-over-day aggregates summarizing deltas in finding counts, errors, and runtimes.
   * Week-over-week rolling windows to capture more stable signals (avg runtime, median finding count, new finding kinds appearing).
3. **Corpus growth & drift**: new files added, total bytes processed, skew in filter usage (e.g., % of `/JPXDecode` streams).

We already retain CSV artifacts (`evaluate-mwb-corpus.py`), but the script must be extended to compute these statistics and keep living outputs in `reports/trends/` (daily and weekly subfolders) ready for Grafana ingestion. Documentation must explain how to trigger the pipeline and interpret fields (`docs/trend-guide.md`).

## Goals

1. Extend `scripts/evaluate-mwb-corpus.py` to:
   - Accept arguments pointing to the latest batch and the master corpus directories.
   - Run `sis scan --deep` (or `sis report --deep --json`) against each target, capture timing, and read resulting findings JSON.
   - Aggregate per-run summaries (counts by severity/kind, CI run durations, errors) and write `daily_summary.csv`.
   - Merge new data into long-running stats files `trends/daily.csv` and `trends/weekly.csv`.
   - Emit `findings_distribution_YYYY-MM-DD.csv` and `errors_YYYY-MM-DD.csv` for Grafana dashboards.

2. Document the workflow in `docs/trend-guide.md`:
   - Describe inputs (batch dir, corpus dir) and triggers (CI nightly job or cron-based job).
   - Include installation steps for dependencies (`sis` binary, Python env), linking back to `scripts/install.sh` and `install.ps1`.
   - Provide cron example (e.g., `0 3 * * * /path/to/scripts/mwb_corpus_pipeline.py --ci --report`) capturing both daily batch ingestion and full-corpus runs, plus log rotation/storage suggestions.
   - Define each CSV schema (columns: date, kind, severity, count, runtime_ms, files_scanned, new_files, errors, filter_usage, run_id, etc.).
   - Provide sample Grafana queries (e.g., `SELECT count FROM daily WHERE kind='declared_filter_invalid'`) and recommended visualizations (stacked bars, line of avg runtime).
   - Explain how to interpret deltas vs. corpus growth and how to handle noisy patterns (e.g., spiky new `vector_graphics_anomaly` counts).

3. Ensure plan includes:
   - Example data snapshots in the plan (e.g., sample CSV rows, derived metrics like `runtime_ms` or `avg_findings_per_file`).
   - Guidance on running the pipeline manually for debugging.
   - Mention storage location (e.g., `reports/trends/daily.csv`) and retention policy (append-only, normalized).

## Proposed steps

1. **Instrument `evaluate-mwb-corpus.py`.**
   * Add CLI options for batch path, corpus path, output dir, and `--grafana` flag toggles.
   * After running `sis scan --deep`, parse JSON/JSONL by streaming (avoid loading everything). Collect:
     - Total findings, severity breakdown.
     - Top 10 finding kinds (with counts).
     - Runtime (wall+CPU) from `sis` output or record start/end times.
     - Errors (failures, aborted files).
     - Corpus metrics (files scanned, bytes processed).
   * Emit a JSON summary that includes the same stats plus the list of changed finding kinds (present in daily summary but not previous daily) captured via a rolling cache (maybe `reports/trends/last_kind_set.json`).
   * Append row to `reports/trends/daily.csv`: `date,stage,target,total_findings,info,low,medium,high,critical,files,bytes,new_finding_kinds,avg_findings_per_file,runtime_ms,error_count`. Include `run_id` or deterministic hash so re-running the same input (same batch/corpus + date) can detect duplicates and replace/skip existing rows, ensuring idempotent writes.
   * Weekly file: compute aggregates (sum/avg per week) and append to `reports/trends/weekly.csv`, recalculating entries for affected week ranges when reprocessing.
   * Write Grafana-ready artifact (e.g., `reports/trends/grafana/findings_by_kind_YYYY-MM-DD.csv` with columns `date,kind,count,severity,target`).

2. **Schedule execution** via the existing daily job (probably `scripts/mwb_corpus_pipeline.py`).
   * After new batch is generated, call the evaluation script twice (batch vs. corpus) and copy stats to `reports/trends`.
   * Add a simple `scripts/run_trend_pipeline.sh` (keeps script count minimal) that orchestrates `sis scan` calls, `evaluate-mwb-corpus.py`, and rotates weekly summaries.

3. **Doc updates**
   * `docs/trend-guide.md` should describe:
     - Where stats live (`reports/trends/*`), naming convention, ingestion in Grafana.
     - Definitions for `daily.csv`, `weekly.csv`, and per-kind CSVs.
     - Steps to trigger (manually run install script, call `scripts/mwb_corpus_pipeline.py --report`).
     - Example analyses: day/day delta, weekly comparison, anomaly detection.

## Example data samples

`reports/trends/daily.csv`:
```
date,target,total_findings,info,low,medium,high,critical,files_scanned,total_bytes,new_kinds,avg_findings_per_file,runtime_ms,error_count
2026-02-03,batch-20260203,128,64,32,20,10,2,15,1203045,vector_graphics_anomaly,8.5,45231,0
2026-02-03,corpus-master,9240,4320,2560,1620,530,110,1200,83645032,js_present,7.7,862133,3
```

`reports/trends/weekly.csv`:
```
week_start,target,total_findings,median_runtime_ms,avg_findings_per_file,new_kinds,sum_errors
2026-01-28,batch,910,44500,8.1,vector_graphics_anomaly|split_path,1
2026-01-28,corpus,60250,131200,6.9,uri_present|high_entropy,5
```

`reports/trends/grafana/findings_by_kind_2026-02-03.csv`:
```
date,kind,severity,count,target
2026-02-03,vector_graphics_anomaly,Medium,42,batch-20260203
2026-02-03,js_present,High,19,corpus-master
2026-02-03,uri_present,Medium,130,corpus-master
```

## Next steps

1. Update `scripts/evaluate-mwb-corpus.py` per above.
2. Create doc `docs/trend-guide.md` with schemas and Grafana hints.
3. Add a helper orchestration script to `scripts/` that reuses `evaluate-mwb-corpus.py` outputs.
`reports/trends/json/daily_<date>_<target>.json` (contains the same fields as `daily.csv` plus derived metrics such as `duration_stats`, `parse_errors`, `warning_count`, `filter_usage`, `surface_counts`, `avg_severity_rank`, `error_ratio`, and `new_kind_flags`). Grafana can ingest these via HTTP.
