# Trend measurement guide

This guide explains how to collect daily/weekly statistics from the MWB corpus using `sis --deep`, where the CSV outputs in `reports/trends/` feed Grafana dashboards for finding distribution, performance, and drift.

## Installation prerequisites

1. Install the latest `sis` binary (Linux/macOS/x86_64 by default):

   ```bash
   curl -fsSL https://raw.githubusercontent.com/michiel/sis-pdf/main/scripts/install.sh | sh
   ```

2. On Windows PowerShell:

   ```powershell
   irm https://raw.githubusercontent.com/michiel/sis-pdf/main/scripts/install.ps1 | iex
   ```

3. Our pipeline relies on `scripts/evaluate-mwb-corpus.py`. Ensure Python 3.9+ is available and dependencies (standard library only) are met.

## Running the trend pipeline

The Fedora VM already maintains a `corpus/` tree under `/home/sis-scanner`, with manifests alongside each `mwb-YYYY-MM-DD` directory. After the daily download (see `scripts/run_daily.sh` triggered from cron), run the trend pipeline from the repo checkout:

```bash
cd /home/sis-scanner/dev/sis-pdf
scripts/run_trend_pipeline.sh /home/sis-scanner/corpus/mwb-2026-02-04 /home/sis-scanner/corpus --batch-parallel
```

Set `SIS_BINARY` if you need the virtualenv copy:

```bash
SIS_BINARY=/home/sis-scanner/.venv/bin/sis scripts/run_trend_pipeline.sh ...
```

### Cron + corpus maintenance

Daily fetches already run via `/home/sis-scanner/scripts/run_daily.sh`, which sources `/home/sis-scanner/.env.prod`, activates `/home/sis-scanner/.venv`, downloads the day’s files into `/home/sis-scanner/corpus/mwb-YYYY-MM-DD`, and logs to `/home/sis-scanner/scripts/download.log`.

Use cron entry:

```
0 03 * * * /home/sis-scanner/scripts/run_daily.sh
```

Then (at e.g. 04:00) run the trend pipeline over the newest batch and entire corpus:

```
0 04 * * * cd /home/sis-scanner/dev/sis-pdf && \
  scripts/run_trend_pipeline.sh /home/sis-scanner/corpus/mwb-latest /home/sis-scanner/corpus \
  >> /home/sis-scanner/logs/trend_pipeline.log 2>&1
```

This pipeline writes CSVs to `/home/sis-scanner/dev/sis-pdf/reports/trends`. Copy (or symlink) `daily.csv` into `/var/www/html/daily.csv` so Grafana SaaS can scrape it, and keep the Grafana directory in sync (`reports/trends/grafana/`). Rotate both logs monthly and upload archived CSV snapshots if needed.

## CSV outputs

All files are under `reports/trends/`.

### `daily.csv`

| column | description |
| --- | --- |
| `run_id` | SHA1 hash of `<target>|sorted_pdf_paths` for idempotency. |
| `date` | ISO date of the run. |
| `target` | Batch directory name or corpus identifier. |
| `total_findings`, `info`, `low`, `medium`, `high`, `critical` | Finding breakdown. |
| `files_scanned`, `bytes_scanned` | Scope of the run. |
| `avg_findings_per_file`, `runtime_ms` | Derived ratios. |
| `error_count` | `sis` errors/warnings observed. |
| `new_kinds` | Pipe-separated kinds unseen in previous runs. |

Example row:

```
run_id,date,target,total_findings,info,low,medium,high,critical,files_scanned,bytes_scanned,avg_findings_per_file,runtime_ms,error_count,new_kinds
af1b3c...,2026-02-04,mwb-2026-02-04,112,44,28,30,8,2,12,1030456,9.33,41210.5,0,vector_graphics_anomaly
```

### `weekly.csv`

Aggregated view (Monday week start) built from `daily.csv`. Columns:

`week_start`, `target`, `total_findings`, `median_runtime_ms`, `avg_findings_per_file`, `files_scanned`, `errors`, `new_kinds`.

Use this file to spot weekly momentum (e.g., sustained rise in `high` counts) without per-day noise.

### Grafana CSVs

`reports/trends/grafana/findings_by_kind_<date>_<target>.csv` lists per-kind counts:

```
date,target,kind,severity,count
2026-02-04,mwb-2026-02-04,vector_graphics_anomaly,Medium,42
2026-02-04,corpus-master,js_present,High,18
```

Ingest these files directly via Grafana SaaS upload or via automated connectors.

## Grafana queries

- **Finding trend**: `SELECT total_findings FROM daily WHERE target='mwb-2026-02-04'` (line chart).  
- **Severity mix**: sum columns `info`, `low`, ... to create stacked bar per day.  
- **Runtime stability**: median runtime from `weekly.csv` (line).  
- **New kinds**: filter `daily.csv` for `new_kinds != ""`, explode on Grafana side.

## Interpreting trends

- Day-over-day deltas highlight regressions immediately; watch for spikes in `error_count` or `high` severity.  
- Week-over-week smoothing reveals drift (e.g., new `vector_graphics_anomaly` counts due to batch ingestion).  
- New `kinds` indicate previously unseen heuristics firing; correlate with `docs/findings.md` to validate significance.  
- Compare `corpus-master` vs. latest batch to verify new samples remain in line with historic behaviour.

## Troubleshooting

- If `daily.csv` shows duplicate `run_id` entries, rerun `scripts/run_trend_pipeline.sh` after deleting the offending day row; the script will replace entries deterministically.  
- Review `reports/trends/grafana/` CSVs for missing dates—the script overwrites them each run.  
- Keep `SIS_BINARY` in PATH or specify absolute path in cron.
