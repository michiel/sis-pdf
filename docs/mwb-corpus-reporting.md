# MWB corpus reporting

This guide extends the daily MalwareBazaar corpus collection workflow with SIS scans,
trend metrics, and static web reports.

## Install/update SIS from releases

Use the install script to fetch the latest release binary:

```bash
./scripts/update_sis_release.sh
```

If you want a different install directory:

```bash
SIS_INSTALL_DIR=/opt/sis/bin ./scripts/update_sis_release.sh
```

## Scan the daily corpus and build reports

```bash
./scripts/mwb_corpus_pipeline.py \
  --corpus-root ~/corpus \
  --output-root ~/corpus-metrics \
  --deep
```

The pipeline performs three steps:

1. Scans each `mwb-YYYY-MM-DD` directory with `sis scan --jsonl-findings`.
2. Aggregates findings into summary JSON for each day.
3. Generates static HTML reports for daily, weekly, and monthly views.

If you only want a specific day:

```bash
./scripts/mwb_corpus_pipeline.py --date 2026-01-15
```

To re-run scans even if outputs exist:

```bash
./scripts/mwb_corpus_pipeline.py --force
```

## Ad-hoc random sweeps with hash dedup (default)

Use the dedicated sampler to build a deterministic 30-file list that is deduplicated by
content hash across daily folders:

```bash
python scripts/sample_corpus_unique.py \
  --corpus-root tmp/corpus \
  --sample-size 30 \
  --seed 20260212 \
  --out /tmp/corpus_sample_unique_30.txt \
  --summary-out /tmp/corpus_sample_unique_30.summary.json
```

Then run the scan against the sampled list:

```bash
xargs -a /tmp/corpus_sample_unique_30.txt -I{} sis scan "{}" --deep --json > /tmp/corpus_sample_unique_30.scan.jsonl
```

## Output structure

```
~/corpus-metrics/
  scans/2026-01-15/sis_findings.jsonl
  scans/2026-01-15/sis_scan_errors.log
  summaries/2026-01-15.json
  reports/index.html
  reports/daily/2026-01-15.html
  reports/weekly/2026-W03.html
  reports/monthly/2026-01.html
```

## Cron example

This cron example updates SIS, runs the daily scan, and refreshes reports:

```cron
15 3 * * * /home/sis-scanner/sis-pdf/scripts/update_sis_release.sh
30 3 * * * /home/sis-scanner/sis-pdf/scripts/mwb_corpus_pipeline.py --corpus-root /home/sis-scanner/corpus --output-root /home/sis-scanner/corpus-metrics --deep
```

## Interpreting regressions and gaps

The daily report highlights:

- **Missing kinds**: findings present on the previous day but absent today.
- **High severity drops**: cases where High findings went to zero.
- **Largest deltas**: the biggest kind-level changes day-over-day.

Use the error and warning counters to spot parsing regressions or stability issues.
