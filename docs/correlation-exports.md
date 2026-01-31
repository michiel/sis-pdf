# Correlation exports

Stage 9 composite findings can be exported for dashboards or ML ingestion via the new `correlations` query. The result contains a per-pattern summary (count + severity) that is easy to turn into CSV, JSON or JSONL.

## Quick commands

```bash
sis query sample.pdf correlations --format json
sis query sample.pdf correlations --format jsonl
sis query --path some/corpus --glob "*.pdf" correlations --format jsonl > correlations.jsonl
sis query sample.pdf correlations.count
```

The default JSON response looks like:

```json
{
  "file": "/tmp/sample.pdf",
  "query": "correlations",
  "result": {
    "launch_obfuscated_executable": {
      "count": 1,
      "severity": "Critical"
    },
    "xfa_data_exfiltration_risk": {
      "count": 0,
      "severity": "High"
    }
  }
}
```

## CSV exports

Use the helper script to flatten the JSONL stream into CSV for dashboards or automation:

```bash
python scripts/export_correlations.py --path some/corpus --glob "*.pdf" --format jsonl --out correlations.csv
```

The script emits rows with `file`, `pattern`, `count`, and `severity`, so you can ingest it into Grafana/Looker/Sheets without additional transformation.

## Dashboard tips

- Run the script once per collection and upload `correlations.csv` to your telemetry dashboard (use `pattern` as the panel dimension).  
- Schedule the `sis query` command via cron to append new JSONL lines to a data lake for ML retraining.  
- Monitor `correlations.count` in alerting pipelines to detect when a correlation becomes active in the corpus.
