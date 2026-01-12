# Corpus benchmarking

This guide documents the corpus benchmarking harness that compares SIS scan
coverage against external tooling (`pdfid` and `pdf-parser`).

## Overview

The harness:
- Runs a SIS scan across a corpus directory and records findings in JSONL.
- Optionally runs `pdfid` and/or `pdf-parser` against the same files.
- Compares external keyword counts to SIS findings (e.g. `OpenAction` vs
  `open_action_present`) and reports mismatches.
- Stores a summary JSON that can be diffed against a baseline to spot
  regressions.

The harness lives at `scripts/corpus_benchmark.py`.

## Requirements

- `sis` built in release mode (`cargo build --release`).
- Optional: `pdfid.py` and/or `pdf-parser.py` in your PATH.

## Basic usage

Run a deep scan and compare to `pdfid` and `pdf-parser`:

```bash
scripts/corpus_benchmark.py /path/to/corpus \
  --glob '*.pdf' \
  --output-dir corpus_benchmark \
  --sis-bin target/release/sis \
  --deep \
  --pdfid-cmd "pdfid.py {file}" \
  --pdfparser-cmd "pdf-parser.py --stats {file}"
```

Run against hash-named files (no extension):

```bash
scripts/corpus_benchmark.py /path/to/corpus \
  --glob '*' \
  --output-dir corpus_benchmark \
  --sis-bin target/release/sis \
  --deep
```

Skip the SIS scan when you already have `sis.jsonl`:

```bash
scripts/corpus_benchmark.py /path/to/corpus \
  --glob '*.pdf' \
  --output-dir corpus_benchmark \
  --sis-bin target/release/sis \
  --skip-sis \
  --pdfid-cmd "pdfid.py {file}"
```

## Outputs

The harness writes:
- `corpus_benchmark/sis.jsonl`: raw SIS findings.
- `corpus_benchmark/summary.json`: aggregated counts and mismatch report.

Example summary fields:
- `sis_findings_by_kind`: total SIS finding counts.
- `pdfid_totals` / `pdfparser_totals`: external keyword counts.
- `pdfid_mismatch_counts`: how many files had external keywords without SIS
  findings mapped to those indicators.
- `regressions`: delta vs a previous baseline summary.

## Baseline comparison

To compare to a previous run:

```bash
scripts/corpus_benchmark.py /path/to/corpus \
  --glob '*.pdf' \
  --output-dir corpus_benchmark \
  --sis-bin target/release/sis \
  --deep \
  --baseline-summary corpus_benchmark_previous/summary.json
```

The `regressions` field lists increases and decreases in SIS finding counts.

## Notes

- The PDF tool mapping is keyword-based and intentionally conservative.
- Use deep scans (`--deep`) when validating stream-derived indicators.
