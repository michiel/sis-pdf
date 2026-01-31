#!/usr/bin/env python3
"""Collect daily trend data for findings/correlations and emit a CSV for dashboards."""

import argparse
import csv
import json
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def sis_version() -> str:
    try:
        proc = subprocess.run(["sis", "--version"], check=True, capture_output=True, text=True)
        return proc.stdout.strip()
    except subprocess.CalledProcessError:
        return "unknown"


def record_file_path(record: dict) -> str | None:
    return record.get("file") or record.get("path")


def run_batch_query(corpus: Path, glob: str, query: str) -> list[dict]:
    cmd = [
        "sis",
        "query",
        "--path",
        str(corpus),
        "--glob",
        glob,
        query,
        "--format",
        "jsonl",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        err_msg = proc.stderr.strip().replace("\n", " ")
        print(
            f"sis query {query} exited with status {proc.returncode}: {err_msg}",
            file=sys.stderr,
        )

    records = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as err:
            snippet = line[:100]
            print(
                f"Failed to parse sis {query} JSON line ({snippet!r}): {err}",
                file=sys.stderr,
            )
    return records


def aggregate_findings(records: list[dict]) -> tuple[Counter, set[str]]:
    counter = Counter()
    files = set()
    for record in records:
        file_path = record_file_path(record)
        if file_path:
            files.add(file_path)
        result = record.get("result")
        if not isinstance(result, list):
            continue
        for finding in result:
            if not isinstance(finding, dict):
                continue
            key = (
                finding.get("kind"),
                finding.get("severity"),
                finding.get("surface"),
                finding.get("confidence"),
            )
            counter[key] += 1
    return counter, files


def aggregate_correlations(records: list[dict]) -> tuple[Counter, set[str]]:
    counter = Counter()
    files = set()
    for record in records:
        file_path = record_file_path(record)
        if file_path:
            files.add(file_path)
        result = record.get("result")
        if not isinstance(result, dict):
            continue
        for pattern, summary in result.items():
            if not isinstance(summary, dict):
                continue
            count = summary.get("count", 0)
            severity = summary.get("severity", "Unknown")
            counter[(pattern, severity)] += count
    return counter, files


def write_rows(
    csv_path: Path,
    rows: list[dict],
    header: list[str],
) -> None:
    mode = "a" if csv_path.exists() else "w"
    with csv_path.open(mode, newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=header)
        if mode == "w":
            writer.writeheader()
        writer.writerows(rows)


def build_rows(
    date_iso: str,
    sis_version_str: str,
    total_files: int,
    finding_counts: Counter,
    correlation_counts: Counter,
) -> list[dict]:
    rows: list[dict] = []
    for (kind, severity, surface, confidence), count in finding_counts.items():
        rows.append(
            {
                "date": date_iso,
                "sis_version": sis_version_str,
                "type": "finding",
                "kind_or_pattern": kind,
                "severity": severity,
                "surface": surface,
                "confidence": confidence,
                "count": count,
                "files_scanned": total_files,
                "notes": None,
            }
        )
    for (pattern, severity), count in correlation_counts.items():
        rows.append(
            {
                "date": date_iso,
                "sis_version": sis_version_str,
                "type": "correlation",
                "kind_or_pattern": pattern,
                "severity": severity,
                "surface": "correlation",
                "confidence": None,
                "count": count,
                "files_scanned": total_files,
                "notes": None,
            }
        )
    rows.append(
        {
            "date": date_iso,
            "sis_version": sis_version_str,
            "type": "summary",
            "kind_or_pattern": "samples_processed",
            "severity": None,
            "surface": None,
            "confidence": None,
            "count": len(rows),
            "files_scanned": total_files,
            "notes": "Automated daily import",
        }
    )
    return rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emit daily trend data for sis findings.")
    parser.add_argument(
        "--corpus",
        type=Path,
        required=True,
        help="Path to the corpus directory generated by mwb_corpus_pipeline.py",
    )
    parser.add_argument(
        "--glob",
        type=str,
        default="*.pdf",
        help="Glob pattern used by sis query (default %(default)s).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("daily.csv"),
        help="Path for the emitted CSV (appends if file exists).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    version = sis_version()
    date_iso = datetime.now(timezone.utc).isoformat()

    finding_records = run_batch_query(args.corpus, args.glob, "findings")
    finding_counts, finding_files = aggregate_findings(finding_records)
    correlation_records = run_batch_query(args.corpus, args.glob, "correlations")
    correlation_counts, correlation_files = aggregate_correlations(correlation_records)
    total_files = len(finding_files | correlation_files)

    rows = build_rows(
        date_iso,
        version,
        total_files,
        finding_counts,
        correlation_counts,
    )

    header = [
        "date",
        "sis_version",
        "type",
        "kind_or_pattern",
        "severity",
        "surface",
        "confidence",
        "count",
        "files_scanned",
        "notes",
    ]
    write_rows(args.out, rows, header)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:  # noqa: BLE001
        print(f"failed to build trend CSV: {err}", file=sys.stderr)
        sys.exit(1)
