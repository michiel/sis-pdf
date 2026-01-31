#!/usr/bin/env python3
import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path


def run_correlation_query(path: Path, glob: str, output_format: str) -> list[dict]:
    cmd = [
        "sis",
        "query",
        "--path",
        str(path),
        "--glob",
        glob,
        "correlations",
        "--format",
        output_format,
    ]
    proc = subprocess.run(cmd, check=True, capture_output=True)
    lines = proc.stdout.decode().splitlines()
    return [json.loads(line) for line in lines]


def flatten_correlations(record: dict) -> list[dict]:
    rows = []
    file_path = record.get("file", "-")
    for pattern, summary in record.get("result", {}).items():
        rows.append(
            {
                "file": file_path,
                "pattern": pattern,
                "count": summary.get("count", 0),
                "severity": summary.get("severity", "Unknown"),
            }
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Export sis correlations to CSV.")
    parser.add_argument(
        "--path",
        type=Path,
        required=True,
        help="Directory that sis should scan (passed to --path).",
    )
    parser.add_argument(
        "--glob",
        type=str,
        default="*.pdf",
        help="Glob pattern to limit PDF selection (default %(default)s).",
    )
    parser.add_argument(
        "--format",
        choices=["jsonl", "json"],
        default="jsonl",
        help="Query format to ask from `sis query` (default %(default)s).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Write the flattened CSV to this path (stdout if not set).",
    )

    args = parser.parse_args()
    records = run_correlation_query(args.path, args.glob, args.format)
    rows = []
    for record in records:
        rows.extend(flatten_correlations(record))

    writer = csv.DictWriter(
        args.out.open("w", newline="") if args.out else sys.stdout,
        fieldnames=["file", "pattern", "count", "severity"],
    )
    writer.writeheader()
    writer.writerows(rows)


if __name__ == "__main__":
    main()
