#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import statistics
import subprocess
import sys
import time
from datetime import date, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

DEFAULT_SIS = "sis"
TREND_DIR = Path("reports/trends")
DAILY_CSV = TREND_DIR / "daily.csv"
WEEKLY_CSV = TREND_DIR / "weekly.csv"
KIND_HISTORY = TREND_DIR / "kind_history.json"
GRAFANA_DIR = TREND_DIR / "grafana"


def configure_output(path: Path):
    global TREND_DIR, DAILY_CSV, WEEKLY_CSV, KIND_HISTORY, GRAFANA_DIR
    TREND_DIR = path
    DAILY_CSV = TREND_DIR / "daily.csv"
    WEEKLY_CSV = TREND_DIR / "weekly.csv"
    KIND_HISTORY = TREND_DIR / "kind_history.json"
    GRAFANA_DIR = TREND_DIR / "grafana"
    for target in [TREND_DIR, GRAFANA_DIR]:
        target.mkdir(parents=True, exist_ok=True)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run sis --deep over MWB corpora and emit Grafana-ready trend CSVs."
    )
    parser.add_argument("--batch-dir", type=Path, help="Path to latest mwb-YYYY-MM-DD batch")
    parser.add_argument("--corpus-dir", type=Path, help="Path to the master corpus root")
    parser.add_argument("--output-dir", type=Path, default=TREND_DIR, help="Directory for trend CSVs")
    parser.add_argument("--sis-binary", type=Path, default=Path(DEFAULT_SIS), help="sis binary path")
    parser.add_argument(
        "--manifest",
        type=Path,
        help="Manifest file describing the batch (defaults to manifest-<batchname>.json next to batch dir)",
    )
    return parser.parse_args()


def log(msg: str):
    print(msg)
    sys.stdout.flush()


def load_manifest(manifest_path: Path) -> Sequence[Path]:
    if not manifest_path.exists():
        raise FileNotFoundError(f"{manifest_path} missing")
    with open(manifest_path, "r") as fp:
        data = json.load(fp)
    return [Path(entry["filename"]) for entry in data if "filename" in entry]


def list_pdf_paths(root: Path) -> List[Path]:
    return sorted(root.rglob("*.pdf"))


def run_sis_scan(sis_binary: Path, pdf_path: Path) -> Dict:
    start = time.monotonic()
    command = [str(sis_binary), "scan", "--deep", str(pdf_path)]
    process = subprocess.run(command, capture_output=True, text=True)
    duration = time.monotonic() - start
    findings = collect_findings(sis_binary, pdf_path)
    errors = (process.stdout + process.stderr).count("ERROR")
    warnings = (process.stdout + process.stderr).count("WARN")
    return {
        "pdf": str(pdf_path),
        "duration_seconds": duration,
        "returncode": process.returncode,
        "errors": errors,
        "warnings": warnings,
        "findings": findings,
        "size_bytes": pdf_path.stat().st_size if pdf_path.exists() else 0,
    }


def collect_findings(sis_binary: Path, pdf_path: Path) -> List[Dict]:
    cmd = [str(sis_binary), "query", str(pdf_path), "findings", "--json"]
    process = subprocess.run(cmd, capture_output=True, text=True)
    if process.returncode != 0:
        return []
    # remove incidental logging lines
    lines = [line for line in process.stdout.splitlines() if not line.startswith("WARN")]
    data = "\n".join(lines)
    try:
        payload = json.loads(data)
        return payload.get("result", [])
    except json.JSONDecodeError:
        return []


def summarize_results(results: Sequence[Dict]) -> Dict:
    severity_counts = {}
    kind_counts = {}
    total_findings = 0
    for entry in results:
        for finding in entry["findings"]:
            severity = finding.get("severity", "unknown")
            kind = finding.get("kind", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            kind_counts[kind] = kind_counts.get(kind, 0) + 1
            total_findings += 1
    avg_findings = (total_findings / len(results)) if results else 0
    runtime_ms = sum(entry["duration_seconds"] * 1000 for entry in results)
    return {
        "total_findings": total_findings,
        "info": severity_counts.get("Info", 0),
        "low": severity_counts.get("Low", 0),
        "medium": severity_counts.get("Medium", 0),
        "high": severity_counts.get("High", 0),
        "critical": severity_counts.get("Critical", 0),
        "files_scanned": len(results),
        "bytes_scanned": sum(entry["size_bytes"] for entry in results),
        "avg_findings_per_file": round(avg_findings, 2),
        "runtime_ms": round(runtime_ms, 2),
        "errors": sum(entry["errors"] for entry in results),
        "kind_counts": kind_counts,
    }


def compute_run_id(target: str, pdfs: Sequence[Path]) -> str:
    hasher = hashlib.sha1()
    hasher.update(target.encode())
    for pdf in sorted(str(p) for p in pdfs):
        hasher.update(pdf.encode())
    return hasher.hexdigest()


def upsert_csv(file_path: Path, headers: List[str], row: Dict[str, str], key_field: str):
    rows = []
    if file_path.exists():
        with open(file_path, newline="") as csvfile:
            reader = csv.DictReader(csvfile)
            for existing in reader:
                if existing.get(key_field) != row[key_field]:
                    rows.append(existing)
    rows.append({k: row.get(k, "") for k in headers})
    with open(file_path, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def update_weekly_csv(daily_rows: List[Dict[str, str]]):
    weekly = {}
    for row in daily_rows:
        if not row.get("date"):
            continue
        d = date.fromisoformat(row["date"])
        week_start = (d - timedelta(days=d.weekday())).isoformat()
        target = row["target"]
        key = (week_start, target)
        entry = weekly.setdefault(key, {"runtime": [], "findings": 0, "files": 0, "errors": 0, "new_kinds": set()})
        entry["runtime"].append(float(row.get("runtime_ms", 0)) if row.get("runtime_ms") else 0)
        entry["findings"] += int(row.get("total_findings", "0"))
        entry["files"] += int(row.get("files_scanned", "0"))
        entry["errors"] += int(row.get("error_count", "0"))
        kinds = row.get("new_kinds", "")
        if kinds:
            entry["new_kinds"].update(kinds.split("|"))
    headers = ["week_start", "target", "total_findings", "median_runtime_ms", "avg_findings_per_file", "files_scanned", "errors", "new_kinds"]
    weekly_rows = []
    for (week_start, target), stats in sorted(weekly.items()):
        median_runtime = statistics.median(stats["runtime"]) if stats["runtime"] else 0
        avg_findings = stats["findings"] / 7 if stats["findings"] else 0
        weekly_rows.append({
            "week_start": week_start,
            "target": target,
            "total_findings": stats["findings"],
            "median_runtime_ms": round(median_runtime, 2),
            "avg_findings_per_file": round(avg_findings, 2),
            "files_scanned": stats["files"],
            "errors": stats["errors"],
            "new_kinds": "|".join(sorted(stats["new_kinds"])),
        })
    with open(WEEKLY_CSV, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        writer.writerows(weekly_rows)


def load_daily_rows() -> List[Dict[str, str]]:
    if not DAILY_CSV.exists():
        return []
    with open(DAILY_CSV, newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        return [row for row in reader]


def write_grafana_csv(date_str: str, target: str, kind_counts: Dict[str, int]):
    path = GRAFANA_DIR / f"findings_by_kind_{date_str}_{target}.csv"
    headers = ["date", "target", "kind", "severity", "count"]
    rows = []
    for kind, count in sorted(kind_counts.items(), key=lambda kv: kv[1], reverse=True):
        rows.append({
            "date": date_str,
            "target": target,
            "kind": kind,
            "severity": "",  # severity not captured per kind here
            "count": count,
        })
    with open(path, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def update_kind_history(current_kinds: Iterable[str]):
    previous = set()
    if KIND_HISTORY.exists():
        with open(KIND_HISTORY) as fp:
            previous = set(json.load(fp))
    new_kinds = sorted(set(current_kinds) - previous)
    with open(KIND_HISTORY, "w") as fp:
        json.dump(sorted(set(current_kinds) | previous), fp)
    return new_kinds


def run_target(
    sis_binary: Path,
    target_name: str,
    pdf_paths: Sequence[Path],
    run_date: date,
):
    if not pdf_paths:
        log(f"No PDF files for {target_name}, skipping trend row.")
        return
    if not pdf_paths:
        log(f"Skipping {target_name}: no PDF files found.")
        return
    run_id = compute_run_id(target_name, pdf_paths)
    daily_row = {
        "run_id": run_id,
        "date": run_date.isoformat(),
        "target": target_name,
    }
    results = []
    for pdf in pdf_paths:
        results.append(run_sis_scan(sis_binary, pdf))
    summary = summarize_results(results)
    daily_row.update({
        "total_findings": summary["total_findings"],
        "info": summary["info"],
        "low": summary["low"],
        "medium": summary["medium"],
        "high": summary["high"],
        "critical": summary["critical"],
        "files_scanned": summary["files_scanned"],
        "bytes_scanned": summary["bytes_scanned"],
        "avg_findings_per_file": summary["avg_findings_per_file"],
        "runtime_ms": summary["runtime_ms"],
        "error_count": summary["errors"],
        "new_kinds": "|".join(update_kind_history(summary["kind_counts"].keys())),
    })
    headers = [
        "run_id", "date", "target", "total_findings", "info", "low", "medium", "high",
        "critical", "files_scanned", "bytes_scanned", "avg_findings_per_file", "runtime_ms",
        "error_count", "new_kinds"
    ]
    upsert_csv(DAILY_CSV, headers, daily_row, key_field="run_id")
    write_grafana_csv(run_date.isoformat(), target_name, summary["kind_counts"])
    log(f"Wrote daily trend row for {target_name}.")


def main():
    args = parse_args()
    configure_output(args.output_dir)
    sis_binary = args.sis_binary
    today = date.today()
    if args.batch_dir:
        batch_target = args.batch_dir.name
        manifest = args.manifest or (args.batch_dir.parent / f"manifest-{args.batch_dir.name}.json")
        try:
            pdfs = [args.batch_dir / rel for rel in load_manifest(manifest)]
        except FileNotFoundError:
            log(f"manifest missing for {batch_target}, skipping batch run")
            pdfs = []
        run_target(sis_binary, batch_target, pdfs, today)
    if args.corpus_dir:
        pdfs = list_pdf_paths(args.corpus_dir)
        run_target(sis_binary, args.corpus_dir.name, pdfs, today)
    daily_rows = load_daily_rows()
    update_weekly_csv(daily_rows)


if __name__ == "__main__":
    main()
