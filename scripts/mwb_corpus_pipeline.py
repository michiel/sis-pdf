#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


DATE_PREFIX = "mwb-"
SUMMARY_VERSION = 1


@dataclass
class ScanArtifacts:
    day: str
    corpus_dir: Path
    jsonl_path: Path
    stderr_path: Path
    summary_path: Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run SIS against MWB daily corpus snapshots and build reports."
    )
    parser.add_argument(
        "--corpus-root",
        default=str(Path.home() / "corpus"),
        help="Root directory containing mwb-YYYY-MM-DD folders.",
    )
    parser.add_argument(
        "--output-root",
        default=str(Path.home() / "corpus-metrics"),
        help="Root directory for scan outputs, summaries, and reports.",
    )
    parser.add_argument(
        "--sis-bin",
        default="sis",
        help="Path to sis binary (default: sis in PATH).",
    )
    parser.add_argument(
        "--glob",
        default="*.pdf",
        help="Glob pattern for PDFs in each daily corpus folder.",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Enable deep scan mode.",
    )
    parser.add_argument(
        "--date",
        help="Process a specific date (YYYY-MM-DD). Defaults to all days.",
    )
    parser.add_argument(
        "--scan-only",
        action="store_true",
        help="Run scans and summaries only (skip report generation).",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Generate reports only (skip scans).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-run scans and summaries even if outputs already exist.",
    )
    return parser.parse_args()


def parse_day_from_dir(path: Path) -> Optional[str]:
    if not path.is_dir() or not path.name.startswith(DATE_PREFIX):
        return None
    suffix = path.name[len(DATE_PREFIX) :]
    try:
        dt.datetime.strptime(suffix, "%Y-%m-%d")
    except ValueError:
        return None
    return suffix


def find_day_dirs(root: Path, specific_day: Optional[str]) -> List[Path]:
    days = []
    if specific_day:
        day_dir = root / f"{DATE_PREFIX}{specific_day}"
        if day_dir.exists():
            return [day_dir]
        return []
    for entry in root.iterdir():
        day = parse_day_from_dir(entry)
        if day:
            days.append(entry)
    return sorted(days, key=lambda p: p.name)


def build_artifacts(output_root: Path, day_dir: Path) -> ScanArtifacts:
    day = day_dir.name[len(DATE_PREFIX) :]
    scan_dir = output_root / "scans" / day
    summary_dir = output_root / "summaries"
    scan_dir.mkdir(parents=True, exist_ok=True)
    summary_dir.mkdir(parents=True, exist_ok=True)
    return ScanArtifacts(
        day=day,
        corpus_dir=day_dir,
        jsonl_path=scan_dir / "sis_findings.jsonl",
        stderr_path=scan_dir / "sis_scan_errors.log",
        summary_path=summary_dir / f"{day}.json",
    )


def run_sis_scan(
    sis_bin: str,
    day_dir: Path,
    jsonl_path: Path,
    stderr_path: Path,
    glob: str,
    deep: bool,
    force: bool,
) -> None:
    if jsonl_path.exists() and jsonl_path.stat().st_size > 0 and not force:
        return
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    args = [
        sis_bin,
        "scan",
        "--path",
        str(day_dir),
        "--glob",
        glob,
        "--jsonl-findings",
    ]
    if deep:
        args.append("--deep")
    with jsonl_path.open("w", encoding="utf-8") as out, stderr_path.open(
        "w", encoding="utf-8"
    ) as err:
        proc = subprocess.run(args, stdout=out, stderr=err, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"sis scan failed for {day_dir} (exit {proc.returncode})")


def read_sis_version(sis_bin: str) -> str:
    try:
        proc = subprocess.run(
            [sis_bin, "version"], capture_output=True, text=True, check=False
        )
        version = proc.stdout.strip()
        return version or "unknown"
    except FileNotFoundError:
        return "not_found"


def parse_findings_line(entry: dict) -> Iterable[dict]:
    if "finding" in entry:
        finding = entry.get("finding")
        if isinstance(finding, dict):
            yield finding
        return
    findings = entry.get("findings")
    if isinstance(findings, list):
        for finding in findings:
            if isinstance(finding, dict):
                yield finding


def normalise_key(value: Optional[str]) -> str:
    if not value:
        return "unknown"
    return str(value)


def extract_finding_kind(finding: dict) -> str:
    return normalise_key(finding.get("kind") or finding.get("id"))


def extract_surface(finding: dict) -> str:
    return normalise_key(finding.get("surface") or finding.get("attack_surface"))


def parse_jsonl_findings(
    jsonl_path: Path,
) -> Tuple[Counter, Dict[str, Counter], int, int]:
    by_kind = Counter()
    by_field: Dict[str, Counter] = {
        "severity": Counter(),
        "impact": Counter(),
        "confidence": Counter(),
        "surface": Counter(),
    }
    total_findings = 0
    parse_errors = 0
    with jsonl_path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            if entry.get("status") == "error":
                continue
            for finding in parse_findings_line(entry):
                kind = extract_finding_kind(finding)
                by_kind[kind] += 1
                by_field["severity"][normalise_key(finding.get("severity"))] += 1
                by_field["impact"][normalise_key(finding.get("impact"))] += 1
                by_field["confidence"][normalise_key(finding.get("confidence"))] += 1
                by_field["surface"][extract_surface(finding)] += 1
                total_findings += 1
    return by_kind, by_field, total_findings, parse_errors


def update_latest_symlink(corpus_root: Path, latest_dir: Path) -> None:
    link_path = corpus_root / "mwb-latest"
    if link_path.exists() or link_path.is_symlink():
        if link_path.is_symlink() or link_path.is_file():
            link_path.unlink()
        else:
            # remove directory if leftover
            if link_path.is_dir():
                for child in link_path.iterdir():
                    if child.is_dir():
                        os.rmdir(child)
                link_path.rmdir()
    os.symlink(latest_dir.resolve(), link_path)


def count_errors(stderr_path: Path) -> Dict[str, int]:
    counts = {"errors": 0, "warnings": 0}
    if not stderr_path.exists():
        return counts
    with stderr_path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            lower = line.lower()
            if "error" in lower:
                counts["errors"] += 1
            if "warn" in lower:
                counts["warnings"] += 1
    return counts


def list_pdf_files(corpus_dir: Path, glob: str) -> int:
    return len(list(corpus_dir.glob(glob)))


def write_summary(
    artifacts: ScanArtifacts,
    by_kind: Counter,
    by_field: Dict[str, Counter],
    total_findings: int,
    parse_errors: int,
    error_counts: Dict[str, int],
    sis_version: str,
    deep: bool,
    glob: str,
) -> None:
    summary = {
        "version": SUMMARY_VERSION,
        "date": artifacts.day,
        "corpus_dir": str(artifacts.corpus_dir),
        "file_count": list_pdf_files(artifacts.corpus_dir, glob),
        "scan": {
            "sis_version": sis_version,
            "deep": deep,
            "glob": glob,
        },
        "findings": {
            "total": total_findings,
            "unique_kinds": len(by_kind),
            "by_kind": dict(by_kind),
            "by_severity": dict(by_field["severity"]),
            "by_impact": dict(by_field["impact"]),
            "by_confidence": dict(by_field["confidence"]),
            "by_surface": dict(by_field["surface"]),
        },
        "errors": {
            "json_parse_errors": parse_errors,
            "scan_errors": error_counts.get("errors", 0),
            "scan_warnings": error_counts.get("warnings", 0),
        },
    }
    artifacts.summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )


def load_summaries(summary_dir: Path) -> Dict[str, dict]:
    summaries = {}
    if not summary_dir.exists():
        return summaries
    for path in summary_dir.glob("*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        date = payload.get("date")
        if date:
            summaries[date] = payload
    return dict(sorted(summaries.items()))


def aggregate_period(summaries: Dict[str, dict], dates: List[str]) -> dict:
    total_findings = 0
    file_count = 0
    by_kind = Counter()
    by_severity = Counter()
    by_impact = Counter()
    by_confidence = Counter()
    by_surface = Counter()
    errors = Counter()
    for date in dates:
        summary = summaries[date]
        file_count += summary.get("file_count", 0)
        findings = summary.get("findings", {})
        total_findings += findings.get("total", 0)
        by_kind.update(findings.get("by_kind", {}))
        by_severity.update(findings.get("by_severity", {}))
        by_impact.update(findings.get("by_impact", {}))
        by_confidence.update(findings.get("by_confidence", {}))
        by_surface.update(findings.get("by_surface", {}))
        errors.update(summary.get("errors", {}))
    return {
        "dates": dates,
        "file_count": file_count,
        "findings": {
            "total": total_findings,
            "by_kind": dict(by_kind),
            "by_severity": dict(by_severity),
            "by_impact": dict(by_impact),
            "by_confidence": dict(by_confidence),
            "by_surface": dict(by_surface),
        },
        "errors": dict(errors),
    }


def delta_counts(current: Dict[str, int], previous: Dict[str, int]) -> Dict[str, int]:
    deltas = {}
    keys = set(current) | set(previous)
    for key in keys:
        deltas[key] = current.get(key, 0) - previous.get(key, 0)
    return dict(sorted(deltas.items(), key=lambda item: abs(item[1]), reverse=True))


def detect_regressions(current: dict, previous: Optional[dict]) -> Dict[str, List[str]]:
    if not previous:
        return {"missing_kinds": [], "high_severity_drop": []}
    current_by_kind = current["findings"]["by_kind"]
    previous_by_kind = previous["findings"]["by_kind"]
    missing_kinds = [
        kind for kind, count in previous_by_kind.items() if count > 0 and kind not in current_by_kind
    ]
    current_high = current["findings"]["by_severity"].get("High", 0)
    previous_high = previous["findings"]["by_severity"].get("High", 0)
    high_severity_drop = []
    if previous_high > 0 and current_high == 0:
        high_severity_drop.append("High")
    return {
        "missing_kinds": sorted(missing_kinds),
        "high_severity_drop": high_severity_drop,
    }


def render_table(title: str, rows: List[Tuple[str, str]]) -> str:
    row_html = "\n".join(
        f"<tr><td>{key}</td><td>{value}</td></tr>" for key, value in rows
    )
    return f"<h3>{title}</h3><table><tbody>{row_html}</tbody></table>"


def render_counter(title: str, counter: Dict[str, int], limit: int = 20) -> str:
    sorted_items = sorted(counter.items(), key=lambda item: item[1], reverse=True)[:limit]
    rows = [(key, str(val)) for key, val in sorted_items]
    return render_table(title, rows)


def write_report_index(report_dir: Path, summaries: Dict[str, dict]) -> None:
    dates = list(summaries.keys())
    latest = dates[-1] if dates else ""
    rows = [(date, f"<a href='daily/{date}.html'>{date}</a>") for date in dates[-30:][::-1]]
    content = render_table("Recent Daily Reports", rows)
    html = build_html(
        "MWB Corpus Reports",
        f"<p>Latest report: {latest}</p>{content}",
    )
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "index.html").write_text(html, encoding="utf-8")


def build_html(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>{title}</title>
  <style>
    body {{ font-family: "Helvetica Neue", Arial, sans-serif; margin: 32px; color: #1d1d1f; }}
    h1, h2, h3 {{ color: #2b2b2b; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 24px; }}
    td, th {{ border: 1px solid #d4d4d4; padding: 6px 8px; }}
    th {{ background: #f4f4f4; text-align: left; }}
    .small {{ color: #555; font-size: 0.9em; }}
    .section {{ margin-bottom: 32px; }}
  </style>
</head>
<body>
  <h1>{title}</h1>
  {body}
</body>
</html>
"""


def generate_daily_report(
    report_dir: Path, summaries: Dict[str, dict], date: str
) -> None:
    summary = summaries[date]
    dates = list(summaries.keys())
    idx = dates.index(date)
    previous = summaries[dates[idx - 1]] if idx > 0 else None
    regressions = detect_regressions(summary, previous)
    deltas = {}
    if previous:
        deltas = delta_counts(summary["findings"]["by_kind"], previous["findings"]["by_kind"])

    base_rows = [
        ("Date", date),
        ("Corpus dir", summary.get("corpus_dir", "")),
        ("Files", str(summary.get("file_count", 0))),
        ("Total findings", str(summary["findings"].get("total", 0))),
        ("Unique kinds", str(summary["findings"].get("unique_kinds", 0))),
        ("Errors", str(summary["errors"].get("scan_errors", 0))),
        ("Warnings", str(summary["errors"].get("scan_warnings", 0))),
    ]
    sections = [
        render_table("Summary", base_rows),
        render_counter("Findings by severity", summary["findings"]["by_severity"], limit=10),
        render_counter("Findings by impact", summary["findings"]["by_impact"], limit=10),
        render_counter("Findings by confidence", summary["findings"]["by_confidence"], limit=10),
        render_counter("Findings by surface", summary["findings"]["by_surface"], limit=10),
        render_counter("Top findings by kind", summary["findings"]["by_kind"], limit=25),
    ]
    if previous:
        sections.append(
            render_counter("Largest day-over-day kind deltas", deltas, limit=25)
        )
        sections.append(
            render_table(
                "Regressions",
                [
                    ("Missing kinds", ", ".join(regressions["missing_kinds"]) or "none"),
                    (
                        "High severity drop",
                        ", ".join(regressions["high_severity_drop"]) or "none",
                    ),
                ],
            )
        )
    html = build_html(f"MWB Corpus Report {date}", "<div class='section'>" + "</div><div class='section'>".join(sections) + "</div>")
    output_dir = report_dir / "daily"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / f"{date}.html").write_text(html, encoding="utf-8")


def group_by_period(dates: List[str], period: str) -> Dict[str, List[str]]:
    grouped = defaultdict(list)
    for date_str in dates:
        date = dt.datetime.strptime(date_str, "%Y-%m-%d").date()
        if period == "weekly":
            key = f"{date.isocalendar().year}-W{date.isocalendar().week:02d}"
        else:
            key = f"{date.year}-{date.month:02d}"
        grouped[key].append(date_str)
    return dict(grouped)


def generate_period_reports(
    report_dir: Path, summaries: Dict[str, dict], period: str
) -> None:
    dates = list(summaries.keys())
    grouped = group_by_period(dates, period)
    output_dir = report_dir / period
    output_dir.mkdir(parents=True, exist_ok=True)

    for key, group_dates in grouped.items():
        aggregate = aggregate_period(summaries, group_dates)
        previous_key = None
        keys = sorted(grouped.keys())
        idx = keys.index(key)
        previous = None
        if idx > 0:
            previous_key = keys[idx - 1]
            previous = aggregate_period(summaries, grouped[previous_key])
        deltas = delta_counts(
            aggregate["findings"]["by_kind"],
            previous["findings"]["by_kind"] if previous else {},
        )
        sections = [
            render_table(
                f"{period.title()} summary",
                [
                    ("Period", key),
                    ("Dates", ", ".join(group_dates)),
                    ("Files", str(aggregate["file_count"])),
                    ("Total findings", str(aggregate["findings"]["total"])),
                ],
            ),
            render_counter("Findings by severity", aggregate["findings"]["by_severity"], limit=10),
            render_counter("Top findings by kind", aggregate["findings"]["by_kind"], limit=25),
        ]
        if previous_key:
            sections.append(
                render_counter(
                    f"{period.title()} deltas vs {previous_key}", deltas, limit=25
                )
            )
        html = build_html(
            f"MWB Corpus {period.title()} Report {key}",
            "<div class='section'>" + "</div><div class='section'>".join(sections) + "</div>",
        )
        (output_dir / f"{key}.html").write_text(html, encoding="utf-8")


def main() -> int:
    args = parse_args()
    corpus_root = Path(args.corpus_root).expanduser()
    output_root = Path(args.output_root).expanduser()
    summaries_dir = output_root / "summaries"
    reports_dir = output_root / "reports"

    if not corpus_root.exists():
        print(f"Corpus root not found: {corpus_root}")
        return 1

    day_dirs = find_day_dirs(corpus_root, args.date)
    if not day_dirs and not args.report_only:
        print("No corpus days found to scan.")
        return 1

    sis_version = read_sis_version(args.sis_bin)

    if not args.report_only:
        for day_dir in day_dirs:
            artifacts = build_artifacts(output_root, day_dir)
            run_sis_scan(
                args.sis_bin,
                day_dir,
                artifacts.jsonl_path,
                artifacts.stderr_path,
                args.glob,
                args.deep,
                args.force,
            )
            by_kind, by_field, total_findings, parse_errors = parse_jsonl_findings(
                artifacts.jsonl_path
            )
            error_counts = count_errors(artifacts.stderr_path)
            write_summary(
                artifacts,
                by_kind,
                by_field,
                total_findings,
                parse_errors,
                error_counts,
                sis_version,
                args.deep,
                args.glob,
            )
        if day_dirs:
            update_latest_symlink(corpus_root, day_dirs[-1])

    if args.scan_only:
        return 0

    summaries = load_summaries(summaries_dir)
    if not summaries:
        print("No summaries found to build reports.")
        return 1

    write_report_index(reports_dir, summaries)
    for date in summaries:
        generate_daily_report(reports_dir, summaries, date)
    generate_period_reports(reports_dir, summaries, "weekly")
    generate_period_reports(reports_dir, summaries, "monthly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
