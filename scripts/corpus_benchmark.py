#!/usr/bin/env python3
"""Run corpus benchmarks and compare with external PDF tooling output."""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import shlex
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


PDFID_SIS_MAP = {
    "JS": ["js_present"],
    "JavaScript": ["js_present"],
    "OpenAction": ["open_action_present"],
    "AA": ["aa_present", "aa_event_present"],
    "URI": ["uri_present"],
    "SubmitForm": ["submitform_present"],
    "Launch": ["launch_action_present"],
    "EmbeddedFile": ["embedded_file_present", "filespec_present"],
    "Filespec": ["filespec_present"],
    "XFA": ["xfa_present"],
    "AcroForm": ["acroform_present"],
    "Encrypt": ["encryption_present"],
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run SIS corpus scan and compare against pdfid/pdf-parser output."
    )
    parser.add_argument("corpus", help="Path to corpus directory")
    parser.add_argument(
        "--glob",
        default="*.pdf",
        help="Glob pattern for files in corpus (default: *.pdf)",
    )
    parser.add_argument(
        "--output-dir",
        default="corpus_benchmark",
        help="Output directory (default: corpus_benchmark)",
    )
    parser.add_argument(
        "--sis-bin",
        default="target/release/sis",
        help="Path to sis binary (default: target/release/sis)",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Enable deep scan mode",
    )
    parser.add_argument(
        "--skip-sis",
        action="store_true",
        help="Skip SIS scan and use existing sis.jsonl output",
    )
    parser.add_argument(
        "--pdfid-cmd",
        default="",
        help="Command to run pdfid (use {file} placeholder)",
    )
    parser.add_argument(
        "--pdfparser-cmd",
        default="",
        help="Command to run pdf-parser (use {file} placeholder)",
    )
    parser.add_argument(
        "--baseline-summary",
        default="",
        help="Baseline summary JSON for regression comparison",
    )
    return parser.parse_args()


def iter_files(corpus: Path, pattern: str) -> List[Path]:
    files: List[Path] = []
    for entry in corpus.iterdir():
        if entry.is_file() and fnmatch.fnmatch(entry.name, pattern):
            files.append(entry)
    return sorted(files)


def run_command(cmd: str) -> Tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def run_sis_scan(
    sis_bin: Path,
    corpus: Path,
    pattern: str,
    output_jsonl: Path,
    deep: bool,
) -> None:
    if not sis_bin.exists():
        raise FileNotFoundError(f"sis binary not found: {sis_bin}")
    args = [str(sis_bin), "scan", "--path", str(corpus), "--glob", pattern, "--jsonl-findings"]
    if deep:
        args.append("--deep")
    with output_jsonl.open("w", encoding="utf-8") as out:
        proc = subprocess.run(args, stdout=out, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"sis scan failed: {proc.stderr.strip()}")


def parse_sis_findings(jsonl_path: Path) -> Tuple[Dict[str, List[str]], Counter]:
    per_file: Dict[str, List[str]] = defaultdict(list)
    counts: Counter = Counter()
    with jsonl_path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            entry = json.loads(line)
            path = entry.get("path", "unknown")
            if "finding" in entry:
                finding = entry["finding"]
                kind = finding.get("id", "UNKNOWN")
                per_file[path].append(kind)
                counts[kind] += 1
            elif "findings" in entry:
                for finding in entry["findings"]:
                    kind = finding.get("id", "UNKNOWN")
                    per_file[path].append(kind)
                    counts[kind] += 1
    return per_file, counts


def parse_pdfid_output(output: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("/"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        key = parts[0].lstrip("/")
        try:
            value = int(parts[1])
        except ValueError:
            continue
        counts[key] = value
    return counts


def parse_pdfparser_output(output: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" in line:
            key, val = line.split(":", 1)
            key = key.strip()
            val = val.strip()
        else:
            parts = line.split()
            if len(parts) != 2:
                continue
            key, val = parts
        try:
            value = int(val)
        except ValueError:
            continue
        counts[key] = value
    return counts


def build_mismatch_report(
    pdfid_counts: Dict[str, Dict[str, int]],
    sis_findings: Dict[str, List[str]],
) -> Dict[str, List[str]]:
    mismatches: Dict[str, List[str]] = defaultdict(list)
    for path, counts in pdfid_counts.items():
        sis_kinds = set(sis_findings.get(path, []))
        for pdfid_key, sis_keys in PDFID_SIS_MAP.items():
            if counts.get(pdfid_key, 0) <= 0:
                continue
            if not any(key in sis_kinds for key in sis_keys):
                mismatches[pdfid_key].append(path)
    return mismatches


def compare_regressions(
    current: Counter,
    baseline_path: Optional[Path],
) -> Dict[str, Dict[str, int]]:
    if not baseline_path:
        return {}
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline_counts = Counter(baseline.get("sis_findings_by_kind", {}))
    regressions: Dict[str, Dict[str, int]] = {"increases": {}, "decreases": {}}
    for kind, count in current.items():
        delta = count - baseline_counts.get(kind, 0)
        if delta > 0:
            regressions["increases"][kind] = delta
        elif delta < 0:
            regressions["decreases"][kind] = delta
    return regressions


def main() -> int:
    args = parse_args()
    corpus = Path(args.corpus)
    if not corpus.exists():
        print(f"Corpus directory not found: {corpus}", file=sys.stderr)
        return 1

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    files = iter_files(corpus, args.glob)
    if not files:
        print("No files matched the pattern.", file=sys.stderr)
        return 1

    sis_jsonl = output_dir / "sis.jsonl"
    if not args.skip_sis:
        run_sis_scan(Path(args.sis_bin), corpus, args.glob, sis_jsonl, args.deep)
    elif not sis_jsonl.exists():
        print("sis.jsonl not found; run without --skip-sis or provide output.", file=sys.stderr)
        return 1

    sis_findings, sis_counts = parse_sis_findings(sis_jsonl)

    pdfid_results: Dict[str, Dict[str, int]] = {}
    pdfparser_results: Dict[str, Dict[str, int]] = {}

    if args.pdfid_cmd:
        for path in files:
            cmd = args.pdfid_cmd.format(file=shlex.quote(str(path)))
            code, out, err = run_command(cmd)
            if code != 0:
                print(f"pdfid failed for {path}: {err.strip()}", file=sys.stderr)
                continue
            pdfid_results[str(path)] = parse_pdfid_output(out)

    if args.pdfparser_cmd:
        for path in files:
            cmd = args.pdfparser_cmd.format(file=shlex.quote(str(path)))
            code, out, err = run_command(cmd)
            if code != 0:
                print(f"pdf-parser failed for {path}: {err.strip()}", file=sys.stderr)
                continue
            pdfparser_results[str(path)] = parse_pdfparser_output(out)

    pdfid_totals = Counter()
    for counts in pdfid_results.values():
        pdfid_totals.update(counts)

    pdfparser_totals = Counter()
    for counts in pdfparser_results.values():
        pdfparser_totals.update(counts)

    mismatches = build_mismatch_report(pdfid_results, sis_findings) if pdfid_results else {}

    summary = {
        "corpus": str(corpus),
        "file_count": len(files),
        "sis_jsonl": str(sis_jsonl),
        "sis_findings_by_kind": dict(sis_counts),
        "pdfid_totals": dict(pdfid_totals),
        "pdfparser_totals": dict(pdfparser_totals),
        "pdfid_mismatches": {k: v[:20] for k, v in mismatches.items()},
        "pdfid_mismatch_counts": {k: len(v) for k, v in mismatches.items()},
        "regressions": compare_regressions(
            sis_counts, Path(args.baseline_summary) if args.baseline_summary else None
        ),
    }

    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"Wrote summary: {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
