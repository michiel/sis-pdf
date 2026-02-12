#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


DATE_PREFIX = "mwb-"
SUMMARY_VERSION = 2
DEFAULT_SAMPLE_SEED = 1337
DEFAULT_PASS1_TIMEOUT_SECONDS = 20
DEFAULT_PASS2_TIMEOUT_SECONDS = 60
DEFAULT_HIGH_INTEREST_KINDS = {
    "launch_action_present",
    "launch_external_program",
    "launch_embedded_file",
    "launch_obfuscated_executable",
    "action_chain_malicious",
    "action_chain_complex",
    "annotation_action_chain",
    "js_runtime_downloader_pattern",
    "js_runtime_network_intent",
    "js_intent_user_interaction",
    "declared_filter_invalid",
    "decoder_risk_present",
    "parser_resource_exhaustion",
    "structural_evasion_composite",
}
HASH_NAME_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass
class ScanArtifacts:
    day: str
    corpus_dir: Path
    jsonl_path: Path
    stderr_path: Path
    summary_path: Path


@dataclass
class PerFileScanRecord:
    path: str
    content_hash: str
    selected: bool
    reason_code: str
    stage: str
    pass1_duration_ms: int = 0
    pass2_duration_ms: int = 0
    rerun_reason: Optional[str] = None


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
        "--batch-parallel",
        action="store_true",
        help="Forward --batch-parallel to sis scan for intra-run worker pools.",
    )
    parser.add_argument(
        "--two-pass",
        action="store_true",
        help=(
            "Run deterministic per-file two-pass sweep "
            "(pass1 bounded, pass2 targeted rerun)."
        ),
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=0,
        help="Limit each day to a deterministic random sample size after hash dedup.",
    )
    parser.add_argument(
        "--sample-seed",
        type=int,
        default=DEFAULT_SAMPLE_SEED,
        help="Seed for deterministic random sampling.",
    )
    parser.add_argument(
        "--pass1-timeout-seconds",
        type=int,
        default=DEFAULT_PASS1_TIMEOUT_SECONDS,
        help="Per-file timeout in seconds for pass 1 (bounded sweep).",
    )
    parser.add_argument(
        "--pass2-timeout-seconds",
        type=int,
        default=DEFAULT_PASS2_TIMEOUT_SECONDS,
        help="Per-file timeout in seconds for targeted pass 2 reruns.",
    )
    parser.add_argument(
        "--high-interest-kind",
        action="append",
        default=[],
        help="Finding kind that triggers pass 2 rerun (repeatable).",
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
    parser.add_argument(
        "--fail-on-unknown-runtime-behaviour",
        action="store_true",
        help=(
            "Exit non-zero when js_runtime_unknown_behaviour_pattern names are observed "
            "outside the configured allow-list."
        ),
    )
    parser.add_argument(
        "--allow-runtime-behaviour",
        action="append",
        default=[],
        help="Allow-list a runtime behaviour name for unknown-pattern guardrails.",
    )
    parser.add_argument(
        "--allow-runtime-behaviour-file",
        help=(
            "Path to JSON array or newline-delimited file of allow-listed unknown "
            "runtime behaviour names."
        ),
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


def extract_content_hash(path: Path) -> str:
    stem = path.stem
    if HASH_NAME_RE.match(stem):
        return stem.lower()
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def build_day_scan_plan(
    pdf_paths: List[Path],
    seen_hashes: Set[str],
    sample_size: int,
    sample_seed: int,
    day: str,
) -> Tuple[List[Tuple[Path, str]], List[PerFileScanRecord]]:
    unique_candidates: List[Tuple[Path, str]] = []
    local_seen_hashes: Set[str] = set()
    skipped: List[PerFileScanRecord] = []
    for path in sorted(pdf_paths):
        content_hash = extract_content_hash(path)
        if content_hash in seen_hashes:
            skipped.append(
                PerFileScanRecord(
                    path=str(path),
                    content_hash=content_hash,
                    selected=False,
                    reason_code="dedup.hash_duplicate",
                    stage="selection",
                )
            )
            continue
        if content_hash in local_seen_hashes:
            skipped.append(
                PerFileScanRecord(
                    path=str(path),
                    content_hash=content_hash,
                    selected=False,
                    reason_code="dedup.hash_duplicate",
                    stage="selection",
                )
            )
            continue
        local_seen_hashes.add(content_hash)
        unique_candidates.append((path, content_hash))
    if sample_size > 0 and len(unique_candidates) > sample_size:
        seed_material = int(day.replace("-", ""))
        rng = random.Random(sample_seed ^ seed_material)
        selected = sorted(
            rng.sample(unique_candidates, sample_size),
            key=lambda item: str(item[0]),
        )
        selected_path_set = {str(path) for path, _ in selected}
        for path, content_hash in unique_candidates:
            if str(path) not in selected_path_set:
                skipped.append(
                    PerFileScanRecord(
                        path=str(path),
                        content_hash=content_hash,
                        selected=False,
                        reason_code="dedup.sampled_out",
                        stage="selection",
                    )
                )
        for _, content_hash in selected:
            seen_hashes.add(content_hash)
        return selected, skipped
    for _, content_hash in unique_candidates:
        seen_hashes.add(content_hash)
    return unique_candidates, skipped


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
    batch_parallel: bool,
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
    if batch_parallel:
        args.append("--batch-parallel")
    with jsonl_path.open("w", encoding="utf-8") as out, stderr_path.open(
        "w", encoding="utf-8"
    ) as err:
        proc = subprocess.run(args, stdout=out, stderr=err, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"sis scan failed for {day_dir} (exit {proc.returncode})")


def parse_findings_from_jsonl_text(payload: str) -> List[dict]:
    findings: List[dict] = []
    for line in payload.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        for finding in parse_findings_line(entry):
            findings.append(finding)
    return findings


def is_high_interest_file(
    findings: List[dict], high_interest_kinds: Set[str]
) -> Tuple[bool, str]:
    for finding in findings:
        severity = normalise_key(finding.get("severity"))
        if severity in {"High", "Critical"}:
            return True, f"high_severity:{severity}"
        kind = extract_finding_kind(finding)
        if kind in high_interest_kinds:
            return True, f"high_interest_kind:{kind}"
    return False, ""


def run_single_file_scan(
    sis_bin: str,
    path: Path,
    deep: bool,
    timeout_seconds: int,
) -> Tuple[str, str, int, int]:
    args = [sis_bin, "scan", str(path), "--jsonl-findings"]
    if deep:
        args.append("--deep")
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=max(timeout_seconds, 1),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.perf_counter() - started) * 1000)
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return stdout, stderr, duration_ms, 124
    duration_ms = int((time.perf_counter() - started) * 1000)
    return proc.stdout, proc.stderr, duration_ms, proc.returncode


def run_sis_scan_two_pass(
    sis_bin: str,
    artifacts: ScanArtifacts,
    glob: str,
    deep: bool,
    force: bool,
    seen_hashes: Set[str],
    sample_size: int,
    sample_seed: int,
    pass1_timeout_seconds: int,
    pass2_timeout_seconds: int,
    high_interest_kinds: Set[str],
) -> Dict[str, object]:
    if artifacts.jsonl_path.exists() and artifacts.jsonl_path.stat().st_size > 0 and not force:
        return {
            "mode": "two_pass",
            "skipped_scan": True,
            "records": [],
            "reason_code_counts": {},
            "stage_counts": {},
            "selected_files": 0,
            "skipped_files": 0,
        }
    artifacts.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    pdf_paths = list(artifacts.corpus_dir.glob(glob))
    selected, skipped_records = build_day_scan_plan(
        pdf_paths,
        seen_hashes,
        sample_size=sample_size,
        sample_seed=sample_seed,
        day=artifacts.day,
    )

    final_outputs: Dict[str, str] = {}
    records: List[PerFileScanRecord] = list(skipped_records)
    rerun_candidates: Dict[str, str] = {}
    pass1_outputs: Dict[str, str] = {}
    pass1_hashes: Dict[str, str] = {}
    stderr_lines: List[str] = []

    for path, content_hash in selected:
        pass1_hashes[str(path)] = content_hash
        stdout, stderr, duration_ms, return_code = run_single_file_scan(
            sis_bin=sis_bin,
            path=path,
            deep=deep,
            timeout_seconds=pass1_timeout_seconds,
        )
        pass1_outputs[str(path)] = stdout
        if stderr:
            stderr_lines.append(f"[pass1][{path}] {stderr.strip()}")
        if return_code == 124:
            records.append(
                PerFileScanRecord(
                    path=str(path),
                    content_hash=content_hash,
                    selected=True,
                    reason_code="timeout.pass1",
                    stage="pass1",
                    pass1_duration_ms=duration_ms,
                    rerun_reason="timeout.pass1",
                )
            )
            rerun_candidates[str(path)] = "timeout.pass1"
            continue
        if return_code != 0:
            records.append(
                PerFileScanRecord(
                    path=str(path),
                    content_hash=content_hash,
                    selected=True,
                    reason_code="scan_error.pass1",
                    stage="pass1",
                    pass1_duration_ms=duration_ms,
                )
            )
            final_outputs[str(path)] = stdout
            continue
        findings = parse_findings_from_jsonl_text(stdout)
        high_interest, rerun_reason = is_high_interest_file(findings, high_interest_kinds)
        if high_interest:
            records.append(
                PerFileScanRecord(
                    path=str(path),
                    content_hash=content_hash,
                    selected=True,
                    reason_code="rerun_queued.high_interest",
                    stage="pass1",
                    pass1_duration_ms=duration_ms,
                    rerun_reason=rerun_reason,
                )
            )
            rerun_candidates[str(path)] = rerun_reason
            continue
        records.append(
            PerFileScanRecord(
                path=str(path),
                content_hash=content_hash,
                selected=True,
                reason_code="ok.pass1",
                stage="pass1",
                pass1_duration_ms=duration_ms,
            )
        )
        final_outputs[str(path)] = stdout

    for path_string, rerun_reason in sorted(rerun_candidates.items()):
        path = Path(path_string)
        stdout, stderr, duration_ms, return_code = run_single_file_scan(
            sis_bin=sis_bin,
            path=path,
            deep=deep,
            timeout_seconds=pass2_timeout_seconds,
        )
        if stderr:
            stderr_lines.append(f"[pass2][{path}] {stderr.strip()}")
        base_output = pass1_outputs.get(path_string, "")
        content_hash = pass1_hashes.get(path_string, extract_content_hash(path))
        if return_code == 124:
            records.append(
                PerFileScanRecord(
                    path=path_string,
                    content_hash=content_hash,
                    selected=True,
                    reason_code="timeout.pass2",
                    stage="pass2",
                    pass2_duration_ms=duration_ms,
                    rerun_reason=rerun_reason,
                )
            )
            final_outputs[path_string] = base_output
            continue
        if return_code != 0:
            records.append(
                PerFileScanRecord(
                    path=path_string,
                    content_hash=content_hash,
                    selected=True,
                    reason_code="scan_error.pass2",
                    stage="pass2",
                    pass2_duration_ms=duration_ms,
                    rerun_reason=rerun_reason,
                )
            )
            final_outputs[path_string] = base_output
            continue
        reason_code = (
            "ok.pass2.timeout_recovery"
            if rerun_reason == "timeout.pass1"
            else "ok.pass2.high_interest"
        )
        records.append(
            PerFileScanRecord(
                path=path_string,
                content_hash=content_hash,
                selected=True,
                reason_code=reason_code,
                stage="pass2",
                pass2_duration_ms=duration_ms,
                rerun_reason=rerun_reason,
            )
        )
        final_outputs[path_string] = stdout

    with artifacts.jsonl_path.open("w", encoding="utf-8") as out:
        for path_string in sorted(final_outputs.keys()):
            payload = final_outputs[path_string]
            if not payload:
                continue
            out.write(payload)
            if not payload.endswith("\n"):
                out.write("\n")
    with artifacts.stderr_path.open("w", encoding="utf-8") as err:
        for line in stderr_lines:
            err.write(line)
            if not line.endswith("\n"):
                err.write("\n")

    reason_code_counts = Counter(record.reason_code for record in records)
    stage_counts = Counter(record.stage for record in records if record.selected)
    timeout_stage_counts = Counter(
        record.stage for record in records if record.reason_code.startswith("timeout.")
    )
    return {
        "mode": "two_pass",
        "skipped_scan": False,
        "selected_files": len(selected),
        "skipped_files": len(skipped_records),
        "records": [record.__dict__ for record in records],
        "reason_code_counts": dict(reason_code_counts),
        "stage_counts": dict(stage_counts),
        "timeout_stage_counts": dict(timeout_stage_counts),
        "pass1_timeout_seconds": pass1_timeout_seconds,
        "pass2_timeout_seconds": pass2_timeout_seconds,
        "sample_size": sample_size,
        "sample_seed": sample_seed,
    }


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


def normalise_runtime_behaviour_name(value: Optional[str]) -> str:
    name = normalise_key(value).strip()
    if not name:
        return "unknown"
    return name


def load_runtime_behaviour_allow_list(path: Optional[str]) -> set[str]:
    if not path:
        return set()
    target = Path(path).expanduser()
    if not target.exists():
        raise FileNotFoundError(f"allow-list file not found: {target}")
    text = target.read_text(encoding="utf-8")
    if target.suffix.lower() == ".json":
        payload = json.loads(text)
        if not isinstance(payload, list):
            raise ValueError("allow-list JSON must be an array of strings")
        return {
            normalise_runtime_behaviour_name(item)
            for item in payload
            if isinstance(item, str) and item.strip()
        }
    return {
        normalise_runtime_behaviour_name(line)
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    }


def parse_jsonl_findings(
    jsonl_path: Path,
) -> Tuple[Counter, Dict[str, Counter], int, int, Counter, List[dict]]:
    by_kind = Counter()
    by_field: Dict[str, Counter] = {
        "severity": Counter(),
        "impact": Counter(),
        "confidence": Counter(),
        "surface": Counter(),
    }
    unknown_runtime_behaviour = Counter()
    unknown_runtime_samples = []
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
                if kind == "js_runtime_unknown_behaviour_pattern":
                    meta = finding.get("meta")
                    if not isinstance(meta, dict):
                        meta = {}
                    behaviour_name = normalise_runtime_behaviour_name(
                        meta.get("js.runtime.behavior.name")
                    )
                    unknown_runtime_behaviour[behaviour_name] += 1
                    if len(unknown_runtime_samples) < 64:
                        unknown_runtime_samples.append(
                            {
                                "name": behaviour_name,
                                "evidence": normalise_key(
                                    meta.get("js.runtime.behavior.evidence")
                                ),
                                "source_object": (
                                    finding.get("objects", [None])[0]
                                    if isinstance(finding.get("objects"), list)
                                    and finding.get("objects")
                                    else None
                                ),
                                "position": finding.get("position"),
                            }
                        )
                total_findings += 1
    return (
        by_kind,
        by_field,
        total_findings,
        parse_errors,
        unknown_runtime_behaviour,
        unknown_runtime_samples,
    )


def update_latest_symlink(corpus_root: Path, latest_dir: Path) -> None:
    link_path = corpus_root / "mwb-latest"
    if link_path.exists() or link_path.is_symlink():
        if link_path.is_symlink() or link_path.is_file():
            link_path.unlink()
        else:
            if link_path.is_dir():
                shutil.rmtree(link_path)
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
    unknown_runtime_behaviour: Counter,
    unknown_runtime_samples: List[dict],
    error_counts: Dict[str, int],
    sis_version: str,
    deep: bool,
    glob: str,
    sweep_telemetry: Optional[dict] = None,
) -> None:
    telemetry = sweep_telemetry or {}
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
        "runtime_unknown_behaviour": {
            "total": int(sum(unknown_runtime_behaviour.values())),
            "unique_names": len(unknown_runtime_behaviour),
            "by_name": dict(unknown_runtime_behaviour),
            "samples": unknown_runtime_samples,
        },
        "sweep": telemetry,
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
        (
            "Unknown runtime behaviour findings",
            str(summary.get("runtime_unknown_behaviour", {}).get("total", 0)),
        ),
        (
            "Unknown runtime behaviour names",
            str(summary.get("runtime_unknown_behaviour", {}).get("unique_names", 0)),
        ),
        ("Errors", str(summary["errors"].get("scan_errors", 0))),
        ("Warnings", str(summary["errors"].get("scan_warnings", 0))),
        ("Sweep mode", normalise_key(summary.get("sweep", {}).get("mode"))),
        (
            "Sweep reason codes",
            str(len(summary.get("sweep", {}).get("reason_code_counts", {}))),
        ),
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
    unknown_runtime_counter = summary.get("runtime_unknown_behaviour", {}).get("by_name", {})
    if isinstance(unknown_runtime_counter, dict) and unknown_runtime_counter:
        sections.append(
            render_counter(
                "Unknown runtime behaviour names",
                unknown_runtime_counter,
                limit=25,
            )
        )
    reason_codes = summary.get("sweep", {}).get("reason_code_counts", {})
    if isinstance(reason_codes, dict) and reason_codes:
        sections.append(render_counter("Sweep reason codes", reason_codes, limit=20))
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
    observed_unknown_runtime_behaviour: set[str] = set()
    seen_hashes: Set[str] = set()
    high_interest_kinds = set(DEFAULT_HIGH_INTEREST_KINDS)
    high_interest_kinds.update(
        extract_finding_kind({"kind": item})
        for item in args.high_interest_kind
        if item and item.strip()
    )
    allow_list = {
        normalise_runtime_behaviour_name(name) for name in args.allow_runtime_behaviour if name
    }
    allow_list.update(load_runtime_behaviour_allow_list(args.allow_runtime_behaviour_file))

    if not args.report_only:
        for day_dir in day_dirs:
            artifacts = build_artifacts(output_root, day_dir)
            sweep_telemetry: dict = {"mode": "batch"}
            if args.two_pass:
                sweep_telemetry = run_sis_scan_two_pass(
                    sis_bin=args.sis_bin,
                    artifacts=artifacts,
                    glob=args.glob,
                    deep=args.deep,
                    force=args.force,
                    seen_hashes=seen_hashes,
                    sample_size=max(args.sample_size, 0),
                    sample_seed=args.sample_seed,
                    pass1_timeout_seconds=max(args.pass1_timeout_seconds, 1),
                    pass2_timeout_seconds=max(args.pass2_timeout_seconds, 1),
                    high_interest_kinds=high_interest_kinds,
                )
            else:
                run_sis_scan(
                    args.sis_bin,
                    day_dir,
                    artifacts.jsonl_path,
                    artifacts.stderr_path,
                    args.glob,
                    args.deep,
                    args.force,
                    args.batch_parallel,
                )
            (
                by_kind,
                by_field,
                total_findings,
                parse_errors,
                unknown_runtime_behaviour,
                unknown_runtime_samples,
            ) = parse_jsonl_findings(
                artifacts.jsonl_path
            )
            observed_unknown_runtime_behaviour.update(unknown_runtime_behaviour.keys())
            error_counts = count_errors(artifacts.stderr_path)
            write_summary(
                artifacts,
                by_kind,
                by_field,
                total_findings,
                parse_errors,
                unknown_runtime_behaviour,
                unknown_runtime_samples,
                error_counts,
                sis_version,
                args.deep,
                args.glob,
                sweep_telemetry,
            )
        if day_dirs:
            update_latest_symlink(corpus_root, day_dirs[-1])

    if args.scan_only:
        return 0

    summaries = load_summaries(summaries_dir)
    if not summaries:
        print("No summaries found to build reports.")
        return 1
    if args.report_only:
        for summary in summaries.values():
            names = summary.get("runtime_unknown_behaviour", {}).get("by_name", {})
            if isinstance(names, dict):
                observed_unknown_runtime_behaviour.update(
                    normalise_runtime_behaviour_name(name) for name in names.keys()
                )

    write_report_index(reports_dir, summaries)
    for date in summaries:
        generate_daily_report(reports_dir, summaries, date)
    generate_period_reports(reports_dir, summaries, "weekly")
    generate_period_reports(reports_dir, summaries, "monthly")
    if args.fail_on_unknown_runtime_behaviour:
        disallowed = sorted(
            name for name in observed_unknown_runtime_behaviour if name not in allow_list
        )
        if disallowed:
            print(
                "Unknown runtime behaviour names detected outside allow-list: "
                + ", ".join(disallowed)
            )
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
