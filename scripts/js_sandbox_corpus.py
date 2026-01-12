#!/usr/bin/env python3
"""Extract JS from a corpus and evaluate each payload in the sandbox."""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run JS sandbox over a PDF corpus.")
    parser.add_argument("corpus", help="Path to corpus directory")
    parser.add_argument("--glob", default="*.pdf", help="Glob pattern (default: *.pdf)")
    parser.add_argument("--output-dir", default="out/js_sandbox", help="Output directory")
    parser.add_argument("--sis-bin", default="target/release/sis", help="Path to sis binary")
    parser.add_argument("--workers", type=int, default=8, help="Parallel workers")
    parser.add_argument("--max-files", type=int, default=0, help="Limit files processed")
    parser.add_argument("--keep-extracted", action="store_true", help="Keep extracted JS files")
    return parser.parse_args()


def iter_files(corpus: Path, pattern: str) -> List[Path]:
    files: List[Path] = []
    for root, _, filenames in os.walk(corpus):
        for name in filenames:
            if fnmatch.fnmatch(name, pattern):
                files.append(Path(root) / name)
    return sorted(files)


def run_cmd(args: List[str]) -> Tuple[int, str, str]:
    proc = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def extract_js(sis_bin: Path, pdf_path: Path, out_dir: Path) -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    code, _, err = run_cmd([str(sis_bin), "extract", "js", str(pdf_path), "--out", str(out_dir)])
    if code != 0:
        raise RuntimeError(err.strip() or "extract failed")
    return sorted(out_dir.glob("*.js"))


def eval_js(sis_bin: Path, js_path: Path) -> Dict:
    code, stdout, stderr = run_cmd(
        [str(sis_bin), "sandbox", "eval", str(js_path), "--type", "js"]
    )
    if code != 0:
        return {
            "status": "error",
            "stderr": stderr.strip(),
        }
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return {"status": "error", "stderr": "invalid json output"}


def error_signature(report: Dict) -> str:
    if report.get("status") == "timeout":
        return "timeout"
    if report.get("status") == "skipped":
        return report.get("skip_reason") or "skipped"
    if report.get("status") == "error":
        return report.get("stderr") or "error"
    signals = report.get("signals") or {}
    errors = signals.get("errors") or []
    return errors[0] if errors else "none"


def process_file(
    sis_bin: Path,
    pdf_path: Path,
    extract_root: Path,
    failure_payloads: Path,
    keep_extracted: bool,
) -> List[Dict]:
    pdf_hash = hashlib.sha256(str(pdf_path).encode("utf-8")).hexdigest()[:12]
    extract_dir = extract_root / pdf_hash
    results: List[Dict] = []
    try:
        js_files = extract_js(sis_bin, pdf_path, extract_dir)
    except Exception as exc:
        return [
            {
                "pdf_path": str(pdf_path),
                "status": "extract_failed",
                "error": str(exc),
            }
        ]
    for js_file in js_files:
        report = eval_js(sis_bin, js_file)
        signature = error_signature(report)
        failure_payload_path = None
        if signature != "none":
            payload_hash = hashlib.sha256(js_file.read_bytes()).hexdigest()[:16]
            target = failure_payloads / f"{payload_hash}.js"
            if not target.exists():
                shutil.copy(js_file, target)
            failure_payload_path = str(target)
        results.append(
            {
                "pdf_path": str(pdf_path),
                "js_path": str(js_file),
                "report": report,
                "signature": signature,
                "failure_payload": failure_payload_path,
            }
        )
    if not keep_extracted:
        shutil.rmtree(extract_dir, ignore_errors=True)
    return results


def main() -> int:
    args = parse_args()
    corpus = Path(args.corpus)
    if not corpus.exists():
        raise SystemExit(f"Corpus not found: {corpus}")
    sis_bin = Path(args.sis_bin)
    if not sis_bin.exists():
        raise SystemExit(f"sis binary not found: {sis_bin}")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    extract_root = output_dir / "extracted"
    results_path = output_dir / "results.jsonl"
    failures_path = output_dir / "failures.jsonl"
    failure_payloads = output_dir / "failure_payloads"
    failure_payloads.mkdir(parents=True, exist_ok=True)

    files = iter_files(corpus, args.glob)
    if args.max_files:
        files = files[: args.max_files]
    if not files:
        raise SystemExit(f"No files matched pattern '{args.glob}' in {corpus}")

    print(f"Found {len(files)} files to process")
    with results_path.open("w", encoding="utf-8") as results_out, failures_path.open(
        "w", encoding="utf-8"
    ) as failures_out:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(
                    process_file,
                    sis_bin,
                    pdf_path,
                    extract_root,
                    failure_payloads,
                    args.keep_extracted,
                ): pdf_path
                for pdf_path in files
            }
            for future in as_completed(futures):
                for entry in future.result():
                    results_out.write(json.dumps(entry) + "\n")
                    report = entry.get("report") or {}
                    signature = entry.get("signature") or error_signature(report)
                    if signature != "none":
                        failure_entry = {
                            "pdf_path": entry.get("pdf_path"),
                            "js_path": entry.get("js_path"),
                            "signature": signature,
                            "failure_payload": entry.get("failure_payload"),
                            "report": report,
                        }
                        failures_out.write(json.dumps(failure_entry) + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
