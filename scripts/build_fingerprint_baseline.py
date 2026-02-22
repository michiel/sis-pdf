#!/usr/bin/env python3
"""
Build a stream fingerprint baseline profile from events.full JSON exports.

Input files may be JSON documents produced by:
  sis query <pdf> events.full --format json

Only ContentStreamExec rows with stream_exec.op_family_counts are used.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import uuid
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List


def iter_events_from_file(path: Path) -> Iterable[dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    result = payload.get("result", payload)
    events = result.get("events", []) if isinstance(result, dict) else []
    for event in events:
        yield event


def normalise_histogram(counts: Dict[str, int]) -> Dict[str, float]:
    total = float(sum(max(v, 0) for v in counts.values()))
    if total <= 0:
        return {}
    return {k: (max(v, 0) / total) for k, v in sorted(counts.items())}


def build_profile(input_paths: List[Path]) -> dict:
    centroid_acc = Counter()
    vectors = []
    source_hash = hashlib.sha256()

    for path in input_paths:
        data = path.read_bytes()
        source_hash.update(path.as_posix().encode("utf-8"))
        source_hash.update(len(data).to_bytes(8, "little"))
        source_hash.update(hashlib.sha256(data).digest())

        for event in iter_events_from_file(path):
            if event.get("event_type") != "ContentStreamExec":
                continue
            stream_exec = event.get("stream_exec") or {}
            op_counts = stream_exec.get("op_family_counts") or {}
            if not isinstance(op_counts, dict) or not op_counts:
                continue
            histogram = normalise_histogram({str(k): int(v) for k, v in op_counts.items()})
            if not histogram:
                continue
            vectors.append(histogram)
            centroid_acc.update(histogram)

    centroid = {}
    if vectors:
        for key in sorted(centroid_acc):
            centroid[key] = centroid_acc[key] / float(len(vectors))

    return {
        "schema_version": 1,
        "baseline_id": f"baseline-{uuid.uuid4()}",
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "builder_version": "scripts/build_fingerprint_baseline.py@1",
        "source_corpus_digest": source_hash.hexdigest(),
        "stream_count": len(vectors),
        "centroids": [
            {
                "id": "global",
                "histogram": centroid,
            }
        ],
    }


def write_sha256(path: Path) -> Path:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    out = path.with_suffix(path.suffix + ".sha256")
    out.write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Build fingerprint baseline profile JSON.")
    parser.add_argument("inputs", nargs="+", help="Input events.full JSON files")
    parser.add_argument("--out", required=True, help="Output baseline profile path")
    parser.add_argument(
        "--write-sha256",
        action="store_true",
        help="Also write <out>.sha256 checksum file",
    )
    args = parser.parse_args()

    input_paths = [Path(value) for value in args.inputs]
    for path in input_paths:
        if not path.is_file():
            raise SystemExit(f"input file not found: {path}")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    profile = build_profile(input_paths)
    out_path.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote baseline profile: {out_path} (streams={profile['stream_count']})")

    if args.write_sha256:
        checksum_path = write_sha256(out_path)
        print(f"Wrote checksum: {checksum_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
