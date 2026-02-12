#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

HASH_NAME_HEX_LEN = 64
DEFAULT_SAMPLE_SIZE = 30
DEFAULT_SEED = 20260212


@dataclass(frozen=True)
class Candidate:
    path: Path
    content_hash: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Select a deterministic random sample of PDFs from a corpus with hash dedup enabled by default."
        )
    )
    parser.add_argument(
        "--corpus-root",
        required=True,
        help="Corpus root directory (recursively searched).",
    )
    parser.add_argument(
        "--glob",
        default="*.pdf",
        help="Filename glob matched recursively under corpus root.",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=DEFAULT_SAMPLE_SIZE,
        help=f"Number of unique-hash files to sample (default: {DEFAULT_SAMPLE_SIZE}).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help=f"Deterministic random seed (default: {DEFAULT_SEED}).",
    )
    parser.add_argument(
        "--out",
        default="-",
        help="Output file path for sampled file list (default: stdout).",
    )
    parser.add_argument(
        "--summary-out",
        help="Optional JSON summary output path.",
    )
    return parser.parse_args()


def looks_like_sha256_filename(path: Path) -> bool:
    stem = path.stem.lower()
    if len(stem) != HASH_NAME_HEX_LEN:
        return False
    return all(ch in "0123456789abcdef" for ch in stem)


def content_hash(path: Path) -> str:
    if looks_like_sha256_filename(path):
        return path.stem.lower()
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def collect_candidates(corpus_root: Path, glob: str) -> Tuple[List[Candidate], Dict[str, int]]:
    candidates: List[Candidate] = []
    hash_counts: Dict[str, int] = {}
    for path in sorted(corpus_root.rglob(glob)):
        if not path.is_file():
            continue
        digest = content_hash(path)
        hash_counts[digest] = hash_counts.get(digest, 0) + 1
        if hash_counts[digest] > 1:
            continue
        candidates.append(Candidate(path=path, content_hash=digest))
    return candidates, hash_counts


def sample_candidates(
    candidates: Sequence[Candidate], sample_size: int, seed: int
) -> List[Candidate]:
    if sample_size <= 0 or sample_size >= len(candidates):
        return list(candidates)
    rng = random.Random(seed)
    selected = rng.sample(list(candidates), sample_size)
    return sorted(selected, key=lambda candidate: str(candidate.path))


def write_paths(paths: Sequence[Path], out: str) -> None:
    text = "\n".join(str(path) for path in paths)
    if text:
        text += "\n"
    if out == "-":
        print(text, end="")
        return
    Path(out).write_text(text, encoding="utf-8")


def build_summary(
    corpus_root: Path,
    glob: str,
    sample_size: int,
    seed: int,
    selected: Sequence[Candidate],
    hash_counts: Dict[str, int],
) -> Dict[str, object]:
    duplicate_hashes = sorted(digest for digest, count in hash_counts.items() if count > 1)
    return {
        "corpus_root": str(corpus_root),
        "glob": glob,
        "seed": seed,
        "sample_size_requested": sample_size,
        "sample_size_selected": len(selected),
        "unique_hash_count": len(hash_counts),
        "duplicate_hash_count": len(duplicate_hashes),
        "duplicate_hashes_sample": duplicate_hashes[:12],
        "selected_hashes": [candidate.content_hash for candidate in selected],
        "selected_paths": [str(candidate.path) for candidate in selected],
    }


def run(args: argparse.Namespace) -> int:
    corpus_root = Path(args.corpus_root).expanduser()
    if not corpus_root.exists():
        print(f"Corpus root not found: {corpus_root}")
        return 2
    candidates, hash_counts = collect_candidates(corpus_root, args.glob)
    selected = sample_candidates(candidates, args.sample_size, args.seed)
    write_paths([candidate.path for candidate in selected], args.out)

    if args.summary_out:
        summary = build_summary(
            corpus_root=corpus_root,
            glob=args.glob,
            sample_size=args.sample_size,
            seed=args.seed,
            selected=selected,
            hash_counts=hash_counts,
        )
        Path(args.summary_out).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return 0


def main() -> int:
    return run(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
