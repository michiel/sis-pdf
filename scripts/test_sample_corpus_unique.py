#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from sample_corpus_unique import (
    build_summary,
    collect_candidates,
    sample_candidates,
)


def write_pdf(path: Path, body: bytes) -> None:
    path.write_bytes(b"%PDF-1.7\n" + body + b"\n%%EOF\n")


class SampleCorpusUniqueTests(unittest.TestCase):
    def test_collect_candidates_dedups_identical_content_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            day1 = root / "mwb-2026-02-10"
            day2 = root / "mwb-2026-02-11"
            day1.mkdir(parents=True)
            day2.mkdir(parents=True)
            write_pdf(day1 / "a.pdf", b"same payload")
            write_pdf(day2 / "b.pdf", b"same payload")
            write_pdf(day2 / "c.pdf", b"different payload")

            candidates, hash_counts = collect_candidates(root, "*.pdf")

            self.assertEqual(len(candidates), 2)
            duplicate_hashes = [digest for digest, count in hash_counts.items() if count > 1]
            self.assertEqual(len(duplicate_hashes), 1)

    def test_sampling_is_deterministic_for_seed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(20):
                day = root / f"mwb-2026-02-{10 + (index % 3):02d}"
                day.mkdir(parents=True, exist_ok=True)
                write_pdf(day / f"f{index}.pdf", f"payload-{index}".encode())

            candidates, _ = collect_candidates(root, "*.pdf")
            sample_a = sample_candidates(candidates, sample_size=7, seed=99)
            sample_b = sample_candidates(candidates, sample_size=7, seed=99)
            self.assertEqual(
                [str(candidate.path) for candidate in sample_a],
                [str(candidate.path) for candidate in sample_b],
            )

    def test_summary_reports_zero_duplicate_hashes_in_selected_sample(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            day1 = root / "mwb-2026-02-10"
            day2 = root / "mwb-2026-02-11"
            day1.mkdir(parents=True)
            day2.mkdir(parents=True)
            write_pdf(day1 / "x1.pdf", b"same")
            write_pdf(day2 / "x2.pdf", b"same")
            write_pdf(day2 / "x3.pdf", b"unique")

            candidates, hash_counts = collect_candidates(root, "*.pdf")
            selected = sample_candidates(candidates, sample_size=30, seed=1)
            summary = build_summary(
                corpus_root=root,
                glob="*.pdf",
                sample_size=30,
                seed=1,
                selected=selected,
                hash_counts=hash_counts,
            )
            self.assertEqual(summary["sample_size_selected"], len(selected))
            self.assertEqual(summary["duplicate_hash_count"], 1)
            selected_hashes = summary["selected_hashes"]
            self.assertEqual(len(selected_hashes), len(set(selected_hashes)))


if __name__ == "__main__":
    unittest.main()
