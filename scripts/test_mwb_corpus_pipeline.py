#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from mwb_corpus_pipeline import build_day_scan_plan, is_high_interest_file


def make_pdf(path: Path) -> None:
    path.write_bytes(b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n")


class MwbCorpusPipelineTests(unittest.TestCase):
    def test_build_day_scan_plan_dedups_cross_day_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            day1 = root / "mwb-2026-02-11"
            day2 = root / "mwb-2026-02-12"
            day1.mkdir(parents=True)
            day2.mkdir(parents=True)
            first = day1 / ("a" * 64 + ".pdf")
            second = day1 / ("b" * 64 + ".pdf")
            duplicate = day2 / ("a" * 64 + ".pdf")
            make_pdf(first)
            make_pdf(second)
            make_pdf(duplicate)

            seen_hashes = set()
            selected_day1, skipped_day1 = build_day_scan_plan(
                [first, second],
                seen_hashes=seen_hashes,
                sample_size=0,
                sample_seed=1337,
                day="2026-02-11",
            )
            self.assertEqual(len(selected_day1), 2)
            self.assertEqual(len(skipped_day1), 0)

            selected_day2, skipped_day2 = build_day_scan_plan(
                [duplicate],
                seen_hashes=seen_hashes,
                sample_size=0,
                sample_seed=1337,
                day="2026-02-12",
            )
            self.assertEqual(len(selected_day2), 0)
            self.assertEqual(len(skipped_day2), 1)
            self.assertEqual(skipped_day2[0].reason_code, "dedup.hash_duplicate")

    def test_build_day_scan_plan_sampling_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = []
            for index in range(10):
                stem = f"{index:064x}"
                path = root / f"{stem}.pdf"
                make_pdf(path)
                paths.append(path)

            selected_a, _ = build_day_scan_plan(
                paths,
                seen_hashes=set(),
                sample_size=3,
                sample_seed=42,
                day="2026-02-11",
            )
            selected_b, _ = build_day_scan_plan(
                paths,
                seen_hashes=set(),
                sample_size=3,
                sample_seed=42,
                day="2026-02-11",
            )
            self.assertEqual([str(path) for path, _ in selected_a], [str(path) for path, _ in selected_b])

    def test_high_interest_detection_by_severity_and_kind(self) -> None:
        high_severity, reason = is_high_interest_file(
            [{"kind": "content_stream_anomaly", "severity": "High"}],
            {"launch_action_present"},
        )
        self.assertTrue(high_severity)
        self.assertIn("high_severity", reason)

        high_kind, reason = is_high_interest_file(
            [{"kind": "launch_action_present", "severity": "Low"}],
            {"launch_action_present"},
        )
        self.assertTrue(high_kind)
        self.assertIn("high_interest_kind", reason)

        neutral, reason = is_high_interest_file(
            [{"kind": "content_stream_anomaly", "severity": "Low"}],
            {"launch_action_present"},
        )
        self.assertFalse(neutral)
        self.assertEqual(reason, "")
if __name__ == "__main__":
    unittest.main()
