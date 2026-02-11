# PR-20 S6-4: Validation sweep metrics report

Date: 2026-02-11
Status: Implemented
Input corpus: `crates/js-analysis/tests/fixtures/corpus`
Report JSON: `plans/20260211-pr20-validation-report.json`

## Summary metrics

- Total samples: 120
- Adversarial samples: 60
- Benign samples: 60
- Execution rate: 1.000
- True positive rate: 1.000
- False positive rate: 0.000
- Threshold check: pass

## Threshold policy

- Execution rate >= 0.75
- True positive rate >= 0.85
- False positive rate < 0.05

## Notes

- This sweep uses synthetic adversarial and benign corpora committed for deterministic CI coverage.
- Per-sample outcomes are recorded in the JSON report for trend comparison between runs.
- Threshold enforcement is wired into the harness (`--enforce-thresholds`) and suitable for CI gating.

