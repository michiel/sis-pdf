# Future work: post-PR-20 execution plan

Date: 2026-02-11
Status: Proposed
Scope: JavaScript corpus regression, CI hardening, and coverage modernisation

## 1) Make corpus regression a required CI gate

### Objective
Prevent silent degradation in detection quality by enforcing PR-20 regression thresholds on every pull request.

### Tasks
1. Add a CI workflow step that runs:
   - `scripts/js-corpus-regression.sh crates/js-analysis/tests/fixtures/corpus plans/20260211-pr20-validation-report.json`
2. Fail the workflow when harness threshold checks fail (`--enforce-thresholds` already handles this).
3. Upload `plans/20260211-pr20-validation-report.json` as a workflow artefact.
4. Add a concise CI summary section with:
   - execution rate
   - true positive rate
   - false positive rate
   - pass/fail status
5. Mark this workflow as required in branch protection.

### Acceptance criteria
- Every PR runs the harness automatically.
- Any threshold breach fails CI.
- The JSON report is always available in CI artefacts.

## 2) Add trendline and regression-delta reporting

### Objective
Move from absolute pass/fail only to change-aware quality monitoring.

### Tasks
1. Persist a baseline report in-repo (or CI cache) with a stable schema.
2. Extend the harness to emit deltas against baseline:
   - `execution_rate_delta`
   - `true_positive_rate_delta`
   - `false_positive_rate_delta`
   - per-pattern detection count deltas
3. Add a compact machine-readable `regressions` array listing any negative deltas beyond tolerance.
4. Define tolerance policy (for example):
   - execution rate drop > 0.02 => regression
   - true positive drop > 0.02 => regression
   - false positive increase > 0.01 => regression
5. Surface deltas in CI summary markdown.

### Acceptance criteria
- PRs show both current metrics and baseline deltas.
- Regressions are explicit and actionable, not inferred manually.

## 3) Introduce governed real-world 2018-2025 corpus slices

### Objective
Reduce overfitting to synthetic fixtures and improve modern threat representativeness.

### Tasks
1. Define ingestion manifest schema with required fields:
   - sample hash
   - source provider
   - acquisition date
   - family/tag
   - licence/disclosure constraints
   - storage location reference
2. Build a curated “promotion” pipeline:
   - stage in local/offline storage
   - normalise encoding
   - deduplicate
   - classify adversarial/benign
   - promote approved subset into regression packs
3. Keep third-party payload bodies out of git unless redistribution rights are explicit.
4. Start with a small controlled slice (for example 25 adversarial + 25 benign modern samples), then scale.
5. Add quarantine handling for ambiguous or noisy samples.

### Acceptance criteria
- A documented and auditable acquisition trail exists for each promoted sample.
- At least one modern curated slice is integrated into automated regression.

## 4) Add per-family coverage metrics

### Objective
Ensure broad behavioural coverage, not just high aggregate rates.

### Tasks
1. Extend harness output with family buckets, for example:
   - esoteric encoding
   - advanced obfuscation
   - modern heap primitive
   - source-to-sink semantic flow
   - runtime exfiltration chain
   - social-engineering interaction coercion
2. Track per-family counts:
   - sample count
   - detected count
   - detection rate
3. Add minimum family-level targets (initially soft warnings, then hard gates).
4. Record unmapped or low-coverage families in a backlog section for detector improvements.

### Acceptance criteria
- JSON report includes family-level metrics.
- Low-coverage families are visible and prioritised.

## 5) Strengthen detector integration stability checks

### Objective
Ensure detector-layer mapping remains aligned with js-analysis signals.

### Tasks
1. Add integration tests asserting expected finding kinds for corpus slices.
2. Add tests validating metadata fields required by triage (for example confidence, severity, key behavioural metadata).
3. Add compatibility tests for `js-sandbox` and `js-ast` feature combinations.
4. Add a detector contract test that fails when a known behavioural pattern is no longer mapped to a finding ID.

### Acceptance criteria
- Signal-to-finding mapping regressions fail tests immediately.
- Feature-flag combinations remain validated.

## 6) Define and enforce runtime SLOs for regression sweeps

### Objective
Keep regression checks reliable and fast enough for regular CI usage.

### Tasks
1. Define SLOs:
   - max wall-clock duration for corpus sweep
   - max timeout ratio
   - max skipped ratio
2. Extend harness summary with timing and skip/timeout distributions.
3. Enforce SLO thresholds in CI with clear failure reasons.
4. Add periodic profiling runs to detect performance drift.
5. Introduce “fast” and “full” sweep modes if needed:
   - fast mode for PR gating
   - full mode for scheduled nightly runs

### Acceptance criteria
- CI runtime remains within agreed limits.
- Performance regressions are surfaced as first-class failures.

## Recommended execution order

1. CI gate integration (Step 1)
2. Trendline/delta reporting (Step 2)
3. Per-family coverage metrics (Step 4)
4. Detector integration stability checks (Step 5)
5. Runtime SLO enforcement (Step 6)
6. Governed real-world corpus expansion (Step 3, ongoing)

## Handover notes

- PR-20 baseline currently passes with:
  - execution rate: 1.000
  - true positive rate: 1.000
  - false positive rate: 0.000
- Reference artefacts:
  - `plans/20260211-pr20-validation-report.json`
  - `plans/20260211-pr20-validation-report.md`
  - `plans/20260211-js-corpus-acquisition.md`

## Secondary-parser hazard regression handover

- Deterministic fixtures now exist for parser-diff hazard metadata:
  - `crates/sis-pdf-core/tests/fixtures/parser_diff_hazards/creation-date-trailing-timezone.pdf`
  - `crates/sis-pdf-core/tests/fixtures/parser_diff_hazards/unbalanced-literal-parentheses.pdf`
- Required regression suite:
  - `cargo test -p sis-pdf-core --test parser_diff_hazard_regressions -- --nocapture`
- Companion baseline suite:
  - `cargo test -p sis-pdf-core --test corpus_captured_regressions -- --nocapture`
- When touching parser-diff logic (`crates/sis-pdf-core/src/diff.rs`) or secondary-parser prevalence synthesis (`crates/sis-pdf-core/src/runner.rs`), run both suites before merge.
- If corpus drift later provides a stable real sample for these hazards, capture it under `crates/sis-pdf-core/tests/fixtures/corpus_captured/` and update `crates/sis-pdf-core/tests/fixtures/corpus_captured/manifest.json`, while retaining deterministic fixtures as baseline anti-flake coverage.
