# Timeout-heavy PDF anti-analysis plan

Date: 2026-02-14  
Status: Proposed  
Owner: `sis-pdf-core` + `sis-pdf-detectors`

## 1) Objective

Treat recurring scan timeouts in `tmp/corpus` as a distinct anti-analysis bucket and determine whether they represent:

1. Intentional resource-exhaustion/evasion behaviour.
2. Parser/detector performance blind spots.
3. Benign-but-expensive artefact patterns.

## 2) Scope

Initial focus is the timeout-heavy hashes identified in the corpus sweep (12s cap), prioritised by recurrence:

1. `fb87d8a7807626279bae04d56ba01ce1401917f6b0e7a74a335208a940221ddd.pdf`
2. `c95a10a176aa14143f738c3ab6f83fc7465cc98b33655312b9cf917f4b003ea9.pdf`
3. `78a296f46e1490e3c5052b2e44560bd6ab5d1fe13b02e797ed305fe7d42ee789.pdf`
4. `5bb77b5790891f42208d9224a231059ed8e16b7174228caa9dc201329288a741.pdf`
5. `9ff24c464780feb6425d0ab1f30a74401e228b9ad570bb25698e31b4b313a4f4.pdf`

## 3) Hypotheses

1. **Detector hotspot hypothesis**: one or two expensive detector classes dominate runtime tails.
2. **Malformed-structure hypothesis**: heavy xref/objstm/incremental anomalies create expensive traversal patterns.
3. **Anti-analysis hypothesis**: crafted payloads intentionally trigger worst-case decode/font/image paths.

## 4) Work plan

### PH-A: Reproducibility and profiling

1. Reproduce timeout behaviour per hash under fixed budgets (`12s`, `20s`, `30s`) and capture completion rate.
2. Run `--runtime-profile --runtime-profile-format json` on completed runs.
3. Attribute top runtime contributors by phase and detector.

### PH-B: Classification and finding enrichment

1. Define timeout classes:
   - `parser_structural_exhaustion`
   - `decode_budget_exhaustion`
   - `font_analysis_hotspot`
   - `image_analysis_hotspot`
   - `mixed_hotspot`
2. Map each timeout-heavy hash to one class with supporting telemetry.
3. Propose or refine findings/metadata so anti-analysis intent is visible without deep manual triage.

### PH-C: Mitigation strategy

1. Add bounded fast-paths for dominant hotspots while preserving detection quality.
2. Ensure graceful partial-analysis output for timeout-prone files.
3. Add corpus-captured regression fixtures for each timeout class.

## 5) Deliverables

1. Timeout taxonomy with per-hash mapping.
2. Detector/phase hotspot table with p95 runtime impact.
3. Concrete remediation PR checklist for top hotspot class.
4. Regression fixtures/tests for timeout classes.

## 6) Acceptance criteria

1. Timeout-heavy bucket has explicit class labels and consistent triage guidance.
2. At least one hotspot class gets measurable p95 improvement (target: >=15% for that class).
3. No loss of high-severity finding coverage on timeout-heavy samples.

## 7) Execution checklist

- [x] PH-A complete: reproducibility matrix and runtime profiles captured.
- [x] PH-B complete: timeout classes assigned with evidence.
- [x] PH-C complete: first mitigation implemented and validated.
- [ ] Regression fixtures and tests added for mitigated class.

## 8) Initial analysis (2026-02-14)

### 8.1 Reproducibility matrix (`12s`/`20s`/`30s`)

Representative daily sample path was selected per hash.

| Hash | 12s | 20s | 30s | Notes |
|---|---|---|---|---|
| `fb87d8a7...` | timeout | ok (16s) | ok (16s) | Near-threshold runtime; highly budget-sensitive |
| `c95a10a1...` | timeout | timeout | timeout | Persistent timeout even at 30s |
| `78a296f4...` | ok (9s) | ok (8s) | ok (4s) | Completes under all tested budgets |
| `5bb77b57...` | ok (4s) | ok (4s) | ok (4s) | Completes under all tested budgets |
| `9ff24c46...` | ok (2s) | ok (3s) | ok (3s) | Completes under all tested budgets |

### 8.2 Runtime-profile hotspot evidence (completed cases)

`--runtime-profile --runtime-profile-format json` shows detection phase dominates runtime tails. Top contributors:

| Hash | Total ms | Parse ms | Detection ms | Top detector contributors |
|---|---:|---:|---:|---|
| `fb87d8a7...` | 15,958 | 157 | 15,507 | `content_first_stage1` (15,498ms), `content_phishing` (1,631ms), `image_analysis` (635ms) |
| `78a296f4...` | 4,506 | 12 | 4,474 | `content_first_stage1` (4,470ms), `content_phishing` (224ms) |
| `5bb77b57...` | 3,661 | 19 | 3,581 | `content_first_stage1` (3,576ms), `content_phishing` (121ms) |
| `9ff24c46...` | 2,560 | 11 | 2,517 | `content_first_stage1` (2,375ms), `js_present` (384ms), `font_js_exploitation_bridge` (371ms), `js_polymorphic` (364ms) |

### 8.3 Preliminary class mapping

- `fb87d8a7...`: `mixed_hotspot` (dominant detector hotspot + large structural/object volume).
- `c95a10a1...`: provisional `mixed_hotspot` with dominant detector-stage exhaustion (`scan/findings` path) rather than base parser failure.
- `78a296f4...`: not timeout-heavy under current budget; candidate control sample.
- `5bb77b57...`: not timeout-heavy under current budget; candidate control sample.
- `9ff24c46...`: not timeout-heavy under current budget; candidate control sample.

### 8.4 PH-A status update

- Reproducibility matrix: **captured**.
- Runtime profiles for completed samples: **captured**.
- Persistent timeout sample (`c95a10a1...`) now has targeted isolation evidence (below) showing detector/findings-stage exhaustion.

### 8.5 Targeted isolation: `c95a10a1...` (2026-02-14)

#### 8.5.1 Staged scan isolation (30s cap)

All tested scan modes still timed out at `30s`:

- `--deep --json`
- `--fast --json`
- `--deep --json --no-image-analysis`
- `--deep --json --no-js-sandbox`
- `--deep --json --no-js-ast`
- `--deep --json --no-font-signatures`
- `--deep --json --no-js-sandbox --no-image-analysis`
- `--deep --json --no-js-ast --no-image-analysis`
- `--fast --json --no-image-analysis`
- `--fast --json --no-js-sandbox`
- `--fast --json --no-js-sandbox --no-image-analysis`
- `--deep --json --max-objects 20000 --max-recursion-depth 32`

Inference: no single optional subsystem switch (JS/image/font-signature) is sufficient; timeout pressure is upstream and/or in shared detector graph traversal.

#### 8.5.2 Parse-vs-findings query split

On the same sample:

- Fast structural queries complete quickly:
  - `trailer` (`1s`, rc=`0`)
  - `xref.startxrefs` (`1s`, rc=`0`)
  - `xref.sections` (`0s`, rc=`0`)
  - `objects.count` (`1s`, rc=`0`, result=`865`)
- `findings` query times out at `30s` (rc=`124`).

Inference: the base parser/xref path is not the primary bottleneck; timeout is in findings generation (detector/correlation path), consistent with `mixed_hotspot` classification.
