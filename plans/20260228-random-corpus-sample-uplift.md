# Technical Uplift Plan: Random Corpus Sample Deep Analysis
**Date**: 2026-02-28  
**Scope**: 15 random PDFs sampled from `tmp/corpus/` (820 files total) + deep analysis subset of 6 files  
**Branch**: `feature/consistency`

---

## 1. Sampling Method and Baseline Run

Random sampling command used:

```bash
find tmp/corpus -type f -name '*.pdf' | sort > /tmp/all_corpus_pdfs.txt
shuf -n 15 /tmp/all_corpus_pdfs.txt > /tmp/sample15.txt
```

Scan command used for baseline:

```bash
target/debug/sis scan <file.pdf> --deep --json
```

### 1.1 Performance summary (15-file sample)

- Fastest: `2b708...` at 17 ms
- Slowest: `c2d0d7e2...` at 34,652 ms
- Second slowest: `b509f6c9...` at 5,037 ms
- All 15 files completed with exit code `0`
- No hard scan failures, panics, or hangs observed in this sample

### 1.2 Chain quality summary (15-file sample)

Aggregate chain metrics from all 15 reports:

- Total chains: 204
- Singleton chains: 151
- Multi-finding chains: 53
- Singleton rate: **74.0%**
- Chains with edges: 33.3%
- Chains with `chain_completeness > 0`: 51.5%

Interpretation:
- The model has improved versus earlier baselines but still over-produces singletons.
- End-to-end attack-path coverage remains inconsistent; many top-risk files are still dominated by singleton chain leaders.

### 1.3 Error and observability findings

- `c2d0d7e2...` emitted repeated non-fatal `decode_budget_exceeded` warnings to stderr.
- Those warnings are not consistently represented as structured report findings.
- This creates telemetry/report drift: operators see severe log noise that is not queryable in report JSON.

---

## 2. Deep Analysis Subset (Novel Variety Set)

Selected for variety:

1. `ef6dff9b...` — mshta + PowerShell launch chain (action execution)
2. `6648302d...` — polyglot PDF+ZIP+PE dropper (container chain)
3. `9ab20ec2...` — ConnectWise-style filter obfuscation + mass URI links (obfuscation + lure)
4. `c2d0d7e2...` — decode-budget and object-graph exhaustion (performance/DoS)
5. `b509f6c9...` — decompression bomb + parser exhaustion (DoS)
6. `2b708add...` — low-signal anomalous edge case (quality/noise floor)

### 2.1 Runtime profile hot spots

Using:

```bash
sis scan <file> --deep --runtime-profile --runtime-profile-format json --json
```

Top detector by runtime in all 6 files:
- `content_first_stage1` dominated every runtime profile.

Notable profile values:
- `c2d0d7e2...`: `content_first_stage1` ~33,016 ms / 33,712 ms total
- `b509f6c9...`: `content_first_stage1` ~5,055 ms / 5,077 ms total
- `9ab20ec2...`: `content_first_stage1` ~1,510 ms / 1,565 ms total

Conclusion:
- `content_first_stage1` is currently the principal scalability risk in random-corpus operation.

### 2.2 Dynamic analysis coverage

Across all 6 deep-dive reports:
- `sandbox_summary.profiles = 0`

Conclusion:
- Dynamic behaviour modelling was not materially engaged for this subset.
- Current deep-mode value is primarily static-analysis expansion.

---

## 3. Attack Vector Reconstruction vs Chain Representation

### 3.1 `ef6dff9b` (mshta -> PowerShell cradle)

Observed exploit attempt:
- OpenAction/automatic trigger
- Launch action targeting `mshta`
- Embedded URL in launch parameters (`launch_win_embedded_url`)

Chain state:
- Strong high-score chains exist and include launch evidence.
- Residual gap: social-engineering, renderer divergence, and full execution sequence are still split across multiple chains.

### 3.2 `6648302d` (polyglot ZIP+PE)

Observed exploit attempt:
- `polyglot_signature_conflict`
- carved ZIP payload
- nested PE chain findings

Chain state:
- Intent scoring is strong (`ExploitPrimitive` high score).
- Top chain is still not the most semantically complete polyglot dropper narrative; consolidation remains incomplete.

### 3.3 `9ab20ec2` (ConnectWise-style obfuscation + URI lure)

Observed attack vector:
- high-volume annotation URI actions (20)
- external installer lure (`ScreenConnect.ClientSetup.msi`)
- strong filter/structure obfuscation signals

Chain state:
- Some URI multi-finding chain coverage exists.
- Top-ranked chains are still often singleton structural findings, diluting attack-path readability.

### 3.4 `b509f6c9` (decompression bomb)

Observed attack vector:
- `decompression_ratio_suspicious` x6 (max >1000)
- `parser_resource_exhaustion`

Chain state:
- DoS intent is correctly strong.
- Decompression and exhaustion are still distributed over multiple chains rather than one explicit decode-amplification path.

### 3.5 `c2d0d7e2` (decode budget exhaustion)

Observed attack vector:
- parser and reference-depth exhaustion signals
- broad stream/image anomaly pressure

Chain state:
- Predominantly singleton high-score chains with no edges.
- Operationally weak for end-to-end narration of DoS-style attack flow.

---

## 4. Chain Model Suitability Assessment

### 4.1 Is current structure suitable for end-to-end attack paths?

Short answer: **partially suitable, but not sufficient by itself**.

What works:
- Trigger/action/payload fields and chain scoring framework are useful.
- Completeness and edge synthesis provide a base for path semantics.
- Clustered chains now cover several high-volume finding families.

What fails in practice:
- High singleton residual rate (74% in random sample).
- Structural findings frequently outrank semantically richer exploit chains.
- Resource-exhaustion and decompression paths are not modelled as first-class multi-stage chains.
- Dynamic execution evidence is often absent, weakening stage progression confidence.

Conclusion:
- Keep current `ExploitChain` schema, but evolve synthesis to include intent-aware chain construction and resource-exhaustion path templates.

---

## 5. Priority Uplift Backlog

## P0: Performance and Throughput

### P0.1 Optimise `content_first_stage1` for large-page corpora

Problem:
- Dominates runtime in every deep profile; catastrophic on outliers.

Tasks:
1. Add per-detector operation budget based on `(object_count, stream_count, page_count)`.
2. Add bounded sampling mode for very large page sets (e.g. sample N pages per structural bucket).
3. Implement early-stop heuristics when confidence has converged and no new high-value signals appear.
4. Emit explicit truncation metadata in findings/report when budgets activate.

Success criteria:
- `c2d0d7e2` deep scan < 10,000 ms (currently ~33,700 ms)
- `b509f6c9` deep scan < 2,000 ms (currently ~5,100 ms)

### P0.2 Make runtime profile output contract unambiguous

Problem:
- Runtime profile JSON currently arrives on stderr while report JSON arrives on stdout.

Tasks:
1. Add explicit `--runtime-profile-output <stdout|stderr|file>`.
2. Ensure one JSON document per stream.
3. Add integration test covering parseability and stream routing.

Success criteria:
- Tooling can parse profile JSON without stream heuristics.

## P1: Chain Architecture

### P1.1 Intent-aware top-chain ranking

Problem:
- Singleton structural findings often outrank richer exploit-path chains.

Tasks:
1. Add ranking boost for chains that align with top intent bucket findings.
2. Penalise isolated structural chains lacking trigger/action/payload progression.

Success criteria:
- In `9ab20ec2`, top chain becomes URI+obfuscation operational chain, not singleton parser artefact.

### P1.2 Resource-exhaustion chain template

Problem:
- DoS evidence is split across singletons (`decompression_ratio_suspicious`, `parser_resource_exhaustion`, depth/budget findings).

Tasks:
1. Add `resource_exhaustion_chain` composite in correlation pass.
2. Stage mapping: input -> decode -> render/execute_budget -> exhaustion.
3. Auto-link decompression + parser exhaustion + budget/depth anomalies.

Success criteria:
- `b509f6c9` and `c2d0d7e2` produce one dominant multi-finding DoS chain.

### P1.3 Telemetry/report parity for budget warnings

Problem:
- `decode_budget_exceeded` appears in logs but not as stable report finding.

Tasks:
1. Standardise as a first-class finding (or explicit structured telemetry block in report).
2. Ensure count and scope are queryable.

Success criteria:
- No discrepancy between stderr warnings and report evidence for budget exhaustion.

## P2: Dynamic Analysis and Behavioural Depth

### P2.1 Expand dynamic profile coverage in deep mode

Problem:
- Deep subset produced zero sandbox profiles.

Tasks:
1. Add deterministic eligibility rules for when JS/action payloads should trigger sandbox attempts.
2. Add explicit "skipped dynamic analysis" reasons in report.
3. Add runtime budget for sandbox attempts to avoid throughput collapse.

Success criteria:
- At least one applicable file in mixed corpus batches shows non-empty `sandbox_summary.profiles`.

### P2.2 Promote dynamic-to-chain evidence links

Problem:
- Behavioural outcomes are weakly reflected in chain stages.

Tasks:
1. Map dynamic outcomes to `chain.stage` and `chain.capability` metadata.
2. Add confidence promotion when static + dynamic evidence agree.

Success criteria:
- Chains with dynamic corroboration rank above static-only structural chains of equal base score.

## P3: Noise Reduction / Precision

### P3.1 High-volume cycle and mismatch compaction

Problem:
- `object_reference_cycle` and `label_mismatch_stream_type` dominate high-noise samples.

Tasks:
1. Expand benign/suspicious subtype classification.
2. Aggregate repetitive benign forms into summary findings earlier.
3. Keep suspicious subtypes as high-signal findings.

Success criteria:
- Reduced finding flood without dropping known malicious outcomes.

---

## 6. Testing and Validation Plan

Required validation after implementation:

1. `cargo test -p sis-pdf-core --test corpus_captured_regressions`
2. Runtime profile re-runs for:
   - `decode-budget-exhaustion-c2d0d7e2.pdf`
   - `decompression-bomb-font-flood-b509f6c9.pdf`
   - `connectwise-filter-obfuscation-9ab20ec2.pdf`
3. Recompute random-sample chain metrics on fresh 15-file sample and compare:
   - singleton rate
   - edge coverage rate
   - nonzero completeness rate

Target deltas:
- Singleton rate: 74% -> <= 60%
- Files >5s in sample: 2 -> 0
- Outlier max runtime: 34.6s -> <10s

---

## 7. Case Study Additions from This Uplift

Added case studies:

- `casestudies/decode-budget-exhaustion-c2d0d7e2/`
- `casestudies/decompression-bomb-font-flood-b509f6c9/`
- `casestudies/connectwise-filter-obfuscation-9ab20ec2/`

Each case study now has:
- committed fixture under `crates/sis-pdf-core/tests/fixtures/corpus_captured/`
- manifest registration with provenance and regression targets
- dedicated regression test function in `corpus_captured_regressions.rs`
- metadata and narrative analysis documenting exploit vectors and chain gaps
