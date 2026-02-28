# Next Steps — Post Uplift + Consistency Review
**Date**: 2026-02-28
**Branch**: feature/consistency
**Prior plans**: 20260228-full-uplift-implementation.md (all stages complete),
  20260228-corpus-perf-chain-uplift.md (all items addressed)

---

## Completed This Session

| Commit | Change |
|---|---|
| 95c777e | COV-1: Suppress isolated image.decode_skipped (ImageAnalysisDetector post-processing) |
| c75effd | COV-5: `sis correlate findings` subcommand + --deep help text update |
| 6e834a4 | COV-6: EntropyClusteringDetector (Cost::Expensive, threshold=7.9) |
| 9dfdafa | Stage 7.2: Batch corpus fixture performance budget test |

Plus:
- `casestudies/` directory created with metadata.json + analysis.md for 6 deeply investigated fixtures
- `AGENTS.md` updated with Case Study Workflow section
- `intent.rs` fix: `decode.ratio` key lookup for `decompression_ratio_suspicious` (was checking `decompression.ratio`, now correctly reads `decode.ratio` from DecompressionRatioDetector)

---

## Open Items — Priority Order

### HIGH: Chain Architecture (98.8% Singleton Chains)

**Problem**: Phase 2 fallback makes every ungrouped finding its own chain. Object grouping
only works for exact same object ID — related findings in different objects are never grouped.
Result: `edges: []`, `chain_completeness: 0.0` for 97% of chains.

**Root cause locations**:
- `crates/sis-pdf-core/src/chain_synth.rs` — Phase 2 fallback at line ~400
- `crates/sis-pdf-core/src/chain_synth.rs` — `merge_singleton_clusters()` only handles
  exact-object singletons, not kind-prefix grouping

**Proposed approach (Tier A — kind-based)**:
1. In `merge_singleton_clusters()`, also group singletons whose findings share a common
   kind prefix (e.g., all `font.*` findings from the same surface → one cluster).
2. Add edge inference: if two findings share an object reference path in the event graph,
   synthesize an edge between them in the chain.
3. Target: reduce singleton rate from 98.8% to <50%.

**Test**: Add assertion to corpus regression tests that at least one chain in apt42 and
booking fixtures has `chain_completeness > 0.0` and `edges.len() > 0`.

---

### MEDIUM: `sis correlate campaign` Line Limit

**Problem**: `run_campaign_correlate` reads via `read_text_with_limit` with MAX_JSONL_BYTES
(100MB) but individual line processing uses hardcoded network-intent-only logic with
`MAX_CAMPAIGN_INTENT_LEN: usize = 1024`. Rich findings lines (up to 1MB each) are silently
dropped when URL is empty or > 1024 chars.

**Fix**: Already partially addressed by COV-5 (`sis correlate findings`). The remaining
issue is that `campaign` correlator doesn't use the same generous line limit as the findings
correlator. Low urgency since COV-5 provides the richer path.

---

### MEDIUM: `sis query <pdf> chains` Returns Empty

**Problem**: `sis query <pdf> chains` returns 0 chains because the query command re-parses
the PDF but doesn't run the scan pipeline. Chains are synthesized at scan time and not
persisted.

**Fix options**:
1. Have `query chains` trigger a scan internally (simpler, slower).
2. Persist chains to a sidecar file at scan time (complex).

**Decision**: Deferred. Document in USAGE.md that chains require `sis scan --json` output.

---

### LOW: Additional Corpus Fixtures

PDFs known from corpus analysis that are not yet fixtures:

| SHA prefix | Family | Notes |
|---|---|---|
| fog-netlify | netlify-phishing | `/Pay` URL pattern, fog campaign |
| decompression-bomb | dos-decompression | 485:1 ratio, parser exhaustion |

For each: capture to `tests/fixtures/corpus_captured/`, register in manifest.json,
add regression test in corpus_captured_regressions.rs, add case study in casestudies/.

---

### LOW: casestudies/ PDF References

Current casestudies/ entries reference PDFs via `fixture_path` field in metadata.json.
If offline deep analysis is needed, create symlinks:

```bash
cd casestudies/<slug>
ln -rs ../../crates/sis-pdf-core/tests/fixtures/corpus_captured/<filename>.pdf sample.pdf
git add sample.pdf  # git tracks symlinks
```

This keeps a single copy of the binary while providing a local reference in each case study.

---

### LOW: `--fast` / `--deep` help text in scan batch mode

The `deep` argument in the batch scan struct (line ~270 in main.rs) has no `help` annotation.
Add: `#[arg(long, help = "Enable deep analysis (expensive detectors: full font scan, entropy clustering, XFA script extraction)")]`

---

## casestudies/ Directory Plan

**Status**: Created (6 entries)

**Structure**:
```
casestudies/
  README.md                         # index table
  apt42-polyglot-pdf-zip-pe/
    metadata.json
    analysis.md
  booking-js-phishing/
    metadata.json
    analysis.md
  modern-gated-supplychain/
    metadata.json
    analysis.md
  modern-openaction-staged/
    metadata.json
    analysis.md
  modern-renderer-revision/
    metadata.json
    analysis.md
  romcom-embedded-payload/
    metadata.json
    analysis.md
```

**Workflow for new entries**: See AGENTS.md "Case Study Workflow" section.

---

## Verification Commands

```bash
# Run all corpus regression tests (includes new COV-1/6 tests)
cargo test -p sis-pdf-core --test corpus_captured_regressions

# Run CLI integration tests (includes COV-5 correlate findings test)
cargo test -p sis-pdf --test cli_integration

# Run batch performance test
cargo test -p sis-pdf-core --test performance_fixtures -- batch_of_corpus_fixtures

# Run detector lib tests
cargo test -p sis-pdf-detectors --lib

# Smoke test casestudies correlate workflow
sis scan casestudies/apt42-polyglot-pdf-zip-pe/sample.pdf --deep --json | jq .verdict
```

---

## Status Legend
- ✅ Complete
- 🔄 In progress
- 📋 Planned
- ⏸ Deferred

| Item | Status |
|---|---|
| COV-1: decode_skipped suppression | ✅ |
| COV-5: correlate findings CLI | ✅ |
| COV-6: entropy clustering detector | ✅ |
| Stage 7.2: batch perf test | ✅ |
| intent.rs decode.ratio key fix | ✅ |
| casestudies/ directory (6 entries) | ✅ |
| AGENTS.md case study workflow | ✅ |
| Chain architecture: singleton reduction | 📋 |
| correlate campaign line limit | ⏸ |
| query chains without scan | ⏸ |
| fog-netlify fixture capture | 📋 |
| decompression-bomb fixture capture | 📋 |
