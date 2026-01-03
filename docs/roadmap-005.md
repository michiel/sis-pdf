# Roadmap 005: Deep Analysis and Cross-Signal Inference

This roadmap focuses on higher-fidelity analysis, stronger intent inference, and better cross-signal reasoning. Each section includes scope, implementation steps, and acceptance criteria.

---

## 1) Page tree resolution and annotation/action tracing

**Scope**
- Resolve page tree to map objects to page numbers, inherited resources, and MediaBox.
- Trace annotation actions with explicit object references for action chains.

**Implementation**
- `crates/sis-pdf-core/src/page_tree.rs` (new)
  - Traverse `/Pages` → `/Kids` recursively.
  - Track page index and inherited `/MediaBox`, `/Resources`.
- `crates/sis-pdf-core/src/content_index.rs`
  - Use page tree metadata instead of linear object scan.
- `crates/sis-pdf-detectors/src/lib.rs`
  - Add annotation parent object metadata where available.
- `crates/sis-pdf-core/src/chain_synth.rs`
  - Add action chain steps with object references (page → annot → action → payload).

**Acceptance**
- Content findings include stable page numbers and inherited MediaBox metadata.
- AA/Annot findings include parent page object references and an action sequence.

---

## 2) Evidence snapshotting for decoded payloads

**Scope**
- Provide short decoded previews tied to origin spans for high-value findings.

**Implementation**
- `crates/sis-pdf-core/src/evidence.rs` (new)
  - Add helpers to capture decoded previews with byte offsets and origin spans.
- `crates/sis-pdf-detectors/src/lib.rs`
  - Use snapshot helpers for JS, embedded files, and action payloads.
- `crates/sis-pdf-core/src/report.rs`
  - Render decoded previews under **Evidence** for decoded sources.
- `crates/sis-pdf-core/src/sarif.rs`
  - Include preview metadata in `properties` when present.

**Acceptance**
- Reports show decoded previews for JS and embedded payload findings.
- SARIF includes preview metadata without changing the base schema.

---

## 3) JS AST enrichment and argument summarisation

**Scope**
- Move beyond call names to capture arguments and URL/domain hints.

**Implementation**
- `crates/sis-pdf-detectors/src/js_signals.rs`
  - Extract call expressions with argument summaries (string literals, URLs).
  - Summarise domains and endpoint types in `js.behaviour_summary`.
- `crates/sis-pdf-core/src/intent.rs`
  - Use argument summaries for stronger exfiltration and escape signals.

**Acceptance**
- JS findings include URL/domain hints when AST parsing succeeds.
- Intent scoring increases confidence when arguments indicate network targets.

---

## 4) Cross-signal scoring and confidence tuning

**Scope**
- Improve intent inference by weighting signals based on correlation.

**Implementation**
- `crates/sis-pdf-core/src/intent.rs`
  - Add correlation boosts (e.g. action + JS + URI → higher score).
  - Reduce weight of isolated structural anomalies in intent buckets.
- `crates/sis-pdf-core/src/report.rs`
  - Include top contributing signals per bucket in **Intent Details**.

**Acceptance**
- Intent summaries align with expected outcomes in mixed-signal fixtures.
- Confidence improves for combined action + payload cases.

---

## 5) Differential parsing regression suite

**Scope**
- Add deterministic tests for parser differentials and exploit primitives.

**Implementation**
- `crates/sis-pdf-core/tests/diff.rs` (new)
  - Fixtures with known parser differentials.
  - Assertions for `parser_object_count_diff` and `parser_trailer_count_diff`.
- `crates/sis-pdf-core/src/diff.rs`
  - Expose a stable diff summary model for tests.

**Acceptance**
- Differential tests pass reliably and capture expected mismatches.
- Diff summary is stable across repeated runs.

---

## 6) Batch scan profiling and caching

**Scope**
- Improve batch throughput and consistency across large corpora.

**Implementation**
- `crates/sis-pdf-core/src/cache.rs` (new)
  - Cache decoded streams and intent summaries by file hash.
- `crates/sis-pdf/src/main.rs`
  - Add `--cache-dir` for batch scans.
  - Provide timing stats in batch summary.

**Acceptance**
- Batch scans support caching and output timing metadata.
- Large collections run faster on second pass with identical results.
