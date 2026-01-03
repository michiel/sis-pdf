# Roadmap 004: Precision Analysis and Operational Scaling

This roadmap targets higher-fidelity analysis, stronger evidence capture, and operational scalability. Each section contains scope, implementation steps, and acceptance criteria.

---

## 1) Page tree resolution and page-aware findings

**Scope**
- Resolve the page tree to derive stable page numbers and inherited properties.
- Attach page numbers to findings derived from page content or annotations.

**Implementation**
- `crates/ysnp-core/src/page_tree.rs` (new)
  - Parse `/Pages` and `/Kids` recursively.
  - Build a map of page object IDs to resolved page index and inherited `/MediaBox`.
- `crates/ysnp-core/src/content_index.rs`
  - Use page tree metadata instead of a linear object scan.
- `crates/ysnp-detectors/src/content_phishing.rs`
  - Attach page numbers from page tree map in `meta`.

**Acceptance**
- Page numbers match PDF page order for multi-page fixtures.
- Content findings always include `page.number` when available.

---

## 2) Annotation and action tracing

**Scope**
- Track annotation actions and build explicit action chains with references.

**Implementation**
- `crates/ysnp-core/src/graph_walk.rs`
  - Add helper to collect action edges from `/A`, `/AA`, `/OpenAction` and annotation dicts.
- `crates/ysnp-core/src/chain_synth.rs`
  - Build a chain variant that includes action dictionary IDs and payload refs.
- `crates/ysnp-core/src/report.rs`
  - Render action chain with object references and payload types.

**Acceptance**
- Findings show a multi-step action chain with object IDs.
- Annotation action findings include references to their parent page.

---

## 3) Stream extraction and evidence snapshotting

**Scope**
- Improve evidence capture with small inline previews for decoded streams.

**Implementation**
- `crates/ysnp-core/src/evidence.rs` (new)
  - Add helper to capture a short decoded preview and its origin span.
- `crates/ysnp-detectors/src/lib.rs`
  - Use snapshot helper in payload-based detectors.
- `crates/ysnp-core/src/report.rs`
  - Render decoded previews under **Evidence** for decoded sources.

**Acceptance**
- Reports show decoded previews for JS and embedded payload findings.
- SARIF includes origin spans and preview metadata.

---

## 4) Batch scanning exports and profiles

**Scope**
- Improve batch scanning output and allow per-profile overrides.

**Implementation**
- `crates/ysnp-cli/src/main.rs`
  - Add `--batch-out` for JSON summary output.
  - Add `--batch-format` for `json|md` in batch mode.
- `crates/ysnp-core/src/report.rs`
  - Add JSON schema-friendly batch summary.

**Acceptance**
- Batch scans can emit JSON without writing to stdout.
- Batch reports include summary and per-file totals.

---

## 5) Cross-parser differential tests

**Scope**
- Add regression tests that compare ysnp output with lopdf and enforce consistent deltas.

**Implementation**
- `crates/ysnp-core/tests/diff.rs` (new)
  - Add fixtures with deliberate parser differentials.
  - Assert `parser_object_count_diff` on known cases.
- `crates/ysnp-core/src/diff.rs`
  - Expose a stable diff summary object for testing.

**Acceptance**
- Differential tests pass and capture expected mismatches.
- Diff summary is stable across runs.

---

## 6) CLI output improvements

**Scope**
- Make CLI output more actionable for incident response.

**Implementation**
- `crates/ysnp-core/src/report.rs`
  - Add a "Top Risks" section summarising highest severity findings.
- `crates/ysnp-cli/src/main.rs`
  - Add `--summary-only` for minimal output.

**Acceptance**
- CLI output supports a concise summary mode.
- Reports highlight top risk findings without scrolling.
