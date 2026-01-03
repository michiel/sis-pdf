# Roadmap 003: Operational Maturity and Advanced Analysis

This roadmap focuses on operational readiness, richer analysis output, and deeper PDF behaviour modelling. Each section includes scope, implementation steps, and acceptance criteria.

---

## 1) Content index and layout-aware reporting

**Scope**
- Expand content analysis into a structured index for pages, text blocks, and image regions.
- Improve reporting with page-aware context and visual coordinates.

**Implementation**
- `crates/sis-pdf-pdf/src/content.rs`
  - Extend tokenisation to include numeric operands and inline content arguments.
  - Track simple text positioning (`Td`, `Tm`) to attach approximate coordinates.
- `crates/sis-pdf-core/src/content_index.rs` (new)
  - Build a per-page index: text bounding boxes, image bounding boxes, and clip regions.
  - Store coordinates in a normalised page space (0..1) for portability.
- `crates/sis-pdf-detectors/src/content_phishing.rs` (new)
  - Refine deception heuristics using bounding boxes and overlap calculations.
- `crates/sis-pdf-core/src/report.rs`
  - Include page numbers and coordinates in findings where available.

**Acceptance**
- Findings include page references for content-based alerts.
- Report shows at least one coordinate hint for image-only and overlay cases.

---

## 2) Enhanced reachability modelling

**Scope**
- Model trigger-to-action-to-payload chains with depth control and action type awareness.

**Implementation**
- `crates/sis-pdf-core/src/graph_walk.rs`
  - Add edge labels for action types and payload references.
  - Provide a function to return a traced path for each reachable object.
- `crates/sis-pdf-core/src/chain_synth.rs`
  - Enrich chain synthesis with explicit action steps and payload types.
- `crates/sis-pdf-core/src/report.rs`
  - Render multi-step chains and indicate which steps were inferred.

**Acceptance**
- Findings show a chain with action transitions for OpenAction and Additional Actions.
- Report uses consistent wording across chain types.

---

## 3) Parser resilience and strict mode tuning

**Scope**
- Improve strict parser fidelity and reduce false positives.

**Implementation**
- `crates/sis-pdf-pdf/src/parser.rs`
  - Add explicit deviation types for invalid escape sequences and truncated streams.
  - Capture offsets for partial object reads.
- `crates/sis-pdf-detectors/src/strict.rs` (new)
  - Map deviation types to severity with richer remediation guidance.
- `crates/sis-pdf-core/src/report.rs`
  - Group strict deviations under a dedicated section in Markdown reports.

**Acceptance**
- Strict deviations appear with stable IDs and consistent severity.
- Report contains a dedicated section for strict parse anomalies.

---

## 4) YARA and SARIF enrichment

**Scope**
- Provide more metadata in YARA and SARIF outputs for traceability.

**Implementation**
- `crates/sis-pdf-core/src/yara.rs`
  - Add optional metadata fields for action type, payload type, and confidence.
- `crates/sis-pdf-core/src/report.rs`
  - Include evidence origin spans for decoded evidence in SARIF.
- `crates/sis-pdf-core/src/sarif.rs` (new or split from report)
  - Separate SARIF generation to a dedicated module for maintainability.

**Acceptance**
- SARIF includes decoded evidence origins when present.
- YARA rules include consistent metadata and tags for action findings.

---

## 5) Batch scanning and profiling

**Scope**
- Allow scanning a directory of PDFs with summarised output.

**Implementation**
- `crates/sis-pdf/src/main.rs`
  - Add `sis scan --path DIR` and `--glob` options.
  - Aggregate results into a summary report.
- `crates/sis-pdf-core/src/report.rs`
  - Add a batch summary renderer with per-file totals.

**Acceptance**
- Batch scan prints a concise summary and optional JSON output.
- Report includes per-file totals and top findings.

---

## 6) Fixtures and regression coverage

**Scope**
- Grow the fixture set and regression tests for newly added detection logic.

**Implementation**
- `crates/sis-pdf-core/tests/fixtures/`
  - Add fixtures for signatures, encryption, and ObjStm embedded actions.
- `crates/sis-pdf-core/tests/golden.rs`
  - Extend assertions to cover new detectors and strict deviations.

**Acceptance**
- New fixtures exercise strict parsing, crypto detections, and reachability.
- Tests confirm findings are stable and evidence spans are present.
