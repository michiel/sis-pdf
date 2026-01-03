# Gaps Plan: Payload Coverage Improvements

This plan addresses detection gaps observed in the sample collections and adds concrete detection and regression coverage.

---

## 1) URI action detection in annotations

**Gap**
- Payloads with `/URI` actions in annotations did not trigger `uri_present`.

**Implementation**
- `crates/sis-pdf-detectors/src/lib.rs`
  - Extend `UriDetector` to scan `/A` and `/AA` dictionaries in annotations.
  - Follow indirect references from annotation dictionaries to action dictionaries.
  - Attach evidence spans for the action dictionary and the `/URI` value.
- `crates/sis-pdf-core/src/report.rs`
  - Include action targets in metadata for URI actions when available.

**Tests**
- Add a fixture with `/Annot` + `/A` + `/URI` action.
- Assert `uri_present` fires with evidence.

---

## 2) FontMatrix JavaScript injection detection

**Gap**
- `payload8.pdf` uses a FontMatrix JavaScript payload that does not trigger findings.

**Implementation**
- `crates/sis-pdf-detectors/src/lib.rs`
  - Add a detector for suspicious `/FontMatrix` entries containing non-numeric tokens.
  - Flag strings or names inside `/FontMatrix` arrays.
  - Provide evidence for the font dictionary span.
- `crates/sis-pdf-core/src/report.rs`
  - Add an impact statement for `fontmatrix_payload_present`.

**Tests**
- Add a fixture with `/FontMatrix` containing a literal string.
- Assert `fontmatrix_payload_present` is emitted.

---

## 3) Content-only XSS heuristics (optional)

**Gap**
- XSS payloads as visible text do not trigger findings.

**Implementation**
- `crates/sis-pdf-detectors/src/content_phishing.rs`
  - Add an optional heuristic for HTML-like tags or `javascript:` in visible text.
  - Keep severity low and mark confidence as heuristic.
- `crates/sis-pdf-core/src/report.rs`
  - Add impact text for `content_html_payload`.

**Tests**
- Add a fixture with visible `<script>` content and assert the heuristic finding.

---

## 4) Regression coverage for known payload sets

**Gap**
- No automated regression tests for the external payload collections.

**Implementation**
- `crates/sis-pdf-core/tests/regression_payloads.rs` (new)
  - Add optional tests that run only when fixtures are present.
  - Use environment flags to skip when collections are absent.

**Acceptance**
- Gaps are covered by targeted detectors and tests.
- Strict/deep scans produce stable findings with evidence spans.
