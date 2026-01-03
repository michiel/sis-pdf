# Intent Classifier Plan

This plan adds intent inference on top of existing detections. It is designed to integrate with current parsing, evidence, metadata, and reporting flows without breaking existing outputs.

---

## Goals

- Infer high-level intent buckets (exfiltration, execution, phishing, persistence, evasion) using multiple signals, not just JS call graphs.
- Reuse existing detectors, evidence spans, and metadata to avoid duplicate scanning.
- Surface intent in reports, JSON, SARIF, and YARA metadata without changing the current schema.

---

## Intent Buckets (Comprehensive)

### 1) Data Exfiltration
Signals:
- Actions: `submitform_present`, `uri_present`, `gotor_present` with external destinations.
- JS APIs: `submitForm`, `getURL`, `app.launchURL`, `app.mailMsg`, `exportDataObject`.
- Strings: `http://`, `https://`, `mailto:`, `ftp://`, `data:`.
- Form data usage or embedded file export targets.

### 2) Sandbox Escape / External Execution
Signals:
- Actions: `launch_action_present`, `open_action_present` + JS payload.
- JS APIs: `app.openDoc`, `app.launchURL` with `file://` or shell-like strings, `util.readFileIntoStream`, `app.execMenuItem` (if available).
- Strings: `cmd.exe`, `powershell`, `/C/Windows`, `.exe`, `.bat`, `.ps1`, `file:///`.

### 3) Phishing / UI Deception
Signals:
- Content heuristics: `content_image_only_page`, `content_overlay_link`, `content_invisible_text`, `content_phishing`, `content_html_payload`.
- JS APIs: `app.alert`, `app.response`, `util.printf`, DOM/HTML strings.
- Annotation text with HTML/script-like payloads.

### 4) Persistence / Dropper Behaviour
Signals:
- Embedded files: `embedded_file_present`, `filespec_present`.
- JS APIs: `exportDataObject`, `importDataObject`, `app.launchURL` with local file targets.
- Evidence of executable or script payloads from embedded file metadata.

### 5) Obfuscation / Evasion
Signals:
- JS signals: `js.obfuscation_suspected`, `js.contains_eval`, `js.contains_unescape`, `js.contains_fromcharcode`, entropy > threshold.
- Structural anomalies: `xref_conflict`, `incremental_update_chain`, `object_id_shadowing`, `objstm_density_high`, strict deviations.

### 6) Exploit Primitive / Parser Differential
Signals:
- Differential parsing: `parser_object_count_diff`, `parser_trailer_count_diff`.
- FontMatrix injection: `fontmatrix_payload_present`.
- Decoder risks: `decoder_risk_present`, `decompression_ratio_suspicious`, `huge_image_dimensions`.

---

## Inputs and Integration Points

### Data Sources
- Existing `Finding` entries and their `meta`:
  - `action.*`, `payload.*`, `js.*`, `content.*`, `embedded.*`.
- Evidence spans for action targets and payload previews.
- Content index metadata (page number + coords).

### Where to implement
- `crates/ysnp-core/src/intent.rs` (new)
  - Build intent signals from findings and optional AST summaries.
  - Generate intent scores and confidence levels.
- `crates/ysnp-core/src/report.rs`
  - Render **Intent Summary** at the top of reports.
  - Attach per-finding intent metadata (non-breaking, in `meta` only).
- `crates/ysnp-core/src/yara.rs`
  - Add intent tags to YARA metadata if present.
- `crates/ysnp-core/src/sarif.rs`
  - Add intent info under `properties` if present.

---

## Implementation Plan

### 1) Intent signal extraction
- Add `IntentSignal` enum and `IntentBucket` model.
- Build mapping of findings → signals using `kind` and `meta`.
- Use `js.behaviour_summary` and `payload.preview` when present.
- Detect URI intent using `action.target` and decoded payloads.

### 2) Scoring model
- Each bucket gets a weighted score:
  - High-confidence signals (explicit API call or action) weight 3.
  - Medium signals (strings, content heuristics) weight 2.
  - Low signals (structural anomalies) weight 1.
- Produce bucket confidence: `Strong` if score >= 6, `Probable` if >= 3, else `Heuristic`.
- Track contributing finding IDs and evidence spans.

### 3) Metadata integration
- For findings with strong intent overlap, add `intent.bucket` and `intent.confidence` to `meta`.
- For report-level summary, emit:
  - Per-bucket score, confidence, and top contributing findings.

### 4) Report output
- Add **Intent Summary** section in `render_markdown`:
  - List buckets sorted by score.
  - Show confidence and top evidence notes.
- Add to JSON output as an optional `intent_summary` field in the report.

### 5) YARA and SARIF
- Add intent bucket tags in YARA metadata:
  - `intent_bucket`, `intent_confidence`.
- Add `intent` in SARIF `properties` for affected findings.

### 6) Tests and fixtures
- Add tests under `crates/ysnp-core/tests/intent.rs` with fixtures that exercise:
  - Exfiltration (URI + submitForm)
  - Sandbox escape (launch + file path)
  - Phishing (content overlay + JS alert)
  - Obfuscation (eval + high entropy)
- Use existing fixtures where possible to avoid duplication.

---

## Acceptance Criteria

- Intent summary appears in Markdown reports and JSON output.
- Each bucket has at least one deterministic test.
- Intent metadata appears in SARIF and YARA outputs when applicable.
- No breaking changes to existing schema; intent fields are additive.
