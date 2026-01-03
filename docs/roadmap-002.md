# Roadmap 002: Next-Phase Enhancements

This plan extends the current ysnp roadmap with deeper content analysis, true reachability, strict parsing, and secondary-parser differentials. Each section includes scope, concrete implementation steps, and acceptance criteria.

---

## 1) Content stream parsing and deception heuristics

**Scope**
- Parse page content streams and detect deceptive layouts: link overlays, invisible text, image-only pages, and full-page button traps.

**Implementation**
- `crates/ysnp-pdf/src/content.rs` (new)
  - Implement a minimal content stream parser:
    - Tokenise operators (`q`, `Q`, `cm`, `Do`, `BT`, `ET`, `Tf`, `Tj`, `TJ`, `Td`, `Tm`, `re`, `W`, `W*`, `gs`).
    - Track current transformation matrix (CTM) and text state for bounding boxes.
  - Output `ContentOp` list with operator + operands + span.
- `crates/ysnp-core/src/content_index.rs` (new)
  - Index per-page:
    - Image placements (`Do` with `/XObject` image)
    - Text runs and bounding boxes
    - Path rectangles used as clip masks
- `crates/ysnp-detectors/src/content_phishing.rs` (new)
  - Heuristics:
    - Image-only page: large image coverage + low/no text.
    - Link overlays: annotation rectangles overlapping image/large text blocks.
    - Invisible text: text render mode or alpha/colour matching background.
- Add detector registration and evidence spans in `crates/ysnp-detectors/src/lib.rs`.

**Acceptance**
- Reports include `content_overlay_link`, `content_image_only_page`, `content_invisible_text` findings with evidence spans.

---

## 2) True reachability graph (trigger → action → payload)

**Scope**
- Replace naive `focus_trigger` filtering with actual graph traversal from trigger objects.

**Implementation**
- `crates/ysnp-core/src/graph_walk.rs` (new)
  - Build adjacency from dict keys and indirect refs.
  - Provide `reachable_from(refs: &[ObjRef]) -> HashSet<ObjRef>`.
- `crates/ysnp-core/src/runner.rs`
  - When `focus_trigger` is set, resolve trigger objects to ObjRefs, then run detectors only on reachable objects.
  - Add `--focus-depth` to limit traversal depth.
- `crates/ysnp-detectors/src/lib.rs`
  - Expose trigger object references for OpenAction and AA so `focus_trigger` can seed traversal.

**Acceptance**
- `ysnp scan --focus-trigger openaction` processes only reachable objects.
- Unit tests confirm reachability reduces object set while preserving trigger/action findings.

---

## 3) ObjStm deep parsing

**Scope**
- Decode object streams and parse embedded objects in deep mode.

**Implementation**
- `crates/ysnp-pdf/src/objstm.rs` (new)
  - Parse `/ObjStm` header, decode stream, parse object table, and build embedded objects.
  - Maintain origin spans back to stream bytes.
- `crates/ysnp-pdf/src/graph.rs`
  - When `deep` and `/ObjStm` present, expand embedded objects into graph with synthetic spans.
- `crates/ysnp-detectors/src/lib.rs`
  - Allow detectors to include embedded objects in scans.

**Acceptance**
- Deep scans surface actions embedded in ObjStm with evidence spans.

---

## 4) Strict parser mode (lexer-level deviations)

**Scope**
- Add strict parsing mode that records invalid tokens, malformed objects, and stream length anomalies.

**Implementation**
- `crates/ysnp-pdf/src/parser.rs`
  - Add `strict` flag to parser.
  - Capture deviations (unexpected delimiters, invalid names, invalid number forms, unterminated strings).
  - Emit a `Vec<Deviation>` with spans and types.
- `crates/ysnp-core/src/scan.rs`
  - Surface deviations in `ScanContext`.
- `crates/ysnp-detectors/src/strict.rs` (new)
  - Emit findings with deviation type, severity, and evidence.

**Acceptance**
- Strict mode produces deterministic deviation findings with exact spans.

---

## 5) Secondary parser integration (true differential)

**Scope**
- Compare ysnp parser output with an independent parser in test harness or optional runtime.

**Implementation**
- Choose a secondary parser:
  - Option A: `pdf-extract` or another Rust crate (parse only).
  - Option B: external tool invoked in test harness.
- `crates/ysnp-core/src/diff.rs`
  - Extend to accept external parse results (object count, xref offsets, action extraction).
- `crates/ysnp-cli/src/main.rs`
  - Add `--diff-parser=external` and `--diff-parser=internal` modes.

**Acceptance**
- Differences report in findings with clear evidence and secondary source name.

---

## 6) Signature/encryption analysis

**Scope**
- Surface DSS/LTV structures, signature fields, and encryption configuration risks.

**Implementation**
- `crates/ysnp-detectors/src/crypto.rs` (new)
  - Detect `/Sig`, `/DSS`, `/ByteRange`, `/Encrypt`.
  - Emit findings with algorithm metadata.
- `crates/ysnp-detectors/src/lib.rs`
  - Register crypto detectors.

**Acceptance**
- Reports include `signature_present`, `encryption_present`, and `dss_present`.

---

## 7) JS behaviour summary from AST

**Scope**
- Provide higher-level JS behaviour summaries (call sites, URLs, string literals).

**Implementation**
- `crates/ysnp-detectors/src/js_signals.rs`
  - If `js-ast` feature enabled:
    - Extract function calls (top 10)
    - Extract string literal URL-like values
    - Add `js.behaviour_summary` metadata
- `crates/ysnp-core/src/report.rs`
  - Render `js.behaviour_summary` under **Payload Behaviour**.

**Acceptance**
- JS findings include call/URL summaries when AST parsing succeeds.

---

## Execution order (recommended)
1) Content stream parsing + deception heuristics
2) True reachability graph
3) ObjStm deep parsing
4) Strict parser mode
5) Secondary parser integration
6) Signature/encryption analysis
7) JS behaviour summary from AST
