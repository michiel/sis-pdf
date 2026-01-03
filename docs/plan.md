# ysnp Implementation Plan

This plan covers the remaining items from the spec and the full roadmap in `docs/roadmap.md`. It is ordered by impact and dependency chain, and includes concrete technical changes per crate.

## Guiding principles
- Preserve deterministic output and stable finding IDs.
- Always attach evidence spans; for decoded data, include `origin` spans to raw stream bytes.
- Keep triage scans fast; gate expensive decoding behind `--deep` or targeted focus.

---

## Phase 1 — Detection quality and coverage

### Issue tickets (Phase 1)

1) JS stream decode + metadata
   - Implement filter decode with predictors for `/JS` stream payloads
   - Add decoded evidence spans with `origin` mapping
   - Add JS signal extraction from decoded bytes

2) Action payload resolution
   - Resolve `/URI`, `/F`, `/Launch`, `/GoToR`, `/SubmitForm` payload refs
   - Attach payload metadata and evidence spans

3) Action surface expansion
   - Add detectors for RichMedia/3D/Sound/Movie/Rendition/Filespec/AF/XFA/AcroForm/OCG
   - Add name-tree traversal helpers

4) Annotation/form event coverage
   - Enumerate AA event keys across catalog/page/field
   - Emit event-path findings with evidence

### 1) Decode filtered `/JS` streams (major coverage win)

**Scope**
- Decode filter chains for stream-based `/JS` objects (Flate/LZW/ASCII85/RunLength; add predictors when present).
- Apply size/budget caps for decoded data.
- Attach metadata and JS signals to findings.

**Implementation**
- `crates/ysnp-pdf/src/decode.rs`
  - Add predictor handling (PNG predictor and TIFF predictor) based on `/DecodeParms`.
  - Expose `decode_stream_with_parms(...) -> DecodedStream` returning filters, decoded length, decode ratio, and error status.
- `crates/ysnp-pdf/src/object.rs`
  - Extend `PdfStream` to carry optional `decode_parms` parsed from the dict (as raw `PdfObj` list for now).
- `crates/ysnp-detectors/src/lib.rs`
  - In `JavaScriptDetector`, resolve `/JS` to inline string or stream. For stream, run decode and feed decoded bytes to JS signals.
  - Add meta fields:
    - `js.stream.filters`, `js.stream.decoded`, `js.stream.decode_error`
    - `js.decoded_len`, `js.decode_ratio`
- `crates/ysnp-core/src/model.rs`
  - Add `meta: HashMap<String, String>` to `Finding` (optional). If not adding to model, add `description` details for JS signals.

**Acceptance**
- `/JS` from string, stream, or ref is decoded with budget caps.
- Findings show decoded evidence with `EvidenceSource::Decoded` and `origin` from raw stream span.

---

### 2) Resolve action payloads for `/URI`, `/F`, `/Launch`, `/GoToR`, `/SubmitForm`

**Scope**
- Resolve target payloads (string/stream/ref) and attach safe previews.

**Implementation**
- `crates/ysnp-detectors/src/lib.rs`
  - Add a shared resolver helper:
    - `resolve_payload(graph, bytes, obj) -> PayloadInfo` where `PayloadInfo` includes type, bytes, decoded length, and ref chain.
  - In each action detector, attach meta:
    - `payload.type`, `payload.decoded_len`, `payload.ref_chain` (bounded), and preview note.
  - Update evidence spans:
    - Add decoded evidence span for resolved payload bytes; include `origin` when derived from a stream.

**Acceptance**
- Action findings include payload metadata and evidence when payloads are resolved.

---

### 3) Expand action surface coverage

**Scope**
- Add detectors for: `/RichMedia`, `/3D`/`/U3D`/`/PRC`, `/Sound`, `/Movie`, `/Rendition`, `/EmbeddedFile` + `/Filespec` + `/AF`, `/XFA`, `/AcroForm`, `/OCG` triggers.

**Implementation**
- `crates/ysnp-detectors/src/lib.rs`
  - Add new detector structs per action family.
  - Reuse a common helper for finding name keys in dicts and name trees.
- `crates/ysnp-pdf/src/parser.rs`
  - Ensure name tree parsing support (names dictionaries are already parsed as dicts; add traversal helpers).

**Acceptance**
- Findings emitted for each of the above action classes with correct surface classification and evidence spans.

---

### 4) Annotation + form event completeness

**Scope**
- Enumerate additional event keys on annotations, form fields, and document catalog AA.

**Implementation**
- `crates/ysnp-detectors/src/lib.rs`
  - Add an `AAEventDetector` that scans for `/AA` dictionaries and enumerates standard event keys.
  - Emit findings with event path (e.g., `Catalog.AA.O`) in `description` or `meta`.

**Acceptance**
- Event coverage includes document, page, and form AA key sets.

---

## Phase 2 — Exploit chain synthesis maturity

### Issue tickets (Phase 2)

5) Chain model + synthesis
   - Implement `ExploitChain` + builder + template clustering
   - Export chain templates + instances in report

6) Chain scoring improvements
   - Add scoring factors and explainable reasons
   - Extend JS signal set for obfuscation

7) Chain path reconstruction + export
   - Emit canonical chain path text
   - Export per-chain subgraphs (DOT/JSON)

### 5) Chain clustering & de-dup

**Scope**
- Cluster chains that share the same trigger/action/payload.

**Implementation**
- `crates/ysnp-core/src/chain.rs` (new)
  - Define `ExploitChain`, `ChainTemplate`, and cluster key.
- `crates/ysnp-core/src/chain_synth.rs` (new)
  - Build chains from detectors, create templates, and output instance lists.
- `crates/ysnp-core/src/report.rs`
  - Extend report with `chains` and `chain_templates`.

**Acceptance**
- JSON output contains deduped chain templates and per-template instances.

---

### 6) Scoring improvements

**Scope**
- Add explainable scoring factors for triggers, action class severity, payload obfuscation, structural suspiciousness, exploitability.

**Implementation**
- `crates/ysnp-core/src/chain_score.rs` (new)
  - Implement a weighted scoring function with rationale strings.
- `crates/ysnp-detectors/src/lib.rs`
  - Expand JS signals to include `js.string_concat_density`, `js.escape_density`, `js.regex_packing`, `js.suspicious_apis`.
- `crates/ysnp-core/src/report.rs`
  - Surface scoring reasons in output.

**Acceptance**
- Chain scores are deterministic and include a list of reasons.

---

### 7) Path-to-payload reconstruction

**Scope**
- Build canonical chain paths and export per-chain subgraphs.

**Implementation**
- `crates/ysnp-core/src/chain_render.rs` (new)
  - Render canonical chain path text.
- `crates/ysnp-core/src/graph_export.rs` (new)
  - Export chain subgraphs to DOT and JSON.
- CLI support: `ysnp export-graph --chains-only`.

**Acceptance**
- Stable chain path string emitted per chain; optional graph export works.

---

## Phase 3 — Malformation and parser differential analysis

### Issue tickets (Phase 3)

8) Strict parse deviation findings
   - Strict-mode parser
   - Deviation catalogue + findings with spans

9) Cross-parser differential mode
   - Secondary parser integration (test harness only)
   - Diff reporting

### 8) Strict grammar validation

**Scope**
- Implement strict parsing mode; record deviations as findings.

**Implementation**
- `crates/ysnp-pdf/src/parser.rs`
  - Add strict mode flag that records invalid constructs.
- `crates/ysnp-detectors/src/lib.rs`
  - Add `strict_parse_deviation` detector that emits findings with byte spans.

**Acceptance**
- Deviations are reported with precise spans and classification.

---

### 9) Cross-parser differential mode

**Scope**
- Compare ysnp parse results with a second parser or external tool (test harness only).

**Implementation**
- `crates/ysnp-cli/src/main.rs`
  - Add `--diff-parser` flag to run comparison if available.
- `crates/ysnp-core/src/diff.rs` (new)
  - Compare object counts, refs, stream decode results, action extraction results.

**Acceptance**
- Emit findings when parser outputs diverge.

---

## Phase 4 — Payload intelligence without execution

### Issue tickets (Phase 4)

10) JS feature extraction
    - Token-level stats + suspicious API signatures
    - Optional AST parse-only support

11) Embedded file triage
    - Magic bytes + hashes + container flags
    - Attach metadata to embedded findings

### 10) Static JS feature extraction

**Scope**
- Token-level stats, suspicious API signatures, optional parse-only AST extraction.

**Implementation**
- `crates/ysnp-detectors/src/js_signals.rs` (new)
  - Add token stats, entropy, escape density, API matchers.
- Optional feature flag for AST parsing (Boa parse-only).

**Acceptance**
- JS findings include richer metadata and obfuscation indicators.

---

### 11) Embedded file triage

**Scope**
- Magic bytes, hashes, compression ratios, double extensions, encrypted containers.

**Implementation**
- `crates/ysnp-detectors/src/embedded.rs` (new)
  - Add file type detection and SHA256.
- `crates/ysnp-cli/src/main.rs`
  - Emit hashes on `extract embedded`.

**Acceptance**
- Embedded file findings include type, size, hash, and risk flags.

---

## Phase 5 — Performance, UX, and interactive workflows

### Issue tickets (Phase 5)

12) Multi-stage scan pipeline
    - Fast pre-scan + targeted deep scan + full scan
    - Deterministic parallel traversal

13) Output formats + integrations
    - JSONL + SARIF + graph export
    - CLI flags and docs

14) Configurable rules and profiles
    - YAML config loader
    - Profiles: interactive/ci/forensics

### 12) Interactive mode performance

**Scope**
- Multi-stage pipeline (fast pre-scan, targeted deep scan, full scan), caching, deterministic parallel traversal.

**Implementation**
- `crates/ysnp-core/src/scan.rs`
  - Add scan stages with object reachability analysis.
- `crates/ysnp-pdf/src/graph.rs`
  - Add name tree cache and object reachability index.
- `crates/ysnp-core/src/runner.rs`
  - Execute detectors by stage and cost.

**Acceptance**
- `ysnp scan --fast` finishes without decoding streams.
- `ysnp scan --focus trigger=openaction` limits to reachable objects.

---

### 13) Output formats and integrations

**Scope**
- JSONL, SARIF, triage summary, graph export.

**Implementation**
- `crates/ysnp-core/src/report.rs`
  - Add JSONL stream writer and SARIF serializer.
- CLI:
  - `--jsonl`, `--sarif`, `export-graph`.

**Acceptance**
- Reports validate against SARIF schema and are deterministic.

---

### 14) Rule system / configuration

**Scope**
- YAML-based tuning, profiles, allow/deny lists, budgets.

**Implementation**
- `crates/ysnp-core/src/config.rs` (new)
  - Load profiles `interactive`, `ci`, `forensics`.
- CLI:
  - `--config`, `--profile`.

**Acceptance**
- Scans respect configured limits and scoring weights.

---

## Phase 6 — Hardening & test strategy

### Issue tickets (Phase 6)

15) Corpus + regression harness
    - Golden tests
    - Fuzzing targets
    - Benchmarks

16) Safety rails + taint tracking
    - Global budgets
    - Taint propagation to chain scoring

---

## Progress checklist

- [x] Phase 1 — Detection quality and coverage
  - [x] 1) JS stream decode + metadata
    - [x] Add predictor-aware filter decode
    - [x] Attach decoded evidence spans with origin mapping
    - [x] Feed decoded bytes into JS signals
  - [x] 2) Action payload resolution
    - [x] Resolver helper for string/stream/ref payloads
    - [x] Payload metadata + evidence spans in action findings
  - [x] 3) Action surface expansion
    - [x] RichMedia/3D/Sound/Movie/Rendition detectors
    - [x] Filespec/AF/EmbeddedFile expansion
    - [x] XFA/AcroForm/OCG detectors
  - [x] 4) Annotation/form event coverage
    - [x] AA event enumeration across catalog/page/field
    - [x] Event-path evidence and descriptions

- [x] Phase 2 — Exploit chain synthesis maturity
  - [x] 5) Chain model + synthesis
    - [x] Chain data types and synthesis pipeline
    - [x] Template clustering + instance lists
  - [x] 6) Chain scoring improvements
    - [x] Trigger/action severity weighting
    - [x] JS obfuscation signal integration
    - [x] Structural suspiciousness factors
  - [x] 7) Chain path reconstruction + export
    - [x] Canonical path rendering
    - [x] Chain subgraph export (DOT/JSON)

- [x] Phase 3 — Malformation and parser differential analysis
  - [x] 8) Strict parse deviation findings
    - [x] Strict parser mode and deviation capture
    - [x] Deviation findings with spans and classification
  - [x] 9) Cross-parser differential mode
    - [x] Secondary parser integration
    - [x] Diff findings and output

- [x] Phase 4 — Payload intelligence without execution
  - [x] 10) JS feature extraction
    - [x] Token stats + entropy + API signatures
    - [x] Optional AST parse-only support
  - [x] 11) Embedded file triage
    - [x] File magic + hash extraction
    - [x] Risk flags (double extensions, encrypted containers)

- [x] Phase 5 — Performance, UX, and interactive workflows
  - [x] 12) Multi-stage scan pipeline
    - [x] Fast pre-scan and reachability targeting
    - [x] Deterministic parallel detector execution
  - [x] 13) Output formats + integrations
    - [x] JSONL + SARIF output
    - [x] Graph export CLI
  - [x] 14) Configurable rules and profiles
    - [x] YAML config loader
    - [x] Profiles: interactive, ci, forensics

- [x] Phase 6 — Hardening & test strategy
  - [x] 15) Corpus + regression harness
    - [x] Golden test harness
    - [x] Fuzzing targets (lexer/xref/decoder)
    - [x] Benchmarks
  - [x] 16) Safety rails + taint tracking
    - [x] Global resource budgets
    - [x] Taint propagation to chain scoring

### 15) Corpus + regression harness

**Scope**
- Unit tests, golden tests, fuzzing, performance benchmarks.

**Implementation**
- `crates/ysnp-pdf/tests/` for xref/objstm edge cases.
- `tests/golden/` with expected JSON outputs.
- `fuzz/` using cargo-fuzz for tokenizer/xref/decoder.
- `benches/` with criterion.

**Acceptance**
- CI runs unit + golden tests; fuzzing in nightly job.

---

### 16) Safety rails

**Scope**
- Hard resource budgets and taint tracking.

**Implementation**
- `crates/ysnp-core/src/scan.rs`
  - Global caps: recursion depth, object count, total decoded bytes.
- `crates/ysnp-core/src/taint.rs` (new)
  - Propagate taint across chain scoring.

**Acceptance**
- Scans terminate safely under malicious inputs.

---

## Suggested execution order (next 5 milestones)

1. Decode filtered `/JS` streams + metadata + JS signals
2. Resolve action payload refs for `/URI`, `/F`, `/Launch`
3. Extend action/event coverage (AcroForm/XFA/AF/EmbeddedFile)
4. Chain de-dup + chain subgraph export
5. Strict parse deviation findings
