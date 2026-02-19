# Detection Uplift Plan: Hidden/Obfuscated Content and Exploit Chain Quality

Date: 2026-02-19
Status: Proposed
Owner: Detection pipeline (`sis-pdf-detectors`, `sis-pdf-core`, docs)

## Implementation status update (2026-02-19)

- Completed: WS1 mixed-signal aggregation now accumulates JavaScript and HTML signals across `/V`, `/DV`, `/AP`, nested arrays/dicts/streams, and indirect refs without first-hit short-circuiting.
- Completed: WS5 initial regression expansion for distributed/fragmented scenarios:
  - split-signal test across `/V` (HTML) and `/AP` (JavaScript),
  - fragmented ref-chain test where a single form value aggregates indirect objects containing separate HTML and JavaScript fragments.
- Completed: WS2 precision tightening (initial):
  - `form_html_injection` now requires HTML-context indicators (tags/event attributes/context-break/protocol handlers) and no longer triggers on script-only DOM tokens by themselves.
  - integration and unit precision guards added for script-only values.
- Completed: WS3 normalisation uplift (initial):
  - Added bounded multi-layer payload normalisation (max 3 layers, max 64 KB) for form injection detection with decode passes for UTF-16/null padding, percent-encoding, JavaScript escapes (`\\xNN`, `\\uNNNN`), and HTML entities.
  - Added finding metadata when normalisation contributes (`injection.normalised=true`, `injection.decode_layers=<n>`).
  - Added confidence boost for JavaScript form injection when multi-layer decoding is required (`Probable` -> `Strong`).
  - Added regression fixtures for modern obfuscation styles, including fragmented multi-object payloads with double-encoded percent/entity wrappers and hex-string escaped JavaScript fragments.
- Completed: WS4 evidence/meta alignment (initial):
  - Added source-key metadata for form injection findings (`injection.sources=/V,/DV,/AP` as applicable).
  - Updated form injection evidence anchoring to prefer actual triggering sources (`/AP`, `/V`, `/DV`) instead of fixed fallback markers.
  - Added regression assertions for source metadata on split-field detections.
  - Updated `docs/findings.md` entries for `pdfjs_form_injection` and `form_html_injection` to document source metadata, normalisation metadata, confidence behaviour, and refined HTML-context pattern semantics.
- Completed: WS3 action-parameter normalisation (initial):
  - Action payload enrichment now applies the same bounded normalisation utility and emits `injection.action_param_normalised=true` and `injection.decode_layers=<n>` when action targets are encoded/obfuscated.
  - Added `action.param.source` metadata to identify which action dictionary parameter carried the payload (e.g. `/F`, `/URI`).
  - Added integration fixture for obfuscated Launch `/F` target with multi-layer percent encoding and regression assertions for normalisation metadata.
- Completed: WS6 scattered payload detection (initial):
  - Added `scattered_payload_assembly` detector to identify form-linked payload fragments that are benign independently but malicious when assembled.
  - Added guarded fragment collection over `/V`, `/DV`, `/AP` reference chains with depth and size caps, plus metadata (`scatter.fragment_count`, `scatter.object_ids`, `injection.signal.*`, `chain.stage=decode`).
  - Added regression fixtures for distributed encoded payload assembly and benign fragmented controls.
  - Documented `scattered_payload_assembly` in `docs/findings.md`.
- Completed: WS6 cross-stream payload bridge (initial):
  - Added `cross_stream_payload_assembly` detector that correlates JavaScript assembly behaviour (`fromCharCode`, split/join, concat) with reconstructed fragmented form payloads.
  - Added fromCharCode reconstruction matching and cross-object metadata (`js.object.ref`, `scatter.object_ids`, `injection.sources`).
  - Added integration fixture validating JavaScript/form fragment correlation and documented `cross_stream_payload_assembly` in `docs/findings.md`.
- Completed: CQ1 groundwork (partial):
  - Added stable chain metadata primitives to form and scatter findings:
    - `chain.stage`
    - `chain.capability`
    - `chain.trigger`
  - Added regression assertions to lock metadata shape for downstream chain-synthesis work.
- Completed: CQ2 deterministic edge synthesis (initial):
  - Added correlation-time edge composites for injection/action joins:
    - `form_html_injection -> pdfjs_form_injection`
    - `*_injection -> submitform_present`
    - `pdfjs_form_injection -> pdfjs_eval_path_risk`
    - `scattered_payload_assembly|cross_stream_payload_assembly -> *_injection`
    - `obfuscated_name_encoding -> action_*`
  - Added stable edge metadata on composites:
    - `edge.reason`
    - `edge.confidence`
    - `edge.from`, `edge.to`
    - `edge.shared_objects`
    - `edge.stage.from`, `edge.stage.to` (when available)
  - Added correlation regression coverage for scatter/injection/submitform and name-obfuscation/action bridge paths.
- Completed: WS3 PDF name obfuscation coverage (initial):
  - Added `obfuscated_name_encoding` detector using raw name token inspection for `#xx` hex-encoded security-relevant names.
  - Added integration tests for obfuscated `/JavaScript` name values and benign control coverage.
  - Documented `obfuscated_name_encoding` in `docs/findings.md`.
- Validation run:
  - `cargo test -p sis-pdf-detectors --test pdfjs_rendering_indicators`
  - `cargo test -p sis-pdf-detectors`
  - `cargo test -p sis-pdf-detectors contains_html_injection_rejects_`

## Goals

1. Implement all identified improvements from commit `004088a2a4e77400c025144caef518d14bb46b02` review.
2. Improve detection of hidden and obfuscated form payloads without materially increasing false positives.
3. Uplift event and chain quality so analysts can understand how disparate findings connect into exploitable paths.
4. Expand detection surface to cover embedded, hidden, obfuscated, distributed, and scattered exploit patterns beyond the form-field injection surface.

## Scope

In scope:
- `PdfjsRenderingIndicatorDetector` injection classification logic.
- HTML/JavaScript token heuristics for form payloads.
- Obfuscation-aware normalisation covering form field values and action dictionary parameters.
- PDF name encoding obfuscation (`#xx` sequences in PDF name tokens).
- Cross-object scattered payload detection via object graph traversal.
- Optional Content (OCG/OCMD) severity gating for hidden-layer findings.
- GoToR/GoToE action parameter inspection for suspicious remote targets.
- AcroForm calculated-field action (`/AA` per-field) detection.
- Evidence/meta/detail fidelity for field-level triggers.
- Integration, regression, and precision tests.
- Finding-chain correlation metadata and explainability details, built on top of the existing `chain_synth.rs` infrastructure.

Out of scope (this plan):
- New sandbox execution runtimes (the existing `js_sandbox.rs` multi-runtime profiles remain; no new runtimes are added here).
- Steganography (deep covert channel detection) — tracked separately.
- SWF bytecode-level analysis — tracked separately.
- XFA field-level obfuscation normalisation — WS3 utility is designed to be callable from `xfa_forms.rs` in a follow-up; XFA field decoding is deferred.

## Workstreams

## WS1: Correct mixed-signal aggregation across fields and nested objects

Problem:
- Current logic can short-circuit on first match (`or`, `find_map`) and lose combined JavaScript+HTML signal when payloads are split across `/V`, `/DV`, `/AP`, refs, arrays, or dict branches.

Implementation:
- Replace `Option<InjectionType>` first-hit traversal with accumulative detection state:
  - `has_js: bool`
  - `has_html: bool`
- Update object traversal helper to scan all reachable branches within depth limit, not first match only.
- Merge field-level outcomes from `/V`, `/DV`, `/AP` with OR semantics on booleans, then map to final type.
- Preserve bounded recursion (`depth < 8`) and no-panic behaviour.

Deliverables:
- Refactored helper API (e.g. `InjectionSignals` struct or tuple).
- Updated detector logic for form objects.

Acceptance criteria:
- A form object with HTML in `/V` and JS in `/AP` emits both relevant findings.
- A form object with split signals via indirect refs still emits both findings.

## WS2: Refine HTML detection precision and confidence policy

Problem:
- Current HTML detector includes generic JS/DOM tokens that can over-trigger (`document.`, `window.`, `eval(`).

Implementation:
- Re-balance token groups:
  - `html_context`: tags, event attributes, context-break sequences, HTML/protocol vectors.
  - `generic_script`: JS/DOM-only markers.
- Require at least one `html_context` marker to classify `form_html_injection`.
- Optionally add metadata counters per group (`html_context_hits`, `script_only_hits`).
- Revisit confidence assignment:
  - Keep `Strong` only when HTML-context evidence exists.
  - Downgrade to `Probable` if only weak context combinations are present (if retained).

Deliverables:
- Updated `contains_html_injection_tokens` or split classifier helpers.
- Confidence logic tied to matched signal quality.

Acceptance criteria:
- Benign script-like text without HTML context does not emit `form_html_injection`.
- Existing high-signal HTML payload tests continue to pass.

## WS3: Add obfuscation-aware normalisation for hidden payload recovery

Problem:
- Form payload matching does not reuse existing normalisation/deobfuscation pipeline, reducing recall for UTF-16, null-padded, and encoded payloads.
- Action dictionary parameters (`/F`, `/URI`, `/JS` string values in Launch/SubmitForm/GoToR/GoToE) are not examined for encoding or obfuscation.
- PDF name tokens can carry `#xx` hex encoding (e.g. `/Jav#61script`) that some detectors see post-decode and cannot distinguish from a benign name.

Implementation:

**Normalisation utility (shared):**
- Create a shared normalisation utility callable from `PdfjsRenderingIndicatorDetector` and `xfa_forms.rs` (for future XFA extension).
- Apply decode passes in this fixed order, capping at 3 nested layers:
  1. UTF-16 / null-padding stripping
  2. Percent-encoding (`%3cscript%3e`)
  3. JavaScript hex/unicode escapes (`\x3c`, `\u003c`)
  4. HTML entities (`&lt;`, `&gt;`, `&#x3c;`, `&#60;`)
- Do not recurse further than 3 layers; record the layer count.
- Cap decoded output at 64 KB to prevent amplification abuse.
- Record normalisation metadata per matched field:
  - `injection.normalised=true`
  - `injection.decode_layers=<n>`
- Emit a confidence boost (e.g. `Probable` -> `Strong`) when more than one normalisation layer was required, as multi-layer encoding is a strong adversarial signal.

**Action parameter normalisation:**
- Apply the same normalisation pass to action dictionary target fields before existing classification logic:
  - Launch: `/F` (file specification string)
  - SubmitForm: `/F` (URL string)
  - GoToR: `/F` (file specification)
  - GoToE: `/F` (embedded file reference)
  - URI: `/URI` value
- Emit `injection.action_param_normalised=true` when a decode layer was applied.

**PDF name obfuscation detection:**
- The parser already decodes `#xx` sequences in names before detectors receive them. Add a pre-detection annotation pass that flags names where `#xx` sequences were present in the raw token (requires parser cooperation or a raw-name comparison path).
- Emit a standalone low-confidence finding `obfuscated_name_encoding` when any security-relevant name (action type, filter name, JS keyword) contained `#xx` encoding.
- Use this finding as a confidence booster for any co-located action or injection finding.

Deliverables:
- Shared normalisation utility used by JS and HTML injection checks and action parameter inspection.
- Guardrails on decode depth (max 3 layers) and output size (max 64 KB).
- `obfuscated_name_encoding` finding kind with documentation.

Acceptance criteria:
- Obfuscated fixture variants (percent, entity, JS-escape, UTF-16, null-padded) trigger expected findings.
- A payload requiring two or more decode layers receives a confidence boost.
- Action parameters with encoded targets emit `injection.action_param_normalised=true` in metadata.
- Runtime overhead remains within the Stage 0.5 SLO targets documented in `docs/performance.md` (parse <10 ms, detection <50 ms for the CVE fixture `crates/sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf`).

## WS4: Align evidence, metadata, and findings documentation

Problem:
- Detection source keys and emitted evidence/docs are partially misaligned.

Implementation:
- Emit source-key metadata for each matched object, e.g.:
  - `injection.sources=/V,/AP`
  - `injection.signal.js=true`
  - `injection.signal.html=true`
- Ensure evidence reflects actual triggering keys (not fixed `/V` when `/AP` triggered).
- For action parameter findings, include the parameter name that contained the encoded value (e.g. `action.param.source=/F`).
- Update `docs/findings.md` to document exact source fields, signal quality model, confidence logic, and the new `obfuscated_name_encoding` finding kind.

Deliverables:
- Meta enrichment for triage and query.
- Documentation update with exact semantics.

Acceptance criteria:
- Findings include enough metadata to explain why they fired and where.
- Documentation matches implementation behaviour.

## WS5: Regression and baseline test uplift

Note: WS5 tests for each workstream are written alongside that workstream's implementation — tests are expected to fail on the current behaviour before the fix and pass after. WS5 is not a separate phase; it is the testing discipline applied throughout WS1-WS6.

Implementation:
- Extend `crates/sis-pdf-detectors/tests/pdfjs_rendering_indicators.rs` with:
  - split-signal field tests (`/V` + `/AP`, `/DV` + ref)
  - obfuscated payload tests (UTF-16, percent, entity, JS-escape, null-padded)
  - multi-layer obfuscation tests (two or more decode layers)
  - precision guards (benign JS-like text, harmless HTML snippets)
  - action parameter encoding tests (Launch `/F`, SubmitForm URL)
- Add unit tests for classifier and normalisation helpers.
- Run targeted baseline workflow after each workstream:
  1. `cargo test -p sis-pdf-detectors --test pdfjs_rendering_indicators`
  2. Adjacent impacted suites in `sis-pdf-core` where finding metadata invariants are asserted.
  3. Runtime profile for the CVE fixture: `sis scan crates/sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf --deep --runtime-profile --runtime-profile-format json`
- Capture deltas (new findings, severity/confidence shifts, timing changes) in this plan after each workstream lands.

Acceptance criteria:
- New tests fail on current behaviour and pass with uplift.
- No regression in existing detector suites.
- Runtime profile shows no throughput regression outside SLO bounds in `docs/performance.md`.

## WS6: Cross-object scattered payload detection

Problem:
- Current detectors operate per-object. A payload deliberately fragmented across multiple objects — form fields, annotation `/Contents` values, stream fragments, or indirect-reference chains — does not trigger any individual finding because each fragment appears benign in isolation.
- This is qualitatively different from the intra-object field splitting in WS1; it requires a multi-object graph traversal pass.

Background:
- Scattered payloads can be assembled at render time by JavaScript via `String.fromCharCode`, array-join patterns, or dictionary-walk accumulation. The `js-analysis` crate can already identify these patterns in isolated JavaScript; the missing piece is tracing source values back to PDF object origins.

Implementation:
- Add a graph-walk pass in `sis-pdf-core` (post-parse, pre-detection) that collects string values reachable from form field chains and indirect-reference chains, concatenates them in traversal order, and runs the WS3 normalisation + WS2/WS1 token checks on the concatenated result.
- Scope the pass to reference chains of depth ≤ 12 and total concatenated size ≤ 256 KB to prevent abuse.
- When a concatenated result triggers an injection finding that no individual object triggered alone, emit:
  - `scattered_payload_assembly` finding with `chain.stage=decode` and `chain.capability=payload_scatter`
  - Metadata listing contributing object IDs: `scatter.object_ids=6 0,9 0,14 0`
  - Metadata with the number of fragments: `scatter.fragment_count=3`
- Cross-reference with `js-analysis` findings: if a JS finding identifies assembly patterns (`String.fromCharCode`, split/join) and the assembled string matches a PDF form field value, emit a combined `cross_stream_payload_assembly` finding linking the JS object and the source field objects.

New finding kinds:
- `scattered_payload_assembly`: payload assembled from multiple PDF objects along a reference chain.
- `cross_stream_payload_assembly`: payload assembled via JavaScript string operations traceable to PDF object values.

Deliverables:
- Graph-walk accumulation pass in `sis-pdf-core` with depth and size guards.
- Two new finding kinds with documentation in `docs/findings.md`.
- Fixtures with split payloads across at least two objects.

Acceptance criteria:
- A payload split across two form fields that is benign individually but malicious when concatenated triggers `scattered_payload_assembly`.
- A JS assembly pattern that sources values from named form field objects triggers `cross_stream_payload_assembly` when the assembled string contains injection tokens.
- No false positives on normal multi-field forms with benign values.

## Event and Chain Quality Review: Opportunities to improve exploit connectivity

### Current state

`chain_synth.rs` already synthesises exploit chains using a trigger/action/payload role model, builds object-position edges via `build_object_chains`, and groups chains by signature via `group_chains_by_signature`. The CQ workstreams below extend this infrastructure; they do not replace it. CQ1's stage vocabulary (`input`, `decode`, `render`, `execute`, `egress`) maps onto the existing role model: `input` ≈ trigger, `execute`/`render` ≈ action, `egress` ≈ payload. CQ2's edge fields (`edge.reason`, `edge.confidence`, `edge.shared_objects`) extend the existing edge structure produced by `build_object_chains`.

### Design-first note (CQ5)

The `--with-chain` query schema (field names, output format, JSON structure) must be drafted and reviewed before CQ1-CQ4 implementation begins. Locking the schema after data is emitted risks breaking downstream automation. CQ5 implementation (the CLI flag itself) lands last, but the schema definition is a design prerequisite for CQ1.

## CQ1: Introduce normalised event primitives for finding correlation

Proposal:
- For each relevant finding, emit compact chain fields:
  - `chain.stage`: `input`, `decode`, `render`, `execute`, `egress` (maps to trigger/action/payload roles in `chain_synth.rs`)
  - `chain.capability`: e.g. `html_injection`, `js_execution`, `network_exfil`, `user_prompt`, `payload_scatter`
  - `chain.trigger`: viewer/runtime assumptions (`pdfjs`, `browser_export`, `acrobat_js`)
- Keep fields stable and queryable.

Benefit:
- Enables deterministic multi-finding joins without brittle kind-specific logic.

## CQ2: Add deterministic chain edge synthesis in core reporting

Current state: `build_object_chains` in `chain_synth.rs` already synthesises edges by shared object position and groups chains by signature. The following extends that with explicit, typed edges for injection-specific paths.

Proposal:
- In `sis-pdf-core` correlation pass, synthesise edges when preconditions align:
  - `form_html_injection -> pdfjs_form_injection` (same object or shared form lineage)
  - `*_injection -> submitform_present` (possible data egress bridge)
  - `pdfjs_* -> pdfjs_eval_path_risk` (renderer risk context)
  - `scattered_payload_assembly -> *_injection` (scatter feeds into injection)
  - `obfuscated_name_encoding -> action_*` (name obfuscation co-located with action)
- Edge metadata (extending existing edge structure):
  - `edge.reason`
  - `edge.confidence`
  - `edge.shared_objects`

Benefit:
- Produces machine-readable exploit paths instead of analyst-only mental joins.

## CQ3: Upgrade finding details with exploit preconditions and blockers

Proposal:
- Add structured detail fields:
  - `exploit.preconditions` (viewer/version, feature enabled, user action)
  - `exploit.blockers` (sanitisation, CSP, disabled JS)
  - `exploit.outcomes` (xss, credential capture, exfil)
- Include these in `explain` output and JSONL.

Benefit:
- Better triage quality and less over-escalation from isolated indicators.

## CQ4: Chain-level confidence and severity composition

Proposal:
- Compute `chain.confidence` from edge quality + finding confidence.
- Compute `chain.severity` using highest plausible outcome with guardrails:
  - require execution+egress evidence before elevating to `High` impact chain
  - keep isolated indicators at `Medium`/`Low` chain levels
  - `scattered_payload_assembly` without a confirmed execution link remains at `Medium`

Benefit:
- Reduces alert fatigue while preserving high-risk exploit paths.

## CQ5: Explainability and query ergonomics for exploit graphs

Schema design prerequisite (complete before CQ1 implementation):
- Draft and review the full JSON schema for `--with-chain` output, including field names, stage ordering, edge representation, and text summary format.
- Record the approved schema in `docs/findings.md` under a `Chain Query Output` section.

Implementation (lands after CQ1-CQ4):
- Add optional query mode (`sis query ... findings --with-chain`) returning:
  - chain id
  - ordered stages
  - contributing findings and shared object refs
- Add concise text-mode summary:
  - "Potential chain: form_html_injection (obj 6 0) -> pdfjs_form_injection (obj 6 0) -> submitform_present (obj 9 0)"

Benefit:
- Speeds analyst workflow on large corpora where manual correlation is costly.

## CQ6: Chain-focused test fixtures

Proposal:
- Add/extend fixtures that deliberately split exploit stages across objects and encodings.
- Assertions should validate:
  - edge creation
  - stage order
  - chain confidence/severity
  - stable metadata fields for downstream automation
- Include at least one end-to-end test: raw PDF input -> chain query output, validating the full pipeline from detector through `chain_synth.rs` to `--with-chain` JSON.

Benefit:
- Prevents regressions in cross-finding exploit connectivity.

## CQ7: Scatter chain synthesis

Proposal:
- When `scattered_payload_assembly` or `cross_stream_payload_assembly` findings are emitted, synthesise a chain that explicitly links all contributing fragment objects as `chain.stage=decode` nodes and the assembled output as a `render` or `execute` node.
- Chain path example: "Scattered payload: fragments at obj 6 0, obj 9 0, obj 14 0 -> assembled injection -> pdfjs_form_injection (obj 6 0)"
- Assertions in CQ6 fixtures should validate scatter chain structure (fragment count, contributing object IDs, assembled finding link).

Benefit:
- Makes distributed/scattered exploit patterns visible in the exploit graph without requiring manual correlation across many low-signal findings.

## New opportunities (not in current workstreams)

The following gaps were identified during the plan review. They are captured here for prioritisation after the above workstreams are complete, or to inform parallel work.

### NO1: Invisible layer / optional content action gating

Current state: `lib.rs:3615` detects `OCG`/`OCProperties` and emits a low-severity informational finding. No severity adjustment is applied when optional content groups conceal actions or JS payloads.

Opportunity:
- When an action or JS payload is reachable only through an object tagged with an OCG entry, tag the finding with `context.hidden_layer=true`.
- Elevate confidence and severity of that finding because the content is specifically structured to be invisible to static inspection.
- Emit a composite finding `hidden_layer_action` when an OCG-gated object also carries a high-risk action type.

### NO2: Form field value length anomaly

Opportunity:
- Very long form field values (multi-kilobyte `/V` strings) are abnormal for user-facing forms.
- Add a simple threshold check (e.g. > 4 KB) emitting `form_field_oversized_value` at low confidence.
- Use as a confidence booster when co-located with injection findings.
- Low implementation cost, low false-positive risk on documents without large base64 data URIs in fields.

### NO3: AcroForm calculated field exploitation

Current state: Document-level `AA` is detected. Per-field `/AA` entries (carrying `calculate`, `validate`, `format`, `keystroke` JS actions) are not differentiated from document-level actions.

Opportunity:
- Emit a distinct finding for per-field `/AA` entries that carry JavaScript actions.
- These fire on user interaction (focus, keystroke, blur) without requiring OpenAction, making them harder to detect behaviourally and easier to overlook in static analysis.
- Classify as `acroform_field_action` with severity/confidence based on payload content.

### NO4: GoToR/GoToE suspicious remote target inspection

Current state: `actions_triggers.rs:834` classifies GoToR and GoToE as high-risk action types, but does not inspect the `/F` (file specification) parameter for suspicious patterns.

Opportunity:
- Add target inspection to GoToR and GoToE action handling:
  - UNC paths (`\\server\share`)
  - Data URIs (`data:text/html,...`)
  - Percent-encoded or obfuscated file paths
  - Suspicious URL schemes (file://, javascript://)
- Emit `action_remote_target_suspicious` when patterns match.
- Apply the WS3 normalisation pass to `/F` values before classification.

### NO5: Null-object reference chain exploitation

Current state: `object_cycles.rs` and `xref_deviation.rs` cover cycles and xref anomalies, but not the specific pattern of a deeply-nested indirect reference chain terminating in a null or non-existent object.

Opportunity:
- Detect chains of indirect references ending at object 0 (null object) or at a missing object ID as a parser-state confusion trigger.
- Emit `null_ref_chain_termination` when a chain of depth ≥ 3 resolves to a null or absent object in a security-relevant context (action, form field, annotation appearance).

### NO6: Cross-stream payload assembly via JavaScript string operations

Note: partially covered by WS6. The additional opportunity here is the inverse direction: when `js-analysis` detects `String.fromCharCode`, array-join, or split/join patterns assembling a string, probe whether the assembled string value matches any known form field, annotation, or metadata string in the same document. If so, emit `cross_stream_payload_assembly` linking the JS object and the source PDF objects.

This requires a query interface between `js-analysis` findings and the PDF object graph — a non-trivial integration. Track as a follow-up to WS6.

### NO7: PDF string literal obfuscation signal

Current state: Hex-literal PDF strings (`<3c736372697074>`) are decoded at parse time. Detectors see decoded bytes and cannot distinguish a hex-encoded string from an inline string.

Opportunity:
- Add a parser annotation that records whether a given string object used hex-literal syntax.
- Emit `pdf_string_hex_encoded` (low confidence, informational) when security-relevant strings (JS action bodies, form field values, annotation contents) used hex-literal encoding.
- Use as a taint/confidence signal in downstream detectors rather than a standalone alert.

## Delivery sequence

1. **Design:** Draft and review `--with-chain` JSON schema (CQ5 prerequisite). Record in `docs/findings.md`.
2. **WS1** (aggregation correctness) with accompanying WS5 split-signal tests.
3. **WS2** (precision refinement) with WS5 precision guard tests.
4. **WS3** (obfuscation normalisation) with WS5 encoded fixtures and action parameter tests.
5. **WS4** (docs/meta evidence alignment).
6. **WS6** (cross-object scatter detection) with WS5 scatter fixtures.
7. **CQ1 and CQ2** (baseline chain metadata + edge synthesis, extending `chain_synth.rs`).
8. **CQ3 and CQ4** (exploit preconditions + chain confidence/severity).
9. **CQ5** (CLI `--with-chain` flag, using pre-approved schema).
10. **CQ6 and CQ7** (chain fixtures + scatter chain synthesis).
11. **NO1-NO7** prioritised based on corpus signal after core uplift is stable.

## Risks and mitigations

- Risk: false-positive increase from expanded decoding.
  - Mitigation: bounded decode depth (max 3 layers) and size (max 64 KB), HTML-context gating, precision regression tests.
- Risk: throughput regression on large corpora.
  - Mitigation: byte-scan caps, early exits after sufficient signal, runtime profiling checks against SLO in `docs/performance.md`.
- Risk: chain model instability across finding kinds.
  - Mitigation: stable schema fields, deterministic edge rules, fixture-backed regression tests.
- Risk: WS6 scatter detection over-triggers on normal multi-field forms.
  - Mitigation: precision guard fixtures with benign multi-field forms; require assembled result to clear injection token threshold, not just any non-empty concatenation.
- Risk: CQ1-CQ4 implementation diverges from or conflicts with existing `chain_synth.rs` logic.
  - Mitigation: CQ workstreams are explicitly additive to `chain_synth.rs`; any structural changes to that module require a review note in the plan and a corresponding regression run.
- Risk: CQ5 schema locked in by implementation before real usage.
  - Mitigation: schema design is a delivery prerequisite (step 1), completed and reviewed before CQ1 implementation begins.

## Definition of done

1. All workstream detector/documentation improvements are implemented with tests (WS1-WS6).
2. Hidden/obfuscated payload variants (UTF-16, percent, entity, JS-escape, null-padded, multi-layer) are detected in regression fixtures.
3. HTML-injection precision improves with no new obvious benign regressions.
4. Finding metadata clearly exposes signal source, matched context, normalisation layers applied, and contributing object IDs for scattered payloads.
5. Action parameter obfuscation is detected and reported in metadata.
6. `scattered_payload_assembly` and `cross_stream_payload_assembly` finding kinds are implemented and tested.
7. `obfuscated_name_encoding` finding kind is implemented and tested.
8. Initial chain connectivity model is implemented and query/explain-visible for related findings (`chain.stage`, `chain.capability`, `edge.*` fields).
9. `--with-chain` query mode returns well-formed output matching the pre-approved schema.
10. Runtime profile shows no throughput regression outside the SLO bounds in `docs/performance.md`.
