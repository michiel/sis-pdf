# Detection Uplift Plan: Hidden/Obfuscated Content and Exploit Chain Quality

Date: 2026-02-19
Status: Proposed
Owner: Detection pipeline (`sis-pdf-detectors`, `sis-pdf-core`, docs)

## Goals

1. Implement all identified improvements from commit `004088a2a4e77400c025144caef518d14bb46b02` review.
2. Improve detection of hidden and obfuscated form payloads without materially increasing false positives.
3. Uplift event and chain quality so analysts can understand how disparate findings connect into exploitable paths.

## Scope

In scope:
- `PdfjsRenderingIndicatorDetector` injection classification logic.
- HTML/JavaScript token heuristics for form payloads.
- Obfuscation-aware normalisation path reuse.
- Evidence/meta/detail fidelity for field-level triggers.
- Integration, regression, and precision tests.
- Finding-chain correlation metadata and explainability details.

Out of scope (this plan):
- New dynamic sandbox execution engines.
- Non-form attack surfaces except where chain correlation consumes existing findings.

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

Implementation:
- Reuse `normalise_text_bytes_for_script` before token matching.
- Add lightweight decode passes for common encodings used in evasions:
  - percent-encoding (`%3cscript%3e`)
  - JavaScript hex escapes (`\\x3c`, `\\u003c`)
  - HTML entities (`&lt;script&gt;`)
- Limit decode passes and output size to prevent abuse and preserve throughput.
- Record normalisation metadata (e.g. `injection.normalised=true`, `injection.decode_layers=2`).

Deliverables:
- Shared normalisation utility path used by JS and HTML injection checks.
- Guardrails on decode depth and size.

Acceptance criteria:
- Obfuscated fixture variants trigger expected findings.
- Runtime overhead remains inside current Stage 0.5 SLO expectations for detector stage.

## WS4: Align evidence, metadata, and findings documentation

Problem:
- Detection source keys and emitted evidence/docs are partially misaligned.

Implementation:
- Emit source-key metadata for each matched object, e.g.:
  - `injection.sources=/V,/AP`
  - `injection.signal.js=true`
  - `injection.signal.html=true`
- Ensure evidence reflects actual triggering keys (not fixed `/V` when `/AP` triggered).
- Update `docs/findings.md` to document exact source fields, signal quality model, and confidence logic.

Deliverables:
- Meta enrichment for triage and query.
- Documentation update with exact semantics.

Acceptance criteria:
- Findings include enough metadata to explain why they fired and where.
- Documentation matches implementation behaviour.

## WS5: Regression and baseline test uplift

Implementation:
- Extend `crates/sis-pdf-detectors/tests/pdfjs_rendering_indicators.rs` with:
  - split-signal field tests (`/V` + `/AP`, `/DV` + ref)
  - obfuscated payload tests (UTF-16, percent, entity, escape)
  - precision guards (benign JS-like text, harmless HTML snippets)
- Add unit tests for classifier/normalisation helpers.
- Run targeted baseline workflow:
  1. `cargo test -p sis-pdf-detectors --test pdfjs_rendering_indicators`
  2. adjacent impacted suites in `sis-pdf-core` where finding metadata invariants are asserted
  3. runtime profile command for the CVE fixture with JSON output
- Capture deltas in this plan after implementation.

Acceptance criteria:
- New tests fail on current behaviour and pass with uplift.
- No regression in existing detector suites.

## Event and Chain Quality Review: Opportunities to improve exploit connectivity

Current opportunity:
- Findings exist, but exploit storytelling across stages (entry, obfuscation, execution, exfiltration) is still fragmented.

## CQ1: Introduce normalised event primitives for finding correlation

Proposal:
- For each relevant finding, emit compact chain fields:
  - `chain.stage`: `input`, `decode`, `render`, `execute`, `egress`
  - `chain.capability`: e.g. `html_injection`, `js_execution`, `network_exfil`, `user_prompt`
  - `chain.trigger`: viewer/runtime assumptions (`pdfjs`, `browser_export`, `acrobat_js`)
- Keep fields stable and queryable.

Benefit:
- Enables deterministic multi-finding joins without brittle kind-specific logic.

## CQ2: Add deterministic chain edge synthesis in core reporting

Proposal:
- In `sis-pdf-core` correlation pass, synthesise edges when preconditions align:
  - `form_html_injection -> pdfjs_form_injection` (same object or shared form lineage)
  - `*_injection -> submitform_present` (possible data egress bridge)
  - `pdfjs_* -> pdfjs_eval_path_risk` (renderer risk context)
- Edge metadata:
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

Benefit:
- Reduces alert fatigue while preserving high-risk exploit paths.

## CQ5: Explainability and query ergonomics for exploit graphs

Proposal:
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

Benefit:
- Prevents regressions in cross-finding exploit connectivity.

## Delivery sequence

1. WS1 (aggregation correctness) and WS5 minimal regression tests.
2. WS2 (precision refinement) with precision guard tests.
3. WS3 (obfuscation normalisation) with encoded fixtures.
4. WS4 docs/meta evidence alignment.
5. CQ1 and CQ2 baseline chain metadata + edge synthesis.
6. CQ3-CQ6 iterative uplift after baseline chain model lands.

## Risks and mitigations

- Risk: false-positive increase from expanded decoding.
  - Mitigation: bounded decode depth/size, HTML-context gating, precision regression tests.
- Risk: throughput regression on large corpora.
  - Mitigation: byte-scan caps, early exits after sufficient signal, runtime profiling checks.
- Risk: chain model instability across finding kinds.
  - Mitigation: stable schema fields, deterministic edge rules, fixture-backed regression tests.

## Definition of done

1. All five detector/documentation improvements are implemented with tests.
2. Hidden/obfuscated payload variants are detected in regression fixtures.
3. HTML-injection precision improves with no new obvious benign regressions.
4. Finding metadata clearly exposes signal source and matched context.
5. Initial chain connectivity model is implemented and query/explain-visible for related findings.
