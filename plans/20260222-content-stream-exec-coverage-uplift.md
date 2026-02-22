# ContentStreamExec Coverage, Stream Visualisation, and Detection Uplift Plan

Date: 2026-02-22
Status: Proposed (not yet implemented)
Owner: Core + CLI + GUI

## Scope

Assess current `ContentStreamExec` coverage, define gaps, and provide an implementation plan to:
1. Improve execution-surface coverage fidelity.
2. Add a forensic stream-execution visualisation overlay.
3. Extend stream-focused detection where current analysis is shallow.
4. Keep existing behaviour stable by default while adding optional depth.

## Assumptions

1. Current default behaviour must remain stable for existing users and automation.
2. Event and graph outputs should remain internally consistent across CLI and GUI.
3. New analysis and visualisation depth should be strict and automated (no manual analyst annotation loop in-product).
4. GUI-specific dependencies must not leak into non-GUI builds.
5. Runtime and memory budgets remain bounded for large-corpus processing.

## Current Coverage (Observed)

### What is covered now

1. `ContentStreamExec` events are emitted from typed `PageContents` edges in the event graph.
2. Event labels include page->stream object refs (useful triage context).
3. GUI event list and details expose `ContentStreamExec`, execute target object links, and finding linkage.
4. Existing detectors already parse decoded content operators and emit stream-oriented findings, including:
   - `content_stream_anomaly` (unknown operators and operand mismatches),
   - resource usage semantics (`Do`/`Tf` volume and hidden invocation patterns),
   - vector operator anomalies,
   - rendered-script lure signals.

### Coverage shape today

1. Event graph `ContentStreamExec` is currently one event per typed `PageContents` edge.
2. CLI `events.full` now surfaces per-event edge metadata and reverse finding index, but event payload does not yet include stream-op summaries.
3. Graph visual mode can navigate from `ContentStreamExec` event node to its target stream object.

## Findings

### High-severity gaps

1. `PageContents` typed-edge extraction only resolves a single indirect ref for `/Contents`.
   - Consequence: pages using `/Contents` arrays or direct stream objects can be underrepresented in typed graph and therefore in `ContentStreamExec` events.
   - Risk: false negatives in execution-surface mapping and event counts.

2. `ContentStreamExec` derivation is restricted to `PageContents` edges.
   - Consequence: nested execution surfaces are not modelled as execution events (for example form XObject rendering chains and Type3 charproc execution paths already parsed by detectors).
   - Risk: incomplete runtime-like path view; disconnected forensic narrative.

### Medium-severity gaps

1. Event graph does not currently encode stream-operation semantics.
   - Missing: operator families, resource invocation names, marked-content transitions, graphics-state stack anomalies, and per-op spans.
   - Risk: analysts must pivot to raw stream inspection instead of using graph-native flow.

2. Suspicious-edge rendering is too coarse in event mode.
   - Current rule marks `Executes` and `ProducesOutcome` as suspicious broadly.
   - Risk: signal dilution and visual alert fatigue.

3. Stream provenance/revision context is not first-class on `ContentStreamExec` events.
   - Missing: object provenance class, revision-introduced/overridden hints, filter-chain fingerprints.
   - Risk: weaker incremental-update and anti-forensics triage.

### Low-severity gaps

1. No dedicated query for stream-execution narratives (event->stream->resource/outcome path story).
2. No CSV contract yet for stream-operation-level rows (only event-level schema drafted).

## Opportunities For Improvement

1. Close structural coverage gaps first: robust `/Contents` extraction (ref, array, direct stream).
2. Introduce optional stream-execution overlay layers to avoid default graph bloat.
3. Reuse existing operator parser (`ContentOp.span`) to provide precise operator evidence and graph anchors.
4. Convert coarse suspicious marking to scored/rule-based suspicious semantics with explicit reason fields.
5. Add content-stream execution summaries in `events.full` (counts, operator classes, resource references, anomaly counters).
6. Extend detection with correlation between `ContentStreamExec` and existing findings to raise confidence when stream semantics and outcomes align on a connected path.

## Detailed Technical Implementation Plan

## Stage 0: Baseline and Guardrails

1. Add baseline metrics command outputs for selected fixtures:
   - count of pages,
   - count of `/Contents` refs/arrays/direct streams discovered,
   - count of typed `page_contents` edges,
   - count of `ContentStreamExec` events.
2. Record baseline in this plan and maintain during rollout.
3. Add explicit non-regression expectation: existing `events`/`graph.event` schemas remain stable unless behind new optional fields.

Acceptance criteria:
1. Baseline script/test runs deterministically in CI.
2. Any coverage delta is explicit and reviewed.

## Stage 1: Correct `PageContents` Coverage in Typed Graph

1. Refactor page edge extraction to collect all `/Contents` targets:
   - indirect ref,
   - array of refs,
   - direct stream object (using synthetic per-object anchor strategy or direct object identity mapping).
2. Add deduplication for repeated refs in `/Contents` arrays.
3. Ensure `EdgeType::PageContents` edge count matches actual discovered page-content stream target count.

Implementation notes:
1. Keep current API shape for `TypedEdge`.
2. Prefer helper `collect_page_content_targets(dict, graph)` to isolate parsing logic and test it directly.

Tests:
1. Unit tests in `crates/sis-pdf-pdf/src/typed_graph.rs`:
   - `/Contents` single ref,
   - `/Contents` array (multi-stream),
   - `/Contents` direct stream,
   - duplicate refs deduped.
2. Integration tests in `crates/sis-pdf-core/tests/event_graph_outcomes.rs` asserting `ContentStreamExec` counts for each scenario.

Acceptance criteria:
1. No regression for existing fixtures.
2. Array/direct content streams now produce `PageContents` edges and `ContentStreamExec` events.

## Stage 2: Extend ContentStreamExec Surface Beyond PageContents

1. Add optional event-builder pass for additional stream execution surfaces:
   - form XObject execution (`Do` into `/Subtype /Form` targets),
   - Type3 charproc stream execution.
2. Model these as `ContentStreamExec` with richer `event_key`/metadata context (for example `xobject.form` vs `type3.charproc`).
3. Preserve default behaviour by gating advanced stream surfaces via `EventGraphOptions` flag (default `false` initially).

Implementation notes:
1. Keep event IDs deterministic and collision-safe.
2. Reuse typed graph + classification, avoid GUI dependencies.

Tests:
1. Add synthetic fixture tests for nested form XObject and Type3 charproc.
2. Assert event type, trigger class, source object, execute target, and metadata context.

Acceptance criteria:
1. Optional mode adds events without changing default counts.
2. Event IDs remain stable across runs.

## Stage 3: Stream Operation Projection Layer

1. Add core projection module for stream-op summaries tied to event nodes:
   - total op count,
   - operator family counts (text/path/state/resource/marked-content/inline-image),
   - `Do` targets by resource name and resolved object ref where possible,
   - anomaly counters (unknown op, arity/type mismatch, graphics-state imbalance).
2. Add optional detailed op rows for JSON only:
   - op index,
   - operator token,
   - span offset,
   - normalised operands (bounded for size).
3. Extend `events.full` with optional `stream_exec` section for `ContentStreamExec` rows.

Implementation notes:
1. Use bounded collection (max ops and max bytes per event row) to avoid output explosion.
2. Keep fields additive to prevent breaking consumers.

Tests:
1. Unit tests for operator family classification.
2. Integration tests validating `events.full` includes stream summaries when enabled.
3. Budget/performance tests on existing CVE fixture and at least one multi-stream fixture.

Acceptance criteria:
1. `events.full` provides actionable stream semantics for `ContentStreamExec`.
2. No unbounded memory growth on large streams.

## Stage 4: Graph Visualisation Overlay (Optional)

1. Add optional `graph.event.stream` overlay query and GUI toggle:
   - base event graph remains unchanged by default,
   - overlay adds pseudo nodes/edges for stream semantics.
2. Proposed pseudo-node types:
   - `stream.opcluster.<event_id>.<class>` (operator family aggregates),
   - `stream.resource.<event_id>.<name>` (resource names used by `Do`, `Tf`, `gs`, `sh`),
   - `stream.anomaly.<event_id>.<kind>` (syntax/stack anomalies),
   - `stream.marked.<event_id>.<tag>` (marked-content boundaries, optional).
3. Proposed edge kinds:
   - `exec_observed`, `invokes_resource`, `signals_anomaly`, `enters_marked_content`.
4. Render suspicious-edge style from explicit reasoned score, not blanket edge kind.

Implementation notes:
1. Keep overlay entirely in core/query outputs; GUI only renders provided graph payload.
2. Add strict node/edge caps and truncation metadata.

Tests:
1. Query tests for `graph.event.stream` JSON schema and truncation.
2. GUI mapping tests for new node kinds and edge hover details.

Acceptance criteria:
1. Analysts can see “what happens in the stream” without manually decoding every stream.
2. Overlay remains performant and optional.

## Stage 5: Detection Extension Opportunities

1. Add correlation detector: `content_stream_exec_outcome_alignment`.
   - Trigger when suspicious stream-op semantics and high-risk outcomes are connected in event graph paths.
2. Add graphics-state abuse detector:
   - repeated `q`/`Q` imbalance, excessive nesting, abrupt state resets around `Do`/text draws.
3. Add marked-content evasion detector:
   - suspicious content concentrated in `BMC/BDC` segments with low visible rendering footprint.
4. Add resource-name obfuscation signal:
   - anomalous resource name churn/high entropy names used by `Do`/`Tf` across pages/revisions.

Calibration and metadata:
1. Follow finding metadata guidance with explicit `severity`, `impact`, `confidence`.
2. Emit deterministic metadata keys and evidence spans.

Tests:
1. Add integration tests with representative fixtures under `crates/sis-pdf-core/tests/fixtures/corpus_captured/` where needed.
2. Register any new fixtures in corpus manifest with SHA256 and provenance.

Acceptance criteria:
1. New detectors produce low false-positive rates on clean fixture baseline.
2. High-confidence findings align with connected event graph evidence.

## Stage 6: CLI, Docs, and Export Contracts

1. Add query docs for new optional stream overlay and `events.full` stream fields.
2. Add CSV schema extension doc for stream summaries (separate from per-op rows).
3. Ensure text output remains concise; JSON/JSONL remain machine-parseable and stable.

Acceptance criteria:
1. `docs/query-interface.md` and findings docs updated with examples.
2. Schema changes documented before release.

## Risks and Mitigations

1. Risk: graph explosion with per-op modelling.
   - Mitigation: aggregate-by-default, optional detail mode, strict caps + truncation flags.
2. Risk: behaviour drift in existing event counts.
   - Mitigation: default-preserving flags and fixture-based regression gates.
3. Risk: GUI/core coupling.
   - Mitigation: keep all modelling/projection in core; GUI consumes serialisable structures only.

## Out of Scope (for this plan)

1. Full symbolic execution of PDF graphics operators.
2. Rendering-equivalence engine across Acrobat/PDFium/PDF.js.
3. Manual analyst annotation workflows in-product.

## Delivery Checklist

- [ ] Stage 0 baseline metrics and non-regression checks committed.
- [ ] Stage 1 `/Contents` coverage fix implemented with tests.
- [ ] Stage 2 extended execution surfaces behind option flag.
- [ ] Stage 3 `events.full` stream-op projection implemented.
- [ ] Stage 4 optional stream overlay graph query + GUI view wiring.
- [ ] Stage 5 detection extensions implemented and calibrated.
- [ ] Stage 6 docs and export contracts updated.
