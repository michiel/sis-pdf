# GUI Events Integration and Triage De-scope Plan

Date: 2026-02-21
Status: Implemented
Owner: GUI (`sis-pdf-gui`), core (`sis-pdf-core`), CLI (`sis-pdf`)

## Implementation status (2026-02-21)

Completed:
1. GUI Events dialog now consumes EventGraph-derived event rows (node-id keyed selection) via
   shared `event_view` extraction helpers.
2. Event graph construction is cached per active analysis result and reused by graph/detail/events
   panels to avoid repeated parsing.
3. Reader-impact enrichment was removed:
   - removed `reader_context` module and report/query enrichment calls,
   - removed `ReaderProfile` / `ReaderImpact` model types and `Finding.reader_impacts`,
   - removed reader-impact metadata emissions and GUI reader-impact consumers.
4. Manual GUI annotation workflow was removed:
   - deleted annotation sidecar module/state/load-save/editor UI,
   - removed annotation-dependent findings/chains panel behaviour.
5. Documentation updates added:
   - `docs/reader-profiles.md` (historical capability notes),
   - `docs/schema-changelog.md` (pre-release schema break),
   - removed reader-impact references from query/findings docs.

Validation completed:
1. `cargo test -p sis-pdf-gui`
2. `cargo test -p sis-pdf-core -p sis-pdf`
3. `cargo test -p sis-pdf-detectors --test supply_chain_staging -- --nocapture`
4. `cargo test -p sis-pdf-gui -p sis-pdf-core -p sis-pdf -p sis-pdf-detectors`
5. `cargo build --target wasm32-unknown-unknown -p sis-pdf-gui`

## Problem statement

Three related changes are required:

1. The GUI `Events` dialog currently derives rows from finding metadata only, but does not
   directly expose events that are present in the built `EventGraph` model.
2. Reader-specific impact assignment (`reader_context::annotate_reader_context`) injects derived
   per-reader severities and `reader.impact.*` metadata into findings; this is now out of scope.
3. Manual analyst annotations in GUI findings/chains are no longer part of product scope; analysts
   will annotate externally after CSV export is introduced.

## Assumptions

1. Current scanner detection behaviour (finding generation/severity/confidence) remains unchanged.
2. Output and UI behaviour should stay deterministic and consistent across runs.
3. Validation is strict and automated (unit + integration tests); manual checks are supplementary.
4. Reader-impact de-scope includes removal of assignment, metadata writes, and serialised schema
   fields in the same change.
5. CSV export workflow is a follow-on plan and is out of scope for this work item.
6. No `egui` types or GUI-only data structures leak into non-GUI crates.
7. `crates/sis-pdf/src/commands/query.rs` is already modified (dirty in working tree at plan
   authoring time); the query-time reader context removal in B1 must reconcile with that
   in-flight change rather than treating it as a clean slate.

## Goals

1. Include event-graph-registered events in the GUI `Events` view with selectable detail.
2. Remove reader-impact assignment path and associated `reader.impact.*` metadata writes.
3. Remove GUI analyst-annotation interaction and persistence paths.
4. Keep builds green and preserve deterministic output contracts unless explicitly documented.

## Non-goals

1. Implementing CSV export in this plan.
2. Changing detector logic or finding taxonomy.
3. Reworking event graph semantics in `sis-pdf-core` beyond consumer integration.

## Current state findings

1. GUI graph panel builds `EventGraph` from parsed bytes and findings (`build_event_graph_for_gui`)
   then maps to `GraphData`; `Events` dialog currently does not consume this source.
2. Reader impacts are assigned centrally in `Report::from_findings` via
   `reader_context::annotate_reader_context` (`sis-pdf-core/src/reader_context.rs`), and are also
   injected in query code paths (`sis-pdf/src/commands/query.rs`).
3. GUI annotations are wired through `AnnotationStore` + `app` state + `findings`/`chains` UI.
4. `sha256_hex` is currently defined in `annotations.rs` and imported into `app.rs`; removing
   `annotations.rs` requires relocating this function.
5. The `event_reader_profile_filter` field in app state and the reader-profile combobox UI
   (`graph.rs` lines 791-813) and `build_visible_node_set` filter path (`graph.rs` lines
   1387-1392) are all tied to reader impacts and must be removed together with B2.
6. `detail.rs` holds a `ReaderImpactDisplay` derived struct and test coverage for the
   reader-impacts table; both are concrete deletion targets for B2.
7. `WorkspaceContext` serialises `annotations: AnnotationStore`; removal without serde handling
   risks deserialisation failure on existing workspace files.
8. `reader_context.rs` encodes operationally significant knowledge about PDF reader
   capability differences (JavaScript/Actions/EmbeddedFiles severity caps per profile) that
   should be preserved in documentation before the file is deleted.

## Workstream A: EventGraph-backed Events dialog

### A1. Introduce shared event extraction for GUI

1. Define a `EventViewModel` struct in a new `crates/sis-pdf-gui/src/event_view.rs` module:
   - `node_id: NodeId` — stable EventGraph node identifier used as the selection key.
   - `event_type: EventNodeKind` — e.g. `AutomaticAction`, `JavaScript`, `ContentStreamExec`.
   - `trigger_class: TriggerClass` — automatic / hidden / user.
   - `source_object: Option<ObjectId>` — originating PDF object.
   - `execute_targets: Vec<NodeId>` — outgoing Execute edge targets.
   - `outcome_targets: Vec<NodeId>` — outgoing Outcome edge targets.
   - `linked_finding_ids: Vec<String>` — finding IDs carried in EventGraph provenance for this node.
   - `event_key: Option<String>` — action/annotation key string where present.
   - `initiation: Option<String>` — initiation metadata from edge.
   - `branch_index: Option<u32>` — branch index from edge metadata.
   - Fields are named and typed to be export-friendly (plain strings / primitives) so the same
     struct can feed the future CSV export without redesign.
2. Expose a single function `extract_event_view_models(event_graph: &EventGraph) -> Vec<EventViewModel>`
   that iterates Event nodes only (not Outcome, Object, or Collapse nodes) and populates the
   struct. Non-Event nodes are not surfaced as event rows.
3. Both consumers call this one function:
   - `panels/graph.rs` for the existing Event graph path (replace any duplicated logic).
   - `panels/events.rs` for the new Events dialog source of truth.

### A2. Update Events dialog behaviour

1. Primary list source becomes `EventGraph` event nodes via `extract_event_view_models`.
   Old `collect_events()` heuristic and `finding_has_event_signal()` are removed.
2. Reset `app.selected_event` to `None` whenever the active result changes, and key selection
   by `NodeId` rather than a bare `usize` index to avoid stale-index confusion between the
   old finding-based and new EventGraph-based entry sets.
3. Keep selectable rows with detail pane; include for each Event node:
   - graph node id (`node_id`),
   - event type and trigger class,
   - source object,
   - outgoing execute/outcome targets,
   - linked finding IDs where present.
4. Detail pane content is scoped to Event-node fields only. Outcome, Object, and Collapse
   nodes are not rendered as selectable event rows.
5. Secondary section: "Unmapped finding event signals" — rendered after the main list for
   findings where `finding_has_event_signal()` would have matched but no EventGraph event node
   carries that finding's ID in provenance. Definition: a finding appears here when its ID is
   absent from all `linked_finding_ids` sets across all `EventViewModel` rows. This section is
   labelled clearly as forensic/supplementary.

### A3. Caching and performance guardrails

1. The `EventGraph` is built once per `AnalysisResult` and stored in the analysis result cache
   alongside the existing `GraphData` cache. Both panels read from the cached value; neither
   re-parses PDF bytes independently when a cached result is present.
2. Cache key is the result's document SHA-256 (already computed and available in `app.rs`).
3. If the graph panel's existing cache already holds a built `EventGraph` for the active result,
   the Events dialog reads that directly rather than triggering a second build.
4. Keep event view deterministic: stable ordering by `node_id`, then by `event_type` label.
5. Add a budget test asserting `extract_event_view_models` completes within an acceptable bound
   on the standard CVE fixture (`launch_cve_2010_1240.pdf`), following the pattern of the
   existing `critical_path_budget()` and `taint_overlay_mapping_budget()` tests in `graph.rs`.

### A4. Validation

1. Unit tests for `extract_event_view_models`: correct node type filtering, field population,
   stable ordering, and empty-graph edge case.
2. Unit tests for the "unmapped finding event signals" secondary section: a finding with an
   event-signal metadata key but no corresponding EventGraph provenance entry appears in the
   secondary section and not in the primary list.
3. GUI tests for selection/detail rendering helpers.
4. Regression test proving Events dialog includes `ContentStreamExec` and other event node
   types from `EventGraph` fixtures.
5. Performance budget test for `extract_event_view_models` on the CVE fixture (see A3.5).

## Workstream B: Remove reader-impact assignment and metadata writes

### B1. Stop enrichment at source

1. Remove `reader_context::annotate_reader_context` invocation from `Report::from_findings`
   in `sis-pdf-core/src/report.rs`.
2. Remove query-time augmentation in `sis-pdf/src/commands/query.rs`. Reconcile with the
   current dirty state of that file before committing; do not produce a double-removal or
   conflict with in-flight changes.
3. Remove insertion of `reader.impact.*` and `reader.impact.summary` metadata keys from
   `reader_context::annotate_reader_context` itself, then delete the function and module.
4. Before deleting `reader_context.rs`, extract its reader capability knowledge into
   `docs/reader-profiles.md`: document the per-reader severity caps for JavaScript, Actions,
   and EmbeddedFiles attack surfaces so the operational rationale is not lost.

### B2. Remove consumer dependencies

1. `panels/detail.rs`: remove reader-impacts table rendering, the `ReaderImpactDisplay` derived
   struct, and associated tests.
2. `panels/graph.rs`: remove `annotate_reader_profiles()` function, `event_reader_profile_filter`
   app state field, the reader-profile combobox UI (lines 791-813), and the
   `build_visible_node_set` filter branch that gates on reader profile (lines 1387-1392).
3. Core chain/explainability code paths that read `finding.reader_impacts` should be updated to
   remove the dependency; do not leave degraded fallback paths that silently ignore a now-absent
   field.

### B3. Pre-release schema removal

1. Remove `ReaderProfile`, `ReaderImpact` model types and `Finding.reader_impacts` field from
   `sis-pdf-core/src/model.rs`.
2. `Finding.reader_impacts` is currently annotated `#[serde(default, skip_serializing_if =
   "Vec::is_empty")]`. Removing the field means existing JSON with `reader_impacts` present will
   be silently dropped on deserialisation (serde default behaviour); document this in the schema
   changelog and verify with a round-trip test using a fixture that previously emitted the field.
3. Update all in-tree serialisation consumers, tests, and docs to the new schema. Record the
   breaking change in `docs/` (e.g. `docs/schema-changelog.md` or equivalent).
4. External tooling is expected to adapt during pre-release.

### B4. Validation

1. Update/replace tests asserting populated reader impacts.
2. Add regression tests asserting no `reader.impact.*` keys appear in JSON/JSONL output.
3. Confirm JSON/JSONL output remains parseable and stable; include a round-trip test for a
   fixture that previously carried `reader_impacts` to confirm silent-drop behaviour is safe.
4. Confirm `cargo test -p sis-pdf-detectors` still passes (detectors must not depend on
   reader-context enrichment).

## Workstream C: Remove manual analyst annotations in GUI

### C1. Remove annotation data path

1. Remove `AnnotationStore` field from `SisApp` and `WorkspaceContext`.
2. Before removing the sidecar load path, emit a one-time log warning (or UI toast on open) when
   a `.sis-notes.json` sidecar is detected: "Analyst annotation files are no longer loaded.
   Export findings via CSV when available." This bridges the UX gap for users with existing
   sidecars.
3. Remove annotation load/save sidecar functions and calls (`load_annotations_for_active_result`,
   `persist_annotations`).
4. Relocate `sha256_hex` from `annotations.rs` to `app.rs` or a suitable `util.rs` before
   deleting the module, since `app.rs` imports it from there.
5. Remove `annotations.rs` module once all references are resolved.
6. For workspace deserialisation safety: add `#[serde(default)]` to the `annotations` field in
   `WorkspaceContext` before removing it, or verify that the workspace deserialiser already
   tolerates unknown fields, so existing workspace files do not fail to load after the field
   is gone.

### C2. Remove annotation UI

1. Findings panel: remove triage-dot column and inline annotation editor.
2. Chains panel: remove annotation-based filtering/counting logic.
3. Remove related keyboard/interaction affordances if present.

### C3. Keep future export-ready hooks minimal

1. Do not add new in-app annotation replacement.
2. Keep finding IDs and report data export-friendly for future CSV plan.
3. The `EventViewModel` struct from A1 is designed to serve as the CSV export row type; no
   additional hooks are needed in this plan.

### C4. Validation

1. Update GUI tests impacted by removed annotation affordances.
2. Ensure native and wasm builds pass without annotation paths.
3. Verify tab/workspace serialisation remains stable after field removal; test round-trip with
   a workspace file that previously carried `annotations`.

## Delivery stages

Removal-first ordering reduces dead-code surface and simplifies the new EventGraph integration
in Stage 3 (no reader-profile filter paths to route around, no annotation state to preserve).

### Stage 1: Annotation de-scope

1. Implement Workstream C.
2. Emit sidecar warning, relocate `sha256_hex`, remove dead annotation code.
3. Verify native and wasm builds and workspace serialisation round-trip.

### Stage 2: Reader-impact de-assignment

1. Implement Workstream B.
2. Reconcile `query.rs` dirty state before committing.
3. Publish `docs/reader-profiles.md` and schema changelog entry in the same commit.
4. Update tests/docs for removed reader context enrichment behaviour.

### Stage 3: EventGraph-backed Events dialog

1. Implement Workstream A.
2. Land `event_view.rs` module, shared helper, caching wiring, and all tests.
3. Confirm Events dialog no longer references removed annotation or reader-impact fields.

## New opportunities (explicitly out of scope for this plan, prioritised for follow-on)

### N1. `sis query events` CLI subcommand

`EventGraph` is now the authoritative event source for the GUI. Batch users have no equivalent.
A `sis query events` subcommand (or `--include-events` flag) outputting event nodes as JSON/JSONL
would expose the same data to pipelines. The `EventViewModel` struct from A1 is the natural row
type. This also creates a testable CLI contract for the shared extraction helper.

### N2. EventGraph events in overlay views

Recent overlay work (detached overlay stats, commit 0117906) surfaces graph-level data in
overlay annotations. The `extract_event_view_models` helper from A1 could feed overlay
annotations with event-node labels, making event coverage visible in the structure overlay
without a separate dialog visit.

### N3. Finding-to-EventGraph bidirectional index

When implementing "linked finding provenance" in A2, there is an opportunity to maintain a
reverse index: `finding_id → Vec<NodeId>`. This enables "jump to event" from the finding detail
panel and highlight-on-select between the Events dialog and graph panel. Low implementation cost
if added during A1/A2; costly to retrofit later.

## Risks and mitigations

1. Risk: event view and graph view diverge in semantics.
   Mitigation: single `extract_event_view_models` function in `event_view.rs`; both panels
   call it; shared tests assert identical output for the same `EventGraph` input.
2. Risk: removal of reader enrichment affects downstream expectations.
   Mitigation: pre-release policy allows schema change; update in-tree assertions, publish
   `docs/reader-profiles.md` and schema changelog in the same stage; round-trip test covers
   the serde silent-drop path.
3. Risk: annotation removal causes broad GUI churn.
   Mitigation: staged deletion (C1 → C2 → C3) with compile/test checkpoints; workspace
   deserialisation guarded with `#[serde(default)]` before field is removed; sidecar warning
   prevents silent data loss for users.
4. Risk: `query.rs` in-flight changes conflict with B1 reader context removal.
   Mitigation: inspect dirty diff before starting Stage 2; resolve conflicts explicitly rather
   than applying removal blindly.
5. Risk: `selected_event` index becomes stale after Events dialog source changes.
   Mitigation: reset to `None` on result change; key by `NodeId` not `usize`.

## Acceptance criteria

1. GUI Events dialog shows events that exist as `EventGraph` event nodes.
2. No reader-impact assignment occurs in report or query paths.
3. No `reader.impact.*` metadata is emitted in any output format.
4. GUI contains no manual analyst annotation UI or persistence behaviour.
5. `cargo test -p sis-pdf-gui -p sis-pdf-core -p sis-pdf -p sis-pdf-detectors` passes.
6. WASM build passes (`cargo build --target wasm32-unknown-unknown -p sis-pdf-gui` or
   equivalent project target).
7. Regression test asserts `ContentStreamExec` and other EventGraph node types appear in
   Events dialog output.
8. Regression test asserts no `reader.impact.*` keys in JSON/JSONL output.
9. Workspace round-trip test passes with a fixture that previously carried `annotations`
   and `reader_impacts` fields.
10. `docs/reader-profiles.md` exists documenting per-reader severity caps.

## Follow-on plans (explicitly deferred)

1. Add findings export to CSV for analyst workflows outside GUI (natural consumer of
   `EventViewModel` struct introduced in A1).
2. `sis query events` CLI subcommand (N1 above).
3. EventGraph events in overlay views (N2 above).
4. Finding-to-EventGraph bidirectional index and "jump to event" affordance (N3 above).
