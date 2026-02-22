# Events Dialog Depth and Integration Plan

Date: 2026-02-21
Status: Implemented
Owner: GUI (`sis-pdf-gui`), core (`sis-pdf-core`), CLI (`sis-pdf`)

## Implementation status (2026-02-22)

Completed:
1. Added shared core event projection in `sis-pdf-core`:
   - new `event_projection` module,
   - `EventRecord`, structured execute targets and outcome detail records,
   - stable extraction ordering and finding-to-event reverse index helper.
2. GUI now maps core `EventRecord` into view models with structured outcomes:
   - outcome type/label/confidence/severity/evidence/source object are rendered in Events detail.
3. Events list usability updates:
   - severity dots from linked findings,
   - `ContentStreamExec` grouping when high-volume,
   - deterministic ordering preserved by projection sorting.
4. Cross-panel navigation updates:
   - graph double-click on event nodes opens/focuses Events dialog,
   - `E` shortcut opens Events for selected graph event node,
   - Events detail `Show in graph` selects/focuses corresponding graph node,
   - finding detail now supports `← Back to event` via `finding_origin_event`.
5. CLI `events` query now emits EventGraph-backed structured rows:
   - includes `node_id`, `trigger`, structured outcomes, execute target details, and metadata fields,
   - supports `--where trigger=...` via predicate metadata context,
   - works with existing `--format text|json|jsonl` handling.
6. Added projection budget coverage:
   - `event_projection::tests::events_projection_budget_on_cve_fixture`.
7. Implemented `events.full` CLI mode:
   - emits structured event rows plus explicit `finding_event_index`,
   - includes per-event edge provenance/metadata for deeper forensic analysis.
8. Documented CSV-ready event schema contract:
   - `docs/events-csv-schema.md`.
9. Removed obsolete legacy event extraction helpers from query code path:
   - deleted `extract_aa_events` and `extract_action_details` dead paths.

Deferred follow-on opportunities:
1. Add CLI flag alias (`--full`) in the command-line surface for parity with
   `events.full` query shortcut.

Validation completed:
1. `cargo test -p sis-pdf-gui -p sis-pdf-core -p sis-pdf --no-run`
2. `cargo test -p sis-pdf extract_event_triggers_includes_open_action_from_fallback_catalog -- --nocapture`
3. `cargo test -p sis-pdf events_query_ -- --nocapture`
4. `cargo test -p sis-pdf predicate_context_for_event_maps_level_and_type -- --nocapture`
5. `cargo test -p sis-pdf-gui panels::events::tests:: -- --nocapture`
6. `cargo test -p sis-pdf-gui panels::graph::tests::graph_double_click_ -- --nocapture`
7. `cargo test -p sis-pdf-gui event_view::tests:: -- --nocapture`
8. `cargo test -p sis-pdf-core event_projection::tests:: -- --nocapture`
9. `cargo test -p sis-pdf-gui -p sis-pdf-core -p sis-pdf -p sis-pdf-detectors`
10. `cargo build --target wasm32-unknown-unknown -p sis-pdf-gui`

## Assumptions

1. Current detection behaviour (finding generation, severity, confidence) remains unchanged.
2. Event list and CLI event output must be deterministic across runs for the same input.
3. `sis-pdf` and other non-GUI crates must not depend on `sis-pdf-gui`.
4. Validation is strict and automated; manual GUI checks are supplementary.

## Non-goals

1. Changing EventGraph semantics or detector taxonomy.
2. Reintroducing analyst annotation workflows in the GUI.
3. Reducing forensic detail from existing EventGraph nodes.

## Context

The Events dialog now consumes `EventGraph` event nodes directly and renders
clickable object references, linked findings, MITRE techniques, and per-type
descriptions (see `20260221-gui-events-and-triage-deprecation.md`, implemented).

Several integration gaps and depth opportunities remain.

## Gaps from the current implementation

### G1. Outcome nodes carry no detail

`EventViewModel.outcome_targets` holds node-id strings. Outcome nodes in the
`EventGraph` carry `outcome_type`, `label`, `confidence_score`, `evidence`, and
`severity_hint` — none of which is currently surfaced. The detail pane shows
`Outcomes: -` or bare node IDs even when meaningful data is present.

### G2. Event list row is dense and hard to scan

The list row format is `{label} [{trigger_class}]`. For documents with many
`ContentStreamExec` nodes (one per page), all rows look identical and cannot be
distinguished at a glance. There is no severity/confidence signal in the list.

### G3. No cross-navigation from graph panel to Events dialog

Double-clicking an event node in the graph panel does not open or focus the
corresponding row in the Events dialog. The two panels share the same
`selected_event` state but there is no affordance to move between them.

### G4. Finding Detail panel has no back-link to the originating event

When a user navigates from the Events dialog to a finding, there is no way to
return to the event that referred them. The finding detail panel has no "origin
event" context.

### G5. `EventViewModel` carries a label but the EventGraph builder produces
generic labels for many node types (except `ContentStreamExec`, already improved)

`ContentStreamExec` labels are already enriched in core as
`"Content stream (page {obj} {gen} -> stream {obj} {gen})"`. However, many
other event types still rely on generic labels and have limited scanability in
the Events list without additional context signals.

### G6. No SLO regression test for Events dialog build path

`AGENTS.md` requires a performance budget test for new expensive operations in
the render path. `cached_event_graph()` adds EventGraph build cost to the Events
panel frame path but has no corresponding budget test (unlike `critical_path_budget`
and `taint_overlay_mapping_budget` in `graph.rs`).

### G7. `sis query events` CLI subcommand is not yet implemented

This was identified in the deprecation plan (N1) as a follow-on. Batch users
have no access to the EventGraph event list that GUI analysts now have.

## Workstream A: Outcome node detail

### A1. Add `OutcomeDetail` to the view model

1. Define in `event_view.rs`:
   ```
   pub struct OutcomeDetail {
       pub node_id: String,
       pub outcome_type: String,    // Debug format of OutcomeType
       pub label: String,
       pub confidence_score: Option<u8>,
       pub severity_hint: Option<String>,
       pub evidence: Vec<String>,
       pub source_obj: Option<(u32, u16)>,
   }
   ```
2. Change GUI `EventViewModel.outcome_targets` from `Vec<String>` to
   `Vec<OutcomeDetail>`.
3. In `extract_event_view_models`, resolve each `ProducesOutcome` target node
   by looking it up in `event_graph.node_index` and extracting its
   `EventNodeKind::Outcome` fields.

### A2. Render outcome detail in the Events dialog

1. Show each outcome as a labelled row: `{outcome_type} — {label}`, with
   confidence as a percentage badge and severity hint as a coloured label
   matching the existing severity colour scheme.
2. Evidence strings (if any) rendered as an indented list under each outcome.
3. If `source_obj` is present on the outcome node, render as a clickable object
   reference (same pattern as execute targets).

### A3. Validation

1. Unit test: `extract_event_view_models` populates `OutcomeDetail` fields for a
   graph containing an Outcome node with confidence and evidence.
2. Unit test: outcome with no confidence renders without panicking.

## Workstream B: Event list usability

### B1. Enrich the EventGraph builder label for ContentStreamExec

No implementation needed for `ContentStreamExec` specifically: this label is
already enriched in `sis-pdf-core`.

Instead, add/standardise enriched labels for other high-volume event types that
still render as generic strings, and keep label formatting stable and concise.
Add/adjust regression tests for any updated labels.

### B2. Contextual severity/confidence badge in the list row

The worst linked-finding severity for each event row is computable from
`EventViewModel.linked_finding_ids` and the findings slice. Render a small
coloured severity dot (matching the findings panel's severity colour scheme)
at the left of each list row. Use `Info` / no dot for events with no linked
findings.

### B3. Group ContentStreamExec rows

When three or more `ContentStreamExec` events are present, group
them under a collapsible "Content streams (N)" header to reduce noise for
benign multi-page documents. Keep the group expanded by default when any
member has a linked finding with severity ≥ Medium.

Determinism rule: event ordering is stable by `(source_object, node_id)` before
grouping so grouping does not depend on incidental insertion order.

## Workstream C: Cross-panel navigation

### C1. Graph panel → Events dialog

When the user double-clicks an Event node in the graph panel:
1. Set `app.selected_event` to the node's ID (already done implicitly via
   graph node selection state).
2. Set `app.show_events = true` to open the dialog.
3. The Events dialog already validates `selected_event` against the current
   event list and defaults to the first row if invalid, so no further
   synchronisation is needed.

Add a keyboard shortcut `E` (when graph is focused and a node is selected)
to jump to the Events dialog for that node.

### C2. Events dialog → graph panel

Add a small "Show in graph" button in the detail pane that:
1. Sets the graph panel's selected node to `selected_event`.
2. Sets `app.show_graph = true`.

This is a one-field write; no new state needed.

### C3. Finding Detail → originating event back-link

When the finding detail panel is opened from the Events dialog (via linked
finding click), store `app.finding_origin_event: Option<String>` with the
node ID of the originating event. Render a small "← Back to event" link at
the top of the finding detail panel when this field is set. Clicking it
restores `selected_event` and focuses the Events dialog.

Clear `finding_origin_event` when `selected_finding` is changed through any
other path.

## Workstream D: CLI `sis query events`

### D1. Define the events query output format

Define a serialisable, GUI-independent `EventRecord` in `sis-pdf-core` and use
it as the shared projection for GUI and CLI consumers.

`EventRecord` includes:
- `node_id`, `event_type`, `label`, `trigger_class`, `source_object`
  (`obj:gen` string), `execute_targets` (list of node IDs plus resolved object refs),
  `outcome_targets` (structured objects with `node_id`, `outcome_type`, `label`,
  `confidence_score`, `severity_hint`, `evidence`, `source_object`),
  `linked_finding_ids`, `mitre_techniques`, `event_key`, `initiation`, `branch_index`.

`crates/sis-pdf-gui` maps `EventRecord` to UI-specific view models; `crates/sis-pdf`
uses `EventRecord` directly for query output. This avoids any GUI dependency leak
into non-GUI builds.

### D2. Add `sis query events` subcommand

1. New subcommand `events` in `sis-pdf/src/commands/query.rs`.
2. Accept standard query formats: `--format text|json|jsonl` and `--json`
   shorthand (`--format json`) consistent with existing query behaviour.
3. Support `--where trigger=automatic|hidden|user` predicate.
4. Single-file and batch (`--batch`) modes consistent with other query types.
5. Keep strict format conflict handling and stable top-level keys aligned with
   existing query interface conventions.

### D3. Validation

1. Integration test asserting `sis query events` on a known fixture produces
   the expected node IDs in JSON output.
2. Test asserting `--where trigger=automatic` filters correctly.
3. Test asserting batch mode continues after a parse error.
4. Test asserting JSONL emits one record per event row and remains parseable.
5. Test asserting structured outcome fields are present (no flattening loss).

## Workstream E: Performance budget test (G6)

1. Add extraction-focused budget test (`events_projection_budget`) in the shared
   projection module (core), measuring projection over a prebuilt EventGraph.
2. Keep end-to-end parse + EventGraph build + projection performance in runtime
   profile / fixture performance tests; avoid brittle hard-coded unit-test wall
   clock limits for full pipeline timing.
3. Follow existing profiling test patterns and document budget targets with
   tolerances rather than fixed single-threshold CI timing.

## Workstream F: Navigation and provenance depth

### F1. Finding-to-event reverse index

1. Build and cache a reverse index `finding_id -> Vec<event_node_id>` from the
   shared event projection.
2. Use it for Events -> Finding and Finding -> Event round-trip navigation.
3. Expose this mapping in CLI JSON/JSONL output for offline triage joins.

### F2. Optional full-forensic output mode for CLI

1. Add optional `--full` (or equivalent) for `sis query events` to include full
   outcome evidence payloads and extended edge metadata.
2. Keep default output concise for throughput; `--full` preserves maximum signal
   for investigations.

### F3. CSV-ready schema track

1. Define and document an events CSV schema (columns and field normalisation)
   without implementing export in this plan.
2. Ensure `EventRecord` fields align with this schema to avoid later breaking
   reshapes.

## Delivery stages

### Stage 1: Shared projection and outcome depth (A + D1 foundation)

1. Introduce core `EventRecord` projection (GUI-independent).
2. Implement structured outcome detail extraction.
3. Wire GUI event view model mapping from `EventRecord`.

### Stage 2: Event list usability and cross-panel navigation (B + C + F1)

1. Add severity badges and deterministic grouping.
2. Graph → Events jump.
3. Events → Graph button.
4. Finding Detail back-link.
5. Add finding/event reverse index.

### Stage 3: CLI events query and performance validation (D2 + D3 + E + F2 + F3)

1. Implement `sis query events`.
2. Add JSONL and structured outcome validation tests.
3. Add projection/runtime performance coverage.
4. Define CSV-ready schema contract and optional full-forensic mode.

## Risks and mitigations

1. Risk: changing `outcome_targets` type in `EventViewModel` breaks callers.
   Mitigation: introduce `EventRecord` in core and keep GUI-only `EventViewModel`
   as an adapter layer; update tests at both layers.
2. Risk: CLI/GUI schemas drift over time.
   Mitigation: single shared projection type (`EventRecord`) and shared fixture
   assertions across GUI mapping and CLI output.
3. Risk: `sis query events` re-parses PDF bytes for every invocation.
   Mitigation: same as the GUI cache pattern — document that batch mode parses
   once per file; consider a shared pipeline entry point if cost is unacceptable.
4. Risk: full pipeline timing tests are flaky in CI.
   Mitigation: keep strict wall-clock budget assertions to projection-only scope
   and use profiled/tolerant checks for end-to-end path.

## Acceptance criteria

1. Outcome nodes with confidence and evidence are visible in the Events detail
   pane.
2. Event list labels are enriched and stable for high-volume event types, with
   deterministic ordering/grouping.
3. Severity badges appear on list rows with linked findings.
4. Double-clicking an Event node in the graph panel focuses the corresponding
   Events dialog row.
5. "Show in graph" button in Events detail navigates to the selected event node.
6. Finding Detail opened from Events shows a back-link to the originating event.
7. `sis query events --format json` outputs one JSON object per event node,
   matching the structured field schema defined in D1 without loss of outcome
   evidence/severity metadata.
8. `sis query events --format jsonl` outputs one JSON object per event row.
9. Projection performance budget and end-to-end performance validations pass per
   Workstream E.
10. `cargo test -p sis-pdf-gui -p sis-pdf-core -p sis-pdf -p sis-pdf-detectors`
    passes.
