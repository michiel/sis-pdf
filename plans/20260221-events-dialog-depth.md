# Events Dialog Depth and Integration Plan

Date: 2026-02-21
Status: Proposed
Owner: GUI (`sis-pdf-gui`), core (`sis-pdf-core`), CLI (`sis-pdf`)

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
generic labels for many node types

For `ContentStreamExec`, the label is `"content stream exec"` rather than
something like `"Page 3 — stream obj 7"`. The builder has access to the source
page number and target object but does not encode it. The GUI has to display the
generic label.

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
2. Change `EventViewModel.outcome_targets` from `Vec<String>` to
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

In `sis-pdf-core`, update the `ContentStreamExec` node label to include the
page object number and target stream object number where available:
`"ContentStreamExec: page {obj} → stream {target}"`.

This is a pure core change with no GUI impact beyond the string value. Update
the builder's existing label assignment code; no new fields needed.

Update the regression test that asserts the existing `ContentStreamExec` label
string.

### B2. Contextual severity/confidence badge in the list row

The worst linked-finding severity for each event row is computable from
`EventViewModel.linked_finding_ids` and the findings slice. Render a small
coloured severity dot (matching the findings panel's severity colour scheme)
at the left of each list row. Use `Info` / no dot for events with no linked
findings.

### B3. Group ContentStreamExec rows

When three or more consecutive `ContentStreamExec` events are present, group
them under a collapsible "Content streams (N)" header to reduce noise for
benign multi-page documents. Keep the group expanded by default when any
member has a linked finding with severity ≥ Medium.

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

The output row type mirrors `EventViewModel` in a serialisable, egui-free
struct suitable for JSONL output:
- `node_id`, `event_type`, `label`, `trigger_class`, `source_object`
  (`obj:gen` string), `execute_targets` (list of `obj:gen` strings),
  `outcome_targets` (list of `{type}:{confidence}` strings),
  `linked_finding_ids`, `mitre_techniques`.

Reuse `extract_event_view_models` from `event_view.rs` where possible, or
extract the core logic into `sis-pdf-core` if crate boundaries require it.

### D2. Add `sis query events` subcommand

1. New subcommand `events` in `sis-pdf/src/commands/query.rs`.
2. Accept `--format json|text` (defaulting to text).
3. Support `--where trigger=automatic|hidden|user` predicate.
4. Single-file and batch (`--batch`) modes consistent with other query types.

### D3. Validation

1. Integration test asserting `sis query events` on a known fixture produces
   the expected node IDs in JSON output.
2. Test asserting `--where trigger=automatic` filters correctly.
3. Test asserting batch mode continues after a parse error.

## Workstream E: Performance budget test (G6)

1. Add a unit test `events_build_budget` in `event_view.rs` that calls
   `build_event_graph_for_result` followed by `extract_event_view_models` on
   the standard CVE fixture and asserts total elapsed time is under 100ms.
2. Follow the pattern of `critical_path_budget` in `panels/graph.rs`.

## Delivery stages

### Stage 1: Outcome detail and list usability (A + B)

1. Implement `OutcomeDetail` and render in detail pane.
2. Enrich ContentStreamExec label in the EventGraph builder.
3. Add severity badges to list rows.
4. Add ContentStreamExec grouping.

### Stage 2: Cross-panel navigation (C)

1. Graph → Events jump.
2. Events → Graph button.
3. Finding Detail back-link.

### Stage 3: CLI events query (D) and budget test (E)

1. Implement `sis query events`.
2. Add performance budget test.

## Risks and mitigations

1. Risk: changing `outcome_targets` type in `EventViewModel` breaks callers.
   Mitigation: `EventViewModel` derives `Default`; test constructors use
   `..EventViewModel::default()`; only one external consumer (events.rs).
2. Risk: ContentStreamExec label change in core breaks existing snapshot tests.
   Mitigation: update the one label assertion in the existing regression test
   in the same commit.
3. Risk: `sis query events` re-parses PDF bytes for every invocation.
   Mitigation: same as the GUI cache pattern — document that batch mode parses
   once per file; consider a shared pipeline entry point if cost is unacceptable.

## Acceptance criteria

1. Outcome nodes with confidence and evidence are visible in the Events detail
   pane.
2. ContentStreamExec list rows include the source page and target stream object
   in the label.
3. Severity badges appear on list rows with linked findings.
4. Double-clicking an Event node in the graph panel focuses the corresponding
   Events dialog row.
5. "Show in graph" button in Events detail navigates to the selected event node.
6. Finding Detail opened from Events shows a back-link to the originating event.
7. `sis query events --format json` outputs one JSON object per event node,
   matching the field schema defined in D1.
8. Performance budget test passes: full EventGraph build + extraction < 100ms on
   the CVE fixture.
9. `cargo test -p sis-pdf-gui -p sis-pdf-core -p sis-pdf` passes.
