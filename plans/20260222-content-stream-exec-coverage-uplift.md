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

## Implementation progress

Last updated: 2026-02-22

Completed in this cycle:
1. Stage 1 `/Contents` array coverage fix implemented in `typed_graph.rs`.
   - `extract_page_edges()` now collects all unique `/Contents` reference targets.
   - Duplicate refs in `/Contents` arrays are deduplicated per page.
2. Stage 1 tests added and passing:
   - `typed_graph::tests::page_contents_single_ref_emits_one_edge`
   - `typed_graph::tests::page_contents_array_emits_edges_for_all_unique_refs`
   - `typed_graph::tests::page_missing_contents_emits_no_page_contents_edge`
   - `test_content_stream_exec_event_count_matches_contents_array_length`
3. Formatting and targeted regression commands executed successfully:
   - `cargo fmt --all`
   - `cargo test -p sis-pdf-pdf typed_graph::tests::page_ -- --nocapture`
   - `cargo test -p sis-pdf-core --test event_graph_outcomes test_content_stream_exec_event -- --nocapture`

In progress / pending:
1. Stage 0 baseline metrics table and `get_first` scope audit documentation.
2. Stage 0 dedicated non-regression baseline test.
3. Stages 2-6 are not yet implemented.

## Assumptions

1. Current default behaviour must remain stable for existing users and automation.
2. Event and graph outputs should remain internally consistent across CLI and GUI.
3. New analysis and visualisation depth should be strict and automated (no manual analyst annotation loop in-product).
4. GUI-specific dependencies must not leak into non-GUI builds.
5. Runtime and memory budgets remain bounded for large-corpus processing.

## Feasibility assessment (added after codebase audit)

All stages are feasible with the current codebase. Key findings from the audit:

- **Stage 1**: Bug confirmed at `typed_graph.rs:418` — `get_first(b"/Contents")` followed by
  `resolve_ref()` only captures a single content stream target. The fix mirrors the existing
  `/Annots` array-handling pattern at line 434-442, which already handles both single refs and
  arrays correctly. No new infrastructure needed.
- **Stage 2**: `XObjectReference` edges are already built by `extract_xobject_edges()`. The
  event graph builder can consume these to emit form XObject ContentStreamExec events without
  any operator parsing — simpler than originally proposed.
- **Stage 3**: `event_projection.rs` now owns the `EventRecord` schema and mediates data flow
  from `EventGraph` to the CLI and GUI. Any new stream-op fields must flow through this module.
  The content operator parser in `sis-pdf-pdf/src/content.rs` already provides `ContentOp {
  op, operands, span }` with operator token, typed operands, and file offset.
- **Stage 4**: `graph.event` and `graph.event.json` query variants already exist; the overlay
  would add a new `graph.event.stream` variant following the same pattern.
- **Stage 5**: `correlation.rs` defines 15+ correlators following a standard pattern —
  `correlate_findings(findings, config) → Vec<Finding>`. The new stream correlator integrates
  here without new infrastructure. Individual stream detectors fit naturally in
  existing stream-focused detector modules (`parser_divergence.rs`,
  `resource_usage_semantics.rs`) to avoid ownership fragmentation.

## Current Coverage (Observed)

### What is covered now

1. `ContentStreamExec` events are emitted from typed `PageContents` edges in the event graph.
2. Event labels include page→stream object refs (useful triage context).
3. GUI event list and details expose `ContentStreamExec`, execute target object links, and
   finding linkage.
4. Existing detectors already parse decoded content operators and emit stream-oriented findings,
   including:
   - `content_stream_anomaly` (unknown operators and operand mismatches),
   - resource usage semantics (`Do`/`Tf` volume and hidden invocation patterns),
   - vector operator anomalies,
   - rendered-script lure signals.
5. `events.full` query already returns per-event node IDs, execute targets (with object refs),
   outcome targets with confidence scores and evidence, linked finding IDs, MITRE techniques,
   edge details, and a reverse finding→event index.
6. `event_projection.rs` (`sis-pdf-core`) mediates the `EventRecord` schema consumed by both
   CLI (`events.full`) and GUI (`event_view.rs`).

### Coverage shape today

1. Event graph `ContentStreamExec` is one event per typed `PageContents` edge.
2. `PageContents` edge extraction uses `get_first(b"/Contents")` + `resolve_ref()`, which
   captures only the first content stream target even when `/Contents` is an array.
3. Form XObjects and Type3 charproc streams are not modelled as execution events.
4. CLI `events.full` surfaces per-event edge metadata and reverse finding index, but event
   payload does not yet include stream-op summaries.
5. Graph visual mode can navigate from `ContentStreamExec` event node to its target stream
   object via clickable object links.
6. `XObjectReference` typed edges are already built for all XObject resources but are not
   consumed by the event graph builder to produce execution events.

## Findings

### High-severity gaps

1. `/Contents` array under-collection in typed graph.
   - Root cause: `extract_page_edges()` at `typed_graph.rs:418` uses `get_first(b"/Contents")`
     and `resolve_ref()`. When `/Contents` is an array (e.g. `[3 0 R, 7 0 R]`), `resolve_ref`
     on the array object returns `None` and subsequent array elements are silently skipped.
   - Consequence: pages with multiple content streams produce only one `PageContents` edge and
     therefore only one `ContentStreamExec` event; the remaining streams are invisible to the
     event graph.
   - Reference fix: the `/Annots` extraction at `typed_graph.rs:434-442` already handles both
     single-ref and array-of-refs patterns correctly. Stage 1 should mirror this exactly.
   - Risk: false negatives in execution-surface mapping and event counts.

2. `ContentStreamExec` derivation is restricted to `PageContents` edges.
   - Consequence: form XObjects (invoked via `Do` operator) and Type3 font charproc streams
     (invoked implicitly during text rendering) are not modelled as execution events, despite
     being significant attack surfaces.
   - `XObjectReference` typed edges already exist for all page XObject resources; the event
     builder only needs to filter these by destination classification to emit form XObject events.
   - Risk: incomplete runtime-like path view; disconnected forensic narrative.

### Medium-severity gaps

1. Event graph does not currently encode stream-operation semantics.
   - Missing: operator family counts, resource invocation names, marked-content transitions,
     graphics-state stack depth anomalies, and per-op file spans.
   - The content operator parser in `sis-pdf-pdf/src/content.rs` already produces
     `ContentOp { op: String, operands: Vec<ContentOperand>, span: Span }` with file offsets.
     The projection layer just needs to consume this.
   - `EventRecord` in `event_projection.rs` has no stream-op fields yet; they must be added
     here before they can appear in `events.full` or the GUI.
   - Risk: analysts must pivot to raw stream inspection instead of using graph-native flow.

2. Suspicious-edge rendering is too coarse in event mode.
   - Current rule in `graph_data.rs` marks all `EventEdgeKind::Executes` and
     `EventEdgeKind::ProducesOutcome` edges as suspicious via a boolean flag with no granularity.
   - Risk: signal dilution and visual alert fatigue when benign content streams generate many
     edges.

3. Stream provenance/revision context is not first-class on `ContentStreamExec` events.
   - Missing: object provenance class, revision-introduced/overridden hints, filter-chain
     fingerprints.
   - Risk: weaker incremental-update and anti-forensics triage.

4. `EventGraphOptions` has no flag for extended execution surfaces.
   - Current fields: `include_structure_edges`, `collapse_structure_only`, `max_nodes`,
     `max_edges`.
   - Stages 2 and 3 each require a new opt-in flag; these must be named and added together
     to avoid repeated struct changes.

### Low-severity gaps

1. No dedicated query for stream-execution narratives (event→stream→resource/outcome path story).
2. No CSV contract yet for stream-operation-level rows (only event-level schema drafted).
3. Stage 5 detector specifications are incomplete: finding `kind` strings, `AttackSurface`
   variants, and initial severity/confidence calibration values are not defined.
4. `correlation.rs` (`sis-pdf-core`) is not referenced in Stage 5 despite providing the exact
   pattern the new stream correlator should follow.

## Opportunities for improvement

1. **Stage 1 is a strict bug-fix with a clear reference implementation.** Land it independently
   before other stages to establish a correct baseline; it unblocks all downstream work.

2. **Stage 2 should use existing `XObjectReference` edges, not operator parsing.** The typed
   graph already has resolved (src, dst) pairs for all XObject resources. The event builder
   only needs to check if the destination node is classified as a Form XObject (Subtype `/Form`)
   to emit a `ContentStreamExec` with `event_key = "xobject.form"`. This avoids the complexity
   of parsing `Do` operands and resolving resource dictionary names at the event-graph layer.

3. **Stage 3 projection must flow through `event_projection.rs`.** Any new `stream_exec`
   fields added to events must appear first in `EventRecord` (the projection struct), then in
   `events.full` JSON output, then in the GUI `EventViewModel`. Keeping this data flow strict
   prevents GUI/core coupling.

4. **Stage 3 bounded collection: name the limits explicitly.** Based on the existing
   performance SLO pattern (CVE fixture < 50ms detection), a reasonable default bound is
   1,000 operators and 64 KB of projection data per ContentStreamExec event row. Define
   these as named constants, not magic numbers.

5. **Stage 4 overlay query syntax must be defined before implementation.** The proposed
   `graph.event.stream` query variant should follow the exact parse pattern of the existing
   `graph.event`, `graph.event.json`, and `graph.event.hops N` variants in `query.rs`.

6. **Stage 5 correlator should integrate with `correlation.rs` and `CorrelationOptions`.**
   The new `correlate_content_stream_exec_outcome_alignment` function follows the exact same
   signature and registration pattern as the 15 existing correlators. It should be added to
   the `correlate_findings` dispatch list and gated by a new `CorrelationOptions` boolean
   field to allow opt-out.

7. **`get_first` scope audit should accompany Stage 1.** `/Annots` already handles arrays
   correctly; scan all other `get_first()` usages in `typed_graph.rs` (OpenAction, Resources,
   Kids, etc.) to identify any with similar single-ref assumptions. Capture as issues even if
   not fixed in Stage 1.

## Detailed Technical Implementation Plan

## Stage 0: Baseline and Guardrails

### S0.1 Capture baseline metrics

Run the following against the CVE fixture and at least two multi-page fixtures:

```
sis query crates/sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf events.count --format json
sis query crates/sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf events.full --format json \
  | jq '[.result.events[] | select(.event_type == "ContentStreamExec")] | length'
```

Record in this plan:
- page count per fixture,
- `/Contents` ref/array/direct-stream counts discovered,
- typed `page_contents` edge count,
- `ContentStreamExec` event count before and after Stage 1.

### S0.2 Non-regression gate

Add a test asserting `ContentStreamExec` count equality for each baseline fixture before any
Stage 1 changes land. This test fails (and must be updated with explanation) if Stage 1 changes
the count.

### S0.3 `get_first` scope audit

Enumerate all `get_first(b"/...")` calls in `typed_graph.rs`. For each, document whether the
PDF spec allows the value to be an array. Capture any cases where array-valued entries are
silently truncated as numbered issues in this plan without blocking Stage 1.

Acceptance criteria:
1. Baseline metrics recorded in this plan.
2. Non-regression test committed and green.
3. Scope audit complete; issues listed.

## Stage 1: Correct `/Contents` Coverage in Typed Graph

### S1.1 Fix `extract_page_edges` to handle array-valued `/Contents`

Replace the single-ref extraction at `typed_graph.rs:418-422` with logic that handles both:
- `PdfObject::Ref(obj, gen)` — resolve directly, emit one `PageContents` edge.
- `PdfObject::Array(items)` — iterate, resolve each item ref, emit one edge per resolved target.
- Direct stream (object has no indirect ref wrapper) — do not emit a synthetic self-edge.
  Record this case in Stage 0 metrics as `contents_direct_stream_count` and keep behaviour
  explicit/documented until a dedicated pseudo-node strategy is designed.

The `/Annots` extraction at `typed_graph.rs:434-442` is the reference implementation — use the
same branching pattern.

Extract to a private helper:

```rust
fn collect_page_content_targets(
    &self,
    src: (u32, u16),
    dict: &PdfDict,
) -> Vec<TypedEdge>
```

This isolates the parsing logic and makes it unit-testable independently of the full typed
graph build.

### S1.2 Deduplication

Deduplicate resolved targets by `(obj, gen)` pair before emitting edges. Some malformed PDFs
repeat the same stream ref in a `/Contents` array. Use a local `HashSet<(u32, u16)>` per page.

### S1.3 Update Stage 0 non-regression test

After Stage 1, update the non-regression test expectations with the new (higher) event counts
and add a comment explaining the delta.

### S1.4 Tests

In `crates/sis-pdf-pdf/src/typed_graph.rs` (unit tests):
1. `/Contents` single indirect ref → one `PageContents` edge.
2. `/Contents` array of two refs → two `PageContents` edges.
3. `/Contents` array with duplicate ref → one edge (deduplication).
4. `/Contents` missing → zero edges (no panic).

In `crates/sis-pdf-core/tests/` (integration):
1. Synthetic fixture with array `/Contents` → assert `ContentStreamExec` count matches
   array length.

Acceptance criteria:
1. No regression for existing fixtures.
2. Array `/Contents` pages produce the correct number of `PageContents` edges and
   `ContentStreamExec` events.

## Stage 2: Extend ContentStreamExec Surface Beyond PageContents

### S2.1 Extend `EventGraphOptions`

Add two new opt-in flags (default `false`) in a single struct change:

```rust
pub struct EventGraphOptions {
    pub include_structure_edges: bool,
    pub collapse_structure_only: bool,
    pub max_nodes: usize,
    pub max_edges: usize,
    /// Emit ContentStreamExec events for form XObject execution surfaces.
    pub include_xobject_exec: bool,
    /// Emit ContentStreamExec events for Type3 font charproc streams.
    pub include_type3_exec: bool,
}
```

Default impl: both new flags `false`. All existing call sites that use
`EventGraphOptions::default()` are unaffected.

### S2.2 Form XObject execution events

In the event graph builder, when `include_xobject_exec` is set:

1. Derive candidate Form XObject targets from `typed_graph.edges` where
   `edge_type == EdgeType::XObjectReference` and destination classification indicates
   Form XObject (`/Subtype /Form`).
2. Confirm execution by resolving `Do` operator usage in the source page/form content stream(s)
   and matching referenced resource names to the candidate target object refs.
3. Only for confirmed matches, emit a
   `ContentStreamExec` event with:
   - `source_obj`: the page or resource dict object that holds the `/XObject` resource.
   - `event_key`: `"xobject.form"`.
   - `trigger`: `TriggerClass::Automatic` (form XObjects execute during page rendering).
   - An `Executes` edge to the form XObject's object node.
4. Use deterministic IDs: `ev:{src.obj}:{src.gen}:ContentStreamExec:xobj:{counter}`.

Note: `XObjectReference` alone represents declared reachability, not confirmed runtime invocation.

### S2.3 Type3 charproc execution events

In the event graph builder, when `include_type3_exec` is set:

1. Iterate objects classified as `PdfObjectType::Font` where the font subtype is `Type3`.
2. For each Type3 font, resolve the `/CharProcs` dictionary entries. Each value is a
   content stream ref; emit a `ContentStreamExec` event with:
   - `source_obj`: the Type3 font object.
   - `event_key`: `"type3.charproc"`.
   - `trigger`: `TriggerClass::Automatic`.
   - An `Executes` edge to the charproc stream object.
3. Use deterministic IDs: `ev:{font.obj}:{font.gen}:ContentStreamExec:t3:{glyph_name}:{counter}`.

### S2.4 Tests

1. Synthetic fixture: page with a form XObject in `/Resources/XObject` dict → with
   `include_xobject_exec = true`, assert one additional `ContentStreamExec` event with
   `event_key = "xobject.form"`.
2. Synthetic fixture: Type3 font with two charproc entries → with `include_type3_exec = true`,
   assert two additional `ContentStreamExec` events with `event_key = "type3.charproc"`.
3. Default mode (`EventGraphOptions::default()`) → no additional events; existing count
   unchanged.

Acceptance criteria:
1. Optional modes add events without changing default counts.
2. Event IDs remain stable (deterministic) across runs.
3. Source/execute target object refs are correct and navigable in the GUI.

## Stage 3: Stream Operation Projection Layer

### S3.1 Define stream-op projection bounds

Add named constants in `sis-pdf-core`:

```rust
/// Maximum number of content operators captured per ContentStreamExec event.
pub const STREAM_PROJ_MAX_OPS: usize = 1_000;
/// Maximum total byte size of operator projection data per event.
pub const STREAM_PROJ_MAX_BYTES: usize = 64 * 1024;
```

### S3.2 Operator family classification

Define an `OpFamily` enum (or equivalent string-keyed grouping) in the projection module:

- `Text` — `BT`, `ET`, `Tj`, `TJ`, `Tf`, `Td`, `Tm`, `T*`, `'`, `"`, and all `T*` operators.
- `Path` — `m`, `l`, `c`, `v`, `y`, `h`, `re`, `S`, `s`, `f`, `F`, `f*`, `B`, `b`, `n`,
  `W`, `W*`.
- `State` — `q`, `Q`, `cm`, `w`, `J`, `j`, `M`, `d`, `ri`, `i`, `gs`.
- `Resource` — `Do`, `Tf`, `gs`, `sh`, `cs`, `CS`, `sc`, `SC`, `scn`, `SCN`, `g`, `G`,
  `rg`, `RG`, `k`, `K`.
- `MarkedContent` — `BMC`, `BDC`, `EMC`, `MP`, `DP`.
- `InlineImage` — `BI`, `ID`, `EI`.
- `Unknown` — any token not matching the above.

### S3.3 Add `StreamExecSummary` to `EventRecord` in `event_projection.rs`

Extend `EventRecord`:

```rust
pub struct EventRecord {
    // … existing fields unchanged …

    /// Stream operation summary for ContentStreamExec events; None for other event types.
    pub stream_exec: Option<StreamExecSummary>,
}

pub struct StreamExecSummary {
    /// Total operator count in the content stream.
    pub total_ops: usize,
    /// Operator count by family name.
    pub op_family_counts: BTreeMap<String, usize>,
    /// Resource names invoked by Do, Tf, gs, sh (bounded to STREAM_PROJ_MAX_OPS entries).
    pub resource_refs: Vec<ResourceRef>,
    /// q/Q nesting anomalies: max depth reached, and whether it ever went negative.
    pub graphics_state_max_depth: usize,
    pub graphics_state_underflow: bool,
    /// Count of unknown/unrecognised operators.
    pub unknown_op_count: usize,
    /// Whether projection was truncated (total_ops > STREAM_PROJ_MAX_OPS).
    pub truncated: bool,
}

pub struct ResourceRef {
    /// Operator name that invoked this resource (e.g. "Do", "Tf").
    pub op: String,
    /// Resource name operand (e.g. "/Im1", "/F1").
    pub name: String,
    /// Resolved object ref if determinable (requires typed graph cross-reference).
    pub object_ref: Option<(u32, u16)>,
}
```

Populate `stream_exec` for `ContentStreamExec` nodes via an explicit data-flow:
1. Build stream summaries from `ScanContext` + execute-target object refs in a dedicated core
   helper (for example `stream_exec_projection.rs`).
2. Pass those summaries into `event_projection.rs` as a map keyed by event node ID.
3. Keep `event_projection.rs` as projection/merge logic only (no decoding side effects).

The projection is opt-in. Use a new entrypoint to avoid breaking existing callers:

```rust
pub fn extract_event_records_with_projection(
    event_graph: &EventGraph,
    projection: &ProjectionOptions,
    stream_summaries: Option<&BTreeMap<String, StreamExecSummary>>,
) -> Vec<EventRecord>

pub struct ProjectionOptions {
    pub include_stream_exec_summary: bool,
}
```

`extract_event_records(event_graph)` remains unchanged and delegates to the new function with
defaults, preserving backwards compatibility.

### S3.4 Extend `events.full` JSON output

When `stream_exec` is populated, include it under each `ContentStreamExec` event row:

```json
{
  "event_type": "ContentStreamExec",
  "stream_exec": {
    "total_ops": 142,
    "op_family_counts": { "Text": 45, "Path": 37, "State": 12, "Resource": 8, "Unknown": 2 },
    "resource_refs": [
      { "op": "Do", "name": "/Im1", "object_ref": "7:0" },
      { "op": "Tf", "name": "/F1", "object_ref": null }
    ],
    "graphics_state_max_depth": 3,
    "graphics_state_underflow": false,
    "unknown_op_count": 2,
    "truncated": false
  }
}
```

Fields are additive and absent when `stream_exec` is `null` (non-ContentStreamExec events
or when projection is disabled). Existing JSON consumers see no change.

### S3.5 Performance budget test

Add a test asserting the full projection pipeline (event graph build + extraction with
`include_stream_exec_summary = true`) on the CVE fixture completes within 150ms. Follow
the pattern of `critical_path_budget` in `panels/graph.rs`.

### S3.6 Tests

1. Unit: `OpFamily` classification covers all named operators; unrecognised token maps to
   `Unknown`.
2. Unit: `StreamExecSummary` populates correct counts for a synthetic op sequence.
3. Unit: truncation flag set when op count exceeds `STREAM_PROJ_MAX_OPS`.
4. Unit: `q`/`Q` nesting depth tracked; underflow detected.
5. Integration: `events.full` JSON for CVE fixture includes `stream_exec` section when
   projection is enabled.
6. Performance budget (S3.5).

Acceptance criteria:
1. `events.full` provides actionable stream semantics for `ContentStreamExec`.
2. No unbounded memory growth on large streams.
3. All existing `events.full` tests pass with no schema regressions.

## Stage 4: Graph Visualisation Overlay (Optional)

### S4.1 Define query syntax

Add the following parse cases in `query.rs` following the existing `graph.event` pattern:

```
graph.event.stream          → dot/text overlay graph (operator clusters and resource refs)
graph.event.stream.json     → JSON overlay graph
graph.event.stream.dot      → DOT format overlay
graph.event.stream.hops N   → hop-limited overlay export (format-aware)
```

### S4.2 Pseudo-node and edge scheme

Overlay nodes use a deterministic ID prefix distinct from event/object/outcome nodes:

| Node type | ID format | Purpose |
|---|---|---|
| Op cluster | `stream.ops.<event_id>.<family>` | Operator family aggregate |
| Resource ref | `stream.res.<event_id>.<name_hash>` | Named resource invocation |
| Anomaly | `stream.anom.<event_id>.<kind>` | Syntax/stack anomaly |
| Marked-content | `stream.mc.<event_id>.<tag_hash>` | Marked-content boundary |

Overlay edges:

| Kind | From → To | Meaning |
|---|---|---|
| `exec_observed` | ContentStreamExec event → op cluster | Event contains operator family |
| `invokes_resource` | ContentStreamExec event → resource ref node | Event calls named resource |
| `signals_anomaly` | ContentStreamExec event → anomaly node | Event exhibits anomalous pattern |
| `enters_marked_content` | ContentStreamExec event → marked-content node | BMC/BDC boundary |

### S4.3 Suspicious edge scoring

Add a scored field while preserving the existing boolean compatibility field:

```rust
pub enum SuspicionScore {
    None,
    Low { reason: String },
    Medium { reason: String },
    High { reason: String },
}
```

`GraphEdge` keeps `suspicious: bool` and adds `suspicion_score: SuspicionScore`.
Existing edges that were boolean-`true` are mapped to `Medium { reason: "executes" }` or
`High { reason: "produces_outcome" }`. GUI renders colour intensity from the score level.

### S4.4 Caps and truncation

Overlay nodes and edges are subject to existing `max_nodes`/`max_edges` from
`EventGraphOptions`. If truncated, a `truncation` field in the overlay JSON marks the
affected event IDs. This reuses the existing `EventGraphTruncation` schema.

### S4.5 Tests

1. Query test: `graph.event.stream` JSON contains overlay node IDs with correct prefixes.
2. Query test: truncation metadata present when cap exceeded.
3. `SuspicionScore` serialisation round-trip test.
4. GUI: `GraphEdge` display maps `High` score to high-contrast colour; `None` to neutral.

Acceptance criteria:
1. Analysts can see "what happens in the stream" without manually decoding every stream.
2. Overlay remains performant and optional.
3. Existing `graph.event` and `graph.event.json` tests pass unchanged.

## Stage 5: Detection Extension

### S5.1 `correlate_content_stream_exec_outcome_alignment` (correlator)

**Finding kind**: `content_stream_exec_outcome_alignment`
**Surface**: `AttackSurface::FileStructure`
**Severity**: `High`
**Confidence**: `Strong`

Add to `correlation.rs` following the existing correlator pattern. Register in
`correlate_findings()`. Gate with a new `CorrelationOptions` boolean field
`content_stream_exec_alignment_enabled` (default `true`).

Trigger condition: a `ContentStreamExec` event node and a high-risk outcome node
(`CodeExecution`, `NetworkEgress`, `FormSubmission`, or `ExternalLaunch`) are connected by a path
of length ≤ 3 in the event graph, AND at least one stream-op anomaly finding is
linked to the intermediate nodes.

Evidence metadata:
- `event.node_id`: the ContentStreamExec event node ID.
- `outcome.node_id`: the outcome node ID.
- `path.length`: edge count between them.
- `aligned.finding_ids`: comma-separated IDs of linked stream findings.

### S5.2 `content_stream_gstate_abuse` detector

**Finding kind**: `content_stream_gstate_abuse`
**Surface**: `AttackSurface::FileStructure`
**Severity**: `Medium`
**Confidence**: `Probable`

Trigger conditions (any one sufficient):
1. `q`/`Q` nesting exceeds depth 28 (common viewer implementation limit).
2. `Q` operator with no matching `q` (graphics state underflow — malformed stream).
3. `q` calls clustered immediately before `Do` operators targeting form XObjects
   (graphics-state sandboxing to isolate suspicious execution).

Metadata keys:
- `gstate.max_depth`: maximum nesting depth observed.
- `gstate.underflow_count`: number of unmatched `Q` operators.
- `gstate.do_sandwich_count`: count of `q`…`Do`…`Q` patterns around form XObject calls.
- `stream.obj`: `"{obj} {gen}"` of the content stream.

### S5.3 `content_stream_marked_evasion` detector

**Finding kind**: `content_stream_marked_evasion`
**Surface**: `AttackSurface::FileStructure`
**Severity**: `Medium`
**Confidence**: `Tentative`

Trigger condition: a `BMC`/`BDC` marked-content block contains a disproportionate fraction
of the stream's `Do` and `Tf` resource invocations (> 80% of resource ops inside ≤ 10% of
op count boundary) with no corresponding visible rendering operators (`Tj`, `TJ`, path
fills) inside the same boundary.

This pattern is used to concentrate payload invocations inside marked-content sections that
are invisible in accessible-document renderers but execute in standard renderers.

Metadata keys:
- `mc.tag`: the marked-content tag name.
- `mc.resource_op_fraction`: fraction of resource ops inside the boundary.
- `mc.visible_op_count`: count of visible rendering ops inside the boundary.
- `stream.obj`: `"{obj} {gen}"` of the content stream.

### S5.4 `content_stream_resource_name_obfuscation` detector

**Finding kind**: `content_stream_resource_name_obfuscation`
**Surface**: `AttackSurface::FileStructure`
**Severity**: `Low`
**Confidence**: `Tentative`

Trigger conditions (any one sufficient):
1. Resource name entropy in `Do`/`Tf` operands exceeds 4.5 bits/char (high-entropy names
   such as `/AABBBCCDD` instead of `/Im1` or `/F1`).
2. Resource names change on every page (high churn relative to document page count).
3. Resource name length > 32 characters without a common prefix pattern.

Metadata keys:
- `resource.name_max_entropy`: highest entropy resource name seen.
- `resource.churn_rate`: distinct names per page.
- `resource.max_name_length`: longest name observed.

### S5.5 Calibration

After implementing each detector, run the full corpus regression suite:

```
cargo test -p sis-pdf-core --test corpus_captured_regressions
```

Record false-positive rates against the clean fixture baseline. If any clean fixture triggers
a new finding, lower confidence to `Weak` or add an exclusion condition with a documented
rationale.

### S5.6 Tests

1. Integration test for each detector on a synthetic fixture designed to trigger it.
2. Integration test for each detector on a clean fixture — assert no finding emitted.
3. Correlator test: event graph path with aligned stream finding and outcome → composite
   finding emitted.
4. Correlator test: event graph with no stream finding → no composite.
5. Register any new fixtures in the corpus manifest with SHA-256 and provenance.

Acceptance criteria:
1. New detectors produce low false-positive rates on clean fixture baseline.
2. High-confidence findings align with connected event graph evidence.

## Stage 6: CLI, Docs, and Export Contracts

### S6.1 Query documentation

Update `docs/query-interface.md` with:
- `events.full` stream_exec section format and opt-in mechanism.
- New `graph.event.stream` query variants and their overlay node/edge schema.
- `graph.event.stream.hops N` hop limit behaviour.
- Examples for each new query type.

### S6.2 Findings documentation

Update `docs/findings.md` with the four new finding kinds (S5.1-S5.4): kind string,
surface, severity, confidence, and example metadata keys.

### S6.3 CSV schema

Add a section to the CSV schema draft (from the events plan follow-on) covering:
- Stream-operation summary row format (one row per ContentStreamExec event).
- Resource-ref detail row format (one row per Do/Tf invocation).
- These are separate from per-event rows and are opt-in.

Acceptance criteria:
1. All documentation updated before release.
2. CSV schema changes documented with field names, types, and nullability.

## New opportunities (out of scope, prioritised for follow-on)

### N1. `Do` operator chain recursion tracer

A form XObject's content stream can itself contain `Do` operators invoking nested form
XObjects, creating execution chains of arbitrary depth. A depth-limited tracer (max depth 8,
following the existing `DEFAULT_FINDING_DETAIL_MAX_HOPS` value) that follows `Do` chains
would produce a complete nested execution graph. Each level becomes a `ContentStreamExec`
event with `event_key = "xobject.form.nested.{depth}"`. This closes a significant gap for
PDFs that use layered form XObjects to conceal payload delivery paths.

### N2. Inline image anomaly detection

The `ID`/`EI` pair (inline image data) has special parser handling already. Inline images
that are abnormally large (> 64 KB of raw data), use suspicious filter chains (e.g.
`/Filter [/ASCII85Decode /FlateDecode]` rather than the expected `/DCTDecode`), or appear
in a content stream with no other text/path operators are a potential payload carrier signal.
A `content_stream_inline_image_anomaly` detector using the existing `span`-based position
data would not require any new parsing infrastructure.

### N3. Per-page execution surface summary query

A `sis query page-execution-summary <pdf>` command (or `sis query pages --include-streams`)
would provide for each page: number of content streams, total operator count by family, named
resources, anomaly flags, and linked finding IDs. Currently there is no single command that
gives this overview; analysts must cross-reference `events.full` output manually. This is the
natural surface for Stage 3's `StreamExecSummary` data.

### N4. Content stream fingerprinting

Each content stream has a characteristic operator profile — the ratio of text to path to
resource operators encodes both document purpose and generator behaviour. Computing a compact
fingerprint (e.g. a normalised histogram across the 6 operator families) and comparing
against a reference corpus of known-benign and known-malicious streams could provide a
standalone confidence signal without full analysis. The `StreamExecSummary` from Stage 3
already produces the input data for this fingerprint. This is a natural follow-on to Stage 3
once the projection layer is established.

### N5. Type3 font charproc attack surface detector

Type3 fonts define each glyph as a content stream in the `/CharProcs` dictionary. These
streams execute during text rendering and have historically been used to embed arbitrary
operators, including `Do` calls invoking form XObjects. A dedicated
`type3_charproc_suspicious_ops` detector checking charproc streams for non-drawing operators
(`Do`, `JS`, action-related operators) would close a gap not covered by the existing
`content_stream_anomaly` detector, which focuses on page-level content streams. This depends
on Stage 2's `include_type3_exec` infrastructure.

### N6. Cross-revision content stream diffing

For PDFs with incremental updates, the same page's content stream may be replaced in a later
revision. Comparing the operator-profile fingerprint (N4) of the original stream against the
replacement stream — detecting insertions of `Do` calls, new resource invocations, or
operator-family ratio shifts — would identify anti-forensic stream replacement. The revision
index already exists in the PDF graph (`revision_extract.rs`). This requires N4's fingerprint
infrastructure.

## Risks and Mitigations

1. Risk: graph explosion with per-op modelling.
   Mitigation: aggregate-by-default with named bounds (`STREAM_PROJ_MAX_OPS` = 1,000,
   `STREAM_PROJ_MAX_BYTES` = 64 KB), optional detail mode, strict caps and truncation flags
   in both projection and overlay.

2. Risk: Stage 1 `/Contents` fix changes existing event counts, breaking automation.
   Mitigation: Stage 0 non-regression test captures baseline; Stage 1 updates it explicitly.
   Default flags in Stage 2 ensure no additional change to default event counts.

3. Risk: GUI/core coupling via stream projection.
   Mitigation: all projection in `event_projection.rs` (core); GUI consumes `EventViewModel`
   only; the mapping in `event_view.rs` is a thin translation layer.

4. Risk: Stage 2 form XObject event IDs collide across runs.
   Mitigation: IDs are derived from typed graph object refs (deterministic); the `xobj` and
   `t3` namespace prefixes prevent collision with existing event counter scheme.

5. Risk: Stage 5 detectors have high false-positive rates on legitimate PDFs that use
   complex graphics (e.g. complex vector artwork with deep `q`/`Q` nesting).
   Mitigation: start with `Tentative` or `Probable` confidence; calibrate thresholds against
   clean corpus before raising; document exclusion conditions explicitly.

6. Risk: introducing projection options causes API churn for existing event projection callers.
   Mitigation: keep `extract_event_records(event_graph)` unchanged as a compatibility wrapper;
   add `extract_event_records_with_projection(...)` for opt-in callers only.

7. Risk: `SuspicionScore` addition in `GraphEdge` (Stage 4) breaks graph serialisation tests.
   Mitigation: keep the existing `suspicious: bool` field unchanged; add
   `suspicion_score` as an additive field and update tests incrementally.

## Out of Scope (for this plan)

1. Full symbolic execution of PDF graphics operators.
2. Rendering-equivalence engine across Acrobat/PDFium/PDF.js.
3. Manual analyst annotation workflows in-product.
4. `Do` chain recursion tracer (N1 — follow-on after Stage 2).
5. Inline image anomaly (N2 — follow-on after Stage 3).
6. Content stream fingerprinting (N4 — follow-on after Stage 3).

## Delivery Checklist

- [ ] Stage 0: baseline metrics recorded; non-regression test committed; `get_first` audit
      complete.
- [x] Stage 1: `/Contents` array coverage fixed; unit and integration tests passing.
- [ ] Stage 1 follow-up: baseline delta documented in Stage 0 metrics table.
- [ ] Stage 2: form XObject and Type3 execution surfaces behind `EventGraphOptions` flags;
      synthetic fixture tests passing.
- [ ] Stage 3: `StreamExecSummary` in `EventRecord`; `events.full` includes stream section;
      performance budget test passing.
- [ ] Stage 4: `graph.event.stream` query implemented; overlay node/edge schema documented;
      additive `SuspicionScore` field implemented with backward-compatible `suspicious: bool`.
- [ ] Stage 5: four detectors implemented and calibrated; correlator integrated in
      `correlation.rs`; corpus regression clean.
- [ ] Stage 6: `docs/query-interface.md`, `docs/findings.md`, and CSV schema updated.
