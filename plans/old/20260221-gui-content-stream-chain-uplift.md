# GUI Uplift: Content Stream Execution Context and Chain Display Readability

Date: 2026-02-21
Status: Ready for implementation
Owner: GUI (`sis-pdf-gui`), core models (`sis-pdf-core`)

## Problem statement

Two related usability gaps identified while inspecting `20250820_120506_js_annot.pdf` in the GUI:

### Gap 1: `ContentStreamExec` node lacks execution context

The event graph shows `ContentStreamExec` nodes as `Content stream execution`, without explicit
page or stream identifiers. Tooltip and navigation do not make the executed stream obvious.

### Gap 2: Chain membership display is dense and inconsistent

Object Inspector and Finding Detail currently expose raw/internal chain strings (`chain.path`,
hash IDs, repeated `unknown (findings: N)` tokens) instead of concise analyst-oriented summaries.

---

## Assumptions confirmed

1. Keep current navigation behaviour for all non-`ContentStreamExec` nodes.
2. Chain membership presentation should be consistent across Object Inspector and Finding Detail.
3. Validation must be strict and automated; manual checks are supplemental only.

---

## Review findings incorporated (opportunities and recommendations)

1. Avoid navigation regressions:
   - Populate and use stream target only for `ContentStreamExec`, not all `Executes` events.
2. Reduce `GraphNode` churn and future breakage:
   - Add `Default` for `GraphNode`.
   - Use `..Default::default()` struct update syntax in literals, especially tests.
3. Enforce automated coverage for presentation logic:
   - Extract deterministic formatting/selection logic into testable helper functions.
   - Add GUI crate unit/integration tests for selection, fallback, and truncation.
4. Remove fragile `starts_with("unknown")` checks:
   - Add structured stage-summary API in core (`chain_render`) to expose unresolved/resolved states.
5. Prevent `egui` leakage into non-GUI builds:
   - Place shared UI helpers under `crates/sis-pdf-gui/src/panels/chain_display.rs`.
   - Register via `crates/sis-pdf-gui/src/panels/mod.rs` only (feature-gated surface).
6. Keep panel output consistent:
   - Use one shared render helper path for both Object Inspector and Finding Detail.
7. Clarify narrative rendering semantics:
   - Use explicit wording: “truncated narrative summary”, not “first sentence” unless sentence split is implemented.
8. Control core label impact:
   - If changing core event label text, add/update tests to lock intended format and avoid accidental drift.

---

## Scope

In scope:
- `ContentStreamExec` node label enrichment with page/stream refs.
- `GraphNode.target_obj` support scoped to `ContentStreamExec`.
- Tooltip enrichment showing execution target.
- Chain membership display cleanup in Object Inspector and Finding Detail.
- Shared chain display logic for consistent rendering across both panels.
- Structured chain stage-summary support to avoid string-prefix heuristics.
- Automated test coverage for all behaviour above.

Out of scope:
- New detection logic.
- Changes to chain scoring/synthesis.
- Changes to Chains panel (`panels/chains.rs`) beyond link navigation.
- Deep stream metadata enrichment in graph tooltip.

---

## Stage 1: `ContentStreamExec` contextual enrichment (no cross-event regression)

Goal: `ContentStreamExec` nodes show clear page/stream context, with stream navigation on
double-click only for this event type.

### S1.1 Label enrichment in core event graph

**File:** `crates/sis-pdf-core/src/event_graph.rs`

Update `ContentStreamExec` node label to include both refs:

```rust
label: format!(
    "Content stream (page {} {} -> stream {} {})",
    edge.src.0, edge.src.1, edge.dst.0, edge.dst.1
),
```

### S1.2 Extend `GraphNode` with safe defaults and targeted navigation metadata

**File:** `crates/sis-pdf-gui/src/graph_data.rs`

Add:
- `#[derive(Default)]` on `GraphNode`
- `pub target_obj: Option<(u32, u16)>`
- `pub is_content_stream_exec: bool`

Populate `is_content_stream_exec` while mapping event nodes in `from_event_graph`.
Populate `target_obj` in a post-pass only when:
- edge kind is `EventEdgeKind::Executes`
- `from` node is an event node
- `from` node has `is_content_stream_exec == true`

Use `..Default::default()` in all `GraphNode` literals to minimise compile churn.

### S1.3 Tooltip and double-click behaviour in graph panel

**File:** `crates/sis-pdf-gui/src/panels/graph.rs`

- Tooltip: show `Executes: obj N M` only when `node.is_content_stream_exec` and `target_obj` exists.
- Double-click: navigate to `target_obj` only for `ContentStreamExec`; otherwise keep existing
  `object_ref` navigation.

### S1 automated tests

1. `crates/sis-pdf-core/tests/...`:
   - `content_stream_exec_label_includes_page_and_stream_refs`
2. `crates/sis-pdf-gui/tests/...`:
   - `from_event_graph_sets_target_obj_only_for_content_stream_exec`
   - `from_event_graph_non_content_stream_exec_keeps_target_obj_none`
   - `graph_double_click_prefers_target_only_for_content_stream_exec` (logic-level test via extracted helper)

---

## Stage 2: Shared chain display model and helpers (feature-safe)

Goal: one shared, testable display path with no `egui` leakage into non-GUI builds.

### S2.1 Add structured stage summary API in core

**File:** `crates/sis-pdf-core/src/chain_render.rs`

Add a structured helper to eliminate prefix matching:

```rust
pub struct ChainStageSummary {
    pub trigger: Option<String>,
    pub action: Option<String>,
    pub payload: Option<String>,
    pub all_unresolved: bool,
}

pub fn chain_stage_summary(chain: &ExploitChain) -> ChainStageSummary { ... }
```

Rules:
- unresolved stages become `None`
- `all_unresolved` is authoritative
- existing `chain_*_label` functions remain for compatibility

### S2.2 Add GUI shared display module under panels

**New file:** `crates/sis-pdf-gui/src/panels/chain_display.rs`

Expose:
- `pub struct ChainSummaryDisplay`
- `pub fn truncate_str(s: &str, max: usize) -> &str`
- `pub fn summary_from_chain(...) -> ChainSummaryDisplay`
- `pub fn render_chain_summary(ui: &mut egui::Ui, summary: &ChainSummaryDisplay, ...)`

Register only in `crates/sis-pdf-gui/src/panels/mod.rs` to keep `egui` in GUI-gated modules.
Do not register this module in top-level `crates/sis-pdf-gui/src/lib.rs`.

### S2 automated tests

1. `crates/sis-pdf-core`:
   - `chain_stage_summary_marks_all_unresolved`
   - `chain_stage_summary_exposes_resolved_stages`
2. `crates/sis-pdf-gui`:
   - `truncate_str_handles_ascii_and_unicode_boundaries`
   - `summary_from_chain_uses_unresolved_fallback_when_all_unresolved`
   - `summary_from_chain_prefers_narrative_then_stages`

---

## Stage 3: Object Inspector chain membership cleanup (consistent output path)

**File:** `crates/sis-pdf-gui/src/panels/objects.rs`

Replace ad-hoc chain rendering with shared `chain_display` helpers:
- remove hash ID (`chain_id`) display
- render grouped entries (`ui.group`)
- use consistent header format:
  - `Chain #N [Role] score X.XX`
- show:
  - fallback message when `all_unresolved`
  - otherwise truncated narrative summary when present
  - otherwise structured Trigger/Action/Payload lines

All formatting decisions must call shared helpers, not local duplicates.

### S3 automated tests

- `object_inspector_chain_entries_use_shared_summary_model`
- `object_inspector_chain_link_selects_expected_chain_index`

---

## Stage 4: Finding Detail chain membership cleanup (same rendering contract)

**File:** `crates/sis-pdf-gui/src/panels/detail.rs`

Replace `(usize, String)` chain membership extraction with shared `ChainSummaryDisplay`.

Render using the same helper path as Stage 3 so behaviour stays consistent.

### S4 automated tests

- `finding_detail_chain_entries_use_shared_summary_model`
- `finding_detail_chain_link_selects_expected_chain_index`
- `finding_detail_and_object_inspector_chain_headers_match_for_same_input`

---

## Implementation sequence

1. Baseline test/profile run (see Baseline section).
2. Stage 1 core+GUI graph changes and tests.
3. Stage 2 core structured summary API and GUI shared module.
4. Stage 3 Object Inspector migration and tests.
5. Stage 4 Finding Detail migration and tests.
6. Full workspace test run.
7. Manual verification on fixture PDF as final confidence check.

---

## Baseline

Run before starting:

```bash
cargo test -p sis-pdf-core --test graph_export
cargo test -p sis-pdf-core --test event_graph_outcomes
cargo test -p sis-pdf-gui
cargo test -p sis-pdf
cargo run -p sis-pdf --bin sis -- scan \
  crates/sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf \
  --deep --runtime-profile --runtime-profile-format json
```

Record failures and timing deltas. Runtime profile SLOs (parse <10ms, detection <50ms) must not regress.

---

## Manual verification checklist (supplemental)

Fixture: `20250820_120506_js_annot.pdf`

1. Event graph:
   - `ContentStreamExec` node label includes page and stream refs.
   - Tooltip shows execution target object.
   - Double-click on `ContentStreamExec` opens stream object.
   - Double-click on other event nodes retains existing source-object behaviour.
2. Object Inspector chain membership:
   - no hash IDs shown
   - grouped entries
   - unresolved fallback appears when expected
   - resolved entries show concise narrative or stage lines
3. Finding Detail chain membership:
   - same structure and wording as Object Inspector for equivalent chain input
   - chain link navigation opens Chains panel at selected chain

---

## Definition of done

- [ ] Assumptions documented and implemented exactly.
- [ ] `ContentStreamExec` label includes source page and destination stream refs.
- [ ] Graph tooltip shows target object for `ContentStreamExec`.
- [ ] Double-click navigation changes only for `ContentStreamExec`; other event behaviour unchanged.
- [ ] `GraphNode` has `Default`; literals use struct update syntax to avoid broad churn.
- [ ] `target_obj` population is scoped to `ContentStreamExec`.
- [ ] Core has structured chain stage summary API (no `starts_with("unknown")` logic in GUI).
- [ ] Shared chain display module exists at `crates/sis-pdf-gui/src/panels/chain_display.rs`.
- [ ] No `egui` imports leak into non-GUI build paths.
- [ ] Object Inspector and Finding Detail use the same chain-summary rendering contract.
- [ ] Chain hash IDs removed from Object Inspector and Finding Detail.
- [ ] Automated tests added for graph behaviour, summary derivation, truncation safety, and panel consistency.
- [ ] `cargo test -p sis-pdf-core -p sis-pdf-gui -p sis-pdf` passes.
- [ ] Manual verification checklist completed.
