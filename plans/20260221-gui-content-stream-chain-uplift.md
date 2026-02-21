# GUI Uplift: Content Stream Execution Context and Chain Display Readability

Date: 2026-02-21
Status: Ready for implementation
Owner: GUI (`sis-pdf-gui`), core models (`sis-pdf-core`)

## Problem statement

Two related usability gaps identified while inspecting `20250820_120506_js_annot.pdf` in the GUI:

### Gap 1: "Content stream execution" node is unidentifiable

The `ContentStreamExec` event node in the graph viewer shows "Content stream execution" as its
label with no indication of which page triggers it or which stream object it executes. The
tooltip shows only "Type: event, Roles: ContentStreamExec, automatic". Double-clicking the node
navigates to the page object (`source_obj`) rather than the stream that will actually be
executed. An analyst cannot determine from the graph which stream object is involved without
manually tracing graph edges.

**Root cause (event_graph.rs:464):**
```rust
label: "Content stream execution".to_string(),
```
The stream destination (`edge.dst`) is known at node construction time but is not included in
the label or stored anywhere accessible to the GUI rendering layer. The `GraphNode.object_ref`
points to the source page object; the stream is only reachable by following the outgoing
`Executes` edge — an implicit relationship not surfaced in any tooltip or inspector field.

### Gap 2: Chain membership display is dense and uninformative

When viewing an object in the Object Inspector, the chain membership section shows:

```
Chain #8 [Participant] score 0.80    id=chain-ccf83f0c6f5c27325bf2...
Trigger:Document OpenAction present -> Action:JavaScript action [target: OpenAction ->
action [js_container] (8 0)] -> Payload:JavaScript present [intent=user_interaction]
[ref: -] [len: 34] layers=0
```

Two problems:
1. The `id=chain-<sha256 hash>` on the same line is pure noise — the chain index already
   provides a unique identifier for navigation.
2. The raw `chain.path` string uses internal rendering notation: `[ref: -]`, `[len: 34]`,
   `layers=0`, `(findings: 1)` — none of these are meaningful to an analyst at a glance.
   When chains have no resolved labels, they show `"unknown (findings: 1)"` three times.

The same issue appears in the Finding Detail panel, where chain membership entries display
"Chain #N: Trigger:X -> Action:Y -> Payload:Z" as a single long clickable label.

---

## Scope

In scope:
- ContentStreamExec node label enrichment (label text includes page and stream refs)
- `GraphNode.target_obj` field for navigation to stream on double-click
- Tooltip enrichment for ContentStreamExec nodes showing stream target
- Chain membership display in Object Inspector: remove hash ID, show structured
  trigger/action/payload or narrative in readable form
- Chain membership display in Finding Detail: same structural improvement

Out of scope:
- New detection logic
- Changes to chain scoring or synthesis
- Changes to chain panel (Chains window) — that panel's display is already structured and
  reasonable; improvements to it belong in a separate targeted plan
- Enriching stream content summary in the tooltip (stream filters, length) — that requires
  cross-referencing ObjectData during tooltip render; deferred

---

## Stage 1: ContentStreamExec node contextual enrichment

**Goal:** The ContentStreamExec node label and tooltip clearly identify the page and stream
objects involved. Double-clicking the node navigates to the stream object.

**Success criteria:**
- Node label reads "Content stream (page N M → stream P Q)" in the graph
- Hovering shows "Executes: obj P Q" in the tooltip
- Double-clicking navigates to the stream object in Object Inspector (not the page)
- All existing graph tests pass

### S1.1 Enrich ContentStreamExec label

**File:** `crates/sis-pdf-core/src/event_graph.rs`

Change the hardcoded label at line ~464 from:
```rust
label: "Content stream execution".to_string(),
```
to:
```rust
label: format!(
    "Content stream (page {} {} → stream {} {})",
    edge.src.0, edge.src.1, edge.dst.0, edge.dst.1
),
```

Both `edge.src` (page) and `edge.dst` (stream) are already in scope at this point. No
additional data lookups required.

### S1.2 Add target_obj to GraphNode

**File:** `crates/sis-pdf-gui/src/graph_data.rs`

Add a field to `GraphNode`:
```rust
pub struct GraphNode {
    pub object_ref: Option<(u32, u16)>,
    pub obj_type: String,
    pub label: String,
    pub roles: Vec<String>,
    pub confidence: Option<f32>,
    pub position: [f64; 2],
    /// For event nodes that execute a specific target object, the target's object ref.
    /// Populated via a post-pass over EventEdgeKind::Executes edges in from_event_graph.
    pub target_obj: Option<(u32, u16)>,
}
```

Initialise `target_obj: None` in all `GraphNode` construction sites (the `nodes.push(...)` calls
in `from_event_graph` and `build_graph`).

Add a post-pass in `from_event_graph` after the node-building loop (before adding edges to the
output):

```rust
// Post-pass: for event nodes, populate target_obj from their Executes edges.
for edge in &data.edges {
    if edge.kind != EventEdgeKind::Executes {
        continue;
    }
    let Some(&from_idx) = id_to_idx.get(&edge.from) else { continue };
    let Some(&to_idx) = id_to_idx.get(&edge.to) else { continue };
    if nodes[from_idx].obj_type == "event" {
        nodes[from_idx].target_obj = nodes[to_idx].object_ref;
    }
}
```

This is O(|edges|) and runs once after graph construction.

### S1.3 Update graph tooltip and double-click navigation

**File:** `crates/sis-pdf-gui/src/panels/graph.rs`

**Tooltip (around line 575):** Before the `egui::Tooltip::always_open` call, pre-extract the
`target_obj` from the graph node so it can be captured in the tooltip closure:

```rust
let target_obj = app.graph_state.graph.as_ref()
    .and_then(|g| g.nodes.get(hi))
    .and_then(|n| n.target_obj);
```

Inside the tooltip `.show(|ui| { ... })` closure, after the roles section, add:
```rust
if let Some((tobj, tgen)) = target_obj {
    ui.label(format!("Executes: obj {} {}", tobj, tgen));
    ui.small("Double-click to navigate to stream");
}
```

**Double-click handler (around line 643):** Replace:
```rust
if let Some((obj, gen)) = node.object_ref {
    app.navigate_to_object(obj, gen);
    app.show_objects = true;
}
```
with:
```rust
let nav_ref = node.target_obj.or(node.object_ref);
if let Some((obj, gen)) = nav_ref {
    app.navigate_to_object(obj, gen);
    app.show_objects = true;
}
```

This means double-clicking a ContentStreamExec node navigates to the stream, while all other
nodes retain their existing navigation behaviour.

### S1 Tests

**New unit test in `crates/sis-pdf-core/tests/`** (extend `graph_export` or add a targeted
module):

```rust
#[test]
fn content_stream_exec_label_includes_page_and_stream_refs() {
    // Build a minimal TypedGraph with a PageContents edge from page 3 0 to stream 7 0.
    // Call build_event_graph.
    // Assert that the resulting EventGraph contains a ContentStreamExec event node
    // whose kind label contains "3 0" and "7 0".
}
```

**Non-render test in `crates/sis-pdf-gui/` tests:**

```rust
#[test]
fn from_event_graph_populates_target_obj_for_executes_edges() {
    // Build a minimal EventGraph with:
    //   - Object node: "obj:3:0"
    //   - Event node: "ev:3:0:ContentStreamExec:0" (Event kind)
    //   - Object node: "obj:7:0"
    //   - Edge: obj:3:0 → ev:... (Triggers)
    //   - Edge: ev:... → obj:7:0 (Executes)
    // Call from_event_graph.
    // Find the event GraphNode.
    // Assert target_obj == Some((7, 0)).
    // Assert object_ref == Some((3, 0)).  // source page unchanged
}
```

---

## Stage 2: Chain membership display cleanup in Object Inspector

**Goal:** The chain membership section in the Object Inspector is readable and actionable.
Hash IDs are removed. Each chain entry shows a readable summary (narrative or structured
stages) with proper visual grouping.

**Success criteria:**
- No chain hash IDs displayed
- Each chain entry is visually grouped (e.g., via `ui.group`)
- Chains with a non-empty narrative show the narrative
- Chains with all-unknown stages show "Unresolved chain — see findings" rather than
  "unknown (findings: 1)" repeated three times
- Chains with resolved stages show `Trigger: ...` / `Action: ...` / `Payload: ...`
  on separate lines with truncation at ~80 characters

**File:** `crates/sis-pdf-gui/src/panels/objects.rs`

### S2.1 Pre-collect chain display data

In `show_security_context`, replace the current chain membership loop with a two-step
approach: first collect display data (reading from `app.result`), then render (writing to `app`
for click handlers).

Add a local struct and collection:

```rust
struct ChainEntry {
    chain_index: usize,
    role: ObjectChainRole,
    score: f64,
    narrative: String,
    trigger: String,
    action: String,
    payload: String,
    all_unknown: bool,
}
```

Before the render loop, build the entries:

```rust
let chain_entries: Vec<ChainEntry> = context.chains.iter().map(|m| {
    let (narrative, trigger, action, payload, all_unknown) =
        if let Some(chain) = app.result.as_ref()
            .and_then(|r| r.report.chains.get(m.chain_index))
        {
            let t = sis_pdf_core::chain_render::chain_trigger_label(chain);
            let a = sis_pdf_core::chain_render::chain_action_label(chain);
            let p = sis_pdf_core::chain_render::chain_payload_label(chain);
            let all_unknown = [&t, &a, &p].iter().all(|s| s.starts_with("unknown"));
            (chain.narrative.clone(), t, a, p, all_unknown)
        } else {
            (String::new(), String::new(), String::new(), String::new(), true)
        };
    ChainEntry {
        chain_index: m.chain_index,
        role: m.role,
        score: m.score,
        narrative,
        trigger,
        action,
        payload,
        all_unknown,
    }
}).collect();
```

### S2.2 Render improved chain entries

Replace the current render block with:

```rust
for entry in &chain_entries {
    ui.group(|ui| {
        let role = format_chain_role(entry.role);
        let header = format!(
            "Chain #{} [{}] score {:.2}",
            entry.chain_index + 1,
            role,
            entry.score
        );
        if ui.link(header).clicked() {
            app.selected_chain = Some(entry.chain_index);
            app.show_chains = true;
        }

        if entry.all_unknown {
            ui.small("Unresolved chain — see linked findings for details");
        } else if !entry.narrative.trim().is_empty() {
            // Show first sentence of narrative (truncated at ~100 chars)
            let summary = truncate_str(&entry.narrative, 100);
            ui.small(summary);
        } else {
            show_chain_stage_labels(ui, &entry.trigger, &entry.action, &entry.payload);
        }
    });
}
```

Add helpers:

```rust
fn truncate_str(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..s.floor_char_boundary(max)]  // use std::str::floor_char_boundary (stable 1.74+)
    }
}

fn show_chain_stage_labels(ui: &mut egui::Ui, trigger: &str, action: &str, payload: &str) {
    let stages = [("Trigger", trigger), ("Action", action), ("Payload", payload)];
    for (stage, text) in stages {
        if !text.is_empty() && !text.starts_with("unknown") {
            ui.horizontal(|ui| {
                ui.monospace(format!("{stage}:"));
                ui.small(truncate_str(text, 80));
            });
        }
    }
}
```

**Note on `floor_char_boundary`:** this was stabilised in Rust 1.74. If the toolchain is
earlier, use `s.char_indices().take_while(|(i, _)| *i < max).last().map_or(s, |(i, _)| &s[..i])`
as a fallback. Check Cargo.toml's `rust-version` to confirm.

### S2 Tests

No new integration tests for the render logic itself (GUI rendering tests are handled via
manual verification). Add a compile-time assertion by ensuring the `chain_entries` builder
compiles and that the helper functions have unit tests:

```rust
#[test]
fn truncate_str_handles_ascii_and_unicode() {
    assert_eq!(truncate_str("hello world", 5), "hello");
    // Unicode: do not panic or produce invalid UTF-8
    let long_unicode = "héllo";
    let result = truncate_str(long_unicode, 3);
    assert!(std::str::from_utf8(result.as_bytes()).is_ok());
}
```

Manual verification checklist:
- Load `20250820_120506_js_annot.pdf`
- Open Object Inspector, select object 3 0 (page)
- Confirm: no hash IDs visible; Chain #8 shows a readable trigger/action/payload summary
- Confirm: Chain #1 (all-unknown) shows "Unresolved chain — see linked findings for details"
- Confirm: clicking a chain link opens the Chains panel on that chain

---

## Stage 3: Chain membership display cleanup in Finding Detail

**Goal:** The chain membership section in Finding Detail shows each chain as a structured entry
(header link + brief summary) rather than a single long label containing the full path string.

**File:** `crates/sis-pdf-gui/src/panels/detail.rs`

### S3.1 Enrich chain_membership pre-extraction

Add a local struct:

```rust
struct ChainMemberDisplay {
    chain_index: usize,
    score: f64,
    narrative: String,
    trigger: String,
    action: String,
    payload: String,
    all_unknown: bool,
}
```

Replace the current chain_membership collection:
```rust
let chain_membership: Vec<(usize, String)> = result
    .report
    .chains
    .iter()
    .enumerate()
    .filter(|(_, chain)| chain.findings.contains(&finding_id))
    .map(|(i, chain)| (i, chain.path.clone()))
    .collect();
```
with:
```rust
let chain_membership: Vec<ChainMemberDisplay> = result
    .report
    .chains
    .iter()
    .enumerate()
    .filter(|(_, chain)| chain.findings.contains(&finding_id))
    .map(|(i, chain)| {
        let t = sis_pdf_core::chain_render::chain_trigger_label(chain);
        let a = sis_pdf_core::chain_render::chain_action_label(chain);
        let p = sis_pdf_core::chain_render::chain_payload_label(chain);
        let all_unknown = [&t, &a, &p].iter().all(|s| s.starts_with("unknown"));
        ChainMemberDisplay {
            chain_index: i,
            score: chain.score,
            narrative: chain.narrative.clone(),
            trigger: t,
            action: a,
            payload: p,
            all_unknown,
        }
    })
    .collect();
```

### S3.2 Update chain membership render block

In the chain membership collapsing section (around line 240), replace:
```rust
for (chain_idx, path) in &chain_membership {
    let label = format!("Chain #{}: {}", chain_idx + 1, path);
    if ui.link(&label).clicked() {
        app.show_chains = true;
        app.selected_chain = Some(*chain_idx);
    }
}
```
with:
```rust
for entry in &chain_membership {
    ui.group(|ui| {
        let header = format!("Chain #{} [score {:.2}]", entry.chain_index + 1, entry.score);
        if ui.link(header).clicked() {
            app.show_chains = true;
            app.selected_chain = Some(entry.chain_index);
        }
        if entry.all_unknown {
            ui.small("Unresolved chain — see findings for details");
        } else if !entry.narrative.trim().is_empty() {
            ui.small(truncate_str(&entry.narrative, 120));
        } else {
            show_chain_stage_labels(ui, &entry.trigger, &entry.action, &entry.payload);
        }
    });
}
```

Where `truncate_str` and `show_chain_stage_labels` are the helpers defined in Stage 2. These
can be extracted to a shared module `crates/sis-pdf-gui/src/chain_display.rs` to avoid
duplication between `objects.rs` and `detail.rs`.

### S3 Tests

Manual verification checklist:
- Load `20250820_120506_js_annot.pdf`
- Click a finding in the findings list (e.g., a js_present finding)
- Open Finding Detail panel
- Confirm: Chain Membership section shows "Chain #8 [score 0.80]" with readable trigger/action/
  payload on separate lines, not a single long concatenated string
- Confirm: "unknown" chains show fallback message rather than internal notation

---

## Shared module: chain_display.rs

To avoid code duplication between Stage 2 and Stage 3, extract the helpers into a shared
module:

**New file:** `crates/sis-pdf-gui/src/chain_display.rs`

Contents:
- `pub fn truncate_str(s: &str, max: usize) -> &str`
- `pub fn show_chain_stage_labels(ui: &mut egui::Ui, trigger: &str, action: &str, payload: &str)`
- `pub struct ChainSummaryDisplay` (if useful for sharing state between the two call sites)

Register in `crates/sis-pdf-gui/src/lib.rs` or `mod.rs`.

---

## Implementation sequence

1. **Stage 1.1** — label change in `event_graph.rs`. Trivial, no model impact.
2. **Stage 1.2** — add `target_obj` to `GraphNode` and populate in `from_event_graph`.
3. **Stage 1.3** — update tooltip and double-click in `panels/graph.rs`.
4. **Run tests:** `cargo test -p sis-pdf-core` (for label) and `cargo test -p sis-pdf-gui`.
5. **Stage 2** — chain display in `objects.rs` (extract helpers to `chain_display.rs`).
6. **Stage 3** — chain display in `detail.rs` (reuse helpers from `chain_display.rs`).
7. **Run full suite:** `cargo test -p sis-pdf-core -p sis-pdf-gui -p sis-pdf`.
8. **Manual verification** against `20250820_120506_js_annot.pdf` using both checklists above.

---

## Baseline

Run before starting:
```
cargo test -p sis-pdf-core --test graph_export
cargo test -p sis-pdf-gui
cargo test -p sis-pdf
cargo run -p sis-pdf --bin sis -- scan \
  crates/sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf \
  --deep --runtime-profile --runtime-profile-format json
```

Record any failures or timing deltas. Runtime profile SLOs (parse <10ms, detection <50ms) must
not regress.

---

## Definition of done

- [ ] ContentStreamExec node label includes source page and destination stream object refs
- [ ] Hovering over a ContentStreamExec node in the graph tooltip shows "Executes: obj N M"
- [ ] Double-clicking a ContentStreamExec node navigates to the stream object in Object Inspector
- [ ] `from_event_graph` populates `target_obj` for event nodes via Executes edges
- [ ] `GraphNode.target_obj` field exists and is `None` for non-event nodes
- [ ] Object Inspector chain membership: no chain hash IDs displayed
- [ ] Object Inspector chain membership: all-unknown chains show fallback text
- [ ] Object Inspector chain membership: resolved chains show structured stages or narrative
- [ ] Finding Detail chain membership: same improvements as Object Inspector
- [ ] Shared helpers in `chain_display.rs` with unit tests for `truncate_str`
- [ ] Unit test: ContentStreamExec label format verified
- [ ] Unit test: `target_obj` populated correctly from Executes edges
- [ ] `cargo test` passes with no regressions
- [ ] Manual verification against `20250820_120506_js_annot.pdf` complete
