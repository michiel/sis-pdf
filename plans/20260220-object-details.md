# Object Detail Context Uplift Plan: Taint and Chain Membership in GUI + CLI

Date: 2026-02-20
Status: Completed
Owner: GUI (`sis-pdf-gui`), CLI (`sis-pdf`), shared logic (`sis-pdf-core`)

## Goals

1. Make object-level investigation explicit: when analysts inspect an object, they should immediately see whether it is tainted, which revision introduced it, and whether it participates in one or more exploit chains.
2. Keep GUI and CLI behaviour consistent by deriving object context from one shared implementation path.
3. Preserve machine-parseable output for query tooling while improving human-readable detail for rapid triage.
4. Enable corpus-scale automation via an `object.context` query family that returns security context without rendering raw object content.

## Analyst problem statement

Current behaviour:
- GUI Object Inspector (`crates/sis-pdf-gui/src/panels/objects.rs`) shows related findings and object metadata, but not explicit taint status, taint propagation edges, chain membership summary, revision provenance, or similar-object clustering.
- CLI `obj <n> [gen]` (`Query::ShowObject` in `crates/sis-pdf/src/commands/query.rs`) prints raw object content only.

Operational impact:
- Analysts must manually pivot across findings/chains/graph to answer basic object-risk questions.
- Hidden relationships (distributed chains, indirect taint propagation, post-cert object introduction) are easy to miss.

## Scope

In scope:
- GUI Object Inspector detail panel enrichment with taint, chain, revision, and evidence-jump context.
- `sis query … 'obj.detail <n> [gen]'` new query verb returning structured object security context (text + JSON).
- `sis query … 'object.context <n> [gen]'` lightweight query verb (security context only, no raw content).
- Shared context derivation logic and deterministic tests.
- `finding_roles` storage on `ExploitChain` to enable reliable role assignment.
- Canonical `parse_obj_ref` utility in `sis-pdf-core` to eliminate divergent parsing implementations.
- Fixtures covering complex/distributed/fragmented object relationships.

Out of scope (this plan):
- New detector logic.
- Event graph rendering changes (covered in `plans/20260220-uplift.md`).
- New persistence format for scans beyond additive object-context fields.
- Changes to the existing `obj` query verb JSON shape (preserved unchanged; `obj.detail` is additive).

## Design principles

1. Single source of truth: derive object context once from `Report.findings`, `Report.chains`, and the extended `Taint` model.
2. Additive schema: no breaking field removals or semantic renames. Existing `obj` query JSON output is not altered.
3. Deterministic output: stable ordering for chain lists, taint edges, and reasons.
4. Fast on corpus workflows: object-context lookup is O(1) per query after a single report-level index build. No per-query derivation from findings.
5. WASM safe: index is built in the GUI main thread after `WorkerAnalysisResult` arrives; it is not built inside the worker and does not need to cross the worker message boundary.

## Sequencing dependency

This plan depends on `plans/20260220-uplift.md` **V3** (Taint source and propagation extension), which adds `taint_sources: Vec<(u32, u16)>` and `taint_propagation: Vec<((u32, u16), (u32, u16))>` to `Taint`. The context index consumes these fields directly.

Implementation note (2026-02-20): V3 is landed and authoritative. Legacy fallback derivation has been removed from runtime behaviour; `taint_propagation_unavailable` is retained as a compatibility field and remains `false`.

---

## Proposed technical design

### 0) Prerequisites: canonical object-ref parser and `finding_roles` on `ExploitChain`

#### Canonical `parse_obj_ref`

Multiple ad-hoc object-ref parsers exist in the codebase (`chain_synth.rs`, `panels/chains.rs::extract_obj_ref_from_text`). All object-context derivation must use a single function:

**File:** `crates/sis-pdf-core/src/object_ref.rs` (new, or added to an existing utilities module)

```rust
/// Parse "obj N M", "N M R", or "N M" into (obj, gen).
/// Returns None for any format that does not match.
pub fn parse_obj_ref(s: &str) -> Option<(u32, u16)> { ... }
```

Export from `sis-pdf-core/src/lib.rs`. All existing callers in `chain_synth.rs` and `panels/chains.rs` are updated to use this function. No new ad-hoc parsers.

#### `finding_roles` on `ExploitChain`

**File:** `crates/sis-pdf-core/src/chain.rs`

Add field:

```rust
/// Maps finding id to its role in this chain.
/// Values: "trigger", "action", "payload".
/// Only findings that filled a named role are present; others are participants.
#[serde(default)]
pub finding_roles: std::collections::HashMap<String, String>,
```

**File:** `crates/sis-pdf-core/src/chain_synth.rs`

In `finalize_chain`, populate `finding_roles` from `ChainRoles`:

```rust
if let Some(f) = roles.trigger_finding { chain.finding_roles.insert(f.id.clone(), "trigger".into()); }
if let Some(f) = roles.action_finding  { chain.finding_roles.insert(f.id.clone(), "action".into()); }
if let Some(f) = roles.payload_finding { chain.finding_roles.insert(f.id.clone(), "payload".into()); }
```

This is the only authoritative source of role-to-finding mapping. The context index reads it directly; no role re-derivation at query time.

### 1) Shared object context index in `sis-pdf-core`

**File:** `crates/sis-pdf-core/src/object_context.rs` (new)

#### Types

```rust
pub struct ObjectContextIndex {
    by_object: std::collections::HashMap<(u32, u16), ObjectSecurityContext>,
    /// Count of objects sharing each finding-kind fingerprint, for similar_count derivation.
    kind_set_counts: std::collections::HashMap<Vec<String>, usize>,
}

pub struct ObjectSecurityContext {
    pub obj: u32,
    pub gen: u16,

    // Finding summary
    pub finding_count: usize,
    pub max_severity: Option<Severity>,
    pub max_confidence: Option<Confidence>,
    /// Finding ids linked to this object, sorted by descending severity then id.
    pub finding_ids: Vec<String>,
    /// Per-severity finding counts for the confidence histogram.
    pub severity_histogram: std::collections::BTreeMap<String, usize>,

    // Taint
    pub tainted: bool,
    pub taint_source: bool,
    pub taint_incoming: Vec<(u32, u16)>,
    pub taint_outgoing: Vec<(u32, u16)>,
    /// Taint reasons linked to the finding id that generated each reason.
    pub taint_reasons: Vec<TaintReasonEntry>,
    /// True when taint_propagation data was unavailable (V3 not yet landed).
    pub taint_propagation_unavailable: bool,

    // Chain membership
    pub chains: Vec<ObjectChainMembership>,

    // Revision provenance
    /// Which incremental revision introduced this object (None if baseline or unknown).
    pub introduced_revision: Option<u32>,
    /// True when this object was introduced after a certification signature.
    pub post_cert: bool,

    // Evidence jump
    /// Offset of the highest-severity finding's first evidence span, for hex-viewer jump.
    pub top_evidence_offset: Option<u64>,
    /// Length of that span in bytes.
    pub top_evidence_length: Option<u32>,

    // Clustering
    /// Count of other objects with an identical sorted finding-kind fingerprint.
    pub similar_count: usize,
}

pub struct TaintReasonEntry {
    pub reason: String,
    /// Finding id that generated this reason, if traceable.
    pub finding_id: Option<String>,
}

pub struct ObjectChainMembership {
    pub chain_index: usize,
    pub chain_id: String,
    pub path: String,
    pub score: f64,
    pub role: ObjectChainRole,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ObjectChainRole {
    Trigger,
    Action,
    Payload,
    /// Object is a participant in the chain (appears in finding.objects for a chain finding)
    /// but does not fill a named trigger/action/payload role.
    Participant,
    /// Object appears in chain.nodes (a positional path entry) but not directly in finding.objects.
    PathNode,
}
```

Note on role naming: `Participant` and `PathNode` are distinct. `Participant` means the object is directly referenced by a finding that belongs to the chain. `PathNode` means the object appears only in position strings derived from the finding's location hierarchy, not as a direct participant.

#### API

```rust
/// Build the full index from a completed report. Call once per analysis result.
/// O(F + C) where F = findings count, C = chain count.
pub fn build_object_context_index(report: &Report, taint: &Taint) -> ObjectContextIndex;

/// Look up context for a specific object. O(1).
/// Returns a default empty context (tainted=false, no chains) if the object is not indexed.
pub fn get_object_context(index: &ObjectContextIndex, obj: u32, gen: u16) -> ObjectSecurityContext;

/// Returns true if any context entry exists for this object.
pub fn has_context(index: &ObjectContextIndex, obj: u32, gen: u16) -> bool;
```

The `object_context(report, obj, gen)` free function from the original design is **not added** — it would be O(N) per call and violates design principle 4. All callers use `get_object_context(index, obj, gen)`.

#### `build_object_context_index` implementation notes

**Finding pass:**
- For each finding, parse each `finding.objects` entry with `parse_obj_ref`.
- Accumulate `finding_count`, `max_severity`, `max_confidence`, `severity_histogram`, `finding_ids` per object.

**Taint pass:**
- If `taint.taint_sources` is non-empty (V3 landed): mark `taint_source=true` and `tainted=true` for each source object.
- Populate `taint_incoming`/`taint_outgoing` from `taint.taint_propagation` edges; mark both endpoints `tainted=true`.
- V3 taint data is consumed directly; no fallback taint-source derivation path is used.
- For `taint_reasons`: match each `Taint::reason` string back to the finding that produced it (same kind-matching logic). Emit `TaintReasonEntry { reason, finding_id: Some(f.id) }`. For reasons not traceable to a single finding, emit `finding_id: None`.

**Chain membership pass:**
- For each chain, iterate `chain.findings`:
  - For each finding id, look up the finding's objects via `finding.objects`.
  - Parse each object ref with `parse_obj_ref`.
  - Determine role from `chain.finding_roles.get(&finding_id)`: `"trigger"` → `Trigger`, `"action"` → `Action`, `"payload"` → `Payload`, absent → `Participant`.
  - Add `ObjectChainMembership` to each object's context.
- Then iterate `chain.nodes` (position path entries):
  - Parse with `parse_obj_ref`.
  - If the object already has a membership for this chain (from finding.objects pass), skip.
  - Otherwise add with role `PathNode`.
- Sort each object's `chains` by descending `score`, then `chain_index`.

**Revision pass:**
- For each finding with kind in `{incremental_update_chain, revision_forensics_present, shadow_hide_attack, shadow_replace_attack, object_id_shadowing}`:
  - Parse objects, read `meta["revision.index"]` as `u32`, read `meta["revision.post_cert"]` as bool.
  - Set `introduced_revision` and `post_cert` on each referenced object.

**Evidence jump pass:**
- For each object, among all linked findings pick the one with the highest severity.
- Set `top_evidence_offset` and `top_evidence_length` from `finding.evidence[0]` if present.

**Similar-count pass:**
- For each object, compute the sorted deduplicated set of finding kinds across its findings.
- Use `kind_set_counts` to count how many other objects share the same fingerprint.
- Set `similar_count = count - 1` (exclude self).

#### Replacement of `object_severity_index`

`plans/20260220-uplift.md` V8 adds `object_severity_index: HashMap<(u32, u16), (Severity, usize)>` to `AnalysisResult`. `ObjectSecurityContext` is a strict superset of that data (`max_severity` + `finding_count`). Once `ObjectContextIndex` is built, **derive** `object_severity_index` from it rather than maintaining a separate derivation:

```rust
result.object_severity_index = index.by_object.iter()
    .filter_map(|((obj, gen), ctx)| {
        ctx.max_severity.map(|s| ((*obj, *gen), (s, ctx.finding_count)))
    })
    .collect();
```

Document this in `analysis.rs` so future maintainers do not add a second severity derivation pass.

### 2) GUI Object Inspector integration

**Files:**
- `crates/sis-pdf-gui/src/analysis.rs`
- `crates/sis-pdf-gui/src/panels/objects.rs`

**WASM note:** The index is built in `AnalysisResult` construction code that runs in the GUI main thread after the `WorkerAnalysisResult` message arrives. It is not serialised across the worker boundary. The `build_object_context_index` call happens alongside other post-processing (e.g. `object_severity_index` derivation) in the main-thread result handling.

**`AnalysisResult` addition in `analysis.rs`:**

```rust
pub object_context_index: sis_pdf_core::object_context::ObjectContextIndex,
```

Built immediately after `object_severity_index` is populated (and replaces its separate derivation as described above).

**`panels/objects.rs` additions in `show_object_detail`:**

Look up `ctx = get_object_context(&result.object_context_index, obj, gen)` and render a `Security context` section with:

*Summary chips (always shown, including explicit negatives):*
```
Taint: [source] / [propagated] / [not tainted]
Chains: N  |  Severity: High  |  Confidence: Strong
Revision: Rev 2 (post-cert)   |  Similar objects: 12
```

*Collapsible: Taint details*
- Each `TaintReasonEntry` rendered as: "reason — [finding_id link]" when `finding_id` is present.
- Incoming taint edges: clickable object-ref links via `navigate_to_object`.
- Outgoing taint edges: same.
- `taint_propagation_unavailable` remains present for compatibility and is expected to stay `false` under V3.

*Collapsible: Chain membership*
- One row per `ObjectChainMembership`: role badge, chain path, score, chain-id link.
- Clicking a row: `app.selected_chain = Some(chain_index); app.show_chains = true`.

*Evidence jump button (when `top_evidence_offset` is present):*
- "Jump to evidence (0x{offset}, {length} bytes)" — sets `app.hex_view.jump_to` and `app.show_hex = true`, using the `HexJumpTarget` struct from V7.

*Graph: focus taint neighbourhood button:*
- "Focus taint neighbourhood in graph" — sets `app.graph_state.show_taint_overlay = true`, `app.show_graph = true`, then scrolls/selects the current object in the graph view.

Acceptance detail:
- If an object has no context, show explicit negatives (`Not tainted`, `No chain membership`, `No revision data`) rather than empty sections.
- Context section renders in < 1 ms additional time over existing Object Inspector render (O(1) lookup, no iteration at render time).

### 3) CLI query uplift

**Decision: preserve `obj` JSON unchanged; introduce two new verbs**

The existing `obj <n> [gen]` query verb JSON output (plain object content string) is **not changed**. This avoids any risk of breaking downstream consumers.

Two new query verbs are added:

**`obj.detail <n> [gen]`** — full object content plus structured security context:

Text output appends an `Object security context` block after the existing raw content.

JSON output:
```json
{
  "type": "object_detail",
  "object_detail_schema_version": 1,
  "object": { "obj": 2, "gen": 0, "content": "<<dict content>>" },
  "security_context": {
    "tainted": true,
    "taint_source": false,
    "taint_incoming": [[6, 0]],
    "taint_outgoing": [],
    "taint_reasons": [
      { "reason": "JavaScript present", "finding_id": "finding-abc123" }
    ],
    "taint_propagation_unavailable": false,
    "finding_count": 3,
    "max_severity": "High",
    "max_confidence": "Strong",
    "finding_ids": ["finding-abc123", "finding-def456"],
    "severity_histogram": { "High": 1, "Medium": 2 },
    "chains": [
      { "chain_index": 0, "chain_id": "chain-xyz", "role": "Payload",
        "score": 0.85, "path": "Trigger:open_action_present -> Action:js_present -> Payload:javascript" }
    ],
    "introduced_revision": 2,
    "post_cert": true,
    "top_evidence_offset": 12345,
    "top_evidence_length": 64,
    "similar_count": 3
  }
}
```

Schema versioned via `object_detail_schema_version: 1` at the response level.

**`object.context <n> [gen]`** — security context only, no raw object content. Enables corpus-scale automation:

```
sis query corpus/*.pdf 'object.context 6 0' --format jsonl
```

Returns one JSONL line per file:
```json
{ "file": "sample.pdf", "obj": 6, "gen": 0, "tainted": true, "chain_count": 2, "max_severity": "High", "introduced_revision": 2, "post_cert": true, "similar_count": 3 }
```

Text output: compact single-line summary per file.

**`--context-only` flag on `obj.detail`:**

```
sis query sample.pdf 'obj.detail 6 0' --context-only
```

Skips the raw object content section in both text and JSON output. Useful for very large stream objects where content is not needed.

**Files:** `crates/sis-pdf/src/commands/query.rs`

Add `Query::ShowObjectDetail` and `Query::ShowObjectContext` variants alongside the existing `Query::ShowObject`. Wire them through the existing query dispatch path.

### 4) Documentation updates

**Files:**
- `docs/query-interface.md` — document `obj.detail`, `object.context`, `--context-only`, JSON schema with field definitions.
- `docs/forensic-workflows.md` — add object triage workflow example: inspect → pivot to chain → jump to hex evidence → filter by revision.
- `docs/analysis.md` — if object workflow section exists, update with context fields.

---

## Test and fixture plan

### Core tests

**File:** `crates/sis-pdf-core/tests/object_context.rs`

Test cases:
1. Object with direct taint source (`taint_source=true`, `tainted=true`) and chain role `Payload` via `finding_roles`.
2. Object tainted only via propagation edge — not in `taint_sources`, appears in `taint_propagation`; `tainted=true`, `taint_source=false`.
3. Compatibility guard: context output retains `taint_propagation_unavailable`, and V3 paths keep it `false`.
4. Object in multiple chains with different roles; chain list sorted stably by descending score then `chain_index`.
5. Object appearing in `finding.objects` (role `Participant`) vs. appearing only in `chain.nodes` (role `PathNode`) — both covered, roles distinct.
6. Object absent from findings/chains returns default context with all fields zeroed/false, deterministically.
7. `taint_reasons` entries include `finding_id` when traceable, `None` when not.
8. `introduced_revision` and `post_cert` populated from revision finding metadata.
9. `top_evidence_offset` set from highest-severity finding's first evidence span.
10. `similar_count` correctly reflects other objects with identical finding-kind fingerprint.
11. `similar_count = 0` for an object with a unique finding-kind fingerprint.
12. `parse_obj_ref` unit tests: "obj 6 0", "6 0 R", "6 0", invalid inputs.

**`finding_roles` tests** in `crates/sis-pdf-core/tests/chain_grouping.rs`:
- Chain synthesised from trigger + action + payload findings has all three in `finding_roles`.
- Single-finding chain has correct role in `finding_roles`.
- Findings not assigned a named role are absent from `finding_roles`.

### GUI tests

**File:** `crates/sis-pdf-gui/src/analysis.rs`
- `object_context_index` is built after result construction.
- `object_severity_index` is derived from `object_context_index`, not built independently.

**File:** `crates/sis-pdf-gui/src/panels/objects.rs`
- Security context chips render correct text for tainted/untainted/source/propagation-only cases.
- Chain row click sets `show_chains=true` and `selected_chain` to correct index.
- Evidence jump button sets `hex_view.jump_to` correctly.
- Graph focus button sets `show_taint_overlay=true` and `show_graph=true`.
- `taint_propagation_unavailable` remains `false` for V3 scans.

### CLI tests

**File:** `crates/sis-pdf/tests/` (integration) and `commands/query.rs` unit tests:
1. `obj.detail` text output includes security context block with taint and chain fields.
2. `obj.detail` JSON output has `type="object_detail"`, `object_detail_schema_version=1`, and all context fields.
3. `object.context` JSONL output contains compact summary fields only (no raw content).
4. `obj.detail --context-only` omits raw object content in both text and JSON.
5. Existing `obj <n> [gen]` JSON output is unchanged (regression guard).
6. `OBJ_NOT_FOUND` error behaviour unchanged for all three verbs.

### Fixture requirements

**Reuse fixtures from `plans/20260220-uplift.md`** where the three shared families are defined (complex/distributed, revision-shadow, multi-reader divergence). Do not create duplicate fixtures. Add object-context-specific regression assertions to each existing fixture:
- Complex/distributed: assert `Participant` and `PathNode` roles are correctly distinguished; assert `similar_count > 0` for repeated-pattern objects.
- Revision-shadow: assert `introduced_revision`, `post_cert` correct for shadowed objects.
- Multi-reader divergence: assert chain membership exists for the object regardless of reader profile.

If the shared fixtures have not yet been created (uplift plan Phase 4 not landed), create them here and register in `crates/sis-pdf-core/tests/fixtures/corpus_captured/manifest.json`. The uplift plan Phase 4 then reuses rather than recreates them.

For each fixture:
- Update `manifest.json` with `path`, `sha256`, `source_path`, `regression_targets`.
- Add provenance notes in `crates/sis-pdf-core/tests/fixtures/corpus_captured/README.md`.

---

## Performance and quality gates

| Metric | Target | Benchmark test |
|---|---|---|
| Index build (10,000 findings + 2,000 chains) | ≤ 20 ms | `cargo test -p sis-pdf-core object_context_build_budget -- --nocapture` |
| `get_object_context` lookup | ≤ 1 ms | asserted inline in unit tests (HashMap lookup) |
| `obj.detail` query overhead vs `obj` | ≤ 5 ms | `cargo test -p sis-pdf execute_query_object_detail_budget -- --nocapture` |
| Object Inspector context section render delta | ≤ 1 ms additional | manual verification against CVE fixture |
| `object.context` JSONL for 100k-finding corpus | ≤ 3 s | `cargo test -p sis-pdf object_context_corpus_budget -- --nocapture` |

All benchmark tests are explicit deliverables of Phase 1 and Phase 3 respectively.

Commands:
```
cargo test -p sis-pdf-core --test object_context -- --nocapture
cargo test -p sis-pdf-core --test chain_grouping -- --nocapture
cargo test -p sis-pdf execute_query_supports_object_detail_security_context -- --nocapture
cargo test -p sis-pdf-gui
```

---

## Implementation phases

### Phase 1: Prerequisites and shared context engine

1. Add `parse_obj_ref` canonical utility to `sis-pdf-core`; update existing callers.
2. Add `finding_roles: HashMap<String, String>` to `ExploitChain`; populate in `finalize_chain`.
3. Add `object_context.rs` types and `build_object_context_index` in `sis-pdf-core`.
4. Add deterministic unit tests including all 12 core cases and `finding_roles` tests.
5. Export module and `parse_obj_ref` from `lib.rs`.
6. Add index-build benchmark test.

Exit criteria:
- Context for any `(obj, gen)` can be queried with deterministic ordering.
- `finding_roles` populated correctly on synthesised chains.
- All Phase 1 tests pass.

### Phase 2: GUI Object Inspector

1. Build `object_context_index` in `AnalysisResult`; derive `object_severity_index` from it.
2. Render context section in Object Inspector (chips, taint collapsible, chain collapsible, evidence jump button, graph focus button).
3. Add GUI tests for state transitions and chip labels.
4. Manual verification: CVE fixture shows correct context with no render regression.

Exit criteria:
- Object Inspector always shows taint/chain/revision context block.
- `object_severity_index` derived from `object_context_index`, not built separately.

### Phase 3: CLI query uplift

1. Add `Query::ShowObjectDetail` and `Query::ShowObjectContext` variants.
2. Implement text and JSON output for both verbs, including `--context-only`.
3. Add/adjust unit and integration tests; add query output budget test.
4. Confirm existing `obj` JSON output is unchanged via regression guard test.

Exit criteria:
- `sis query <pdf> 'obj.detail n g'` surfaces full context.
- `sis query <pdf> 'object.context n g'` returns compact context without object content.
- Existing `obj` consumers unaffected.

### Phase 4: Fixtures, docs, and hardening

1. Create or reuse shared fixture families; register in manifest; add object-context assertions.
2. Update `docs/query-interface.md`, `docs/forensic-workflows.md`, `docs/analysis.md`.
3. Run full targeted test matrix.
4. Confirm V3-only taint context derivation remains in place.

Exit criteria:
- Coverage includes complex/distributed/fragmented, revision-shadow, and multi-reader patterns.
- Docs include working CLI examples and GUI workflow description.

---

## Risks and mitigations

1. **Risk:** Divergent GUI/CLI logic if each computes context separately.
   - **Mitigation:** `sis-pdf-core` shared index only. `build_object_context_index` is the single derivation path.

2. **Risk:** Existing `obj` JSON consumers break.
   - **Mitigation:** `obj` verb JSON output is explicitly frozen. New verbs (`obj.detail`, `object.context`) carry the structured output. Regression guard test asserts `obj` output shape is unchanged.

3. **Risk:** Chain role misclassification.
   - **Mitigation:** Roles read from `chain.finding_roles` (authoritative, set at synthesis time). No heuristic re-derivation. `Participant` is the explicit fallback for findings without a named role. `PathNode` reserved for position-path-only appearances.

4. **Risk:** WASM index build unavailable (built inside worker, not serialisable across boundary).
   - **Mitigation:** Index is built in the main thread after `WorkerAnalysisResult` arrives, as part of `AnalysisResult` post-processing alongside other indices. Documented explicitly in the WASM note under section 2.

5. **Risk:** V3 taint model fields regress or are bypassed in future changes.
   - **Mitigation:** Keep integration coverage around taint sources/propagation and assert compatibility field behaviour stays deterministic.

6. **Risk:** `similar_count` computation expensive on large corpora.
   - **Mitigation:** Kind-set fingerprint counted in a single pass over the index during `build_object_context_index`. O(F log F) total. No per-query computation.

---

## Definition of done

1. `parse_obj_ref` canonical utility exists in `sis-pdf-core`; existing callers updated.
2. `ExploitChain` carries `finding_roles`; populated correctly in `chain_synth.rs`.
3. `ObjectContextIndex` and `ObjectSecurityContext` implemented with all fields including revision provenance, evidence jump, similar-count, and linked taint reasons.
4. `object_context_index` built in `AnalysisResult`; `object_severity_index` derived from it.
5. GUI Object Inspector shows taint/chain/revision context section with evidence jump and graph focus navigation.
6. `obj.detail` and `object.context` query verbs implemented with text and JSON output.
7. `--context-only` flag implemented on `obj.detail`.
8. Existing `obj` JSON output is unchanged (regression guard test passing).
9. `object_detail_schema_version: 1` present in `obj.detail` JSON output.
10. All unit, integration, and budget tests pass.
11. Shared fixtures created or reused; registered in manifest with object-context regression assertions.
12. Docs updated with query examples and forensic workflow.

## Implementation readiness checklist

- [x] Output-shape decision resolved: `obj` frozen, `obj.detail` and `object.context` are new additive verbs.
- [x] Land `parse_obj_ref` utility and update callers.
- [x] Land `finding_roles` on `ExploitChain`.
- [x] Land shared context module with all tests.
- [x] Integrate GUI inspector with cross-panel navigation and evidence jump.
- [x] Implement CLI verbs and machine-readable schema tests.
- [x] Add fixture families + manifest entries + provenance docs.
- [x] Derive `object_severity_index` from `object_context_index`; remove separate derivation.
- [x] Update docs and run targeted test commands.
- [x] Confirm V3 taint model status; remove fallback if landed.
