# Object Detail Context Uplift Plan: Taint and Chain Membership in GUI + CLI

Date: 2026-02-20
Status: Ready for implementation
Owner: GUI (`sis-pdf-gui`), CLI (`sis-pdf`), shared logic (`sis-pdf-core`)

## Goals

1. Make object-level investigation explicit: when analysts inspect an object, they should immediately see whether it is tainted and whether it participates in one or more exploit chains.
2. Keep GUI and CLI behaviour consistent by deriving object context from one shared implementation path.
3. Preserve machine-parseable output for query tooling while improving human-readable detail for rapid triage.

## Analyst problem statement

Current behaviour:
- GUI Object Inspector (`crates/sis-pdf-gui/src/panels/objects.rs`) shows related findings and object metadata, but not explicit taint status, taint propagation edges, or chain membership summary.
- CLI `obj <n> [gen]` (`Query::ShowObject` in `crates/sis-pdf/src/commands/query.rs`) prints raw object content only.

Operational impact:
- Analysts must manually pivot across findings/chains/graph to answer basic object-risk questions.
- Hidden relationships (distributed chains, indirect taint propagation) are easy to miss.

## Scope

In scope:
- GUI Object Inspector detail panel enrichment with taint + chain context.
- CLI `obj` output enrichment (text + structured JSON path).
- Shared context derivation logic and deterministic tests.
- Fixtures covering complex/distributed/fragmented object relationships.

Out of scope (this plan):
- New detector logic.
- Event graph rendering changes.
- New persistence format for scans beyond additive object-context fields.

## Design principles

1. Single source of truth: derive object context once from `Report.findings`, `Report.chains`, and taint propagation.
2. Additive schema: no breaking field removals or semantic renames.
3. Deterministic output: stable ordering for chain lists, taint edges, and reasons.
4. Fast on corpus workflows: object-context lookup should be near O(1) after one report-level index build.

## Proposed technical design

### 1) Shared object context index in `sis-pdf-core`

Add a new module:
- `crates/sis-pdf-core/src/object_context.rs`

Proposed types:

```rust
pub struct ObjectContextIndex {
    by_object: std::collections::HashMap<(u32, u16), ObjectSecurityContext>,
}

pub struct ObjectSecurityContext {
    pub obj: u32,
    pub gen: u16,
    pub finding_count: usize,
    pub max_severity: Option<Severity>,
    pub tainted: bool,
    pub taint_source: bool,
    pub taint_incoming: Vec<(u32, u16)>,
    pub taint_outgoing: Vec<(u32, u16)>,
    pub taint_reasons: Vec<String>,
    pub chains: Vec<ObjectChainMembership>,
}

pub struct ObjectChainMembership {
    pub chain_index: usize,
    pub chain_id: String,
    pub path: String,
    pub score: f64,
    pub role: ObjectChainRole,
}

pub enum ObjectChainRole {
    Trigger,
    Action,
    Payload,
    PathNode,
    Unknown,
}
```

Proposed API:

```rust
pub fn build_object_context_index(report: &Report) -> ObjectContextIndex;
pub fn object_context(report: &Report, obj: u32, gen: u16) -> ObjectSecurityContext;
```

Implementation notes:
- Use existing object-ref parser logic (shared helper) for finding objects and chain node refs.
- Derive taint from `taint::taint_from_findings(&report.findings)` and mark:
  - `taint_source` if object is in `taint_sources`
  - `tainted` if source or appears in `taint_propagation` edges
- Populate `chains` from `report.chains`:
  - `PathNode` when object appears in `chain.nodes`
  - Promote role to `Trigger`/`Action`/`Payload` when matching `chain.trigger`, `chain.action`, `chain.payload`, or corresponding `notes` keys.
- Keep ordering stable:
  - sort chain memberships by descending `score`, then `chain_index`
  - sort taint edge refs ascending

### 2) GUI Object Inspector integration

Files:
- `crates/sis-pdf-gui/src/analysis.rs`
- `crates/sis-pdf-gui/src/panels/objects.rs`

Changes:
- Build and store an `object_context_index` in `AnalysisResult` alongside `object_severity_index`.
- In `show_object_detail` / `show_object_meta`:
  - add `Security context` section with concise chips/labels:
    - `Tainted: yes/no`
    - `Taint source: yes/no`
    - `Chain membership: N`
    - `Highest severity: ...` when present
  - add collapsible sections:
    - `Taint propagation` (incoming/outgoing refs with links)
    - `Chain membership` (chain id, role, score, path; clickable to open Chains panel + select chain)
- Reuse existing navigation idioms (`navigate_to_object`, `selected_chain`, `show_chains`) for zero-friction pivots.

Acceptance detail:
- If an object has no context, show explicit negatives (`Not tainted`, `No chain membership`) instead of empty sections.

### 3) CLI `obj` query uplift

Files:
- `crates/sis-pdf/src/commands/query.rs`

Changes:
- Keep current raw object rendering.
- Append an `Object security context` block in text/readable output for `Query::ShowObject`:
  - tainted / taint source / taint incoming/outgoing counts
  - finding count + max severity
  - chain membership summary with chain id/index, role, score, path
- For JSON/YAML modes, return a structured object for `ShowObject` instead of plain string scalar:

```json
{
  "type": "object_detail",
  "object": { "obj": 2, "gen": 0, "content": "..." },
  "security_context": { ...ObjectSecurityContext... }
}
```

Compatibility guard:
- Because this changes JSON shape for `obj`, gate it with explicit tests and document in query docs.
- Optional conservative fallback: introduce `obj.detail` for structured output and keep `obj` scalar JSON unchanged. Decide at implementation time after checking downstream query consumers.

### 4) Documentation updates

Files:
- `docs/query-interface.md`
- `docs/forensic-workflows.md`
- `docs/analysis.md` (if object workflow section exists)

Content:
- document object context fields and interpretation.
- include examples for GUI and CLI (`sis query sample.pdf 'obj 2 0'`).

## Test and fixture plan

### Core tests

Add:
- `crates/sis-pdf-core/tests/object_context.rs`

Test cases:
1. Object with direct taint source and chain role `Payload`.
2. Object tainted only via propagation edge (not direct finding object).
3. Object in multiple chains with different roles; ordering stable by score.
4. Object absent from findings/chains returns empty context deterministically.

### GUI tests

Add unit coverage in:
- `crates/sis-pdf-gui/src/analysis.rs` (index build)
- `crates/sis-pdf-gui/src/panels/objects.rs` (pure helper formatting/selection mapping)

Assertions:
- context chips reflect state correctly.
- chain row click sets `show_chains=true` and `selected_chain` appropriately.

### CLI tests

Extend `crates/sis-pdf/src/commands/query.rs` tests:
1. `obj` text output includes security context block.
2. JSON output includes `type=object_detail` and context fields (or `obj.detail` if conservative path chosen).
3. Object-not-found error behaviour unchanged (`OBJ_NOT_FOUND`).

### Fixture requirements (mandatory)

Add fixtures under `crates/sis-pdf-core/tests/fixtures/corpus_captured/` and register in manifest:
1. Complex/distributed/fragmented chain fixture where one object is:
   - not the trigger,
   - reached through intermediate objects,
   - present in multiple chain stages.
2. Revision-shadow fixture where taint appears in later revision object only.
3. Multi-reader divergence fixture where chain membership exists but reader-risk differs across findings.

For each fixture:
- update `manifest.json` with `path`, `sha256`, `source_path`, `regression_targets`.
- add regression assertions for taint + chain membership invariants.

## Performance and quality gates

1. Add benchmark-style test in `sis-pdf-core` for index build on large synthetic reports:
- target: <= 20 ms for 10,000 findings + 2,000 chains on dev baseline hardware.

2. CLI object query budget:
- `obj` query overhead from context derivation should be <= 5 ms after context index availability.

3. GUI interaction:
- Object Inspector detail render should remain responsive (<16 ms frame budget for typical fixture).

Proposed commands:
- `cargo test -p sis-pdf-core --test object_context -- --nocapture`
- `cargo test -p sis-pdf execute_query_supports_object_detail_security_context -- --nocapture`
- `cargo test -p sis-pdf-gui`

## Implementation phases

### Phase 1: Shared context engine

1. Add `object_context.rs` types + builder in `sis-pdf-core`.
2. Add deterministic unit tests.
3. Export module in `lib.rs`.

Exit criteria:
- Context for any `(obj, gen)` can be queried with deterministic ordering.

### Phase 2: GUI Object Inspector

1. Add context index to `AnalysisResult` build path.
2. Render context in Object Inspector.
3. Add GUI tests for state transitions and labels.

Exit criteria:
- Object Inspector always shows taint/chain status block.

### Phase 3: CLI `obj` enrichment

1. Integrate context lookup in `Query::ShowObject` execution.
2. Update text and structured output.
3. Add/adjust parser/output tests.

Exit criteria:
- `sis query <pdf> 'obj n g'` surfaces taint and chain membership directly.

### Phase 4: Fixtures, docs, and hardening

1. Add required fixtures + manifest and regression tests.
2. Update docs and examples.
3. Run full targeted test matrix.

Exit criteria:
- Coverage includes complex/distributed/fragmented real-world patterns.

## Risks and mitigations

1. Risk: Divergent GUI/CLI logic if each computes context separately.
- Mitigation: `sis-pdf-core` shared index only; no duplicated derivation.

2. Risk: JSON consumer breakage for `obj` query shape changes.
- Mitigation: either additive wrapper with clear `type`, or introduce `obj.detail` and preserve current `obj` JSON scalar.

3. Risk: Chain role misclassification from free-form notes/path strings.
- Mitigation: prefer structured refs (`nodes`, parsed refs from canonical fields), use `Unknown` fallback, and test adversarial text.

## Opportunities for improvement

1. Add `object.context` and `object.context.count` query family for corpus-scale automation without rendering full object atoms.
2. Surface per-object confidence envelope (max confidence and confidence histogram across linked findings).
3. Add object-context export in findings-with-chain responses (`--with-chain`) to speed pivoting in external tools.
4. Extend graph integration with one-click “focus taint neighbourhood” from Object Inspector.
5. Add optional `--context-only` flag for `obj` query to skip raw object content on very large objects.
6. Add schema version marker for object-detail structured output (`object_detail_schema_version`) if JSON shape expands.
7. Add divergence-aware chain role field (`reader_variant_role`) for objects whose role changes by reader profile.

## Implementation readiness checklist

- [ ] Confirm output-shape decision for JSON `obj` (`obj` vs `obj.detail`).
- [ ] Land shared context module with tests.
- [ ] Integrate GUI inspector and cross-panel links.
- [ ] Integrate CLI output and machine-readable schema tests.
- [ ] Add fixture families + manifest entries + provenance docs.
- [ ] Update docs and run targeted test commands.
