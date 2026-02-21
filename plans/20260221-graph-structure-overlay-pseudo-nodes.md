# Optional Structure Overlay Plan: Trailer and Forensic Pseudo Nodes

Date: 2026-02-21
Status: Ready for implementation
Owner: core (`sis-pdf-core`, `sis-pdf-pdf`), CLI (`sis-pdf`)

## Problem statement

`graph.structure` and `graph.org` currently model edges derived from indirect object bodies. Trailer/xref/startxref/revision context exists in `ObjectGraph`, but is not represented as graph nodes/edges. This creates a forensic visibility gap:

- trailer-linked objects (for example `/Info`) can appear isolated in structural graphs;
- analysts cannot see provenance links such as trailer-to-root, startxref-to-section, or section-to-trailer in one graph view;
- connected-component/path-based analysis can under-represent structure rooted outside object bodies.

## Assumptions

1. Default behaviour remains unchanged unless overlay is explicitly requested.
2. Output schemas remain deterministic and consistent across runs.
3. Validation is strict and automated (unit + integration tests), with manual checks supplemental only.
4. Existing query contracts (`graph.structure`, `graph.org`, `xref.*`, `revisions.*`) remain backward compatible.
5. Overlay logic remains GUI-agnostic; no `egui` coupling outside GUI crates.

## Goals

1. Add an optional, explicit overlay that augments structure graphs with pseudo nodes/edges for trailer/xref/revision provenance.
2. Preserve current graph semantics and output by default.
3. Improve forensic traceability without inflating false-positive risk or runtime unpredictability.

## Non-goals

1. Replacing existing typed edge extraction for object-body relationships.
2. Changing finding severity policy in this work item.
3. Introducing non-deterministic enrichment from external tools.

## Exploration findings (current state)

### Finding 1: Trailer links are available but not part of structural graph edges

Evidence:
- metadata lookup resolves `/Info` from trailer then `get_object()` (`crates/sis-pdf/src/commands/query.rs`).
- typed graph extraction iterates `graph.objects` only (`crates/sis-pdf-pdf/src/typed_graph.rs`).
- base adjacency is built from object atoms only (`crates/sis-pdf-core/src/graph_walk.rs`).

Impact:
- forensic visibility gap for trailer-anchored relationships.

Recommendation:
- add pseudo node `trailer.<idx>` with typed overlay edges to `/Root`, `/Info`, `/Encrypt`, `/Prev` target (if resolvable).

### Finding 2: Xref/startxref section data exists in `ObjectGraph` but is disconnected from graph views

Evidence:
- `ObjectGraph` stores `startxrefs`, `xref_sections`, `trailers`.
- `xref.*` queries expose these records, but structure graph does not.

Impact:
- analysts must correlate multiple commands manually.

Recommendation:
- include optional chain: `file.root -> startxref.<i> -> xref.section.<i> -> trailer.<i>`.

### Finding 3: Revision timeline already exists and is queryable

Evidence:
- revision timeline and detail are available via `revisions` / `revisions.detail`.

Impact:
- provenance is rich but not represented in graph form.

Recommendation:
- add optional `revision.<n>` pseudo nodes linked to `startxref` and changed object refs (summary-only first).

### Finding 4: Provenance for ObjStm/carved objects exists but is not graph-visible

Evidence:
- `ObjEntry.provenance` includes `ObjStm { obj, gen }` and `CarvedStream { obj, gen }`.

Impact:
- hidden-container and carved-origin context is not visible in graph overlays.

Recommendation:
- optional provenance edges from pseudo nodes `objstm.<obj>.<gen>` and `carved.<obj>.<gen>` to produced objects.

## Pseudo-node candidate inventory

Priority levels: P1 (implement now), P2 (next), P3 (later/optional)

1. `trailer.<idx>` (P1)
- Source data: `ctx.graph.trailers`
- Edges:
  - `trailer.<idx> -> <obj gen>` (`trailer_root`, `trailer_info`, `trailer_encrypt`)
  - `trailer.<idx> -> trailer.<prev_idx>` when `/Prev` maps to known section/trailer
- Value: high forensic clarity for `/Info` and root resolution.

2. `startxref.<idx>` (P1)
- Source data: `ctx.graph.startxrefs`
- Edges:
  - `file.root -> startxref.<idx>`
  - `startxref.<idx> -> xref.section.<j>` by offset match
- Value: explicit revision anchor points.

3. `xref.section.<idx>` (P1)
- Source data: `ctx.graph.xref_sections`
- Edges:
  - `xref.section.<idx> -> trailer.<k>` when section has trailer
  - optionally `xref.section.<idx> -> xref.section.<prev>` when prev resolvable
- Value: exposes table/stream/unknown section provenance in one graph.

4. `revision.<n>` (P2)
- Source data: `build_revision_timeline()`
- Edges:
  - `revision.<n> -> startxref.<idx>`
  - `revision.<n> -> <obj>` for changed object refs (capped)
- Value: high-value temporal forensics; needs edge caps for scale.

5. `objstm.<obj>.<gen>` (P2)
- Source data: `ObjProvenance::ObjStm`
- Edges:
  - `objstm.<container> -> <expanded_obj>` (`objstm_contains`)
- Value: exposes hidden object-stream expansion paths.

6. `carved.<obj>.<gen>` (P2)
- Source data: `ObjProvenance::CarvedStream`
- Edges:
  - `carved.<carrier> -> <carved_obj>` (`carved_from_stream`)
- Value: makes recovery heuristics auditable.

7. `telemetry.<idx>` (P3)
- Source data: `ctx.graph.telemetry_events`
- Edges:
  - to related pseudo/object nodes when object_ref is available
- Value: useful but noisy; lower priority.

8. `signature.<idx>` (P3)
- Source data: revision/signature boundary summary
- Edges:
  - `signature.<idx> -> revision.<n>` coverage links
- Value: strong forensic context; defer due to cross-module coupling.

## Design recommendations

1. Keep overlay out of baseline queries by default:
- add explicit query variants (recommended):
  - `graph.structure.overlay.json`
  - `graph.structure.overlay.dot`
- keep existing `graph.structure*` unchanged.

2. Use a dedicated overlay model to avoid churn:
- new lightweight structs in core export path:
  - `OverlayNode { id, kind, attrs }`
  - `OverlayEdge { from, to, edge_type, suspicious, attrs }`
- merge overlay into export payload under a dedicated key:
  - JSON: `overlay: { nodes: [...], edges: [...], stats: ... }`
  - DOT: separate subgraph cluster for pseudo nodes.

3. Deterministic and bounded output:
- stable ordering by index/ID.
- cap high-cardinality edges (`revision -> objects`, telemetry links).
- emit truncation metadata fields (`overlay.truncated`, counts).

4. Ensure overlay is analysis-only:
- pseudo nodes must not participate in exploit-path scoring unless explicitly enabled later.

## Staged implementation

### Stage 1: Trailer/startxref/xref overlay (P1)

Files:
- `crates/sis-pdf/src/commands/query.rs`
- `crates/sis-pdf-core/src/org_export.rs`
- optional helper module: `crates/sis-pdf-core/src/structure_overlay.rs`

Work:
1. Add new query parse variants for overlay output.
2. Build overlay nodes/edges from `startxrefs`, `xref_sections`, `trailers`.
3. Extend structure JSON/DOT exporters to include optional overlay payload/cluster.
4. Add summary stats fields for forensic scripting.

Tests:
1. parse-query coverage for new overlay commands.
2. structure overlay JSON includes trailer->info/root edges for fixture with `/Info`.
3. baseline `graph.structure.json` remains unchanged when overlay not requested.

### Stage 2: Provenance and revision pseudo nodes (P2)

Files:
- `crates/sis-pdf/src/commands/query.rs`
- `crates/sis-pdf-core/src/structure_overlay.rs`

Work:
1. Add optional provenance overlays from `ObjProvenance` (ObjStm/carved).
2. Add `revision.<n>` nodes with bounded changed-object fanout.
3. Add truncation metadata and deterministic ordering tests.

Tests:
1. ObjStm fixture: overlay emits `objstm_contains` edges.
2. revision fixture: overlay emits revision anchors and bounded changed-object links.
3. large fixture: cap enforcement and truncation metadata asserted.

### Stage 3: Extended pseudo nodes (P3, optional)

Work:
1. Evaluate telemetry and signature pseudo nodes behind separate flags.
2. Add only if signal-to-noise remains acceptable in corpus tests.

Tests:
1. telemetry overlay is deterministic and bounded.
2. no regression in runtime profile SLO for standard structure queries.

## Risks and mitigations

1. Risk: output churn breaks downstream tooling.
- Mitigation: new explicit overlay query variants; no default schema changes.

2. Risk: graph noise reduces analyst usability.
- Mitigation: staged rollout (P1 first), caps, and pseudo-node clustering in DOT.

3. Risk: performance overhead on large corpora.
- Mitigation: O(n) overlay construction, bounded fanout, runtime-profile regression checks.

## Validation plan

1. `cargo test -p sis-pdf parse_query_supports_org_and_ir_aliases -- --nocapture`
2. add targeted query tests for overlay variants in `crates/sis-pdf/src/commands/query.rs` tests.
3. `cargo test -p sis-pdf query -- --nocapture`
4. runtime profile check on Stage 1 fixture:
- `sis scan crates/sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf --deep --runtime-profile --runtime-profile-format json`

## Success criteria

1. Analysts can request a single overlay graph that shows trailer/startxref/xref provenance links.
2. `/Info`-referenced objects are visibly connected via overlay edges when requested.
3. Default structure graph outputs remain byte-for-byte stable for existing tests.
4. Overlay output remains deterministic, bounded, and covered by automated tests.
