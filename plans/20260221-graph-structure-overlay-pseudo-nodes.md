# Structure Overlay Plan: Trailer and Forensic Pseudo Nodes

Date: 2026-02-21
Status: Ready for implementation
Owner: core (`sis-pdf-core`, `sis-pdf-pdf`), CLI (`sis-pdf`)

## Problem statement

`graph.structure` and `graph.org` model edges derived from indirect object bodies only.
Trailer/xref/startxref/revision context exists in `ObjectGraph`, but is not represented as
graph nodes or edges. This creates a forensic visibility gap:

- trailer-linked objects (for example `/Info`) can appear isolated in structural graphs;
- analysts cannot see provenance links such as trailer-to-root, startxref-to-section, or
  section-to-trailer in one graph view;
- connected-component and path-based analysis under-represents structure rooted outside object
  bodies.

---

## Assumptions

1. Default behaviour remains unchanged unless overlay is explicitly requested.
2. Output schemas remain deterministic and consistent across runs.
3. Validation is strict and automated (unit + integration tests), with manual checks
   supplemental only.
4. Existing query contracts (`graph.structure`, `graph.org`, `xref.*`, `revisions.*`) remain
   backward compatible.
5. Overlay logic remains GUI-agnostic; no `egui` coupling outside GUI crates.
6. GUI integration of overlay data is explicitly out of scope for this plan. The overlay
   serialisation format is designed so a future plan can wire it into `AnalysisResult` and
   surface it in the GUI graph viewer without requiring model changes here.

---

## Goals

1. Add an optional, explicit overlay that augments structure graphs with pseudo nodes/edges
   for trailer/xref/revision provenance.
2. Preserve current graph semantics and output by default.
3. Improve forensic traceability without inflating false-positive risk or runtime unpredictability.

## Non-goals

1. Replacing existing typed edge extraction for object-body relationships.
2. Changing finding severity policy in this work item.
3. Introducing non-deterministic enrichment from external tools.
4. GUI graph viewer integration (deferred to a follow-on plan once overlay model is stable).

---

## Exploration findings (current state)

### Finding 1: Trailer links are available but not part of structural graph edges

Evidence:
- metadata lookup resolves `/Info` from trailer then `get_object()` (`crates/sis-pdf/src/commands/query.rs`).
- typed graph extraction iterates `graph.objects` only (`crates/sis-pdf-pdf/src/typed_graph.rs`).
- base adjacency is built from object atoms only (`crates/sis-pdf-core/src/graph_walk.rs`).
- `ctx.graph.trailers: Vec<PdfDict<'a>>` holds lifetime-bound dict references into raw bytes;
  key lookups are possible via `PdfAtom` methods but resolution to object IDs requires
  `graph.get_object()`.

Impact: forensic visibility gap for trailer-anchored relationships.

Recommendation: add pseudo node `trailer.<idx>` with typed overlay edges to `/Root`, `/Info`,
`/Encrypt`, and `/Prev` targets (if resolvable; see fail-closed specification below).

### Finding 2: Xref/startxref section data exists but is disconnected from graph views

Evidence:
- `ObjectGraph` stores `startxrefs: Vec<u64>`, `xref_sections: Vec<XrefSectionSummary>`,
  `trailers: Vec<PdfDict<'a>>`.
- `xref.*` queries expose these records, but structure graph does not.
- `XrefSectionSummary.kind` is a runtime `String` (not a typed enum). The plan pins the
  exact string values in use: `"table"`, `"stream"`, `"unknown"`. The overlay builder must
  consume these strings via a typed conversion function so changes in the emitter propagate
  cleanly.

Impact: analysts must correlate multiple commands manually.

Recommendation: optional chain `startxref.<i> -> xref.section.<j> -> trailer.<k>`, anchored
at `file.root` (see pseudo-node inventory). The linkage between `startxref.<i>` and
`xref.section.<j>` is by byte-offset exact match only; no nearest-match or tolerance
window. If no xref section matches a startxref offset, emit a `startxref.<i>` node with
no outgoing xref-section edge and annotate it `{ "match": false }` in attrs.

### Finding 3: Revision timeline already exists and is queryable

Evidence:
- `build_revision_timeline()` in `crates/sis-pdf-core/src/revision_timeline.rs` builds
  `RevisionTimeline { revisions: Vec<RevisionRecord>, ... }`.
- `RevisionRecord` carries startxref offset, changed object refs, and `post_cert: bool`.
- Timeline is available via `revisions` / `revisions.detail` queries.

Impact: provenance is rich but not in graph form.

Recommendation: `revision.<n>` pseudo nodes built directly from `RevisionTimeline`, not by
re-deriving from raw `startxrefs`. The revision→startxref link matches on the offset stored
in `RevisionRecord`. Changed-object edges are capped at **50 per revision node** (see edge
cap section).

### Finding 4: ObjStm provenance exists but is not graph-visible

Evidence:
- `ObjEntry.provenance` includes `ObjStm { obj, gen }` and `CarvedStream { obj, gen }`.
- `EdgeType::ObjStmReference` already exists in `typed_graph.rs` and is emitted for objects
  defined in ObjStm containers.

Impact: hidden-container and carved-origin context is not visible in graph overlays.

Recommendation for Stage 2: the `objstm.<obj>.<gen>` overlay pseudo-node is additive over the
typed `ObjStmReference` edge. The typed edge records a direct reference; the overlay pseudo-node
provides a named anchor for the container object as a navigable graph node separate from its
object body representation. Both coexist. `carved.<obj>.<gen>` has no existing counterpart and
is purely additive.

---

## Data availability at query execution

All source data needed for the overlay is available via `ctx.graph` at all `ExportStructure*`
query execution points (query.rs lines 2443–2488):

| Field | Available | Used by |
|---|---|---|
| `ctx.graph.trailers` | yes | trailer pseudo-nodes (P1) |
| `ctx.graph.startxrefs` | yes | startxref pseudo-nodes (P1) |
| `ctx.graph.xref_sections` | yes | xref.section pseudo-nodes (P1) |
| `ctx.graph.objects` → provenance | yes | ObjStm/carved pseudo-nodes (P2) |
| `build_revision_timeline(&ctx, N)` | yes (call on demand) | revision pseudo-nodes (P2) |
| `ctx.graph.telemetry_events` | yes | telemetry pseudo-nodes (P3) |

No additional scan passes are required.

---

## Fail-closed specification for trailer key resolution

When building trailer pseudo-node edges, attempt to resolve `/Root`, `/Info`, `/Encrypt`,
`/Prev` from each `PdfDict<'a>` entry in `ctx.graph.trailers`:

1. Parse the dict key value as a PDF indirect reference (pattern: `N G R`).
2. Call `ctx.graph.get_object(n, g)` to confirm object exists.
3. If found: emit `trailer.<idx> -> <n> <g>` overlay edge with the appropriate `edge_type`.
4. If not found (missing or shadowed object): do not emit the edge. Record the unresolved
   reference in the `trailer.<idx>` node's `unresolved: Vec<String>` attr field.
5. For `/Prev`: value is a byte offset, not an object reference. Resolve to a `startxref.<j>`
   node by exact offset match. If no match: emit no edge; set `prev_unresolved: true` in attrs.

This ensures fail-closed behaviour: missing or corrupt trailer links produce annotated nodes
with no phantom edges.

---

## Pseudo-node candidate inventory

Priority levels: P1 (implement now), P2 (next), P3 (later/optional)

### 0. `file.root` (P1 — virtual document anchor)

This pseudo-node is a virtual anchor for the document's parse entry point. It does not
correspond to any PDF object. It provides a stable graph root from which startxref chains hang.

- ID: `file.root` (exactly one per overlay)
- Attrs: `{ "kind": "file_root" }`
- Edges out: `file.root -> startxref.<i>` for each `i` (one edge per startxref)
- Edge type: `file_root_to_startxref`

### 1. `trailer.<idx>` (P1)

- Source data: `ctx.graph.trailers[idx]`
- Attrs:
  ```
  {
    "kind": "trailer",
    "idx": usize,
    "has_root": bool,
    "has_info": bool,
    "has_encrypt": bool,
    "size": Option<u64>,          // /Size field if present
    "unresolved": Vec<String>,    // key names that could not be resolved
    "prev_unresolved": bool,
  }
  ```
- Edges out (only when target object confirmed via `get_object`):
  - `trailer.<idx> -> <obj gen>` (edge_type: `trailer_root`) for `/Root`
  - `trailer.<idx> -> <obj gen>` (edge_type: `trailer_info`) for `/Info`
  - `trailer.<idx> -> <obj gen>` (edge_type: `trailer_encrypt`) for `/Encrypt`
  - `trailer.<idx> -> startxref.<j>` (edge_type: `trailer_prev`) for `/Prev` (offset match)
- Value: high forensic clarity for `/Info` and root resolution.

### 2. `startxref.<idx>` (P1)

- Source data: `ctx.graph.startxrefs[idx]`
- Attrs:
  ```
  {
    "kind": "startxref",
    "idx": usize,
    "offset": u64,
    "section_match": bool,     // true if a matching xref.section was found
  }
  ```
- Edges out:
  - `startxref.<idx> -> xref.section.<j>` (edge_type: `startxref_to_section`) — only when
    `ctx.graph.xref_sections[j].offset == startxrefs[idx]` (exact match)
- Edges in: `file.root -> startxref.<idx>` (from anchor)
- Value: explicit revision anchor points.

### 3. `xref.section.<idx>` (P1)

- Source data: `ctx.graph.xref_sections[idx]`
- `XrefSectionSummary.kind` (String) is converted via:
  ```rust
  enum XrefSectionKind { Table, Stream, Unknown }
  fn parse_xref_kind(s: &str) -> XrefSectionKind { match s { "table" => Table, "stream" => Stream, _ => Unknown } }
  ```
  This function lives in `structure_overlay.rs` so kind-string changes propagate through one
  point.
- Attrs:
  ```
  {
    "kind": "xref_section",
    "idx": usize,
    "offset": u64,
    "section_kind": "table" | "stream" | "unknown",
    "has_trailer": bool,
    "prev": Option<u64>,         // raw /Prev offset, included for auditability
    "trailer_size": Option<u64>,
    "trailer_root": Option<String>,
  }
  ```
- Edges out:
  - `xref.section.<idx> -> trailer.<k>` (edge_type: `section_to_trailer`) when
    `xref_sections[idx].has_trailer == true` and a matching trailer is identified. Trailer
    matching uses position order: trailer `k` corresponds to section `k` in the sequence
    built during `build_object_graph` (the same order both vecs are populated). If cardinality
    diverges, match by index with a bounds check; any section without a matched trailer emits
    no edge.
  - `xref.section.<idx> -> xref.section.<prev_idx>` (edge_type: `section_prev`) when
    `prev: Option<u64>` can be resolved to another section's offset (exact match).
- Value: exposes table/stream/unknown section provenance in one graph.

### 4. `revision.<n>` (P2)

- Source data: `build_revision_timeline(&ctx, cap)` → `RevisionRecord`
- Attrs:
  ```
  {
    "kind": "revision",
    "n": usize,
    "startxref_offset": u64,
    "post_cert": bool,
    "changed_object_count": usize,   // total, before cap
    "changed_object_edge_count": usize,  // emitted (after cap)
    "truncated": bool,
  }
  ```
- `post_cert: true` nodes receive `suspicious: true` on all their outgoing changed-object
  edges (mirrors the existing `GraphEdge.suspicious` mechanism).
- Edge cap: **50 changed-object edges per revision node**. When `changed_object_count > 50`,
  emit 50 edges, set `truncated: true`, and record `changed_object_count` in attrs for
  downstream scripting.
- Edges out:
  - `revision.<n> -> startxref.<j>` (edge_type: `revision_to_startxref`) matched by offset
  - `revision.<n> -> <obj gen>` (edge_type: `revision_changed_object`, suspicious when
    post_cert) for each changed object ref (capped at 50)
- Value: high-value temporal forensics.

### 5. `objstm.<obj>.<gen>` (P2)

- Source data: `ObjProvenance::ObjStm { obj, gen }` on `ObjEntry` records
- Additive over the existing `EdgeType::ObjStmReference` typed edge (which records a direct
  reference). The overlay pseudo-node provides a named container anchor as a distinct graph
  node. Both coexist without conflict.
- Attrs: `{ "kind": "objstm", "container_obj": u32, "container_gen": u16, "contained_count": usize }`
- Edges out: `objstm.<container> -> <expanded_obj gen>` (edge_type: `objstm_contains`) for
  each object with matching provenance
- Value: exposes hidden object-stream expansion paths.

### 6. `carved.<obj>.<gen>` (P2)

- Source data: `ObjProvenance::CarvedStream { obj, gen }` on `ObjEntry` records
- No existing typed edge counterpart; purely additive.
- Attrs: `{ "kind": "carved", "carrier_obj": u32, "carrier_gen": u16, "carved_count": usize }`
- Edges out: `carved.<carrier> -> <carved_obj gen>` (edge_type: `carved_from_stream`)
- Value: makes recovery heuristics auditable.

### 7. `detached` cluster (P2 — new)

Objects with in-degree zero in the structure graph that are not reachable from any trailer
`/Root` or `/Info` ref are forensically significant (hidden payloads, stale containers, dangling
JS). The overlay emits them as a group for scripting convenience.

- Not a traditional pseudo-node; modelled as a metadata field on the overlay stats:
  ```json
  "detached_objects": [
    { "obj": 5, "gen": 0, "obj_type": "stream" },
    ...
  ]
  ```
  Capped at 100 entries. If count exceeds 100, include `"detached_truncated": true` and
  `"detached_total": N` in stats.
- No graph edges emitted for detached objects — they are enumerated, not connected, to avoid
  polluting graph topology.
- Detection: build in-degree map from all `OverlayEdge` targets and `OrgEdge` targets; objects
  not in that set and not matching any trailer root/info ref are detached.

### 8. `telemetry.<idx>` (P3)

- Source data: `ctx.graph.telemetry_events[idx]`
- Tractable: each event already carries `object_ref: Option<(u32, u16)>` for correlation.
- Attrs: `{ "kind": "telemetry", "idx": usize, "event_type": String, "object_ref": Option<String> }`
- Edges out: `telemetry.<idx> -> <obj gen>` (edge_type: `telemetry_ref`) when `object_ref`
  is present and `graph.get_object()` confirms the object
- Edge cap: **20 edges per telemetry node**. Include only in P3 after signal-to-noise
  evaluation on the full corpus (see Stage 3).
- Evaluation criterion for inclusion: fewer than 5% of overlay outputs have more than
  10 telemetry nodes. If this threshold is exceeded, the telemetry overlay is disabled by
  default and requires an explicit additional flag.

### 9. `signature.<idx>` (P3)

- Source data: revision/signature boundary summary (revision findings with signature metadata)
- Defer: requires cross-module coupling to signature validation logic. Include only after
  `detached` cluster and telemetry nodes are stable.
- Attrs: `{ "kind": "signature", "idx": usize, "revision_n": usize, "post_cert": bool }`
- Edges out: `signature.<idx> -> revision.<n>` (edge_type: `signature_covers_revision`)

---

## Overlay data model

### Typed attribute design

`attrs` must not be an untyped `HashMap<String, String>` or `serde_json::Value` — this would
make serialisation inconsistent and downstream scripting unreliable. Instead use a closed enum:

```rust
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OverlayNodeAttrs {
    FileRoot,
    Trailer {
        idx: usize,
        has_root: bool,
        has_info: bool,
        has_encrypt: bool,
        size: Option<u64>,
        #[serde(default)]
        unresolved: Vec<String>,
        #[serde(default)]
        prev_unresolved: bool,
    },
    Startxref {
        idx: usize,
        offset: u64,
        section_match: bool,
    },
    XrefSection {
        idx: usize,
        offset: u64,
        section_kind: XrefSectionKind,
        has_trailer: bool,
        prev: Option<u64>,
        trailer_size: Option<u64>,
        trailer_root: Option<String>,
    },
    Revision {
        n: usize,
        startxref_offset: u64,
        post_cert: bool,
        changed_object_count: usize,
        changed_object_edge_count: usize,
        truncated: bool,
    },
    Objstm {
        container_obj: u32,
        container_gen: u16,
        contained_count: usize,
    },
    Carved {
        carrier_obj: u32,
        carrier_gen: u16,
        carved_count: usize,
    },
    Telemetry {
        idx: usize,
        event_type: String,
        object_ref: Option<String>,
    },
    Signature {
        idx: usize,
        revision_n: usize,
        post_cert: bool,
    },
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum XrefSectionKind { Table, Stream, Unknown }

pub struct OverlayNode {
    pub id: String,   // e.g. "trailer.0", "startxref.1", "file.root"
    pub attrs: OverlayNodeAttrs,
}

pub struct OverlayEdge {
    pub from: String,
    pub to: String,                // overlay node ID or "obj:<n>:<g>" for real objects
    pub edge_type: String,
    pub suspicious: bool,
}
```

Target objects (real PDF objects) are referenced as `"obj:<n>:<g>"` in `OverlayEdge.to` so
consumers can distinguish them from pseudo-node IDs without string heuristics.

### JSON output structure

The overlay is delivered under an `overlay` key alongside existing structure output:

```json
{
  "type": "structure_graph",
  "org": { ... },
  "typed_edges": { ... },
  "action_paths": { ... },
  "path_helpers": { ... },
  "overlay": {
    "nodes": [ { "id": "file.root", "attrs": { "kind": "file_root" } }, ... ],
    "edges": [ { "from": "trailer.0", "to": "obj:3:0", "edge_type": "trailer_root", "suspicious": false }, ... ],
    "stats": {
      "trailer_count": 2,
      "startxref_count": 2,
      "xref_section_count": 2,
      "unresolved_trailer_refs": 0,
      "detached_objects": [ ... ],
      "detached_total": 0,
      "detached_truncated": false,
      "truncated": false
    }
  }
}
```

When overlay is not requested the `overlay` key is absent entirely (not `null`).

### DOT output structure

The existing DOT `export_structure_dot` function inserts a comment at line ~7450:
```
// structure overlay: N typed edge types, multi-step chains=M, ...
```

This comment must be renamed to avoid confusion with the new overlay subgraph:
```
// structure stats: N typed edge types, multi-step chains=M, ...
```

Overlay pseudo-nodes are emitted as a labelled subgraph cluster:
```dot
subgraph cluster_overlay {
  label="Structural Provenance Overlay";
  style=dashed;
  color=lightblue;
  "file.root" [shape=diamond, color=blue, label="file.root"];
  "startxref.0" [shape=hexagon, color=steelblue, label="startxref.0\noffset=1582"];
  "trailer.0" [shape=box, color=navy, label="trailer.0\nroot=3 0 R"];
  "xref.section.0" [shape=parallelogram, color=steelblue, label="xref.section.0\ntable"];
}
// overlay edges
"file.root" -> "startxref.0" [label="file_root_to_startxref", style=dashed, color=steelblue];
"startxref.0" -> "xref.section.0" [label="startxref_to_section", style=dashed];
"xref.section.0" -> "trailer.0" [label="section_to_trailer", style=dashed];
"trailer.0" -> "obj:3:0" [label="trailer_root", style=bold, color=navy];
```

Node shapes and colours per kind:
- `file.root`: diamond, blue
- `startxref`: hexagon, steelblue
- `xref.section`: parallelogram, steelblue (table), cadetblue (stream), grey (unknown)
- `trailer`: box, navy; `post_cert` trailers: box, red
- `revision`: box3d, darkorange; `post_cert`: box3d, red
- `objstm`, `carved`: ellipse, dimgray
- `telemetry`, `signature`: note shape, grey

### Edge direction convention

Edge direction follows **PDF parse order** (the order a reader encounters the data):
- `file.root → startxref` (entry point → reference)
- `startxref → xref.section` (reference → table/stream)
- `xref.section → trailer` (table → accompanying trailer)
- `trailer → /Root` / `trailer → /Info` (trailer → referenced objects)
- `trailer → startxref.<prev>` (current → previous, for `/Prev` chain)

This is consistent and unambiguous: edges always point in the direction a reader would follow.
The `/Prev` chain from a newer trailer to an older startxref is a backward reference in revision
terms but a forward edge in parse-traversal terms; this is correct and expected.

---

## Query interface

### Query naming

The depth variant precedent (`graph.structure.depth N`) guides the naming:

```
graph.structure.overlay          → DOT with overlay subgraph
graph.structure.overlay.dot      → alias
graph.structure.overlay.json     → JSON with overlay key
```

A `graph.structure.overlay.depth N` variant is deferred to after Stage 2 unless depth
filtering proves necessary during Stage 1 testing.

These are added as new `Query` enum variants:
```rust
ExportStructureOverlayDot,
ExportStructureOverlayJson,
```

And registered in `parse_query` and the format-coercion helpers (`to_json`, `to_dot`).

The DOT comment naming collision is resolved simultaneously: rename `// structure overlay:...`
to `// structure stats:...` in `export_structure_dot` as part of Stage 1.

### Finding interaction: suspicious edge marking

When building overlay edges in Stage 1, query the scan findings to mark edges `suspicious: true`
when:
- the target object of a `trailer_root`, `trailer_info`, or `trailer_encrypt` edge is
  referenced by any finding with severity High or Critical, OR
- the overlay node itself is a `revision` node where `post_cert: true`.

This requires access to the findings list at overlay build time. The overlay builder function
signature must accept an optional `findings: &[Finding]` parameter (passed as `None` when
called from a context without findings, `Some` when available). This connects structural
provenance to the finding severity model without adding new detectors.

---

## New opportunities incorporated

### Overlay stats as Info-level finding

The overlay stats JSON (`trailer_count`, `xref_section_count`, `detached_total`) can be exposed
as a synthetic Info-level finding: "Structural complexity: N trailers, M xref sections, K
revisions." This makes overlay summary visible in standard `sis scan` output without requiring
a separate query. Add this as a low-risk Info finding in Stage 1 alongside the overlay query.

Implementation: add a finding kind `structural_complexity_summary` with:
- severity: Info
- confidence: Certain
- meta: `{ "trailer_count": N, "startxref_count": M, "revision_count": K, "detached_objects": D }`
- emitted only when the overlay is built as part of a scan (not on every structure query)

### `graph.event` overlay anchor (deferred)

A future follow-on plan can wire `startxref` and `trailer` pseudo-nodes into the event graph
as a new `EventNodeKind::Anchor` variant. This would let analysts see the full provenance chain
without switching between `graph.structure.overlay` and `graph.event`. Excluded here to keep
scope bounded; the overlay model must be stable before event-graph integration.

---

## Staged implementation

### Stage 1: Trailer/startxref/xref overlay (P1)

**Files:**
- `crates/sis-pdf/src/commands/query.rs` — query variants, DOT comment rename, findings wiring
- `crates/sis-pdf-core/src/structure_overlay.rs` — required (not optional) new module
- `crates/sis-pdf-core/src/org_export.rs` — if overlay JSON key is appended here

**Work:**

1. Rename `// structure overlay:` comment to `// structure stats:` in `export_structure_dot`.
2. Create `structure_overlay.rs`:
   - `OverlayNodeAttrs`, `XrefSectionKind`, `OverlayNode`, `OverlayEdge` types
   - `parse_xref_kind(s: &str) -> XrefSectionKind`
   - `build_p1_overlay(graph: &ObjectGraph, findings: Option<&[Finding]>) -> StructureOverlay`
   - `StructureOverlay { nodes, edges, stats }`
3. Add `Query::ExportStructureOverlayDot` and `Query::ExportStructureOverlayJson` variants.
4. Register in `parse_query` and format-coercion helpers.
5. Implement `export_structure_overlay_json` and `export_structure_overlay_dot` in `query.rs`.
6. Add Info-level `structural_complexity_summary` finding to scan output.
7. Commit a reference baseline JSON snapshot of `graph.structure.json` for the CVE fixture
   (`crates/sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf`) as a committed
   file; add a test that asserts byte-for-byte equality.

**Tests:**
1. Extend `parse_query_supports_org_and_ir_aliases` with overlay variant parse coverage:
   - `graph.structure.overlay` → `ExportStructureOverlayDot`
   - `graph.structure.overlay.dot` → `ExportStructureOverlayDot`
   - `graph.structure.overlay.json` → `ExportStructureOverlayJson`
2. `structure_overlay_json_includes_trailer_root_edge_for_fixture_with_info`:
   - fixture: any existing fixture with `/Info` in trailer (most fixtures qualify)
   - assert: overlay JSON contains a `trailer_root` and `trailer_info` edge
3. `structure_overlay_emits_file_root_node`:
   - assert: overlay JSON nodes list contains exactly one `{ "id": "file.root" }` entry
4. `structure_overlay_xref_kind_parsing_is_typed`:
   - assert: `parse_xref_kind("table") == XrefSectionKind::Table`
   - assert: `parse_xref_kind("unknown_future_value") == XrefSectionKind::Unknown`
5. `baseline_structure_json_unchanged_without_overlay`:
   - assert byte-for-byte equality against committed reference snapshot
6. `structure_overlay_unresolved_trailer_ref_does_not_emit_edge`:
   - synthetic: call `build_p1_overlay` with a trailer dict referencing a non-existent object
   - assert: no edge emitted; `unresolved` attr contains the key name
7. `structure_overlay_startxref_with_no_matching_section_marks_section_match_false`:
   - synthetic: startxref offset with no matching xref_section offset
   - assert: node attrs `section_match == false`, no `startxref_to_section` edge emitted

**Documentation:**
- Add `docs/query-overlay.md` (or extend `docs/graph-model-schema.md`) describing:
  - query names and output schema
  - overlay node kinds and their attrs
  - edge types and direction semantics
  - `detached_objects` field
  - `suspicious` edge semantics
- Update CLI help / `sis query --list` output if a discovery mechanism exists.

---

### Stage 2: Provenance, revision, and detached objects (P2)

**Files:**
- `crates/sis-pdf/src/commands/query.rs`
- `crates/sis-pdf-core/src/structure_overlay.rs`
- `crates/sis-pdf-core/src/revision_timeline.rs` (read-only, call `build_revision_timeline`)

**Work:**
1. Extend `build_p1_overlay` into `build_overlay(graph, findings, include_provenance, include_revision)`.
2. Implement `revision.<n>` nodes by calling `build_revision_timeline(&ctx, 100)` and mapping
   `RevisionRecord` fields to `OverlayNodeAttrs::Revision`. Apply 50-edge cap with `truncated`
   flag and suspicious marking for post-cert revisions.
3. Implement `objstm.<obj>.<gen>` pseudo-nodes from `ObjProvenance::ObjStm` entries.
4. Implement `carved.<obj>.<gen>` pseudo-nodes from `ObjProvenance::CarvedStream` entries.
5. Implement `detached_objects` collection in overlay stats.

**Edge cap constants (define in `structure_overlay.rs`):**
```rust
pub const REVISION_CHANGED_OBJECT_EDGE_CAP: usize = 50;
pub const DETACHED_OBJECTS_CAP: usize = 100;
```

**Tests:**
1. `structure_overlay_objstm_emits_contains_edges`:
   - fixture: any existing fixture with ObjStm objects
   - assert: overlay contains `objstm_contains` edges
2. `structure_overlay_objstm_is_additive_over_typed_edges`:
   - assert: typed graph still emits `ObjStmReference` edges for the same fixture
   - assert: both edge kinds appear in their respective output fields (no replacement)
3. `structure_overlay_revision_nodes_are_capped`:
   - construct a synthetic `RevisionTimeline` with 80 changed objects in one revision
   - assert: `changed_object_edge_count == 50`, `truncated == true`, `changed_object_count == 80`
4. `structure_overlay_post_cert_revision_edges_marked_suspicious`:
   - synthetic: one post-cert revision with 3 changed objects
   - assert: all 3 changed-object overlay edges have `suspicious == true`
5. `structure_overlay_detached_objects_enumerated_and_capped`:
   - synthetic: object with in-degree zero not reachable from any trailer root
   - assert: appears in `detached_objects` list
   - synthetic: 110 detached objects → assert `detached_truncated == true`, list length 100
6. `structure_overlay_large_corpus_stays_within_budget`:
   - run `build_overlay` on a fixture with known large xref (existing corpus fixture)
   - assert completion in ≤ 100 ms (wall time)

**Performance gate:**
- Stage 2 overlay construction must complete in ≤ 100 ms for any existing test fixture.
  Add as a named benchmark test `structure_overlay_p2_build_budget`.

---

### Stage 3: Extended pseudo nodes and corpus signal evaluation (P3)

**Gating criteria for telemetry overlay inclusion:**
- Run `graph.structure.overlay.json` on a representative corpus sample (≥ 1000 PDFs).
- If fewer than 5% of outputs have more than 10 telemetry nodes: include telemetry overlay
  by default with the 20-edge cap.
- If threshold is exceeded: gate behind a separate explicit flag
  (`graph.structure.overlay.telemetry` or `--include-telemetry`) and document the signal-to-
  noise trade-off in `docs/`.

**Work:**
1. Implement `telemetry.<idx>` nodes after corpus evaluation confirms inclusion criteria.
2. Evaluate signature pseudo-nodes. Include only if `build_revision_timeline` can provide
   signature boundary data without additional scan work.
3. Add corpus telemetry distribution test as a documented baseline measurement.

**Tests:**
1. `structure_overlay_telemetry_is_deterministic_and_bounded`:
   - same fixture produces identical output across runs
   - assert edge count ≤ 20 per telemetry node
2. `structure_overlay_p1_slo_unaffected_by_p3`:
   - run `graph.structure.json` (no overlay) on the runtime-profile CVE fixture
   - assert timing within existing SLO (parse <10ms, detection <50ms)

---

## Risks and mitigations

1. **Risk: output churn breaks downstream tooling.**
   Mitigation: new explicit overlay query variants; no default schema changes; committed
   baseline snapshot test enforces non-regression for existing queries.

2. **Risk: graph noise reduces analyst usability.**
   Mitigation: staged rollout (P1 first), edge caps, pseudo-node clustering in DOT, detached
   objects enumerated not connected.

3. **Risk: performance overhead on large corpora.**
   Mitigation: O(n) overlay construction for P1 (no benchmark needed); explicit ≤ 100 ms
   budget gate for P2; P3 gated on corpus evaluation.

4. **Risk: `XrefSectionSummary.kind` string values change in emitter.**
   Mitigation: `parse_xref_kind()` conversion function is the single point of truth; any
   emitter change surfaces as a test failure in `structure_overlay_xref_kind_parsing_is_typed`.

5. **Risk: trailer lifetime bounds cause borrow-checker complications.**
   Mitigation: extract all needed attrs from `PdfDict<'a>` into owned `String`/`u64` values
   immediately on entry to `build_p1_overlay`; do not store references. The function takes
   `&ObjectGraph<'_>` and produces fully owned `StructureOverlay`.

6. **Risk: `file.root → startxref` chain direction causes analyst confusion.**
   Mitigation: edge direction follows parse order (reader traversal); documented explicitly
   in `docs/query-overlay.md` with a diagram.

---

## Validation plan

Run before starting (baseline):
```bash
cargo test -p sis-pdf-core
cargo test -p sis-pdf
cargo run -p sis-pdf --bin sis -- scan \
  crates/sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf \
  --deep --runtime-profile --runtime-profile-format json
```

Record timing deltas. Runtime profile SLOs (parse <10ms, detection <50ms) must not regress.

Stage 1 gates:
```bash
cargo test -p sis-pdf parse_query_supports_org_and_ir_aliases -- --nocapture
cargo test -p sis-pdf-core structure_overlay -- --nocapture
cargo test -p sis-pdf query -- --nocapture
cargo test -p sis-pdf baseline_structure_json_unchanged_without_overlay -- --nocapture
```

Stage 2 gate:
```bash
cargo test -p sis-pdf-core structure_overlay_p2_build_budget -- --nocapture
```

Stage 3 gate:
- corpus evaluation report (manual pass/fail against 5% threshold)

---

## Definition of done

- [ ] `structure_overlay.rs` module exists with typed `OverlayNodeAttrs` enum, no untyped attrs
- [ ] `parse_xref_kind()` is the single conversion point for xref section kind strings
- [ ] `file.root` pseudo-node is defined, included in inventory, and emitted in all overlays
- [ ] Trailer key resolution is fail-closed: missing targets annotate the node, emit no phantom edge
- [ ] `startxref → xref.section` match is exact-offset-only, with `section_match: false` on misses
- [ ] `// structure overlay:` DOT comment renamed to `// structure stats:` to remove naming collision
- [ ] Overlay delivered under `overlay:` key in JSON; absent (not null) when not requested
- [ ] DOT overlay uses subgraph cluster with defined shapes/colours per node kind
- [ ] Edge direction follows parse order throughout; documented in `docs/query-overlay.md`
- [ ] `ExportStructureOverlayDot` and `ExportStructureOverlayJson` query variants registered
- [ ] `suspicious: true` set on post-cert revision edges and edges to high/critical finding objects
- [ ] `structural_complexity_summary` Info finding emitted during scans
- [ ] Revision changed-object edges capped at 50 via named constant; `truncated` field accurate
- [ ] Detached objects enumerated in stats, capped at 100 via named constant
- [ ] ObjStm overlay nodes are additive over existing `ObjStmReference` typed edges (both coexist)
- [ ] Committed baseline `graph.structure.json` snapshot for CVE fixture; byte-equality test passes
- [ ] All Stage 1 tests listed above pass
- [ ] All Stage 2 tests listed above pass; P2 build budget ≤ 100 ms
- [ ] `docs/query-overlay.md` covers all query names, node kinds, edge types, direction semantics
- [ ] `cargo test -p sis-pdf-core -p sis-pdf` passes with no regressions
