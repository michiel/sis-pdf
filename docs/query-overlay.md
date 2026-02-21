# Structure Overlay Queries

This document describes the optional structure-overlay query outputs. Overlay queries augment
`graph.structure` with forensic pseudo nodes and edges without changing baseline
`graph.structure` output.

## Query names

```bash
sis query sample.pdf graph.structure.overlay
sis query sample.pdf graph.structure.overlay.dot
sis query sample.pdf graph.structure.overlay.json
sis query sample.pdf graph.structure.overlay.telemetry
sis query sample.pdf graph.structure.overlay.telemetry.dot
sis query sample.pdf graph.structure.overlay.telemetry.json
```

- `graph.structure.overlay*` includes trailer/xref/startxref/revision/provenance overlays.
- `graph.structure.overlay.telemetry*` additionally includes telemetry and signature overlays.

## JSON shape

Overlay queries return the normal structure payload plus an `overlay` key:

```json
{
  "type": "structure_graph",
  "org": { "...": "..." },
  "typed_edges": { "...": "..." },
  "action_paths": { "...": "..." },
  "path_helpers": { "...": "..." },
  "overlay": {
    "nodes": [],
    "edges": [],
    "stats": {}
  }
}
```

When overlay is not requested (`graph.structure*`), the `overlay` key is absent.

## Overlay node kinds

- `file_root`: virtual parse anchor (`file.root`)
- `startxref`: `startxref.<idx>`
- `xref_section`: `xref.section.<idx>`
- `trailer`: `trailer.<idx>`
- `revision`: `revision.<n>`
- `objstm`: `objstm.<obj>.<gen>`
- `carved_stream`: `carved.<obj>.<gen>`
- `telemetry`: `telemetry.<idx>` (telemetry query variants only)
- `signature`: `signature.<idx>` (telemetry query variants only)

## Overlay edge types

- `file_root_to_startxref`
- `startxref_to_section`
- `section_to_trailer`
- `section_prev`
- `trailer_root`
- `trailer_info`
- `trailer_encrypt`
- `trailer_prev`
- `revision_to_startxref`
- `revision_changed_object`
- `objstm_contains`
- `carved_from_stream`
- `telemetry_ref` (telemetry query variants only)
- `signature_covers_revision` (telemetry query variants only)

Edge direction follows parse/provenance flow, from container/anchor context to referenced object
or later stage.

## Overlay stats

`overlay.stats` currently includes:

- `node_count`, `edge_count`
- `trailer_count`, `startxref_count`, `xref_section_count`, `revision_count`
- `telemetry_node_count`, `signature_node_count`
- `include_telemetry`, `include_signature`
- `detached_total`, `detached_truncated`, `detached_objects`

`detached_objects` is capped at 100 entries; `detached_total` records the full count.

## Suspicious semantics

Overlay edges include a `suspicious` boolean:

- `revision_changed_object` edges are marked suspicious when the revision is post-signature
  coverage (`post_cert`).
- other overlay edges are currently non-suspicious by default.

## DOT output

DOT overlay queries render the normal ORG graph plus a dashed `cluster_structure_overlay`
subgraph containing pseudo nodes and overlay edges.
