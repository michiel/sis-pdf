# Graph Query Console and Report Path Consistency (2025-01-10)

## Goals

- Make IR/ORG graph paths, chains, and document positions consistent across reports, JSONL, IR exports, and future query tooling.
- Define a clear, human‑readable position scheme that stays stable across parse modes.
- Specify an interactive `sis query-console` experience with example sessions and use cases.

## Part A: Consistent Representation of Paths, Chains, and Positions

### 1) Canonical document position format

Introduce a single, canonical position string that can be used in findings, chains, and graph views:

```
doc:<revision>/<meaningful-path>@<object>
```

Components:
- `revision`: incremental update index (`r0`, `r1`, …), derived from `startxref` ordering.
- `meaningful-path`: the semantic route within the document (e.g. `catalog.pages.kids[2].annots[0].a.js`).
- `object`: object reference `obj:gen` (e.g. `12:0`) to anchor the path.

Examples:
- `doc:r0/catalog.pages.kids[2].annots[0].a.js@12:0`
- `doc:r1/trailer.root.pages.kids[0]@3:0`

Rules:
- Always include revision and object reference.
- Use dotted keys for PDF dictionary names (lower‑case, leading slash stripped).
- Use `kids[n]`, `annots[n]`, `names[n]`, etc for array positions.
- Use `?` for unknown path segments, but keep the object anchor (e.g. `doc:r0/?@45:0`).

### 2) Object identity and aliases

Standardise object identity in reports:
- Primary ID: `obj:<num>:<gen>`.
- Optional alias: `xref:<offset>` or `objstm:<obj>:<gen>:<index>` when relevant.
- Paths should always end with the primary ID, and may include aliases in metadata.

### 3) Path segments used across components

Define a shared path vocabulary so findings, chains, and graph exports align:
- `catalog`, `pages`, `page`, `kids`, `annots`, `openaction`, `aa`, `action`, `js`, `uri`, `embedded`, `filespec`, `objstm`, `stream`.
- For action chains: `action.s`, `action.next`, `action.js`, `action.uri`.
- For supply chain: `embedded`, `launch`, `filespec`, `ef`, `names`.

### 4) Chain representation

Chains should reference the canonical positions of their nodes. In extended (default human‑readable) mode, show a 40‑character sanitised content preview aligned beyond the longest node line:

```
chain:<id>
  nodes:
    - doc:r0/catalog.openaction@5:0          | "OpenAction -> JavaScript action..."
    - doc:r0/action.js@12:0                  | "app.doc.submitForm('http://...')"
    - doc:r0/stream@42:0                     | "if (typeof(ADBE.Reader_Value_..."
  edges:
    - openaction -> action
    - action -> js
    - js -> stream
```

Rules:
- Nodes must include canonical positions.
- Edges should use semantic labels (e.g. `openaction`, `aa`, `js_payload`, `uri_target`).
- Chains should include a `confidence` and `surface` summary.

### 5) Tree view presentation

Provide a consistent tree view rendering for IR/ORG nodes. In extended (default human‑readable) mode, append a 40‑character sanitised preview aligned beyond the longest tree line:

```
catalog@1:0                             | "Catalog"
  pages@2:0                             | "Page tree"
    kids[0]@4:0                         | "Page 1"
      annots[1]@9:0                     | "Annot: /Link"
        a@10:0                          | "Action"
          js@12:0                       | "if (typeof(ADBE.Reader_Value_..."
```

Rules:
- Nodes show key name and object ref.
- Arrays show index with the owning key.
- Tree view must be reproducible between CLI and query console.
- Extended mode is the default for human‑readable reports; plain mode omits previews.

### 6) Report integration

Suggested additions to reports:
- Each finding includes `position` (canonical string).
- Findings referencing multiple objects include `positions[]`.
- Chains use `nodes[]` with canonical positions, and `edges[]` with semantic labels.
- Batch JSONL output for findings and chains should include `position` fields.

## Part B: `sis query-console` Interactive Query Interface

### 1) Goals and scope

The query console should allow:
- Interactive graph exploration for IR/ORG views.
- Querying by object, path, or finding.
- Filtering by revision, surface, and detector kind.
- Exporting filtered views as JSON.

Initial scope:
- Read‑only queries against a parsed document.
- Built‑in commands for common workflows.
- JSON output option for each query.

### 2) CLI entry point

```
sis query-console suspicious.pdf
```

Optional flags:
- `--strict` / `--strict-summary`
- `--deep`
- `--ir` or `--org` (default: `org`)
- `--json` to output JSON for scripting

### 3) Command grammar (initial)

```
help
load <pdf>
show root
show tree [path]
show node <obj>
show chain <id>
find kind <finding_kind>
find path <path_prefix>
find object <obj>
find revision <rN>
filter surface <surface>
filter severity <level>
list chains
list findings
export json <path>
quit
```

### 4) Mock sessions

Session A: inspect a JavaScript chain
```
sis query-console suspicious.pdf
> list chains
chain:001 surface=JavaScript confidence=Probable nodes=4
> show chain chain:001
nodes:
  doc:r0/catalog.openaction@5:0
  doc:r0/action.js@12:0
  doc:r0/js@12:0
  doc:r0/stream@42:0
edges:
  openaction -> action
  action -> js
  js -> stream
> show node 12:0
type=Action/JavaScript
position=doc:r0/action.js@12:0
```

Session B: locate findings on a given page path
```
> show tree catalog.pages.kids[0]
catalog@1:0
  pages@2:0
    kids[0]@4:0
      annots[1]@9:0
> find path catalog.pages.kids[0]
finding: js_present at doc:r0/catalog.pages.kids[0].annots[1].a.js@12:0
```

Session C: revision‑specific diff
```
> find revision r1
finding: objstm_density_high at doc:r1/objstm@88:0
> show tree r1
... (tree view of revision 1) ...
```

### 5) Use cases

- **Rapid triage**: map a high‑severity finding back to its document position and chain.
- **Incident response**: identify all objects impacted by a suspicious action chain.
- **Parser validation**: inspect strict parser deviation summaries at the correct location.
- **Research**: quantify how often certain node types appear across the graph.

### 6) Data structures and output consistency

Proposed JSON for `show node`:
```
{
  "object": "12:0",
  "position": "doc:r0/action.js@12:0",
  "type": "Action/JavaScript",
  "roles": ["JsContainer"],
  "edges": {
    "out": ["12:0 -> 42:0 (js_payload)"],
    "in": ["5:0 -> 12:0 (openaction)"]
  },
  "findings": ["js_present"]
}
```

## Implementation Notes

1) Add a canonical path builder in the core graph/IR layer so all subsystems use the same format.
2) Extend `Report` and chain templates to include `position` fields.
3) Add a new CLI subcommand `query-console` that uses a small REPL.
4) Provide a `--json` output mode for all query results.
5) Ensure strict summary and temporal analysis integrate with the same position scheme.

## Open Questions

- Do we allow multiple canonical positions for a single object if it is reachable via multiple paths?
- Should `position` allow an optional `path_hash` to keep reports compact?
- How do we merge positions across revisions for `temporal_signals` summaries?
