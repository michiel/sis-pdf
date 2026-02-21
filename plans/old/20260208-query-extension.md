# Query extension plan: dedicated xref objects and traceable investigation flow

Date: 2026-02-08  
Owner: sis-pdf maintainers  
Status: Completed

## 1. Problem statement

Analysts can see xref-related findings (for example `xref_conflict`) and can run `explain`, but the query interface does not expose first-class xref structures. This creates a workflow gap:

- `findings` can identify the issue.
- `explain` can describe the issue.
- `query` cannot directly enumerate xref/startxref/trailer chain state in a natural object model.

Current friction points observed in interactive usage:

1. No dedicated `xref` query object exists.
2. REPL predicate usage differs from one-shot usage (`:where` vs inline command flags), which is easy to misuse.
3. Findings-to-structure tracing depends on metadata interpretation rather than direct xref objects.

## 2. Research and current-state audit

This plan is based on source and documentation review across query parsing, execution, predicates, parser internals, and analyst guides.

### 2.1 Query parser and execution surface

Files reviewed:

- `crates/sis-pdf/src/commands/query.rs`
- `crates/sis-pdf/src/main.rs`
- `crates/sis-pdf/src/commands/query/readable.rs`

Observed behaviour:

- `parse_query` supports many namespaces (`findings`, `objects`, `events`, `streams.entropy`, etc.) but not `xref`.
- Structure queries currently include only `trailer` and `catalog`.
- REPL supports `:where EXPR`; one-shot supports `--where EXPR`.
- Predicates already support finding-centric fields (`kind`, `surface`, `meta.*`) but there is no xref-specific typed context.

### 2.2 PDF parser capabilities already available

Files reviewed:

- `crates/sis-pdf-pdf/src/graph.rs`
- `crates/sis-pdf-pdf/src/xref.rs`

Observed behaviour:

- Parser captures `startxrefs: Vec<u64>` and `trailers: Vec<PdfDict>`.
- Parser can parse an xref chain (`parse_xref_chain`) with section `kind` (`Table`, `Stream`, `Unknown`), offset, optional trailer, and deviations.
- Chain section details are not persisted in `ObjectGraph`; only trailers/startxrefs/deviations survive.

Implication:

- We can deliver a useful first-class xref query immediately from existing `ObjectGraph` data.
- Full chain section details require expanding `ObjectGraph` (or reparsing in query execution).

### 2.3 Documentation and UX state

Files reviewed:

- `docs/query-interface.md`
- `docs/query-predicates.md`
- `docs/agent-query-guide.md`

Observed behaviour:

- No xref query object documented.
- Predicates list supported queries; no xref namespace.
- Analyst workflow recommends finding -> object/stream tracing, but xref tracing is indirect.

## 3. Design goals

1. Add a first-class `xref` query family that feels like existing namespaces.
2. Make finding-to-xref tracing direct, predictable, and scriptable.
3. Keep one-shot and REPL workflows consistent.
4. Preserve backward compatibility for existing queries and outputs.
5. Expose enough structural detail for triage without forcing deep mode.

## 4. Proposed query model

## 4.1 New query namespace

Add new queries:

- `xref` (full xref summary records)
- `xref.count` (record count)
- `xref.startxrefs` (startxref marker records)
- `xref.startxrefs.count`
- `xref.sections` (xref chain section records; see staged rollout below)
- `xref.sections.count`
- `xref.trailers` (trailer summary records tied to revisions)
- `xref.trailers.count`
- `xref.deviations` (parser xref deviation records)
- `xref.deviations.count`

### 4.2 Related traceability objects

Add lightweight related namespace to make navigation natural:

- `revisions` (document revision summary derived from startxref ordering)
- `revisions.count`

`revisions` is a thin layer over xref/trailer state and can be queried independently or joined in analyst workflow.

### 4.3 Output schema (stable field names)

`xref.startxrefs` item:

- `index` (u32; chain order in file)
- `offset` (u64)
- `distance_from_eof` (u64)
- `in_bounds` (bool)

`xref.sections` item (Stage 2+):

- `index` (u32; most recent to oldest chain order)
- `offset` (u64)
- `kind` (`table|stream|unknown`)
- `has_trailer` (bool)
- `prev` (u64|null)
- `trailer_size` (u64|null)
- `trailer_root` (string|null; `"<obj> <gen> R"`)

`xref.trailers` item:

- `index` (u32)
- `size` (u64|null)
- `root` (string|null)
- `info` (string|null)
- `encrypt` (string|null)
- `id_present` (bool)
- `prev` (u64|null)

`xref.deviations` item:

- `kind` (string; for example `xref_trailer_search_invalid`)
- `offset_start` (u64)
- `offset_end` (u64)
- `note` (string|null)

`revisions` item:

- `revision` (u32)
- `startxref` (u64|null)
- `trailer_index` (u32|null)
- `root` (string|null)
- `has_incremental_update` (bool)

## 5. Predicate model updates

Extend predicate support list and context mapping for xref/revision objects:

- `type`: `XrefStartxref|XrefSection|XrefTrailer|XrefDeviation|Revision`
- `subtype`: object sub-kind (`table|stream|unknown`, deviation kind)
- `kind`: alias for `subtype`
- `name`: generated label (`section#2`, `trailer#1`, etc.)
- `length`: semantic numeric field by object type:
  - startxref/section/deviation: span or offset-derived value
  - trailer/revision: 0 if not meaningful
- `meta.*`: full object metadata map (for precise filtering)

Document examples:

- `sis query sample.pdf xref.sections --where "kind == 'stream'"`
- `sis query sample.pdf xref.deviations --where "kind contains 'trailer_search'"`
- `sis query sample.pdf revisions --where "has_incremental_update == true"`

## 6. Explain and finding traceability integration

Objective: from finding -> explain -> xref query should be direct and stable.

Planned improvements:

1. Ensure xref-related findings consistently include:
   - `meta.xref.startxref_count`
   - `meta.xref.offsets`
   - `meta.xref.section_kinds` (when known)
2. In `explain`, when finding kind is xref-related, print suggested follow-up queries:
   - `xref.startxrefs`
   - `xref.sections`
   - `xref.deviations`
3. Keep short-ID support consistent across REPL and one-shot `explain` paths.

## 7. Implementation plan

## Step 1: Introduce xref query commands (no parser-core changes)

Files:

- `crates/sis-pdf/src/commands/query.rs`
- `docs/query-interface.md`
- `docs/query-predicates.md`

Tasks:

- Add new `Query` enum variants and `parse_query` mappings for `xref*` and `revisions*`.
- Implement extractors using current `ScanContext` fields (`startxrefs`, `trailers`, `deviations`).
- Add count variants and predicate support gating.

Progress:

- [x] Completed

## Step 2: Persist xref chain section detail in parser graph

Files:

- `crates/sis-pdf-pdf/src/xref.rs`
- `crates/sis-pdf-pdf/src/graph.rs`
- `crates/sis-pdf-pdf/src/lib.rs` (exports if needed)

Tasks:

- Add serialisable/storable section summary type in PDF crate (no heavy object duplication).
- Persist section summaries in `ObjectGraph` during parse.
- Keep memory bounded: store scalar summary only, not full dictionaries.

Progress:

- [x] Completed

## Step 3: Wire `xref.sections` query to stored section summaries

Files:

- `crates/sis-pdf/src/commands/query.rs`
- `crates/sis-pdf/src/commands/query/readable.rs`

Tasks:

- Implement section JSON/list outputs with stable key naming.
- Add readable table rendering and sorting (offset asc; severity-like ordering not applicable).

Progress:

- [x] Completed

## Step 4: Finding traceability enrichment for xref-related kinds

Files:

- `crates/sis-pdf-detectors/*` (xref detectors)
- `crates/sis-pdf-core/src/report.rs`
- `crates/sis-pdf/src/main.rs` (`run_explain` helper text)

Tasks:

- Standardise xref metadata keys on findings.
- Add follow-up query suggestions in explain output.
- Ensure metadata appears in JSON and readable report output without duplication.

Progress:

- [x] Completed (metadata and explain guidance landed; report templating unchanged)

## Step 5: Tests and regressions

Files:

- `crates/sis-pdf/src/commands/query.rs` tests
- `crates/sis-pdf-core/tests/*` integration tests
- Fixtures under `crates/sis-pdf-core/tests/fixtures/` as needed

Test matrix:

1. Parser maps each new query token correctly.
2. Query execution returns stable schemas for all `xref*` variants.
3. Predicate filters work on `kind`, `type`, `meta.*`, and numeric fields.
4. REPL `:where` works with xref objects.
5. `explain` for xref findings suggests relevant `xref*` commands.
6. Non-xref query behaviour unchanged.

Progress:

- [x] Completed (added parser/predicate/execution regression tests for xref namespace)

## Step 6: Documentation and analyst workflows

Files:

- `docs/query-interface.md`
- `docs/query-predicates.md`
- `docs/agent-query-guide.md`

Tasks:

- Add xref query family docs and examples (one-shot and REPL).
- Add explicit note on REPL predicate usage: `:where` command only.
- Add “finding-to-xref trace” mini playbook.

Progress:

- [x] Completed

## 8. Backward compatibility and risk controls

1. Existing query tokens and output formats remain unchanged.
2. New fields are additive; no breaking renames in current finding schemas.
3. If xref section data is unavailable (older parse path), `xref.sections` returns empty array with clear count `0`.
4. Keep parser robustness: never fail whole scan due to malformed xref section summarisation.

## 9. Acceptance criteria

1. Analyst can run:
   - `sis query sample.pdf xref`
   - `sis query sample.pdf xref.startxrefs`
   - `sis query sample.pdf xref.sections`
   - `sis query sample.pdf xref.deviations`
2. Analyst can filter in one-shot and REPL:
   - `--where "kind == 'stream'"` (one-shot)
   - `:where kind == 'stream'` then `xref.sections` (REPL)
3. `explain <xref-finding-id>` provides direct next-query guidance.
4. Docs clearly describe xref/revision objects and predicate fields.
5. Test suite covers parser, execution, predicates, and explain integration.

## 10. Progress log

- 2026-02-08: Completed repository audit for query parser, predicate system, REPL behaviour, and xref parser internals; drafted implementation plan and schema.
- 2026-02-08: Implemented xref and revision query namespaces in `sis query`, including parser mappings, execution handlers, predicate support for granular xref objects, and new regression tests.
- 2026-02-08: Extended `ObjectGraph` with compact xref section summaries and wired them into the query layer (`xref.sections`) without reparsing during query execution.
- 2026-02-08: Enriched xref finding metadata (`xref.offsets`, `xref.section_kinds`) and added explain-mode follow-up query hints for xref-related findings.
- 2026-02-08: Updated analyst-facing docs (`docs/query-interface.md`, `docs/query-predicates.md`, `docs/agent-query-guide.md`) to document xref/revision workflows and REPL `:where` usage.
