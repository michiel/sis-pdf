# xref_conflict heuristic refinement plan

Date: 2026-02-08  
Status: Drafted (implementation pending)

## Problem statement

`xref_conflict` currently escalates to `Medium` when multiple `startxref` markers are present, even when all xref sections are correctly linked and internally coherent. This overstates risk for legitimate incremental-update PDFs and reduces analyst trust.

## Goals

1. Reduce false-positive severity for benign incremental updates.
2. Preserve `Medium`/`High` outcomes for malformed, evasive, or parser-divergent xref chains.
3. Make the finding self-explanatory via explicit integrity signals in metadata/description.
4. Keep behaviour deterministic and easy to query (`sis query xref.*`).

## Non-goals

- Replacing existing xref deviation detectors.
- Rewriting xref parsing logic.
- Removing `xref_conflict` finding kind.

## Current state

- `xref_conflict` is primarily triggered by multiple `startxref` offsets.
- Query layer now exposes `xref.startxrefs`, `xref.sections`, `xref.deviations`, and `revisions`.
- Explain mode already suggests xref follow-up commands.
- Severity is not sufficiently tied to chain integrity quality.

## Proposed severity model

Compute an integrity assessment first, then map to severity.

### Integrity signals

- `startxref.count` (>= 2 required for `xref_conflict`)
- `section.count`
- `section.kind` distribution (`table|stream|unknown`)
- `/Prev` chain coherence (all links resolvable, no cycles, expected length)
- offsets in-bounds
- trailer coherence (`/Size`, `/Root` consistency across revisions)
- xref parse deviations count and kinds (`xref_trailer_search_invalid`, etc.)

### Severity mapping

- `Info`: Multiple `startxref` markers but no effective multi-revision chain (edge-case; mostly informational).
- `Low`: Multiple markers with coherent linked sections and no xref deviations.
- `Medium`: Multiple markers with one or more integrity warnings (broken `/Prev`, unknown section, offset anomaly, trailer inconsistency).
- `High`: Multiple markers with strong evasion indicators (chain fork/cycle + deviations + parser disagreement signals).

## Finding enrichment changes

For `xref_conflict`, add metadata keys:

- `xref.startxref.count`
- `xref.section.count`
- `xref.section.kinds`
- `xref.prev_chain.valid` (`true|false`)
- `xref.prev_chain.length`
- `xref.prev_chain.cycle` (`true|false`)
- `xref.offsets.in_bounds` (`true|false`)
- `xref.deviation.count`
- `xref.deviation.kinds`
- `xref.integrity.level` (`coherent|warning|broken`)
- `query.next` (`xref.sections`, `xref.trailers`, `xref.deviations`, `revisions`)

Update description template to include why severity was chosen, for example:

- "Found 2 startxref markers; xref chain is coherent across 2 linked stream sections (severity downgraded)."
- "Found 3 startxref markers; /Prev chain is broken and trailer search deviations were recorded."

## Implementation plan

### Step 1: Add integrity evaluator helper

Files:

- `crates/sis-pdf-detectors/src/lib.rs` (or dedicated `xref_integrity.rs` helper module)

Tasks:

- Build a pure helper that reads `ctx.graph.startxrefs`, `ctx.graph.xref_sections`, and xref deviations.
- Return structured summary:
  - integrity level
  - warning flags
  - computed severity suggestion
  - metadata map payload

### Step 2: Patch `xref_conflict` detector severity and messaging

Files:

- `crates/sis-pdf-detectors/src/lib.rs` (`XrefConflictDetector`)

Tasks:

- Replace static severity assignment with helper-derived severity.
- Add/standardise metadata keys listed above.
- Update title/description/remediation to mention concrete chain state.

### Step 3: Align report rendering for new xref metadata

Files:

- `crates/sis-pdf-core/src/report.rs`

Tasks:

- Ensure runtime/impact text for `xref_conflict` reflects integrity context.
- Prefer metadata-driven explanation when available (coherent vs broken chain).

### Step 4: Add regression tests

Files:

- `crates/sis-pdf-detectors/src/lib.rs` (unit tests)
- `crates/sis-pdf-core/tests/...` (integration if fixture-based required)

Test matrix:

1. Two linked sections, no deviations -> `Low`
2. Two markers, broken `/Prev` chain -> `Medium`
3. Multiple markers + xref deviations -> `Medium` (or `High` if severe combination)
4. Ensure metadata keys are present and stable.

### Step 5: Query/explain compatibility checks

Files:

- `crates/sis-pdf/src/main.rs` (explain display)
- `crates/sis-pdf/src/commands/query/readable.rs` (readable visibility)

Tasks:

- Confirm key metadata fields are surfaced in `explain` context output.
- Ensure `xref.sections`/`xref.deviations` queries match the finding’s metadata narrative.

## Acceptance criteria

- Benign incremental-update PDFs with coherent xref chains no longer produce `Medium` `xref_conflict`; expected `Low`.
- Broken or suspicious xref chains continue to produce `Medium+`.
- `explain` output states why severity is assigned.
- Regression tests cover benign and suspicious cases.

## Risks and mitigations

- Risk: Over-downgrading truly suspicious files with subtle evasion.
  - Mitigation: keep `Medium` when any integrity warning exists.
- Risk: metadata drift across findings.
  - Mitigation: enforce canonical `xref.*` keys and test them.

## Analyst workflow impact

After refinement, analysts can do:

1. `explain <xref_conflict_id>` to see chain integrity rationale.
2. `xref.sections` to verify section kinds/offsets.
3. `xref.deviations` to confirm parser issues.
4. `revisions` to inspect update chronology.

## Progress log

- 2026-02-08: Plan drafted.
- 2026-02-08: Related in-flight code committed in `13d7765` (context/severity improvements outside this specific heuristic).
