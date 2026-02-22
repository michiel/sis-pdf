# Optional Follow-ons Consolidated Implementation Roadmap

Date: 2026-02-22
Status: Proposed
Owner: Core + CLI + GUI + Release Engineering

## Purpose

Define a single technical implementation plan for optional/deferred work across current plan documents, with explicit source provenance for each item.

This roadmap includes the requested content-stream follow-ons:
1. Do chain recursion tracer for nested form XObjects.
2. Inline image anomaly detector.
3. Per-page execution surface summary query.
4. Content stream fingerprinting enhancements.

And it includes additional optionals identified in other `plans/*.md` files,
plus newly identified opportunities from gap and risk analysis.

## Source inventory (provenance)

Each backlog item below includes the origin plan and section.

### Stream-execution optionals (primary)

1. `OF-CS-01` Do chain recursion tracer.
   Source: `plans/20260222-content-stream-exec-coverage-uplift.md` (`N1. Do operator chain recursion tracer`).
2. `OF-CS-02` Inline image anomaly detector.
   Source: `plans/20260222-content-stream-exec-coverage-uplift.md` (`N2. Inline image anomaly detection`).
3. `OF-CS-03` Per-page execution surface summary query.
   Source: `plans/20260222-content-stream-exec-coverage-uplift.md` (`N3. Per-page execution surface summary query`).
4. `OF-CS-04` Content stream fingerprinting.
   Source: `plans/20260222-content-stream-exec-coverage-uplift.md` (`N4. Content stream fingerprinting`).
5. `OF-CS-05` Type3 charproc suspicious-ops detector.
   Source: `plans/20260222-content-stream-exec-coverage-uplift.md` (`N5. Type3 font charproc attack surface detector`).
6. `OF-CS-06` Cross-revision content stream diffing.
   Source: `plans/20260222-content-stream-exec-coverage-uplift.md` (`N6. Cross-revision content stream diffing`).
   **Depends on:** `OF-CS-04` (uses fingerprints; cannot proceed without A4 complete).

### Events/overlay/query optionals from other plans

7. `OF-EV-01` CLI `events` full-mode alias (`--full`) parity.
   Source: `plans/20260221-events-dialog-depth.md` (`Deferred follow-on opportunities`, `F2`).
8. `OF-EV-02` Finding-to-event bidirectional index expansion and jump affordances.
   Source: `plans/20260221-gui-events-and-triage-deprecation.md` (`N3`, `Follow-on plans`), and `plans/20260221-events-dialog-depth.md` (`F1`).
9. `OF-EV-03` Event data surfaced in structure/overlay views.
   Source: `plans/20260221-gui-events-and-triage-deprecation.md` (`N2`, `Follow-on plans`).
10. `OF-OV-01` `graph.structure.overlay.depth N` variant.
    Source: `plans/20260221-graph-structure-overlay-pseudo-nodes.md` (`Query interface`, deferred depth variant).
11. `OF-OV-02` Event-graph overlay anchors (`startxref`/`trailer` pseudo-nodes in event graph).
    Source: `plans/20260221-graph-structure-overlay-pseudo-nodes.md` (`graph.event overlay anchor (deferred)`).
12. `OF-OV-03` GUI graph viewer integration for structure overlay data.
    Source: `plans/20260221-graph-structure-overlay-pseudo-nodes.md` (out of scope/deferred GUI integration notes).
13. `OF-CSV-01` Findings CSV export workflow for external analyst tooling.
    Source: `plans/20260221-gui-events-and-triage-deprecation.md` (`Follow-on plans`, item 1).

### Native/runtime/release optionals

14. `OF-NAT-01` Native analysis threading (non-blocking UI during analysis).
    Source: `plans/20260222-native-binary.md` (`Follow-on plans`, item 1).
15. `OF-NAT-02` CI screenshot smoke test (Xvfb + Mesa).
    Source: `plans/20260222-native-binary.md` (`Follow-on plans`, item 2).
16. `OF-NAT-03` System packaging (`.desktop`, icon, `.rpm`/`.deb`/`.AppImage`).
    Source: `plans/20260222-native-binary.md` (`Follow-on plans`, item 3; additional packaging references in risks/acceptance).
17. `OF-NAT-04` macOS and Windows native GUI targets.
    Source: `plans/20260222-native-binary.md` (`Follow-on plans`, item 4).
    Note: CLI release-ci.yml already builds CLI binaries for `x86_64-pc-windows-msvc` and
    `aarch64-apple-darwin`. Work here is scoped to adding `--features gui` and a GUI smoke job.

### New opportunities (identified in roadmap review)

18. `OF-FUZZ-01` Fuzz target expansion for new attack surfaces.
    Rationale: A1, A2, and A5 introduce new parsing/execution paths with no fuzz coverage.
19. `OF-QUERY-01` `query.rs` module decomposition.
    Rationale: `query.rs` is already 457 KB; each new query variant increases maintenance risk.
20. `OF-BATCH-01` Parallel batch processing.
    Rationale: AGENTS.md targets 500,000+ PDF throughput; current batch mode is sequential.
21. `OF-DIAG-01` Structured per-detector diagnostic output.
    Rationale: Existing runtime-profile covers phases but not per-detector timing for pipeline monitoring.
22. `OF-WASM-01` WASM build parity CI gate.
    Rationale: GUI items B3 and B6 touch `sis-pdf-gui` which compiles to both native and WASM;
    no WASM CI gate currently protects GUI regression.
23. `OF-SEC-01` Fingerprint baseline integrity and provenance hardening.
    Rationale: `OF-CS-04` introduces external baseline-profile ingestion; untrusted or stale baseline
    files can skew triage and should carry provenance and integrity metadata.
24. `OF-OBS-01` Resource-cap telemetry and query surface.
    Rationale: A1/A2/A6 introduce caps and truncation paths; operators need first-class visibility
    into cap-hit frequency across large corpus runs.
25. `OF-REL-01` Phase-gate rollback playbook.
    Rationale: Multiple optional items alter query/event/output surfaces; pre-release still needs
    deterministic rollback criteria when regressions exceed safety or SLO limits.

## Discovered optionals already delivered (tracked for provenance only)

1. `OF-DONE-01` CLI `sis query events` surface.
   Source: `plans/20260221-gui-events-and-triage-deprecation.md` (`N1`), and
   `plans/20260221-events-dialog-depth.md` (`G7`).
   Delivery status: implemented in current codebase (`events`, `events.full`,
   `events.count`, level-filtered variants).

## Gaps and risks

This section records identified gaps, risks, and the items added or amended to address them.

### Gaps

1. **Missing inter-item dependency declaration** — `OF-CS-06` uses fingerprints from `OF-CS-04`
   but the original sequencing did not document this. Addressed: explicit dependency note added
   to CS-06 in source inventory and in the phase table.

2. **No SLO targets for new features** — A3 and A4 mention "budget tests" but specify no
   concrete SLO values, inconsistent with the existing SLO table in AGENTS.md.
   Addressed: concrete targets added to each item's acceptance criteria.

3. **`OF-CS-05` missing severity/confidence specification** — unlike A2 (`Tentative`/`Probable`),
   A5 gave no detector calibration guidance. Addressed: A5 now specifies defaults and calibration
   criteria.

4. **No fuzz coverage for new execution paths** — A1, A2, and A5 create new parsing/analysis
   paths with no corresponding fuzz targets. Addressed: `OF-FUZZ-01` added as a new item.

5. **Documentation commits not required per-item** — AGENTS.md requires docs in the same commit
   as behaviour changes; only B7 and C4 originally mentioned doc updates. Addressed: each item
   now has an explicit documentation task in its acceptance criteria.

6. **Corpus manifest requirements omitted** — AGENTS.md mandates manifest registration for new
   fixtures. Addressed: each test section that introduces new fixtures now references manifest
   registration.

7. **WASM build compatibility not addressed for GUI items** — B3 and B6 touch the GUI crate
   which compiles to WASM. No parity check was planned. Addressed: `OF-WASM-01` added and each
   GUI item notes the WASM compile check requirement.

8. **`OF-NAT-04` overstates CI work needed** — macOS and Windows CLI runners already exist in
   `.github/workflows/release-cli.yml`. The real gap is adding `--features gui` to those jobs.
   Addressed: C4 scope corrected to extend existing matrix rather than create new runners.

9. **Missing batch mode considerations** — A3 (per-page execution query) and A4 (fingerprinting)
   did not address batch pipeline behaviour. Addressed: batch mode notes added to each item.

10. **Fingerprinting corpus baseline undefined** — A4 references a "local JSON profile file for
    benign centroids" with no plan for how it is created, versioned, or shipped.
    Addressed: baseline creation and storage addressed in A4 implementation detail.

11. **`OF-EV-01` does not address `--count` parity** — adding `--full` without clarifying
    whether `--count` and level-filter flags are also exposed creates a partial API surface.
    Addressed: B1 now requires explicit flag inventory and rejects partial flag exposure.

12. **No explicit rollback gate per phase** — phases list implementation order but not the
    criteria for halting or reverting a phase. Addressed: `OF-REL-01` added with explicit
    rollback trigger thresholds and response path.

13. **Baseline-profile trust model unspecified** — A4 baseline loader accepts local JSON but
    lacks integrity/provenance validation guidance. Addressed: `OF-SEC-01` adds signed-manifest
    and provenance metadata requirements.

14. **Cap-hit observability is local-only metadata** — truncation fields exist on individual
    outputs but no aggregate query exists for batch triage. Addressed: `OF-OBS-01` adds
    runtime-profile counters and query exposure.

### Risks

1. **`query.rs` size explosion** — the file is already 457 KB; each new query variant
   increases maintenance cost and risk. `OF-QUERY-01` must precede or accompany
   Phase 2 query additions.

2. **Adversarial resource exhaustion in A1** — depth 8 and edge cap 128 are specified,
   but wide-and-shallow graphs can exhaust memory before the edge cap is reached. A
   resident memory budget (see A1 implementation) must be added.

3. **A2 false positive risk before corpus calibration** — heuristics using fixed thresholds
   (64 KB, filter chain patterns) must be corpus-calibrated before any confidence above
   `Tentative` is assigned. Confidence promotion is gated on corpus acceptance criteria.

4. **A6 scaling risk** — PDFs with many revisions (100+) have no revision comparison cap.
   An uncapped revision diffing pass could stall batch pipelines. Cap added to A6.

5. **C1 WASM threading incompatibility** — `std::thread` is not available in WASM builds.
   The "inline fallback for test builds" note does not fully address this. C1 now requires
   a `#[cfg(not(target_arch = "wasm32"))]` guard and a defined WASM no-op path.

6. **C2 Xvfb screenshot CI flakiness** — headless rendering tests are known to produce
   intermittent failures in shared CI runners. C2 implementation now includes retry strategy.

7. **B5 anchor node event graph inflation** — adding anchor nodes to every event graph
   without a size budget risks output bloat for complex documents. B5 now requires explicit
   node and edge budgets.

8. **macOS code signing omission in C4** — macOS GUI distribution requires code signing
   and notarisation. Without it, Gatekeeper will block the binary. C4 now explicitly
   calls this out as a known requirement for distribution readiness.

9. **Fingerprint baseline poisoning risk** — external centroid files can be tampered with or
   built from unrepresentative corpora, degrading anomaly scoring quality. `OF-SEC-01` adds
   integrity and provenance controls to reduce this risk.

10. **Parallel batch memory-pressure risk** — D3 parallelism can amplify peak RSS under deep
    decode workloads if concurrency is uncapped by resource class. D3 now includes bounded
    jobs policy and memory-aware defaults.

## Assumptions

1. Current default behaviour remains stable unless behind explicit flags.
2. Strict automated testing and baseline regressions are mandatory before rollout.
3. GUI dependencies must not leak into non-GUI builds.
4. Safety and bounded-resource behaviour take precedence over feature depth.
5. Any export schema additions are additive and versioned.
6. `blake3` is already present in the workspace `Cargo.toml` and requires no new dependency.
7. CI already provides Linux/macOS/Windows runners; new work extends existing workflows
   rather than creating new CI infrastructure from scratch.
8. Pre-release compatibility rules allow additive or breaking query ergonomics where needed;
   external tooling adaptation is expected during this phase.

## Priority and sequencing

### Phase 0 (governance and guardrails)

1. `OF-WASM-01` WASM build parity CI gate.
2. `OF-SEC-01` Fingerprint baseline integrity and provenance.
3. `OF-OBS-01` Resource-cap telemetry/query.
4. `OF-REL-01` Phase-gate rollback playbook.

### Phase 1 (high value, low coupling)

1. `OF-QUERY-01` Query module decomposition (prerequisite for all Phase 2+ query additions).
2. `OF-CS-01` Do recursion tracer.
3. `OF-CS-02` Inline image anomaly detector.
4. `OF-CS-03` Per-page execution summary query.
5. `OF-EV-01` `--full` / `--count` flag inventory for events query.

### Phase 2 (analytics depth and correlation)

1. `OF-CS-04` Content stream fingerprinting. *(prerequisite for CS-06)*
2. `OF-CS-05` Type3 charproc suspicious-ops detector.
3. `OF-CS-06` Cross-revision content stream diffing. *(requires CS-04)*
4. `OF-EV-02` Bidirectional finding/event indexing expansion.
5. `OF-FUZZ-01` Fuzz target expansion.
6. `OF-BATCH-01` Parallel batch processing.

### Phase 3 (overlay and export integration)

1. `OF-OV-01` Overlay depth query.
2. `OF-OV-02` Event-graph anchors.
3. `OF-OV-03` GUI overlay integration.
4. `OF-CSV-01` Findings CSV export.
5. `OF-DIAG-01` Structured per-detector diagnostics.

### Phase 4 (native platform/release hardening)

1. `OF-NAT-01` Analysis threading.
2. `OF-NAT-02` Screenshot CI.
3. `OF-NAT-03` Packaging.
4. `OF-NAT-04` macOS/Windows native GUI targets.

### Phase 5 (event annotation and advanced overlay)

1. `OF-EV-03` Event annotations in overlay views.

## Detailed technical plan

## Workstream A: Content stream execution depth

### A1. `OF-CS-01` Do chain recursion tracer

Goal: Model nested form-XObject execution chains as bounded `ContentStreamExec` lineage.

Implementation:
1. Add recursion walker in core projection layer:
   - File: `crates/sis-pdf-core/src/event_projection.rs`.
   - New helper: `trace_nested_do_chains(...)` with max depth default `8`.
2. Resolve `Do` name -> `/Resources/XObject` -> object ref, recurse only when subtype `/Form`.
3. Emit nested execution records in overlay/projection payload:
   - add nested execution array on `StreamExecSummary` (additive field), or
   - emit separate overlay pseudo edges `event -> nested-stream` for `graph.event.stream*`.
4. Add event metadata key format: `xobject.form.nested.{depth}`.
5. Add loop protection by `(source_event_id, target_obj_ref, depth)` visited set.
6. Add resident memory budget guard: abort traversal and emit truncation metadata
   when accumulated `StreamExecSummary` entries for a single root event exceed 4 MB.
   This bounds adversarial wide-and-shallow graphs independently of the edge cap.

Safety/performance constraints:
1. Max depth 8.
2. Max nested edges per root event 128.
3. Max resident memory per root event 4 MB.
4. Truncation metadata field when any limit is hit.
5. SLO: overhead on CVE fixture (no nested forms) must remain < 2 ms.

Tests:
1. Synthetic fixture with 3-level nested form Do chain — register in corpus manifest.
2. Cycle fixture (`FormA -> FormB -> FormA`) must terminate with truncation/loop marker, no panic.
3. Wide fixture (128+ flat sibling XObjects) must hit edge cap cleanly.
4. Budget test on CVE fixture with negligible overhead when no nested forms (< 2 ms SLO).

Documentation:
- Update `docs/query-interface.md` with nested execution section.
- Update `docs/findings.md` if nested chain metadata appears in any finding.

Acceptance:
1. Nested paths visible in stream overlay JSON/DOT.
2. No default event-count regression for base `events` query.
3. Memory guard tested and proven effective on adversarial fixture.
4. Docs updated in same commit as behaviour change.

### A2. `OF-CS-02` Inline image anomaly detector

Goal: Detect inline-image payload-carrier patterns in content streams.

Implementation:
1. Add detector in `crates/sis-pdf-detectors/src/content_stream_exec_uplift.rs` (or split module):
   - finding kind: `content_stream_inline_image_anomaly`.
2. Parse inline image segments (`BI ... ID ... EI`) from content op stream.
3. Heuristics:
   - raw inline image data > 64 KB,
   - suspicious filter chain (for example `/ASCII85Decode` + `/FlateDecode` in inline context),
   - inline image presence with near-absence of text/path ops.
4. Metadata:
   - `inline.count`, `inline.max_bytes`, `inline.filter_chains`, `stream.obj`, `page.number`.
5. Initial confidence assignment: `Tentative` for threshold-only triggers; `Probable` only
   after corpus calibration confirms false positive rate < 1% across the benign corpus.
   Confidence promotion requires a recorded corpus run in the baseline deltas section
   of this plan before merging the promotion.

Tests:
1. Malicious synthetic fixture with oversized inline image and suspicious filters -> finding
   expected. Register in corpus manifest.
2. Benign fixture with standard inline image usage -> no finding.
3. Corpus regression run to validate false-positive profile before any confidence promotion.

Documentation:
- Add `content_stream_inline_image_anomaly` finding entry to `docs/findings.md`.
- Note in `docs/query-interface.md` that the finding appears in `events.full` output.

Acceptance:
1. Deterministic detection with bounded memory.
2. Confidence defaults `Tentative`, calibrated by corpus before any promotion.
3. Corpus calibration result recorded in this plan's baseline deltas section.
4. Docs updated in same commit as behaviour change.

### A3. `OF-CS-03` Per-page execution surface summary query

Goal: Provide analyst-ready page execution overview without manual joins.

Implementation:
1. Add query variants in `crates/sis-pdf/src/commands/query/` (post `OF-QUERY-01` split):
   - `pages.execution` (table/text),
   - `pages.execution.json`.
2. Back data with `StreamExecSummary` grouped by page source object.
3. Output fields per page:
   - `page_ref`, `content_stream_count`, `total_ops`, `op_family_counts`,
   - `resource_names`, `anomaly_flags`, `linked_finding_ids`.
4. Add predicate support fields consistent with existing `--where` syntax:
   - `page`, `total_ops`, `anomaly_count`, `resource_count`.
5. Batch mode: emit one JSON object per file in JSONL format for batch pipeline use;
   continue on errors and emit error rows.

SLO: `pages.execution.json` on a 100-page CVE fixture must return in < 100 ms.

Tests:
1. Parse/query alias tests.
2. JSON schema shape test on fixture.
3. Predicate filtering test using `--where total_ops>0`.
4. Batch-mode continuation test: one invalid file does not halt processing.
5. SLO budget test (< 100 ms on 100-page fixture).

Documentation:
- Add `pages.execution` section to `docs/query-interface.md`.
- Include example output and predicate reference.

Acceptance:
1. One command returns page-level execution narrative.
2. Stable deterministic row ordering.
3. `--where` predicates behave identically to existing query predicates.
4. Batch mode works and is documented.
5. Docs updated in same commit.

### A4. `OF-CS-04` Content stream fingerprinting enhancements

Goal: Compute stable stream fingerprints for anomaly and similarity scoring.

Implementation:
1. Add `StreamFingerprint` struct in core projection:
   - normalised operator-family histogram,
   - optional hashed resource-name pattern vector,
   - compact fingerprint id (`blake3` over normalised features; already in workspace).
2. Add CLI query in `crates/sis-pdf/src/commands/query/` (post split):
   - `streams.fingerprint` / `streams.fingerprint.json`.
3. Add optional corpus baseline loader:
   - local JSON profile file path configurable via `--baseline-profile` flag.
   - file format: versioned JSON with `schema_version` field and array of benign centroid
     histogram vectors (one entry per known-benign cluster).
   - do not embed a baseline in the binary; this keeps the binary lean and avoids
     shipping a baseline that may become stale or misleading.
   - provide a helper script (`scripts/build_fingerprint_baseline.py`) to create a
     baseline from a labelled corpus directory.
4. Add score fields (only present when baseline loaded):
   - `distance_to_benign_centroid`, `outlier_score`.
5. Batch mode: fingerprints are emitted per-stream in JSONL; one object per file when batching.

SLO: fingerprint computation for a 1 MB content stream must complete in < 10 ms.

Tests:
1. Determinism test (same PDF -> same fingerprint).
2. Small edit sensitivity test (operator-family change alters fingerprint).
3. SLO budget test (< 10 ms per 1 MB stream).
4. Baseline loader test: valid baseline file produces score fields; absent baseline omits them.
5. Invalid baseline format returns `QueryResult::Error` with `QUERY_SYNTAX_ERROR`.

Documentation:
- Add `streams.fingerprint` section to `docs/query-interface.md`.
- Add `scripts/build_fingerprint_baseline.py` usage notes to `docs/analysis.md`.

Acceptance:
1. Fingerprints are stable and cheap.
2. Score is additive metadata; no hard blocking behaviour.
3. Baseline is external, versioned, and opt-in via flag.
4. Docs updated in same commit.

### A5. `OF-CS-05` Type3 charproc suspicious-ops detector

Goal: Close Type3 charproc execution gap.

Implementation:
1. Extend detector path to inspect Type3 `/CharProcs` streams.
2. Emit finding `type3_charproc_suspicious_ops` when suspicious op profile appears:
   - `Do` invocation inside charproc (typically not valid),
   - resource-name obfuscation patterns matching existing detector heuristics,
   - excessive operator count relative to expected glyph-drawing ops.
3. Severity: `Medium` (potential code smuggling path, requires rendering context to trigger).
   Confidence: `Tentative` initially; promote to `Probable` after corpus calibration.
   Calibration criteria: false positive rate < 2% on benign corpus before promotion.
4. Reuse existing Type3 execution options in event graph where possible.

Tests:
1. Synthetic Type3 fixture with suspicious `Do`-heavy charproc -> finding expected.
   Register in corpus manifest.
2. Benign Type3 fixture (standard glyph drawing ops only) -> no finding.
3. Corpus calibration run recorded in baseline deltas before confidence promotion.

Documentation:
- Add `type3_charproc_suspicious_ops` finding entry to `docs/findings.md` with
  severity `Medium`, confidence `Tentative` (initial), and calibration note.

Acceptance:
1. Charproc streams are first-class attack-surface checks.
2. Severity/confidence guidance matches AGENTS.md definitions.
3. Docs updated in same commit.

### A6. `OF-CS-06` Cross-revision content stream diffing

Goal: Detect anti-forensic stream replacement across incremental revisions.

**Dependency: requires `OF-CS-04` (content stream fingerprinting) to be complete.**

Implementation:
1. Build revision-aware stream map using revision extraction index.
2. Cap the number of revisions compared to the earliest and latest 10 revisions when
   the document has more than 20 revisions. Emit truncation metadata field
   `revision_diff_truncated: true` when cap is applied.
3. Compare fingerprints/operator summaries between earliest and latest revision per page stream lineage.
4. Emit finding `content_stream_revision_drift_suspicious` for high delta:
   - new `Do` invocations,
   - large operator-family ratio shift,
   - newly introduced anomaly flags.

Tests:
1. Synthetic incremental-update fixture introducing drift -> finding expected.
   Register in corpus manifest.
2. Baseline fixture with no drift -> no finding.
3. High-revision-count fixture (> 20 revisions) -> truncation metadata present,
   no stall or memory explosion.

Documentation:
- Add `content_stream_revision_drift_suspicious` finding entry to `docs/findings.md`.
- Note dependency on fingerprinting in `docs/query-interface.md`.

Acceptance:
1. Meaningful diffs with low noise.
2. Metadata includes revision refs and delta summary.
3. Revision cap enforced and documented.
4. Docs updated in same commit.

## Workstream B: Event/query/overlay follow-ons

### B1. `OF-EV-01` Flag inventory for `events` query

Implementation:
1. CLI flag parse in `sis query` command path:
   - `events --full` maps to `events.full` query variant (existing).
   - `events --count` maps to `events.count` query variant (existing).
   - `--where` predicate syntax applies to both short and full forms.
   - Level filter flags (`--level critical` etc.) apply consistently.
2. All new flags must be listed in `docs/query-interface.md` under the events section.
3. Keep existing `events.full` query unchanged; flags are aliases only.

Tests:
1. Flag parsing and output parity test for `--full` vs `events.full`.
2. Flag parsing and output parity test for `--count` vs `events.count`.
3. `--where` predicate applied via flag produces same output as dotted query with predicate.
4. Conflict test: `--full --count` returns `QueryResult::Error`.

Documentation:
- Update `docs/query-interface.md` events section with complete flag reference.

Acceptance:
1. All existing query variants are reachable via flags.
2. No partial flag surface (all or nothing).
3. Docs updated in same commit.

### B2. `OF-EV-02` Bidirectional finding/event index expansion

Goal:
Enable stable, first-class finding/event round-trip navigation in CLI and GUI.

Implementation:
1. Core index model:
   - File: `crates/sis-pdf-core/src/event_projection.rs`.
   - Add/extend projection output to include:
     - `finding_event_index: finding_id -> Vec<event_node_id>`
     - `event_finding_index: event_node_id -> Vec<finding_id>` (additive helper map).
2. Report payload integration:
   - File: `crates/sis-pdf-core/src/report.rs` (or report assembly path).
   - Add optional `event_indexes` block in JSON output, versioned by schema tag.
3. Query integration:
   - File: `crates/sis-pdf/src/commands/query/` (post split).
   - Ensure `events.full` exposes both maps under deterministic ordering (sorted keys/values).
4. GUI round-trip:
   - Files: `crates/sis-pdf-gui/src/panels/events.rs`, `crates/sis-pdf-gui/src/panels/findings.rs`, `crates/sis-pdf-gui/src/app.rs`.
   - Add actions:
     - finding detail: `Jump to event` (uses `finding_event_index`),
     - event detail: `Show linked finding` (uses `event_finding_index`),
     - fallback behaviour when no linked row exists.
   - WASM compile check: all new GUI paths must compile without `std::thread` or
     non-WASM-safe crates.
5. Stability contract:
   - Missing links render as empty list, not error.
   - Maps are additive; existing output keys unchanged.

Tests:
1. Core unit test: map generation is deterministic and deduplicated.
2. Query test: `events.full` contains both maps with stable ordering.
3. GUI integration tests:
   - finding -> event jump selects expected event node,
   - event -> finding jump selects expected finding row.
4. Backward-compat test: old consumers parsing `events.full.events` still succeed.
5. WASM build check: `cargo build -p sis-pdf-gui --target wasm32-unknown-unknown`.

Documentation:
- Add index structure description to `docs/query-interface.md`.
- Update `docs/schema-changelog.md` with additive `event_indexes` field note.

Acceptance:
1. Round-trip navigation works without manual ID copy.
2. JSON contracts remain additive and deterministic.
3. WASM build unaffected.
4. Docs updated in same commit.

### B3. `OF-EV-03` Event annotations in overlay views

Goal:
Expose event intensity directly in structure overlay views.

Implementation:
1. Overlay schema extension:
   - File: `crates/sis-pdf-core/src/structure_overlay.rs`.
   - Add optional `event_annotations` section:
     - `by_object_ref: obj:gen -> { event_count, event_types, max_severity }`
     - `by_event_node: event_node_id -> { linked_finding_count, trigger_class }`.
2. Data join:
   - Join from EventGraph object nodes and event nodes to overlay object IDs.
   - Severity derived from linked findings (worst severity).
3. Query path:
   - File: `crates/sis-pdf/src/commands/query/` (post split).
   - `graph.structure.overlay.json` includes `event_annotations` only when event data available.
4. GUI rendering:
   - File: `crates/sis-pdf-gui/src/panels/graph.rs`.
   - Add optional badge layer:
     - small count badge for objects with events,
     - colour intensity by worst linked severity.
5. Controls:
   - Add UI toggle `Show event annotations`.
   - Default on for overlay mode, off for baseline structure mode.
6. WASM compatibility:
   - Badge rendering must use only egui primitives; no native-only APIs.
   - Confirm with `cargo build -p sis-pdf-gui --target wasm32-unknown-unknown`.

Tests:
1. Overlay JSON contract test with/without annotations block.
2. Mapping test: known fixture object with event links gets expected count/type.
3. GUI render test: badge appears and updates with toggle.
4. Performance budget test: annotation join does not exceed established graph panel budget tolerance.
5. WASM build check.

Documentation:
- Update `docs/query-overlay.md` with `event_annotations` schema.
- Update `docs/query-interface.md` with GUI toggle description.

Acceptance:
1. Analysts can identify event hotspots from structure view alone.
2. No change to baseline structure overlay when annotation block is absent.
3. WASM build unaffected.
4. Docs updated in same commit.

### B4. `OF-OV-01` `graph.structure.overlay.depth N`

Goal:
Provide bounded overlay views for large/complex files.

Implementation:
1. Query surface:
   - File: `crates/sis-pdf/src/commands/query/` (post split).
   - Add parse variants:
     - `graph.structure.overlay.depth N`
     - `graph.structure.overlay.telemetry.depth N` (optional parity).
2. Traversal model:
   - File: `crates/sis-pdf-core/src/structure_overlay.rs`.
   - Implement BFS depth cap from anchor set:
     - anchors: `file.root`, `startxref.*`, optionally `revision.*`.
   - Include nodes/edges with minimum distance `<= N`.
3. Truncation metadata:
   - Add to overlay stats:
     - `depth_limit`,
     - `depth_truncated`,
     - `dropped_node_count`,
     - `dropped_edge_count`.
4. DOT export:
   - Add comment header noting applied depth.

Tests:
1. Query parse and output-format coercion tests for depth variant.
2. Snapshot test for fixed fixture at depth `1`, `2`, `3`.
3. Invariant test: increasing depth is monotonic for node/edge count.
4. Fail-closed test: invalid depth returns `QueryResult::Error` with `QUERY_SYNTAX_ERROR`.

Documentation:
- Update `docs/query-overlay.md` with depth variant, truncation metadata schema,
  and example commands.

Acceptance:
1. Depth-limited overlay is deterministic and explicitly labelled.
2. Analysts can reduce visual noise without losing schema clarity.
3. Docs updated in same commit.

### B5. `OF-OV-02` Event-graph anchor nodes

Goal:
Connect structural provenance anchors into event graph narratives.

Implementation:
1. Event node model:
   - File: `crates/sis-pdf-core/src/event_graph.rs`.
   - Add `EventNodeKind::Anchor { anchor_type, label, source_ref }` (additive).
2. Anchor extraction:
   - Map `startxref`, `xref.section`, `trailer` pseudo entities to anchor nodes.
3. Edge model:
   - Add anchor edge kinds (or reuse `References` with metadata) for:
     - `anchor_to_object`,
     - `anchor_to_event`,
     - `anchor_to_outcome` (when derived relation exists).
4. Size budget:
   - Cap anchor nodes at 64 per document (emit `anchor_nodes_truncated` metadata flag
     when exceeded). This prevents event graph bloat for documents with many xref revisions.
   - Cap anchor edges at 256 per document.
5. Query gating:
   - File: `crates/sis-pdf/src/commands/query/` (post split).
   - Add explicit variant/flag:
     - `graph.event.anchor` and json/dot aliases,
     - baseline `graph.event` unchanged.
6. Serialisation:
   - Ensure anchor nodes are additive in JSON and DOT exporters.

Tests:
1. Schema test: `graph.event.anchor.json` contains anchor nodes with stable IDs.
2. Edge test: known trailer-linked object produces expected anchor edge.
3. Compatibility test: `graph.event.json` unchanged when anchor mode not used.
4. Budget test: document with 100+ revisions produces at most 64 anchor nodes.

Documentation:
- Update `docs/query-interface.md` with `graph.event.anchor` variant.
- Update `docs/graph-model-schema.md` with anchor node schema.

Acceptance:
1. Structural provenance can be analysed in event graph mode when requested.
2. Default event graph size and semantics remain stable.
3. Anchor node and edge caps enforced and documented.
4. Docs updated in same commit.

### B6. `OF-OV-03` GUI structure overlay integration

Goal:
Make structure overlay first-class in GUI graph exploration.

Implementation:
1. Data model:
   - Files: `crates/sis-pdf-gui/src/analyzer.rs`, `crates/sis-pdf-gui/src/model.rs`.
   - Carry overlay payload in analysis result cache.
2. Graph renderer:
   - File: `crates/sis-pdf-gui/src/panels/graph.rs`.
   - Distinct visuals for pseudo nodes:
     - startxref/xref/trailer/revision/objstm/telemetry/signature.
   - Distinct edge styles:
     - suspicious edges high-contrast stroke,
     - provenance edge styles dashed/solid by type.
3. UX affordances:
   - toggles:
     - `Show overlay`,
     - `Show telemetry nodes`,
     - `Show event annotations` (if B3 shipped).
4. Selection bridge:
   - clicking pseudo nodes opens detail panel with attrs JSON and related objects.
5. WASM compatibility:
   - all rendering must use egui-only primitives.
   - Confirm with `cargo build -p sis-pdf-gui --target wasm32-unknown-unknown`.

Tests:
1. GUI unit tests for overlay node/edge to draw primitive mapping.
2. Interaction tests for layer toggle and node-detail panel.
3. WASM compile check: `cargo build -p sis-pdf-gui --target wasm32-unknown-unknown`.

Documentation:
- Add overlay controls reference to user-facing docs (README or `docs/analysis.md`).

Acceptance:
1. Overlay is readable and actionable in GUI.
2. Turning overlay off restores existing graph behaviour exactly.
3. WASM build unaffected.
4. Docs updated in same commit.

### B7. `OF-CSV-01` Findings CSV export

Goal:
Provide analyst-friendly tabular exports for external tooling.

Implementation:
1. Query/export interface:
   - File: `crates/sis-pdf/src/commands/query/` (post split).
   - Add CSV support for findings-family queries:
     - `findings`, `findings.composite`, optional `events.full` companion tables.
2. Schema contract:
   - New/updated doc: `docs/findings-csv-schema.md` (or extend existing schema docs).
   - Include version header row or metadata key:
     - `schema_version=1`.
3. Field normalisation:
   - flatten multi-value fields with stable delimiters,
   - escape delimiter/newline/quote safely per RFC 4180,
   - preserve severity/impact/confidence as explicit columns,
   - include stable IDs and object refs.
4. Batch support:
   - ensure `--path` batch mode continues on errors and emits error rows.

Tests:
1. Golden CSV snapshots for representative findings sets.
2. Round-trip parseability test with RFC 4180 parser.
3. Batch-mode continuation test with one invalid file.
4. Regression test for deterministic column order.

Documentation:
- Create or update `docs/findings-csv-schema.md` with field definitions, version history,
  and example rows.

Acceptance:
1. CSV output is machine-parseable and stable.
2. Analysts can ingest exports without post-cleanup.
3. Docs updated in same commit.

## Workstream C: Native/runtime/release optionals

### C1. `OF-NAT-01` Native analysis threading

Goal:
Prevent UI stalls during large-file analysis.

Implementation:
1. Worker architecture:
   - Files: `crates/sis-pdf-gui/src/app.rs`, `crates/sis-pdf-gui/src/analyzer.rs`.
   - Add background worker pool (single-worker default), mpsc channel to UI.
   - Guard all threading code with `#[cfg(not(target_arch = "wasm32"))]`.
   - WASM path: retain existing inline analysis (no-op threading); document as known limitation.
2. Task model:
   - `AnalyseFile { path, options, request_id }`
   - `Cancel(request_id)` for stale requests.
3. State model:
   - `Idle`, `Running`, `Cancelling`, `Completed`, `Failed`.
   - UI progress and status line updates from worker messages.
4. Safety:
   - cancel-on-new-file behaviour to avoid overlapping stale updates,
   - only latest `request_id` can mutate visible analysis state.

Tests:
1. Integration test: UI remains responsive while analysis runs (native only).
2. Cancellation test: older request cannot overwrite newer result.
3. Repeated-open stress test with quick consecutive files.
4. WASM compile check confirming threading code is excluded.

Documentation:
- Note native-only threading in `docs/configuration.md`.
- Note WASM limitation in FAQ or `docs/faq.md`.

Acceptance:
1. No long main-thread freezes during analysis (native).
2. Deterministic final state for rapid user actions.
3. WASM build unaffected.
4. Docs updated in same commit.

### C2. `OF-NAT-02` CI screenshot smoke

Goal:
Catch blank-window/regression issues in headless CI.

Implementation:
1. CI job:
   - Extend `.github/workflows/quality-gates.yml` with a new step (not a new workflow file).
   - Linux runner with `xvfb-run`, Mesa software renderer (`libgl1-mesa-swrast`).
2. Smoke harness:
   - launch `sis gui` with fixture path,
   - wait for initial frame (poll with timeout 30 s),
   - capture screenshot via `xwd` or similar,
   - assert non-empty/non-monochrome baseline invariants.
3. Retry strategy:
   - retry up to 2 times on non-assertion failure (e.g., display initialisation race).
   - fail definitively on third attempt.
4. Artefact retention:
   - save screenshot and logs on failure using `actions/upload-artifact`.

Tests:
1. CI-only smoke step + local script `scripts/gui_smoke.sh` for reproducibility.

Documentation:
- Add GUI smoke test instructions to `docs/analysis.md` or README.

Acceptance:
1. Renderer startup regressions are detected before merge.
2. Retry strategy reduces flakiness without masking real failures.
3. Docs note how to run smoke locally.

### C3. `OF-NAT-03` System packaging

Goal:
Ship installable Linux desktop packages with consistent identity.

Implementation:
1. App identity and assets:
   - add `.desktop` file matching app-id used in runtime options,
   - install icons and metadata files.
2. Packaging pipelines:
   - `fpm`/native tooling or distro-native recipes for `.deb` and `.rpm`,
   - `.AppImage` build for portable distribution.
3. Release artefact naming/version stamping:
   - include git tag + target triple in package metadata.

Tests:
1. Lint `.desktop` with `desktop-file-validate`.
2. Install/uninstall smoke in container images (`ubuntu`, `fedora`).
3. Launch smoke verifying menu entry and icon resolution.

Documentation:
- Add Linux package installation instructions to README or `docs/analysis.md`.

Acceptance:
1. Packages install and launch cleanly across target distros.
2. Desktop metadata is standards-compliant.
3. Docs updated in same commit.

### C4. `OF-NAT-04` macOS/Windows native GUI targets

Goal:
Enable cross-platform native GUI builds and baseline runtime support.

Note: The existing `release-cli.yml` already builds CLI binaries for
`x86_64-pc-windows-msvc` and `aarch64-apple-darwin`. This item extends those
existing matrix jobs to add `--features gui`; it does not create new runners.

Implementation:
1. Build plumbing:
   - add `--features gui` to existing macOS and Windows matrix jobs in `release-cli.yml`.
   - update target-specific `NativeOptions` configuration (windowing, app-id/title, dpi defaults).
2. Platform wrappers:
   - file-open dialog compatibility layer,
   - clipboard and drag-drop parity behaviour,
   - platform-specific path normalisation and error handling.
3. Code signing (known distribution blocker):
   - macOS: document the Gatekeeper requirement; add notarisation step to release workflow
     when a signing identity is available. Mark as distribution-blocking if signing is absent.
   - Windows: document SmartScreen warning for unsigned binaries. Add Authenticode signing
     step to release workflow when a certificate is available.
   - If signing is not yet available, ship with a documented caveat rather than blocking release.
4. CI matrix extension:
   - extend existing `quality-gates.yml` with a cross-platform build check step
     (`cargo build -p sis-pdf --features gui --target ...`) on macOS and Windows runners.
   - optional launch smoke for signed-off runner environments.
5. Documentation:
   - update README with platform caveats, signing status, and known limits.
   - update `docs/configuration.md` for platform-specific options.

Tests:
1. `cargo build -p sis-pdf --features gui` on macOS + Windows in existing CI matrix.
2. Basic native smoke tests (open file, run analysis, copy text).
3. Snapshot test for platform-specific window-state persistence serialisation.

Acceptance:
1. Native GUI builds succeed on macOS and Windows.
2. Core analyst workflow (open/analyse/view/copy) works on both targets.
3. Code signing status is documented (either implemented or explicitly deferred with caveat).
4. Docs updated in same commit.

## Workstream D: Infrastructure and tooling

### D1. `OF-QUERY-01` Query module decomposition

Goal:
Reduce `commands/query.rs` (currently 457 KB) to a maintainable module tree
before adding further query variants in Phase 2 and 3.

Implementation:
1. Split `crates/sis-pdf/src/commands/query.rs` into a module directory:
   - `crates/sis-pdf/src/commands/query/mod.rs` — shared types, dispatch, error handling.
   - `crates/sis-pdf/src/commands/query/content_stream.rs` — `pages.*`, `streams.*` queries.
   - `crates/sis-pdf/src/commands/query/events.rs` — `events.*` queries.
   - `crates/sis-pdf/src/commands/query/graph.rs` — `graph.*` queries.
   - `crates/sis-pdf/src/commands/query/findings.rs` — `findings.*`, `chains.*` queries.
   - `crates/sis-pdf/src/commands/query/export.rs` — CSV, JSON export helpers.
   - Additional modules as needed for remaining query families.
2. No behaviour change; all existing query strings and outputs must remain identical.
3. Migrate one module at a time to minimise merge conflicts.

Tests:
1. All existing query tests must pass without modification.
2. Add a module-level compilation test confirming no public surface regression.

Documentation:
- No user-facing doc changes required (internal refactor only).

Acceptance:
1. No single source file in the query tree exceeds 100 KB.
2. All existing tests pass.
3. No public API surface change.

### D2. `OF-FUZZ-01` Fuzz target expansion

Goal:
Provide fuzz coverage for new attack surfaces introduced by A1, A2, and A5.

Implementation:
1. Add fuzz target `fuzz/fuzz_targets/do_chain_recursion.rs`:
   - input: arbitrary PDF bytes,
   - harness: invoke `trace_nested_do_chains` on parsed content streams,
   - assert: terminates without panic, respects depth/edge/memory caps.
2. Add fuzz target `fuzz/fuzz_targets/inline_image_parse.rs`:
   - input: arbitrary content stream bytes,
   - harness: invoke inline image segment parser,
   - assert: terminates without panic, correct `BI ... EI` boundary detection.
3. Add fuzz target `fuzz/fuzz_targets/type3_charproc.rs`:
   - input: arbitrary PDF bytes with Type3 font,
   - harness: invoke Type3 charproc stream inspection,
   - assert: terminates without panic.
4. Add new targets to `fuzz/Cargo.toml` and update `fuzz/README.md` (if it exists).

Tests:
1. Each fuzz target compiles with `cargo fuzz build`.
2. Each target runs for 10 seconds in CI without crashing.

Documentation:
- Update `docs/` or `fuzz/README.md` with new target names and invocation commands.

Acceptance:
1. All three targets compile and run in CI.
2. No panics on seed corpora.

### D3. `OF-BATCH-01` Parallel batch processing

Goal:
Improve batch throughput towards the AGENTS.md target of 500,000+ PDFs using
parallel per-file analysis.

Implementation:
1. Add `rayon` as a normal workspace dependency for CLI batch execution paths.
2. Refactor batch loop in `crates/sis-pdf/src/commands/` to use `rayon::par_iter()`.
3. Maintain per-file error isolation (one file's failure must not block others).
4. Maintain deterministic output ordering (sort results by input path after parallel collection).
5. Add `--jobs N` flag to control parallelism; default to `min(logical_cpu_count, 8)`.
6. Apply memory-aware guard:
   - when `--deep` is enabled and file size exceeds configured threshold, clamp worker count
     to a lower ceiling (for example 4) unless explicitly overridden by user flag.

Tests:
1. Throughput benchmark test: process 1000 identical fixture files; record time per file.
2. Error isolation test: one corrupt file in batch does not prevent other files completing.
3. Output ordering test: results appear in input path order regardless of completion order.
4. `--jobs 1` produces identical output to pre-parallelism baseline.

Documentation:
- Update `docs/query-interface.md` with `--jobs` flag description.
- Update `docs/performance.md` with throughput improvement notes.

Acceptance:
1. Throughput improvement measurable on multi-core runners (recorded in baseline deltas).
2. Error isolation guaranteed.
3. Output order is deterministic.
4. Docs updated in same commit.

## Workstream E: Governance, trust, and rollout control

### E1. `OF-SEC-01` Fingerprint baseline integrity and provenance hardening

Goal:
Ensure external fingerprint baselines are trustworthy, reproducible, and auditable.

Implementation:
1. Define baseline metadata schema in `docs/analysis.md` (or dedicated schema doc):
   - `schema_version`,
   - `baseline_id`,
   - `created_at`,
   - `source_corpus_digest`,
   - `builder_version`.
2. Add optional detached checksum/signature file support:
   - `--baseline-profile baseline.json --baseline-profile-sha256 baseline.json.sha256`.
3. Baseline loader validates digest when checksum file is provided; mismatch returns
   `QueryResult::Error` with `QUERY_SYNTAX_ERROR`.
4. Emit baseline provenance fields in `streams.fingerprint.json` output when loaded.

Tests:
1. Valid baseline + checksum loads successfully.
2. Checksum mismatch fails closed with deterministic error.
3. Output contains provenance fields when baseline is active.

Documentation:
- Document baseline format and integrity workflow in `docs/analysis.md`.

Acceptance:
1. Baseline integrity can be verified in automated pipelines.
2. Analysts can trace fingerprint scores back to baseline provenance.

### E2. `OF-OBS-01` Resource-cap telemetry and query surface

Goal:
Expose cap-hit behaviour as first-class operational telemetry.

Implementation:
1. Add cap-hit counters in projection/runtime profile paths for:
   - recursion depth cap hits,
   - edge cap hits,
   - revision diff truncations,
   - inline-image parse truncations (when present).
2. Add query variant `runtime.caps` / `runtime.caps.json` summarising cap counters.
3. Include cap counters in batch JSONL per-file records.

Tests:
1. Synthetic cap-trigger fixtures increment expected counters.
2. `runtime.caps.json` schema test for deterministic keys and numeric values.
3. Batch-mode test ensures counters present for successful and errored files.

Documentation:
- Add `runtime.caps` query documentation in `docs/query-interface.md`.

Acceptance:
1. Operators can quantify safety-guard activation rates without manual log parsing.
2. Cap telemetry is deterministic and machine-parseable.

### E3. `OF-REL-01` Phase-gate rollback playbook

Goal:
Define objective stop/rollback conditions per phase to reduce regression blast radius.

Implementation:
1. Add phase gate table in this roadmap with hard thresholds:
   - crash/panic count increase,
   - benign corpus false-positive increase,
   - CVE fixture runtime regression percentage,
   - schema contract breakage.
2. Define rollback actions:
   - revert item commit set,
   - disable via query/feature flag where possible,
   - record cause and mitigation in `Baseline deltas`.
3. Require gate sign-off entry before moving from one phase to the next.

Tests:
1. N/A (process/governance item); validated via checklist completion.

Documentation:
- Keep the phase gate table in this plan current as phases complete.

Acceptance:
1. Every phase transition has an explicit pass/fail record.
2. Rollback path is documented before optional features ship.

### D4. `OF-DIAG-01` Structured per-detector diagnostic output

Goal:
Extend the existing runtime-profile output with per-detector timing and finding
counts to support pipeline monitoring and SLO enforcement.

Implementation:
1. Extend `--runtime-profile-format json` output:
   - add `detectors` array under existing `phases` structure,
   - each entry: `{ name, duration_ms, finding_count, skipped: bool }`.
2. Maintain backward compatibility: new fields are additive only.
3. Update SLO gate in `quality-gates.yml` to also validate individual detector budgets
   if any single detector exceeds 20 ms on the CVE fixture.

Tests:
1. Schema test: `--runtime-profile-format json` output contains `detectors` array.
2. Stability test: detector array is present even when no findings are emitted.
3. SLO gate test: CI fails if any detector exceeds 20 ms on CVE fixture.

Documentation:
- Update `docs/performance.md` with new `detectors` field schema and SLO table.

Acceptance:
1. Per-detector timing is available in runtime-profile output.
2. CI gate enforces per-detector budget.
3. Docs updated in same commit.

### D5. `OF-WASM-01` WASM build parity CI gate

Goal:
Prevent GUI regressions from breaking the WASM build target.

Implementation:
1. Add a WASM build step to `.github/workflows/quality-gates.yml`:
   ```
   cargo build -p sis-pdf-gui --target wasm32-unknown-unknown
   ```
2. Install `wasm32-unknown-unknown` target in the CI Rust toolchain step.
3. Fail the quality-gates job if WASM build fails.
4. Do not run WASM tests (separate concern); this is a compile-only gate.

Tests:
1. CI job succeeds on current codebase (green baseline before any GUI changes).

Documentation:
- Add WASM build note to README or `docs/analysis.md`.

Acceptance:
1. WASM build is validated on every pull request.
2. GUI items B2, B3, B6 each include a WASM build check in their acceptance criteria.

## Cross-cutting test and baseline requirements

For each workstream item:
1. Add/extend integration tests asserting finding kind + severity/confidence invariants.
2. Run `cargo test -p sis-pdf-core --test corpus_captured_regressions` for detector/correlation changes.
3. Record baseline deltas (finding counts/severity shifts/perf impact) in the implementation section of this roadmap before marking item complete.
4. For query/export changes, add parse + format + shape tests in the relevant query module (post D1 split).
5. For any new fixture added:
   - copy into `crates/sis-pdf-core/tests/fixtures/corpus_captured/`,
   - register in `crates/sis-pdf-core/tests/fixtures/corpus_captured/manifest.json`
     with `path`, `sha256`, `source_path`, and `regression_targets`,
   - update `crates/sis-pdf-core/tests/fixtures/README.md`.
6. WASM build check (`cargo build -p sis-pdf-gui --target wasm32-unknown-unknown`)
   required for any item touching `sis-pdf-gui`.
7. For any new baseline-profile file used in tests/docs:
   - include provenance metadata fields,
   - include deterministic digest artefact for integrity checks.

## Delivery governance

1. Ship in small commits per item to isolate regressions.
2. Keep default behaviour stable; gate heavier analytics behind explicit query/flag where needed.
3. Update docs (`docs/query-interface.md`, `docs/findings.md`, schema docs) in the same commit as behaviour changes.
4. Confidence promotion for detectors (A2, A5) requires recorded corpus calibration result
   in this document's baseline deltas section before merging the promotion.
5. `OF-QUERY-01` (D1) must be complete before implementing any Phase 2+ query additions.
6. `OF-CS-04` (A4) must be marked complete before beginning `OF-CS-06` (A6).

## Phase gate table

| Phase | Gate metric | Threshold to pass | Rollback trigger |
| --- | --- | --- | --- |
| 0 | CI build parity (native + WASM) | 100% pass on quality gates | Any reproducible build break in default targets |
| 1 | CVE fixture runtime delta | <= 10% regression vs baseline | > 10% regression on two consecutive runs |
| 2 | Benign corpus FP delta (A2/A5) | <= 1.0% absolute increase | > 1.0% increase or uncategorised high-severity spike |
| 3 | Query/output schema stability | Additive-only changes verified | Missing fields, renamed keys, or parse breakage |
| 4 | Native smoke stability | 100% smoke pass across enabled targets | Any crash/hang in open/analyse/view/copy workflow |
| 5 | Overlay/event UX regression | No critical navigation regressions | Broken finding->event or event->finding navigation |

## Baseline deltas

Record corpus calibration and performance measurement results here before marking
items complete. Format:

```
## <item-id> <date>
- Finding count delta: +N / -N
- Severity/confidence changes: ...
- Timing delta on CVE fixture: ...ms -> ...ms
- False positive rate on benign corpus: N%
```

*(No entries yet; populate as items are implemented.)*

## Progress log

### 2026-02-22 (current pass)
- Implemented `D5 / OF-WASM-01`:
  - `.github/workflows/quality-gates.yml` now installs `wasm32-unknown-unknown`
    and runs `cargo build -p sis-pdf-gui --target wasm32-unknown-unknown`.
- Implemented a first slice of `E2 / OF-OBS-01`:
  - added `runtime.caps` / `runtime.caps.json` query surface in CLI;
  - added initial counters for event-graph truncation, stream projection truncation,
    and truncation-related finding metadata.
  - Remaining for full E2: dedicated projection/runtime-profile cap counters and
    batch JSONL propagation.
- Implemented `B1 / OF-EV-01`:
  - added CLI `events` alias flags in `sis query`:
    - `--full` -> `events.full`
    - `--count` -> `events.count`
    - `--level document|page|field` -> `events.document|events.page|events.field`
  - enforced `--full`/`--count` mutual exclusion and event-query-only guardrails.
- Implemented another slice of `E2 / OF-OBS-01`:
  - batch JSONL output now carries optional per-file `runtime_caps`.
- Implemented a core slice of `D3 / OF-BATCH-01`:
  - added `sis query --jobs N` override for batch workers;
  - default worker ceiling now `min(cpu_count, 8)`;
  - deep+large-file auto-clamp path reduces workers to limit memory pressure.
- Implemented `E3 / OF-REL-01` process scaffolding:
  - added explicit phase-gate execution records and initial Phase 0 pass entry.
- Implemented `B4 / OF-OV-01`:
  - added `graph.structure.overlay.depth N` and
    `graph.structure.overlay.telemetry.depth N` query variants with
    json/dot coercion parity.
- Implemented a slice of `B7 / OF-CSV-01`:
  - added findings CSV queries:
    - `findings.csv`
    - `findings.composite.csv`
    - `findings --format csv`
    - `findings.composite --format csv`
- Implemented `D4 / OF-DIAG-01` CI gate slice:
  - quality gates now fail when any runtime-profile detector exceeds 20 ms
    on the CVE fixture.
- Implemented `C4 / OF-NAT-04` CI slice:
  - quality gates now include macOS and Windows native GUI build jobs
    (`cargo build -p sis-pdf --features gui`).
- Extended `B7 / OF-CSV-01` docs:
  - added `docs/findings-csv-schema.md` with versioned column contract.
- Implemented `D2 / OF-FUZZ-01` coverage slice:
  - added fuzz targets:
    - `do_chain_recursion`
    - `inline_image_parse`
    - `type3_charproc`
  - wired new targets in `fuzz/Cargo.toml`;
  - validated target compilation with `cargo check --manifest-path fuzz/Cargo.toml --bin ...`.
- Completed `D2 / OF-FUZZ-01` CI smoke + docs:
  - `.github/workflows/security-fuzz.yml` now runs 10-second smoke campaigns for:
    - `do_chain_recursion`
    - `inline_image_parse`
    - `type3_charproc`
  - added reproducible local invocation guide in `fuzz/README.md`.
- Implemented `B2 / OF-EV-02` core index expansion:
  - `events.full` now emits both:
    - `finding_event_index` (existing direction),
    - `event_finding_index` (new reverse direction).
- Implemented `D1 / OF-QUERY-01` decomposition slice:
  - extracted CSV query helpers into `crates/sis-pdf/src/commands/query/csv.rs`;
  - `query.rs` now delegates findings CSV row generation via submodule import.
- Implemented `E1 / OF-SEC-01` integrity slice:
  - added query-time checksum validation flags:
    - `--baseline-profile`
    - `--baseline-profile-sha256`
  - added baseline builder utility:
    - `scripts/build_fingerprint_baseline.py`
  - documented profile provenance and integrity workflow in `docs/analysis.md`.
- Implemented additional `B7 / OF-CSV-01` slice:
  - added events companion CSV query:
    - `events.full.csv`
  - documented companion-table schema in `docs/findings-csv-schema.md`.
- Implemented additional `D3 / OF-BATCH-01` slice:
  - batch query now emits structured error rows instead of silently dropping
    file read/parse failures.
- Implemented additional `C4 / OF-NAT-04` release CI slice:
  - `.github/workflows/release-cli.yml` now builds GUI-capable sis binaries on
    macOS/Windows via `--features "ml-graph,gui"` alongside CLI builds.

## Phase gate records

| Phase | Date | Result | Notes |
| --- | --- | --- | --- |
| 0 | 2026-02-22 | Pass | Quality gates include native SLO checks and WASM GUI build parity. |
| 1 | TBD | Pending | |
| 2 | TBD | Pending | |
| 3 | TBD | Pending | |
| 4 | TBD | Pending | |
| 5 | TBD | Pending | |

## Execution checklist

### Phase 0
- [x] D5: `OF-WASM-01` WASM CI gate
- [ ] E1: `OF-SEC-01` Baseline integrity + provenance *(in progress: checksum validation + baseline builder script landed)*
- [ ] E2: `OF-OBS-01` Resource-cap telemetry/query
- [x] E3: `OF-REL-01` Rollback playbook

### Phase 1
- [ ] D1: `OF-QUERY-01` query module decomposition *(in progress: CSV helpers extracted to submodule)*
- [ ] A1: `OF-CS-01` Do recursion tracer
- [ ] A2: `OF-CS-02` Inline image anomaly detector
- [ ] A3: `OF-CS-03` Per-page execution summary query
- [x] B1: `OF-EV-01` events flag inventory

### Phase 2
- [ ] A4: `OF-CS-04` Content stream fingerprinting *(prerequisite for A6)*
- [ ] A5: `OF-CS-05` Type3 charproc detector
- [ ] A6: `OF-CS-06` Cross-revision diffing *(requires A4)*
- [ ] B2: `OF-EV-02` Bidirectional finding/event index *(in progress: bidirectional maps now in events.full; GUI jump affordances remain)*
- [x] D2: `OF-FUZZ-01` Fuzz target expansion
- [ ] D3: `OF-BATCH-01` Parallel batch processing *(in progress: --jobs + caps/clamp + error rows landed)*

### Phase 3
- [x] B4: `OF-OV-01` Overlay depth query
- [ ] B5: `OF-OV-02` Event-graph anchors
- [ ] B6: `OF-OV-03` GUI overlay integration
- [ ] B7: `OF-CSV-01` Findings CSV export *(in progress: findings + events companion CSV and schema docs landed; remaining batch CSV error-row normalisation)*
- [ ] D4: `OF-DIAG-01` Structured diagnostics *(in progress: per-detector CI budget gate landed)*

### Phase 4
- [ ] C1: `OF-NAT-01` Analysis threading
- [ ] C2: `OF-NAT-02` Screenshot CI
- [ ] C3: `OF-NAT-03` Packaging
- [ ] C4: `OF-NAT-04` macOS/Windows GUI targets *(in progress: quality-gates + release-cli GUI builds landed)*

### Phase 5
- [ ] B3: `OF-EV-03` Event annotations in overlay views

### Completion gate
- [ ] All source-linked optional items reviewed and either implemented or explicitly rejected with rationale
- [ ] Baseline deltas recorded for all detector changes
- [ ] Confidence promotions backed by corpus calibration results
- [ ] Phase gate pass/fail entries recorded for each completed phase
