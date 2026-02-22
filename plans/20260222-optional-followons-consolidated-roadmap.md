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

And it includes additional optionals identified in other `plans/*.md` files.

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
17. `OF-NAT-04` macOS and Windows native targets.
    Source: `plans/20260222-native-binary.md` (`Follow-on plans`, item 4).

## Discovered optionals already delivered (tracked for provenance only)

1. `OF-DONE-01` CLI `sis query events` surface.
   Source: `plans/20260221-gui-events-and-triage-deprecation.md` (`N1`), and
   `plans/20260221-events-dialog-depth.md` (`G7`).
   Delivery status: implemented in current codebase (`events`, `events.full`,
   `events.count`, level-filtered variants).

## Assumptions

1. Current default behaviour remains stable unless behind explicit flags.
2. Strict automated testing and baseline regressions are mandatory before rollout.
3. GUI dependencies must not leak into non-GUI builds.
4. Safety and bounded-resource behaviour take precedence over feature depth.
5. Any export schema additions are additive and versioned.

## Priority and sequencing

### Phase 1 (high value, low coupling)

1. `OF-CS-01` Do recursion tracer.
2. `OF-CS-02` Inline image anomaly detector.
3. `OF-CS-03` Per-page execution summary query.
4. `OF-EV-01` `--full` alias for events query.

### Phase 2 (analytics depth and correlation)

1. `OF-CS-04` Content stream fingerprinting.
2. `OF-CS-05` Type3 charproc suspicious-ops detector.
3. `OF-CS-06` Cross-revision content stream diffing.
4. `OF-EV-02` Bidirectional finding/event indexing expansion.

### Phase 3 (overlay and export integration)

1. `OF-OV-01` Overlay depth query.
2. `OF-OV-02` Event-graph anchors.
3. `OF-OV-03` GUI overlay integration.
4. `OF-CSV-01` Findings CSV export.

### Phase 4 (native platform/release hardening)

1. `OF-NAT-01` Analysis threading.
2. `OF-NAT-02` Screenshot CI.
3. `OF-NAT-03` Packaging.
4. `OF-NAT-04` macOS/Windows targets.

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

Safety/performance constraints:
1. Max depth 8.
2. Max nested edges per root event 128.
3. Truncation metadata field when limits hit.

Tests:
1. Synthetic fixture with 3-level nested form Do chain.
2. Cycle fixture (`FormA -> FormB -> FormA`) must terminate with truncation/loop marker, no panic.
3. Budget test on CVE fixture with negligible overhead when no nested forms.

Acceptance:
1. Nested paths visible in stream overlay JSON/DOT.
2. No default event-count regression for base `events` query.

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

Tests:
1. Malicious synthetic fixture with oversized inline image and suspicious filters -> finding expected.
2. Benign fixture with standard inline image usage -> no finding.
3. Corpus regression run to validate false-positive profile.

Acceptance:
1. Deterministic detection with bounded memory.
2. Confidence defaults `Tentative`/`Probable`, calibrated by corpus.

### A3. `OF-CS-03` Per-page execution surface summary query

Goal: Provide analyst-ready page execution overview without manual joins.

Implementation:
1. Add query variants in `crates/sis-pdf/src/commands/query.rs`:
   - `pages.execution` (table/text),
   - `pages.execution.json`.
2. Back data with `StreamExecSummary` grouped by page source object.
3. Output fields per page:
   - `page_ref`, `content_stream_count`, `total_ops`, `op_family_counts`,
   - `resource_names`, `anomaly_flags`, `linked_finding_ids`.
4. Add predicate support fields:
   - `page`, `total_ops`, `anomaly_count`, `resource_count`.

Tests:
1. Parse/query alias tests.
2. JSON schema shape test on fixture.
3. Predicate filtering test.

Acceptance:
1. One command returns page-level execution narrative.
2. Stable deterministic row ordering.

### A4. `OF-CS-04` Content stream fingerprinting enhancements

Goal: Compute stable stream fingerprints for anomaly and similarity scoring.

Implementation:
1. Add `StreamFingerprint` struct in core projection:
   - normalised operator-family histogram,
   - optional hashed resource-name pattern vector,
   - compact fingerprint id (`blake3` over normalised features).
2. Add CLI query:
   - `streams.fingerprint` / `streams.fingerprint.json`.
3. Add optional corpus baseline loader:
   - local JSON profile file for benign centroids.
4. Add score fields:
   - `distance_to_benign_centroid`, `outlier_score`.

Tests:
1. Determinism test (same PDF -> same fingerprint).
2. Small edit sensitivity test (operator-family change alters fingerprint).
3. Budget test for large stream count.

Acceptance:
1. Fingerprints are stable and cheap.
2. Score is additive metadata; no hard blocking behaviour.

### A5. `OF-CS-05` Type3 charproc suspicious-ops detector

Goal: Close Type3 charproc execution gap.

Implementation:
1. Extend detector path to inspect Type3 `/CharProcs` streams.
2. Emit finding `type3_charproc_suspicious_ops` when suspicious op profile appears.
3. Reuse existing Type3 execution options in event graph where possible.

Tests:
1. Synthetic Type3 fixture with suspicious `Do`-heavy charproc.
2. Benign Type3 fixture no-trigger.

Acceptance:
1. Charproc streams are first-class attack-surface checks.

### A6. `OF-CS-06` Cross-revision content stream diffing

Goal: Detect anti-forensic stream replacement across incremental revisions.

Implementation:
1. Build revision-aware stream map using revision extraction index.
2. Compare fingerprints/operator summaries between earliest and latest revision per page stream lineage.
3. Emit finding `content_stream_revision_drift_suspicious` for high delta:
   - new `Do` invocations,
   - large operator-family ratio shift,
   - newly introduced anomaly flags.

Tests:
1. Synthetic incremental-update fixture introducing drift.
2. Baseline fixture with no drift.

Acceptance:
1. Meaningful diffs with low noise.
2. Metadata includes revision refs and delta summary.

## Workstream B: Event/query/overlay follow-ons

### B1. `OF-EV-01` `--full` alias for `events`

Implementation:
1. CLI flag parse in `sis query` command path maps `events --full` to `events.full` query variant.
2. Keep existing `events.full` query unchanged.

Tests:
1. Flag parsing and output parity test.

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
   - File: `crates/sis-pdf/src/commands/query.rs`.
   - Ensure `events.full` exposes both maps under deterministic ordering (sorted keys/values).
4. GUI round-trip:
   - Files: `crates/sis-pdf-gui/src/panels/events.rs`, `crates/sis-pdf-gui/src/panels/findings.rs`, `crates/sis-pdf-gui/src/app.rs`.
   - Add actions:
     - finding detail: `Jump to event` (uses `finding_event_index`),
     - event detail: `Show linked finding` (uses `event_finding_index`),
     - fallback behaviour when no linked row exists.
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

Acceptance:
1. Round-trip navigation works without manual ID copy.
2. JSON contracts remain additive and deterministic.

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
   - File: `crates/sis-pdf/src/commands/query.rs`.
   - `graph.structure.overlay.json` includes `event_annotations` only when event data available.
4. GUI rendering:
   - File: `crates/sis-pdf-gui/src/panels/graph.rs`.
   - Add optional badge layer:
     - small count badge for objects with events,
     - colour intensity by worst linked severity.
5. Controls:
   - Add UI toggle `Show event annotations`.
   - Default on for overlay mode, off for baseline structure mode.

Tests:
1. Overlay JSON contract test with/without annotations block.
2. Mapping test: known fixture object with event links gets expected count/type.
3. GUI render test: badge appears and updates with toggle.
4. Performance budget test: annotation join does not exceed established graph panel budget tolerance.

Acceptance:
1. Analysts can identify event hotspots from structure view alone.
2. No change to baseline structure overlay when annotation block is absent.

### B4. `OF-OV-01` `graph.structure.overlay.depth N`

Goal:
Provide bounded overlay views for large/complex files.

Implementation:
1. Query surface:
   - File: `crates/sis-pdf/src/commands/query.rs`.
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
4. Fail-closed test: invalid depth returns query syntax error.

Acceptance:
1. Depth-limited overlay is deterministic and explicitly labelled.
2. Analysts can reduce visual noise without losing schema clarity.

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
4. Query gating:
   - File: `crates/sis-pdf/src/commands/query.rs`.
   - Add explicit variant/flag:
     - `graph.event.anchor` and json/dot aliases,
     - baseline `graph.event` unchanged.
5. Serialisation:
   - Ensure anchor nodes are additive in JSON and DOT exporters.

Tests:
1. Schema test: `graph.event.anchor.json` contains anchor nodes with stable IDs.
2. Edge test: known trailer-linked object produces expected anchor edge.
3. Compatibility test: `graph.event.json` unchanged when anchor mode not used.

Acceptance:
1. Structural provenance can be analysed in event graph mode when requested.
2. Default event graph size and semantics remain stable.

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

Tests:
1. GUI unit tests for overlay node/edge to draw primitive mapping.
2. Interaction tests for layer toggle and node-detail panel.
3. wasm/native compile checks for overlay-enabled graph panel.

Acceptance:
1. Overlay is readable and actionable in GUI.
2. Turning overlay off restores existing graph behaviour exactly.

### B7. `OF-CSV-01` Findings CSV export

Goal:
Provide analyst-friendly tabular exports for external tooling.

Implementation:
1. Query/export interface:
   - File: `crates/sis-pdf/src/commands/query.rs`.
   - Add CSV support for findings-family queries:
     - `findings`, `findings.composite`, optional `events.full` companion tables.
2. Schema contract:
   - New/updated doc: `docs/findings-csv-schema.md` (or extend existing schema docs).
   - Include version header row or metadata key:
     - `schema_version=1`.
3. Field normalisation:
   - flatten multi-value fields with stable delimiters,
   - escape delimiter/newline/quote safely,
   - preserve severity/impact/confidence as explicit columns,
   - include stable IDs and object refs.
4. Batch support:
   - ensure `--path` batch mode continues on errors and emits error rows.

Tests:
1. Golden CSV snapshots for representative findings sets.
2. Round-trip parseability test with RFC4180 parser.
3. Batch-mode continuation test with one invalid file.
4. Regression test for deterministic column order.

Acceptance:
1. CSV output is machine-parseable and stable.
2. Analysts can ingest exports without post-cleanup.

## Workstream C: Native/runtime/release optionals

### C1. `OF-NAT-01` Native analysis threading

Goal:
Prevent UI stalls during large-file analysis.

Implementation:
1. Worker architecture:
   - Files: `crates/sis-pdf-gui/src/app.rs`, `crates/sis-pdf-gui/src/analyzer.rs`.
   - Add background worker pool (single-worker default), mpsc channel to UI.
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
1. Integration test: UI remains responsive while analysis runs.
2. Cancellation test: older request cannot overwrite newer result.
3. Repeated-open stress test with quick consecutive files.

Acceptance:
1. No long main-thread freezes during analysis.
2. Deterministic final state for rapid user actions.

### C2. `OF-NAT-02` CI screenshot smoke

Goal:
Catch blank-window/regression issues in headless CI.

Implementation:
1. CI job:
   - Linux runner with `xvfb`, Mesa software renderer.
2. Smoke harness:
   - launch `sis gui` with fixture path,
   - wait for initial frame,
   - capture screenshot,
   - assert non-empty/non-monochrome baseline invariants.
3. Artefact retention:
   - save screenshot and logs on failure.

Tests:
1. CI-only smoke step + local script for reproducibility.

Acceptance:
1. Renderer startup regressions are detected before merge.

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

Acceptance:
1. Packages install and launch cleanly across target distros.
2. Desktop metadata is standards-compliant.

### C4. `OF-NAT-04` macOS/Windows targets

Goal:
Enable cross-platform native GUI builds and baseline runtime support.

Implementation:
1. Build plumbing:
   - ensure `--features gui` works on macOS/Windows targets.
   - update target-specific `NativeOptions` configuration (windowing, app-id/title, dpi defaults).
2. Platform wrappers:
   - file-open dialog compatibility layer,
   - clipboard and drag-drop parity behaviour,
   - platform-specific path normalisation and error handling.
3. CI matrix:
   - add macOS and Windows build jobs,
   - optional launch smoke for signed-off runner environments.
4. Documentation:
   - update `docs/configuration.md`/README for platform caveats and known limits.

Tests:
1. `cargo build -p sis-pdf --features gui` on macOS + Windows CI.
2. Basic native smoke tests (open file, run analysis, copy text).
3. Snapshot test for platform-specific window-state persistence serialisation.

Acceptance:
1. Native GUI builds succeed on macOS and Windows.
2. Core analyst workflow (open/analyse/view/copy) works on both targets.

## Cross-cutting test and baseline requirements

For each workstream item:
1. Add/extend integration tests asserting finding kind + severity/confidence invariants.
2. Run `cargo test -p sis-pdf-core --test corpus_captured_regressions` for detector/correlation changes.
3. Record baseline deltas (finding counts/severity shifts/perf impact) in the implementation section of this roadmap before marking item complete.
4. For query/export changes, add parse + format + shape tests in `crates/sis-pdf/src/commands/query.rs` tests.

## Delivery governance

1. Ship in small commits per item to isolate regressions.
2. Keep default behaviour stable; gate heavier analytics behind explicit query/flag where needed.
3. Update docs (`docs/query-interface.md`, `docs/findings.md`, schema docs) in the same commit as behaviour changes.

## Execution checklist

- [ ] Phase 1 complete
- [ ] Phase 2 complete
- [ ] Phase 3 complete
- [ ] Phase 4 complete
- [ ] All source-linked optional items reviewed and either implemented or explicitly rejected with rationale
