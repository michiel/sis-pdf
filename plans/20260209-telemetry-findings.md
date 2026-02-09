# Telemetry-to-finding parity plan

Date: 2026-02-09  
Owner: sis-pdf maintainers  
Status: Proposed

## 1. Problem statement

Security-relevant `WARN`/`ERROR` telemetry is not consistently represented as findings. This creates analyst blind spots:

- REPL/CLI output can show warnings without a corresponding `findings` row.
- Some subsystems emit repeated warnings from identical triggers, causing log noise without structured aggregation.
- Existing findings do not consistently carry telemetry context for triage and manual follow-up.

Goal: ensure security-impacting telemetry is always captured in findings (directly or via deterministic aggregation), with severity/confidence consistency and object-level traceability.

## 2. Current-state audit (security-impact telemetry)

## 2.1 Confirmed gaps (no direct finding registration)

1. `pdf.xref` telemetry:
   - `xref_loop_detected` (`crates/sis-pdf-pdf/src/xref.rs`)
   - `xref_offset_oob` (`crates/sis-pdf-pdf/src/xref.rs`)
   - Gap: logged only; not emitted as dedicated findings.

2. `pdf.object_stream` telemetry:
   - `high_objstm_count`, `objstm_count_exceeded`
   - `objstm_decode_budget_reached`, `objstm_decode_budget_exceeded`
   - `objstm_decoded_bytes_high`, `objstm_decoded_bytes_exceeded`
   - `objstm_recursive_reference`, `objstm_nested_reference`
   - `max_objects_total_reached`
   - Source: `crates/sis-pdf-pdf/src/objstm.rs`
   - Gap: logged only; partial overlap with `objstm_*` detectors but no deterministic telemetry parity.

3. `pdf.decode` telemetry:
   - `decode_parms_out_of_range`
   - `flate_recovery`
   - Source: `crates/sis-pdf-pdf/src/decode.rs`
   - Gap: logged only; no dedicated finding kind.

4. `pdf.encryption` telemetry:
   - `encrypt_dict_fallback` warning is emitted (`crates/sis-pdf-detectors/src/advanced_crypto.rs`) but no finding of that kind is currently registered.

5. `runtime.detection` telemetry:
   - `detector_execution_failed` is logged in parallel detector mode (`crates/sis-pdf-core/src/runner.rs`) but currently dropped (no finding emitted).

## 2.2 Partial-coverage areas (needs normalisation/aggregation)

1. Parser-limit telemetry from `crates/sis-pdf-pdf/src/parser.rs`:
   - `array_size_limit_exceeded`, `dict_size_limit_exceeded`, `stream_length_overflow`, `max_objects_reached`.
   - Current coverage is indirect via strict deviations (`strict_parse_deviation*`) and `object_count_exceeded`; behaviour differs by strict mode and does not provide one-to-one telemetry parity.

2. Page-tree telemetry naming mismatch:
   - Log kind: `page_tree_cycle_detected`/`page_tree_depth_exceeded`.
   - Finding kinds: `page_tree_cycle`/`page_tree_depth_exceeded` (`crates/sis-pdf-detectors/src/page_tree_anomalies.rs`).
   - Coverage exists, but kind harmonisation is needed for deterministic joins.

3. Font hinting truncation:
   - Log kind: `hinting_analysis_truncated` (`crates/font-analysis/src/dynamic/mod.rs`).
   - Captured today via aggregate `font.ttf_hinting_torture` with truncation metadata.
   - Coverage exists, but no direct kind parity.

## 3. Design principles

1. **Deterministic parity**: every security-impact telemetry event maps to a finding or an explicitly documented aggregate finding.
2. **No finding spam**: repeated identical telemetry must be grouped by stable keys.
3. **Traceability first**: include object refs/spans and next-step query hints.
4. **Stable schema**: keep machine-parseable metadata keys and kind naming consistent.
5. **Safe defaults**: telemetry capture must not significantly increase memory/CPU costs on large corpora.

## 4. Target architecture

## 4.1 Add telemetry event collection to parse/runtime pipeline

Introduce a structured `TelemetryEventRecord` model in core/PDF parsing path with:

- `domain`, `kind`, `level`, `severity_hint`, `message`
- `object_ref` (optional), `span` (optional), `meta` map
- `occurrence_key` (for aggregation grouping)

Plumbing targets:

- `ObjectGraph` gains a `telemetry_events` collection for parser/xref/decode/objstm events.
- Runtime detector execution (`run_scan_with_detectors`) appends runtime events (e.g., detector failure).
- Existing logging remains, but telemetry events become first-class data.

## 4.2 Add a telemetry bridge detector

Add a detector in `crates/sis-pdf-detectors` that converts telemetry events into findings using a mapping table:

- direct one-to-one mapping for high-signal events;
- aggregate mapping for high-volume repetitive events.

Proposed detector id: `telemetry_bridge`.

## 4.3 Aggregation model

Aggregation key defaults:

- `domain + kind + object_ref` (or `domain + kind + span_bucket` when no object_ref).

Per aggregate finding:

- `meta.telemetry.count`
- `meta.telemetry.first_seen_offset`/`last_seen_offset` (when available)
- `meta.telemetry.unique_objects`
- `meta.telemetry.sample_messages` (bounded)
- evidence: first N distinct spans (N capped, e.g. 5)

## 5. Mapping plan (initial)

## 5.1 New or normalised finding kinds

1. `xref_loop_detected` (Medium, Strong): xref `/Prev` cycle or loop.
2. `xref_offset_oob` (Medium, Strong): xref chain points outside file bounds.
3. `objstm_processing_limited` (Medium, Strong): aggregate of ObjStm budget/count stop conditions.
4. `objstm_recursive_reference` (Low, Strong): recursive/nested ObjStm references (aggregate-capable).
5. `decode_parms_out_of_range` (Medium, Strong): decode parameter limits exceeded.
6. `flate_recovery` (Low, Probable): malformed Flate stream required raw-deflate recovery.
7. `encrypt_dict_fallback` (Low, Probable): `/Encrypt` recovered heuristically from graph.
8. `detector_execution_failed` (Medium, Strong): detector runtime failure; include detector id and error.
9. `parser_resource_limits_reached` (Medium, Probable): aggregate parser limit overflows and object-budget stops.

## 5.2 Existing findings to enrich instead of duplicate

1. `pdf.trailer_inconsistent` and `pdf.trailer_size_noncanonical`:
   - add telemetry rollup fields where relevant to avoid separate duplicate findings.

2. `strict_parse_deviation*`:
   - if strict mode is enabled, attach telemetry counts in metadata rather than duplicating per-deviation findings.

3. `font.ttf_hinting_torture`:
   - retain as aggregate target for `hinting_analysis_truncated`; add stable `meta.telemetry.kind` for parity.

## 6. Implementation workstreams

## WS1: Telemetry inventory and mapping registry

Files:

- `crates/sis-pdf-core/src/security_log.rs`
- new `crates/sis-pdf-core/src/telemetry.rs` (or equivalent)

Tasks:

- Define canonical registry: telemetry kind -> finding strategy (direct/aggregate/enrich-existing).
- Add validation test ensuring every registry entry has severity/confidence and schema.

## WS2: Event capture plumbing

Files:

- `crates/sis-pdf-pdf/src/{parser.rs,xref.rs,objstm.rs,decode.rs,graph.rs}`
- `crates/sis-pdf-core/src/runner.rs`

Tasks:

- Replace log-only sites with dual emit: log + structured telemetry record.
- Ensure parse/runtime contexts can carry and merge event vectors safely.

## WS3: Detector bridge and aggregation

Files:

- new `crates/sis-pdf-detectors/src/telemetry_bridge.rs`
- `crates/sis-pdf-detectors/src/lib.rs`

Tasks:

- Implement mapping table and aggregate reducer.
- Add object refs (`object.ref`) and analyst hints (`query.next`) to produced findings.
- Enforce cap on evidence samples and metadata payload size.

## WS4: Report/query/explain normalisation

Files:

- `crates/sis-pdf-core/src/report.rs`
- `crates/sis-pdf/src/main.rs`
- `crates/sis-pdf/src/commands/query.rs`

Tasks:

- Ensure aggregated telemetry findings render cleanly in text and JSON.
- Add concise “aggregated from N telemetry events” messaging in explain output.
- Add filtering support for `meta.telemetry.*` fields.

## WS5: Tests and regression harness

Files:

- `crates/sis-pdf-detectors/tests/*`
- `crates/sis-pdf-core/tests/*`
- `crates/sis-pdf-pdf/tests/*`

Tasks:

- Unit tests for mapping registry completeness.
- Integration tests for each high-priority kind above.
- Repetition tests proving aggregation (single finding with count) for repeated identical triggers.
- Strict/non-strict parity tests for parser-limit cases.

## WS6: Documentation and findings catalogue

Files:

- `docs/findings.md`
- `docs/query-interface.md` (if telemetry metadata querying is documented)

Tasks:

- Document any new finding kinds and aggregation metadata keys.
- Clarify that telemetry-derived findings may represent grouped events.

## 7. Aggregation policy details

1. **Direct findings** for rare, high-signal faults (`xref_loop_detected`, `detector_execution_failed`).
2. **Grouped findings** for noisy budget/limit events (`objstm_*`, parser limits):
   - one finding per kind/object scope;
   - include count and representative spans.
3. **Enrichment mode** when an existing semantic finding already expresses the risk:
   - attach telemetry metadata to existing finding instead of emitting duplicates.

## 8. Acceptance criteria

1. No security-impacting telemetry kind remains “log-only” without mapping strategy.
2. Repeated identical telemetry events collapse into aggregated findings with counts.
3. Every produced telemetry-derived finding has:
   - stable `kind`,
   - severity/impact/confidence,
   - object/span traceability where available.
4. `sis query ... findings` and `explain <id>` expose telemetry context without duplicate evidence spam.
5. Test coverage includes positive, negative, and aggregation scenarios.

## 9. Rollout sequence

1. Land registry and plumbing (WS1 + WS2) behind a guarded internal option.
2. Land bridge detector and tests (WS3 + WS5).
3. Enable by default after perf and noise validation on large corpora.
4. Finalise docs and findings catalogue updates (WS6).

## 10. Risks and mitigations

1. **Risk**: finding volume explosion on noisy files.  
   **Mitigation**: strict aggregation caps and enrichment preference.

2. **Risk**: duplicate semantics with existing detectors.  
   **Mitigation**: registry supports `enrich-existing` mode and dedupe by `(kind, objects, evidence)`.

3. **Risk**: memory growth from telemetry retention.  
   **Mitigation**: bounded ring buffer per kind and sampled evidence retention.

4. **Risk**: inconsistent severity across modules.  
   **Mitigation**: single mapping registry with tests and documented severity/confidence rationale.

