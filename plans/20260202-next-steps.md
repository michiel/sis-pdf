# 20260202 Next Steps

## Objective
Coordinate the remaining schema, canonicalisation, CVE automation, and CLI/fixture work so the enhanced metadata, telemetry, and triage tooling ship as a cohesive unit.

## Plan
1. **Schema completion and reader-impact struct**
   - Add `impact: Option<Impact>` and `reader_impacts: Vec<ReaderImpact>` to `Finding` with `#[serde(default)]` so existing JSON consumers keep working.
   - Define `ReaderImpact`/`ReaderProfile` structs inside `crates/sis-pdf-core` and expose helpers to build the structured entries alongside the legacy `reader.impact.*` metadata.
   - Update `crates/sis-pdf-core` detectors (action, filter, image, font, etc.) to use a central `FindingBuilder` that seeds default telemetry and lets each detector layer in `impact/action_*/reader_impacts`. Add unit tests asserting serde round trips for representative findings.

2. **Canonicalisation + reader scoring + telemetry guards**
   - Finalise the canonicalisation pass in `crates/sis-pdf-core` so the object graph, filter chains, and names feed `reader_context` with stable inputs; add regression tests exercising obfuscated PDFs to prove determinism.
   - Implement reader-score propagation so the `report` sinks and query predicates get `impact`, `action_type`, and canonical filter metadata. Document how `predicate_context_for_finding` now surfaces these fields.
   - Instrument telemetry around canonicalisation/reader scoring (e.g., tracing spans, metric counters) and add nightly/CI guards: rerun `sis scan <canonical fixture> --deep --runtime-profile --runtime-profile-format json` when these components change, compare to the baseline in `docs/performance-data/profile-launch-cve.json`, and fail fast if thresholds exceed parse 10 ms / detection 50 ms.

3. **CVE automation robustness**
   - Rewrite `tools/cve-update` so it queries the NVD API for the last seven days only, accepts configurable output directories beyond `font-analysis`, and serialises idempotent results (e.g., deterministic filenames or versioned JSON) for each workspace crate that also wants CVE rows.
   - Update `.github/workflows/cve-update.yml` to run the revised tool daily, check for idempotency (e.g., rerun without diffing results), and drop any CVE rows directly into `docs/threat-intel-tracker.md` with placeholders for owner/severity/impact.
   - Document the new automation schedule/caveats in `plans/20260201-threat-intel-cadence.md` and confirm the workflow pushes updates for every workspace crate (not just fonts).

4. **CLI queries + predicates + fixtures**
   - Add dedicated `sis query canonical-diff` subcommand that prints canonicalisation removals/renames for analyst transparency; ensure it reuses the canonical metadata from step 2.
   - Expand `sis query findings` to accept telemetry-aware predicates (`--where action_type=Launch`, `--where meta.cve=CVE-2025-27363`, etc.) and document these in `docs/query-predicates.md` and release notes.
   - Refresh/annotate fixture names (e.g., `cve_2025_27363_gvar.pdf`) so each CVE listed in `docs/threat-intel-tracker.md` has a corresponding test; update detectors/tests to assert the telemetry fields appear as expected.

## Verification
- Each task should include targeted tests (`cargo test -p sis-pdf-core ...`, fixture-specific cases) and final SLO-profile runs before being marked done in this plan file.
- Keep `plans/20260201-triage.md` and `plans/20260201-threat-intel-cadence.md` in sync with completed steps from this plan.

## Progress
- [x] Step 1: Added `FindingBuilder`, serde-aware tests, and taught the filter-chain detector to consume the helper so metadata, impact, and reader-impact fields stay consistent.
- [x] Step 2: Instrumented canonical view construction, added tracing around the computed metrics, and introduced `tools/perf-guard` to gate runtime-profile SLOs.
- [x] Step 3: CVE automation now accepts multiple output directories, prints the resolved targets, and writes deterministic stubs into each path while placating the tracker.
- [x] Step 4: Documented the canonical-diff workflow and action-type predicates, linked tracker entries to their fixtures/tests, and validated the CVE fixtures via targeted font (`test_gvar_glyph_count_mismatch_metadata`) and image (`cve_2021_30860_jbig2_dynamic`) test suites.
