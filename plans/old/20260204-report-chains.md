# 20260204 Report chain summarisation plan

## Context

Verbosity filtering now lets analysts suppress low-severity findings, but `chains` and other structured outputs can still blow up with dozens of trivial edges. A summarisation layer should keep reports readable while preserving the detailed JSON output for investigations.

## Goals

1. Add a `ChainSummaryLevel` (e.g., `minimal`, `events-only`, `full`) that works alongside `ReportVerbosity` to control how much chain detail is emitted by default.
2. In compact mode, collapse chains into trigger-only summaries with counts/names instead of all edges; keep full edge lists in `verbose` or when the user requests an explicit format (e.g., `--format json`).
3. Provide digest-style exports (aggregated counts per severity/surface) for dashboards: extend `findings` export to optionally emit `summary` with severity buckets.
4. Keep the REPL/pipes aware of the new summarisation controls and document the knobs in `docs/query-interface.md`.

## Implementation steps

1. Add a `ChainSummaryLevel` `ValueEnum` and wire it to `--chain-summary` (default `events`). Document how it pairs with `report_verbosity`/`--format` (JSON always uses the full chain while text/readable outputs can summarize) and show the active level in the REPL prompt/status.
2. Summarise chain JSON structures after they are produced via a new `apply_chain_summary` helper: `minimal` clears edges, `events` keeps suspicious/high-weight edges (using `risk_score`/`weight` thresholds), and `full` preserves every link. Track `edges_summary` metadata so analysts understand how much was removed.
3. Introduce a findings digest helper that counts results by severity/surface and include it as the `summary` field in JSON/YAML/JSONL exports so dashboards can ingest the digest directly.
4. Update docs/help (`docs/query-interface.md`, `docs/analysis.md`) to describe `--chain-summary`, the `edges_summary` metadata, and the new `summary` object for findings queries.
5. Run `cargo fmt` and `cargo test -p sis-pdf`, record the results, and close out the plan.

## Status

- Step 1 complete: `ChainSummaryLevel` exists, the CLI/REPL accept `--chain-summary`, and the option is documented.
- Step 2 complete: `apply_chain_summary` filters edges in textual outputs, records `edges_summary`, and honours `risk_score` thresholds.
- Step 3 complete: findings JSON/YAML/JSONL now expose a `summary` object with severity/surface buckets via `build_findings_digest`.
- Step 4 complete: `docs/query-interface.md` and `docs/analysis.md` describe the new knobs and metadata.
- Step 5 complete: `cargo fmt` and `cargo test -p sis-pdf` have already run successfully.
