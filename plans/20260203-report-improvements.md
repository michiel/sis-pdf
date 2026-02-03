# 20260203 Report improvements plan

## Context

Reports (`findings`, `chains`, `events`, etc.) are currently noisy: every finding/chain link is emitted regardless of severity, causing huge dumps in text/JSON output. Analysts want configurable verbosity so day-to-day triage focuses on the significant results while the JSON pipeline still captures every detail.

## Goals

1. Add a configurable verbosity level (`compact`, `standard`, `verbose`) that controls the default report filtering.
2. Shrink the default output by dropping informational/low-severity findings and collapsed chains when `compact` mode is active.
3. Make the REPL/docs aware of pipe/redirect workflows for capturing trimmed output.
4. Document the new behaviour in `docs/query-interface.md` and `docs/analysis.md`, and describe how to override verbosity (`--report-verbosity`).

## Implementation steps

1. Define a `ReportVerbosity` enum (with `ValueEnum` support) so the CLI/REPL can switch modes. Expose a new `--report-verbosity` flag for `sis query` (and the REPL will inherit the same level).
2. Add a helper in `commands::query` that filters `QueryResult` objects according to the verbosity: `compact` should drop informational/low findings from the `findings` array, `standard` leaves data unchanged, and `verbose` can just return the full dataset while reserving the ability to add further summarisation later.
3. Apply the filter both to one-shot queries (after `execute_query`) and to the REPL (after `execute_query_with_context`). Ensure the REPL still pipes/redirects using the filtered string so analysts interact with the trimmed view.
4. Update the REPL help text and `docs/query-interface.md` to mention the new `--report-verbosity` option and how it affects `findings` output.
5. After implementation, rerun `cargo fmt`/`cargo test -p sis-pdf` to keep the regression suite clean and note completion in this plan.

## Status

- Step 1 complete: `ReportVerbosity` exists and is exposed via `--report-verbosity`, including REPL/CLI plumbing.
- Step 2 complete: `apply_report_verbosity` filters finding arrays in compact mode.
- Step 3 complete: both one-shot and REPL flows invoke the filter before formatting/output.
- Step 4 complete: `docs/query-interface.md` now mentions the verbosity flag.
- Step 5 complete: `cargo fmt` / `cargo test -p sis-pdf` have been run successfully.
