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
2. Add a helper in `commands::query` that filters `QueryResult` objects according to the verbosity — `compact` drops informational/low findings only for the default textual/readable outputs while JSON/YAML/JSONL remain untouched, and the other verbosity levels leave data unchanged.
3. Apply the filter both to one-shot queries (after `execute_query`) and to the REPL (after `execute_query_with_context`), passing the eventual output format so the helper can skip JSON exports when necessary.
4. Update the REPL help text and `docs/query-interface.md` / `docs/analysis.md` to mention the new `--report-verbosity` option, its default, and how compact mode trims tables but keeps JSON exports unchanged.
5. Add regression tests for `apply_report_verbosity` confirming compact mode removes `Info`/`Low` entries for `OutputFormat::Text` but leaves `OutputFormat::Json` untouched.
6. After implementation, rerun `cargo fmt`/`cargo test -p sis-pdf` to keep the regression suite clean and note completion in this plan.

## Status

- Step 1 complete: `ReportVerbosity` exists and is exposed via `--report-verbosity`, including REPL/CLI plumbing.
- Step 2 complete: `apply_report_verbosity` now checks the eventual `OutputFormat` and filters only when text/readable output is selected.
- Step 3 complete: oneshot and REPL pipelines pass the format to the helper and trim only the intended outputs.
- Step 4 complete: `docs/query-interface.md` and `docs/analysis.md` now describe the `--report-verbosity` option and compact behaviour.
- Step 5 complete: regression tests for compact filtering vs JSON have been added.
- Step 6 complete: `cargo fmt` and `cargo test -p sis-pdf` have been run successfully.
