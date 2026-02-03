# 20260203 Query interactive plan

## Context

`sis query` interactive sessions currently produce JSON or YAML when the user requests `:json` or `:yaml`. Analysts want a more human-friendly default (like an ASCII table for lists and readable structures for objects) and the ability to pipe query results to arbitrary shell commands inside the REPL.

## Goals

1. Add a `:readable` output formatter used by default in interactive mode. It should render:
   - Lists as ASCII tables summarising key columns (ID, severity, kind, path, score, timestamp) with column wrapping.
   - Single objects (e.g., `object 13 0`) as hierarchical diagrams using arrows and indentation showing relationships.
2. Preserve existing explicit format options (`:json`, `:yaml`, `:raw`). Non-interactive sessions continue to default to `:json` (or prior behaviour).
3. Extend the interactive parser so lines may include a `|` operator. Everything before `|` is interpreted as the query expression; everything after (trimmed) is run as a shell pipeline receiving the textual output from the formatter.
   - The shell command must execute via `sh -c` to handle piping/redirects.
   - The REPL should display the shell command exit status and capture stderr/stdout for debugging.
4. Ensure the REPL can be scripted (exit on EOF, repeat prompt) and document the new interface in USAGE or docs.
5. Provide tests that simulate interactive sessions (e.g., feeding commands and verifying output format and pipe behavior).

## Design considerations

- The formatter needs insight into findings; reuse the existing reporting traits from `crates/sis-pdf-core/reporting` if possible, or add a new `ReadableReporter`.
- Table heuristics should sample multiple entries to determine headers. Provide fallbacks for heterogenous lists (show union of keys, mark missing values as `-`).
- ASCII tree for objects should limit depth (configurable) and highlight references (use `->` or `│`).
- Pipe implementation must be resilient to commands that expect stdin; if the query returns nothing, still send an empty string (plus newline) so tools like `wc -l` work.
- Security: run shell commands with CWD of current working dir; do not drop privileges.

## Implementation steps

1. **Explore CLI entry point** (likely `crates/sis-pdf/src/bin/sis.rs` and `crates/sis-pdf-core/cli`).
   - Identify how interactive mode is detected and how output format is chosen.
   - Pinpoint where query parsing occurs to inject `|` handling and default format selection.
2. **Implement the `Readable` formatter**:
   - Add new module (e.g., `crates/sis-pdf-core/reporting/readable.rs`) that consumes `Vec<Findings>` or `QueryResult`.
   - Provide helper utilities (table builder, tree renderer). Keep width ~80 columns but allow `SIS_WIDTH` env override.
   - Add tests ensuring it formats list and object cases (see detectors with path info). Validate ASCII art structure.
3. **Integrate new format**:
   - Update CLI argument parsing so interactive REPL (or `--interactive`) defaults to `:readable` unless user supplies `:json`, `:yaml`, or `:raw`.
   - Ensure non-interactive behaviour remains unchanged (maybe `non_interactive_fmt` variable). Document this change in `docs/USAGE.md` (mention toggling formats inside query via `:json`, etc.)
4. **Extend REPL loop for pipes**:
   - When reading input line, split on first `|`. Trim both sides.
   - Evaluate query using existing pipeline into string output (via the chosen formatter). Keep the string in memory for both display and piping.
   - If pipe present, spawn `sh -c "command"`, pass the output via stdin (write string plus newline). Capture exit status and display (e.g., `[pipe] command exited 0`). Show stderr if non-zero.
   - Continue REPL regardless of the pipe result.
5. **Tests**:
   - Add integration tests under `tests/query_interactive.rs` or similar; simulate interactive session by feeding commands through stdin (use `assert_cmd` or custom harness). Check that default output matches readable format and that piping works (mock command such as `cat` or `wc -l`).
6. **Docs & UX**:
   - Update `docs/USAGE.md` and maybe `README.md` block describing interactive query enhancements (default readable, example pipe usage, instructions on switching formats).
   - Mention new features in `plans/` or `NEXT_STEPS` if relevant.
7. **Optional extras**:
   - Provide CLI prompt indicator (maybe `[json]` vs `[readable]`) to remind users which format is active.
   - Allow `:format readable` command to toggle without re-running entire CLI.

## Example sequences

1. `query> findings` -> render ASCII table summarising high-level attributes.
2. `query> findings | jq . | wc -l` -> send the readable table through the shell pipeline, display command exit code, keep REPL open.
3. `query> object 13 0` -> show tree with links like:
```
object 13 0
├─ catalog -> object 7 0
│  ├─ /Pages -> object 5 0
│  └─ /AcroForm -> object 9 0
└─ /Metadata -> stream (size: 1024)
```

## Next steps

1. Implement the `Readable` formatter and hook it into the existing `QueryResult`/`Findings` rendering pipeline. This includes table heuristics, ASCII tree builders, and a width configuration (respecting `SIS_WIDTH`).
2. Update `crates/sis-pdf/src/main.rs` (REPL command loop) to track the current interactive format (defaulting to `:readable`), build the textual output once, and reuse it when piping to shell commands.
3. Extend the REPL parser so commands may include `|` (split once, trim, evaluate left-side query, optionally redirect the result string to `sh -c` with `stdin`), and ensure the CLI reports pipe exit status/stderr without breaking the session.
4. Add regression tests (query unit/integration tests) covering default readable output, toggling formats via `:json/:yaml/:readable`, and executing pipes to dummy commands (`cat`, `wc -l`) to ensure behavior remains stable.
5. Update `docs/query-interface.md` (and USAGE/README if needed) with the new default format, pipe syntax, and examples of tables/trees.
6. Run `cargo fmt` / `cargo test` / `cargo clippy` (if configured) before the next commit to demonstrate regressions are caught, then capture the new behavior in the plan notes for review.
