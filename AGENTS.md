# Repository Guidelines

## Project Structure & Module Organization

- `crates/` contains the Rust workspace members:
  - `crates/sis-pdf/` CLI front-end (`sis` binary).
  - `crates/sis-pdf-core/` core scan pipeline, reporting, and models.
  - `crates/sis-pdf-pdf/` PDF parsing, object graph, and decoding.
  - `crates/sis-pdf-detectors/` detection rules and heuristics.
  - `crates/sis-pdf-ml-graph/` ML graph utilities.
- `docs/` holds specs and analysis notes (see `docs/sis-pdf-spec.md`).
- `fuzz/` contains cargo-fuzz targets and corpora.
- `scripts/` includes helper tooling (e.g., `scripts/eval_features.py`).
- Tests live under `crates/*/tests/` with fixtures in
  `crates/sis-pdf-core/tests/fixtures/`.

## Build, Test, and Development Commands

- `cargo build` builds the workspace.
- `cargo run -p sis-pdf --bin sis -- scan path/to/file.pdf` runs a triage scan.
- `cargo run -p sis-pdf --bin sis -- scan path/to/file.pdf --deep` runs a
  deeper decode pass.
- `cargo test` runs the Rust test suites.
- `cd fuzz && cargo fuzz list` shows fuzz targets; `cargo fuzz run parser`
  runs a target against its corpus.

## Coding Style & Naming Conventions

- Rust formatting follows standard `rustfmt` defaults (4-space indentation).
- Use `snake_case` for functions/modules, `CamelCase` for types/traits,
  and `SCREAMING_SNAKE_CASE` for constants.
- Keep module boundaries aligned with crate responsibilities
  (parser logic in `crates/sis-pdf-pdf`, detectors in
  `crates/sis-pdf-detectors`, etc.).

## Testing Guidelines

- Tests are standard Rust integration tests in `crates/*/tests/`.
- Prefer descriptive, behavior-focused test names (e.g., `intent.rs`,
  `regression_payloads.rs`).
- Add or update fixtures in
  `crates/sis-pdf-core/tests/fixtures/` when coverage needs realistic PDFs.

## Commit & Pull Request Guidelines

- Commit messages are short, imperative, and capitalized
  (e.g., `Add analysis guide`).
- PRs should include a clear description, testing notes, and links to any
  relevant plan docs in `plans/` or specs in `docs/`.
- Include example commands or output samples if the change affects CLI output
  or report formats.

## Security & Configuration Tips

- Treat PDF samples and fuzz corpora as untrusted. Avoid opening them in
  desktop viewers unless necessary, and prefer the `sis` CLI.
- For new analysis features, document behavior updates in `docs/` or
  `plans/` as appropriate.
