# Repository Guidelines

## Project background

This project is a security tool focused on analysing PDF files to determine if they are malicious. This involves detecting, analysing and handling potentially malicious code, data.

- Safety, accuracy, efficiency and completeness are primary goals.
- Use Australian English spelling
- Do not use emojis
- Planning and implementation documentation is in ./plans/
- User facing documentation (e.g. for Github Pages) is in ./docs/
  - User facing documentation always uses 'sis' binary for invocation documentation, not 'cargo run'
- Ensure implemented features have test coverage

### Finding Metadata Guidance

Findings in this project include metadata fields for `severity`, `impact`, and `confidence`. These fields are crucial for prioritising and understanding the significance of detected issues.

*   **Severity**: This indicates the potential harm or risk associated with a finding.
    *   `Critical`: Immediate and severe threat, likely to lead to system compromise or data exfiltration. Requires urgent attention.
    *   `High`: Significant threat, potential for serious harm, but may require specific conditions or user interaction. Requires prompt attention.
    *   `Medium`: Moderate threat, potential for some harm or information disclosure. Requires attention.
    *   `Low`: Minor threat, limited potential for harm, often informational or best practice violations. May be addressed in routine maintenance.
    *   `Info`: Purely informational, no direct threat, but provides useful context.
*   **Impact**: This describes the potential consequences if the finding is exploited or realised. It helps to contextualise the severity.
    *   `Critical`: Direct system compromise, arbitrary code execution, data loss/exfiltration.
    *   `High`: Significant data exposure, denial of service, privilege escalation.
    *   `Medium`: Minor data exposure, system instability, bypass of security controls.
    *   `Low`: Information leakage, minor functionality disruption.
    *   `None`: No direct negative consequence.
*   **Confidence**: This reflects the certainty that the finding is accurate and not a false positive.
    *   `Certain`: Highly reliable, almost no chance of false positive.
    *   `Strong`: Very likely to be accurate, low chance of false positive.
    *   `Probable`: Good chance of accuracy, some possibility of false positive.
    *   `Tentative`: Possible, but with a higher chance of false positive, requires further investigation.
    *   `Weak`: Low certainty, likely a false positive or requires significant additional context.

## Project Structure & Module Organization

- `crates/` contains the Rust workspace members:
  - `crates/sis-pdf/` CLI front-end (`sis` binary).
  - `crates/sis-pdf-core/` core scan pipeline, reporting, and models.
  - `crates/sis-pdf-pdf/` PDF parsing, object graph, and decoding.
  - `crates/sis-pdf-detectors/` detection rules and heuristics.
  - `crates/sis-pdf-ml-graph/` ML graph utilities.
  - `crates/js-analysis/` JavaScript static and dynamic analysis with sandboxing (feature: `js-sandbox`).
  - `crates/font-analysis/` Font static and dynamic analysis
- `plans/` holds development planning and implementation documentation
- `docs/` holds user facing documentation
  - `docs/findings.md` documents all 72+ JavaScript finding IDs.
  - `docs/js-detection-*.md` comprehensive JavaScript malware detection documentation.
- `fuzz/` contains cargo-fuzz targets and corpora.
- `scripts/` includes helper tooling (e.g., `scripts/eval_features.py`, `scripts/extract_js_payloads.py`).
  - `scripts/test_helpers/` development test fixtures and helper code.
- Tests live under `crates/*/tests/` with fixtures in
  `crates/sis-pdf-core/tests/fixtures/` and `crates/js-analysis/tests/fixtures/`.
  - Hostile payload tests use real VirusShare malware samples for validation.


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

## Tracing & Logging Conventions

- Use `tracing` macros for observability (`info!`, `debug!`, `warn!`, `error!`).
- Prefer structured fields (`domain`, `kind`, `security`) over free-form text.
- Avoid logging sensitive content (raw PDF bytes, extracted payloads, full paths) unless required for diagnostics.
- Keep messages concise and stable; prefer adding context via fields.

## Error Handling Guidelines

- Treat untrusted PDFs defensively; prefer structured errors over panics.
- Query errors should surface via `QueryResult::Error` with:
  - `error_code` aligned to documented codes (e.g. `OBJ_NOT_FOUND`, `QUERY_SYNTAX_ERROR`, `FILE_READ_ERROR`).
  - `message` suitable for human-readable output.
  - `context` containing actionable metadata (paths, requested object id).
- JSON/JSONL output must remain machine-parseable; text output can be concise.
- Batch mode should continue processing after errors and emit error entries for failed files.

## Query Interface Intent & Consistency

- The `sis query` interface is a forensic tool; prioritise predictable, composable output.
- Use explicit format control (`--format` or `--json` shorthand for `--format json`); keep conflict handling strict and clear.
- Maintain stable field names across outputs and documents.
- Predicate filtering (`--where`) should remain consistent across supported query types.
- Stream decoding modes (`--raw`, `--decode`, `--hexdump`) should be explicit and mutually exclusive in behaviour.

## Security Guidance

- Assume PDFs and embedded payloads are hostile and may target this codebase specifically.
- Construct parsing and decoding defensively (bounds checks, limits, and early exits).
- Prefer secure defaults and explicit flags for risky operations (decoding, extraction).
- Avoid unsafe resource usage; enforce size, recursion, and object limits.

## Performance & Scale

- Balance deep analysis and artefact recovery with throughput for large-scale processing.
- Optimise for rapid handling of very large corpora (500,000+ PDFs) without sacrificing safety.
- Keep batch mode resilient; avoid per-file failures halting pipelines.
- Stage 0.5 performance instrumentation lives under `docs/performance.md`: we already exercise `sis scan <fixture> --deep --runtime-profile --runtime-profile-format json` (Stage 1 CVE fixture `crates/sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf`) and the resulting metrics prove the SLO table (parse <10ms, detection <50ms, etc.). Capture future runs with the same pattern so anomalies surface quickly.
- Profiling tests: `cargo test -p sis-pdf batch_query_supports_findings_composite_predicate -- --nocapture` and `cargo test -p sis-pdf execute_query_supports_findings_composite_predicate -- --nocapture` cover the new composite query predicate paths while the runtime profile command ensures the profiler wiring works end-to-end.

## Testing Guidelines

- Tests are standard Rust integration tests in `crates/*/tests/`.
- Prefer descriptive, behavior-focused test names (e.g., `intent.rs`,
  `regression_payloads.rs`).
- Add or update fixtures in
  `crates/sis-pdf-core/tests/fixtures/` when coverage needs realistic PDFs.
- Every new change or capability must include tests and representative fixtures.

### Test and fixture baseline workflow

- For every detector/runtime/normalisation change, add or update at least one integration test in `crates/sis-pdf-core/tests/` asserting:
  - finding `kind`,
  - `severity` and `confidence`,
  - critical metadata invariants used for triage and explain output.
- Prefer extending existing regression suites first (for example `corpus_captured_regressions.rs`) before creating new test files.
- Corpus-derived fixtures must be copied into version control under `crates/sis-pdf-core/tests/fixtures/corpus_captured/`; do not depend on `tmp/` paths for test execution.
- Every committed corpus-captured fixture must be registered in `crates/sis-pdf-core/tests/fixtures/corpus_captured/manifest.json` with:
  - fixture `path`,
  - `sha256`,
  - original `source_path`,
  - explicit `regression_targets`.
- Preserve fixture integrity: changes to fixture bytes require a manifest digest update and an accompanying regression expectation review.
- Keep fixture provenance documentation current in:
  - `crates/sis-pdf-core/tests/fixtures/README.md`,
  - `crates/sis-pdf-core/tests/fixtures/corpus_captured/README.md`.
- Baseline measurement is mandatory when extending corpus-captured coverage:
  1. run targeted regressions (`cargo test -p sis-pdf-core --test corpus_captured_regressions`);
  2. run adjacent test modules affected by the change;
  3. record meaningful baseline deltas (new findings, severity/confidence shifts, timing changes) in the active plan under `plans/`.
- If a new fixture is added for modern malware patterns, include at least one assertion guarding against silent drift in runtime profile metadata (for example call ratios, divergence markers, staged payload indicators).

**CLI integration tests** live in `crates/sis-pdf/tests/cli_integration.rs` and exercise the compiled `sis` binary via `std::process::Command`. Run with `cargo test -p sis-pdf --test cli_integration`. The fixture used is `crates/sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf`. A deferred test for `sis diff` (identical inputs → exit 0) requires temp-file coordination and is tracked as a follow-up.

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

## Code and supply chain

 - No unsafe code, no unwraps
 - Rust native crates only
