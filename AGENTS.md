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

## Case Study Workflow

`casestudies/` at the project root contains deep-analysis records for corpus PDFs that have been thoroughly investigated. Each entry has `metadata.json` (structured threat data) and `analysis.md` (narrative analysis). The PDF files themselves are tracked as test fixtures in `crates/sis-pdf-core/tests/fixtures/corpus_captured/`.

### When to add a new case study

Add a case study when a corpus sample meets **all** of the following:

1. The PDF has been committed to `tests/fixtures/corpus_captured/` and registered in `manifest.json`.
2. At least one regression test in `corpus_captured_regressions.rs` guards a key detection signal.
3. A deep scan (`sis scan <file> --deep --json`) has been run and its output reviewed.

### Steps to create a case study entry

1. **Choose a slug**: use `<threat-name>-<sha256-prefix-8>` (e.g., `apt42-polyglot-pdf-zip-pe`).

2. **Create the directory**:
   ```
   mkdir casestudies/<slug>
   ```

3. **Run a deep scan** and capture JSON output:
   ```
   sis scan <path/to/file.pdf> --deep --json > /tmp/scan.json
   ```

4. **Write `metadata.json`** with these fields:
   - `id`, `filename`, `sha256`
   - `fixture_path` (relative to `crates/sis-pdf-core/tests/fixtures/`)
   - `source` (corpus batch name and date)
   - `threat_actor` (attributed or Unknown)
   - `threat_family` (short label)
   - `classification` (Malicious / Suspicious / Anomalous / Clean)
   - `techniques` (list of technique names)
   - `mitre_attack` (list of ATT&CK technique IDs)
   - `detection_signals` (list of key findings with severity/confidence)
   - `intent_buckets` (from scan output `intent_summary`)
   - `verdict` (from scan output)
   - `regression_test` (test function name in corpus_captured_regressions.rs)
   - `first_seen`, `analysis_date`
   - `notes` (optional: notable false positives, historical bugs, caveats)

5. **Write `analysis.md`** covering:
   - **Threat Summary** — one-paragraph overview
   - **File Structure** — object layout, stream counts, key object IDs
   - **Detection Chain** — how signals connect from low-level findings to intent buckets
   - **Evasion Techniques** — how the sample attempts to evade detection
   - **Key Indicators** — actionable IOCs (hashes, domains, API names, patterns)
   - **Regression Coverage** — list of test functions that guard this sample

6. **Update `casestudies/README.md`**: add a row to the index table.

### Keeping case studies current after detection improvements

When a detector change materially affects a documented case study (new finding added, severity/confidence changed, false positive removed, chain improved):

1. Re-run `sis scan <fixture> --deep --json` and compare to the previous capture.
2. Update `metadata.json`: adjust `detection_signals`, `intent_buckets`, `verdict` if changed.
3. Update `analysis.md`: add a dated note in the relevant section describing what changed and why.
4. Commit both files together with the detector change in the same PR.

### Updating after a new corpus batch run

When a new corpus batch (e.g., `mwb-YYYY-MM-DD`) is analysed:

1. Identify samples with novel attack patterns not represented in `casestudies/`.
2. Follow the "Steps to create a case study entry" workflow above.
3. For existing case studies where the new batch reveals drift (e.g., the threat family evolved, a new evasion is present), add a "Drift observed" note in `analysis.md`.
4. Update the active plan under `plans/` with baseline delta notes as required by the fixture baseline workflow.

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
