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
