# Next Steps: SARIF and YARA Annotations

This plan defines how to add richer SARIF metadata and YARA annotations, export paths, and report inclusion.

## Goals
- Emit SARIF with structured evidence and properties suitable for CI triage.
- Attach YARA annotations to findings and allow export to `.yar` files.
- Include SARIF/YARA details in Markdown reports.

## SARIF enhancements

### 1) Evidence mapping in SARIF
- Map `EvidenceSpan` into `physicalLocation` with file offsets.
- For decoded evidence, add `properties` with `origin` spans and `source=Decoded`.

### 2) Rule metadata
- Include `helpUri`, `defaultConfiguration`, and `properties` (confidence, surface).
- Add rule tags for attack surface and detector needs.

### 3) Result properties
- Add `properties` with `objects`, `meta` fields, and `impact`.
- Include `fingerprints` using stable finding IDs.

### 4) SARIF export options
- CLI flags:
  - `--sarif` for stdout
  - `--sarif-out <file>` for file output
- Add report section linking SARIF output path when written.

## YARA annotations

### 5) YARA metadata model
- Add `yara` block to `Finding.meta` for:
  - `rule_name`
  - `tags`
  - `strings` (matched identifiers)
  - `namespace`

### 6) YARA generation
- Generate YARA rules for high-risk findings:
  - JS obfuscation, embedded files, decoder risk
- Include evidence excerpts or hashes in YARA `strings`.
- Deterministic rule naming based on finding ID.

### 7) YARA export options
- CLI flags:
  - `--yara` for stdout
  - `--yara-out <file>` for file output
- Optional `--yara-scope` to include only High/Critical.

## Report inclusion

### 8) Markdown report updates
- Add **SARIF** section:
  - summary of rule count, result count, and path
- Add **YARA** section:
  - list of generated rule names and tags
- For each finding, include any YARA metadata when present.

## Implementation sketch

- `crates/ysnp-core/src/report.rs`
  - Extend SARIF output to map evidence and include metadata.
  - Add Markdown sections for SARIF and YARA.
- `crates/ysnp-core/src/model.rs`
  - Add structured `yara` metadata (or standardised meta keys).
- `crates/ysnp-cli/src/main.rs`
  - Add export flags and file write paths for SARIF/YARA.
- `crates/ysnp-detectors/src/lib.rs`
  - Populate YARA metadata for relevant findings.

## Acceptance criteria
- SARIF validates against schema and includes evidence locations.
- YARA export produces valid `.yar` files with deterministic rule names.
- Markdown report includes SARIF/YARA summaries and per-finding annotations.
