# Corpus-captured fixtures

This directory contains malware-PDF fixtures extracted from corpus triage and committed to version control for stable, portable regressions.

## Baseline policy

- Treat all files as hostile inputs.
- Keep fixture filenames deterministic and hash-referenced where practical.
- Record provenance and expected behaviours in `manifest.json`.
- Update or add regression tests in `crates/sis-pdf-core/tests/corpus_captured_regressions.rs` for every new captured fixture.
- Synthetic fixtures are allowed for deterministic edge-case coverage; mark them clearly in `manifest.json` via `source_path` under `generated/synthetic/...`.

## Integrity

`manifest.json` stores the expected `sha256` for each fixture.  
The `corpus_captured_manifest_integrity_stays_stable` test verifies:

1. each manifest entry exists on disk;
2. each fixture digest matches the manifest value.

This guarantees the baseline remains self-contained and does not require `tmp/corpus` to execute regression coverage.
