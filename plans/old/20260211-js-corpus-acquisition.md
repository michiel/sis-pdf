# PR-20 S6-1: Modern JavaScript corpus acquisition pipeline

Date: 2026-02-11
Status: Implemented

## Goal

Provide a repeatable and legally safe acquisition workflow for 2018-2025 JavaScript malware and benign controls used by the regression harness.

## Source tiers

1. **Public malware feeds (primary)**
   - MalwareBazaar (tagged JavaScript artefacts)
   - VirusShare datasets with redistributable metadata only
   - Public CVE PoC repositories for Acrobat/PDF.js JavaScript chains
2. **Internal synthetic corpus (fallback and augmentation)**
   - Adversarial rewrite variants
   - Obfuscation family templates
   - Heap-primitive and source-to-sink behavioural templates
3. **Benign controls**
   - Legitimate PDF form scripts
   - Validation/calculation snippets
   - Annotation and accessibility helper scripts

## Governance and safety

- Do not commit third-party malware payload bodies unless redistribution rights are explicit.
- Commit only metadata manifests and synthetic fixtures by default.
- Keep original feed artefacts in local/offline storage under `tmp/` or external secured storage.
- Record acquisition metadata: source, date, family label, licence/disclosure constraints, and hash.

## Normalised layout

- Regression-ready corpus layout:
  - `crates/js-analysis/tests/fixtures/corpus/adversarial/`
  - `crates/js-analysis/tests/fixtures/corpus/benign/`
- Optional local staging layout (not committed):
  - `tmp/javascript-malware-collection/<year>/<day>/...`

## Ingestion workflow

1. Acquire candidate scripts and hash every sample.
2. Normalise text encoding to UTF-8 and retain original hash mapping.
3. Label samples (`adversarial`/`benign`) and assign family tags.
4. Deduplicate by normalised hash and semantic family.
5. Promote curated samples to regression corpus directories.
6. Run regression harness and archive JSON report in `plans/`.

## Quality gates before promotion

- **Adversarial sample** must trigger at least one high-risk static or behavioural signal.
- **Benign sample** must not trigger high-risk static or behavioural signals.
- Samples failing gate are quarantined for manual triage.

## Automation entry points

- CI/local sweep command:
  - `scripts/js-corpus-regression.sh crates/js-analysis/tests/fixtures/corpus plans/20260211-pr20-validation-report.json`
- Direct harness command:
  - `cargo run -p js-analysis --bin js-corpus-harness --features js-sandbox,js-ast -- --corpus-root crates/js-analysis/tests/fixtures/corpus --output plans/20260211-pr20-validation-report.json --enforce-thresholds`

