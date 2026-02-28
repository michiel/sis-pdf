# Case Studies

Deep-analysis records for corpus PDF samples that have been thoroughly investigated and used as regression fixtures.

Each subdirectory contains:
- `metadata.json` — structured threat metadata (sha256, classification, techniques, MITRE ATT&CK, detection signals)
- `analysis.md` — narrative analysis of the file's structure, attack chain, evasion techniques, and key indicators

The corresponding PDF files are tracked as test fixtures in:
`crates/sis-pdf-core/tests/fixtures/corpus_captured/`

## Index

| Directory | Threat Family | Verdict | Threat Actor |
|---|---|---|---|
| apt42-polyglot-pdf-zip-pe | polyglot-dropper | Malicious | APT42 |
| booking-js-phishing | js-credential-phishing | Suspicious | Unknown |
| modern-gated-supplychain | supply-chain-update-vector | Suspicious | Unknown |
| modern-openaction-staged | staged-openaction-exploit | Suspicious | Unknown |
| modern-renderer-revision | renderer-divergence-revision-shadow | Suspicious | Unknown |
| romcom-embedded-payload | embedded-payload-dropper | Suspicious | RomCom |

## Adding a New Case Study

See the workflow in `AGENTS.md` under "Case Study Workflow".
