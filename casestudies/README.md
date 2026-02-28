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
| connectwise-filter-obfuscation-9ab20ec2 | connectwise-filter-obfuscation | Malicious | Unknown (ConnectWise lure cluster) |
| decode-budget-exhaustion-c2d0d7e2 | decode-budget-exhaustion | Malicious | Unknown |
| decompression-bomb-font-flood-b509f6c9 | decompression-bomb-with-font-noise | Malicious | Unknown |
| jbig2-zeroclick-cve2021-30860 | image-codec-exploit | Malicious | Unknown |
| modern-gated-supplychain | supply-chain-update-vector | Suspicious | Unknown |
| modern-openaction-staged | staged-openaction-exploit | Suspicious | Unknown |
| modern-renderer-revision | renderer-divergence-revision-shadow | Suspicious | Unknown |
| mshta-italian-sandbox-escape | mshta-powershell-downloader | Malicious | Unknown (Italian campaign) |
| romcom-embedded-payload | embedded-payload-dropper | Suspicious | RomCom |
| url-bombing-25-annotation | annotation-url-bombing | Suspicious | Unknown |

## Adding a New Case Study

See the workflow in `AGENTS.md` under "Case Study Workflow".
