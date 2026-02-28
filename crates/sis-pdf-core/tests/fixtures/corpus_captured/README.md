# Corpus-captured fixtures

This directory contains malware-PDF fixtures extracted from corpus triage and committed to version control for stable, portable regressions.

## Baseline policy

- Treat all files as hostile inputs.
- Keep fixture filenames deterministic and hash-referenced where practical.
- Record provenance and expected behaviours in `manifest.json`.
- Update or add regression tests in `crates/sis-pdf-core/tests/corpus_captured_regressions.rs` for every new captured fixture.
- Synthetic fixtures are allowed for deterministic edge-case coverage; mark them clearly in `manifest.json` via `source_path` under `generated/synthetic/...`.

## Uplift fixture families

### Visualisation / chain uplift (2026-02-17)

The following captured fixtures are used as explicit validation anchors for the visualisation/chain uplift:

- `modern-openaction-staged-38851573.pdf`
  - complex/distributed/fragmented chain baseline
  - multi-reader divergence baseline
- `modern-renderer-revision-8d42d425.pdf`
  - revision-shadow baseline
- `modern-gated-supplychain-9ff24c46.pdf`
  - multi-reader divergence baseline

Each family has drift guards in `corpus_captured_regressions.rs` (stage coverage, chain connectivity, revision metadata stability, reader-risk consistency). Corresponding `fixture_family:*` and `drift_guard:*` targets are tracked in `manifest.json`.

### Performance, chain architecture, and detection uplift (2026-02-28)

The following fixtures drive the uplift plan in `plans/20260228-full-uplift-implementation.md`:

| File | Attack vector | Key regression targets |
|---|---|---|
| `apt42-polyglot-pdf-zip-pe-6648302d.pdf` | APT42: PDF+ZIP polyglot embedding two PE executables | `polyglot_signature_conflict`, `nested_container_chain` ×2, `polyglot_pe_dropper` (stage 3), `ExploitPrimitive/Probable+` (stage 3) |
| `booking-js-phishing-379b41e3.pdf` | JS `user_interaction` + bogus netlify booking URLs | `js_present`, `annotation_action_chain`, chain dedup ≤8 chains (stage 2), verdict field (stage 4) |
| `romcom-embedded-payload-a99903.pdf` | RomCom: embedded payload carve + external URI | `embedded_payload_carved` ×2, intent promotes above Heuristic (stage 3) |
| `perf-hang-717obj-fb87d8a7.pdf` | 717 objects, caused 292 s hang in `content_stream_exec_uplift` | scan completes in <10 s (stage 1 fix) |
| `font-heavy-objstm-5bb77b57.pdf` | 25+ font hinting anomalies, was 13 s scan | `font_exploitation_cluster` (stage 3), singleton rate ≤70% (stage 2), scan <5 s (stage 1+3) |
| `encoded-uri-payload-b710ae59.pdf` | Encoded C2 URL with base64 query params | network intents, URI classification |
| `decode-budget-exhaustion-c2d0d7e2.pdf` | 545-page oversized structure with repeated decode budget exhaustion | `decode_budget_exceeded` multiplicity, `DenialOfService` intent, content-first runtime hotspot |
| `decompression-bomb-font-flood-b509f6c9.pdf` | decompression bomb + font anomaly flood | `decompression_ratio_suspicious` critical signals, `parser_resource_exhaustion`, DoS intent scoring |
| `connectwise-filter-obfuscation-9ab20ec2.pdf` | ConnectWise-style filter obfuscation + mass external links | `declared_filter_invalid` dominance, `annotation_action_chain` volume, DataExfiltration intent behaviour |

These fixtures also guard against regression for existing fixtures:
- `noisy-correlated-highrisk-11606.pdf` — decompression bomb (485:1 ratio), `DenialOfService` intent (stage 3)
- `secondary-invalid-trailer-6eb8.pdf` — Fog netlify phishing, chain quality

## Integrity

`manifest.json` stores the expected `sha256` for each fixture.  
The `corpus_captured_manifest_integrity_stays_stable` test verifies:

1. each manifest entry exists on disk;
2. each fixture digest matches the manifest value.

This guarantees the baseline remains self-contained and does not require `tmp/corpus` to execute regression coverage.
