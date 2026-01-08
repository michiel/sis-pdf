# _"Smiley is suspicious, Percy"_
```text
██████████▅▄▅▟███████████▇▆▇████▛▜▜▜██████████████▊▜██████████▛▀▘▔╵╵█████████▉▔▔▔ ╵▗██████
▊╴  ╵▀██████████╴   ╵▜█████████▍    ╵█████████████████████████╴    ▗█████████▎    ╶███████
█╴    ▐█████████▏    ▝█████████▋   ▂▄███████████████▛▀▀██████▋    ╷▟████████▉╴    ▗███████
█▅▁  ╷▃█████████▙▄▂╷▁▄██████████▅▄▟█████████▀▔ ▝▔╶▝▔     ▀████▇▆▅▆██████▛▀▘╵▅▇▆▆▇██████▛▛▀
████████▛▀▘▘▀▜██████████▘▔╵▔▘███████████████▅▃▃▃▄▄▅▆▇▆▅▃   ▜██████████╵    ▗█████████▘    
████████▋    ╶▜████████▉╴    ▐███████████████████████████▖  ▜▞▜██████▍     ▟████████▌     
████████▉╴    ▐█████████▁    ▗██▅▀▀██████████████████████▉ ╶▁▜▖▜████▀╷╷ ╷▂▅███████▜▀╴╷  ╷▂
█▛███████▇▅▅▄▆███▛███████▇▆▇▇██▉  ╶██████████████████████▉ ▜▞┱▁▖▔  ╶▐█████████▘╵  ╵▕▇█████
▉╴   ╵▐█████████╴    ▔█████████▌   ██████████████████████▉ ╷▜▇▞╴╴  ╶█████████▏     ▟██████
█╴    ╶█████████▎     ▜████████▌  ▃██▀▔▔▔▘▀▀▀▀▀▀▀▀▀██████╴ ▐╶╋▔╲   ▁████████▀╴    ╶███████
█▄╷  ╷▁▟████████▙▂╷╷╷▂█████████▙  ▖                  ▀▜██▙ ▕▘╴  ╺▄▅████▛▛▀╵╶▗▆▆▆▆▆████▛▛▀╵
████████▋╵╵▔▝▀██████████╴╵  ╵▀██▌▕▇╴ ▁     ▄▖          ▝▀▀   ╶╷━▇████▉╵    ╶█████████▔    
████████▊     ▐█████████╴    ╶██▋╵╶▛█▋▃▃▖ ▟██▖╻╷    ╷▃▖▅▆▇▍▗▆┘▗▎█████▋     ▗████████▋     
████████▊╴    ╶█████████╴    ╶███▊ ▗████┓▆███▙▁▜██▇▇██▐███▁▄▋ ▝▐███▛▀╴╷   ▁███████▛▘╷╷   ▁
╻▀▀▜▜████▙▅▄▄▅▆█▀▀▀▀▜▜███▆▅▅▆███▀┑         ▔▀▀▀  ▔▔▜█▇▇████▛▃▖▘▔▔  ╵▗▇███████▛▔╵   ╶▅█████
▊╴    ▝█████████╴     █████████▋ ╹    ╶╹╴    ▄▇▇▄ ╶▕███████▆█▇╴     ▐████████▍     ▐██████
█╴     ▜████████╴     ▐████████▌  ╷         ╴▐██▜▋╶▂▜██▟┹▝▃██▋      ████████▘╴     ▕██████
█▅▁╷  ╷▄▜███████▄▂╷  ▁▟████████▍╶╶╴           ╶╷╴╵ ▀▝██▘╶▕▀▀▘▗▄▃▃▄▄▟███▛▀▀▔╵╶▄▄▅▆▆▆███▛▀▀▔
████████▌╵   ▔▜████████▉╴▁▃▅▆▀▔               ╵╵╵╵ ╵▝▛▔ ╶ ╵╺╸▀████████╴     ▐████████▏    
████████▋     ╶█████████▛▘╵         ▗       ╶╌╴╵╶╵╶ ╵╷╷╴▗      ▔▀▜███▋      ▟███████▀     
▜███████▍ ▁▂▃▅▆████▛▛▀▔             ▐▙               ╵ ▅▉          ▝▜▅▄▃▂▁╷▂██████▘╵     ╷
╌▝▘▀▀▀▀▛▜▀██▜▀▘╴                     ▜              ▁▅██▘              ╵╵▔▀▀▛▘╷▁    ▗▇▇▇██
▋╴        ▔╵                          ╴           ▃▆███▛                     ╶╵▔▘╶╶┎▀█████
▊                                      ╶       ╶▆█████▛                            ▔ ▝████
▍╷   ╵                                  ╴╷╷╷    ▐████▛                                ▝▀▀▔
███▇▍                                    ╶╷╴     ████                                     
████▘                                    ╵▐      ███▍                                     

```


_Smiley Is Suspicious_ (`sis`) is a PDF analyser that inventories PDF attack surface, detects suspicious or exploitable constructs, and produces grouped findings with evidence spans. It is designed for interactive speed without trading away parser correctness.

Key goals:
- Viewer-tolerant parsing with recovery scanning for malformed PDFs.
- Evidence spans for both raw file bytes and decoded artifacts.
- Two-phase analysis: fast triage by default, deeper decoding on demand.
- Deterministic, stable finding IDs with reproducible evidence pointers.

## Workspace layout

```
sis-pdf/
  Cargo.toml
  crates/
    sis-pdf-core/      Core scan pipeline, models, reporting
    sis-pdf-pdf/       PDF parsing, object graph, decoding
    sis-pdf-detectors/ Detection rules
    sis-pdf/           CLI front-end
    js-analysis/       JavaScript static and dynamic analysis
  docs/                Specifications and analysis documentation
  scripts/
    test_helpers/      Development test fixtures and helper code
```

## Features

Core analysis:
- PDF parser with recovery scanning and optional strict deviation tracking.
- Object graph with xref and trailer awareness plus deep object stream expansion.
- Stream decoding with filter tracking, decode ratio metrics, and evidence spans.
- Stable, deterministic finding IDs with dual-source evidence spans.
- Differential parsing using an independent parser for cross-checking.

Detection surfaces:
- Actions: OpenAction, Additional Actions, Launch, GoToR, URI, SubmitForm.
- JavaScript malware detection with comprehensive static analysis (73 detection functions, 72 finding IDs):
  - Shellcode detection, memory corruption primitives, exploit kit signatures.
  - Ransomware patterns, resource exhaustion, code injection vectors.
  - Anti-analysis techniques, data exfiltration, persistence mechanisms.
  - Supply chain attacks, network abuse, steganography, polyglot files.
  - ~95% coverage of known PDF JavaScript malware patterns (see `docs/js-detection-*.md`).
- Optional JavaScript sandboxing for runtime API intent (feature: `js-sandbox`).
- Embedded files, filespecs, and rich media constructs (3D, sound, movie).
- Linearization anomalies, page tree mismatches, and annotation action chains.
- Font embedding anomalies and ICC profile stream checks.
- Form technologies: AcroForm and XFA.
- Decoder risks and decompression ratio anomalies.
- Crypto indicators: signatures, DSS structures, and encryption dictionaries.
- Content heuristics: phishing cues, image-only pages, invisible text, and overlay links.
- Structural anomalies: missing header/EOF, stream length mismatches, xref conflicts.

Reporting and evidence:
- Human-readable reports and Markdown reports with impacts and remediation.
- JSON, JSONL, and SARIF outputs for automation and CI workflows.
- YARA rule generation with action and payload metadata.
- ML feature extraction and optional stacking classifier scoring.
- Action chain synthesis and chain templates.
- Input path tracking in JSON and reports.
- Strict parse deviations grouped in the Markdown report.

CLI workflows:
- `docs/scenarios.md` for end-to-end operator workflows.
- `sis scan` for triage, deep scans, strict mode, and focused trigger scans.
- `sis report` for full Markdown reporting, with optional output file.
- `sis explain` for individual finding inspection with evidence previews.
- `sis extract` for JavaScript and embedded files.
- `sis export-graph` for chain export in DOT or JSON.
- `sis export-features` for ML dataset feature extraction.
- Batch scanning with `--path` and `--glob` plus batch summaries.
- Batch scans are parallel by default; use `--sequential` (alias `--seq`) to disable.

Testing and fixtures:
- Golden test fixtures for action and JavaScript findings.
- Fixtures for signatures, encryption, ObjStm payloads, and strict deviations.
- Hostile JavaScript payload fixtures using real VirusShare malware samples for validation.
- Regression tests covering crypto, ObjStm expansion, strict mode, and JavaScript malware detection.
- 100% crash-free analysis on hostile payloads.

## Build

```
cargo build
```

To enable JavaScript sandboxing for runtime behavior analysis:

```
cargo build --features js-sandbox
```

## Quick start

```
# Triage scan
cargo run -p sis-pdf --bin sis -- scan path/to/file.pdf

# JSON report
cargo run -p sis-pdf --bin sis -- scan path/to/file.pdf --json

# Deep scan (decodes selected streams)
cargo run -p sis-pdf --bin sis -- scan path/to/file.pdf --deep

# Export features for ML pipelines
cargo run -p sis-pdf --bin sis -- export-features --path samples --glob "*.pdf" --format jsonl -o features.jsonl
```

## Configuration

Batch scan parallelism can be enabled in config:

```yaml
scan:
  batch_parallel: false
```

## Tests

```
cargo test
```

## Fuzzing

Install cargo-fuzz:

```
cargo install cargo-fuzz
```

List targets:

```
cd fuzz
cargo fuzz list
```

Run a target (examples):

```
cargo fuzz run lexer
cargo fuzz run parser
cargo fuzz run graph
cargo fuzz run objstm
cargo fuzz run decode_streams
```

To use a custom corpus, pass a directory path:

```
cargo fuzz run parser fuzz/corpus/parser
```

## Status

This is a working implementation aligned to the spec in `docs/sis-pdf-spec.md`. It focuses on parsing correctness, evidence spans, and a practical rule set.

JavaScript malware detection includes comprehensive static analysis with 73 detection functions covering 22 malware categories, providing ~95% coverage of known PDF JavaScript malware patterns. See `docs/js-detection-roadmap.md` for implementation details and future enhancements.

Expect iterative hardening and expansion.
