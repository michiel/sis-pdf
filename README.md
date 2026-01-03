# ysnp

_"Smiley is suspicious, Percy"_
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


ysnp is a Rust PDF analyser that inventories PDF attack surface, detects suspicious or exploitable constructs, and produces grouped findings with evidence spans. It is designed for interactive speed without trading away parser correctness.

Key goals:
- Viewer-tolerant parsing with recovery scanning for malformed PDFs.
- Evidence spans for both raw file bytes and decoded artifacts.
- Two-phase analysis: fast triage by default, deeper decoding on demand.
- Deterministic, stable finding IDs with reproducible evidence pointers.

## Workspace layout

```
ysnp/
  Cargo.toml
  crates/
    ysnp-core/      Core scan pipeline, models, reporting
    ysnp-pdf/       PDF parsing, object graph, decoding
    ysnp-detectors/ Detection rules
    ysnp-cli/       CLI front-end
  docs/
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
- JavaScript detection with payload inspection and optional AST summaries.
- Embedded files, filespecs, and rich media constructs (3D, sound, movie).
- Form technologies: AcroForm and XFA.
- Decoder risks and decompression ratio anomalies.
- Crypto indicators: signatures, DSS structures, and encryption dictionaries.
- Content heuristics: phishing cues, image-only pages, invisible text, and overlay links.
- Structural anomalies: missing header/EOF, stream length mismatches, xref conflicts.

Reporting and evidence:
- Human-readable reports and Markdown reports with impacts and remediation.
- JSON, JSONL, and SARIF outputs for automation and CI workflows.
- YARA rule generation with action and payload metadata.
- Action chain synthesis and chain templates.
- Input path tracking in JSON and reports.
- Strict parse deviations grouped in the Markdown report.

CLI workflows:
- `ysnp scan` for triage, deep scans, strict mode, and focused trigger scans.
- `ysnp report` for full Markdown reporting, with optional output file.
- `ysnp explain` for individual finding inspection with evidence previews.
- `ysnp extract` for JavaScript and embedded files.
- `ysnp export-graph` for chain export in DOT or JSON.
- Batch scanning with `--path` and `--glob` plus batch summaries.

Testing and fixtures:
- Golden test fixtures for action and JavaScript findings.
- Fixtures for signatures, encryption, ObjStm payloads, and strict deviations.
- Regression tests covering crypto, ObjStm expansion, and strict mode.

## Build

```
cargo build
```

## Quick start

```
# Triage scan
cargo run -p ysnp-cli --bin ysnp -- scan path/to/file.pdf

# JSON report
cargo run -p ysnp-cli --bin ysnp -- scan path/to/file.pdf --json

# Deep scan (decodes selected streams)
cargo run -p ysnp-cli --bin ysnp -- scan path/to/file.pdf --deep
```

## Tests

```
cargo test
```

## Status

This is a working implementation aligned to the spec in `docs/ysnp-spec.md`. It focuses on parsing correctness, evidence spans, and a practical rule set. Expect iterative hardening and expansion.
