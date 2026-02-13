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
- Safety-first parsing and analysis of hostile PDFs.
- Deterministic findings with stable IDs and reproducible evidence.
- Fast default triage, with deep analysis when requested.
- Practical forensic workflows for operators and automation.

## What `sis` does

`sis` is a CLI-first PDF security analyser for:

- **Detection**: suspicious actions, JavaScript, embedded payloads, filter abuse, structural evasion, image/font attack surfaces.
- **Correlation**: trigger/action/payload chain synthesis and composite findings.
- **Forensics**: queryable evidence, object-level stream inspection, explainable findings.
- **Operations**: JSON/JSONL/SARIF output, markdown reporting, batch scanning, optional ML scoring.

All finding IDs, metadata fields, and semantics are documented in `docs/findings.md`.

## Analysis pipeline

1. **Parse and index**  
   Builds object graph and structural views with recovery support for malformed files.
2. **Fast triage (default)**  
   Runs low-cost detectors for rapid first-pass risk assessment.
3. **Deep analysis (`--deep`)**  
   Performs heavier decoding and richer payload analysis.
4. **Correlation and output**  
   Produces chains, composites, and machine-readable/operator-facing output.

## Command overview

- `sis scan` — primary detector pipeline for one file or batch paths.
- `sis query` — forensic query interface + interactive REPL.
- `sis explain` — detailed explanation for one finding ID.
- `sis report` — full markdown reporting output.
- `sis sanitize` — CDR strip-and-report workflow.
- `sis sandbox` — dynamic sandbox evaluation commands.
- `sis stream` — streaming analysis for large/continuous content.
- `sis correlate` — campaign-level correlation from structured data.
- `sis ml` / `sis config` / `sis update` — ML runtime, config, and updates.

## Typical workflows

```bash
# 1) Fast triage
sis scan sample.pdf

# 2) Deep analysis with machine output
sis scan sample.pdf --deep --json

# 3) Explain a specific finding
sis explain sample.pdf <finding-id>

# 4) Generate markdown report
sis report sample.pdf --deep -o report.md

# 5) Query findings and structure
sis query sample.pdf findings --where "severity == 'High'" --format json
sis query sample.pdf actions.chains --format json
sis query sample.pdf xref.deviations

# 6) Inspect a stream object
sis query sample.pdf stream 8 0 --decode
sis query sample.pdf stream 8 0 --raw --extract-to /tmp/streams
```

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/michiel/sis-pdf/main/scripts/install.sh | sh
```

Custom install destination:

```bash
SIS_INSTALL_DIR=/opt/bin curl -fsSL https://raw.githubusercontent.com/michiel/sis-pdf/main/scripts/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/michiel/sis-pdf/main/scripts/install.ps1 | iex
```

Binary releases are published in [Releases](https://github.com/michiel/sis-pdf/releases).

## Configuration

Default config path:

```
Linux:   ~/.config/sis/config.toml
macOS:   ~/.config/sis/config.toml
Windows: %APPDATA%\sis\config.toml
```

Initialise and validate:

```bash
sis config init
sis config verify
```

Example:

```toml
[logging]
level = "warn"

[scan]
deep = true
parallel = true
```

## Updating

```bash
sis update
```

Include prereleases:

```bash
sis update --include-prerelease
```

## Documentation

- `docs/findings.md` — canonical finding catalogue and metadata semantics.
- `docs/query-interface.md` — query grammar, namespaces, and output formats.
- `docs/agent-query-guide.md` — practical operator query workflows.
- `docs/js-analysis-engine.md` — JavaScript static/dynamic analysis design.
- `docs/uri-classification.md` — URI detection, scoring, and metadata model.
- `docs/performance.md` — profiling approach and runtime SLO checks.
- `README-DEV.md` — development setup and workspace workflows.
