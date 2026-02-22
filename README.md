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

- **Safety-first** -- defensive parsing with strict resource budgets, bounded recursion, and no unsafe code. PDFs are assumed hostile.
- **Deterministic** -- stable finding IDs, reproducible evidence spans, and consistent output across runs for the same input and options.
- **Fast triage, deep on demand** -- low-cost detectors run by default; heavier decoding, dynamic analysis, and ML scoring activate with `--deep`.
- **Forensic-grade query** -- interactive REPL with structured namespaces, predicate filtering, stream decoding, and object inspection.
- **Operator and pipeline ready** -- JSON/JSONL/SARIF output, batch scanning, markdown reports, and campaign-level correlation.

## What `sis` analyses

`sis` runs 40+ detectors across 13 attack surfaces, producing 100+ distinct finding kinds:

| Attack surface | Examples |
|---|---|
| **File structure** | xref conflicts, incremental update chains, object shadowing, trailer inconsistencies |
| **Actions and triggers** | OpenAction, AdditionalAction, Launch, GoToR, URI, SubmitForm |
| **JavaScript** | obfuscation (JSFuck, JJencode, fromCharCode chains), heap grooming, sandbox evasion, environment fingerprinting, runtime behaviour profiling via V8 sandbox |
| **Forms** | AcroForm field abuse, XFA script extraction, XFA image payloads, XML entity risk |
| **Embedded files** | executables, scripts, archives, nested documents |
| **Streams and filters** | filter chain abuse, high-entropy payloads, JBIG2 decoder risk, nested decode anomalies |
| **Fonts** | Type 1 eexec analysis, TrueType/OpenType/WOFF vulnerability signatures, decompression bombs, external references, font exploitation bridges |
| **Images** | JPEG/JPEG2000/PNG/TIFF/JBIG2/CCITT header validation, decoder budget enforcement |
| **Rich media** | SWF ActionScript detection, U3D/PRC 3D format analysis, embedded media |
| **URIs** | obfuscation, phishing indicators, IDN homoglyphs, credential lure patterns, automatic trigger correlation |
| **Passive render pipeline** | UNC/SMB credential leak paths, preview-triggered external fetch, render surface risk composites |
| **Crypto and signatures** | short keys, quantum-vulnerable algorithms, certified document manipulation, shadow attacks |
| **Content phishing** | invisible text overlays, image-only pages, annotation link spoofing |

Findings are correlated into trigger/action/payload chains and composite scores. Multi-stage attack chains, supply chain indicators, and parser divergence risks are synthesised from cross-surface evidence.

All finding IDs, metadata fields, and semantics are documented in [`docs/findings.md`](docs/findings.md).

## Analysis pipeline

1. **Parse and index** -- dual-parser architecture (primary + secondary via lopdf) builds a typed object graph with xref resolution, structural views, and recovery support for malformed files. Parser divergence is measured and reported.
2. **Fast triage (default)** -- runs low-cost detectors for rapid first-pass risk assessment. Typical triage completes in under 50ms.
3. **Deep analysis (`--deep`)** -- activates stream decoding, JavaScript static and dynamic analysis (V8 sandbox), font/image vulnerability scanning, and entropy profiling.
4. **Correlation** -- chain synthesis links triggers, actions, and payloads into exploit chains. Composite findings aggregate cross-surface evidence with severity uplift rules.
5. **Output** -- findings with evidence spans, reader-specific impact annotations (Acrobat, PDFium, Preview), and machine-readable or operator-facing formats.

## Commands

| Command | Purpose |
|---|---|
| `sis scan` | Primary detector pipeline for one file or batch paths |
| `sis query` | Forensic query interface with interactive REPL |
| `sis explain` | Detailed explanation for a specific finding |
| `sis report` | Full markdown report generation |
| `sis sanitize` | CDR strip-and-report for active content removal |
| `sis sandbox` | Dynamic sandbox evaluation for extracted assets |
| `sis stream` | Streaming chunk analysis with early-stop on indicators |
| `sis correlate` | Campaign-level network intent correlation from JSONL |
| `sis generate` | Test fixture mutation and YARA rule generation |
| `sis doc` | Print bundled documentation (agent query guide) |
| `sis ml` | ML runtime configuration, detection, and baseline computation |
| `sis config` | Configuration initialisation and validation |
| `sis update` | Self-update from GitHub releases |

## Typical workflows

```bash
# Fast triage
sis scan sample.pdf

# Deep analysis with machine output
sis scan sample.pdf --deep --json

# Batch scan a directory
sis scan samples/ --dir --deep --format jsonl

# Explain a specific finding
sis explain sample.pdf <finding-id>

# Generate markdown report
sis report sample.pdf --deep -o report.md

# Query findings with predicate filtering
sis query sample.pdf findings --where "severity == 'High'" --format json
sis query sample.pdf findings.composite --format json

# Query structure and actions
sis query sample.pdf actions.chains --format json
sis query sample.pdf xref.deviations

# Interactive REPL (parse once, query many)
sis query sample.pdf
> findings.high
> actions.chains
> stream 8 0 --decode
> js
> :json
> findings --where "confidence == 'Certain'"

# Inspect a stream object
sis query sample.pdf stream 8 0 --decode
sis query sample.pdf stream 8 0 --raw --extract-to /tmp/streams

# Sanitise active content
sis sanitize sample.pdf --out clean.pdf --report-json report.json

# Generate YARA rules from findings
sis generate yara --kind js_obfuscation_heavy -o rules.yar
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

## Native GUI

The native GUI package builds separately from the CLI:

```bash
cargo build -p sis-pdf-gui
```

On macOS and Windows, unsigned binaries may show platform trust prompts
(Gatekeeper/SmartScreen) until signing is enabled in the release process.

Linux desktop metadata (entry + icon) can be installed with:

```bash
scripts/install_linux_desktop_entry.sh
```

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

- [`docs/findings.md`](docs/findings.md) — canonical finding catalogue and metadata semantics.
- [`docs/query-interface.md`](docs/query-interface.md) — query grammar, namespaces, and output formats.
- [`docs/agent-query-guide.md`](docs/agent-query-guide.md) — practical operator query workflows.
- [`docs/js-analysis-engine.md`](docs/js-analysis-engine.md) — JavaScript static/dynamic analysis design.
- [`docs/uri-classification.md`](docs/uri-classification.md) — URI detection, scoring, and metadata model.
- [`docs/performance.md`](docs/performance.md) — profiling approach and runtime SLO checks.
- [`README-DEV.md`](README-DEV.md) — development setup and workspace workflows.
