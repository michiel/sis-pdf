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
- Evidence spans for raw bytes and decoded artefacts.
- Two-phase analysis: fast triage by default, deeper decoding on demand.
- Deterministic, stable finding IDs with reproducible evidence pointers.

## Features

- Viewer-tolerant parsing, document deviation tracking, and deterministic, reproducible findings.
- Stream decoding with cached results, filter recovery, and evidence spans for both raw and decoded bytes.
- Action-chain inference that links triggers (actions, annotations) to payloads (JavaScript, embedded files, font gadgets).
- Content-first pipeline covering JavaScript, vector and raster payloads, metadata/phishing signals, and rich media.
- Font analysis for Type 1, TrueType, OpenType, and variable fonts (see `docs/findings.md` for CVE coverage).
- Image/decoder scrutiny (JPEG, JPEG2000, PNG, TIFF, JBIG2, CCITT) with the new vector path anomaly detector.
- Filter-chain anomaly, entropy, and decoder budget detection plus embedded file classification.
- Queryable output (JSON/JSONL/SARIF) combined with CLI (`sis report`, `sis explain`, `sis extract`) and optional ML scoring (ONNX).

### Scanning stages

1. **Stage 0 (Index + Parse)** – Build the object graph, page tree, and preliminary indexes. Data is parsed once so detectors can reuse shared views.
2. **Stage 1 (Fast triage)** – Run cheap detectors that do not decode large streams (metadata, actions, structure, table checks). This provides instant feedback inside `sis scan`.
3. **Stage 2 (Decoded payloads)** – Optional (triggered via `--deep` or detectors that request it). Streams are decoded, JavaScript is analyzed, embedded files commented, and vector/raster heuristics applied.
4. **Stage 3 (Correlation & ML)** – Build action chains, correlate findings, score with ML models (if configured), and emit enriched reports (`sis report`, JSON output, SARIF).

## Capabilities

- **Actions & JavaScript** – Detects `/OpenAction`, `/AA`, `/Launch`, `/GoToR`, `/URI`, `/SubmitForm`, script payloads, and obfuscation signals (signature counts, entropy, AST hints).
- **Embedded content** – Finds embedded files, font gists, XFA submissions, and now vector-heavy streams (`vector_graphics_anomaly`), combining evidence spans and meta for tracing.
- **Images & decoders** – Supports JPEG/JPX, PNG, TIFF, JBIG2, CCITT with deferred filter handling so image-analysis detectors own their filters; includes the new vector-path detector for suspicious Illustrator/EPS/SVG content.
- **Fonts** – Examines Type 1, TrueType, OpenType, and variable fonts for CVEs and stack anomalies, includes reader-impact reasoning.
- **Entropy & resources** – Tracks entropy metrics, decoding budgets, and filter-chain anomalies to catch obfuscation or DoS attempts.
- **Query & reporting** – CLI outputs (Markdown/JSON/SARIF), `sis query` for structured exploration (`pages`, `js`, `urls`, `events`, `filters`), and `sis explain` for per-finding breakdowns.

## Taxonomy

All finding definitions live under `docs/findings.md`. Findings are grouped by weak spot:

- **Actions & chains** (URI, Launch, SubmitForm, JS chains)
- **Embedded payloads** (files, scripts, executables, vector anomalies)
- **Streams & decoders** (filters invalid, entropy, decompression ratio, corrupt data)
- **Fonts & typography** (Type 1 stack, TrueType VM, CFF/CFF2 tables)
- **Metadata & phishing** (XFA forms, URI classifications, structure anomalies)

Each finding carries `severity`, `confidence`, and `impact`, making it easy to score, chain, and filter through the CLI or ML outputs.

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/michiel/sis-pdf/main/scripts/install.sh | sh
```

Pass `SIS_INSTALL_DIR=/path/team/bin` to install elsewhere and use the PowerShell helper for Windows:

```powershell
irm https://raw.githubusercontent.com/michiel/sis-pdf/main/scripts/install.ps1 | iex
```

`cis update` keeps your release current; include `--include-prerelease` when you need nightly builds.

## Examples

```bash
# Fast triage scan
sis scan sample.pdf

# Deep scan with Markdown report
sis report --deep sample.pdf -o report.md

# JSON/SARIF results for automation
sis scan sample.pdf --json
sis report sample.pdf --format=sarif

# Explain an interesting finding
sis explain sample.pdf vector_graphics_anomaly

# Extract JavaScript or embedded files defensively
sis extract js sample.pdf -o payloads/
sis extract embedded sample.pdf -o embedded/

# ML health check
sis ml health --ml-provider auto

# Query specific sections
sis query pages sample.pdf
sis query js sample.pdf --where "entropy > 7.5"
sis query urls sample.pdf --json
sis query filters sample.pdf --where "filter == '/FlateDecode'"
sis query events sample.pdf # interactive REPL
```

## Documentation

- `docs/findings.md` – canonical taxonomy, severities, tags, and evidence guidance.
- `docs/sis-pdf-spec.md` – implementation notes, features, and content-stream parsing.
- `docs/query-interface.md` – `sis query` grammar, predicates, and example workflows.
- `docs/ml-features.md` – exported ML features and normalization.
- `README-DEV.md` – development setup, cargo commands, and workspace tips.

Also check `plans/` for long-lived project agendas (filters, chains, ML signals, etc.).

## Install

Linux (x86_64) and macOS (arm64):

```
curl -fsSL https://raw.githubusercontent.com/michiel/sis-pdf/main/scripts/install.sh | sh
```

Windows (PowerShell):

```
irm https://raw.githubusercontent.com/michiel/sis-pdf/main/scripts/install.ps1 | iex
```

Custom install directory:

```
SIS_INSTALL_DIR=/path/to/bin curl -fsSL https://raw.githubusercontent.com/michiel/sis-pdf/main/scripts/install.sh | sh
```

You can also download release binaries directly from GitHub releases.

## Examples

```
# Triage scan
sis scan path/to/file.pdf

# Deep scan with Markdown report
sis report --deep path/to/file.pdf -o report.md

# JSON report
sis scan path/to/file.pdf --json

# Explain a finding
sis explain path/to/file.pdf PDF.JS.OBFUSCATION.001

# Extract JavaScript
sis extract js path/to/file.pdf -o extracted.js

# Validate ML runtime
sis ml health --ml-provider auto --ml-provider-info

# Print the installed sis version
sis version
sis --version

# Query PDF metadata and structure
sis query pages file.pdf
sis query "pages,creator,producer,version" file.pdf --json

# Extract content via queries
sis query js file.pdf
sis query urls file.pdf
sis query events file.pdf

# Interactive query mode (REPL)
sis query file.pdf
```

## Font Security Analysis

`sis-pdf` includes comprehensive font security analysis to detect exploits targeting PDF font renderers. This feature analyzes embedded fonts for known vulnerabilities, suspicious patterns, and exploit techniques.

### Supported Font Formats

- **Type 1 (PostScript)**: BLEND exploit detection, dangerous operator analysis, stack depth tracking
- **TrueType**: Hinting program analysis, table validation, VM instruction budgets
- **OpenType/CFF**: Variable font validation, CFF2 table checks
- **Variable Fonts**: gvar/avar/HVAR/MVAR table anomaly detection

### CVE Detection

The analyzer includes signatures for known font vulnerabilities:

- **CVE-2025-27163**: hmtx/hhea table length mismatch
- **CVE-2025-27164**: CFF2/maxp glyph count mismatch
- **CVE-2023-26369**: EBSC table out-of-bounds
- **BLEND Exploit (2015)**: PostScript Type 1 stack manipulation

CVE signatures are automatically updated weekly via GitHub Actions.

### Configuration

Font analysis is enabled by default. Configure via `config.toml`:

```toml
[scan.font_analysis]
enabled = true
dynamic_enabled = true
dynamic_timeout_ms = 5000
max_fonts = 100
```

### Example Usage

```bash
# Scan PDF with font analysis
sis scan suspicious.pdf

# View font findings
sis scan suspicious.pdf | grep "^font\."

# Detailed font analysis example
cargo run --example font_analysis suspicious.pdf
```

For all font finding definitions, see [`docs/findings.md`](docs/findings.md).

## Configuration

Config defaults to the platform user config directory, or pass `--config=PATH`.

```
Linux:   ~/.config/sis/config.toml
macOS:   ~/.config/sis/config.toml
Windows: %APPDATA%\sis\config.toml
```

Generate a default config and validate it:

```
sis config init
sis config verify
```

Example (TOML):

```toml
[logging]
level = "warn"

[scan]
deep = true
parallel = true

ml_provider = "auto" # auto, cpu, cuda, migraphx, rocm, directml, coreml, onednn, openvino
ml_provider_order = ["migraphx", "cuda", "cpu"]
ml_ort_dylib = "/path/to/libonnxruntime.so"
ml_provider_info = true
```

## Updates

```
sis update
```

Or re-run the install script to pull the latest release.

To include prerelease builds:

```
sis update --include-prerelease
```

## Documentation

- Operator scenarios: `docs/scenarios.md`
- JavaScript detection catalogue: `docs/findings.md`
- Development notes and workspace details: `README-DEV.md`
