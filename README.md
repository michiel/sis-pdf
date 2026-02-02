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

- Viewer-tolerant PDF parsing with strict deviation tracking.
- Deep object stream expansion and robust stream decoding with evidence spans.
- Stable, deterministic finding IDs with reproducible evidence pointers.
- Action chain detection across PDF actions, JavaScript, embedded files, and rich media.
- Embedded file classification (executables, scripts, encrypted archives, double extensions).
- XFA form inspection (submit actions, sensitive fields, script counts).
- Rich media SWF detection and stream entropy signals.
- Filter chain anomaly detection for unusual decoding sequences.
- JavaScript malware detection with 72+ finding IDs (see `docs/findings.md`).
- Font security analysis with Type 1, TrueType, OpenType, and variable font support (8+ finding IDs, see `docs/findings.md`).
- Human-readable reports plus JSON, JSONL, and SARIF outputs.
- Optional ML scoring and graph inference with ONNX Runtime.

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
