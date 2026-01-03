# ysnp

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

This is a working skeleton aligned to the spec in `docs/ysnp-spec.md`. It focuses on parsing correctness, evidence spans, and a practical initial rule set. Expect iterative hardening and expansion.
