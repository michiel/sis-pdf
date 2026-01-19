---
title: "Smiley Is Suspicious (sis-pdf) Documentation"
layout: default
---

# Smiley Is Suspicious (sis-pdf)

_"Smiley is suspicious, Percy"_

**sis-pdf** is a PDF analyzer that inventories PDF attack surface, detects suspicious or exploitable constructs, and produces grouped findings with evidence spans. It is designed for interactive speed without trading away parser correctness.

## Quick Links

- [GitHub Repository](https://github.com/michiel/sis-pdf)
- [Main README](../README.md)
- [Usage Guide](../USAGE.md)

## Getting Started

### Installation & Usage

- [Main README](../README.md) - Installation, quick start, and basic usage
- [Complete Usage Guide](../USAGE.md) - Comprehensive command-line reference
- [Configuration Guide](configuration.md) - Configuration files and profiles
- [Glossary](glossary.md) - Terminology and concepts

## Core Documentation

### Architecture & Design

- [Technical Specification](sis-pdf-spec.md) - Complete technical specification
- [IR/ORG Graph Model](ir-org-graph.md) - Internal representation and object reference graph
- [Graph Model Schema](graph-model-schema.md) - Schema documentation for the graph model
- [Analysis Overview](analysis.md) - Analysis architecture and approach

### Features & Capabilities

- [Findings Catalog](findings.md) - Complete catalog of all finding types (72+ detection rules)
- [JavaScript Extraction](JS_EXTRACTION_README.md) - JavaScript detection and extraction
- [Risk Profiling](risk-profiling.md) - Document-level risk profiling and calibration
- [URI Classification](uri-classification.md) - URL and network intent classification

### Machine Learning

- [ML Runtime](ml-runtime.md) - ONNX Runtime integration and ML capabilities
- [ML Modeling](modeling.md) - ML model architecture and features
- [Training Pipeline](training-pipeline.md) - ML model training workflow

## Testing & Evaluation

### Corpus Analysis

- [Corpus Analysis](corpus-analysis.md) - Analysis methodology and results
- [Corpus Benchmarking](corpus-benchmarking.md) - Performance benchmarking results
- [Deep Findings Analysis](corpus-findings-deep-analysis.md) - Detailed findings analysis
- [Implementation Status (2026-01-11)](implementation-status-20260111.md) - Current implementation status

### Test Results

- [2022 Corpus Testing](testing-20260111-corpus-2022.md) - Results from 2022 test corpus
- [2024 VirusShare Testing](testing-20260111-corpus-2024-virusshare.md) - Results from 2024 VirusShare corpus

## Research & Background

- [PDF State of the Art](pdf-state-of-the-art.md) - Survey of PDF security research and tools
- [Datasets](datasets.md) - Public PDF malware datasets and corpora
- [Use Case Scenarios](scenarios.md) - Practical usage scenarios

## Examples

### Basic Scanning

```bash
# Triage scan
sis scan suspicious.pdf

# Deep scan with Markdown report
sis report --deep suspicious.pdf -o report.md

# JSON output for automation
sis scan suspicious.pdf --json
```

### Query Interface

```bash
# Query PDF metadata
sis query pages file.pdf
sis query version file.pdf

# Extract content
sis query js file.pdf
sis query urls file.pdf
sis query events file.pdf

# Reference lookup
sis query file.pdf ref 52 0

# Predicate filtering
sis query js file.pdf --where "length > 1024 AND entropy > 5.0"
sis query urls file.pdf --where "length > 25"
sis query events file.pdf --where "filter == 'document'"
sis query findings file.pdf --where "filter == 'high'"

# Streaming output
sis query js.count file.pdf --format jsonl

# Extraction decode controls
sis query js file.pdf --extract-to /tmp/out --raw
sis query js file.pdf --extract-to /tmp/out --hexdump

# Interactive REPL mode
sis query file.pdf
```

Predicate filtering is available on the most common query types (js, embedded, objects, urls, events, findings). For field mappings and examples, see `docs/query-predicates.md`.

### Finding Explanation

```bash
# Explain a specific finding
sis explain suspicious.pdf sis-JS-001
```

## Key Features

- **Viewer-tolerant parsing** with strict deviation tracking
- **Deep object stream expansion** and robust stream decoding with evidence spans
- **Stable, deterministic finding IDs** with reproducible evidence pointers
- **Action chain detection** across PDF actions, JavaScript, embedded files, and rich media
- **JavaScript malware detection** with 72+ finding IDs
- **Multiple output formats**: Human-readable reports, JSON, JSONL, and SARIF
- **Optional ML scoring** and graph inference with ONNX Runtime
- **Event trigger detection** for document, page, and field-level events

## Contributing

See the main [README](../README.md) for contribution guidelines.

## License

See [LICENSE](../LICENSE) in the repository root.

---

_Generated documentation for sis-pdf_
