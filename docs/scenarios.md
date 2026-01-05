# End-to-End Scenarios

This document provides practical, end-to-end workflows using SIS-PDF, from first-pass triage to graph ML classification and export workflows.

## Scenario 1: Fast Triage and Report

Goal: get a quick risk signal and a shareable report.

Steps:
- Run a fast scan: `sis scan suspicious.pdf`
- Generate a report: `sis report suspicious.pdf -o report.md`

Expected outputs:
- Findings grouped by attack surface.
- `structural_summary` with xref/trailer and polyglot signals.
- Action and JavaScript presence indicators.

## Scenario 2: Deep Decode Investigation

Goal: confirm whether suspicious streams hide payloads or embedded files.

Steps:
- Run a deep scan: `sis scan suspicious.pdf --deep`
- Extract JavaScript: `sis extract js suspicious.pdf -o out/js`
- Extract embedded files: `sis extract embedded suspicious.pdf -o out/embedded`

Expected outputs:
- Decoder-risk findings and decompression ratios.
- Extracted payloads mapped to object IDs.

## Scenario 3: IR/ORG Static Graph Analysis (No ML)

Goal: identify action-to-payload paths and hidden objects without ML.

Steps:
- Enable IR detectors: `sis scan suspicious.pdf --ir`
- Review IR/ORG summary in report: `sis report suspicious.pdf --ir -o report.md`

Expected outputs:
- `action_payload_path` findings for reachability chains.
- `orphan_payload_object` for unreachable payload objects.
- `shadow_payload_chain` for hidden revisions.

## Scenario 4: Graph ML Classification (ONNX)

Goal: apply graph ML for a malware score.

Prerequisites:
- Build with `--features ml-graph`.
- Provide a model directory containing `graph_model.json`, `embedding.onnx`, `graph.onnx`, and `tokenizer.json`.

Steps:
- Run graph ML scan:
  `sis scan suspicious.pdf --ml --ml-mode graph --ml-model-dir models`
- Inspect ML summary in JSON output:
  `sis scan suspicious.pdf --ml --ml-mode graph --ml-model-dir models --json`

Expected outputs:
- `ml_graph_score_high` when score exceeds threshold.
- `ml_summary.graph` populated in JSON and Markdown.

## Scenario 5: Export for Offline Graph Analysis

Goal: export artifacts for external tooling.

Steps:
- Export IR:
  `sis export-ir suspicious.pdf --format json -o ir.json`
- Export ORG:
  `sis export-org suspicious.pdf --format json -o org.json`
- Visualize ORG:
  `sis export-org suspicious.pdf --format dot -o org.dot`
  `dot -Tpng org.dot -o org.png`

Expected outputs:
- IR and ORG files suitable for offline inspection or training data generation.
