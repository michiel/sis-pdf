#!/usr/bin/env bash
set -euo pipefail

CORPUS_ROOT="${1:-crates/js-analysis/tests/fixtures/corpus}"
OUTPUT_PATH="${2:-plans/20260211-pr20-validation-report.json}"

cargo run -p js-analysis --bin js-corpus-harness --features js-sandbox,js-ast -- \
  --corpus-root "${CORPUS_ROOT}" \
  --output "${OUTPUT_PATH}" \
  --enforce-thresholds
