#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIS_BINARY="${SIS_BINARY:-sis}"

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <batch-dir> <corpus-dir>"
  exit 1
fi

BATCH_DIR="$1"
CORPUS_DIR="$2"
OUTPUT_DIR="${3:-reports/trends}"

run_evaluate() {
  target="$1"
  shift
  python "${SCRIPT_DIR}/evaluate-mwb-corpus.py" \
    --batch-dir "${target}" \
    --sis-binary "${SIS_BINARY}" \
    --output-dir "${OUTPUT_DIR}" \
    "$@"
}

# Run both batch and corpus evaluations in parallel to reduce total runtime.
run_batch() {
  python "${SCRIPT_DIR}/evaluate-mwb-corpus.py" \
    --batch-dir "${BATCH_DIR}" \
    --sis-binary "${SIS_BINARY}" \
    --output-dir "${OUTPUT_DIR}"
}

run_corpus() {
  python "${SCRIPT_DIR}/evaluate-mwb-corpus.py" \
    --corpus-dir "${CORPUS_DIR}" \
    --sis-binary "${SIS_BINARY}" \
    --output-dir "${OUTPUT_DIR}"
}

run_batch &
BATCH_PID=$!

run_corpus &
CORPUS_PID=$!

wait "${BATCH_PID}" "${CORPUS_PID}"
