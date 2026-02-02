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

python "${SCRIPT_DIR}/evaluate-mwb-corpus.py" \
  --batch-dir "${BATCH_DIR}" \
  --corpus-dir "${CORPUS_DIR}" \
  --sis-binary "${SIS_BINARY}"
