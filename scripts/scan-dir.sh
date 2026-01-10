#!/usr/bin/env bash
set -xeuo pipefail

BASE_OUT="out"
mkdir -p "${BASE_OUT}/ir/benign" "${BASE_OUT}/ir/malicious"
mkdir -p "${BASE_OUT}/org/benign" "${BASE_OUT}/org/malicious"

scan_dir() {
  local label="$1"
  local src_dir="$2"
  for pdf in "${src_dir}"/*.pdf; do
    [ -e "$pdf" ] || continue
    local name
    name="$(basename "$pdf" .pdf)"
    sis export-ir "$pdf" --format json -o "${BASE_OUT}/ir/${label}/${name}.json"
    sis export-org "$pdf" --format json -o "${BASE_OUT}/org/${label}/${name}.json"
  done
}

scan_dir benign sample-data/2022-min/benign
scan_dir malicious sample-data/2022-min/malicious
