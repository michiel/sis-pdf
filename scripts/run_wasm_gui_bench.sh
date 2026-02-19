#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

pushd "${repo_root}/crates/sis-pdf-gui" >/dev/null
NO_COLOR=false trunk build --release
popd >/dev/null

pushd "${repo_root}/scripts/wasm-bench" >/dev/null
npm_config_cache=/tmp/sis-npm-cache npm install
PLAYWRIGHT_BROWSERS_PATH=/tmp/sis-playwright npx playwright install --with-deps chromium
popd >/dev/null

PLAYWRIGHT_BROWSERS_PATH=/tmp/sis-playwright node "${repo_root}/scripts/wasm-bench/run.mjs"
