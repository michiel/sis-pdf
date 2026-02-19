# WASM GUI Benchmark Harness

This harness runs browser-side benchmark checks for the WASM GUI analysis worker.

## What it checks

- end-to-end worker roundtrip duration;
- worker execution duration reported by `analysis_worker.js`;
- serialised result size (to detect payload bloat);
- optional JS heap usage snapshot (`performance.memory`, when exposed).

## Fixture classes

- `small`: synthetic minimal PDF.
- `medium`: `crates/sis-pdf-core/tests/fixtures/launch_action.pdf`.
- `large`: `crates/sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf`.
- `adversarial`: generated stream-heavy PDF.

## Run locally

From repository root:

```bash
scripts/run_wasm_gui_bench.sh
```

Or manually:

```bash
cd crates/sis-pdf-gui
trunk build --release
cd ../../scripts/wasm-bench
npm install
npx playwright install --with-deps chromium
node run.mjs
```
