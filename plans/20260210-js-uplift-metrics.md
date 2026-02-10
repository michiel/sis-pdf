# JavaScript Sandbox Uplift Metrics (Wave 1–3)

Date: 2026-02-10  
Scope: `js-analysis` dynamic runtime + `sis-pdf-detectors` sandbox finding bridge

## Commands run

```bash
# Focused dynamic regression
cargo test -p js-analysis --features js-sandbox --test dynamic_signals

# Detector integration regression
cargo test -p sis-pdf-detectors --features js-sandbox --test js_sandbox_integration

# Cross-year hostile sweep sample (2015/2016/2017)
find tmp/javascript-malware-collection/2015 tmp/javascript-malware-collection/2016 tmp/javascript-malware-collection/2017 \
  -type f -name '*.js' | shuf -n 300
# each sample executed via:
# cargo run -q -p js-analysis --features js-sandbox --example test_hostile -- <sample.js>
```

## Test status

- `js-analysis` dynamic suite: **60 passed, 0 failed**
- `sis-pdf-detectors` JS sandbox integration suite: **10 passed, 0 failed**

## Sweep summary (n=300)

- Outcomes:
  - `executed`: 201
  - `skipped`: 99
- Unresolved suspicious/no-pattern executions: **2**
- Runtime latency:
  - median: **31 ms**
  - p95: **868 ms**

## Top observed behavioural patterns

- `variable_promotion_detected`: 77
- `dynamic_code_generation`: 50
- `obfuscated_string_construction`: 35
- `multi_pass_decode_pipeline`: 28
- `telemetry_budget_saturation`: 28
- `wsh_environment_gating`: 26
- `com_downloader_staging_chain`: 25
- `dormant_or_gated_execution`: 23
- `com_downloader_network_chain`: 23
- `dormant_marked_small_payload`: 8
- `wsh_com_object_probe`: 8

Additional low-frequency signals include `com_downloader_execution_chain`, `wsh_direct_run_execution`, `timing_probe_evasion`, and `wsh_early_quit_gate`.

## Remaining unresolved samples (for next bucket)

- `tmp/javascript-malware-collection/2016/20160309/20160309_5c9cf35146bfb5613d8b3a30f123ff7c.js`
- `tmp/javascript-malware-collection/2016/20160917/20160917_f9009674c76d0fdeb671b9d50da00ea8.js`

## Notes

- Wave 1–3 patterns are now live in runtime behaviour analysis and surfaced via dedicated detector findings for:
  - `js_runtime_wasm_loader_staging`
  - `js_runtime_dependency_loader_abuse`
  - `js_runtime_credential_harvest`
- COM/WSH chain confidence is calibrated by observed chain completeness.
- Next pass should target the remaining two unresolved samples and add benign-control coverage for any new detector refinements.
