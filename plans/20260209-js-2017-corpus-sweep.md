# 2017 JavaScript malware corpus sweep (10-sample nested directory run)

## Scope

This report captures a targeted run of the current JS dynamic tooling against 10 samples selected from distinct subdirectories under:

- `tmp/javascript-malware-collection/2017/`

The goal is to identify concrete opportunities to improve detection quality, emulation fidelity, and triage output quality.

## Sample selection

One sample was selected per date subdirectory (first lexicographic file per folder), giving 10 files:

1. `tmp/javascript-malware-collection/2017/20170110/20170110_9330ee612a9027120543d6cd601cda83.js`
2. `tmp/javascript-malware-collection/2017/20170111/20170111_696bc89689693a74e35a10b747d095bf.js`
3. `tmp/javascript-malware-collection/2017/20170116/20170116_8a698d85797d59c1965997718b070c25.js`
4. `tmp/javascript-malware-collection/2017/20170117/20170117_027a6bae8d394da269a4ca68842b0139.js`
5. `tmp/javascript-malware-collection/2017/20170118/20170118_197838f7e8c96c91ac764b554e2d9d06.js`
6. `tmp/javascript-malware-collection/2017/20170119/20170119_1954ad79e35cc13f0f0643a3cbaf2c60.js`
7. `tmp/javascript-malware-collection/2017/20170122/20170122_38f3734379c19b7bfbb48e9f6ed4ca84.js`
8. `tmp/javascript-malware-collection/2017/20170123/20170123_4aad32dfd7247be7d04717e90dc5d2c5.js`
9. `tmp/javascript-malware-collection/2017/20170124/20170124_0ec4b612cc379bb036cc05d4ca24fc3b.js`
10. `tmp/javascript-malware-collection/2017/20170125/20170125_41de50a7449d34cf6ccc3bd1d4467095.js`

## Execution method

Each sample was run with:

- `cargo run -q -p sis-pdf -- sandbox eval <sample>`

Collected fields included status, call telemetry, dynamic code markers, behavioural pattern labels, and first runtime error signature.

## High-level results

- 10/10 executed (no timeouts/skips).
- 7/10 produced runtime errors.
- 7/10 invoked `WScript.CreateObject` (heavy WSH-family prevalence).
- 5/10 showed dynamic code pathways (`eval`/`Function`).
- Frequent behavioural labels:
  - `error_recovery_patterns`: 7
  - `dynamic_code_generation`: 3
  - `variable_promotion_detected`: 2

Most common error signatures:

- `not a callable function` (3)
- `cannot convert 'null' or 'undefined' to object` (2)
- `not a constructor` (1)
- parse error: `expected token '(', got '.' in function declaration` (1)

## Sample-level observations

- 20170117/20170119/20170122 variants hit `Function` and then fail with `not a callable function`; this strongly suggests partially implemented callable-return contracts in COM/WSH stubs or chained object graph methods.
- 20170123/20170124 variants repeatedly call `WScript.CreateObject` then fail with undefined-object conversion errors, indicating missing object/property scaffolding after object creation.
- 20170125 variant combines `WScript.CreateObject` and `eval` and fails with `not a constructor`, pointing to constructor semantics mismatch in one or more emulated objects.
- 20170118 fails at parse time (likely dialect or malformed/obfuscated syntax); currently this is only reflected as a generic runtime error path.
- 20170111 executes with no calls or errors, which is a blind spot candidate (payload may require trigger phases, alternate globals, or pre-processing).

## Priority opportunities for improvement

## 1) WSH/COM object model completeness (highest impact)

### Problem

The current environment exposes `WScript.CreateObject`, but many post-creation paths degrade into callability/null-conversion failures.

### Proposed remediation

- Implement richer per-ProgID object contracts for common malware targets:
  - `Scripting.FileSystemObject`
  - `WScript.Shell`
  - `MSXML2.XMLHTTP` / `WinHttp.WinHttpRequest.5.1`
  - `ADODB.Stream`
- Ensure returned object graphs include realistic callable methods and property defaults.
- Add constructor/callable semantics parity where scripts expect `new`/call interchangeability.

### Expected outcome

- Lower emulation-break errors; higher behavioural surface recovery; better intent extraction.

## 2) Error-to-finding mapping for emulator breakpoints

### Problem

High-frequency runtime break signatures are currently telemetry-heavy but triage-light.

### Proposed remediation

- Add/extend a finding class for `js_emulation_breakpoint` with normalised reason buckets:
  - `missing_callable`
  - `missing_constructor`
  - `null_object_conversion`
  - `parser_dialect_mismatch`
- Aggregate repeated identical breaks per sample to avoid noise.
- Attach object/function context when known (`WScript.CreateObject` chain, method name).

### Expected outcome

- Faster analyst triage and clearer distinction between malicious behaviour and emulator limitations.

## 3) Multi-phase trigger expansion for script-only artefacts

### Problem

Some samples show minimal/no behaviour despite likely malicious intent.

### Proposed remediation

- Add optional script-mode phase schedules mirroring the PDF sandbox phases:
  - initial load
  - delayed timer ticks
  - callback flush
- Re-run the same payload across phase bundles and merge telemetry.

### Expected outcome

- Better coverage of staged/deferred payloads and reduced false negatives.

## 4) Parser/dialect resilience channel

### Problem

Parse-level failures (e.g. the 20170118 sample) terminate deeper behaviour collection.

### Proposed remediation

- Introduce a tolerant pre-parse pass for common obfuscation/dialect artefacts (without unsafe execution).
- Record explicit parse anomaly findings with confidence scoring and line/column metadata.
- Optionally fall back to static intent heuristics when dynamic execution cannot start.

### Expected outcome

- Improved coverage of malformed-but-malicious scripts; less silent loss of intent signals.

## 5) Intent scoring upgrades from current telemetry

### Problem

Telemetry already captures calls and patterns, but intent findings remain under-leveraged in WSH-heavy samples.

### Proposed remediation

- Add intent correlation rules combining:
  - `WScript.CreateObject` +
  - dynamic execution (`eval`/`Function`) +
  - downloader/file/system object access
- Raise severity/confidence when multi-signal combinations appear across phases.
- Lower confidence when behaviour is dominated by emulator-break artefacts.

### Expected outcome

- More discriminative malicious intent findings, fewer generic/high-noise alerts.

## Suggested implementation order (PR-sized)

1. Add `js_emulation_breakpoint` finding with normalised buckets and aggregation.
2. Expand WSH/COM stub contracts for four high-frequency ProgIDs plus tests.
3. Add constructor/callable parity tests for common object chains.
4. Add script-mode multi-phase execution option and telemetry merge tests.
5. Add parse anomaly finding + static fallback heuristics for dynamic-start failures.
6. Add intent-correlation rules leveraging WSH + dynamic-code + object access combinations.

## Validation plan

- Re-run this exact 10-sample set after each PR.
- Track:
  - reduction in emulator-break errors,
  - increase in meaningful call telemetry depth,
  - increase in intent-bearing findings with stable confidence.
- Extend the sweep to 50+ samples across 2017 once break-rate improves.
