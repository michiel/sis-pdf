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

## Follow-up sweep (second 10-sample batch, post-implementation)

## Scope and sample set

A second batch of 10 samples was executed from different subdirectories (next 10 date folders):

1. `tmp/javascript-malware-collection/2017/20170126/20170126_2c07ec12e87a9d0b4cc8a8ab472e1873.js`
2. `tmp/javascript-malware-collection/2017/20170127/20170127_ac02f835cc57f3f58c788eb66d607275.js`
3. `tmp/javascript-malware-collection/2017/20170128/20170128_b3e5c2afec9a727eb35b69af3b097033.js`
4. `tmp/javascript-malware-collection/2017/20170130/20170130_27d82dc4bb8bcaf513c17c3acddba8f5.js`
5. `tmp/javascript-malware-collection/2017/20170131/20170131_55550f61aa88d3e875498fd6c5f3a790.js`
6. `tmp/javascript-malware-collection/2017/20170202/20170202_fd62ce23cc6f4d5aa5f37369d7be95af.js`
7. `tmp/javascript-malware-collection/2017/20170203/20170203_671786823d3f486e8e6c55a5371cfe3b.js`
8. `tmp/javascript-malware-collection/2017/20170206/20170206_07542265c4814fc1988ce537ba2c9255.js`
9. `tmp/javascript-malware-collection/2017/20170210/20170210_9014940ebd231f4efcc6a7a811a634d6.js`
10. `tmp/javascript-malware-collection/2017/20170211/20170211_667febed1c61ab169a6677e164d62e5a.js`

Execution command remained:

- `cargo run -q -p sis-pdf -- sandbox eval <sample>`

## Results summary

- 10/10 executed.
- 8/10 produced runtime errors.
- 3/10 exercised `WScript.CreateObject`.
- 3/10 showed dynamic code generation.
- Dominant error buckets:
  - `not a constructor` (5)
  - `not a callable function` (3)

Behavioural pattern labels observed:

- `error_recovery_patterns` (8)
- `dynamic_code_generation` (3)
- `obfuscated_string_construction` (2)

## What improved

- COM factory refinement now recovers deeper behaviour before breakpointing in at least one loader-like sample:
  - `20170127_ac02f835cc57f3f58c788eb66d607275.js`
  - observed chained calls include `Scripting.FileSystemObject.GetSpecialFolder`, `MSXML2.XMLHTTP.open/send`, and `ADODB.Stream.Open/Write/SaveToFile/Close`.
- This indicates the newer ProgID-aware stubs are enabling materially better intent recovery than single-call `CreateObject` telemetry alone.

## Remaining gaps

1. **Constructor semantics mismatch remains common**
   - `not a constructor` is now the dominant failure mode.
   - Likely causes include missing constructor-compatible emulation for selected built-ins and malware-specific helper objects.

2. **Callable-return contract gaps still present**
   - `not a callable function` persists in staged samples using `Function` and COM return objects.
   - Some methods likely need callable returns or function-valued properties rather than plain objects/undefined.

3. **Sparse environment globals for script-host payloads**
   - `print` appears in call telemetry for one sample, suggesting host-specific global surface assumptions still vary.

## Updated recommendations (priority)

1. **Add constructor parity layer (PR next)**
   - Extend emulation with constructor-safe wrappers for high-frequency host objects and selected built-ins used by obfuscated loaders.
   - Include dedicated tests for `new` versus direct-call compatibility.

2. **Refine callable-return contracts**
   - For COM-heavy paths (`XMLHTTP`, `ADODB.Stream`, `WScript.Shell`, FSO), return object graphs that preserve expected method/property callability through second-order chaining.
   - Add targeted regression fixtures for the 20170127/20170202/20170203 patterns.

3. **Expand script-host globals minimally and safely**
   - Add low-risk host aliases (for example `print`) as monitored stubs to reduce avoidable breakpoints while keeping strict bounds.

4. **Promote `js_emulation_breakpoint` aggregation in reporting workflows**
   - Use the new bucket metadata to prioritise emulator hardening work by frequency and exploit-family clustering.
   - Report top breakpoint buckets in batch summaries.

## Third sweep (next 10-sample batch, post-hardening repeat)

## Scope and sample set

Third batch from the next 10 date folders:

1. `tmp/javascript-malware-collection/2017/20170214/20170214_02e6a11e1d35346f3754991bff75a0a4.js`
2. `tmp/javascript-malware-collection/2017/20170215/20170215_3d8e5cd536caf13bd53f1015809f93c6.js`
3. `tmp/javascript-malware-collection/2017/20170216/20170216_d6c0f10fe507f03db2ca546c3a42ae2f.js`
4. `tmp/javascript-malware-collection/2017/20170218/20170218_2d2f63d8f4470e88e509c59119635bd9.js`
5. `tmp/javascript-malware-collection/2017/20170219/20170219_2eb997fab8dc4151b2a936fc513fbc07.js`
6. `tmp/javascript-malware-collection/2017/20170220/20170220_56d677774c137373f7e9eb5e30e9ab91.js`
7. `tmp/javascript-malware-collection/2017/20170221/20170221_1486c6103e734fdbafde9c8f93618d03.js`
8. `tmp/javascript-malware-collection/2017/20170222/20170222_8971850d582ef58c23e954503d21f321.js`
9. `tmp/javascript-malware-collection/2017/20170223/20170223_2f30562531561e4a1e6eeeaddcb73781.js`
10. `tmp/javascript-malware-collection/2017/20170225/20170225_3557e92ea687a0986e58b05d7751da70.js`

## Results summary

- 10/10 executed.
- 3/10 emitted runtime errors (improved from 8/10 in the second sweep batch).
- 0/10 used `WScript.CreateObject` directly; this batch is mostly `ActiveXObject`/`XMLHTTP`-leaning.
- 2/10 exhibited dynamic code generation.
- Dominant error signatures shifted to:
  - `exceeded maximum number of recursive calls` (2)
  - `unexpected token '<', primary expression at line 1, col 1` (1)

## Notable changes vs previous sweeps

- Constructor/callable COM hardening appears effective for this segment:
  - repeated `ActiveXObject -> MSXML2.XMLHTTP.open/send` chains now execute without the earlier `not a constructor` / `not a callable function` dominance.
- Error profile moved from **emulation shape mismatch** to **runtime limit / parser format mismatch**.
- This is a positive shift: failures are now concentrated in two more tractable classes.

## Updated recommendations (post-third sweep)

1. **Add explicit recursion-depth telemetry + finding linkage**
   - Current runtime captures the recursion error text, but we should expose a dedicated `js_runtime_recursion_limit`/`js_emulation_breakpoint` bucket enrichment with depth counters when available.
   - This helps distinguish adversarial recursion bombs from benign deep utility code.

2. **Add script-format pre-classification before sandbox execution**
   - The `<` token parse failure indicates HTML/markup-like or non-JS container content entering the JS sandbox path.
   - Add a light pre-check (for leading markup signatures and MIME/extension hints) and emit a dedicated parse-format finding instead of only runtime parser failure.

3. **Keep strengthening `ActiveXObject` network chain intent extraction**
   - Even when execution succeeds, many samples repeatedly call `MSXML2.XMLHTTP.open/send`.
   - Add/raise intent scoring when repeated request loops occur with object-creation cadence consistent with downloader logic.

4. **Batch reporting**
   - Continue surfacing top emulation-breakpoint buckets in batch summaries (now implemented) and track trend lines across corpus slices.
