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

## Fourth sweep (post-recursion/format/downloader finding implementation)

## Scope and sample set

Fourth batch from the next 10 date folders:

1. `tmp/javascript-malware-collection/2017/20170227/20170227_a2d5c059dcbb09d5d9cbd886c8fe7b51.js`
2. `tmp/javascript-malware-collection/2017/20170228/20170228_7b146dc09978b32161ce1fc29f3e020d.js`
3. `tmp/javascript-malware-collection/2017/20170301/20170301_bf55dc97b611f894f3550515d45a4171.js`
4. `tmp/javascript-malware-collection/2017/20170302/20170302_62a7cd7b44ecf34e189522f1484ba399.js`
5. `tmp/javascript-malware-collection/2017/20170303/20170303_7b7ca63d72bfadf876a1800ae472f8f3.js`
6. `tmp/javascript-malware-collection/2017/20170304/20170304_810b89ab9772b0c5f2d1bd8a8963499a.js`
7. `tmp/javascript-malware-collection/2017/20170306/20170306_fbb7e6840238ac85698cc001df13289a.js`
8. `tmp/javascript-malware-collection/2017/20170307/20170307_516de46e8268c371b74375013046d3ef.js`
9. `tmp/javascript-malware-collection/2017/20170309/20170309_053a4cc9b14ac1233ee7401b1621a0c8.js`
10. `tmp/javascript-malware-collection/2017/20170310/20170310_946474cd9cc88ffed5cf2e12d64b523c.js`

## Results summary

- 10/10 executed.
- 3/10 emitted runtime errors (stable vs third sweep).
- Error signatures converged to:
  - `not a callable function` (3)
- `ActiveXObject` appeared in 4/10 samples.
- `WScript.CreateObject` appeared in 4/10 samples.
- Dynamic-code patterns in 2/10 samples.

## Observed impact of latest changes

- Broad downloader-style chains now execute deeply in this slice:
  - repeated `ActiveXObject/WScript.CreateObject` + `MSXML2.XMLHTTP.open/send` + `ADODB.Stream.*`.
- The new detector-level findings (`js_runtime_downloader_pattern`, `js_runtime_recursion_limit`, `js_payload_non_javascript_format`) are now available for scan workflows to classify these behaviours more explicitly than generic sandbox execution status.
- Remaining failures are now tightly clustered in callable semantics for specific chained object/function returns.

## Updated recommendations (post-fourth sweep)

1. **Callable-return parity (targeted)**
   - Focus on the residual `not a callable function` cluster in samples that already execute deep COM chains.
   - Add targeted return-shape fixtures derived from 20170227/20170309 patterns.

2. **Promote downloader-loop finding in triage defaults**
   - Given repeated open/send loops observed across this and prior batches, prioritise `js_runtime_downloader_pattern` visibility in operator workflows (query docs/examples and analyst runbooks).

3. **Corpus-scale trend tracking**
   - Continue batched 10-sample stepping and track:
     - runtime-error rate,
     - top emulation buckets,
     - downloader-loop prevalence.
   - Stop criteria for this phase: error rate <20% for two consecutive batches or no new dominant failure class.

## Fifth sweep (post-callable recovery + triage summary refinements)

## Scope and sample set

Fifth batch from the next 10 date folders:

1. `tmp/javascript-malware-collection/2017/20170313/20170313_0cfcad8dd858daef2558235fa4eeda16.js`
2. `tmp/javascript-malware-collection/2017/20170314/20170314_9bb8f3a5628be4329860313e6dbd28ed.js`
3. `tmp/javascript-malware-collection/2017/20170315/20170315_a619b6a40c3be963562cbf54e36b45db.js`
4. `tmp/javascript-malware-collection/2017/20170317/20170317_d46aac8fea73563ed94cea04f50ec2af.js`
5. `tmp/javascript-malware-collection/2017/20170318/20170318_3170ec01a7c33215b9b942e6679208b0.js`
6. `tmp/javascript-malware-collection/2017/20170320/20170320_318f0937aae8425c94f985b30b4b1d75.js`
7. `tmp/javascript-malware-collection/2017/20170321/20170321_1f9962e3782d65de0ca96cc8ea1525a2.js`
8. `tmp/javascript-malware-collection/2017/20170322/20170322_4aef2f2f6b431c204b5f11e4e2b29229.js`
9. `tmp/javascript-malware-collection/2017/20170323/20170323_05a3cc924d4c8c0699f8d72342482e51.js`
10. `tmp/javascript-malware-collection/2017/20170324/20170324_b37b1f0515d8039249fb472ce670c80b.js`

Execution command remained:

- `cargo run -q -p sis-pdf -- sandbox eval <sample>`

## Results summary

- 7/10 executed; 3/10 timed out.
- 2/10 executed samples emitted runtime errors.
- Error buckets were:
  - `not_callable_function` (1)
  - `loop_iteration_limit` (1)
- Repeated downloader-style call chains remain prevalent in executed samples:
  - `WScript.CreateObject` + repeated `MSXML2.XMLHTTP.open/send` observed in 5/10 samples.
- Dynamic code generation was present in 1/10 samples (`eval`).
- Behavioural pattern labels remained concentrated in:
  - `error_recovery_patterns` (2)
  - `variable_promotion_detected` (1)

## Observed impact of latest changes

- The dotted-call recovery refinement appears to reduce hard failure spread: only one executed sample now fails with `not_callable_function` despite deep COM chain use.
- Findings digest extensions (`findings_by_kind`, breakpoint bucket summaries) improve operator visibility for these recurring behaviours without requiring full evidence inspection.
- Remaining instability is now dominated by execution budget limits (timeouts and loop limits), not broad constructor/callability collapse.

## Updated recommendations (post-fifth sweep)

1. **Timeout and loop-budget telemetry split**
   - Separate timeout root causes in telemetry/findings (`script_timeout` versus `loop_iteration_limit`) with per-sample counters.
   - Surface both in batch-level summaries so execution-budget pressure is immediately visible.

2. **Focused scheduler hardening for long-loop downloaders**
   - Add a bounded yield/checkpoint strategy for repeated `CreateObject` + `XMLHTTP` loops so benign high-iteration emulation paths are less likely to terminate early.
   - Preserve strict limits and no-unsafe constraints.

3. **Promote timeout-aware confidence adjustments**
   - When execution times out before behavioural completion, reduce confidence for intent findings that rely on partial dynamic traces.
   - Keep severity driven by observed high-risk signals (for example downloader cadence) while marking confidence degradation explicitly.

4. **Continue rolling 10-sample sweeps with stop criteria**
   - Track timeout rate and loop-limit rate as first-class regression metrics.
   - Stop this hardening stream when two consecutive batches achieve:
     - timeout rate <=10%
     - runtime error rate <=20%
     - no new dominant breakpoint class.

## Sixth sweep (post-timeout/loop telemetry hardening)

## Scope and sample set

Sixth batch from the next 10 date folders:

1. `tmp/javascript-malware-collection/2017/20170325/20170325_5aa6ec4dad24f98b7652224a9d65afb2.js`
2. `tmp/javascript-malware-collection/2017/20170327/20170327_10a99df98343965846c40c89c3f6327f.js`
3. `tmp/javascript-malware-collection/2017/20170331/20170331_3e38dd52734be11f4c47ab5128f493be.js`
4. `tmp/javascript-malware-collection/2017/20170401/20170401_6488b5fc036553fdad166bc1f6ab2b77.js`
5. `tmp/javascript-malware-collection/2017/20170402/20170402_620f42a48c2375d42e73510482873a8b.js`
6. `tmp/javascript-malware-collection/2017/20170403/20170403_5cc0758c10bcfc404fa32b99af73bcee.js`
7. `tmp/javascript-malware-collection/2017/20170404/20170404_6a2cce2ba0dcee0647a17c28bdfb6999.js`
8. `tmp/javascript-malware-collection/2017/20170407/20170407_dd1a8a2f582254c152a1e68bbc0c7358.js`
9. `tmp/javascript-malware-collection/2017/20170408/20170408_4eafcdb770a1f045af43a9b3d4705acb.js`
10. `tmp/javascript-malware-collection/2017/20170409/20170409_00768c0e28bebe1b12fcfe4f0708b9cd.js`

Execution command remained:

- `cargo run -q -p sis-pdf -- sandbox eval <sample>`

## Results summary

- 9/10 executed; 1/10 timed out; 0 skipped.
- 0/9 executed samples emitted runtime errors.
- Error buckets in this batch:
  - `loop_iteration_limit`: 0
  - `not_callable_function`: 0
  - `recursion_limit`: 0
- Downloader-like cadence remains dominant in executed traces:
  - `MSXML2.XMLHTTP.open`: 35 calls
  - `MSXML2.XMLHTTP.send`: 35 calls
  - `WScript.CreateObject`: present in 7/10 samples
- Dynamic code generation present in 1/10 samples.
- Behavioural pattern labels remained low-noise:
  - `variable_promotion_detected` (1)
  - `error_recovery_patterns` (0)

## Observed impact of latest changes

- Timeout/loop telemetry split is now operational with low-noise output in this slice: no loop-limit bucket pressure and only one top-level timeout.
- Callable/constructor breakpoints were eliminated in this batch, indicating the recent callable and profile-hardening work is reducing emulation-breakpoint churn.
- The downloader-style signal remains highly consistent, so confidence adjustment policy is now the main lever for triage precision rather than additional stub expansion for this segment.

## Updated recommendations (post-sixth sweep)

1. **Timeout root-cause capture for the remaining timeout sample**
   - Add a lightweight timeout context field to `sandbox eval` output and detector metadata (`phase`, `runtime_profile`, elapsed budget ratio) so `20170327`-style timeouts can be triaged without reruns.

2. **Promote downloader confidence when no breakpoint pressure exists**
   - For samples with repeated `CreateObject` + `XMLHTTP.open/send` and zero runtime errors, consider promoting confidence one level (while keeping severity stable) to prioritise likely-active downloader behaviour.

3. **Keep stop-criteria tracking for one more consecutive batch**
   - This batch meets the current thresholds (`timeout rate = 10%`, runtime error rate = 0%).
   - Run one additional 10-sample sweep; if thresholds hold again and no new dominant breakpoint class appears, conclude this hardening phase.

4. **Add corpus-regression assertion for runtime-budget telemetry fields**
   - Add a targeted test that validates presence/shape of `js_runtime_budget` summary keys and batch markdown timeout/loop counters so reporting regressions are caught early.
