# Plan: Modern JavaScript Pattern Expansion for `js-analysis`

Date: 2026-02-10  
Status: Implemented (Wave 1 + Wave 2 + Wave 3)  
Scope: `crates/js-analysis` dynamic behavioural pattern coverage

## Implementation status update (2026-02-10)

Implemented:

- **Wave 1**
  - `indirect_dynamic_eval_dispatch`
  - `multi_pass_decode_pipeline`
  - `timing_probe_evasion`
  - `capability_matrix_fingerprinting`
- **Wave 2**
  - `covert_beacon_exfil`
  - `prototype_chain_execution_hijack`
  - COM/WSH chain confidence calibration (`calibrate_chain_signal`)

Pending:

- None in the original wave scope. Follow-on work should focus on tuning, benign controls, and profile-depth improvements.

Follow-on status (2026-02-11):

- Implemented additional recommendation patterns:
  - `chunked_data_exfil_pipeline`
  - `interaction_coercion_loop`
  - `lotl_api_chain_execution`
- PR-D completed: expanded `covert_beacon_exfil` URL-feature scoring (`deep_label_domains`, `dense_query_key_urls`, encoded argument markers) with calibrated severity/confidence.
- PR-E completed: expanded prototype/WASM coverage and profile gating:
  - prototype mutation calls and property-write markers are now incorporated with profile-aware thresholds.
  - WASM coverage now includes `instantiateStreaming`, `compileStreaming`, and `WebAssembly.Table` with profile-aware scoring metadata.

## 1) Objective

Expand sandbox detection coverage for modern malware and fraud patterns that are under-represented in the current pattern set, while preserving:

- no unsafe constructs
- bounded runtime behaviour
- deterministic telemetry and reproducibility
- low false-positive rates in benign office/PDF JavaScript

## 2) Current Coverage Snapshot

Current dynamic patterns are strongest in:

- legacy WSH/COM downloader chains
- obfuscation and dynamic code generation
- gating/dormancy and anti-analysis delay/quit behaviour
- telemetry saturation and execution quality signals

Primary gap area: modern post-2019 JavaScript tradecraft seen in browser/PDF hybrid lures and script-stage loaders that avoid classic `XMLHTTP + ADODB + Run` signatures.

## 3) MECE Recommendation Set (New Pattern Families)

## A. Modern Dynamic Code Loading and VM Evasion

### A1. Indirect eval and constructor graph abuse

**Examples**
- `globalThis['ev'+'al'](...)`
- `(0, eval)(...)`
- `[].filter.constructor('...')()`
- `Function('return this')()` plus deferred dispatch

**Why missing now**
- Current patterns focus on direct `eval`/`Function` counts, less on indirection graph semantics.

**Recommendation**
- Add a pattern: `indirect_dynamic_eval_dispatch`.
- Track call-graph edges where callable origin is resolved from property chains, constructor retrieval, or aliasing.

**Countermeasure**
- Add a taint-like tag for function values sourced from `eval`/`Function`/constructor paths.
- Emit high-confidence signal when tagged callables execute code strings.

---

### A2. WASM-assisted loader staging

**Examples**
- `WebAssembly.instantiate`, `WebAssembly.Module`, memory writes then JS trampoline.

**Why missing now**
- No dedicated signal for WASM as a decode/execution intermediary.

**Recommendation**
- Add pattern: `wasm_loader_staging`.

**Countermeasure**
- Instrument WASM API stubs and memory interaction summaries.
- Flag sequence: decode blob -> WASM instantiate -> dynamic JS dispatch.

---

## B. Modern Obfuscation and Deobfuscation Pipelines

### B1. Multi-pass codec chains

**Examples**
- nested `atob`, `decodeURIComponent`, `TextDecoder`, byte-array joins, XOR loops.

**Why missing now**
- String obfuscation currently centres on `fromCharCode` density.

**Recommendation**
- Add pattern: `multi_pass_decode_pipeline`.

**Countermeasure**
- Count ordered decode-transform stages.
- Emit severity based on stage depth + subsequent dynamic execution.

---

### B2. Prototype pollution for execution indirection

**Examples**
- mutation of `Object.prototype`, `Array.prototype`, `Function.prototype` to trigger hidden dispatch.

**Why missing now**
- Property telemetry exists but lacks prototype abuse correlation.

**Recommendation**
- Add pattern: `prototype_chain_execution_hijack`.

**Countermeasure**
- Record writes to core prototype objects.
- Correlate with later call-site behaviour changes.

---

## C. Anti-analysis and Fingerprint Resistance Evasion

### C1. High-resolution timing and jitter validation

**Examples**
- repeated timer probes, monotonicity checks, delta thresholds.

**Why missing now**
- Delay/quit gating is detected, but not timing integrity probes.

**Recommendation**
- Add pattern: `timing_probe_evasion`.

**Countermeasure**
- Track repeated reads of time sources (`Date.now`, `performance.now`) and comparison loops.
- Surface evidence when control flow depends on measured jitter.

---

### C2. Capability matrix probing

**Examples**
- broad probing of `navigator`, `screen`, plugin APIs, PDF viewer/app object variants.

**Why missing now**
- `environment_fingerprinting` is basic and thresholded.

**Recommendation**
- Add pattern: `capability_matrix_fingerprinting`.

**Countermeasure**
- Cluster property probes by domain (browser, PDF reader, OS, Node).
- Escalate confidence when probing spans multiple domains before execution.

---

## D. Modern Exfiltration and Covert Communication

### D1. DNS-over-URL and image/beacon exfil patterns

**Examples**
- high-entropy subdomain beacons, tiny image requests with encoded payloads.

**Why missing now**
- URL capture exists; exfil intent scoring is limited.

**Recommendation**
- Add pattern: `covert_beacon_exfil`.

**Countermeasure**
- Add URL feature extraction in dynamic stage (entropy, label depth, query density).
- Correlate with data marshaling calls just prior to network sinks.

---

### D2. Chunked exfil via storage buffers

**Examples**
- staged chunks in arrays/local state then periodic sends.

**Recommendation**
- Add pattern: `chunked_data_exfil_pipeline`.

**Countermeasure**
- Track repeated encode/append/send cycles over phase boundaries.

---

## E. Social Engineering and User-Interaction Abuse (Modern Lures)

### E1. Modal pressure and coercive workflow loops

**Examples**
- repeated `alert/confirm/prompt` with branching coercion.

**Why missing now**
- Existing dedicated lure coverage can be expanded beyond primitive usage.

**Recommendation**
- Add pattern: `interaction_coercion_loop`.

**Countermeasure**
- Detect repeated user-dialog primitives combined with conditional branching and retry loops.

---

### E2. Phishing form synthesis in script

**Examples**
- dynamic field generation and fake credential prompts in document context.

**Recommendation**
- Add pattern: `credential_harvest_form_emulation`.

**Countermeasure**
- Correlate dynamic UI/form construction with outbound data serialisation.

---

## F. Supply-chain and Dependency Abuse in Scripted Environments

### F1. Runtime package loader abuse (Node-like profiles)

**Examples**
- dynamic `require` path synthesis, fallback module probing.

**Recommendation**
- Add pattern: `runtime_dependency_loader_abuse`.

**Countermeasure**
- Extend profile stubs for Node variants; record unresolved/synthesised module paths.

---

### F2. Living-off-the-land API chains

**Examples**
- benign-seeming host APIs chained into execution or persistence.

**Recommendation**
- Add pattern: `lotl_api_chain_execution`.

**Countermeasure**
- Introduce weighted chain scoring across non-obvious API combinations rather than single API flags.

## 4) Prioritised Delivery Roadmap

## Wave 1 (highest impact, low/moderate implementation risk)

1. `indirect_dynamic_eval_dispatch`
2. `multi_pass_decode_pipeline`
3. `timing_probe_evasion`
4. `capability_matrix_fingerprinting`

Rationale: broad modern coverage uplift, strong telemetry reuse, minimal profile-surface expansion.

## Wave 2 (moderate/high impact, moderate risk)

1. `covert_beacon_exfil`
2. `com/wsh` chain confidence calibration with sequence scoring
3. `prototype_chain_execution_hijack`

Rationale: improves intent precision and catches evasive obfuscation patterns.

## Wave 3 (high complexity, profile expansion required)

1. `wasm_loader_staging`
2. `runtime_dependency_loader_abuse`
3. `credential_harvest_form_emulation`

Rationale: requires deeper host emulation and larger test corpus support.

## 5) Implementation Guidelines

- Preserve deterministic ordering and replay IDs.
- Keep all telemetry channels bounded; new fields must include truncation accounting.
- Prefer additive metadata over changing existing output keys.
- Use confidence scaling based on chain completeness, not binary triggers.
- Avoid introducing any unsafe Rust or unbounded dynamic structures.

## 6) Test Strategy

For each new pattern:

1. Add focused regression in `crates/js-analysis/tests/dynamic_signals.rs`.
2. Add at least one hostile corpus replay assertion from `tmp/javascript-malware-collection/`.
3. Add one benign-control script to estimate false-positive pressure.
4. Run:
   - `cargo test -p js-analysis --features js-sandbox --test dynamic_signals`
   - periodic random sweep scripts over yearly malware buckets.

## 7) Success Metrics

- Reduction in “executed suspicious/no-pattern” rate in sweep reports.
- Increased chain completeness confidence for dynamic findings.
- Stable or reduced timeout/telemetry-saturation rates after additions.
- No regressions in deterministic output contracts.

## 8) Risks and Mitigations

- **Risk**: FP growth from broad pattern matching.  
  **Mitigation**: multi-signal thresholds and confidence gating.

- **Risk**: runtime overhead from deeper instrumentation.  
  **Mitigation**: cap new counters and reuse existing telemetry channels.

- **Risk**: profile drift across environments (PDF/browser/node).  
  **Mitigation**: keep profile-specific expectations explicit and tested.

## 9) Recommended Next PR Sequence

1. PR-A: `indirect_dynamic_eval_dispatch` + tests + corpus replay.
2. PR-B: `multi_pass_decode_pipeline` + tests + confidence calibration.
3. PR-C: `timing_probe_evasion` + `capability_matrix_fingerprinting`.
4. PR-D: `covert_beacon_exfil` URL-feature scoring.
5. PR-E: prototype and WASM expansion (gated behind profile options).
