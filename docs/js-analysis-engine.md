# JavaScript Sandbox Engine (`js-analysis`)

## Summary (MECE)

The JavaScript sandbox in `crates/js-analysis` is a deterministic, profile-driven dynamic analysis engine designed to execute hostile script fragments with bounded resources and high telemetry quality.

At a high level, the engine is **mutually exclusive and collectively exhaustive (MECE)** across six concerns:

1. **Admission control**: decides whether execution should be attempted.
2. **Execution environment**: constructs a constrained, instrumented runtime.
3. **Runtime orchestration**: executes across staged user-behaviour phases.
4. **Telemetry capture**: records calls, properties, URLs/domains, errors, and truncation.
5. **Behaviour classification**: maps raw telemetry to malware-relevant behavioural patterns.
6. **Outcome contract**: returns structured `Executed`, `Skipped`, or `TimedOut` results.

This decomposition keeps responsibilities non-overlapping while covering the full dynamic pipeline.

---

## Stage Model

The engine flow can be treated as ten stages:

1. **Stage 0: Feature gate and entry contract**
2. **Stage 1: Payload admission and skip classification**
3. **Stage 2: Source normalisation and marker extraction**
4. **Stage 3: Runtime profile and limit configuration**
5. **Stage 4: Stubbed host API registration and deception surface**
6. **Stage 5: Phase planning and orchestration**
7. **Stage 6: Instrumented execution and recovery**
8. **Stage 7: Telemetry reduction and truncation accounting**
9. **Stage 8: Behavioural pattern analysis**
10. **Stage 9: Structured outcome emission**

---

## Detailed Stage Descriptions

## Stage 0: Feature gate and entry contract

**Purpose**
- Ensure the public API is stable irrespective of build feature flags.

**Mechanism**
- `run_sandbox(bytes, options)` is always available.
- With `js-sandbox` feature enabled, full dynamic execution is used.
- Without it, execution is skipped with `reason = "sandbox_unavailable"`.

**Security effect**
- Prevents accidental implicit execution when the sandbox runtime is not compiled in.

---

## Stage 1: Payload admission and skip classification

**Purpose**
- Reject inputs that are unsafe or low-value to execute under configured constraints.

**Mechanism**
- Enforces `DynamicOptions.max_bytes` (default `256 KiB`).
- Performs pre-execution checks for complex token-decoder payloads and oversized classes.
- Emits explicit skip reasons such as:
  - `payload_too_large`
  - `payload_too_large_token_decoder`
  - `complex_token_decoder_payload`

**Security effect**
- Mitigates parser/runtime exhaustion and known decoder-bomb classes.

**Integrity effect**
- Skip outcomes are deterministic and explainable.

---

## Stage 2: Source normalisation and marker extraction

**Purpose**
- Convert noisy/obfuscated source into a stable analysis substrate.

**Mechanism**
- Normalises script bytes before execution.
- Extracts dormant/gating markers used later in behavioural classification.
- Marker families include dynamic execution and host-object cues (for example `eval(`, split/reverse chains, `adodb.`, `activexobject`, `wscript.createobject`, `xmlhttp.open`).

**Security effect**
- Raises visibility into scripts that intentionally avoid observable runtime side-effects.

---

## Stage 3: Runtime profile and limit configuration

**Purpose**
- Emulate expected host environments while retaining strict runtime safety.

**Mechanism**
- Runtime profile tuple: `kind`, `vendor`, `version`, `mode`.
- Defaults to `pdf_reader:adobe:11:compat`.
- Supports phase-level and total timeout budgets (`phase_timeout_ms`, `timeout_ms`).
- Applies loop/recursion/stack controls with adaptive loop-hardening for hostile patterns.

**Security effect**
- Bounds CPU and stack abuse.
- Makes profile-sensitive malware paths observable.

---

## Stage 4: Stubbed host API registration and deception surface

**Purpose**
- Expose malware-relevant host APIs while intercepting and recording behaviour.

**Mechanism**
- Registers document/app/event globals, host objects, dynamic eval wrappers, and fallback handlers.
- Instruments call sites for file/network intent classification (`is_file_call`, `is_network_call`).
- Preserves compatibility shims so hostile scripts progress into observable branches.

**Security effect**
- Maximises behavioural coverage without granting real system/network side-effects.

---

## Stage 5: Phase planning and orchestration

**Purpose**
- Model user and document lifecycle triggers that gate malicious code.

**Mechanism**
- Executes configurable phases (`open`, `idle`, `click`, `form`) in deterministic order.
- Can collapse phase plan for specific hostile scheduler signatures.
- Emits per-phase summaries (`call_count`, `prop_read_count`, `error_count`, `elapsed_ms`).

**Security effect**
- Captures delayed and interaction-gated payloads that single-pass execution misses.

---

## Stage 6: Instrumented execution and recovery

**Purpose**
- Execute hostile JavaScript while preserving telemetry continuity.

**Mechanism**
- Wraps and records function calls, argument previews, property reads/writes/deletes, URLs/domains, and errors.
- Tracks variable promotion events and execution-flow metadata.
- Applies bounded recovery for common hostile failure modes (undefined variables, callable gaps, dotted-call stubbing).

**Security effect**
- Improves branch coverage under obfuscation and anti-analysis breakage.

**Integrity effect**
- Recovery is explicit and auditable via telemetry rather than silent mutation.

---

## Stage 7: Telemetry reduction and truncation accounting

**Purpose**
- Keep outputs bounded and machine-consumable under noisy workloads.

**Mechanism**
- Deduplicates and caps high-cardinality channels (calls, args, URLs, domains, errors).
- Preserves truncation counters (`calls_dropped`, `call_args_dropped`, `urls_dropped`, etc.).
- Produces replay-stable identifiers and deterministic ordering where applicable.

**Security effect**
- Prevents telemetry-based memory blow-up attacks.

**Detection effect**
- Truncation itself is treated as behaviour (`telemetry_budget_saturation`).

---

## Stage 8: Behavioural pattern analysis

**Purpose**
- Convert low-level telemetry into actionable behavioural findings.

**Mechanism**
- Pattern engine emits `name`, `confidence`, `severity`, `evidence`, and metadata.
- Current pattern families include:
  - Obfuscation/dynamic execution:
    - `obfuscated_string_construction`
    - `dynamic_code_generation`
    - `indirect_dynamic_eval_dispatch`
    - `multi_pass_decode_pipeline`
    - `wasm_loader_staging`
    - `runtime_dependency_loader_abuse`
    - `credential_harvest_form_emulation`
    - `environment_fingerprinting`
    - `capability_matrix_fingerprinting`
    - `prototype_chain_execution_hijack`
    - `timing_probe_evasion`
    - `covert_beacon_exfil`
    - `service_worker_persistence_abuse`
    - `webcrypto_key_staging_exfil`
    - `storage_backed_payload_staging`
    - `dynamic_module_graph_evasion`
    - `covert_realtime_channel_abuse`
    - `clipboard_session_hijack_behaviour`
    - `dom_sink_policy_bypass_attempt`
    - `wasm_memory_unpacker_pipeline`
    - `extension_api_abuse_probe`
    - `modern_fingerprint_evasion`
  - Runtime resilience/quality signals:
    - `error_recovery_patterns`
    - `variable_promotion_detected`
    - `telemetry_budget_saturation`
  - Dormancy/gating:
    - `dormant_or_gated_execution`
    - `dormant_marked_small_payload`
    - `wsh_timing_gate`
    - `wsh_early_quit_gate`
    - `wsh_sleep_only_execution`
  - COM/WSH execution chains:
    - `com_downloader_execution_chain`
    - `com_downloader_staging_chain`
    - `com_downloader_network_chain`
    - `com_downloader_direct_execution_chain`
    - `com_downloader_incomplete_network_chain`
    - `com_downloader_incomplete_open_chain`
    - `com_downloader_partial_staging_chain`
    - `com_network_buffer_staging`
    - `com_file_drop_staging`
    - `wsh_direct_run_execution`
    - `wsh_environment_gating`
    - `wsh_com_object_probe`
    - `wsh_filesystem_recon_probe`

**Security effect**
- Produces robust intent-level signals even when full payload completion is blocked.

---

## Stage 9: Structured outcome emission

**Purpose**
- Expose a stable contract to downstream detectors, CLI rendering, and query workflows.

**Mechanism**
- Returns one of:
  - `DynamicOutcome::Executed(Box<DynamicSignals>)`
  - `DynamicOutcome::Skipped { reason, limit, actual }`
  - `DynamicOutcome::TimedOut { timeout_ms, context }`
- `DynamicSignals` includes:
  - replay/runtime identifiers
  - raw telemetry vectors
  - phase summaries
  - delta summary for dynamic-code expansion
  - behavioural patterns
  - execution statistics and hardening counters

**Operational effect**
- Supports deterministic triage, batch analysis, and reproducible replay.

---

## Malware Pattern Classes and Countermeasures (MECE Matrix)

| Malware class | Typical behaviour | Sandbox countermeasure | Output signal class |
|---|---|---|---|
| Obfuscated string builders | High `fromCharCode`, layered concat/split | Instrumented call capture + obfuscation heuristics | Obfuscation patterns |
| Dynamic code loaders | `eval`, `Function`, staged snippets | Eval wrappers, delta extraction, phased execution | Dynamic-code + delta signals |
| Runtime module/bootstrap abuse | `WebAssembly`, `require`, dynamic module loads | Stubbed module surfaces + staged runtime patterning | Loader/staging patterns |
| Credential-harvest emulation | DOM/form probing + submit/exfil attempts | Form/event stubs + behavioural correlation | Credential-harvest patterns |
| Environment probes | Host/property checks, anti-VM gates | Profiled stubs + property telemetry + gating patterns | Fingerprinting/gating patterns |
| COM downloader chains | `XMLHTTP` + `ADODB` + `Run` | COM stub surface + chain classifiers | Downloader chain patterns |
| Partial/incomplete chains | `open`/`send` without terminal stage | Incomplete-chain detectors + confidence scaling | Medium/low-confidence chain patterns |
| Filesystem reconnaissance | `FileSystemObject.GetFile`/exists probes | Recon-specific COM/FSO classifiers | Recon/probe patterns |
| File-drop staging | Stream open/write/save without run | File-stage behavioural classifier | Staging patterns |
| Abort/timing gates | `Sleep`, `Quit`, low-activity stalls | Timing/quit/sleep-only detectors + phase budgets | Gating/abort patterns |
| Telemetry flooding | Excessive repeated calls/args | Hard caps + dropped counters + saturation pattern | Saturation pattern |
| Resource-exhaustion payloads | Huge token decoder loops, pathological loops | Pre-skip checks + loop profile hardening + timeout context | Skip/timeout outcomes |

---

## Detection Robustness and Integrity Guarantees

## Safety boundaries
- No direct execution in host OS context; behaviour is mediated through stubs.
- Hard limits apply to bytes, time, loops, recursion, stack, and telemetry volume.

## Determinism boundaries
- Replay IDs are content/options-derived for stable correlation.
- Phase order and output schema are deterministic under fixed options.

## Explainability boundaries
- Every non-executed path has an explicit skip/timeout reason.
- Behavioural patterns include evidence and metadata, not just labels.

---

## Practical Interpretation Guidance

- Treat **chain-complete patterns** (for example `com_downloader_execution_chain`, `wsh_direct_run_execution`) as high-priority intent.
- Treat **incomplete-chain patterns** as potentially obfuscated or gated behaviour requiring correlation with static signals.
- Treat **loader/bootstrap patterns** (for example `wasm_loader_staging`, `runtime_dependency_loader_abuse`) as strong evidence of staged execution intent.
- Treat **credential-harvest patterns** as user-targeting behaviours requiring high-priority triage.
- Treat **filesystem reconnaissance patterns** (for example `wsh_filesystem_recon_probe`) as pre-execution signal that often precedes staging or evasion.
- Treat **dormant/gating-only patterns** as execution-coverage alerts, not immediate proof of benignity.
- Treat **telemetry saturation** as a confidence qualifier: behaviour likely exceeds observable budget.

---

## Relationship to the wider `sis` pipeline

The sandbox is one layer in the overall JavaScript analysis stack:

1. Static extraction and decoding identify JavaScript material.
2. Dynamic sandbox execution provides runtime telemetry and behavioural patterns.
3. Higher-level detectors correlate static and dynamic evidence into user-facing findings.

This separation keeps the sandbox focused on bounded execution and telemetry integrity while allowing detector logic to evolve independently.
