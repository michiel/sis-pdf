# JavaScript Sandbox Modern Pattern Roadmap

Date: 2026-02-11  
Status: Proposed  
Owner: `js-analysis` + `sis-pdf-detectors`

## 1. Objective

Add modern JavaScript malware behaviour coverage to the dynamic sandbox and detector bridge, with:

- Strong integrity guarantees (deterministic, bounded, auditable outcomes).
- No unsafe constructs and no privileged host side-effects.
- Clear severity/impact/confidence defaults aligned with project metadata guidance.
- Production-ready test coverage (unit + integration + corpus sweeps).

## 2. In scope

The following new behaviour families are in scope:

1. Service worker persistence abuse
2. WebCrypto key theft/staging
3. Client-side storage staging chains
4. Dynamic `import()`/module graph evasion
5. WebSocket/WebRTC covert channels
6. Clipboard/session hijack behaviour
7. CSP/Trusted Types bypass attempts
8. WASM memory unpacker pipelines
9. Browser extension/runtime API abuse probes
10. Modern anti-analysis fingerprinting (UA-CH, WebGL, AudioContext, permissions)

## 3. Design constraints

- Keep sandbox execution bounded by existing budgets (`timeout`, loop, recursion, stack, telemetry caps).
- Extend stub surfaces only with deterministic, side-effect-free mocks.
- Emit explainable evidence and metadata for every new pattern.
- Prefer additive changes to existing pattern engine and detector bridge.
- Preserve backwards compatibility for `sis query` output fields.

## 4. Pattern specification (detector-ready)

Each row defines runtime pattern name, detector finding kind, default metadata, and minimal signal criteria.

| Runtime pattern | Detector finding kind | Default severity | Default impact | Default confidence | Minimum runtime signal |
|---|---|---|---|---|---|
| `service_worker_persistence_abuse` | `js_runtime_service_worker_persistence` | High | High | Probable | `serviceWorker.register` plus cache/update/activation management sequence |
| `webcrypto_key_staging_exfil` | `js_runtime_webcrypto_key_staging` | High | High | Probable | `crypto.subtle` key generation/import with export and outbound channel attempt |
| `storage_backed_payload_staging` | `js_runtime_storage_payload_staging` | Medium | Medium | Probable | payload-like blobs written to `indexedDB`/`localStorage` then executed/decoded |
| `dynamic_module_graph_evasion` | `js_runtime_dynamic_module_evasion` | Medium | Medium | Probable | repeated `import()`/loader fallback chain with computed module specifiers |
| `covert_realtime_channel_abuse` | `js_runtime_realtime_channel_abuse` | High | High | Probable | suspicious `WebSocket` or `RTCDataChannel` setup with encoded payload transfer |
| `clipboard_session_hijack_behaviour` | `js_runtime_clipboard_session_hijack` | High | High | Probable | clipboard read/write or token/form interception tied to exfil/eval chain |
| `dom_sink_policy_bypass_attempt` | `js_runtime_dom_policy_bypass` | Medium | Medium | Probable | unsafe DOM sink (`innerHTML`, script URL sink) with obfuscated source path |
| `wasm_memory_unpacker_pipeline` | `js_runtime_wasm_memory_unpacker` | High | High | Strong | WASM instantiate + high-entropy buffer transform + dynamic dispatch/eval |
| `extension_api_abuse_probe` | `js_runtime_extension_api_abuse` | Medium | Low | Tentative | `chrome.runtime`/`browser.*` privilege probing with command/message chaining |
| `modern_fingerprint_evasion` | `js_runtime_modern_fingerprint_evasion` | Medium | Medium | Probable | combined UA-CH/WebGL/AudioContext/permissions probing with gating logic |

## 5. Telemetry and stub additions required

## 5.1 New call/property surfaces

- `navigator.serviceWorker.*`
- `caches.*`, `CacheStorage.*`
- `crypto.subtle.*`
- `indexedDB.*`, `IDB*` minimal API path
- dynamic `import()` tracking hook
- `WebSocket.*`, `RTCPeerConnection`, `RTCDataChannel.*`
- `navigator.clipboard.*`
- `trustedTypes.*`, DOM sink wrappers (`innerHTML`, `outerHTML`, `insertAdjacentHTML`)
- `WebAssembly.Memory`, `WebAssembly.Table` access tracking
- `chrome.runtime.*`, `chrome.storage.*`, `browser.*`
- `navigator.userAgentData.*`, `permissions.query`, WebGL and Audio fingerprint APIs

## 5.2 Metadata keys (normalised)

Emit structured keys under `js.runtime.*`, including:

- `js.runtime.pattern.<name>.trigger_count`
- `js.runtime.pattern.<name>.critical_calls`
- `js.runtime.pattern.<name>.phase_span`
- `js.runtime.pattern.<name>.channel_count`
- `js.runtime.pattern.<name>.entropy_hint`
- `js.runtime.pattern.<name>.gating_signals`

## 6. Confidence and severity calibration rules

Use the existing chain-calibration model, extended with pattern-specific component counts:

- Promote confidence when independent components are observed across phases.
- Demote confidence when critical links are inferred but not directly observed.
- Promote severity when execution-capable sinks are reached (`eval`, direct execution, privileged API path).
- Cap confidence at `Tentative` for pure probing patterns unless chained with a second malicious behaviour class.

## 7. PR-sized execution milestones

## PR-1: Service worker + storage

- Add stubs/telemetry for service worker and storage APIs.
- Implement:
  - `service_worker_persistence_abuse`
  - `storage_backed_payload_staging`
- Add tests:
  - `crates/js-analysis/tests/dynamic_signals.rs` positive/negative cases.
  - detector mapping tests in `crates/sis-pdf-detectors/tests/js_sandbox_integration.rs`.

## PR-2: WebCrypto + realtime channels

- Add `crypto.subtle` and WebSocket/WebRTC telemetry.
- Implement:
  - `webcrypto_key_staging_exfil`
  - `covert_realtime_channel_abuse`
- Add confidence calibration tests for complete vs incomplete exfil chains.

## PR-3: Dynamic module and DOM policy bypass

- Add dynamic import tracer and sink wrappers.
- Implement:
  - `dynamic_module_graph_evasion`
  - `dom_sink_policy_bypass_attempt`
- Add replay stability and truncation-behaviour tests.

## PR-4: WASM unpackers and extension API abuse

- Extend WASM runtime tracing (memory/table operations).
- Add extension API probe stubs and telemetry.
- Implement:
  - `wasm_memory_unpacker_pipeline`
  - `extension_api_abuse_probe`
- Add detector finding documentation updates in `docs/findings.md`.

## PR-5: Modern fingerprinting and correlation hardening

- Add UA-CH/WebGL/Audio/permissions instrumentation.
- Implement:
  - `modern_fingerprint_evasion`
- Add cross-pattern correlation rule:
  - fingerprinting + gating + payload staging => confidence uplift.

## PR-6: Corpus validation and tuning

- Run multi-year malware sweeps across `tmp/javascript-malware-collection/`.
- Record unresolved buckets and false-positive candidates.
- Tune thresholds and confidence floors.
- Update:
  - `plans/20260210-js-uplift-metrics.md`
  - `docs/js-analysis-engine.md`
  - `docs/agent-query-guide.md` (new query examples).

## 8. Testing strategy

Minimum required coverage per new pattern:

- 1 positive unit test (pattern should fire).
- 1 benign control test (pattern should not fire).
- 1 degraded-chain test (reduced confidence/severity expected).
- 1 detector integration test (finding emitted with expected metadata).

Batch validation:

- 2 × random 10-sample sweeps from different yearly directories.
- 1 targeted replay on unresolved bucket samples after each PR.

## 9. Security and integrity acceptance criteria

- No `unsafe` and no `unwrap` usage.
- No outbound network or filesystem side-effects from stubs.
- Deterministic output for identical input/options across repeated runs.
- All new findings include object references where available and non-duplicated evidence.
- No regression in existing sandbox tests and detector integration tests.

## 10. Rollout and risk controls

- Feature-flag guard for any high-surface API additions if needed.
- Land detector mappings in same PR as runtime patterns to avoid telemetry-only blind spots.
- Keep thresholds conservative for probe-only patterns to control false positives.
- Track unresolved bucket count as primary uplift KPI.

## 11. Deliverables checklist

- [ ] Runtime patterns implemented (10/10)
- [ ] Detector mappings added (10/10)
- [ ] Findings documentation updated
- [ ] Query guide updated with examples
- [ ] Corpus sweep results documented
- [ ] Unresolved bucket count reduced vs baseline
