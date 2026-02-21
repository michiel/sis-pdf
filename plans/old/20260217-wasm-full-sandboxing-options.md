# WASM Full Sandboxing Options Plan

Date: 2026-02-17  
Status: Planned  
Scope: `crates/sis-pdf-gui`, `crates/sis-pdf-detectors`, JS sandbox runtime wiring, web deployment/runtime constraints

## Objective

Enable efficient full dynamic sandboxing for the WASM GUI (JS sandbox, dynamic image analysis, dynamic font analysis where supported) with strong user experience and sustainable maintenance cost.

This plan evaluates architecture options, rates them across engineering and product criteria, and recommends an execution path.

## Constraints and External Facts

1. Web worker off-main-thread architecture is the primary browser mechanism for keeping UI responsive under heavy compute.
2. True shared-memory multi-threading in browser (for Wasm threads / shared memory patterns) depends on cross-origin isolation (`COOP` + `COEP`) and `crossOriginIsolated` runtime state.
3. Cross-origin isolation increases deployment complexity (resource headers, third-party embedding constraints, CORS/CORP tuning).
4. Module/classic worker behaviour and same-origin restrictions require careful bundling and worker asset wiring.

## Evidence Summary

1. Current JS sandbox path is expensive by design (multi-profile, multi-phase runtime emulation).
2. In profiling, `js_sandbox` can contribute a large fraction of scan time for JS-heavy samples.
3. Moving expensive execution off the main thread is likely the highest UX improvement lever.
4. Full Wasm threading (shared memory) is feasible but introduces significant deployment and compatibility work.

## Option Set

### Option A: Keep current WASM single-thread sandbox in main analysis path (baseline)

Description:
- Continue with target-tuned limits (reduced profile set, reduced timeouts, per-document budget).
- No architectural changes.

### Option B: Dedicated Web Worker sandbox executor (single worker, no shared memory)

Description:
- Move dynamic JS sandbox execution to a dedicated worker.
- Main thread handles UI + orchestration only.
- Keep single-worker serial execution initially; maintain current detector semantics.

### Option C: Worker pool sandbox executor (multiple workers, no shared memory)

Description:
- Use a small worker pool (for example 2-4 workers) to evaluate independent payload candidates concurrently.
- Each worker runs its own Wasm instance and receives payload tasks by message passing.
- No SharedArrayBuffer dependency.

### Option D: True Wasm threads (SharedArrayBuffer + cross-origin isolation)

Description:
- Introduce thread-enabled build and runtime using worker-backed shared-memory model.
- Likely requires dual builds (threaded and non-threaded) with runtime feature detection.
- Requires strict deployment headers and resource policy compliance.

### Option E: Hybrid mode (WASM triage + server-side heavy dynamic replay)

Description:
- Browser performs fast local triage and lightweight dynamic checks.
- Heavy multi-profile sandboxing offloaded to backend service when available.

## Rating Matrix

Scale: 1 (poor) to 5 (excellent)

| Option | Ease of implementation | Maintainability | Efficiency/perf | UX responsiveness | Build size/time | Complexity risk | Testability | Deployment burden | Overall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| A: Main-thread tuned only | 5 | 4 | 2 | 2 | 5 | 4 | 4 | 5 | 3.9 |
| B: Single worker executor | 4 | 4 | 3 | 5 | 4 | 3 | 4 | 4 | 3.9 |
| C: Worker pool (no SAB) | 3 | 3 | 4 | 5 | 3 | 3 | 3 | 4 | 3.5 |
| D: True Wasm threads (SAB) | 2 | 2 | 5 | 5 | 2 | 2 | 2 | 1 | 2.6 |
| E: Hybrid server replay | 3 | 3 | 4 | 4 | 4 | 3 | 3 | 2 | 3.3 |

## Option-by-Option Notes

### A: Main-thread tuned only

Pros:
1. Minimal engineering and operational change.
2. Lowest risk of regressions in build/deploy.

Cons:
1. UI can still feel blocked on slower devices.
2. Ceiling on practical dynamic depth remains low.

### B: Single worker executor

Pros:
1. Large UX gain without cross-origin isolation requirements.
2. Clear isolation boundary for sandbox runtime.
3. Good maintainability if worker protocol is small and typed.

Cons:
1. Limited throughput improvement vs pool/threading.
2. Requires careful worker lifecycle/error handling.

### C: Worker pool executor (no SAB)

Pros:
1. Better throughput while preserving broad compatibility.
2. Avoids COOP/COEP operational burden.

Cons:
1. Higher memory and bundle overhead (multiple Wasm instances).
2. Harder scheduling/cancellation/ordering semantics.

### D: True Wasm threads

Pros:
1. Best theoretical throughput and utilisation.
2. Strong long-term path for heavy compute if environment supports it.

Cons:
1. Highest deployment burden (COOP/COEP/CORP/CORS correctness everywhere).
2. Higher compatibility and debugging complexity.
3. Higher CI, test matrix, and packaging complexity (dual builds and feature detection).

### E: Hybrid server replay

Pros:
1. Keeps browser UI smooth.
2. Centralises heavy sandbox capability and updates.

Cons:
1. Requires backend service and trust model.
2. Reduces offline/local-only capability.

## Recommended Strategy

Recommendation: **B -> C -> optional D**

1. Implement Option B first as default architecture for WASM GUI dynamic sandboxing.
2. Add Option C behind configuration once worker protocol and observability are stable.
3. Evaluate Option D only after B/C metrics plateau and deployment environment can guarantee cross-origin isolation reliably.

Rationale:
- Best balance of maintainability, user experience, and delivery speed.
- Avoids committing early to high operational complexity of SharedArrayBuffer threading.
- Preserves a practical path to full-threaded mode later.

## Proposed Phased Execution

### Phase 1: Workerised sandbox orchestration (Option B)

Changes:
1. Add dedicated sandbox worker runtime module for JS dynamic execution.
2. Define typed request/response protocol:
   - request id, payload hash, budget config, profile mode
   - response findings, telemetry, timeout/skip status
3. Move heavy sandbox execution off main UI path; preserve existing finding kinds.
4. Add cancellation and timeout propagation from UI/session lifecycle.

Validation:
1. GUI integration tests for worker startup, message round-trip, timeout, cancellation.
2. Regression tests ensuring finding IDs/metadata parity for representative fixtures.
3. Measure UI responsiveness (interaction latency during scan).

### Phase 2: Worker pool parallelism (Option C)

Changes:
1. Add small bounded worker pool.
2. Schedule by payload candidate with fair queue and global budget.
3. Deduplicate identical payloads by hash before dispatch.
4. Merge results deterministically (stable ordering and provenance metadata).

Validation:
1. Determinism tests across repeated runs.
2. Throughput benchmarks on JS-heavy fixture set.
3. Memory ceiling tests under many candidates.

### Phase 3: Threaded feasibility spike (Option D, optional)

Changes:
1. Add isolated prototype build with thread support and feature detection.
2. Integrate runtime checks:
   - `crossOriginIsolated`
   - wasm threads feature detection
3. Implement graceful fallback to non-threaded worker path.

Validation:
1. End-to-end tests with and without COOP/COEP headers.
2. Bundle/build size tracking.
3. Browser compatibility matrix checks.

## Non-Functional Requirements

1. Deterministic findings output ordering regardless of worker scheduling.
2. Strict resource controls: per-payload timeout, per-document budget, queue limits.
3. Clear user feedback states:
   - queued
   - running
   - timed out
   - skipped (with explicit reason)
4. Comprehensive telemetry for performance and failure diagnosis.

## Test Strategy

1. Unit tests for worker protocol serialisation/deserialisation.
2. Integration tests for cancellation/timeout/budget exhaustion paths.
3. Snapshot tests for finding metadata consistency.
4. WASM-target CI checks for both primary and fallback modes.
5. Performance regression checks on representative JS-heavy fixtures.

## Risks and Mitigations

1. Risk: Worker orchestration bugs create stale or dropped results.
   - Mitigation: request-id correlation, ack/retry-safe state machine, deterministic merge layer.
2. Risk: Worker pool increases memory pressure.
   - Mitigation: low default pool size, adaptive throttling, payload dedupe.
3. Risk: Threaded mode introduces deployment breakage due to COEP/COOP.
   - Mitigation: keep threaded mode optional; default to worker non-SAB path.

## Deliverables

1. Architecture decision record selecting B as default next step.
2. Worker protocol and implementation in GUI runtime.
3. Benchmark report comparing A vs B vs C on selected fixtures.
4. Optional D feasibility report with go/no-go recommendation.

## Sources

1. MDN: `Window.crossOriginIsolated`  
   https://developer.mozilla.org/docs/Web/API/Window/crossOriginIsolated
2. MDN: `Cross-Origin-Embedder-Policy` header  
   https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy
3. MDN: `Worker()` constructor  
   https://developer.mozilla.org/en-US/docs/Web/API/Worker/Worker
4. MDN: Using Web Workers  
   https://developer.mozilla.org/docs/Web/API/Web_Workers_API/Using_web_workers
5. web.dev: Off-main-thread with Web Workers  
   https://web.dev/articles/off-main-thread
6. web.dev: COOP/COEP for cross-origin isolation  
   https://web.dev/articles/coop-coep
7. web.dev: Why cross-origin isolated is needed  
   https://web.dev/articles/why-coop-coep
8. web.dev: Using WebAssembly threads  
   https://web.dev/articles/webassembly-threads
9. wasm-bindgen-rayon (Rust/Web worker threading guidance)  
   https://github.com/RReverser/wasm-bindgen-rayon
