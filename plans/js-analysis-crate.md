# Plan: js-analysis crate

## Goals
- Separate JavaScript static analysis (AST parsing, heuristics) and dynamic sandbox profiling from `sis-pdf-detectors`.
- Provide a stable API for extracting JS signals and sandbox observations that can be reused by detectors and reports.
- Reduce coupling between detector wiring and JS analysis implementation.

## Proposed crate layout
- `crates/js-analysis/`
  - `src/lib.rs` (public API)
  - `src/static.rs` (AST + static heuristics)
  - `src/dynamic.rs` (sandbox execution + logging)
  - `src/types.rs` (shared structs + enums)

## Public API (draft)
- `StaticAnalysisOptions` (enable_ast, decode_layers, max_preview_len, ...)
- `DynamicAnalysisOptions` (max_bytes, timeout_ms, limits, api_profile, arg_capture, ...)
- `StaticSignals` (maps + summaries)
- `DynamicSignals` (calls, args, urls/domains, errors, exec_ms, status)
- `analyze_static(bytes, opts) -> StaticSignals`
- `analyze_dynamic(bytes, opts) -> DynamicSignals`

## Migration steps
1) Move AST/static utilities from `crates/sis-pdf-detectors/src/js_signals.rs` into `crates/js-analysis/src/static.rs`.
2) Move sandbox engine from `crates/sis-pdf-detectors/src/js_sandbox.rs` into `crates/js-analysis/src/dynamic.rs`.
3) Keep a thin adapter in `sis-pdf-detectors` that calls `js_analysis::analyze_static/dynamic`.
4) Update feature flags:
   - `js-ast` and `js-sandbox` move to `js-analysis` crate features.
   - `sis-pdf-detectors` depends on `js-analysis` and re-exports feature toggles.
5) Update report wiring to consume `StaticSignals`/`DynamicSignals` outputs.
6) Add focused tests for static and dynamic analysis in `crates/js-analysis/tests/`.

## Open decisions
- Where to store shared URL/domain parsing helpers (likely `js-analysis::types` or `js-analysis::static`).
- How much of the sandbox API profile should be configurable vs hardcoded.
- Whether to support multiple sandbox profiles (Acrobat-only vs extended).

## Risks
- Feature-gating changes may affect build flags and default features.
- Moving types across crates will require updating serde derives and any report serialization.
