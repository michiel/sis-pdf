# WASM GUI Dynamic Analysis Enablement Plan

Date: 2026-02-17  
Status: Planned  
Scope: `crates/sis-pdf-gui`, `crates/sis-pdf-detectors`, `crates/font-analysis`, WASM build pipeline

## Objective

Enable maximum dynamic analysis capability in the WASM GUI while keeping builds deterministic and safe:

1. Enable dynamic JavaScript sandbox analysis in WASM GUI.
2. Keep dynamic image analysis enabled by default.
3. Close the current blocker preventing dynamic font analysis on WASM.
4. Add tests and CI checks so this does not regress.

## Current State

1. GUI runtime defaults already use deep analysis and dynamic image/font flags.
2. Native GUI builds can enable `js-sandbox` and `font-dynamic` detector features.
3. WASM GUI currently excludes `js-sandbox` feature wiring.
4. `font-dynamic` on WASM fails due to transitive `libz-sys` (via `allsorts -> flate2`) requiring C cross-toolchain/zlib sysroot.

## Constraints

1. No unsafe code.
2. Deterministic resource limits remain mandatory for browser execution.
3. Preserve `wasm32-unknown-unknown` buildability in CI.
4. Do not depend on local `tmp/` fixtures or PII-bearing files.

## Stage 1: Enable Dynamic JS Sandbox For WASM GUI

### Changes

1. Update `crates/sis-pdf-gui/Cargo.toml` target-specific dependency wiring so WASM target includes:
   - `sis-pdf-detectors` with `features = ["js-ast", "js-sandbox"]`.
2. Keep native target using full dynamic set (`js-ast`, `js-sandbox`, `font-dynamic`).
3. Ensure no duplicate dependency declarations cause feature resolution ambiguity.

### Validation

1. `cargo check -p sis-pdf-gui --target wasm32-unknown-unknown`
2. Add/adjust GUI unit test asserting sandbox availability path for WASM-target detector set (feature-gated test).

### Acceptance

1. WASM build includes `JavaScriptSandboxDetector`.
2. GUI reports dynamic JS findings (`js_sandbox_*`, `js_runtime_*`) when relevant payloads are present.

## Stage 2: Confirm And Lock Runtime Dynamic Defaults

### Changes

1. Keep `crates/sis-pdf-gui/src/analysis.rs` defaults at:
   - `deep = true`
   - `font_analysis.dynamic_enabled = true`
   - `image_analysis.dynamic_enabled = true`
2. Retain/extend unit tests around `gui_scan_options()` defaults.

### Validation

1. `cargo test -p sis-pdf-gui --no-default-features analysis::tests::gui_defaults_enable_dynamic_analysis_paths -- --nocapture`

### Acceptance

1. Runtime defaults remain explicit and test-protected.

## Stage 3: Remove WASM Font-Dynamic Build Blocker

### Problem Detail

`font-dynamic` currently pulls `libz-sys` transitively on WASM (`font-analysis -> allsorts -> flate2 -> libz-sys`), which requires non-portable C/zlib toolchain setup.

### Implementation Options

1. Preferred: make font-analysis WASM path pure-Rust for compression/decompression.
   - Replace/feature-gate transitive paths that force `libz-sys` on WASM.
   - Use rust backend alternatives where available.
2. Fallback: introduce explicit target gating so WASM uses a reduced dynamic font path without `allsorts` dependency.
3. Last resort: document and provision cross-toolchain/sysroot for CI and developer environments.

### Planned Changes

1. Audit `crates/font-analysis/Cargo.toml` and transitive features for WASM compatibility.
2. Introduce target-gated dependency/features in `font-analysis` to avoid `libz-sys` on `wasm32`.
3. If full dynamic path is not feasible immediately, add partial dynamic mode with explicit finding metadata indicating reduced coverage.

### Validation

1. `cargo check -p font-analysis --target wasm32-unknown-unknown --features dynamic`
2. `cargo check -p sis-pdf-detectors --target wasm32-unknown-unknown --no-default-features --features js-ast,js-sandbox,font-dynamic`
3. `cargo check -p sis-pdf-gui --target wasm32-unknown-unknown`

### Acceptance

1. WASM builds succeed with `font-dynamic` enabled, or
2. Reduced mode is explicit, documented, and surfaced in findings/report metadata.

## Stage 4: Detection Fidelity And Telemetry Guardrails

### Changes

1. Add reporting metadata indicating dynamic subsystem status in GUI output:
   - JS sandbox executed/skipped + reason.
   - Font dynamic enabled/reduced/unavailable + reason.
   - Image dynamic enabled state.
2. Ensure remediation text remains concrete when dynamic engines are unavailable.

### Validation

1. Add tests in `crates/sis-pdf-core/tests/` or GUI tests validating status metadata presence.

### Acceptance

1. Users can distinguish between "no finding" and "engine unavailable/partially available".

## Stage 5: CI and Regression Protection

### Changes

1. Add WASM CI checks for GUI and detector feature sets:
   - `sis-pdf-gui` wasm check.
   - `sis-pdf-detectors` wasm check with `js-ast,js-sandbox`.
   - optional/conditional check for `font-dynamic` once resolved.
2. Add targeted regression fixture tests for JS sandbox execution in GUI scan pipeline.

### Acceptance

1. Feature drift (sandbox accidentally disabled in WASM) is caught automatically.
2. WASM dynamic capability remains auditable release-to-release.

## Risks and Mitigations

1. Browser runtime cost increase from dynamic JS sandbox.
   - Mitigation: preserve strict time/memory/step limits already used by sandbox options.
2. Font dynamic parity may lag due to dependency ecosystem constraints.
   - Mitigation: staged rollout with explicit reduced-mode reporting.
3. Feature unification in Cargo may unexpectedly enable unsupported paths.
   - Mitigation: strict target-specific dependency declarations and CI matrix checks.

## Deliverables

1. Updated target-specific feature wiring for GUI WASM/native.
2. Runtime default tests for deep + dynamic subsystems.
3. Font-dynamic WASM compatibility patch or reduced-mode fallback with explicit telemetry.
4. CI checks for WASM dynamic analysis feature coverage.
5. Documentation update summarising dynamic capability by target (native vs WASM).
