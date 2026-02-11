# JS Analysis Uplift Review

**Scope**: Changes since `5ca094a` across `crates/js-analysis/` and `crates/sis-pdf-detectors/`
**Date**: 2026-02-11
**Stats**: ~10,000 lines changed across 15 files, 47 behavioural patterns, 53 commits

---

## 1. Executive Summary

The uplift introduces multi-profile sandbox execution, 47 behavioural patterns for malware classification, adaptive loop hardening, phase-based telemetry, and profile divergence scoring. The implementation demonstrates strong architectural thinking and comprehensive coverage of COM downloader chains, WSH gating, modern browser primitives, and WASM staging.

Critical issues centre on determinism violations (HashMap iteration order), missing bounds checks on dynamic source construction, profile divergence threshold calibration, and significant test coverage gaps (5 untested patterns, 3% negative test ratio).

---

## 2. Findings Summary

| Severity | Count |
|----------|-------|
| Critical | 5 |
| High | 11 |
| Medium | 16 |
| Low | 10 |

---

## 3. Critical Findings

### C-1: HashMap iteration non-determinism in telemetry

**File**: `dynamic.rs:57, 327`
**Category**: Functional correctness

`SandboxLog.call_counts_by_name` uses `HashMap` and `approx_string_entropy` builds a `HashMap` for character frequency. HashMap iteration order is non-deterministic in Rust, violating the guardrail that output must be deterministic under identical input.

**Fix**: Replace with `BTreeMap` for all maps that feed into output or pattern analysis.

### C-2: Unbounded string accumulation in augmented_source

**File**: `dynamic.rs:3622-3630`
**Category**: Gap

`augmented_source` construction iterates over `dynamic_snippets` without any cumulative size limit. Malicious payloads with extreme dynamic code generation could cause OOM.

**Fix**: Cap at `MAX_AUGMENTED_SOURCE_BYTES` (e.g. 128 KiB) and silently truncate.

### C-3: Profile divergence calculation over-flags consistency

**File**: `js_sandbox.rs:46-67`
**Category**: Functional correctness

`divergence_label` flags a 67% agreement ratio (2/3 profiles) as "divergent". With 3 profiles, any behaviour present in exactly 2 profiles triggers both `seen_present` and `seen_absent`, making "divergent" the most common label. This reduces the diagnostic value of the divergence field and may cause over-demotion of confidence in multi-profile runs.

**Fix**: Widen the consistency band. A ratio above 0.6 should count as "consistent"; only ratios in the 0.2-0.6 range should be "divergent".

### C-4: Five core behavioural patterns have zero test coverage

**File**: `tests/dynamic_signals.rs`
**Category**: Gap

The following patterns have no test:

- `dynamic_code_generation` (primary malware indicator)
- `obfuscated_string_construction` (fromCharCode abuse)
- `environment_fingerprinting` (navigator probing)
- `error_recovery_patterns` (try/catch abuse)
- `variable_promotion_detected` (scope exploitation)

These patterns could silently regress without detection. `dynamic_code_generation` is arguably the single most important pattern for eval/Function-based malware.

### C-5: Negative test coverage is 3% (3 of 78 tests)

**File**: `tests/dynamic_signals.rs`
**Category**: Gap

Only 3 tests verify that benign code does NOT trigger a pattern. Zero benign fixture files exist. For a security tool, false positive regression prevention is as critical as true positive coverage. Without negative tests, any future change could introduce widespread false positives undetected.

---

## 4. High Findings

### H-1: Phase timeout does not stop execution

**File**: `dynamic.rs:3570-3582`
**Category**: Functional correctness

When a phase exceeds `phase_timeout_ms`, the code records an error but continues executing subsequent phases. A single slow phase can monopolise the entire timeout budget, preventing later phases from running.

**Fix**: Break out of the phase loop on phase timeout.

### H-2: Poisoned mutex recovery masks errors

**File**: `dynamic.rs:3725-3743`
**Category**: Functional correctness

When the timeout context mutex is poisoned, the code silently falls back to `budget_ratio: Some(1.0)`. This masks threading failures and produces misleading diagnostic data.

**Fix**: Report mutex poisoning with `phase: Some("mutex_poisoned")` and `budget_ratio: None`.

### H-3: WshEnvironmentGatingPattern inconsistent with calibration model

**File**: `dynamic.rs:2435-2500`
**Category**: Code quality

This pattern uses hardcoded confidence (`0.86` / `0.74`) instead of `calibrate_chain_signal`, unlike all other WSH patterns. This makes confidence behaviour inconsistent and harder to reason about.

**Fix**: Refactor to use `calibrate_chain_signal` with 5 component signals.

### H-4: Component hits double-counting in COM downloader patterns

**File**: `dynamic.rs:2225-2301, 2303-2370, 2372-2433, 2502-2567, 3012-3084`
**Category**: Functional correctness

Multiple COM downloader patterns count compound `has_*` booleans AND their constituent checks in `component_hits`. For example, `has_staging` requires `stream_write > 0 || save_to_file > 0`, and then `stream_write > 0 || save_to_file > 0` appears again as a separate component. This inflates coverage ratios and artificially raises confidence.

**Fix**: Count only atomic signals in `component_hits`, not compound conditions.

### H-5: Severity assignment misaligned for js_runtime_network_intent

**File**: `js_sandbox.rs:1681-1708`
**Category**: Gap (vs AGENTS.md guidance)

Network API invocation uses `Severity::High` as base. Per AGENTS.md, High severity requires "significant threat, potential for serious harm". Plain network intent without confirmed outbound connection or specific malicious payload should be `Severity::Medium`, with promotion by profile consistency.

### H-6: Risky call detection sets are inconsistent

**File**: `js_sandbox.rs:136-142 vs 1605-1616`
**Category**: Functional correctness

Profile divergence scoring checks `eval`, `app.eval`, `event.target.eval`, `Function`, `unescape` for risky calls. The `js_runtime_risky_calls` finding only checks `eval` and `unescape`. This means profile scoring flags calls that don't generate findings, creating an inconsistent risk picture.

**Fix**: Unify into a single `is_risky_call` helper shared by both paths.

### H-7: Missing impact field assignment on all findings

**File**: `js_sandbox.rs` (throughout)
**Category**: Gap

All findings set `impact: None` despite AGENTS.md defining impact levels. Network intent should have `Impact::High`, downloader patterns `Impact::Critical`, timeout `Impact::None`, etc. The field exists but is never populated.

### H-8: Weak assertion quality in tests

**File**: `tests/dynamic_signals.rs` (throughout)
**Category**: Code quality

Tests check only for pattern name presence, not confidence ranges, severity values, evidence content, or metadata completeness. A pattern could report 0.01 confidence and tests would pass.

**Fix**: Assert confidence ranges, severity matches, and key metadata keys for each pattern test.

### H-9: Missing edge case test coverage

**File**: `tests/dynamic_signals.rs`
**Category**: Gap

No tests for: empty payloads, unicode payloads, near-limit payloads, malformed JavaScript, null bytes. Security tools must handle malformed input gracefully; missing edge case tests could hide crashes.

### H-10: Missing confidence level in behavioural mapping

**File**: `js_sandbox.rs:677-688`
**Category**: Functional correctness

`confidence_from_behavioral` maps scores below 0.45 to `Confidence::Weak`. AGENTS.md defines a lower tier below Weak. Very low scores (0.20) should map to the lowest confidence tier, not Weak.

### H-11: Timeout finding severity too low for evasive payloads

**File**: `js_sandbox.rs:539-610`
**Category**: Improvement opportunity

`extend_with_script_timeout_finding` always uses `Severity::Low`. When all profiles time out (`timed_out_count == total()`), this likely indicates anti-analysis evasion and should be `Severity::Medium`.

---

## 5. Medium Findings

### M-1: Floating-point arithmetic in entropy function

**File**: `dynamic.rs:323-339`

`approx_string_entropy` uses `f64` operations that can differ across platforms due to rounding. Entropy thresholds (e.g. `>= 3.4`) could produce different results on different architectures. Document the limitation or use fixed-point approximations.

### M-2: calibrate_chain_signal lacks input validation

**File**: `dynamic.rs:310-321`

No validation that `component_hits <= component_total`. A `debug_assert!` would catch pattern implementation bugs early.

### M-3: No validation that phase_plan is non-empty

**File**: `dynamic.rs:3515-3543`

If the phase plan is empty (theoretically possible), execution silently does nothing. Should return `DynamicOutcome::Skipped` with a clear reason.

### M-4: Dormant source markers use simple substring matching

**File**: `dynamic.rs:3500-3513`

Case-insensitive `contains` matching produces false positives (e.g. `"eval("` in comments) and false negatives (Unicode escapes like `eval\u0028`).

### M-5: Missing mutex failure logging during phase execution

**File**: `dynamic.rs:3545-3565`

`timeout_context_thread.lock()` failures during phase execution are silently ignored with `if let Ok(...)`, losing timeout tracking.

### M-6: Duplicated metadata insertion logic (~190 lines)

**File**: `js_sandbox.rs:1069-1259 vs 1345-1511`

The "no calls" and "has calls" branches duplicate nearly identical metadata population code. Extract a shared `populate_base_metadata` function.

### M-7: Parser dialect mismatch severity too high

**File**: `js_sandbox.rs:892-894`

Dialect mismatches use `Severity::Medium` and `Confidence::Strong`. These are often false positives from unusual but valid JS syntax. Should be `Severity::Low` with `Confidence::Probable`.

### M-8: No test for all-profiles-timeout scenario

**File**: `tests/js_sandbox_integration.rs`

No integration test verifies behaviour when all profiles time out. This is a critical edge case for evasive payloads.

### M-9: No test for Skipped outcome (payload > 256 KiB)

**File**: `tests/js_sandbox_integration.rs`

The `DynamicOutcome::Skipped` path has no integration test. A >256 KiB payload would trigger this.

### M-10: No test for downloader pattern with timeouts

**File**: `tests/js_sandbox_integration.rs`

The confidence demotion logic for `js_runtime_downloader_pattern` under timeout conditions is untested.

### M-11: Hostile payload success threshold too low (70%)

**File**: `tests/hostile_payloads.rs:241-248`

Accepts 30% failure without investigation. For a security tool, 90%+ should be the threshold.

### M-12: Profile contract tests too permissive

**File**: `tests/profile_contracts.rs:258-275`

`browser_profile_missing_pdf_api_has_stable_error_signature` silently returns if no errors. Should assert that cross-profile API access always errors.

### M-13: Phase timeout validation uses wrong bound

**File**: `tests/dynamic_signals.rs:975-977`

Test checks `phase.elapsed_ms <= options.timeout_ms` (total timeout) instead of `options.phase_timeout_ms` (per-phase timeout).

### M-14: Truncation tests check `> 0` not actual boundaries

**File**: `tests/dynamic_signals.rs:1026-1042`

Truncation assertions don't verify that dropped counts match expected values based on known limits.

### M-15: Confidence calibration test is weak

**File**: `tests/dynamic_signals.rs:448-486`

`sandbox_calibrates_downloader_chain_confidence_by_completeness` checks `full_conf > partial_conf` without validating confidence ranges. Scores of 0.01 and 0.009 would pass.

### M-16: Missing unknown pattern fallback

**File**: `js_sandbox.rs:798-807`

`extend_with_behavioral_pattern_findings` silently skips unrecognised patterns. If `js-analysis` adds new patterns, they'll be invisible until the detector is updated.

---

## 6. Low Findings

### L-1: Clone-heavy log access at phase boundaries

**File**: `dynamic.rs:3640-3694`

Final log assembly clones all collections. Profile and optimise if this becomes a bottleneck.

### L-2: Inconsistent spelling: "behavior" vs "behaviour"

**File**: Throughout

Code uses American English ("behavior") while AGENTS.md specifies Australian English ("behaviour"). Struct names (`BehaviorPattern`, `BehaviorSeverity`) are inconsistent with project convention.

### L-3: Missing metadata in WshTimingGatePattern

**File**: `dynamic.rs:2694-2727`

Pattern checks `prop_reads.is_empty()` and `errors.is_empty()` but doesn't include these in metadata.

### L-4: WshSleepOnlyPattern threshold low

**File**: `dynamic.rs:3307-3340`

Triggers on `input_bytes >= 2_048` which could match legitimate delay scripts. Consider raising to 4096 or combining with dormant marker presence.

### L-5: WshEarlyQuitPattern requires dormant markers

**File**: `dynamic.rs:3272-3305`

Won't detect early-quit anti-analysis behaviour without dormant source markers. Consider making markers additive to confidence rather than required.

### L-6: Promote/demote symmetry undocumented

**File**: `js_sandbox.rs:245-285`

`promote_severity`/`demote_severity` ceiling/floor behaviour is not documented.

### L-7: No replay_id negative test

**File**: `tests/dynamic_signals.rs:1011-1022`

Tests replay_id stability for same input but not that it differs for different inputs.

### L-8: No deduplication test for all collections

**File**: `tests/dynamic_signals.rs:1137-1155`

Only tests `prop_writes` deduplication. Should cover `calls`, `domains`, `urls`.

### L-9: Limited fixture variety

**File**: `tests/fixtures/`

12 fixtures covering 9 malware families. No benign fixtures, no modern attack patterns (supply chain, polyglot), no fixture-to-pattern coverage matrix.

### L-10: Non-deterministic phase assertion in delta test

**File**: `tests/dynamic_signals.rs:76-80`

Test accepts any phase for a synchronous `eval` payload. Should assert `"open"` specifically.

---

## 7. Positive Observations

1. **Comprehensive pattern library**: 47 patterns covering COM downloaders, WSH gating, browser primitives, WASM staging, prototype hijacking, and credential harvesting demonstrate deep threat model understanding.

2. **Adaptive loop hardening**: `select_loop_iteration_limit` adapts to payload characteristics (downloader, token decoder, probe, spin-loop, busy-wait) with profile-specific iteration budgets. Excellent defensive engineering.

3. **Multi-profile execution**: Running payloads across PDF Reader, Browser, and Node profiles and scoring divergence is a strong approach to reducing false positives and detecting environment-specific evasion.

4. **Bounded telemetry**: `MAX_RECORDED_CALLS`, `MAX_RECORDED_PROP_READS`, `MAX_RECORDED_ERRORS` with `*_dropped` counters prevent unbounded growth while preserving observability.

5. **Phase-based execution model**: Open/Idle/Click/Form phases with per-phase timeouts and delta tracking allow fine-grained analysis of interaction-gated payloads.

6. **calibrate_chain_signal**: Shared confidence calibration function promotes consistency across patterns and is a good abstraction.

7. **Real-world fixtures**: Hostile payload tests use actual VirusShare malware samples, not synthetic examples.

8. **Emulation breakpoint classification**: Thoughtful bucketing of runtime errors (missing symbols, parser mismatches, recursion limits) enables targeted sandbox improvements.

---

## 8. Recommendations

### Immediate (blocking)

1. Replace all `HashMap` usage in `SandboxLog` and pattern metadata with `BTreeMap` (C-1)
2. Add bounds check to `augmented_source` construction (C-2)
3. Fix profile divergence thresholds (C-3)
4. Add tests for 5 untested patterns (C-4)
5. Add 10+ negative/benign control tests (C-5)

### High priority

6. Fix phase timeout to break execution loop (H-1)
7. Fix poisoned mutex handling (H-2)
8. Fix component_hits double-counting in COM patterns (H-4)
9. Unify risky call detection sets (H-6)
10. Strengthen test assertions to check confidence ranges and severity (H-8)
11. Add edge case tests (empty, unicode, malformed, near-limit) (H-9)

### Medium priority

12. Extract shared metadata population function (M-6)
13. Add integration tests for all-timeout, skipped, and timeout+pattern scenarios (M-8, M-9, M-10)
14. Raise hostile payload success threshold to 90% (M-11)
15. Add `debug_assert!` to `calibrate_chain_signal` (M-2)
16. Document floating-point determinism limitation (M-1)

### Low priority

17. Standardise to Australian English spelling (L-2)
18. Add fixture coverage matrix and benign fixtures (L-9)
19. Strengthen truncation and phase timeout assertions (M-13, M-14)
