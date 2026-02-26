# Remaining Work: Consistency Review Implementation
**Source**: `reviews/20260226-comprehensive-codebase-review.md`
**Branch**: `feature/consistency`
**Last commit**: `bbeac47` — All priority 1–5 items complete
**Date**: 2026-02-26

---

## What Was Completed

| Stage | Items | Commit |
|---|---|---|
| 1 (Data model) | 1.1 meta_keys.rs, 1.2 typed accessors, 1.3 remove position field, 1.4 Impact::Unknown variant, 1.7 risk_score doc | c691d44 |
| 1 (Data model) | 1.4 make impact non-optional (field + serde default + mass-replace), 1.6 chain ID validation | bd8f1fe |
| 2 (Docs) | ARCHITECTURE.md rewrite, AGENTS.md Heuristic level, --fast/--deep help + conflict | c691d44 |
| 3 (Safety) | 3.1 shadow_attacks depth guard, 3.4 stable cache hash, 3.5 low_completeness annotation | c691d44 |
| 3 (Safety) | 3.2 AcroForm widget depth cap, 3.3 Do operator depth tracking | bd8f1fe |
| 4 (Detection) | 4.2 UNC/NTLM path detection (`has_unc_path` + `uri_unc_path_ntlm_risk` finding) | 96ef305 |
| 4 (Detection) | 4.3 Intent ↔ chain score feedback (runner.rs boost pass) | b07499c |
| 4 (Detection) | 4.1 XFA script forwarding to JS analysis (deep mode, `xfa_js.*` findings) | 0dc568f |
| 4 (Detection) | 4.4 Evasion regression tests (entropy pad, low completeness, UNC submit) | bbeac47 |
| 5 (Consolidation) | 5.1 ObjProvenance::label(), 5.2 entropy.rs, 5.3 resolve_dict consolidation, 5.4 graph_walk depth guard | c691d44, bd8f1fe |
| 6 (Interfaces) | 6.1 record_type on Report/BatchEntry, 6.2 BatchError struct, 6.3 --fast conflicts_with | c691d44 |
| 7 (CLI tests) | cli_integration.rs with 6 tests, AGENTS.md documentation | c691d44, bd8f1fe |

Bug fixes applied along the way:
- `sis-pdf-gui/src/panels/detail.rs`: `Impact` is no longer `Option<Impact>` (96ef305)
- `docs/findings-schema.json`: added `"Unknown"` to impact enum (b07499c)

All tests pass. One pre-existing flaky failure (`sandbox_suppresses_runtime_limit_for_sentinel_spin_with_wsh_calls` in `js-analysis`) is timing-related and unrelated.

---

## Remaining Items

### Item 1.5 — Reconcile action field duplication
**Priority**: Cleanup / correctness (no behaviour change)
**Files**: `crates/sis-pdf-core/src/chain_synth.rs`, `crates/sis-pdf-core/src/intent.rs`, multiple detector files in `crates/sis-pdf-detectors/src/`

**Context**: `Finding` has typed fields `action_type`, `action_target`, `action_initiation`. Several detectors also insert `meta["action.s"]` (action subtype string) which duplicates `action_type`. This creates redundancy and inconsistency.

**Current state** (verified by `grep -r '"action\.s"' crates/`):
- `lib.rs:4295` and `lib.rs:6916` insert `meta["action.s"]` alongside `finding.action_type`
- `chain_synth.rs:579` reads `f.meta.get("action.s")` to populate chain notes
- `chain_synth.rs:854` reads `f.meta.get("action.s")` for scoring
- `intent.rs:72` checks `f.meta.contains_key("action.s")`
- `yara.rs:144`, `report.rs:1499`, `report.rs:1574`, `report.rs:3351` read `meta["action.s"]`
- `correlation.rs:1329` checks `meta.contains_key("action.s")`

**Task** (do in this order to avoid compile breaks):
1. In `chain_synth.rs:notes_from_findings()` (around line 543), after the meta loop, add a fallback: if no `action.type` note set yet, read `f.action_type` directly.
2. In `intent.rs`, change `f.meta.contains_key("action.s")` to also check `f.action_type.is_some()`.
3. In `yara.rs`, `report.rs`, `correlation.rs`: add fallback reads from `f.action_type` when `meta["action.s"]` is absent.
4. Only after all readers are dual-reading: remove `meta.insert("action.s", ...)` from `lib.rs:4295` and `lib.rs:6916`.

**Do NOT** remove `meta_keys::ACTION_S` from meta_keys.rs — it may still be used by external consumers or tests.

**Success**: `cargo test` passes; `grep -r 'meta.insert.*"action\.s"' crates/` returns zero results.

---

### Items 8.1–8.3 — GUI bidirectional navigation
**Priority**: Feature work (user-visible)
**Branch**: `feature/consistency` (implement here or in a new branch off it)

Before starting, read these files to understand state management:
- `crates/sis-pdf-gui/src/app.rs` — `SisApp` struct and `update()` method
- `crates/sis-pdf-gui/src/workspace.rs` — `Workspace` type (holds `report`)
- `crates/sis-pdf-gui/src/panels/findings.rs` — finding list panel
- `crates/sis-pdf-gui/src/panels/chains.rs` — chain list panel

#### 8.1 — Finding → chain navigation
**Task**:
1. Add to `SisApp`: `chains_for_selected_finding: Vec<usize>` and `scroll_to_chain: Option<usize>`.
2. Recompute `chains_for_selected_finding` whenever `selected_finding` changes: find all chain indices where `chain.findings.contains(&selected_finding_id)`.
3. In `panels/findings.rs`: if `chains_for_finding` non-empty, render a `"View in chains (N)"` button after the finding row. On click: set `app.show_chains = true`, `app.scroll_to_chain = Some(chains_for_finding[0])`.
4. In `panels/chains.rs`: on render, if `scroll_to_chain` is `Some(idx)`, scroll the egui list to that row using `ui.scroll_to_cursor` or equivalent, then clear `scroll_to_chain` to `None`.

#### 8.2 — Chain → finding navigation
**Task**:
1. In `panels/chains.rs`, for each finding ID listed under an expanded chain, render a small clickable label/badge (truncate to first 8 chars of id + `…`).
2. On click: look up the finding index in `workspace.report.findings` by id; set `app.selected_finding = Some(idx)`; set `app.show_findings = true`.

#### 8.3 — Persist graph node positions within session
**Task**:
1. Add `graph_node_positions: HashMap<String, egui::Pos2>` to `SisApp` (keyed by node id string).
2. In the graph rendering code (check `crates/sis-pdf-gui/src/panels/content_graph.rs` or equivalent), before placing a node at its computed initial position, check if a stored position exists and use it instead.
3. After any drag/layout update, save the new position back to the map.
4. Clear the map when a new workspace is loaded (`workspace.load()` call site in `app.rs`).

---

## Verification Checklist

For each item:
- `cargo build` — must compile cleanly
- `cargo test` — must pass (pre-existing flaky js-analysis test is expected)
- `cargo clippy -- -D warnings` — no new warnings
- Item-specific success criteria above
