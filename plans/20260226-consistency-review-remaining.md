# Remaining Work: Consistency Review Implementation
**Source**: `reviews/20260226-comprehensive-codebase-review.md`
**Branch**: `feature/consistency`
**Last commit**: `c691d44` — Stages 1–7 (partial) implemented
**Date**: 2026-02-26

---

## What Was Completed

Commit `c691d44` on `feature/consistency` covers:

| Stage | Items done |
|---|---|
| 1 (Data model) | 1.1 meta_keys.rs, 1.2 typed accessors, 1.3 remove position field, 1.4 Impact::Unknown variant, 1.7 risk_score doc |
| 2 (Docs) | ARCHITECTURE.md rewrite, AGENTS.md Heuristic level, --fast/--deep help + conflict |
| 3 (Safety) | 3.1 shadow_attacks depth guard, 3.4 stable cache hash, 3.5 low_completeness annotation |
| 5 (Consolidation) | 5.1 ObjProvenance::label(), 5.2 entropy.rs, 5.4 graph_walk depth guard |
| 6 (Interfaces) | 6.1 record_type on Report/BatchEntry, 6.2 BatchError struct, 6.3 --fast conflicts_with |
| 7 (CLI tests) | cli_integration.rs with 6 tests |

All tests pass (one pre-existing flaky failure in `js-analysis` is unrelated).

---

## Remaining Items

### Priority 1 — Safety (low risk, bounded scope)

#### 3.2 — AcroForm widget tree depth cap
**File**: `crates/sis-pdf-core/src/page_tree.rs`
**Task**: Check `build_annotation_parent_map()` (line ~46). It calls `build_page_tree()` which walks the page tree. Verify that walk has a depth guard and a `seen: HashSet<ObjRef>`. If absent, add `MAX_FORM_DEPTH: usize = 32` and a visited set before the parent-map traversal — same pattern as `walk_pages()` in the same file.
**Test**: Add a unit test with a synthetic dict chain longer than 32 entries; assert it returns without panic.
**Success**: `cargo test -p sis-pdf-core` passes; no stack overflow on crafted deep AcroForm.

#### 3.3 — Do operator depth tracking in content streams
**Files**: `crates/sis-pdf-detectors/src/content_stream_exec_uplift.rs`, `crates/sis-pdf-pdf/src/content_summary.rs`
**Task**: `content_summary.rs` builds a `ContentSummary` per stream. Add a `do_call_depth: usize` field tracking the maximum nesting of `Do` operators across Form XObjects. In `content_stream_exec_uplift.rs`, after analysing the summary, emit a finding if `do_call_depth > MAX_DO_DEPTH` (suggest 16):
```
kind:       "content_stream_do_depth_excessive"
surface:    StreamsAndFilters
severity:   Medium
confidence: Strong
meta:       "do.max_depth" => depth.to_string()
```
**Success**: `cargo test -p sis-pdf-detectors` passes; new finding kind appears in a crafted fixture.

---

### Priority 2 — Data model completion (invasive, many files)

#### 1.4 (complete) — Make `impact` non-optional
**File**: `crates/sis-pdf-core/src/model.rs` and every detector file
**Context**: `Impact::Unknown` variant already exists. The `Finding.impact` field is still `Option<Impact>`. The work remaining is:
1. Change `pub impact: Option<Impact>` → `pub impact: Impact` in `Finding`.
2. Add `#[serde(default = "default_impact")]` to the field and `fn default_impact() -> Impact { Impact::Unknown }` for backward-compatible JSON deserialisation.
3. Update `FindingBuilder::impact()` to take `Impact` directly (already does, via `Some(impact)` → now just assign).
4. Update `Default` impl: `impact: Impact::Unknown`.
5. Mass-replace all `impact: None` → `impact: Impact::Unknown` (132+ sites across detector files, tests, core). This is mechanical — the compiler will catch every missed site after step 1.
6. Review each detector file and replace `Impact::Unknown` with an appropriate value where the impact is actually known (optional cleanup pass).

**Approach**: Make the struct change first; let `cargo check` enumerate all remaining sites; fix each in a single pass.
**Success**: `cargo check` clean; no `Option<Impact>` in `model.rs`; `cargo test` passes.

#### 1.5 — Reconcile action field duplication
**Files**: `crates/sis-pdf-core/src/chain_synth.rs` (notes_from_findings), `crates/sis-pdf-core/src/chain_score.rs`, `crates/sis-pdf-core/src/intent.rs`, detector files
**Context**: `Finding` has typed fields `action_type`, `action_target`, `action_initiation`. Several detectors also insert `meta["action.s"]` (action subtype string) which duplicates `action_type`. `chain_synth.rs:550` reads `f.meta.get("action.s")` and copies it to chain notes; `intent.rs:312` reads `f.meta.get("action.target")` which duplicates `finding.action_target`.

**Task**:
1. Grep for all detectors that set **both** `meta["action.s"]` and `finding.action_type`. Remove the `meta.insert("action.s", ...)` line from those detectors.
2. In `notes_from_findings()` (`chain_synth.rs:543`), after the meta loop, add a fallback: if `action.type` note not yet set, check `f.action_type` and use it.
3. In `intent.rs`, change `f.meta.get("action.target")` comparisons to read `f.action_target.as_deref()` instead.
4. Add `meta_keys::ACTION_S` and `meta_keys::ACTION_TARGET` usage where the meta key is still needed.

**Success**: `grep -r '"action\.s"' crates/` returns only `meta_keys.rs` definition and chain_synth fallback; `cargo test` passes.

#### 1.6 — Finding ID validation in chain synthesis
**File**: `crates/sis-pdf-core/src/chain_synth.rs`
**Task**: After `synthesise_chains()` assembles chains, add a validation pass:
```rust
let finding_ids: HashSet<&str> = findings.iter().map(|f| f.id.as_str()).collect();
for chain in &chains {
    for fid in &chain.findings {
        if !finding_ids.contains(fid.as_str()) {
            tracing::warn!(
                chain_id = %chain.id,
                missing_finding = %fid,
                "chain references unknown finding id"
            );
        }
    }
}
```
Insert before the final `(chains, templates)` return.
**Success**: `cargo check -p sis-pdf-core` clean; no test regression.

---

### Priority 3 — Detection gaps (new behaviour, needs fixtures)

#### 4.2 — NTLM/UNC path detection
**Files**: `crates/sis-pdf-detectors/src/uri_classification.rs`, `crates/sis-pdf-detectors/src/external_target.rs`
**Task**: In `uri_classification.rs`, the function that evaluates URI risk already has `file://` and SMB pattern checks. Extend it to also flag UNC-style paths:
- Windows UNC: `\\server\share` (starts with `\\`)
- Slash-form: `//server/share` where scheme is absent

Add a new `bool` field `has_unc_path: bool` to `UriContentAnalysis`. Set it when the URL matches `^\\\\\w` or `^//[^/]` (with no preceding scheme).

In `external_target.rs` (and/or the URI classification detector), emit a finding when `has_unc_path` is true:
```
kind:       "uri_unc_path_ntlm_risk"
surface:    Actions
severity:   High
confidence: Strong
description: "UNC path in action target; triggers NTLM hash capture on Windows renderers"
meta:       "uri.unc_path" => the UNC value
```

Check all three contexts: `SubmitForm` action targets, `GoToR` remote targets, annotation `/URI` values.

**Fixture**: Create `crates/sis-pdf-core/tests/fixtures/evasion/unc_path_submit.pdf` (a minimal PDF with a SubmitForm action to `\\attacker\share`). Register in `manifest.json`. Add regression assertion in `corpus_captured_regressions.rs`.
**Success**: `sis scan unc_path_submit.pdf` produces `uri_unc_path_ntlm_risk`; `cargo test` passes.

#### 4.1 — XFA script forwarding to JS analysis
**File**: `crates/sis-pdf-detectors/src/xfa_forms.rs`
**Context**: `XfaFormDetector` already calls `extract_xfa_script_payloads()` and stores a preview. Scripts are not passed to static JS analysis.
**Task**: In `XfaFormDetector::run()`, after `script_payloads` is populated, gate on `ctx.options.deep`:
```rust
if ctx.options.deep {
    for script in &script_payloads {
        if let Ok(signals) = js_analysis::static_analysis::extract_js_signals(script.as_bytes()) {
            // translate significant signals to findings
            // prefix kind with "xfa_js." e.g. "xfa_js.obfuscated"
            // use surface: Forms
        }
    }
}
```
Check `crates/js-analysis/src/static_analysis.rs` for the `extract_js_signals` function signature. You may need to add a public re-export.
**Success**: `cargo test -p sis-pdf-detectors` passes; `sis scan --deep <xfa_fixture>` produces `xfa_js.*` findings for a script with eval().

#### 4.3 — Intent ↔ chain score feedback
**File**: `crates/sis-pdf-core/src/runner.rs` (post-detection assembly) or `crates/sis-pdf-core/src/chain_synth.rs`
**Task**: After both intent analysis and chain synthesis have run, add a lightweight pass:
```rust
// In runner.rs, after synthesise_chains() and analyse_intent():
if let Some(ref intent) = intent_summary {
    for chain in chains.iter_mut() {
        for signal in &intent.signals {
            if signal.confidence >= Confidence::Strong {
                if chain.findings.iter().any(|fid| signal.finding_id.as_deref() == Some(fid)) {
                    chain.score = (chain.score + 0.1).min(1.0);
                    chain.notes.insert("intent_boost".into(), signal.bucket.as_str().into());
                    break;
                }
            }
        }
    }
}
```
Locate the exact construction site in `runner.rs` where chains are assembled and intent is computed; insert the feedback pass between the two.
**Success**: `cargo test` passes; chains containing findings flagged by strong intent signals show a 0.1 score increase.

#### 4.4 — Evasion test fixtures
**Directory**: `crates/sis-pdf-core/tests/fixtures/evasion/`
**Task**: Create three minimal crafted PDFs and corresponding regression tests. The fixture PDFs can be built programmatically using `sis-pdf-pdf` primitives or written as raw bytes. Register each in `crates/sis-pdf-core/tests/fixtures/corpus_captured/manifest.json` with `sha256`, `source_path`, and `regression_targets`.

1. `entropy_padded_js.pdf` — JS payload padded with low-entropy bytes. Assert `js_present` finding still emitted.
2. `deep_chain_low_completeness.pdf` — Partial chain (trigger + action, no payload). Assert chain emitted with `low_completeness: "true"` in notes.
3. `unc_path_submit.pdf` — SubmitForm to `\\attacker\share`. Assert `uri_unc_path_ntlm_risk` (depends on 4.2).

Add assertions in a new test file `crates/sis-pdf-core/tests/evasion_fixtures.rs`.

---

### Priority 4 — Consolidation (cleanup, no behaviour change)

#### 5.3 — Consolidate resolve_dict helpers
**Files**: `crates/sis-pdf-pdf/src/graph.rs`, `crates/sis-pdf-detectors/src/font_exploits.rs:714`, `crates/sis-pdf-detectors/src/shadow_attacks.rs:667`, `crates/sis-pdf-core/src/page_tree.rs:194`

Three near-identical private functions:
```rust
fn resolve_dict<'a>(graph/ctx, obj: &PdfObj<'a>) -> Option<PdfDict<'a>>
```
**Task**: Add to `ObjectGraph` in `crates/sis-pdf-pdf/src/graph.rs`:
```rust
impl<'a> ObjectGraph<'a> {
    pub fn resolve_to_dict(&self, obj: &PdfObj<'a>) -> Option<PdfDict<'a>> {
        match &obj.atom {
            PdfAtom::Dict(d) => Some(d.clone()),
            PdfAtom::Stream(st) => Some(st.dict.clone()),
            PdfAtom::Ref { .. } => self.resolve_ref(obj).and_then(|e| match &e.atom {
                PdfAtom::Dict(d) => Some(d.clone()),
                PdfAtom::Stream(st) => Some(st.dict.clone()),
                _ => None,
            }),
            _ => None,
        }
    }
}
```
Update all three callers to use `ctx.graph.resolve_to_dict(obj)` (font_exploits.rs passes `ctx.graph` directly; shadow_attacks.rs has `ctx.graph`; page_tree.rs receives `graph` directly).
Remove the three private functions.
**Success**: `grep -r "fn resolve_dict" crates/` returns zero results; `cargo test` passes.

---

### Priority 5 — CLI test gap (minor documentation)

#### 7.2 — Document CLI test approach in AGENTS.md
**File**: `AGENTS.md`, Testing Guidelines section
**Task**: Add a paragraph after the existing test guidelines:

> **CLI integration tests** live in `crates/sis-pdf/tests/cli_integration.rs` and exercise the compiled `sis` binary via `std::process::Command`. Run with `cargo test -p sis-pdf --test cli_integration`. The fixture used is `crates/sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf`. A deferred test for `sis diff` (identical inputs → exit 0) requires temp-file coordination and is tracked as a follow-up.

---

### Priority 6 — GUI navigation (feature work)

#### 8.1 — Finding → chain navigation
**Files**: `crates/sis-pdf-gui/src/app.rs`, `crates/sis-pdf-gui/src/panels/findings.rs`, `crates/sis-pdf-gui/src/panels/chains.rs`
**Task**:
1. In `app.rs`, when `selected_finding` changes, compute `chains_for_finding: Vec<usize>` — indices of chains whose `.findings` vec contains the selected finding's id. Store on `SisApp`.
2. In `panels/findings.rs`, if `chains_for_finding` non-empty, render a "View in chains (N)" button. On click: `show_chains = true`; set `scroll_to_chain = Some(chains_for_finding[0])` in app state.
3. In `panels/chains.rs`, accept `scroll_to_chain: Option<usize>` from app state; on first render with a new value, scroll the list to that row.

#### 8.2 — Chain → finding navigation
**Files**: `crates/sis-pdf-gui/src/panels/chains.rs`
**Task**: For each finding ID listed under a chain, render a clickable badge (e.g. short truncated id). On click: set `selected_finding` to the index of that finding in `workspace.report.findings`; set `show_findings = true`.

#### 8.3 — Persist graph node positions within session
**Files**: `crates/sis-pdf-gui/src/graph_data.rs` or `graph_layout.rs`
**Task**: Store node positions in a `HashMap<NodeId, egui::Pos2>` in app state. When graph is re-rendered (mode switch, panel toggle), only initialise positions for nodes without a stored position. Clear the position store on workspace load.

---

## Verification Checklist (per item)

For each item above, verify with:
- `cargo build` — must compile cleanly
- `cargo test` — must pass all existing tests (the pre-existing failure `sandbox_suppresses_runtime_limit_for_sentinel_spin_with_wsh_calls` in `js-analysis` is unrelated and expected)
- `cargo clippy -- -D warnings` — must produce no new warnings
- Item-specific success criteria noted above
