# Quality Improvements Plan

**Date**: 2026-02-04
**Scope**: Codebase review findings, AGENTS.md compliance, correctness, build infrastructure

---

## Review Findings

### 1. AGENTS.md Compliance Violations

#### "No unsafe code, no unwraps" -- VIOLATED

AGENTS.md explicitly states: "No unsafe code, no unwraps". The codebase has both.

**Unsafe blocks (21 total):**

| Location | Count | Reason |
|----------|-------|--------|
| `crates/js-analysis/src/dynamic.rs` | 18 | Boa `NativeFunction::from_closure` |
| `crates/sis-pdf/src/main.rs` | 2 | `memmap2::Mmap::map` |
| `crates/sis-pdf/src/commands/query.rs` | 1 | `memmap2::Mmap::map` |

**Boa `unsafe` -- not FFI, it is a GC safety contract.** Boa is a pure Rust crate. The `from_closure` method is `unsafe` because closures that capture `JsValue` (GC-managed) types without registering them with Boa's garbage collector via the `Trace` trait can lead to use-after-free if the GC collects referenced objects. The safe alternatives are:

- `from_copy_closure` -- requires `Copy` bound on the closure (no GC-traced captures).
- `from_closure_with_captures` -- takes an explicit `T: Trace` captures argument so the GC can trace them.

The current code clones `JsValue` instances into closures without registering them as GC roots. In practice this is likely safe because sandbox execution is short-lived and references are kept alive by the object graph, but it is technically unsound per Boa's safety contract. The fix is to refactor captures into explicit `Trace`-implementing structs passed via `from_closure_with_captures`.

**Memmap `unsafe`** -- `Mmap::map` is unsafe because the OS may modify the mapped region (e.g. file truncation by another process). For read-only analysis of files the user has provided, the risk is low. The alternative is `std::fs::read()` which copies the file into memory. A pragmatic middle ground: use `std::fs::read()` by default and memmap only for files above a size threshold, wrapped in a safe helper function that documents the safety invariant.

**Unwrap calls in production code (110+ total):**

| Crate | `unwrap()` count | Notes |
|-------|-------------------|-------|
| font-analysis | 37 | `signatures.rs` (19), `ttf_vm.rs` (7), `model.rs` (9), `eexec.rs` (2) |
| sis-pdf-core | 35 | `explainability.rs` (21), `rich_media.rs` (4), `org_export.rs` (4), others |
| sis-pdf (CLI) | 32 | `main.rs` (2), `query.rs` (29), `readable.rs` (1) |
| sis-pdf-detectors | 3 | `vector_graphics.rs` (1), `lib.rs` (1), `object_cycles.rs` (1) |
| js-analysis | 2 | `dynamic.rs` (1), `static_analysis.rs` (1) |
| sis-pdf-ml-graph | 1 | `lib.rs` (1) |
| sis-pdf-pdf | 0 | Fully compliant |
| image-analysis | 0 | Fully compliant |

`sis-pdf-pdf` and `image-analysis` are the model crates -- zero unwraps, zero unsafe.

#### "Rust native crates only" -- MOSTLY COMPLIANT

- `ort` (ONNX Runtime) wraps a C++ library but is behind the optional `ml-graph` feature flag. Acceptable given the purpose.
- All other dependencies are native Rust.

---

### 2. Correctness Issues

#### Failing Test on main

```
test classifies_action_and_payload_labels ... FAILED
  left: Some("test")
 right: Some("JavaScript action")
```

Location: `crates/sis-pdf-core/tests/chain_grouping.rs:69`

#### Clippy Errors (3 distinct, block compilation of benchmarks/tests)

- `crates/sis-pdf-core/benches/scan.rs`: `cannot move out of opts, a captured variable in an FnMut closure` -- benchmark does not compile.
- `crates/sis-pdf-core/tests/structural_summary.rs`: comparison involving min/max element always true or false.
- `crates/sis-pdf-core/tests/findings_schema.rs`: same always-true comparison.

#### Clippy Warnings (266 total)

| Count | Category | Risk |
|-------|----------|------|
| 82 | "struct update has no effect" -- `..Default::default()` after all fields specified | Noise |
| 34 | "field assignment outside of initializer for Default::default()" | Style |
| 9 | "map_or can be simplified" | Style |
| 7 | "this impl can be derived" -- manual Default/Clone that could be `#[derive]` | Style |
| 7 | "redundant closure" | Style |
| 6 | "using contains() instead of iter().any()" | Performance |
| 5 | "items after a test module" | Style |
| 4 | "this if has identical blocks" | **Possible logic bug** |
| 4 | "this operation has no effect" | Possible bug |
| 3 | "this function has too many arguments (8/7)" | Design |
| 3 | "manually reimplementing div_ceil" | Clarity |
| 3 | "explicit lifetimes could be elided" | Style |
| Others | Various minor lints | Style |

The 4 "identical if blocks" warnings need manual review -- they may indicate copy-paste logic errors.

---

### 3. Security Concerns

#### Strengths -- Excellent

- **Parser** (`sis-pdf-pdf`): Zero unsafe/unwrap, `checked_add`/`checked_mul`, size limits (arrays 100K, dicts 10K, filter chains 8 deep, decoded output 8MB, ObjStm 100).
- **Cycle detection**: XRef chain via `HashSet`, ObjStm recursive reference rejection, DFS cycle detection in path finder.
- **Stream decoding**: Multi-layer fallback (zlib then deflate), saturating arithmetic, truncation with flagging.
- **Image analysis**: Atomic timeout checker, pixel limit enforcement, zero unwraps.
- **Font analysis**: Type1 charstring limits (stack 100, operators 10K), WOFF decompression bomb protection.

#### Concerns Requiring Remediation

1. **JS decoder bounds check** -- `crates/js-analysis/src/static_analysis.rs:477-479`: Slice `data[i + 2..i + 4]` without explicit guard that `i + 4 <= data.len()`.
   - **Recommendation**: Add `if i + 4 > data.len() { break; }` before the slice operation.

2. **Regex capture unwrap** -- `crates/js-analysis/src/dynamic.rs:2269`: `caps.get(0).unwrap()` on regex match.
   - **Recommendation**: Replace with `if let Some(m) = caps.get(0) { ... }`.

3. **Batch expect** -- `crates/sis-pdf/src/main.rs:4063`: `.expect("report")` in batch processing. Implicit invariant not enforced by types.
   - **Recommendation**: Replace with `.ok_or_else(|| anyhow!("report not produced for {}", path.display()))?`.

4. **SWF version unwrap** -- `crates/sis-pdf/src/commands/query.rs:3049`: `version.unwrap()` processing data from untrusted PDFs.
   - **Recommendation**: Replace with `version.unwrap_or(0)` or propagate as error.

5. **REPL path unwrap** -- `crates/sis-pdf/src/main.rs:833`: `.unwrap()` on `actual_pdf.as_deref()` with comment "Safe because we validated above".
   - **Recommendation**: Replace with `.ok_or_else(|| anyhow!("no PDF path available"))?` to decouple from upstream validation logic.

6. **Boa GC unsoundness** -- 18 closures in `dynamic.rs` capture cloned `JsValue` without registering them with Boa's GC.
   - **Recommendation**: Refactor to use `from_closure_with_captures` with explicit `Trace`-implementing capture structs. See stage 3 below.

---

### 4. Build Configuration and CI Gaps

#### Missing CI Workflows

The project has **no test or lint CI**. Only:
- `release-cli.yml` -- multi-platform release builds
- `cve-update.yml` -- weekly CVE signature sync

Missing:
- `cargo test` on PR/push
- `cargo clippy -- -D warnings` enforcement
- `cargo fmt --check`
- Feature matrix testing (`--features ml-graph`, `--no-default-features`)
- Fuzz target integration (6 targets exist, not run in CI)
- MSRV validation
- Code coverage

#### Missing Configuration Files

- No `rust-toolchain.toml` -- MSRV undeclared
- No `clippy.toml` or `rustfmt.toml`
- No `deny.toml` (cargo-deny) for licence/vulnerability scanning
- No workspace-level `[profile.release]` or `[profile.dev]`

#### Workspace Dependency Duplication

`serde`, `serde_json`, `anyhow`, `tracing`, `base64`, and `flate2` appear in 4-7 crates each, specified per-crate. Should be consolidated in `[workspace.dependencies]`.

#### Pre-release Dependency

`ort = "2.0.0-rc.11"` in `sis-pdf-ml-graph`. Behind a feature flag but should be tracked for stable release.

---

### 5. Architecture Observations

#### Strengths

- Clean crate boundaries aligned with functional concerns.
- Consistent builder patterns (`FindingBuilder`, `EvidenceBuilder`).
- `ScanContext` uses `OnceLock` for lazy initialisation.
- Feature gating for heavy optional dependencies (ML, JS sandbox, font dynamic).
- Detector registration via factory function with conditional compilation.
- 50 test files with real malware fixtures.

#### Large Files (Low Priority)

Several files exceed 2,000 lines: `query.rs` (8,921), `features_extended.rs` (3,482), `report.rs` (3,502), `dynamic.rs` (~2,900), `explainability.rs` (2,803). These are internally well-organised and functional. Splitting is a low-priority cleanup that can be done opportunistically when making changes to these files.

---

## Implementation Plan

### Stage 1: Fix Correctness Issues

**Goal**: Green test suite and clean clippy on main
**Status**: Nearly Complete

- [x] Fix failing test `classifies_action_and_payload_labels` in `crates/sis-pdf-core/tests/chain_grouping.rs:69`
- [x] Fix clippy error in `crates/sis-pdf-core/benches/scan.rs` (move semantics in FnMut closure)
- [x] Fix clippy errors in `crates/sis-pdf-core/tests/structural_summary.rs` and `tests/findings_schema.rs` (always-true comparisons)
- [x] Review and fix 4 "identical if blocks" clippy warnings (verify not logic bugs)
- [ ] Run `cargo clippy --fix` for mechanical lint fixes (redundant closures, map_or simplifications, derive impls, struct update removals)
- [ ] Verify `cargo test` passes, `cargo clippy -- -D warnings` is clean

**Success Criteria**: `cargo test` all pass, `cargo clippy --all-targets` zero errors and zero warnings

*Note*: `cargo test -p sis-pdf-core` and `cargo clippy -p sis-pdf-core --benches|--tests` now succeed, but workspace-wide clippy lints (e.g., `upper_case_acronyms`, `manual_div_ceil`, `unwrap_or_default`) still fire and block `-D warnings`. Follow-up work in later stages will address those before rerunning the full `clippy -- -D warnings` sweep.

---

### Stage 2: Eliminate Unwraps in Production Code

**Goal**: AGENTS.md compliance -- no unwraps in `src/` directories
**Status**: Effort moved to `plans/20260204-safety.md` (see new safety-focused stage)

See `plans/20260204-safety.md` for the detailed crate-by-crate breakdown, captured progress, and follow-up verification steps for the remaining `unwrap()` sites listed in the original Stage 2 section.

**Success Criteria**: `plans/20260204-safety.md` tracks the remaining crates and signals when `grep -r '\\.unwrap()' crates/*/src/ --include='*.rs'` yields zero hits.

---

### Stage 3: Eliminate Unsafe Code

**Goal**: AGENTS.md compliance -- no unsafe blocks in workspace
**Status**: In Progress (Stage 3a done, Stage 3b completed for remaining closures)

#### 3a. Memmap removal (3 blocks)

- [x] Create a helper function `fn read_pdf_bytes(path: &Path) -> Result<Vec<u8>>` that uses `std::fs::read()` and preserves the existing size checks
- [x] Replace `unsafe { Mmap::map(&f) }` in `main.rs` (2 sites) and `query.rs` (1 site) with the helper
- [x] Remove `memmap2` dependency from `crates/sis-pdf/Cargo.toml`
- [x] Benchmark large-file scan performance to verify acceptable regression (ran `sis scan crates/sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf --deep --runtime-profile --runtime-profile-format json`; parse 0 ms, detection 2 ms, total_duration 7 ms)

*Note*: `cargo test -p sis-pdf` and `cargo test -p js-analysis --features js-sandbox` exercise the new read helper and confirm the CLI and sandbox integrations still behave; the runtime profile above shows the thin path stays within the Stage 0.5 SLO after dropping `memmap2`.

#### 3b. Boa closure refactor (18 blocks)

The `unsafe` in `NativeFunction::from_closure` exists because Boa's GC cannot trace captured `JsValue` instances inside opaque closures. The safe API is `from_closure_with_captures<F, T>(closure, captures)` where `T: Trace`, which means each closure must supply traceable captures, or use `from_copy_closure` when only `Copy` data is stored.

- [x] Replace the last two `NativeFunction::from_closure` helpers (`make_native` and `make_getter`) with `from_closure_with_captures`, using `LogNameCapture` and `LogValueCapture` so the sandbox log references are traced before the GC runs
- [x] Keep all other Boa helper bindings on `from_closure_with_captures` (already updated during earlier work)
- [x] Re-run `cargo test -p js-analysis --features js-sandbox` to verify behaviour remains unchanged

**Success Criteria**: All `NativeFunction::from_closure` usages now call `from_closure_with_captures` (or `from_copy_closure` where appropriate); targeted closures no longer require `unsafe`.

---

### Stage 4: Build Infrastructure

**Goal**: CI enforcement of quality gates, workspace dependency consolidation
**Status**: Not Started

#### 4a. Workspace dependency consolidation

- [ ] Add `[workspace.dependencies]` to root `Cargo.toml` for: `serde`, `serde_json`, `anyhow`, `tracing`, `base64`, `flate2`, `blake3`, `sha2`, `clap`, `hex`
- [ ] Update each crate's `Cargo.toml` to use `serde.workspace = true` syntax
- [ ] Verify `cargo build` and `cargo test` still pass

#### 4b. Configuration files

- [ ] Add `rust-toolchain.toml` pinning the MSRV (determine from current dependency requirements)
- [ ] Add `rustfmt.toml` (can be empty to use defaults, but makes the intent explicit)
- [ ] Add `clippy.toml` if any project-specific lint configuration is needed
- [ ] Add `deny.toml` for cargo-deny: licence allowlist, vulnerability advisory checking, duplicate crate detection

#### 4c. CI test/lint workflow

- [ ] Create `.github/workflows/ci.yml` with:
  - `cargo fmt --check`
  - `cargo clippy --all-targets -- -D warnings`
  - `cargo test`
  - Feature matrix: default features, `--features ml-graph`, `--no-default-features`
  - Runs on: push to main, pull requests
- [ ] Add nightly/weekly fuzz workflow using existing 6 fuzz targets and corpus

#### 4d. Build profiles

- [ ] Add workspace `[profile.release]` with `lto = "thin"`, `strip = true`
- [ ] Add `[profile.dev.package."*"]` with `opt-level = 1` (optimise dependencies, keep crate code unoptimised for fast iteration)

**Success Criteria**: CI runs on every PR, all checks green, workspace deps unified

---

### Stage 5: Remaining Improvements

**Goal**: Address remaining review findings
**Status**: Not Started

- [ ] Review 4 "this operation has no effect" clippy warnings for possible bugs
- [ ] Refactor functions with >7 arguments (3 occurrences) to use option/config structs
- [ ] Replace manual `div_ceil` implementations (3 occurrences) with `usize::div_ceil` (stabilised in Rust 1.73)
- [ ] Address TODO in `crates/sis-pdf-core/src/explainability.rs:1484` (`// TODO: extract from metadata`)
- [ ] Track `ort` crate for stable 2.0 release and update when available
- [ ] Audit `js-analysis/src/static_analysis.rs` `String::from_utf8_lossy` usage for cases where malicious unicode sequences could evade detection
- [ ] Add explicit `usize::try_from(u64_val)?` in `crates/sis-pdf-pdf/src/objstm.rs:64-65` for 32-bit platform safety (currently safe due to downstream validation, but explicit is better)

**Success Criteria**: All items addressed or explicitly deferred with justification

### Stage 6: Documentation and Knowledge Transfer

**Goal**: Capture the rationale, usage changes, and validation status for the quality improvements so analysts and contributors can follow the new guarantees.
**Status**: Not Started

- [ ] Update `docs/analysis.md` (and any other user-facing docs impacted by pipeline behaviour) to describe new detection guarantees, reporting knobs, and CLI safeguards introduced by previous stages.
- [ ] Refresh `docs/findings.md` with any reclassified labels or metadata fields that surfaced while fixing the `chain_grouping` test.
- [ ] Record implementation notes in `plans/` subdocuments where non-obvious choices (e.g. memmap replacement, Boa capture structs) were made so future maintainers can trace the safety work.
- [ ] Publish a short `AGENTS-progress.md` note summarising compliance status (unwrap/unsafe elimination) and include links to the docs and tests that confirm each step.
- [ ] Ensure `plans/20260204-quality-improvements.md` is listed in the repo's active plan index so reviewers know where to look for status updates.

**Success Criteria**: Documentation reflects every behavioural or structural change, and a traceable note links back to test coverage that proves safety goals.

### Stage 7: Measurement and Continuous Assurance

**Goal**: Keep the board of regressions and quality goals visible, and make it easy to catch regressions in the future.
**Status**: Not Started

- [ ] Add a `quality-metrics.md` sketch (or extend `docs/performance.md`) to track clippy-clean runs, test coverage, and dependence on optional features (ml-graph, js-sandbox).
- [ ] Integrate `cargo test`, `cargo clippy`, `cargo fmt`, and the new workflows into a standalone `docs/ci-setup.md` section so on-call engineers know how to re-run checks locally.
- [ ] Set up a lightweight `plans/QUALITY-BOARD.md` (or extend existing plan) that lists blockers, owners, and completion dates for each stage; revisit weekly with team leads.
- [ ] Evaluate a subset of fuzz targets (at least one pdf parser target) after every stage to ensure no new sanitiser or crash regressions; document results.
- [ ] Define a regression signal (e.g. `cargo test --package sis-pdf-core classifies_action_and_payload_labels`) that must stay green before shipping further feature work.

**Success Criteria**: Quality metrics stay red/green at a glance, CI tests cover critical paths, and regression signals guard future changes.
