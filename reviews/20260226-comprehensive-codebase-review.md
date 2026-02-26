# Comprehensive Codebase Review: sis-pdf

**Date**: 2026-02-26
**Scope**: Full codebase — architecture, detection coverage, data models, interfaces, quality, gaps, and recommendations
**Codebase state**: Pre-release; no external interface stability guarantees

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Data Model Coherence](#3-data-model-coherence)
4. [Scan Pipeline & Internal Interfaces](#4-scan-pipeline--internal-interfaces)
5. [Detection Coverage](#5-detection-coverage)
6. [Correlation & Chain Synthesis](#6-correlation--chain-synthesis)
7. [Output & External Interfaces](#7-output--external-interfaces)
8. [CLI Surface](#8-cli-surface)
9. [GUI Surface](#9-gui-surface)
10. [Test Coverage & Quality](#10-test-coverage--quality)
11. [Code Quality & Safety](#11-code-quality--safety)
12. [Documentation State](#12-documentation-state)
13. [Findings & Recommendations](#13-findings--recommendations)

---

## 1. Executive Summary

sis-pdf is a well-engineered, multi-layered PDF security analysis platform. Its core detection architecture is sophisticated, with 45+ detector modules covering 9 attack surfaces, a layered static/dynamic analysis pipeline, a rich correlation system, and an intent classification layer. The codebase is written in safe Rust throughout, resource limits are comprehensive, and test coverage is solid across the core and detector layers.

The project has real strengths: the typed graph / event graph model is semantically expressive; the chain synthesis system links findings into coherent attack narratives; the JavaScript analysis module is unusually deep; and the incremental update / shadow attack detection is particularly strong.

However, several design-level issues have accumulated that will increasingly impede development and consumer trust if left unaddressed:

- The **Finding data model is internally incoherent**: metadata keys have no schema, dual position fields coexist, impact is optional in contexts where it is load-bearing, and type coercion is scattered throughout consumers.
- **ARCHITECTURE.md is dangerously stale**: it describes a completely different codebase (SeaORM, SQLite, `sis-pdf-cli`, `sis-pdf-storage`, `sis-pdf-discovery`) that bears no relation to the actual workspace.
- The **chain scoring and intent systems operate in isolation**, with no feedback path between them.
- Several **detection gaps** allow known evasion strategies to avoid detection or produce no findings.
- **Utility code is duplicated** across crates (entropy, provenance labelling, stream/dict resolution, cycle detection), creating divergence risk.
- The **ML integration is structurally present but functionally hollow** without shipped models and lacks adversarial robustness.

Addressing the data model coherence issues and the documentation debt should be the highest priority items before any external release.

---

## 2. Architecture Overview

### 2.1 Workspace Layout

The workspace currently contains 9 crates:

| Crate | Responsibility | Status |
|---|---|---|
| `sis-pdf` | CLI binary (`sis`), all subcommands | Production-ready |
| `sis-pdf-core` | Scan pipeline, models, correlation, chains, ML, reporting | Production-ready |
| `sis-pdf-pdf` | PDF parser, object graph, decode, typed graph, IR | Production-ready |
| `sis-pdf-detectors` | 45+ detector modules | Production-ready |
| `sis-pdf-gui` | egui/eframe GUI (native + WASM) | WASM ready; native in progress |
| `js-analysis` | JavaScript static + dynamic (sandboxed) analysis | Production-ready |
| `font-analysis` | Font static + dynamic analysis (TTF/CFF/Type1/WOFF) | Production-ready |
| `image-analysis` | Image static + dynamic analysis (JBIG2, JPX, CCITT, etc.) | Production-ready |
| `sis-pdf-ml-graph` | GNN / ONNX inference for object graph classification | Infrastructure present; models not shipped |

**Finding**: `ARCHITECTURE.md` describes `sis-pdf-cli`, `sis-pdf-storage`, `sis-pdf-discovery`, SeaORM, and SQLite — none of which exist. This document must be rewritten entirely. It currently misleads any contributor reading it.

### 2.2 Dependency Direction

```
sis-pdf (CLI)
  └─ sis-pdf-core
       ├─ sis-pdf-pdf
       ├─ sis-pdf-detectors
       │    ├─ js-analysis
       │    ├─ font-analysis
       │    ├─ image-analysis
       │    └─ sis-pdf-ml-graph
       └─ (all analysis types converge here for report assembly)

sis-pdf-gui
  └─ sis-pdf-core (via analysis.rs wrapper)
```

The direction is clean and the crate boundaries broadly reflect the right abstractions. The primary structural concern is that `sis-pdf-core` is doing too much: scan orchestration, correlation, chain synthesis, intent analysis, feature extraction, ML integration, export, reporting, YARA annotation, revision forensics, temporal analysis, CDR, and more. Many of these could be extracted into narrower crates or modules without disrupting the pipeline.

### 2.3 Build and Feature Flags

Feature flags are used appropriately to gate expensive optional capabilities (`ml-graph`, `font-dynamic`, `gui`, `js-sandbox`). The WASM/native split in the GUI is handled correctly. No issues found with the Cargo workspace configuration.

---

## 3. Data Model Coherence

This is the most significant structural problem in the codebase. The `Finding` type in `sis-pdf-core/src/model.rs` has accumulated inconsistencies that make it harder to consume, query, test against, and reason about.

### 3.1 Dual Position Fields

```rust
pub position: Option<String>,   // deprecated; single position
pub positions: Vec<String>,     // current; multiple positions
```

Both fields are present with no migration helpers and no documented semantics. Consumers must check both. The `position` field should be removed and `positions` used exclusively.

**Recommendation**: Remove `position`. Migrate any detectors still setting it to use `positions`.

### 3.2 Impact is Nominally Optional but Functionally Required

`impact: Option<Impact>` is `None` for a large fraction of findings. Chain scoring and intent analysis must defensively handle `None` everywhere. For a forensic tool, every finding should have a stated impact — even `Impact::None` when there is genuinely no direct consequence. The option-ness is misleading.

**Recommendation**: Make `impact` non-optional. Add `Impact::Unknown` if needed for newly-detected patterns that haven't been assessed yet. Audit all detectors to fill in impact.

### 3.3 Metadata Key Convention

All detector-specific context is stored as `HashMap<String, String>` with no schema, no validation, and no central registry. Key naming conventions are inconsistent:

| Usage | Example Key | Type | How Used |
|---|---|---|---|
| Action type | `action.s` | String | Set in detectors, matched in chain_score.rs |
| Boolean signal | `js.contains_eval` | `"true"`/`"false"` | Matched as string comparison throughout |
| Float signal | `js.string_concat_density` | `"0.05"` | `parse::<f64>()` scattered in consumers |
| Numeric signal | `uri_risk_score` | `"100"` | `parse::<u32>()` in chain_score.rs |
| Nested object ref | `action.target` | String | Free-form, inconsistent separator style |

The result is that chain_score.rs, intent.rs, and correlation.rs each contain ad hoc string comparisons and numeric parsing scattered throughout, creating a maintenance burden and a silent-failure risk when keys are misspelled or format changes.

**Recommendation**: Define a `FindingMeta` struct (or at minimum a documented constant set for key names) and enforce it. Use typed accessors for common patterns (`meta_bool("js.contains_eval")`, `meta_f64("js.string_concat_density")`). This is the most impactful single change that can be made to the data model.

### 3.4 Redundant Typed Fields and Metadata Overlap

`action_type`, `action_target`, and `action_initiation` are dedicated struct fields, but similar values also appear in the `meta` HashMap under keys like `action.s` and `action.target`. This creates two representations of the same data with no reconciliation.

**Recommendation**: Pick one representation. Either promote the metadata keys to typed fields, or remove the dedicated typed fields and use only `meta`. Either direction is fine; mixing both is not.

### 3.5 Finding ID Convention

Finding IDs are set by individual detectors with no enforced format. `ExploitChain.findings` holds `Vec<String>` references to `Finding.id` values, but there is no validation that the referenced IDs exist. Serialisation round-trips may silently produce dangling references.

**Recommendation**: Enforce a naming convention for finding IDs (e.g., `{surface}:{kind}:{obj_ref}` or similar). Add a validation pass in report assembly to check that all chain-referenced finding IDs are present.

### 3.6 Two Independent Scoring Systems

- `ExploitChain.score: f64` — synthesised from finding signals in `chain_score.rs`
- `ActionChain.risk_score(): f32` — computed from typed graph edge properties in `path_finder.rs`

These are never reconciled. A consumer reading a chain report sees one score, but the internal path finder may have computed a different one. It is not clear which should be authoritative.

**Recommendation**: Remove `ActionChain.risk_score()` or document it explicitly as a pre-correlation score that is superseded by `ExploitChain.score` after full analysis. The two should not coexist at the output boundary.

### 3.7 Evidence Span Semantic Ambiguity

`EvidenceSpan.offset` is `u64` but its semantics differ by context: file position vs. position within a decoded stream. The `EvidenceSource` enum distinguishes these, but the offset interpretation is not self-documenting.

**Recommendation**: Rename fields to `file_offset` vs. `decoded_offset` or add a doc comment making the context-dependence explicit. This is a source of subtle bugs for anyone writing a consumer.

---

## 4. Scan Pipeline & Internal Interfaces

### 4.1 Overall Pipeline

The pipeline is well-structured:

```
PDF bytes → ObjectGraph → ScanContext (lazy state) → Detectors → Findings
  → Correlation → Chain synthesis → Intent analysis → Report
```

Lazy initialisation via `OnceLock` is correct and efficient. The `DecodedCache` with atomic budget management is a sound design.

### 4.2 Detector Trait

```rust
pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;
    fn surface(&self) -> AttackSurface;
    fn needs(&self) -> Needs;
    fn cost(&self) -> Cost;
    fn run(&self, ctx: &ScanContext) -> anyhow::Result<Vec<Finding>>;
}
```

The interface is clean and has been stable. `Needs` bitflags allow the runner to reason about dependency ordering and optimise resource access.

**Issue**: `Cost` (Cheap / Moderate / Expensive) is a self-declaration with no enforcement or feedback mechanism. A detector declaring itself `Cheap` that actually spends 500ms will silently violate SLOs. The runtime profiler exists but isn't used to validate Cost declarations.

**Recommendation**: In CI, run the profiler against a reference fixture set and assert that `Cost::Cheap` detectors finish within their budget. Consider adding `Cost::WithTimeout(Duration)` as a variant so the runner can enforce it rather than just scheduling.

### 4.3 TypedGraph Rebuilding

`build_typed_graph()` on `ScanContext` is expensive but cannot be cached due to lifetime constraints — the graph borrows from the `ObjectGraph` which borrows from the raw PDF bytes. Every detector that calls it must rebuild it from scratch.

**Finding**: This is the most significant performance bottleneck in the detection pipeline for documents with many detectors requesting the typed graph.

**Recommendation**: Pre-build a single owned `TypedGraph` as part of scan setup and store it in `ScanContext`. This requires either changing the ownership model (clone the relevant data during graph construction) or using `Arc<TypedGraph>` with an explicit handle. The performance gain for expensive detectors would be substantial.

### 4.4 ScanOptions Explosion

`ScanOptions` has 20+ flat fields. The fingerprinting mechanism that gates cache invalidation formats `ScanOptions` via `Debug` trait (`format!("{:?}", options)`). This is fragile: adding a new field with a derived `Debug` implementation will change the hash and invalidate all existing caches silently.

**Recommendation**: Implement a stable `hash_for_cache()` method on `ScanOptions` that explicitly selects which fields affect cached outputs. This should use a stable serialisation rather than `Debug` formatting.

### 4.5 Page Tree Cycle Detection Gap

`sis-pdf-core/src/page_tree.rs` has a `MAX_PAGE_TREE_DEPTH` constant and depth limiting, but lacks a `visited: HashSet` for cycle detection. A page tree with a cycle (malformed or adversarial) could still exhaust the stack if the cycle depth is within the depth limit.

**Recommendation**: Add cycle detection via a `seen: HashSet<(u32, u16)>` alongside the depth counter. This is already noted in `MEMORY.md` and has not been fixed.

---

## 5. Detection Coverage

### 5.1 Coverage Summary

| Attack Surface | Detector Count | Coverage Assessment |
|---|---|---|
| FileStructure | 12+ | Strong: polyglot, xref deviation, shadow attacks, page tree, object cycles, revision forensics |
| StreamsAndFilters | 10+ | Strong: font exploits, image analysis, filter depth/anomaly, ObjStm torture, decompression |
| JavaScript | 5+ | Very strong: static (80+ signals), dynamic sandbox (4 runtimes), polymorphic, evasion |
| Actions | 6+ | Strong: trigger chains, multi-stage, launch actions, URI classification |
| CryptoSignatures | 4+ | Moderate: shadow attacks, encryption obfuscation, advanced crypto, revision forensics |
| Forms | 3+ | Moderate: XFA (static only), AcroForm, form field anomalies |
| EmbeddedFiles | 2+ | Moderate: embedded file detection, archive analysis |
| Images | 2+ | Moderate: JBIG2/JPX/CCITT, zero-click pattern |
| ContentPhishing | 2 | Basic: content_first, content_phishing |

### 5.2 Significant Detection Gaps

**Gap 1: Page Tree Cycle Without Depth Limit Exhaustion**
A page tree cycle confined to depth ≤ `MAX_PAGE_TREE_DEPTH` (128) but without a visited set will not be detected. The detector declares it detects cycles, but the current implementation is incomplete.

**Gap 2: XFA → JavaScript Bridge Not Traced**
`xfa_forms.rs` performs static XML analysis but does not trace XFA script invocations through to JavaScript execution. XFA scripts can invoke JavaScript via `xfa.resolveNode()`, `xfa.event`, and related APIs. This bridge is a common vector and is not covered dynamically.

**Gap 3: Content Stream Operator-Level Depth**
`content_stream_exec_uplift.rs` detects execution uplift patterns, but there is no operator-level recursion tracking for nested Form XObjects (invoking `Do` within `Do`). The font analysis module tracks Type 3 charproc depth, but an equivalent check does not exist for page content streams.

**Gap 4: AcroForm Widget Tree Depth**
`annotations_advanced.rs` performs overlay and injection detection, but deep AcroForm widget trees (fields with `/Kids` referencing more fields recursively) are not subject to a traversal depth cap. A deeply nested widget tree could be used to exhaust resources during form field enumeration.

**Gap 5: ObjStm Parser-Differential Carving**
The carvedstream provenance path exists in the object graph, but no detector compares how different parsers would carve an ObjStm. A stream crafted to be parsed differently by Adobe Reader vs. an open-source parser would only be caught if the `--diff-parser` (lopdf) mode happens to detect a deviation in the specific field being abused.

**Gap 6: Renderer-Specific Semantic Divergence**
`renderer_divergence.rs` detects structural divergence (xref, trailer) but not semantic divergence: colour space handling, CMap interpretation, glyph substitution, and resource inheritance rules differ between renderers. These are known vectors for targeted exploitation.

**Gap 7: Entropy-Based Detection is Bypassable**
Entropy-based signals (JS obfuscation heuristics, stream analysis) can be trivially defeated by adding low-entropy padding or distributing payload content across multiple objects. These signals should be treated as `Confidence::Tentative` or `Confidence::Heuristic` exclusively and not as primary detection evidence.

**Gap 8: ML Adversarial Robustness**
The GNN model in `sis-pdf-ml-graph` has no adversarial robustness validation. A targeted attacker with knowledge of the model architecture can craft PDFs that score as benign. No explainability or perturbation testing is in place.

**Gap 9: NTLM / SMB Hash Capture via URIs**
`uri_classification.rs` detects suspicious URI schemes including SMB-style URIs, but the detection is primarily heuristic (scheme matching). A UNC path embedded as a form submit target or annotation action — which triggers NTLM hash capture when rendered on Windows — may not generate a finding if the path is obfuscated or uses a variant scheme.

**Gap 10: Signature Validation Is Forensic Only**
The shadow attack and revision forensics detectors are forensic (they detect that signatures were present and tampering occurred), but there is no attempt to verify whether any embedded digital signature is actually valid against its claimed certificate. A document with an invalid signature over manipulated content is not flagged at the cryptographic level.

### 5.3 Evasion Resistance Assessment

| Technique | Resistance | Notes |
|---|---|---|
| Shadow hide/replace attacks | High | Semantic content fingerprinting |
| JavaScript obfuscation (JSFuck, JJEncode) | High | 8-layer deobfuscation with multiple codec supports |
| XRef / trailer manipulation | High | Multiple independent checks |
| Page tree cycles | Medium | Depth limit present, but cycle detection not complete |
| Deeply nested action chains | Medium | Depth cap at 20 (/Next), but lateral spread not capped |
| Entropy obfuscation bypass | Low | Padding/distribution trivially bypasses entropy signals |
| Targeted ML evasion | Low | No adversarial robustness testing |
| Renderer-specific semantic divergence | Low | Not covered beyond structural deviations |

---

## 6. Correlation & Chain Synthesis

### 6.1 Correlation System

`correlation.rs` (77 KB) is the largest single file in the codebase. It synthesises composite findings by matching patterns across individual detector outputs. The breadth of correlations is impressive, and the logic is generally sound.

**Issue**: The file has grown to the point where it is difficult to audit and maintain. Individual correlation rules are long match expressions over finding kinds and metadata keys, with no encapsulation. Adding a new correlation requires understanding the entire file to avoid conflicts.

**Recommendation**: Extract each correlation rule into its own function or struct, each with a documented threat model rationale. Consider a declarative rule format (similar to how YARA works) that can be loaded and validated independently.

### 6.2 Intent Analysis and Chain Scoring Are Decoupled

`intent.rs` maps findings to adversarial intent buckets (DataExfiltration, SandboxEscape, Phishing, etc.) with a weight-based confidence score. `chain_score.rs` assigns a risk score to exploit chains based on trigger/action/payload analysis. These two systems are independent and produce outputs that are not cross-referenced.

A chain with high maliciousness score may map to a low-confidence intent bucket if the relevant finding kinds are not listed in `intent.rs`'s signal table. Conversely, a strong intent signal may come from a finding that is not part of any high-scoring chain.

**Recommendation**: Feed intent analysis results back into chain scoring, and vice versa. If intent.rs assigns `DataExfiltration` with `Confidence::Strong`, that should increase the score of any chain that contains a DataExfiltration finding. If a chain score is high, the corresponding findings should have their intent weights boosted.

### 6.3 Chain Completeness and Narrative Quality

`ExploitChain.chain_completeness` (fraction of chain resolved) is a good signal, but chains with completeness below a threshold are still surfaced at full prominence. A chain with 20% completeness and a high score may represent a false positive or a fragment that shouldn't drive triage decisions.

**Recommendation**: Add a completeness threshold below which chains are surfaced at reduced severity or relegated to informational status, with explicit annotation. A chain reporting score 0.9 with completeness 0.15 is misleading.

### 6.4 Event Graph Integration

The EventGraph is well-designed and expressive. The integration between EventGraph outcomes and findings is good for JavaScript actions, but content stream execution events and font execution events are less well represented. The EventGraph should be the primary mechanism for linking findings across different layers (structural → execution → outcome), but currently this linkage is inconsistently applied.

---

## 7. Output & External Interfaces

### 7.1 Output Format Coverage

| Format | Scan | Query | Diff | Notes |
|---|---|---|---|---|
| JSON | ✅ | ✅ | ✅ | Canonical format |
| JSONL | ✅ | ✅ | ✅ | Batch/streaming |
| SARIF 2.1 | ✅ | — | — | CI/CD integration |
| YAML | ✅ | ✅ | — | Config-style output |
| CSV | ✅ (flag) | — | — | Not yet implemented despite flag presence |
| DOT | — | ✅ | — | Graph export |
| Readable text | ✅ | ✅ | ✅ | Human-facing, syntax-highlighted |

**Issue**: `--csv` is present as a CLI flag for scan output but not yet implemented. This is a silent no-op or a confusing error state. If it is not implemented, the flag should be removed or explicitly marked as `--experimental-csv` until it works.

### 7.2 SARIF Output

The SARIF output exists but has not been reviewed in detail here. For CI/CD integration (GitHub Advanced Security, etc.), SARIF schema conformance and the quality of `rule.shortDescription`, `result.message.text`, and `locations` are critical. Recommend a targeted SARIF conformance review before announcing this as a feature.

### 7.3 JSON Schema Consistency

Finding kinds, severity values, confidence values, and attack surface names are tested via JSON schema in `findings_schema.rs`. This is good practice. However:

- `confidence` in the Rust type has 6 levels (`Certain`, `Strong`, `Probable`, `Tentative`, `Weak`, `Heuristic`), but the JSON output documentation in `AGENTS.md` lists only 3 (`Strong`, `Tentative`, `Speculative`). These are inconsistent.
- `impact` is optional in the Rust type but the JSON output schema behaviour for absent impact fields is not documented.

**Recommendation**: Ensure the JSON schema test covers the full enum space for each field. Update `AGENTS.md` to reflect the actual confidence levels.

### 7.4 Query Interface

The query interface is very rich (100+ query types) and well-designed. The `--where` predicate filtering is useful and composable. No significant issues found with the query surface itself.

**Issue**: Some query types (`GraphOrg`, `GraphOrgEdges`) produce Org-mode output — a non-standard format that requires the Emacs Org-mode viewer or a converter. This is idiosyncratic and may surprise users. If Org-mode export is intended for internal use, it should be clearly documented as such.

### 7.5 Batch Mode Output Consistency

In batch/JSONL mode, per-file error entries are emitted when a file fails to parse. The error entry schema is not explicitly documented or tested. A consumer building a pipeline on top of JSONL output needs to handle both `ScanReport` records and error records, but the distinguishing field (`"error"` key vs. `"findings"` key) is not formally specified.

**Recommendation**: Define a formal discriminated union schema for JSONL batch output: every record should have a `type` field (`"report"` or `"error"`) with consistent sibling fields for each variant.

---

## 8. CLI Surface

### 8.1 Command Coverage

The CLI is comprehensive. 11 top-level commands covering all major use cases: scan, query (with interactive REPL), sandbox, diff, config, ML management, documentation, stream analysis, and correlation.

The `scan` command is particularly thorough, with fine-grained control over analysis depth, resource limits, output formats, and ML mode. This is appropriate for a tool targeting both automated pipelines and manual forensic analysis.

### 8.2 User Experience Issues

**Inconsistent flag naming**: `--json` is shorthand for `--format json`, but there is no `--jsonl` shorthand equivalent for `--format jsonl`. Users familiar with `--json` will reach for `--jsonl` and be confused.

**`--diff-parser` naming**: The flag enables secondary parser (lopdf) validation for structural deviation detection. The name implies it runs a diff, but the purpose is actually parser divergence detection. `--secondary-parser` or `--strict-parse` would be clearer.

**`--deep` vs. `--fast` vs. `--strict`**: There are three independent analysis depth modifiers, and their interactions are not documented. Does `--deep --fast` mean "fast but deeper than default"? Does `--strict` imply `--deep`? The help text should describe how these compose.

**`--focus-trigger` and `--focus-depth`**: These flags are not explained in the help output that was reviewed. Their purpose and interaction with standard scan modes should be documented.

### 8.3 The `sis generate` Command

A `Generate` subcommand is listed but not described in the explored code. The purpose is unclear. If it generates synthetic test fixtures, detection rules, or report templates, it should be documented. If it is incomplete or experimental, it should be gated or removed.

### 8.4 Interactive REPL

The REPL mode via `rustyline` is a good feature for interactive forensic analysis. The command history and completion functionality should be tested for correctness with the full query type set.

---

## 9. GUI Surface

### 9.1 Panel Coverage

The GUI covers all major analysis dimensions: findings, chains, metadata, objects, hex viewer, revision timeline, events, graph (structure + event + content stream), detail, summary, and a command bar for ad-hoc queries. This is an impressive surface area for a Rust-native GUI.

### 9.2 WASM vs. Native Divergence

The WASM build is functional and deployable. The native build is incomplete (no `sis gui` subcommand entry point yet, no non-blocking analysis thread). The divergence between the two targets is managed via `cfg(target_arch = "wasm32")` conditionals, which is the correct approach.

**Issue**: In native mode, analysis runs on the main thread, blocking the UI. For large PDFs, this is a significant UX problem. The plan (20260222-native-binary.md) addresses this, but until it is implemented, the native GUI is not production-usable for typical workloads.

### 9.3 Graph Visualisation

The force-directed graph layout is functional. Three graph modes (structure, event, content stream) are navigable and interoperate. The auto-activation of content stream graph mode on node selection is a good UX decision (implemented in 427c89d).

**Issue**: The graph layout is force-directed without persistent node positions. Each time a panel is rendered or mode is switched, nodes will re-settle. For forensic review, reproducible layouts are important — analysts need to annotate and revisit specific subgraph structures. Node positions should persist within a session at minimum.

### 9.4 Filtering and Sorting

The findings panel supports filtering by severity, attack surface, and confidence threshold. Sorting by column is supported. These are the right primitives.

**Issue**: There is no cross-panel finding-to-chain navigation. Selecting a finding does not highlight or navigate to chains that contain it, and selecting a chain does not highlight its constituent findings. This cross-panel linkage would significantly improve triage workflow.

### 9.5 Image Preview in Malware Samples

The image preview panel renders decoded images from the PDF. When analysing malware samples, this may decode and render content from adversarial image streams (JBIG2, JPX, or steganographic payloads). The analysis module imposes limits on decode, but the rendering path (converting decoded pixel data to a displayable image in egui) should be reviewed for safety.

**Recommendation**: Ensure image rendering in the GUI uses a size cap and does not render images that failed during malware analysis with `High` or `Critical` image findings attached to them, without explicit user acknowledgement.

---

## 10. Test Coverage & Quality

### 10.1 Coverage Summary

| Layer | Test Files | Quality |
|---|---|---|
| sis-pdf-core | 40 | High: full pipeline tests, schema validation, performance gates |
| sis-pdf-detectors | 36 | High: fixture-driven, pattern-specific |
| sis-pdf-pdf | 7 | Moderate: parser, decode, typed graph, classification |
| js-analysis | 7 | High: adversarial rewrites, dynamic signals, corpus regression |
| font-analysis | 2 | Moderate: integration + static; dynamic analysis less covered |
| image-analysis | 2 | Moderate: static findings, dynamic limits |
| sis-pdf-gui | Inline | Low: no scenario/E2E tests |
| sis-pdf (CLI) | None | Gap: no CLI integration tests |

### 10.2 Strengths

- **Fixture-driven integration tests** throughout core and detectors. The corpus (CVE PDFs, XFA forms, encrypted documents, filter chain PDFs, shadow attack PDFs) is comprehensive.
- **Performance gates** (`runtime_profile.rs`) enforce the parse <10ms, detect <50ms SLOs.
- **JSON schema validation** of output is tested for core findings and chains.
- **Corpus regression tests** (`corpus_captured_regressions.rs`) guard against silent behaviour drift.
- **Deterministic tests** — no flaky timing-dependent assertions.

### 10.3 Gaps

**No CLI integration tests**: The `sis` binary has no integration test suite. A test that exercises `sis scan <fixture>` and validates stdout schema is essential for regression detection on the user-facing interface.

**No batch mode tests**: The `--path` directory scan mode and JSONL batch output are untested at the integration level.

**Font dynamic analysis under-tested**: The TTF VM and Type 1 CharString interpreter have only integration-level tests. Property-based or fuzz testing would give higher assurance for these parsers given their complexity.

**No adversarial test fixtures for evasion**: The test suite covers detection of known attack patterns, but does not include fixtures designed to evade specific detectors (e.g., a PDF that uses entropy-padding to defeat entropy heuristics, or a carefully crafted shadow attack below the detection threshold). Negative test fixtures are important for a security tool.

**GUI has no scenario tests**: Panel rendering, state transitions, and cross-panel interactions are not tested programmatically. At minimum, smoke tests should verify that analysis completes and panels initialise without panic for a representative fixture set.

### 10.4 Fuzz Coverage

`fuzz/` contains targets for the parser. This is appropriate. Recommend adding fuzz targets for:
- Stream decoding pipeline (filters in combination)
- Font analysis (Type 1 CharString, CFF, TTF)
- JavaScript static analysis (token extraction, decode_layers)
- XFA XML parsing

---

## 11. Code Quality & Safety

### 11.1 Safety and Memory

`#![forbid(unsafe_code)]` is enforced in all core crates. All major dependencies are pure-Rust or use well-maintained FFI wrappers. No known supply chain issues identified.

The GUI crate (`sis-pdf-gui`) depends on `eframe`/`egui`/`glow`/`glutin` which contain unsafe code internally (necessary for OpenGL), but this is accepted and appropriate for the use case.

### 11.2 Error Handling

Error handling is generally good. All public APIs return `Result`. The `anyhow` crate is used for error propagation. No `unwrap()` calls were found in production paths.

**Issue**: Several `expect()` calls exist in CDR integration code (`cdr.rs`). These are in what appears to be integration/utility code rather than the hot path, but any `expect()` in Rust is a potential panic. These should be converted to structured error returns.

**Issue**: Floating-point arithmetic in entropy calculations and density ratios has no NaN/infinity guards. A stream with zero length passed to an entropy function could produce a division-by-zero or NaN, which would then propagate silently through metadata as `"NaN"` strings.

### 11.3 Duplicated Utility Code

The following logic is duplicated across crates and should be consolidated:

| Function | Locations | Recommended Home |
|---|---|---|
| `shannon_entropy()` | `js-analysis/static_analysis.rs` + likely others | `sis-pdf-core` utility module |
| `provenance_label()` / `object_provenance_label()` | `font_exploits.rs`, `image_analysis.rs` | `sis-pdf-core::model` |
| `resolve_dict()` / `resolve_dict_from_obj()` | `shadow_attacks.rs`, `font_exploits.rs` | `sis-pdf-pdf::graph` |
| Cycle detection (DFS with visited set) | `page_tree_anomalies.rs`, `object_cycles.rs` | `sis-pdf-core::graph_walk` |
| `resolve_stream()` | `font_exploits.rs` + similar pattern in others | `sis-pdf-pdf::graph` |

### 11.4 `correlation.rs` Size

At 77 KB, `correlation.rs` is the largest single file and a maintenance liability. No individual correlation rule is unreasonable in isolation, but the file as a whole is difficult to audit, test, or extend without understanding all of it.

**Recommendation**: Refactor into one module per correlation domain (e.g., `correlation/js_action.rs`, `correlation/image_exploit.rs`, `correlation/shadow.rs`). Each domain module exports its correlation functions and has its own test coverage.

### 11.5 `main.rs` in sis-pdf at 5,817 LOC

The CLI entry point is a single 5,817-line file. The query handler at 13,155 LOC (`query.rs`) is also very large. While neither is necessarily wrong (the CLI is inherently verbose), the `main.rs` should delegate to command modules rather than containing all logic inline.

### 11.6 ScanOptions Debug-Based Fingerprinting

The cache key for `FindingsCache` uses `format!("{:?}", options)`. This will silently break if:
- A new field is added with a non-deterministic `Debug` output
- Field ordering changes in a derived `Debug` implementation
- A dependency changes how it formats its own Debug output

This is a time bomb. The cache may serve stale results after a code change, which is particularly dangerous in a security tool.

---

## 12. Documentation State

### 12.1 `ARCHITECTURE.md` — Critically Stale

Must be rewritten. Currently describes a completely different project:
- Lists `sis-pdf-cli`, `sis-pdf-storage`, `sis-pdf-discovery` — none exist
- Describes SeaORM and SQLite persistence — not used
- References `proj describe` commands — wrong binary name
- ADR table references a different decision set

This document actively misleads contributors. It should be replaced or completely rewritten before any external collaboration.

### 12.2 `AGENTS.md` — Largely Accurate

`AGENTS.md` is a good operational guide. Minor issues:
- Confidence levels listed as `Strong/Tentative/Speculative` (3 levels) vs. the actual 6 levels in the Rust model
- Performance SLO table could be updated to reflect current test fixtures
- Finding metadata guidance would benefit from a reference table of standard keys

### 12.3 `docs/` — Adequate but Sparse

`docs/findings.md` documents 72+ JavaScript finding IDs, which is useful. The query interface documentation is good. However:
- No user guide covering the overall analysis workflow (scan → query → interpret)
- No worked examples with realistic malicious PDFs
- No documentation of what each output format is optimised for
- No documentation of the confidence/severity calibration rationale

### 12.4 Plans

Active plans are clearly written and well-tracked. The pattern of staging implementation into numbered stages with explicit success criteria is good practice. The plans are more current and more accurate than the architecture documentation.

---

## 13. Findings & Recommendations

Grouped by priority.

### Priority 1: Correctness and Safety Issues

**R1. Fix page tree cycle detection** (`sis-pdf-core/src/page_tree.rs`)
Add a `seen: HashSet<(u32, u16)>` alongside the existing depth counter. A cycle within the depth limit is not currently detected. This is a known issue in MEMORY.md that has not been resolved.

**R2. Remove `expect()` calls from production paths** (`cdr.rs` and others)
Convert all `expect()` calls to structured `Result` returns. Document why each call site cannot fail, or handle the failure case explicitly.

**R3. Guard floating-point operations against NaN/infinity**
All entropy, density, and ratio computations should check for zero denominators and clamp or return early with a safe default rather than propagating NaN through metadata.

**R4. Replace Debug-format cache key with explicit stable hash**
Implement a `hash_for_cache()` method on `ScanOptions` that explicitly selects which fields affect cache validity, using a stable serialisation (e.g., a canonical byte sequence via `Hash` + `DefaultHasher` with documented field inclusion).

**R5. Remove or implement `--csv` scan output**
The `--csv` flag for scan output is not implemented. Either implement it or remove the flag to avoid silent failures or user confusion.

### Priority 2: Data Model Coherence

**R6. Remove `Finding.position` (deprecated field)**
Migrate all detectors using the single `position` field to use `positions`. Remove the `position` field from the struct. Add a deprecation notice in the next commit message for auditability.

**R7. Define a metadata key registry**
Create a documented constant set (or a `meta_keys.rs` module) with `pub const` names for all standard metadata keys used in chain scoring, intent analysis, and correlation. Replace bare string literals in `chain_score.rs`, `intent.rs`, and `correlation.rs` with references to these constants.

**R8. Add typed metadata accessors to Finding**
Implement `meta_bool`, `meta_f64`, `meta_u32`, `meta_str` helper methods on `Finding` that handle parsing and return `Option`. Replace scattered `parse::<T>()` calls throughout consumers.

**R9. Make `impact` non-optional or add `Impact::Unknown`**
All findings should have an explicit impact. Audit all detectors and assign an impact. Use `Impact::Unknown` as a transitional value for findings that have not yet been assessed.

**R10. Reconcile `action_type`/`action_target`/`action_initiation` fields with metadata**
Pick a single representation for action-related finding context (either typed struct fields or `meta` HashMap entries). Remove the duplicate.

**R11. Validate chain finding ID references in report assembly**
Add a validation pass when assembling `Report` that checks all `ExploitChain.findings` IDs against the present `Finding.id` values. Emit a warning or error on dangling references.

**R12. Document and disambiguate the two chain scoring systems**
Either remove `ActionChain.risk_score()` from the public surface (treating it as an internal pre-correlation value), or clearly document its relationship to `ExploitChain.score`. These should not both be visible at the output boundary.

### Priority 3: Architecture and Maintainability

**R13. Rewrite `ARCHITECTURE.md`**
The current file is dangerously stale. Write a replacement that accurately reflects the current workspace: 9 crates, their responsibilities, the data flow, the detector interface, and the key design decisions actually in use.

**R14. Refactor `correlation.rs` into domain modules**
Break `correlation.rs` (77 KB) into a `correlation/` module directory, one file per correlation domain. Each domain file should export its correlation functions and have its own unit tests.

**R15. Cache `TypedGraph` in `ScanContext`**
Pre-build a single `TypedGraph` during scan setup and share it across all detectors that need it. This likely requires changing ownership semantics (e.g., storing an `Arc<TypedGraph>` or using an owned structure built by cloning relevant object data). The performance gain will be significant for complex documents.

**R16. Consolidate duplicated utility functions**
Move `shannon_entropy`, `provenance_label`, `resolve_dict`, `resolve_stream`, and the DFS cycle detection pattern into shared utility locations (`sis-pdf-core` or `sis-pdf-pdf` as appropriate). Remove the duplicates.

**R17. Add Cost enforcement in CI via runtime profiler**
Run the profiler against the standard fixture set in CI. Assert that `Cost::Cheap` detectors complete within a budget (e.g., 10ms), `Cost::Moderate` within 100ms, and `Cost::Expensive` within a configured limit. Fail the build if a detector self-declares as `Cheap` but exceeds the budget.

### Priority 4: Detection Gaps

**R18. Add XFA → JavaScript bridge tracking**
XFA scripts can invoke JavaScript through the XFA object model. Either instrument this statically (trace `xfa.resolveNode`, `xfa.event`, etc. in the XFA script extractor to produce synthetic JavaScript findings) or, if the JavaScript sandbox supports it, feed extracted XFA scripts through it with appropriate runtime profile.

**R19. Add Form XObject recursion depth tracking in content streams**
Mirror the Type 3 charproc depth tracking (already present in font analysis) for `Do` operators in page content streams. Flag content streams with `Do`-call depth exceeding a threshold.

**R20. Add AcroForm widget tree depth cap**
Add an explicit depth limit (e.g., `MAX_FORM_FIELD_DEPTH = 32`) when traversing `/Kids` hierarchies in AcroForm fields. Generate a finding if the depth limit is reached, similar to page tree anomalies.

**R21. Cross-reference NTLM hash capture via form submit targets**
`uri_classification.rs` and `external_target.rs` should explicitly flag UNC paths (`\\server\share\`) in SubmitForm targets, GoToR targets, and annotation URI actions, regardless of scheme obfuscation. The NTLM hash capture via PDF render is a well-documented attack vector.

**R22. Add negative (evasion) test fixtures**
Create a small set of fixtures designed to test that entropy-padding does not suppress findings that should still be detected by other signals, and that confidence values correctly reflect the evasion attempt. These fixtures should be registered in the manifest and included in corpus regression.

### Priority 5: Output and Interface Quality

**R23. Standardise JSONL batch record schema**
Define a formal discriminated union for JSONL batch output records with a `type` field (`"report"` | `"error"`) and stable sibling schemas for each variant. Add a JSON schema test for both variants.

**R24. Reconcile confidence level documentation**
Update `AGENTS.md`, `docs/findings.md`, and any JSON schema to accurately reflect the 6-level confidence model (`Certain`, `Strong`, `Probable`, `Tentative`, `Weak`, `Heuristic`). Remove the stale 3-level description (`Strong/Tentative/Speculative`).

**R25. Clarify `--deep`, `--fast`, `--strict` interaction**
Document (in `--help` output and in docs) the precedence and composition rules for these three flags. If they are mutually exclusive, enforce that at parse time and give a clear error message.

**R26. Add cross-panel finding ↔ chain navigation in GUI**
Selecting a finding in the findings panel should scroll the chains panel to the chains containing that finding (and vice versa). This is the most impactful single UX improvement for triage workflows.

**R27. Persist graph node positions within a GUI session**
Store the force-directed layout node positions in `SisApp` state so that switching panel modes or navigating away and back does not re-settle the layout. Reproducible layouts are important for forensic annotation.

**R28. Gate image rendering on finding severity in GUI**
Do not automatically render decoded image content for images with attached `High` or `Critical` findings in the image preview panel. Instead, display the metadata and a "render anyway" confirmation prompt. This avoids any risk from adversarial image content being surfaced through the rendering pipeline.

### Priority 6: Testing Infrastructure

**R29. Add CLI integration test suite**
Add tests under `crates/sis-pdf/tests/` that exercise `sis scan`, `sis query`, and `sis diff` as processes, validate stdout for schema conformance, and check exit codes. Cover the happy path and at least two error paths (corrupt PDF, missing file).

**R30. Add fuzz targets for font analysis and stream decoding**
Add `cargo-fuzz` targets for: the Type 1 CharString interpreter, the TTF hinting VM, the stream filter decode pipeline (multi-filter chains), and the XFA XML parser. These are the highest-complexity parsers processing untrusted input.

**R31. Add GUI smoke tests against fixtures**
Add tests that instantiate `SisApp`, load a fixture PDF, run analysis, and assert that all panels initialise without panic and that the finding count matches expectations. These can run headlessly via `eframe`'s testing support.

---

## Appendix: Quick Reference — Key File Locations

| Concern | File |
|---|---|
| Finding / Report model | `sis-pdf-core/src/model.rs`, `report.rs` |
| Scan pipeline | `sis-pdf-core/src/scan.rs`, `runner.rs` |
| Detector trait | `sis-pdf-core/src/detect.rs` |
| Correlation rules | `sis-pdf-core/src/correlation.rs` |
| Intent analysis | `sis-pdf-core/src/intent.rs` |
| Chain scoring | `sis-pdf-core/src/chain_score.rs` |
| Event graph | `sis-pdf-core/src/event_graph.rs` |
| PDF parser | `sis-pdf-pdf/src/parser.rs`, `graph.rs` |
| Typed graph / edges | `sis-pdf-pdf/src/typed_graph.rs` |
| Path finding / ActionChain | `sis-pdf-pdf/src/path_finder.rs` |
| Decode pipeline | `sis-pdf-pdf/src/decode.rs` |
| Page tree | `sis-pdf-core/src/page_tree.rs` |
| All detector modules | `sis-pdf-detectors/src/*.rs` |
| JS static analysis | `js-analysis/src/static_analysis.rs` |
| JS sandbox | `js-analysis/src/dynamic.rs` |
| Font analysis | `font-analysis/src/` |
| Image analysis | `image-analysis/src/` |
| ML graph | `sis-pdf-ml-graph/src/` |
| CLI entry | `sis-pdf/src/main.rs` |
| Query handler | `sis-pdf/src/commands/query.rs` |
| GUI app state | `sis-pdf-gui/src/app.rs` |
| Architecture doc (stale) | `ARCHITECTURE.md` |
| Active plans | `plans/` |
