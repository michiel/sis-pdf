# sis modernisation plan against 2020-2026 PDF malware evolution

Date: 2026-02-13  
Status: Updated (post-review)  
Inputs: `docs/research/2026013-pdf-malware-evolution.md`, `plans/20260213-modernisation-comments.md`

## 1) Executive assessment

`sis` already has strong capability in structural evasion, JavaScript behavioural analysis, parser differential telemetry, and exploit-chain correlation.  
The remaining work is primarily **gap-closing and calibration**, not wholesale subsystem replacement.

Key review-driven adjustments:
1. Add a **PR-M0 capability audit** before further large additions.
2. Rescope PR-M1 as an **incremental uplift** of the existing passive render detector.
3. Narrow PR-M2 to an **actionable renderer divergence catalogue**, not a speculative semantics engine.
4. Tighten PR-M3/PR-M4 to avoid overlap with existing findings and preserve taxonomy consistency.
5. Split CDR into phased delivery (`M7a`, `M7b`) with explicit risk controls.
6. Add missing threat classes to coverage planning:
   - annotation/overlay phishing abuse
   - embedded MalDoc-in-PDF and archive/polyglot attachment chains

## 2) Coverage map (research theme -> sis position)

1. RenderShock/passive execution: **Strong-Partial** (existing detector family present; indexer/hash-leak depth incomplete)
2. Polyglot/chameleon parser ambiguity: **Strong-Partial**
3. Advanced obfuscation/high-entropy payload staging: **Partial**
4. Remote template injection and staged fetch: **Partial** (foundational supply-chain findings exist)
5. JS fingerprinting/evasion/forced execution behaviours: **Strong**
6. XFA/XML (including XXE-adjacent risk): **Partial** (core XFA support exists; entity-risk modelling incomplete)
7. 3D (U3D/PRC) attack surface: **Early-Partial**
8. Annotation/overlay phishing abuse: **Partial**
9. Embedded MalDoc-in-PDF chain analysis: **Partial**
10. Dynamic analysis depth and side-channel-aware instrumentation: **Partial**

## 3) Assumptions and evidence quality guardrails

1. CVE-labelled prioritisation must be sourced and verifiable; where uncertain, prioritise by technique class rather than a single CVE claim.
2. Vendor statistics across mixed methodologies are treated as directional context, not absolute baseline.
3. New detections must map to observed corpus behaviour and fixture-backed regression tests.

## 4) Detailed technical roadmap (PR-sized)

## PR-M0: Baseline capability audit and gap ledger

Objective: prevent redundant implementation and lock a precise delta against current capability.

Changes:
1. Build a findings-to-threat matrix for:
   - passive render/credential leakage
   - staged remote payload chains
   - XFA/XML ingest risk
   - annotation/overlay phishing
   - embedded MalDoc/attachment abuse
2. Identify overlaps, naming conflicts, and unimplemented slices.
3. Produce an explicit “do not duplicate” map for existing findings.

Deliverables:
1. Audit table in `plans/20260213-modenisation.md` appendix.
2. Backlog labels: `new`, `extend-existing`, `calibration-only`.

## PR-M1: Passive render pipeline uplift (extend existing detector)

Objective: close residual passive no-click gaps in existing `passive_render_pipeline` coverage.

Changes:
1. Extend current passive finding family with:
   - indexer/preview trigger context modelling (e.g., search/index workflows)
   - NTLMv2 hash-leak specificity metadata where UNC/SMB patterns are present
   - richer source context mapping for font/image/forms metadata paths
2. Calibrate confidence/severity based on:
   - automatic trigger presence
   - protocol risk class
   - preview/indexer-prone surfaces
3. Keep existing finding IDs stable; add additive metadata only.

Test/fixture requirements:
1. Fixtures for UNC + auto-trigger, UNC + passive render path, HTTP passive fetch control case.
2. Integration tests for severity/confidence calibration and object reference output.

## PR-M2: Renderer divergence catalogue (narrow scope)

Objective: model known renderer-behaviour differences with deterministic rules.

Changes:
1. Create a curated divergence catalogue for known high-value behaviours:
   - action handling differences
   - JS execution policy differences
   - attachment/open behaviour differences
2. Emit catalogue-based findings only where divergence is evidence-backed:
   - `renderer_behavior_divergence_known_path`
   - optional composite only when chained with existing high-risk signals
3. Avoid generic semantics simulation layer.

Test/fixture requirements:
1. Deterministic fixtures that map to known divergence entries.
2. Snapshot tests for divergence metadata serialisation.

## PR-M3: XFA/XML entity-risk hardening (targeted)

Objective: close XML entity/DOCTYPE external-reference risk in XFA ingestion contexts.

Changes:
1. Add DTD/DOCTYPE/entity token detection in XFA payload streams.
2. Add findings:
   - `xfa_entity_resolution_risk`
   - `xfa_backend_xxe_pattern` (risk signal, not exploit claim)
3. Add ingest metadata:
   - `xfa.dtd_present`
   - `xfa.xml_entity_count`
   - `xfa.external_entity_refs`
   - `backend.ingest_risk`
4. Link remediation guidance for safe XML parser configuration.

Test/fixture requirements:
1. Benign XFA XML fixture.
2. Inline-entity fixture.
3. External-entity-like fixture with severity/confidence assertions.

## PR-M4: Staged remote chain uplift (extend existing supply-chain detectors)

Objective: close staged-fetch chain gaps without duplicating existing supply-chain taxonomy.

Changes:
1. Extend existing findings (`supply_chain_*`, `multi_stage_attack_chain`) with richer stage metadata:
   - `stage.sources`
   - `stage.fetch_targets`
   - `stage.execution_bridge`
2. Add one new finding only if required for uncovered behaviour:
   - `staged_remote_template_fetch_unresolved`
3. Correlate with launch/action/js intent for guarded severity uplift.

Test/fixture requirements:
1. Multi-stage fixture with execution bridge.
2. Multi-stage fixture without execution bridge (control).
3. False-positive controls for benign update/check workflows.

## PR-M5: Rich media 3D deep analysis uplift

Objective: improve U3D/PRC anomaly confidence with bounded parsing.

Changes:
1. Add bounded structural checks:
   - header/table bounds
   - object count sanity
   - compressed block sanity
2. Add findings:
   - `richmedia_3d_structure_anomaly`
   - `richmedia_3d_decoder_risk`
3. Correlate with stream anomaly and entropy findings.

Fixture strategy:
1. Synthetic minimal U3D/PRC-like fixtures generated in-repo.
2. Curated malformed edge fixtures from corpus captures where licensing permits.

## PR-M6: Packetised payload obfuscation uplift

Objective: improve detection of repeated high-entropy packet staging patterns.

Changes:
1. Add packet index/sequence heuristics for staged blobs.
2. Add finding:
   - `packetised_payload_obfuscation`
3. Add metadata:
   - `packet.block_count`
   - `packet.estimated_index_fields`
   - `packet.reconstruction_feasibility`
4. Require execution-sink or launch-path corroboration for high severity.

Test/fixture requirements:
1. Synthetic packetised payload fixture.
2. Benign compressed media controls.

## PR-M7a: CDR strip-and-report (phase 1)

Objective: deliver operationally safe removal reporting without full rewrite guarantees.

Changes:
1. Add conservative strip mode and deterministic report output.
2. Remove/neutralise high-risk active elements with explicit audit trail.
3. Mark output as degraded/sanitised; no full fidelity guarantee.

## PR-M7b: CDR safe rebuild (phase 2)

Objective: add validated object-graph rebuild with xref/trailer reconstruction.

Changes:
1. Deterministic rebuild pipeline with reference integrity checks.
2. Parseability and residual-risk verification suite.
3. Explicit exclusion/handling strategy for encrypted and malformed edge cases.

## PR-M8: Sandbox profile and interaction depth uplift

Objective: strengthen runtime analysis against gated and morphing JS.

Changes:
1. Expand profile coverage with explicit capability matrix deltas (no generic “all browsers” claim).
2. Add deterministic interaction simulation packs:
   - dialog gating
   - form workflows
   - timing/event gates
3. Add path-delta telemetry and finding:
   - `js_runtime_path_morphism`
4. Track unresolved API and unresolved callable buckets as first-class telemetry counters.

Test/fixture requirements:
1. Interaction-gated fixtures.
2. Self-modifying/morphing fixtures.
3. Stable telemetry snapshot assertions.

## 5) Cross-cutting engineering requirements

1. No unsafe code, no unwraps, Rust-native crates only.
2. Every new capability includes:
   - tests
   - representative fixtures
   - `docs/findings.md` updates
   - query/explain output validation where applicable
3. Preserve JSON schema stability (additive fields only).
4. Enforce bounded resource controls on all deep parsing/runtime paths.
5. New findings must include correlation guardrails to control false positives.

## 6) Dependency graph and execution order

Dependencies:
1. `M0` -> prerequisite for all subsequent PRs.
2. `M1` -> informs metadata used by `M4`.
3. `M3` -> shared stream/entity logic can support `M6`.
4. `M1 + M3 + M4 + M5 + M6` -> prerequisites for `M7b`.
5. `M8` independent but should land before broad corpus recalibration.

Recommended order:
1. PR-M0
2. PR-M1
3. PR-M3
4. PR-M4
5. PR-M2
6. PR-M5
7. PR-M6
8. PR-M8
9. PR-M7a
10. PR-M7b

## 7) Validation gates with explicit budgets

### Gate A: Detection quality
1. No regressions on existing P0/P1 corpus set.
2. New fixtures hit expected severity/confidence and object references.

### Gate B: False-positive control (budgeted)
1. Overall benign FP increase budget: <= 0.30 percentage points.
2. Per-PR FP budget:
   - M1: <= 0.10pp
   - M3: <= 0.05pp
   - M4: <= 0.10pp
   - M5/M6/M8 combined: <= 0.10pp
3. Composite findings require at least two independent signal families.

### Gate C: Performance (budgeted)
1. Overall p95 runtime regression budget: <= 10%.
2. Per-PR target budget:
   - M1/M3/M4: <= 2% each
   - M2/M5/M6/M8: <= 1.5% each
   - M7a/M7b measured separately as opt-in workflows
3. Sweep timeout/scan-error rate must remain within current operational SLO.

### Gate D: Operational readiness
1. Investigation extraction recognises all new finding families and metadata.
2. Trend dashboards include capability coverage counters.
3. Explain output surfaces new enrichment fields where relevant.

## 8) Immediate next step

Execute PR-M0 completion review, then continue PR-M1 as an incremental uplift of the existing passive render pipeline detector (indexer trigger and NTLMv2-specific enrichment first).
