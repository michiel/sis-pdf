# sis modernisation plan against 2020-2026 PDF malware evolution

Date: 2026-02-13  
Status: Proposed  
Input: `docs/research/2026013-pdf-malware-evolution.md`

## 1) Executive assessment

`sis` is well-positioned for several modern attack classes, but not yet complete for full 2026-era operational coverage.

### Current strengths
1. Strong structural-evasion coverage:
   - parser differentials (`parser_diff_structural`, `object_shadow_mismatch`)
   - ObjStm evasions (`empty_objstm_padding`, `objstm_*`)
   - revision/shadow manipulation (`shadow_*`, `certified_doc_manipulation`)
2. Strong JavaScript behavioural coverage:
   - sandbox runtime patterns, unknown-behaviour closure workflows, fingerprint/evasion detection
   - modern JS signal set (heap, obfuscation, semantic source-sink, runtime chain patterns)
3. Strong decoder/zero-click risk indicators:
   - JBIG2 exploit-style signals and decoder risk chains
   - deep stream/filter anomaly and entropy telemetry
4. Mature telemetry and corpus operations:
   - two-pass corpus sweeps, dedup, summary telemetry, gate-based validation.

### Key gaps
1. Passive render-pipeline attack modelling is incomplete:
   - limited dedicated detection for UNC/SMB credential leak pathways and preview/indexer-triggered exfil profiles.
2. Multi-viewer differential rendering is partial:
   - parser differential exists, but not full cross-renderer differential semantics (Adobe/Foxit/PDFium/Preview class parity).
3. XFA/XML hardening and XXE-focused controls need uplift:
   - XFA findings exist; explicit XXE-style entity risk modelling and backend-ingest safety scoring need strengthening.
4. Remote template/style staged-fetch modelling is fragmented:
   - signals exist indirectly via URI/action findings, but no first-class “remote staged template” capability with robust chain semantics.
5. 3D rich-media exploit analysis depth is limited:
   - surface exists, but deep U3D/PRC structural validation and exploit-pattern heuristics are not comprehensive.
6. CDR-oriented sanitisation workflow is missing:
   - detection is strong; deterministic disarm/rebuild mode is not yet present.
7. Fountain-code style payload analysis is early-stage:
   - high entropy detection exists, but fountain-style packetised shellcode reconstruction heuristics are limited.

## 2) Coverage mapping (research theme -> sis position)

1. RenderShock/passive execution: **Partial**
2. Polyglot/chameleon parser ambiguity: **Strong-Partial**
3. Advanced obfuscation/high-entropy payload staging: **Partial**
4. Remote template injection and staged fetch: **Partial**
5. JS fingerprinting/evasion/forced execution behaviours: **Strong**
6. XFA/XML (including XXE-adjacent risk): **Partial**
7. 3D (U3D/PRC) attack surface: **Early-Partial**
8. AI-driven metamorphism resilience: **Partial**
9. Dynamic analysis depth and side-channel-aware instrumentation: **Partial**

## 3) Target state (modern use readiness)

1. High-confidence detection for passive no-click and preview-triggered exfiltration paths.
2. Cross-viewer differential risk scoring beyond parser-only divergence.
3. Explicit XFA/XML entity-resolution risk modelling for backend parser pipelines.
4. First-class staged remote payload/template chain detection.
5. Deep rich-media (U3D/PRC) structural exploit heuristics.
6. Optional CDR mode for operational sanitisation workflows.
7. Stronger obfuscation decoding for fountain-like and packetised payload structures.

## 4) Detailed technical roadmap (PR-sized)

## PR-M1: Passive render pipeline and credential-leak detector pack

Objective: detect preview/index-triggerable external resource fetch and credential leak patterns.

Changes:
1. Add dedicated findings for:
   - UNC/SMB path references in render-triggered contexts
   - passive external fetch indicators in images/fonts/actions/forms
   - credential-leak risk chain composites (e.g. external UNC + auto-trigger + preview-prone surface)
2. Add metadata:
   - `passive.surface`, `passive.trigger_mode`, `passive.external_protocols`, `passive.credential_leak_risk`
3. Add reader impact profiles for preview/index pipelines.

Test/fixture requirements:
1. Synthetic fixtures for UNC-based fetch, external font/image reference, passive trigger variants.
2. Integration tests asserting severity/impact/confidence calibration and object references.

## PR-M2: Cross-renderer differential semantics engine

Objective: extend parser-diff into renderer-behaviour differential scoring.

Changes:
1. Introduce renderer profile abstraction:
   - Adobe-like, PDFium-like, Preview-like, Foxit-like behaviour classes.
2. For critical surfaces (actions, forms, streams, XFA, JS), compute behaviour deltas per profile.
3. Emit new finding family:
   - `renderer_behavior_divergence`
   - `renderer_behavior_exploitation_chain` when divergence overlaps malicious signals.
4. Add metadata:
   - `renderer.profile_deltas`, `renderer.executable_path_variance`, `renderer.risk_score`.

Test/fixture requirements:
1. Fixtures with known divergent behaviour pathways.
2. Deterministic tests for profile-delta serialisation.

## PR-M3: XFA/XML and XXE-style ingest risk hardening

Objective: close modern XFA/XML backend processing risk gaps.

Changes:
1. Add XML entity/DOCTYPE/DTD detection in XFA payload streams.
2. Add explicit finding:
   - `xfa_entity_resolution_risk`
   - `xfa_backend_xxe_pattern` (risk modelling, not exploit claim).
3. Add backend-ingest risk metadata:
   - `xfa.xml_entity_count`, `xfa.dtd_present`, `xfa.external_entity_refs`, `backend.ingest_risk`.
4. Add remediation mapping for parser-side safe XML configuration and CDR stripping profiles.

Test/fixture requirements:
1. Fixtures for benign XFA, inline entity use, external entity-like patterns.
2. Tests for low/medium/high confidence calibration.

## PR-M4: Staged remote template/payload chain capability

Objective: first-class detect “benign shell, remote payload later” campaigns.

Changes:
1. Add staged-fetch detector over URI/action/XFA/JS surfaces.
2. Emit findings:
   - `staged_remote_template_fetch`
   - `staged_remote_payload_chain`
3. Correlate with launch, automatic triggers, and JS intent for composite severity uplift.
4. Add chain metadata:
   - `stage.count`, `stage.sources`, `stage.fetch_targets`, `stage.execution_bridge`.

Test/fixture requirements:
1. Multi-stage fixtures with and without execution bridge.
2. Composite chain tests for escalation guardrails.

## PR-M5: Rich media (U3D/PRC) deep analysis uplift

Objective: improve detection quality on modern 3D-bearing PDFs.

Changes:
1. Expand `RichMedia3D` parsing checks:
   - structure validity, table bounds, object counts, compressed block sanity.
2. Add findings:
   - `richmedia_3d_structure_anomaly`
   - `richmedia_3d_decoder_risk`
3. Add correlation with high-entropy streams and filter anomalies.

Test/fixture requirements:
1. U3D/PRC benign fixtures and malformed edge cases.
2. Performance tests to enforce bounded decode/parse budgets.

## PR-M6: Fountain-style payload obfuscation analysis

Objective: improve packetised high-entropy payload detection and triage quality.

Changes:
1. Add heuristics for repeated high-entropy packet blocks with index-like structures.
2. Add finding:
   - `packetised_payload_obfuscation`
3. Add metadata:
   - `packet.block_count`, `packet.estimated_index_fields`, `packet.reconstruction_feasibility`.
4. Correlate with execution sinks / launch paths to reduce false positives.

Test/fixture requirements:
1. Synthetic fountain-like and benign compressed packet fixtures.
2. False-positive control tests against normal compressed image/PDF streams.

## PR-M7: CDR mode (safe rebuild path, optional)

Objective: add operational disarm capability for high-risk active content.

Changes:
1. Add `sis disarm` command (or `scan --cdr`) with conservative profile:
   - strip/neutralise JS, Launch, OpenAction, XFA active scripts, risky embedded files.
2. Rebuild PDF with stable audit report:
   - removed elements, object references, residual risk summary.
3. Emit deterministic JSON report for SOC pipelines.

Test/fixture requirements:
1. Round-trip fixtures (malicious input -> sanitised output).
2. Validation tests for output parseability and removal guarantees.

## PR-M8: Modern adaptive sandbox profiles and telemetry depth

Objective: strengthen JS dynamic analysis against 2026 evasion patterns.

Changes:
1. Expand browser/PDF-reader profile matrices for APIs/properties (versioned).
2. Add event-simulation packs for user-interaction-gated payloads.
3. Add path-delta telemetry:
   - per-stage AST/behaviour deltas for self-modifying flow detection.
4. Add finding:
   - `js_runtime_path_morphism`.

Test/fixture requirements:
1. Interaction-gated and morphing JS fixtures.
2. Deterministic runtime profile snapshots for regression.

## 5) Cross-cutting engineering requirements

1. No unsafe code, no unwraps, Rust-native crates only.
2. Every new capability includes:
   - tests
   - representative fixtures
   - `docs/findings.md` updates
   - query/explain output validation where applicable.
3. Preserve JSON schema stability (additive fields only).
4. Enforce bounded resource controls on all new deep parsing/dynamic paths.
5. Add corpus regression checks for each new finding family before rollout.

## 6) Validation gates

### Gate A: Detection quality
1. No regression on existing high-severity P0/P1 corpus set.
2. New modern-technique fixtures detected with expected severity/confidence.

### Gate B: False-positive control
1. Benign corpus false-positive rate does not increase beyond agreed threshold.
2. New composite findings require multi-signal context.

### Gate C: Performance
1. No >10% regression in p95 detection runtime on fixed replay set.
2. Two-pass sweep timeout/scan-error rate remains under operational SLO.

### Gate D: Operational readiness
1. Investigation item extraction recognises new finding families.
2. Trend outputs include new capability coverage counters.

## 7) Recommended implementation order

1. PR-M1 (passive render and credential-leak chains)
2. PR-M3 (XFA/XML ingest risk hardening)
3. PR-M4 (staged remote template/payload chains)
4. PR-M2 (cross-renderer differential semantics)
5. PR-M5 (U3D/PRC deep analysis)
6. PR-M6 (fountain-style obfuscation)
7. PR-M8 (sandbox adaptive depth)
8. PR-M7 (CDR mode, after detection maturity)

## 8) Immediate next step

Start with PR-M1 and PR-M3 in parallel planning, then implement PR-M1 first because it has the highest near-term risk reduction for passive enterprise attack paths.
