# Non-Form Attack Surface Expansion Plan

Date: 2026-02-19
Status: Proposed
Owner: Detection pipeline (`sis-pdf-detectors`, `sis-pdf-core`, `sis-pdf-pdf`)
Related: `plans/20260219-detection-uplift.md` (form-focused phase)

## Implementation status update (2026-02-19)

- Completed: WS8 outbound-capable metadata baseline (initial):
  - Added normalised egress metadata on `action_remote_target_suspicious`:
    - `egress.channel`
    - `egress.target_kind`
    - `egress.user_interaction_required`
    - chain context (`chain.stage=egress`, `chain.capability=remote_action_target`, `chain.trigger=action`)
  - Added shared egress metadata for baseline action findings emitted by `action_by_s` for `/SubmitForm`, `/URI`, `/GoToR`, and `/GoToE`.
  - Added correlation bridge `injection_to_remote_action` (`composite.injection_edge_bridge`) linking injection findings to `action_remote_target_suspicious` when object lineage co-locates.
  - Added regression coverage for detector metadata and correlation exploit-context metadata.
- Completed: WS8 outbound-risk classification refinement (initial):
  - Enhanced `action_remote_target_suspicious` indicator model with URI-behaviour signals for remote targets:
    - exfiltration/query pattern detection,
    - userinfo credential embedding,
    - non-standard port usage,
    - shortener/suspicious host traits and path extension risk.
  - Added normalised egress risk metadata:
    - `egress.indicator_count`
    - `egress.risk_score`
    - `egress.risk_class` (`low`, `medium`, `high`, `critical`)
  - Preserved low-noise behaviour for benign HTTPS/relative targets (no suspicious finding emission without risk indicators).
  - Added regression coverage for:
    - benign vs exfiltration-style remote target separation,
    - execute+egress chain-severity escalation guardrail on correlation bridges.
- Completed: WS1 trigger-surface uplift for nested `/Next` and `/AA` context normalisation (initial):
  - Extended action-chain traversal metadata with `/Next` telemetry:
    - `action.next.depth`
    - `action.next.branch_count`
    - `action.next.max_fanout`
    - optional `action.next.has_cycle=true` on cycle detection
  - Added normalised trigger-context metadata across action-trigger findings:
    - `action.trigger_context` (`open_action`, `aa`, `annotation_action`, `field_action`, `field_aa`)
    - `action.trigger_event_normalised` (for example `/OpenAction`, `/O`, `/K`)
    - normalised chain context (`chain.stage=execute`, `chain.capability=action_trigger_chain`, context-derived `chain.trigger`)
  - Added synthetic distributed fixtures for:
    - nested `/Next` chain fan-out from `/OpenAction`,
    - `/AA` automatic-event trigger-context normalisation.
- Completed: WS1 baseline action-presence trigger metadata normalisation (initial):
  - `open_action_present`, `aa_present`, and `aa_event_present` now emit normalised trigger metadata:
    - `action.trigger_context`
    - `action.trigger_event` and `action.trigger_event_normalised`
    - `action.trigger_type` (for AA events)
  - Added consistent exploit-chain context on these findings:
    - `chain.stage=execute`
    - `chain.capability=action_trigger_chain`
    - context-derived `chain.trigger` (`open_action`, `additional_action`)
  - Added detector integration coverage for OpenAction and AA event metadata invariants.
- Completed: WS1 initiation-aware correlation quality uplift (initial):
  - `composite.resource_external_with_trigger_surface` now classifies trigger initiation path:
    - `composite.trigger_path` (`automatic_or_hidden`, `user_only`)
    - initiation counters (`composite.trigger_automatic_count`, `composite.trigger_user_count`, `composite.trigger_hidden_count`, `composite.trigger_unknown_count`)
  - Severity/confidence guardrails are now initiation-aware:
    - automatic/hidden trigger presence: `High` + `Strong`
    - user-only trigger paths: `Medium` + `Probable`
  - `composite.injection_edge_bridge` now includes optional edge initiation metadata:
    - `edge.initiation.from`
    - `edge.initiation.to`
  - Added regression assertions for initiation-aware correlation metadata and severity/confidence behaviour.
- Completed: WS1 event-graph initiation propagation uplift (initial):
  - Finding-provenance outcome edges in `event_graph` now fall back to trigger metadata when `action_initiation` is unset:
    - `action.initiation`
    - `action.trigger_type`
  - Finding-provenance edge metadata now also falls back to trigger event metadata:
    - `action.trigger_event_normalised`
    - `action.trigger_event`
  - Added regression coverage ensuring finding-produced outcome edges preserve user-trigger initiation semantics for `/AA` event findings.
- Completed: WS2 JavaScript source-lineage metadata uplift (initial):
  - `js_present` now emits source lineage metadata for container disambiguation:
    - `js.source`
    - `js.container_path`
    - `js.object_ref_chain`
  - Expanded source extraction inventory for JS payload candidates to include:
    - catalog `/OpenAction` JavaScript path
    - `/AA` event action JavaScript paths
    - annotation `/A` and `/AA` JavaScript paths
    - catalog `/Names -> /JavaScript` name tree values
    - direct catalog JavaScript keys
  - Added mixed-container regression fixture covering open-action, name-tree, annotation, and multi-vector single-object JS surfaces with duplicate-finding guard assertions.
- Completed: WS2 source-aware correlation enrichment (initial):
  - `action_chain_malicious` now propagates JS lineage context from participating JS findings:
    - `js.source_classes`
    - `js.container_paths`
    - `js.object_ref_chains`
  - `composite.injection_edge_bridge` now carries optional JS provenance edge metadata when available:
    - `edge.js.source.from`
    - `edge.js.source.to`
    - `edge.js.container_path.from`
    - `edge.js.container_path.to`
  - Added regression assertions for JS lineage propagation in correlation composites.
- Completed: WS3 annotation rendering and chain-context uplift (initial):
  - `pdfjs_annotation_injection` now emits annotation context metadata:
    - `annot.subtype`
    - `annot.trigger_context` (`annotation_render_only`, `annotation_action`, `mixed`)
    - `annot.action_trigger_count`
    - source/decode context (`injection.sources`, optional `injection.normalised`, `injection.decode_layers`)
    - chain context (`chain.stage=render`, `chain.capability=annotation_injection`, `chain.trigger=annotation_render`)
  - `annotation_action_chain` and `annotation_hidden` now emit annotation subtype/trigger metadata:
    - `annot.subtype`
    - `annot.trigger_context`
    - normalised trigger metadata (`action.trigger_context`, `action.trigger_event`, `action.trigger_event_normalised`, `action.trigger_type`)
  - Added new correlation edges for annotation exploit path connectivity:
    - `pdfjs_annotation_injection -> annotation_action_chain` (`edge.reason=annotation_injection_to_action`)
    - `pdfjs_annotation_injection -> js_present(js.source=annotation*)` (`edge.reason=annotation_injection_to_js`)
  - Added regression coverage for distributed annotation payloads and annotation-edge bridge metadata invariants.
- Completed: WS4 font/renderer bridge quality uplift (initial):
  - Expanded `pdfjs_font_injection` detection and metadata quality:
    - added encoding obfuscation subsignal `encoding_scriptlike_names`,
    - added uncommon structural subsignal `uncommon_subtype_combo`,
    - attached renderer/chain context metadata (`renderer.profile`, `renderer.precondition`, `chain.*`, `font.subtype`).
  - Enhanced `pdfjs_eval_path_risk` context modelling:
    - emits renderer assumptions (`renderer.profile=pdfjs`, `renderer.precondition=pdfjs_font_eval_path_reachable`),
    - propagates participating font subtype classes via `font.subtypes`,
    - emits render-stage chain context metadata.
  - Improved `font_js_exploitation_bridge` quality and prioritisation signals:
    - co-location-aware confidence and severity guardrails,
    - edge-quality metadata (`bridge.co_location`, `bridge.shared_object_count`, optional `bridge.shared_objects`),
    - renderer/chain context metadata for exploit-path explainability.
  - Added regression coverage for new font subsignals, renderer metadata invariants, and co-located bridge confidence uplift.
- Completed: WS5 embedded artefact relationship and mismatch uplift (initial):
  - `embedded_file_present` now emits normalised relationship and family metadata:
    - filespec linkage (`embedded.relationship.filespec_present`, `embedded.relationship.binding`)
    - declared vs observed typing (`embedded.extension_family`, `embedded.declared_subtype`, `embedded.declared_family`, `embedded.magic_family`)
    - chain context (`chain.stage=decode`, `chain.capability=embedded_payload`, `chain.trigger=embedded_file`)
  - Added detector `embedded_type_mismatch` for extension/subtype/magic disagreement with structured mismatch axes:
    - `embedded.family_mismatch=true`
    - `embedded.mismatch_axes` (for example `extension_vs_magic,subtype_vs_magic`)
  - Added correlation composite `composite.embedded_relationship_action` linking embedded mismatch findings to action surfaces (`/Launch`, `/GoToR`, `/GoToE`) via object/hash lineage.
  - Added detector/core regression coverage for Filespec-linked mismatched embedded payloads and composite exploit-chain metadata invariants.
- Completed: WS6 structural evasion and graph-manipulation uplift (initial):
  - Added structured graph-evasion metadata across structural findings:
    - `graph.evasion_kind`
    - `graph.depth`
    - `graph.conflict_count`
    - decode-stage chain context (`chain.stage`, `chain.capability`, `chain.trigger`)
  - Fixed object-cycle traversal to detect cycles reliably by checking active recursion stack before visited-cache short-circuit.
  - Enriched object-graph findings with execution proximity context:
    - cycle overlap metadata (`graph.execute_overlap_count`) for `object_reference_cycle`
    - execute-surface inventory metadata (`graph.execute_surface_count`) for `object_reference_depth_high`
  - Added correlation composite `composite.graph_evasion_with_execute` linking graph-evasion findings with execute-stage surfaces.
  - Added regression coverage for:
    - cycle/deep-indirection metadata invariants,
    - incremental/xref graph metadata invariants,
    - graph-evasion correlation composite semantics.
- Completed: WS7 rich media and 3D surface uplift (initial):
  - Enforced conservative baseline semantics for feature-presence findings:
    - `richmedia_present`, `3d_present`, and `sound_movie_present` now default to low-severity, viewer-dependent context with explicit preconditions.
  - Added normalised viewer/runtime metadata for media surfaces:
    - `viewer.feature`
    - `viewer.support_required`
    - `viewer.support_matrix`
    - `renderer.profile`
    - `renderer.precondition`
    - render-stage chain context metadata (`chain.stage=render`, `chain.capability`, `chain.trigger=viewer_feature`)
  - Added rendition external-target enrichment on `sound_movie_present`:
    - `media.rendition_present`
    - optional `media.external_target`
    - egress metadata (`egress.channel=media_rendition`, `egress.target_kind=remote`, `egress.user_interaction_required=true`)
  - Added correlation composite `composite.richmedia_execute_path` linking richmedia/3D findings with execute/egress findings when object lineage co-locates.
  - Added regression coverage for:
    - conservative richmedia metadata invariants,
    - rendition external-target metadata,
    - richmedia execute-path correlation semantics.

## Objective

Expand exploit-chain coverage beyond forms by adding structured detection, correlation, and explainability across non-form PDF attack surfaces commonly used in malicious documents.

## Scope

In scope:
- Action and trigger abuse.
- JavaScript container and script source expansion.
- Annotation rendering and appearance-stream injection.
- Font/renderer exploitation indicators.
- Embedded artefact and file-relationship abuse.
- Structural evasion and graph-manipulation tactics.
- Rich media and 3D execution-capable features.
- External fetch and exfiltration vectors outside form workflows.

Out of scope:
- Building a new sandbox execution engine in this phase.
- Replacing existing query/report transport formats.

## Workstreams and technical starting points

## WS1: Actions and trigger surfaces (`/OpenAction`, `/AA`, `/Launch`, `/URI`, `/GoTo*`, `/Rendition`)

Technical starting points:
- `crates/sis-pdf-detectors/src/lib.rs`
  - existing action detectors (`action_by_s`, `SubmitFormDetector`, URI/action patterns)
  - add/extend dedicated detectors for trigger context and initiation semantics
- `crates/sis-pdf-core/src/model.rs`
  - ensure `action_type`, `action_target`, `action_initiation` are consistently populated
- `docs/findings.md`
  - define or refine finding IDs for high-risk action chains

Initial implementation tasks:
- Add detector coverage for trigger vectors often paired with payload staging:
  - `/OpenAction` with indirect refs and nested `/Next`
  - `/AA` entries on page/annotation dictionaries
  - `/Launch` and file-opening actions with path/target metadata
- Normalise action metadata fields for all action findings.
- Add chain hints (`chain.stage=execute`, `chain.capability=action_trigger`).

Baseline tests:
- `crates/sis-pdf-core/tests/` integration fixtures for each action family.
- Assert `kind`, `severity`, `confidence`, and `action_*` invariants.

## WS2: JavaScript container expansion (catalog, name trees, actions, XFA)

Technical starting points:
- `crates/sis-pdf-detectors/src/lib.rs`
  - current JavaScript extraction/classification helpers
- `crates/js-analysis/`
  - static/dynamic behaviour analysis outputs available for bridging
- `crates/sis-pdf-core/tests/fixtures/` and `crates/js-analysis/tests/fixtures/`

Initial implementation tasks:
- Extend source extraction inventory to map script origin precisely:
  - catalog `/Names` -> `/JavaScript`
  - action `/JS` payloads with object lineage
  - XFA script-bearing streams/packets
- Add source-specific metadata:
  - `js.source`
  - `js.container_path`
  - `js.object_ref_chain`
- Correlate static container risk with runtime behaviour findings.

Baseline tests:
- Mixed-source fixture where script appears in multiple containers.
- Assert source disambiguation and no duplicate finding spam.

## WS3: Annotation rendering and appearance-stream injection paths

Technical starting points:
- `crates/sis-pdf-detectors/src/lib.rs`
  - `PdfjsRenderingIndicatorDetector`
  - annotation dictionary checks (`/AP`, `/Contents`)
- `crates/sis-pdf-pdf/`
  - stream/object decoding primitives for appearance streams

Initial implementation tasks:
- Expand annotation payload classification beyond token-only checks:
  - appearance stream decoding and bounded inspection
  - rich text-like annotation content with context-aware matching
- Track annotation subtype and trigger path metadata:
  - `annot.subtype`
  - `annot.trigger_context`
- Add correlation edges from annotation injection to action/js execution findings.

Baseline tests:
- Fixtures combining annotation `/AP` payload and action trigger.
- Assert linked chain metadata and shared object refs.

## WS4: Font/renderer exploitation indicators and bridge quality

Technical starting points:
- `crates/sis-pdf-detectors/src/lib.rs`
  - `pdfjs_font_injection`, `pdfjs_eval_path_risk`, font-related helpers
- `docs/performance.md`
  - runtime profiling command and SLO baseline expectations

Initial implementation tasks:
- Refine font risk scoring signals:
  - suspicious encoding/value patterns
  - CMap anomalies and uncommon subtype combinations
- Improve bridge finding quality between renderer-risk and script-capable findings.
- Attach renderer assumptions in metadata:
  - `renderer.profile`
  - `renderer.precondition`

Baseline tests:
- Corpus-captured regressions with malicious font structures.
- Assert severity/confidence consistency and bridge invariants.

## WS5: Embedded artefacts and file-relationship abuse

Technical starting points:
- `crates/sis-pdf-detectors/src/lib.rs`
  - embedded file and MIME/extension heuristics
- `scripts/extract_js_payloads.py`
  - helper path for payload extraction workflows
- fixture manifests under `crates/sis-pdf-core/tests/fixtures/corpus_captured/manifest.json`

Initial implementation tasks:
- Strengthen embedded artefact triage:
  - mismatch checks (extension vs subtype vs content markers)
  - risky relationship mappings (`/Filespec`, launch/open chains)
- Add metadata for extraction routing and provenance.
- Correlate embedded artefact findings with action triggers (`/Launch`, `/GoToR`).

Baseline tests:
- Fixtures with benign and malicious embedded relationships.
- Assert no halting on extraction/parsing errors and stable error metadata.

## WS6: Structural evasion and object-graph manipulation

Technical starting points:
- `crates/sis-pdf-pdf/` graph/xref handling modules
- `crates/sis-pdf-detectors/src/lib.rs`
  - existing xref/deviation-related findings
- prior plans: `plans/20260208-xref-conflict-refinement.md`, `plans/20260218-graph-uplift.md`

Initial implementation tasks:
- Detect and surface evasive graph tactics relevant to exploit delivery:
  - conflicting xref/object identity patterns
  - deep indirection and cycle-heavy reference graphs near executable content
  - suspicious incremental update overlays
- Emit structured graph-evasion metadata:
  - `graph.evasion_kind`
  - `graph.depth`
  - `graph.conflict_count`

Baseline tests:
- Regression fixtures with known xref/graph evasions.
- Assert deterministic findings in strict and non-strict modes.

## WS7: Rich media and 3D feature surfaces

Technical starting points:
- `crates/sis-pdf-detectors/src/lib.rs`
  - existing action/media-related parsing utilities
- `crates/sis-pdf-pdf/` object traversal for `/RichMedia`, `/3D`, `/Rendition`

Initial implementation tasks:
- Add detectors for execution-adjacent multimedia features:
  - rich media activation paths
  - 3D JavaScript/hooks where present
  - rendition actions tied to external resources
- Include viewer support assumptions and confidence constraints.

Baseline tests:
- Synthetic fixtures validating feature presence without over-claiming exploitability.
- Assert `Impact::Low`/`Info` defaults unless corroborated by execution indicators.

## WS8: External fetch and exfiltration vectors (non-form)

Technical starting points:
- `crates/sis-pdf-detectors/src/lib.rs`
  - URI/action detectors, network-like indicator helpers
- `crates/sis-pdf-core/src/query.rs` and related query output paths
  - expose network/exfil metadata for triage queries

Initial implementation tasks:
- Expand detection for outbound-capable vectors:
  - URI actions with suspicious schemes/hosts
  - remote go-to targets and external content fetch patterns
- Add normalised exfil metadata:
  - `egress.channel`
  - `egress.target_kind`
  - `egress.user_interaction_required`
- Correlate egress indicators with injection/execution findings into chain edges.

Baseline tests:
- Fixtures covering benign URLs vs suspicious data-exfil style targets.
- Assert chain severity only escalates when execution + egress evidence co-occur.

## Cross-cutting chain and detail quality requirements

1. Standardise metadata keys for all new findings:
- `chain.stage`
- `chain.capability`
- `chain.trigger`
- `exploit.preconditions`
- `exploit.blockers`
- `exploit.outcomes`

2. Ensure explain/query visibility:
- Add chain-aware query output path (`--with-chain` when implemented).
- Keep JSON/JSONL machine-parseable and field-stable.

3. Enforce aggregation discipline:
- Group repeated equivalent events by stable key.
- Avoid duplicate findings when enrichment of existing findings is sufficient.

## Delivery phases

1. Phase A: WS1 + WS8
- Establish strong trigger/egress baseline and immediate chain value.

2. Phase B: WS2 + WS3
- Improve execution-surface fidelity across JS containers and annotations.

3. Phase C: WS4 + WS6
- Harden renderer and graph-evasion modelling.

4. Phase D: WS5 + WS7
- Finalise embedded and rich-media surfaces.

## Baseline validation workflow

1. `cargo test -p sis-pdf-detectors`
2. `cargo test -p sis-pdf-core`
3. `cargo test -p sis-pdf-core --test corpus_captured_regressions`
4. Runtime profile check:
- `sis scan crates/sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf --deep --runtime-profile --runtime-profile-format json`

Record deltas (new findings, severity/confidence changes, runtime shifts) in this plan as workstreams complete.

## Baseline validation snapshot (2026-02-19)

Executed:
1. `cargo test -p sis-pdf-detectors`
2. `cargo test -p sis-pdf-core`
3. `cargo test -p sis-pdf-core --test corpus_captured_regressions`
4. `cargo run -p sis-pdf --bin sis -- scan crates/sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf --deep --runtime-profile --runtime-profile-format json`

Observed deltas:
- Detector-suite failure:
  - `crates/sis-pdf-detectors/tests/js_sandbox_integration.rs`
  - `sandbox_emulation_breakpoint_tracks_loop_iteration_limit_bucket`
  - assertion mismatch on expected loop-iteration bucket metadata (`loop_iteration_limit`).
- Core-suite and targeted corpus regression failure:
  - `crates/sis-pdf-core/tests/corpus_captured_regressions.rs`
  - `corpus_captured_noisy_likely_noise_bucket_stays_stable`
  - expected `content_stream_anomaly` finding absent.
- Runtime profile command succeeded:
  - `total_duration_ms=16`
  - parse phase: `0 ms`
  - detection phase: `4 ms` (`25.0%`)
  - findings summary: `total=12` (`High=2`, `Medium=4`, `Low=4`, `Info=2`)
  - correlation signal note: `composite.graph_evasion_with_execute` present in output.

Immediate follow-up:
- Triage and stabilise the two failing baseline tests before using these results as the phase completion gate.
- Preserve the runtime profile output above as the current Stage-0.5 reference point for this workstream sequence.

## Risks and mitigations

- Risk: finding volume growth and analyst noise.
  - Mitigation: strict aggregation rules, confidence gating, chain-based prioritisation.
- Risk: performance regression on very large corpora.
  - Mitigation: bounded traversal/decode passes, staged profiling at each phase.
- Risk: inconsistent semantics across findings.
  - Mitigation: shared metadata schema and docs updates alongside each workstream.

## Definition of done

1. Non-form surfaces are covered by dedicated or enriched detectors with documented semantics.
2. Chain connectivity across trigger -> execute -> egress is visible in metadata and explain output.
3. New coverage includes regression fixtures and corpus-backed validation.
4. Throughput and stability remain within existing operational constraints.
