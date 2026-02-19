# Non-Form Attack Surface Expansion Plan

Date: 2026-02-19
Status: Proposed
Owner: Detection pipeline (`sis-pdf-detectors`, `sis-pdf-core`, `sis-pdf-pdf`)
Related: `plans/20260219-detection-uplift.md` (form-focused phase)

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
