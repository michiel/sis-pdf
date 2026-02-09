# JavaScript sandbox uplift plan (fingerprint resistance and dynamic intent depth)

## 1. Problem statement

The current JavaScript dynamic analysis is useful for call-level behavioural signals, but it remains vulnerable to environment fingerprinting and incomplete runtime surface simulation. Malicious payloads can detect missing APIs, identify synthetic execution environments, branch into benign paths, or delay malicious behaviour. We also lack first-class change-tracking between runtime-triggered code states (for self-modifying or staged-obfuscation flows).

## 2. Goals

- Make dynamic execution fingerprint resistant across browser-like, Node-like, and PDF-reader-like environments.
- Expand runtime stub completeness for properties/functions by profile and version.
- Capture high-fidelity property/function access telemetry (reads, writes, calls, existence checks, reflection probes).
- Add AST and graph delta analysis between successive execution states to detect obfuscation unfolding and self-modification.
- Improve robustness, determinism, and triage value while preserving safety limits.
- Emulate realistic user behaviour pathways (document open, click, form events, timing) in controlled phases.

## 3. Non-goals

- Perfect engine-level compatibility with every JavaScript runtime.
- Full browser/PDF-renderer reimplementation.
- Unbounded execution or network-enabled “real world” interaction.

## 4. Threat model and evasion classes to address

- **Environment fingerprinting**: checks for missing globals, incorrect property descriptors, bad prototype chains, unnatural error strings, inconsistent timing.
- **Capability gating**: payload only executes when specific APIs appear present.
- **Staged obfuscation**: runtime decoding and code grafting (`eval`, `Function`, string assembly, prototype poisoning).
- **Self-modifying execution**: function body mutation, dynamic property injection/deletion, closure state pivots.
- **User-gated triggers**: malicious path hidden behind event handlers and delayed interactions.
- **Version/vendor branching**: payload behaves differently per browser/PDF reader/Node version.

## 5. Design principles

- **Security-first containment**: no unsafe execution, strict resource caps, deterministic limits.
- **Profiled realism**: emulate specific runtime profiles explicitly, not ad hoc mixed environments.
- **Telemetry before verdicts**: collect rich events first, derive findings from stable aggregations.
- **Diff-driven analysis**: treat runtime as state transitions, not a single snapshot.
- **Reproducibility**: fixed seeds, deterministic scheduler, recorded profile/version identifiers.

## 6. Target architecture

## 6.1 Runtime profile system

Introduce an explicit runtime profile model:

- `runtime.kind`: `pdf_reader`, `browser`, `node`
- `runtime.vendor`: e.g. `adobe`, `foxit`, `chrome`, `firefox`, `nodejs`
- `runtime.version`: semantic or bucketed major version
- `runtime.mode`: `strict`, `compat`, `deception_hardened`

Profile assets should include:

- global object map
- function stubs and return contracts
- property descriptors (`enumerable`, `writable`, accessor presence)
- prototype chain definitions
- error type/message templates
- clock and random behaviour policy

## 6.2 Fingerprint resistance layer

Add a “consistency shim” that enforces coherent runtime traits:

- normalised descriptor semantics for common introspection paths
- realistic `toString()` outputs for native-like functions
- stable, profile-specific exception signatures
- consistent `typeof`, `instanceof`, and prototype traversal results
- controlled noise injection for anti-fingerprint hardening in `deception_hardened` mode

## 6.3 Stub completeness framework

Create a versioned stub registry:

- namespace coverage: `app`, `doc`, `event`, DOM-like, Node core-like, timers, encoding helpers
- per-stub metadata: availability matrix, side effects, taint behaviour, confidence score
- contract tests to ensure return types and thrown errors are stable per profile
- fallback stubs that log unsupported access without breaking execution flow

## 6.4 Runtime telemetry expansion

Capture and persist:

- property reads/writes/deletes
- `in` checks and reflective queries (`hasOwnProperty`, descriptor lookups)
- function calls with canonicalised argument summaries
- dynamic code creation (`eval`, `Function`, indirect eval patterns)
- prototype chain mutations and global scope mutations
- timer/event registration and trigger execution

Normalise into session-level telemetry records to support aggregation and findings.

## 6.5 AST and graph delta engine

For each execution phase:

1. Parse/normalise baseline AST and IR graph.
2. Execute a bounded interaction phase.
3. Re-extract code surfaces (inline, generated, rewritten functions).
4. Re-parse and compute deltas:
   - new nodes/edges
   - removed nodes/edges
   - entropy/control-flow complexity shifts
   - string literal decoding emergence
   - new sink reachability (network/file/launch/eval)
5. Correlate deltas with triggering telemetry events.

Output should include “why changed” context, not just changed artefacts.

## 6.6 User-behaviour emulation engine

Add phase-based scripted interactions:

- `phase.open`: document load lifecycle
- `phase.idle`: timers and deferred callbacks
- `phase.click`: synthetic annotation/button interactions
- `phase.form`: form field population + submit attempts
- `phase.keyboard`: key event probes where relevant

Each phase should be optional, time-bounded, and individually attributable in telemetry.

## 7. Findings and scoring extension

Add/refine findings for:

- runtime fingerprint probing intensity
- profile-gated behaviour divergence
- self-modifying code confidence
- staged deobfuscation progression
- user-interaction-gated malicious intent

Adjust severity/confidence based on:

- multi-profile consistency of suspicious behaviour
- strength of delta evidence (control-flow and sink reachability)
- directness of malicious sinks and trigger path depth

## 8. Implementation workstreams

## WS1: Baseline and profile scaffolding

- Introduce runtime profile schema and loader.
- Add initial profile packs:
  - Adobe Reader-like (selected versions)
  - Foxit-like (selected versions)
  - Chromium-like browser
  - Firefox-like browser
  - Node.js (LTS majors)
- Add config/CLI flags to choose profile set and execution mode.

## WS2: Stub registry and conformance tests

- Build declarative stub definitions and descriptor templates.
- Port existing stubs into registry format.
- Add conformance tests per profile/version (type behaviour, descriptor correctness, exceptions).
- Add unsupported-access logging hooks.

## WS3: Telemetry deepening

- Extend event model for reads/writes/deletes, reflection probes, prototype edits, dynamic code creation.
- Add runtime mutation log with phase and stack context.
- Ensure output remains compact via canonicalisation and aggregation.

## WS4: AST/graph delta analysis

- Add snapshot manager and parser pipeline for pre/post-phase artefacts.
- Implement graph differ and risk feature extraction.
- Correlate deltas to runtime events and emit structured evidence.

## WS5: Behaviour emulation

- Implement deterministic event scheduler and interaction scripts.
- Add profile-aware user gesture simulation.
- Add safeguards against event explosion loops.

## WS6: Multi-profile execution strategy

- Run selected profiles in parallel (bounded).
- Merge results into a profile divergence report:
  - behaviour only in specific profile/version
  - common behaviour across all profiles
- Promote high-confidence findings when malicious behaviour survives profile diversity.

## WS7: Robustness and safety hardening

- Tighten CPU/time/memory ceilings per phase and per file.
- Add graceful degradation for oversized scripts and recursion-heavy cases.
- Add deterministic replay IDs and seed control for debugging.

## WS8: Reporting and query integration

- Extend findings metadata with:
  - `js.runtime.profile`
  - `js.runtime.phase`
  - `js.delta.*`
  - `js.fingerprint.*`
- Add query shortcuts for runtime telemetry and delta summaries.
- Enhance `explain` with phase and profile breakdowns.

## 9. Test strategy

- **Unit tests**: stub contracts, descriptor fidelity, profile loader validation, delta algorithm correctness.
- **Integration tests**: synthetic evasive scripts for each evasion class.
- **Regression corpus**: known malware and pentest fixtures with expected telemetry signatures.
- **Differential tests**: same sample across profiles; assert expected divergence.
- **Performance tests**: enforce per-phase latency/overhead budgets.
- **Stability tests**: repeat-run determinism checks with fixed seeds.

## 10. Suggested additional improvements

- Add lightweight symbolic value tracking for high-risk variables.
- Track string decode lineage (source bytes -> transformed strings -> sink calls).
- Add taint flow from user-controlled objects to execution sinks.
- Capture exception-driven control-flow pivots as first-class signals.
- Add “anti-analysis suspicion” score for deliberate environment checks.
- Add optional snapshot export for post-mortem forensic replay.

## 11. Rollout sequence

1. Land profile schema + minimal two-profile support.
2. Land stub registry and conformance harness.
3. Land telemetry expansion.
4. Land AST/graph delta engine.
5. Land behaviour emulation phases.
6. Enable multi-profile fusion and new findings by default.

## 11.1 Execution checklist (PR-sized milestones)

- [x] **PR-01: Runtime profile model + safety gates**
  - Add `RuntimeProfile`/`RuntimeKind`/`RuntimeMode` to `js-analysis`.
  - Thread profile identity into dynamic output and detector metadata.
  - Keep `#![forbid(unsafe_code)]` boundaries unchanged and add no new `unsafe` blocks.
  - **Done when**: profile ID appears in sandbox output and `js_sandbox` finding metadata.

- [x] **PR-02: Profile-aware stub registration baseline**
  - Register stubs according to profile kind (`pdf_reader`, `browser`, `node`) with deterministic behaviour.
  - Preserve current default compatibility for existing PDF payload fixtures.
  - **Done when**: existing sandbox regression tests pass with default profile.

- [x] **PR-03: Telemetry expansion v1 (integrity-focused)**
  - Emit structured telemetry for reflection probes, dynamic-code calls, and mutation-like operations.
  - Add metadata fields: `js.runtime.reflection_probes`, `js.runtime.dynamic_code_calls`, `js.runtime.prop_writes`, `js.runtime.prop_deletes`.
  - Ensure outputs are deduplicated and bounded.
  - **Done when**: telemetry fields appear in findings/explain for matching samples.

- [x] **PR-04: Query/explain uplift for runtime telemetry**
  - Extend `explain` and query outputs to display profile + new runtime telemetry fields.
  - Keep output machine-parseable and backwards compatible.
  - **Done when**: analysts can inspect these fields without JSON-only workflows.

- [x] **PR-05: Stub conformance harness**
  - Add profile contract tests for key stubs and descriptors.
  - Assert deterministic error signatures and stable return types.
  - **Done when**: profile contract suite validates baseline profiles.

- [x] **PR-06: AST/graph snapshot and delta scaffolding**
  - Introduce snapshot model and a minimal delta computation pipeline.
  - Correlate first-order deltas with runtime phases/events.
  - **Done when**: delta summary metadata is emitted for dynamic code change cases.

- [x] **PR-07: Behaviour emulation phases**
  - Add deterministic phase scheduler (`open`, `idle`, `click`, `form`).
  - Track phase attribution in telemetry.
  - **Done when**: same payload can be evaluated by phase and produces phase-scoped telemetry.

- [ ] **PR-08: Multi-profile fusion + scoring**
  - Execute across selected profiles and merge into divergence summary.
  - Adjust confidence/severity using cross-profile consistency.
  - **Done when**: profile-divergence metadata affects final findings confidence/severity.

- [ ] **PR-09: Integrity and hardening pass**
  - Remove legacy unsafe capture patterns where upstream APIs now permit safe alternatives.
  - Add invariants for event truncation, deterministic ordering, and replay identifiers.
  - **Done when**: no new unsafe added, and integrity invariants are validated by tests.

## 12. Risks and mitigations

- **Complexity growth**: use modular workstreams and strict interfaces.
- **False positives**: require multi-signal corroboration and confidence downgrades when isolated.
- **Performance regression**: phased budgets, sampling, and adaptive short-circuiting.
- **Profile drift**: maintain versioned profile fixtures with contract tests.
- **Telemetry bloat**: aggregate at ingest and cap repeated events.

## 13. Acceptance criteria

- Dynamic sandbox supports explicit profile/version selection with deterministic output.
- Runtime telemetry includes property/function access, mutations, and dynamic code creation.
- AST/graph delta analysis is emitted and correlated to runtime phases.
- At least one new finding each for fingerprint probing and self-modifying behaviour.
- Query/explain can display profile + phase + delta evidence clearly.
- Targeted fixtures demonstrate improved detection for evasion and staged-obfuscation cases.
- Performance and safety budgets remain within documented limits.
