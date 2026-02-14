# Modern candidate examination plan (corpus triage)

Date: 2026-02-14  
Status: In progress  
Owner: `sis-pdf-core` + `sis-pdf-detectors`

## 1) Objective

Rapidly triage high-signal modern malware PDF candidates from `tmp/corpus` and produce a curated reference set for deeper research and regression fixtures.

## 2) Candidate set (phase 1)

Initial unique hashes selected from corpus heuristic ranking:

1. `8d42d425d003480d1acc9082e51cb7a2007208ebef715493836b6afec9ce91bc.pdf`
2. `9ff24c464780feb6425d0ab1f30a74401e228b9ad570bb25698e31b4b313a4f4.pdf`
3. `38851573fd1731b1bd94a38e35f5ea1bd1e4944821e08e27857d68a670c64105.pdf`
4. `f91d503e3752813ecc0f4766140e94e4cdcdb488c81df38dab786aa2ccdfaf2e.pdf`
5. `a54d2448c10f63a4949e0f5ae4430cf60e2f13b543e2cf6bdd052a99f8fec461.pdf`

## 3) Triage method

For each candidate hash:

1. Locate at least one available daily path in `tmp/corpus`.
2. Run:
   - `sis scan <file> --json` (fast baseline),
   - `sis scan <file> --deep --json` (deeper signal confirmation, bounded timeout).
3. Extract summary:
   - finding count by severity,
   - modern-pattern finding kinds present,
   - chain count and URI/JS/supply-chain related chain signals.
4. Assign a triage label:
   - `Priority-A` (strong modern multi-signal sample),
   - `Priority-B` (interesting but narrower signal),
   - `Priority-C` (low confidence for modern-technique reference use).

## 4) Output artefacts

1. Candidate summary table (hash, path, modern kinds, severity profile, label).
2. Recommended reference subset (target: 3–5 hashes).
3. Follow-up actions for deep reverse-analysis and fixture capture.

## 5) Execution status

- [x] Build candidate hash list from corpus heuristic ranking.
- [x] Run bounded fast + deep scans for each candidate.
- [x] Produce triage labels and reference subset recommendation.
- [x] Record next-step deep-analysis queue.

## 6) Execution log

### 6.1 Run configuration

- Fast: `sis scan <file> --json` with `20s` timeout.
- Deep: `sis scan <file> --deep --json` with `45s` timeout.
- Note: for this candidate set, deep output matched fast output (no extra findings under current detector paths).

### 6.2 Candidate triage results

| Hash | Path used | Fast findings | High/Critical | Chains | Modern finding kinds | Label |
|---|---|---:|---:|---:|---|---|
| `8d42d425...` | `tmp/corpus/mwb-2026-01-16/8d42d425d003480d1acc9082e51cb7a2007208ebef715493836b6afec9ce91bc.pdf` | 96 | 36 | 95 | `pdfjs_eval_path_risk`, `renderer_behavior_divergence_known_path`, `renderer_behavior_exploitation_chain`, `revision_annotations_changed`, `revision_anomaly_scoring` | **Priority-A** |
| `9ff24c46...` | `tmp/corpus/mwb-2026-01-15/9ff24c464780feb6425d0ab1f30a74401e228b9ad570bb25698e31b4b313a4f4.pdf` | 148 | 36 | 134 | `js_runtime_dormant_or_gated_execution`, `pdfjs_eval_path_risk`, `supply_chain_update_vector` | **Priority-A** |
| `38851573...` | `tmp/corpus/mwb-2026-01-25/38851573fd1731b1bd94a38e35f5ea1bd1e4944821e08e27857d68a670c64105.pdf` | 19 | 6 | 22 | `js_obfuscation_deep`, `js_runtime_dormant_or_gated_execution`, `js_runtime_file_probe`, `pdfjs_eval_path_risk`, `renderer_behavior_divergence_known_path`, `renderer_behavior_exploitation_chain`, `supply_chain_staged_payload`, `supply_chain_update_vector` | **Priority-A** |
| `f91d503e...` | `tmp/corpus/mwb-2026-01-20/f91d503e3752813ecc0f4766140e94e4cdcdb488c81df38dab786aa2ccdfaf2e.pdf` | 37 | 9 | 29 | `js_runtime_network_intent`, `pdfjs_eval_path_risk`, `supply_chain_staged_payload` | **Priority-B** |
| `a54d2448...` | `tmp/corpus/mwb-2026-01-23/a54d2448c10f63a4949e0f5ae4430cf60e2f13b543e2cf6bdd052a99f8fec461.pdf` | 93 | 25 | 91 | `pdfjs_eval_path_risk`, `revision_annotations_changed` | **Priority-B** |

### 6.3 Recommended reference subset (phase 1)

Primary reference hashes for modern-technique analysis:

1. `8d42d425d003480d1acc9082e51cb7a2007208ebef715493836b6afec9ce91bc`
2. `9ff24c464780feb6425d0ab1f30a74401e228b9ad570bb25698e31b4b313a4f4`
3. `38851573fd1731b1bd94a38e35f5ea1bd1e4944821e08e27857d68a670c64105`
4. `f91d503e3752813ecc0f4766140e94e4cdcdb488c81df38dab786aa2ccdfaf2e`

Secondary (revision-heavy renderer signal):

5. `a54d2448c10f63a4949e0f5ae4430cf60e2f13b543e2cf6bdd052a99f8fec461`

### 6.4 Next-step deep-analysis queue

For the four Priority-A/B reference hashes:

1. Run `sis query` drill-down for `actions.chains`, `findings.composite`, `xref.deviations`, and `revisions.detail`.
2. Capture representative stream objects via `sis query <file> stream <obj> <gen> --decode --extract-to`.
3. Promote 2–3 strongest artefacts into corpus-captured regression fixtures with expected modern finding sets.

### 6.5 Deep investigation (phase-1 reference hashes)

This section documents the deeper review of attack vectors, object-graph chain behaviour, likely operator objective, and whether each candidate is suitable as a modern reference artefact.

#### 6.5.1 `8d42d425d003480d1acc9082e51cb7a2007208ebef715493836b6afec9ce91bc`

- **Primary attack vector:** renderer-behaviour divergence plus revision-layer annotation/action inflation.
- **Exploit-chain shape:** high chain volume with action-oriented paths; renderer catalogue flags `action_handling_divergence_path`, `attachment_open_behavior_path`, and `js_execution_policy_divergence_path`; revision analysis reports 31 added annotations and action/JS changes in revision 1.
- **Techniques observed:** cross-renderer policy asymmetry abuse, incremental-update layering, annotation surface expansion, and mixed malformed stream pressure.
- **Likely intent/outcome:** maximise execution reliability by relying on viewer-specific behaviour while obscuring malicious transitions inside later revisions.
- **Assessment:** strong modern evasion/reference sample (especially renderer + revision interplay).

#### 6.5.2 `9ff24c464780feb6425d0ab1f30a74401e228b9ad570bb25698e31b4b313a4f4`

- **Primary attack vector:** staged embedded-file supply-chain lure with dormant/gated JavaScript runtime behaviour.
- **Exploit-chain shape:** dense chain graph, embedded file name `IEEE.joboptions`, supply-chain update indicators (`version`), and large JS payload (55,730 bytes) that executes without behavioural activity across all five runtime profiles.
- **Techniques observed:** likely delayed trigger or environment-gated execution, payload parking in embedded object streams, and static artefact seeding for follow-on delivery.
- **Likely intent/outcome:** social or workflow-driven activation where malicious behaviour appears only under specific post-delivery conditions not yet emulated.
- **Assessment:** high-value gated-execution sample for runtime stimulation and profile hardening work.

#### 6.5.3 `38851573fd1731b1bd94a38e35f5ea1bd1e4944821e08e27857d68a670c64105`

- **Primary attack vector:** multi-stage chain combining OpenAction trigger, embedded payload, renderer divergence, and explicit file-extraction API use.
- **Exploit-chain shape:** OpenAction-linked chain (`doc:r0/catalog.openaction@9:0`) with `supply_chain_staged_payload`, `renderer_behavior_exploitation_chain`, and `js_runtime_file_probe`; runtime telemetry shows consistent `exportDataObject` calls across all profiles.
- **Techniques observed:** staged payload packaging (`gdvvvv.doc`), launch/update semantics, cross-renderer path variance (`open_action_js_path` included), and deterministic file-oriented runtime behaviour.
- **Likely intent/outcome:** reliable initial execution followed by embedded artefact extraction and downstream execution/side-loading.
- **Assessment:** best phase-1 modern reference (cleanly demonstrates trigger → stage → runtime bridge with strong telemetry).

#### 6.5.4 `f91d503e3752813ecc0f4766140e94e4cdcdb488c81df38dab786aa2ccdfaf2e`

- **Primary attack vector:** annotation-triggered JavaScript download intent using `app.launchURL`.
- **Exploit-chain shape:** staged payload finding with execution bridge (`annotation_action`) and explicit fetch target (`http://yourserver/malicious.exe`); runtime network behaviour is divergent (observed in PDF-reader profile, absent in browser/node/bun profiles).
- **Techniques observed:** profile-selective activation, explicit URL launch primitive, and likely downloader pattern.
- **Likely intent/outcome:** force user-assisted or reader-native network retrieval of external executable content.
- **Assessment:** useful behavioural specimen for profile divergence and network-intent calibration.

#### 6.5.5 `a54d2448c10f63a4949e0f5ae4430cf60e2f13b543e2cf6bdd052a99f8fec461`

- **Primary attack vector:** heavy revision/annotation expansion with limited direct runtime confirmation.
- **Exploit-chain shape:** revision 1 introduces 19 annotations (multiple stream objects and font structures), with `pdfjs_eval_path_risk` present but no strong runtime action bridge in current telemetry.
- **Techniques observed:** structural inflation and revision-layer clutter likely used for analyst friction or deferred activation.
- **Likely intent/outcome:** increase analysis cost and preserve optional future trigger points rather than immediate executable behaviour.
- **Assessment:** secondary reference (valuable for revision abuse patterns, weaker as an immediate exploit-chain exemplar).

### 6.6 Updated reference ranking and usage

#### 6.6.1 Recommended phase-1 reference hashes

1. `38851573fd1731b1bd94a38e35f5ea1bd1e4944821e08e27857d68a670c64105` (primary multi-stage baseline)
2. `8d42d425d003480d1acc9082e51cb7a2007208ebef715493836b6afec9ce91bc` (renderer + revision evasion baseline)
3. `9ff24c464780feb6425d0ab1f30a74401e228b9ad570bb25698e31b4b313a4f4` (dormant/gated runtime baseline)
4. `f91d503e3752813ecc0f4766140e94e4cdcdb488c81df38dab786aa2ccdfaf2e` (network-intent divergence baseline)

#### 6.6.2 Secondary reference

- `a54d2448c10f63a4949e0f5ae4430cf60e2f13b543e2cf6bdd052a99f8fec461` for revision-abuse regression and clutter-resilience tests.

### 6.7 Concrete fixture-capture backlog (top 3)

The backlog below is implementation-ready. Each item specifies the exact object anchors, repeatable query commands, and minimum expected finding set to lock into regression tests.

#### 6.7.1 Fixture A — Multi-stage OpenAction + embedded payload

- **Hash:** `38851573fd1731b1bd94a38e35f5ea1bd1e4944821e08e27857d68a670c64105`
- **Source path:** `tmp/corpus/mwb-2026-01-25/38851573fd1731b1bd94a38e35f5ea1bd1e4944821e08e27857d68a670c64105.pdf`
- **Fixture target:** `crates/sis-pdf-core/tests/fixtures/corpus/modern/38851573-openaction-staged.pdf`
- **Primary objects to capture:** `9 0 obj` (OpenAction JS action), `8 0 obj` (embedded stream), `6 0 obj` (pdf.js eval-path surface)
- **Exact capture queries:**
  - `sis query <FILE> actions.chains --deep --format json`
  - `sis query <FILE> object 9 0 --raw`
  - `sis query <FILE> stream 8 0 --decode --extract-to <OUT_DIR>/38851573-obj8.bin`
  - `sis query <FILE> object 6 0 --raw`
  - `sis scan <FILE> --deep --json`
- **Expected findings (minimum):**
  - `renderer_behavior_divergence_known_path` (High/Strong)
  - `renderer_behavior_exploitation_chain` (High/Strong)
  - `supply_chain_staged_payload` (High/Probable)
  - `js_runtime_file_probe` (High/Strong)
  - `supply_chain_update_vector` (Medium/Heuristic)
  - `pdfjs_eval_path_risk` (Info/Strong)

#### 6.7.2 Fixture B — Renderer-divergence + revision abuse chain

- **Hash:** `8d42d425d003480d1acc9082e51cb7a2007208ebef715493836b6afec9ce91bc`
- **Source path:** `tmp/corpus/mwb-2026-01-16/8d42d425d003480d1acc9082e51cb7a2007208ebef715493836b6afec9ce91bc.pdf`
- **Fixture target:** `crates/sis-pdf-core/tests/fixtures/corpus/modern/8d42d425-renderer-revision.pdf`
- **Primary objects to capture:** `13 0 obj`–`20 0 obj` (renderer path cluster), `14 0 obj` (widget/action surface), `100 0 obj`/`101 0 obj`/`105 0 obj` (revision-added annotation/font/action-linked structures)
- **Exact capture queries:**
  - `sis query <FILE> actions.chains --deep --format json`
  - `sis query <FILE> revisions.detail --deep --format json`
  - `sis query <FILE> object 14 0 --raw`
  - `sis query <FILE> stream 15 0 --decode --extract-to <OUT_DIR>/8d42d425-obj15.bin`
  - `sis query <FILE> object 100 0 --raw`
  - `sis query <FILE> object 101 0 --raw`
  - `sis scan <FILE> --deep --json`
- **Expected findings (minimum):**
  - `renderer_behavior_divergence_known_path` (High/Strong)
  - `renderer_behavior_exploitation_chain` (High/Strong)
  - `revision_annotations_changed` (Medium/Probable)
  - `revision_anomaly_scoring` (Low/Tentative)
  - `pdfjs_eval_path_risk` (Info/Strong)

#### 6.7.3 Fixture C — Dormant/gated JS supply-chain lure

- **Hash:** `9ff24c464780feb6425d0ab1f30a74401e228b9ad570bb25698e31b4b313a4f4`
- **Source path:** `tmp/corpus/mwb-2026-01-15/9ff24c464780feb6425d0ab1f30a74401e228b9ad570bb25698e31b4b313a4f4.pdf`
- **Fixture target:** `crates/sis-pdf-core/tests/fixtures/corpus/modern/9ff24c46-gated-supply-chain.pdf`
- **Primary objects to capture:** `76 0 obj` (embedded stream + dormant JS locus), `117 0 obj`/`119 0 obj` (pdf.js eval-path font surfaces)
- **Exact capture queries:**
  - `sis query <FILE> actions.chains --deep --format json`
  - `sis query <FILE> object 76 0 --raw`
  - `sis query <FILE> stream 76 0 --decode --extract-to <OUT_DIR>/9ff24c46-obj76.bin`
  - `sis query <FILE> object 117 0 --raw`
  - `sis query <FILE> object 119 0 --raw`
  - `sis scan <FILE> --deep --json`
- **Expected findings (minimum):**
  - `supply_chain_update_vector` (Medium/Heuristic)
  - `js_runtime_dormant_or_gated_execution` (Low/Tentative)
  - `pdfjs_eval_path_risk` (Info/Strong)

#### 6.7.4 Regression harness tasks

- [x] Copy the three source PDFs into the fixture targets above.
- [x] Add integration tests under `crates/sis-pdf-core/tests/` asserting the expected finding kinds for each fixture.
- [x] Assert key metadata invariants for each fixture:
  - Fixture A: `js.runtime.calls` contains `exportDataObject`.
  - Fixture B: `revision.annotations_added_count >= 20` and `revision.anomaly.max_score >= 5`.
  - Fixture C: `js.runtime.behavior.name == dormant_or_gated_execution` and `js.runtime.profile_calls_ratio == 0.00`.
- [x] Add a corpus-capture note in `plans/` linking fixture source hash/date to test file names for provenance tracking.

Corpus-capture provenance note:

- `38851573fd1731b1bd94a38e35f5ea1bd1e4944821e08e27857d68a670c64105` (`tmp/corpus/mwb-2026-01-25/...`) -> `crates/sis-pdf-core/tests/fixtures/corpus_captured/modern-openaction-staged-38851573.pdf` (validated in `crates/sis-pdf-core/tests/corpus_captured_regressions.rs`).
- `8d42d425d003480d1acc9082e51cb7a2007208ebef715493836b6afec9ce91bc` (`tmp/corpus/mwb-2026-01-16/...`) -> `crates/sis-pdf-core/tests/fixtures/corpus_captured/modern-renderer-revision-8d42d425.pdf` (validated in `crates/sis-pdf-core/tests/corpus_captured_regressions.rs`).
- `9ff24c464780feb6425d0ab1f30a74401e228b9ad570bb25698e31b4b313a4f4` (`tmp/corpus/mwb-2026-01-15/...`) -> `crates/sis-pdf-core/tests/fixtures/corpus_captured/modern-gated-supplychain-9ff24c46.pdf` (validated in `crates/sis-pdf-core/tests/corpus_captured_regressions.rs`).

### 6.8 Font heuristic calibration (2026-02-14)

Objective: validate the font hinting heuristic refinement against both clean and corpus-captured malicious fixtures.

#### 6.8.1 Run configuration

- Benign sweep:
  - `cargo run -q -p sis-pdf --bin sis -- scan --deep --path resources/samples/out/ --jsonl-findings`
- Malicious sweep:
  - `cargo run -q -p sis-pdf --bin sis -- scan --deep --path crates/sis-pdf-core/tests/fixtures/corpus_captured/ --jsonl-findings`
- Baseline comparison:
  - Pre-tuning benign snapshot: `/tmp/sis-clean-out-findings.jsonl`
  - Post-tuning benign snapshot: `/tmp/calib-benign.jsonl`
  - Post-tuning malicious snapshot: `/tmp/calib-malicious.jsonl`

#### 6.8.2 Severity summary table

| Dataset | Files | Findings | High | Medium | Low | Info |
|---|---:|---:|---:|---:|---:|---:|
| Benign (pre-tuning baseline) | 11 | 117 | 5 | 40 | 46 | 26 |
| Benign (current) | 11 | 106 | 0 | 34 | 46 | 26 |
| Malicious (current) | 6 | 291 | 71 | 85 | 101 | 34 |

#### 6.8.3 Font finding calibration table

Format: `total/high/medium/low/info`.

| Finding kind | Benign pre | Benign current | Malicious current |
|---|---|---|---|
| `font.multiple_vuln_signals` | `5/5/0/0/0` | `0/0/0/0/0` | `2/0/0/2/0` |
| `font.ttf_hinting_torture` | `6/0/6/0/0` | `0/0/0/0/0` | `0/0/0/0/0` |
| `font.ttf_hinting_push_loop` | `5/0/5/0/0` | `5/0/5/0/0` | `10/0/10/0/0` |
| `font.ttf_hinting_suspicious` | `25/0/0/25/0` | `25/0/0/25/0` | `25/0/2/23/0` |

#### 6.8.4 Interpretation

- The clean-suite false-positive Highs were removed (`High: 5 -> 0`).
- The aggregate font escalation no longer auto-promotes hinting-only patterns to High.
- In malicious fixtures, hinting signals persist as supporting telemetry (`push_loop`, `suspicious`), while aggregate severity is context-gated.
- Example: `modern-gated-supplychain-9ff24c46.pdf` now emits `font.multiple_vuln_signals` as `Low/Tentative` with `aggregate.profile=hinting_only_sparse`.

#### 6.8.5 Follow-up tuning guardrails

1. Keep `font.multiple_vuln_signals` High only when at least two non-hinting medium/high font findings co-occur.
2. Keep hinting-only profiles at `Low/Tentative` or `Medium/Tentative` unless storm/stack-pressure criteria are met.
3. Re-run this calibration table after any change in:
   - hinting VM thresholds,
   - aggregate severity gating,
   - font dynamic parse classification.
