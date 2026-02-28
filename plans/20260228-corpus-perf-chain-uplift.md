# Technical Uplift Plan: Corpus Performance, Chain Architecture, and Detection Uplift
**Date**: 2026-02-28
**Branch**: feature/consistency (baseline)
**Corpus**: mwb-latest (20 PDFs), mwb-2026-02-23 (20 PDFs, 1 hang)
**Method**: Batch scan + per-file deep scan + performance profiling + chain analysis

---

## Executive Summary

A fresh corpus run against 40 malware PDFs (two batches) reveals three critical-severity issues
that block production use, two high-severity chain architecture failures, and a set of medium
findings covering detection gaps and output inconsistencies.

The most urgent issue is a **production-halting performance bug**: the `content_stream_exec_uplift`
detector spends 292 seconds on a single 6 MB, 717-object PDF due to an unbounded O(n²) sliding
window scan. A second slow detector (`content_phishing`) also has no size guards. Both must be
fixed before any corpus-scale batch processing is feasible.

The second critical gap is the **chain architecture**: 98.8% of chains contain exactly one
finding. Chains are not attack paths — they are finding wrappers. The existing `event_graph` and
`behavior_summary` infrastructure is richer than what the chain synthesiser uses. The chain model
needs to be redesigned around correlated finding groups, not individual findings.

This plan extends and supersedes `20260227-corpus-analysis-uplift.md` with today's fresh data.
Where items overlap, this document provides updated success criteria and implementation details.

---

## Corpus Profile (Today's Run)

| File | Tags / Family | Findings | Chains | Multi-chains | Scan time |
|---|---|---|---|---|---|
| 9ff24c4 | font exploit + embedded JS | 139 | 125 | 1 | 8.8s |
| 47476f8 | SAIPEM/Spam-ITA lure | 85 | 81 | 0 | 0.8s |
| 5b293f05 | file-sharecloud phishing | 79 | 78 | 0 | 0.3s |
| 6648302 | APT42 polyglot PDF+ZIP+PE | 12 | 11 | 0 | 1.0s |
| a99903 | RomCom | 22 | 20 | 0 | 0.3s |
| 6eb8b5 | Fog (netlify phishing) | 33 | 34 | 1 | 0.6s |
| 379b41 | Booking.com/Spam-ITA | 22 | 24 | 2 | 0.2s |
| 5bb77b (Feb23) | font heavy | 86 | 69 | 0 | 13.4s |
| 11606a (Feb23) | decompression bomb | 18 | 18 | 0 | 5.0s |
| fb87d8 (Feb23) | **HUNG — 292 sec** | — | — | — | **>292s** |

**Aggregate (batch, 20 files, mwb-latest)**:
- Total findings: 773
- Top finding kinds: `object_reference_cycle` (112), `font.ttf_hinting_suspicious` (77), `image.decode_skipped` (56)
- Critical findings: 5 (0.6%)
- High findings: 110 (14%)
- Multi-finding chains: 1.2% of all chains

---

## Attack Vectors Identified

### AV-1: Font Exploit + Embedded JS (9ff24c4)
**Pattern**: 25 suspicious TTF hinting programs + 21 invalid image colour spaces + embedded
IEEE.joboptions file containing 55 KB compressed payload + JS obfuscation indicators

**Chain produced**: 1 multi-chain (9 findings) with score 0.95
**Missing**: The 25 font findings + 21 image findings generate 46 separate singleton chains.
No chain correlates: "large number of hinting anomalies → heap spray pattern → JS execution".
**Intent**: `Persistence (Strong, score=8)` — correctly categorised
**Gap**: False positive risk — the "JS" is actually an IEEE print preset file, not code.
The tool correctly flags it as obfuscated (dormant) but the sandbox error "unexpected token '<<'"
indicates it tried to execute a PDF dict as JS. No false-positive mitigation in the chain.

### AV-2: APT42 Polyglot PDF+ZIP+PE (6648302)
**Pattern**: Valid PDF with ZIP archive embedded in stream (offset 72 and 891183). ZIP contains
two PE executables: `gcsst` (MZ at offset 40047) and `msvcp140.dll` (MZ at offset 17424).

**Findings produced**:
- `polyglot_signature_conflict/High/Strong`: ZIP@72, ZIP@891183 ✓
- `embedded_payload_carved/Medium/Strong`: ZIP in stream, 888KB, decode failed ✓
- `nested_container_chain/High/Probable` ×2: ZIP→MZ executables ✓
- `pdfjs_eval_path_risk` (Info)
**Missing**: No chain correlates all four findings into "PDF+ZIP polyglot delivering two PE
executables". The three-stage attack path (PDF parse → ZIP extract → PE execute) is not modelled.
**Intent**: `ExploitPrimitive (Heuristic, score=2)` — severely under-scored given the Strong
confidence polyglot detection. Should be `Critical/Certain` for polyglot + nested PE.

### AV-3: Fog Phishing (6eb8b5)
**Pattern**: PDF with reference cycle near `/URI` action → netlify URL with `/Pay` suffix.
Image stream (29 0 obj) has 7 co-located anomaly findings (filter invalid, metadata malformed,
multiple filters, strip dimensions, decode skipped, label mismatch, colour space).

**Chain produced**: 1 multi-chain (3 findings): Object 22 → suspicious remote action → URL ✓
**Behavior summary**: Correctly groups 7 findings by object 29 0 obj
**Missing**: The `behavior_summary` groups are not translated into chains. The 7 co-located
image anomalies on object 29 are not a chain — they are one structural anomaly with 7 signals.

### AV-4: Booking.com JS Phishing (379b41)
**Pattern**: OpenAction → JS with `user_interaction` intent (document.getField, getAnnot) →
two annotation URIs pointing to bookinq/bocking netlify clones.

**Best chain** (7 findings): OpenAction → automatic JS trigger → user_interaction → composite
graph evasion with execute ✓
**Problem**: The same 5 JS-related findings appear across 3 separate chains (7f, 5f, 1f chains).
Finding `js_present` appears in 3 different chains. `renderer_behavior_divergence_known_path`
appears in 2 different chains. No deduplication, no merging.

### AV-5: Decompression Bomb (11606a)
**Pattern**: Two streams with decompression ratio 485:1 (26 MB from 54 KB) and 123:1.
Image declared as `/Image` but contains unknown content. `parser_resource_exhaustion` fires
because content analysis spent 5 seconds on malformed structures.

**Findings**: 2×`decompression_ratio_suspicious/Critical/Strong` ✓, `parser_resource_exhaustion/High/Strong` ✓
**Missing**: No chain correlates decompression bomb + image-declared unknown content + parser
exhaustion into a "DoS/resource exhaustion delivery" attack path.
**Intent**: `ExploitPrimitive (Strong, score=6)` — good, but should also fire `DenialOfService`.

### AV-6: RomCom (a99903)
**Pattern**: 4 font hinting findings + 2 reference cycles + 2 embedded payloads + external URI.

**Findings**: `embedded_payload_carved` ×2, font anomalies, network intent to synlab.de
**Intent**: `DataExfiltration (Heuristic, score=2)`, `ExploitPrimitive (Heuristic, score=2)` —
both are Heuristic despite Strong-confidence individual findings. The intent system is not
accumulating correctly.

---

## Critical Issues (must fix before production use)

---

### CRIT-1: `content_stream_exec_uplift` — O(n²) hang on large PDFs

**Severity**: CRITICAL — production blocker
**Evidence**: fb87d8 (717 objects, 6 MB) causes 292-second scan; detector contributes 293 s total
across batch of 20 files. Any PDF with large content streams will trigger this.

**Root cause** (from source analysis):
`detect_resource_cluster_without_markers()` contains a sliding window scan:
```
for start in 0..=ops.len().saturating_sub(window)
    filter/count ops in window of size ops.len()/10
```
For a content stream with N operations, this is O(N × N/10) = O(N²/10). A page with 10,000
ops creates 9,000 iterations each examining 1,000 elements.

No per-file size limit, no stream size cap, no operation count limit, no timeout guard.

**Fix**:
1. Add `const MAX_CONTENT_OPS: usize = 5_000` — truncate operation list before scanning.
2. Replace the O(n²) sliding window with a single-pass histogram approach:
   count operation types in fixed buckets, then check bucket ratios once.
3. Add a stream byte size guard: skip content streams > 2 MB (return empty results).
4. Add a total-time guard: if cumulative time in this detector exceeds 2 s, log a warning
   and return findings collected so far (same pattern as `content_phishing` hotspot detection).

**Files**: `crates/sis-pdf-detectors/src/content_stream_exec_uplift.rs`

**Test**: Add a fixture with 10,000+ content operations. Assert scan completes in <100 ms.

---

### CRIT-2: `content_phishing` — no size guards on object/stream iteration

**Severity**: CRITICAL — production blocker
**Evidence**: `content_phishing` averages 577 ms per file and peaks at 6,951 ms. Files with many
objects will cause compounding slowdowns. (Previous plan incorrectly reported "no performance
issues".)

**Root cause** (from source analysis):
`detect_html_payload()` iterates ALL objects twice:
1. First pass: extracts strings from every object, lowercase + pattern search.
2. Second pass: decodes every stream, calls `detect_rendered_script_lure()` on decoded content.

`detect_rendered_script_lure()` does a while-loop scan for 6 patterns across the full decoded
stream content with `has_text_operator_context()` called per match.

No object count limit, no stream size limit, no early exit on budget exhaustion.

**Fix**:
1. Add `const MAX_OBJECTS_TO_SCAN: usize = 200` — stop after examining 200 objects.
2. Add `const MAX_STREAM_SCAN_BYTES: usize = 512_000` — truncate decoded stream data.
3. Add `const MAX_MARKER_MATCHES_PER_STREAM: usize = 10` — stop searching for more markers
   after 10 matches in a single stream.
4. Reorder: scan object strings (cheap) before decoding streams (expensive). Exit early if
   no string keyword match found first.

**Files**: `crates/sis-pdf-detectors/src/content_phishing.rs`

**Test**: Fixture with 500+ objects. Assert scan time < 500 ms.

---

### CRIT-3: No scan timeout or per-file circuit breaker in batch mode

**Severity**: CRITICAL — production blocker
**Evidence**: When `content_stream_exec_uplift` hangs, the entire batch blocks. fb87d8 would
block a 500,000-file pipeline for nearly 5 minutes per occurrence.

**Fix**:
1. Add `--timeout-per-file <SECONDS>` CLI flag (default: 60 seconds).
2. In `runner.rs` / batch scan loop, wrap each file scan in a timeout-aware thread.
   On timeout: emit a structured error finding `scan_timeout/High` with elapsed time and
   the current detector name if available, then continue to the next file.
3. In `runtime_profile`, record `timed_out: bool` and `timeout_detector: Option<String>`.
4. The existing `parser_resource_exhaustion` finding pattern is a good model for the output.

**Files**: `crates/sis-pdf-core/src/runner.rs`, `crates/sis-pdf/src/main.rs`

---

## High Priority — Chain Architecture

---

### CHAIN-1: Chain fragmentation — 98.8% singleton chains

**Severity**: HIGH
**Evidence**: Across all scanned files, only 1.2% of chains contain more than one finding.
A file with 139 findings produces 125 chains. This renders the chain output nearly useless for
attack path reconstruction.

**Root cause**:
The chain synthesiser (`chain_synth.rs`) builds chains in two phases:
1. **Object-based grouping**: Groups findings that share the exact same PDF object ID.
   Only works when multiple findings happen to reference the exact same object string (e.g.,
   "1 0 obj"). Rarely fires because findings for different aspects of an attack (font exploit
   in object 5, JS execution in object 12) have different object refs.
2. **Single-finding fallback**: Every finding not grouped in phase 1 becomes its own chain.

The result: 25 font hinting findings on 25 different objects → 25 singleton chains.
The existing `behavior_summary` field (which groups by object) is richer than the chain output.

**Fix — three-tier chain merging**:

**Tier A: Kind-based deduplication** (immediate win, easy)
For findings of the same kind on the same document, create one chain with all findings as members
instead of N singleton chains. Example: 25 `font.ttf_hinting_suspicious` → 1 chain with label
"Font exploitation signals (25 fonts)". Applies to: `font.*`, `image.*`, `object_reference_cycle`,
`label_mismatch_stream_type`, `declared_filter_invalid`.

Implementation: In chain_synth, after building singleton chains, run a post-pass that merges
chains where `finding.kind.split('.')[0]` is the same and the chain contains only one finding.
The merged chain gets the highest severity/confidence from members. Cap merged chains at 50 members.

**Tier B: Object-cluster grouping** (medium effort, high impact)
Use the `behavior_summary` co-occurrence data already computed in the report. For each object
cluster in behavior_summary (e.g., "7 findings share object 29 0 obj"), create one chain containing
all those findings. This directly translates the richer behavior_summary into chains.

Implementation: Pass `behavior_summary` into `synthesise_chains()`. For each cluster with ≥2
findings, create one chain using the cluster's combined findings and assign roles from the
highest-severity finding per role slot.

**Tier C: Cross-object attack path grouping** (high effort, high impact)
Use the event graph to connect findings across different objects when there is an action chain
or data flow relationship. Example: font finding in object 5 + JS finding in object 12 +
embedded file in object 76 → one chain if the event graph shows a path from 5→12→76.

Implementation: Pass `EventGraph` into chain synthesis (partially implemented via
`synthesise_chains_with_event_graph` signature). Walk the event graph from trigger nodes,
collect all reachable findings, and create one chain per connected component.

**Files**: `crates/sis-pdf-core/src/chain_synth.rs`, `crates/sis-pdf-core/src/chain_render.rs`

**Success criteria**: Singleton chain rate drops from 98.8% to ≤ 70%. Files with 100+ findings
produce ≤ 20 chains. Each chain has a meaningful label and ≥2 findings (except truly isolated signals).

---

### CHAIN-2: Chain deduplication — same finding appears in multiple chains

**Severity**: HIGH
**Evidence**: In the booking PDF, `js_present` appears in 3 different chains (7-finding, 5-finding,
and 1-finding chains). `renderer_behavior_divergence_known_path` appears in 2 chains.
This creates confusing output where the same attack step is reported multiple times.

**Root cause**:
There is no deduplication pass after chain synthesis. Chains are built from findings independently,
so the same finding can satisfy the role requirements of multiple chains.

**Fix**:
1. After chain synthesis, sort chains by finding count (descending) then score (descending).
2. Track which finding IDs have been "claimed" by a chain.
3. Remove any chain whose findings are a subset of an already-processed chain's findings.
4. For partially overlapping chains: merge them if their shared findings form ≥50% of either chain.
5. Only keep a finding in one chain (the highest-scoring one that claims it).

**Files**: `crates/sis-pdf-core/src/chain_synth.rs`

**Success criteria**: No finding ID appears in more than one chain in output.

---

### CHAIN-3: Chain completeness always 0.0 — stages not inferred

**Severity**: HIGH
**Evidence**: 97% of chains have `chain_completeness: 0.0`. Even chains with confirmed
trigger/action/payload and evidence of execution have completeness 0.0 because the stage
inference only counts findings with explicit `meta["chain.stage"]` set by detectors.

**Root cause**:
Stage inference is passive — only findings that explicitly set `chain.stage` in metadata
contribute to `confirmed_stages`. Most detectors do not set this field.

**Fix**:
1. Add active stage inference in chain_synth based on assigned roles and finding kinds:
   - If `trigger` role assigned → stage "input" confirmed
   - If `action` role has JS/launch → stage "execute" confirmed
   - If `payload` role is stream/embedded → stage "decode" confirmed
   - If network_intents present for this chain → stage "egress" inferred
   - If image decode anomaly present → stage "render" inferred
2. Adjust completeness formula: `(confirmed × 1.0 + inferred × 0.5) / 5.0`
3. Add `chain.stages_inferred` note when stages are inferred (not from detector metadata).

**Files**: `crates/sis-pdf-core/src/chain_synth.rs`

**Success criteria**: ≥50% of chains with trigger+action assigned have completeness ≥ 0.2.
Chains with trigger+action+payload have completeness ≥ 0.4.

---

### CHAIN-4: Chain schema missing label and severity fields

**Severity**: HIGH
**Evidence**: Chain JSON output has no `label` or `severity` field. The GUI and query interface
display "?" for label and severity. Consumers cannot filter chains by severity without parsing
findings.

**Root cause**:
`ExploitChain` struct has no `label: String` or `severity` field. The `score: f64` (0.0–1.0)
is the only risk indicator.

**Fix**:
1. Add `label: String` to `ExploitChain` (derived from trigger+action+payload labels or kind-based
   dedup group name).
2. Add `severity: Severity` to `ExploitChain` derived from the highest-severity finding in
   the chain (or from score threshold: ≥0.9→Critical, ≥0.75→High, ≥0.5→Medium, else Low).
3. Add `verdict: Option<String>` at the report level: computed from the highest-scoring chain
   with completeness ≥ 0.2.
4. Populate `edges: Vec<String>` to represent object-to-object relationships found in chains.

**Files**: `crates/sis-pdf-core/src/chain.rs`, `crates/sis-pdf-core/src/chain_synth.rs`,
`crates/sis-pdf-core/src/chain_render.rs`

---

## High Priority — Detection Gaps

---

### DET-1: APT42 polyglot chain not assembled

**Severity**: HIGH
**Evidence**: APT42 file (6648302) has `polyglot_signature_conflict`, `embedded_payload_carved`,
and 2×`nested_container_chain` — all High/Strong — but no chain correlates them.
Intent is `ExploitPrimitive (Heuristic, score=2)` despite Strong-confidence findings.

**Fix**:
1. Add composite correlator `correlate_polyglot_dropper()` in `correlation.rs`:
   - Fires when: `polyglot_signature_conflict` + `embedded_payload_carved` + `nested_container_chain`
     all present in the same document.
   - Emits: `polyglot_dropper_chain/Critical/Strong`
   - Sets chain stages: input (polyglot), decode (embedded payload), execute (PE/MZ extraction)
   - Meta: `dropper.inner_format` (zip/mz), `dropper.pe_count`, `dropper.entry_names`
2. In intent scoring, `polyglot_signature_conflict` + `nested_container_chain` (kind=mz) should
   contribute to `ExploitPrimitive` with `Strong` confidence (currently only Heuristic).

**Files**: `crates/sis-pdf-core/src/correlation.rs`, `crates/sis-pdf-core/src/intent.rs`

**Success criteria**: APT42 file produces `polyglot_dropper_chain/Critical` with 4+ findings.
Intent becomes `ExploitPrimitive/Strong score≥8`.

---

### DET-2: Decompression bomb not linked to DoS intent

**Severity**: HIGH
**Evidence**: 11606a produces `decompression_ratio_suspicious/Critical` (ratio 485:1) and
`parser_resource_exhaustion/High` but no `DenialOfService` intent bucket fires.

**Fix**:
1. In `intent.rs`, add `DenialOfService` bucket that scores:
   - `decompression_ratio_suspicious` (ratio ≥ 100): weight 6
   - `parser_resource_exhaustion`: weight 4
   - Both together: confidence `Strong`
2. Add composite finding `decompression_dos_chain` when ratio ≥ 100 and
   `parser_resource_exhaustion` are both present.
3. In chain, link: trigger (stream decode attempt) → action (decompression) → payload
   (resource exhaustion) with stage "render" confirmed.

**Files**: `crates/sis-pdf-core/src/intent.rs`, `crates/sis-pdf-core/src/correlation.rs`

---

### DET-3: Font findings not grouped into exploitation chain

**Severity**: HIGH
**Evidence**: Files with 20+ font anomaly findings (all Medium/Strong) produce 20+ singleton
chains. There is no "font exploitation pattern" summary finding. The individual findings (cmap
range overlap, hinting push loop, multiple vuln signals) are meaningful but fragmented.

**Fix**:
1. Add kind-based chain merging for `font.*` findings (Tier A from CHAIN-1).
2. Add a composite `font_exploitation_cluster` finding when:
   - `font.ttf_hinting_suspicious` count ≥ 5 in one document, OR
   - `font.cmap_range_overlap` + `font.ttf_hinting_push_loop` both present, OR
   - `font.multiple_vuln_signals` present
3. `font_exploitation_cluster/High/Probable` with meta:
   - `font.cluster.count`: number of suspicious fonts
   - `font.cluster.kinds`: distinct finding kinds observed
   - `font.cluster.assessment`: "heap spray pattern" or "CVE exploitation setup"
4. Downgrade individual `font.ttf_hinting_suspicious` from Medium to Low when
   `font_exploitation_cluster` is also emitted (to reduce noise).

**Files**: `crates/sis-pdf-core/src/correlation.rs`, `crates/sis-pdf-detectors/src/font_exploits.rs`

---

### DET-4: Intent scoring not accumulating properly for mixed-confidence findings

**Severity**: HIGH
**Evidence**: RomCom (a99903) has Strong-confidence `embedded_payload_carved` ×2 but intent
scores only as `Heuristic`. APT42 has Strong-confidence polyglot but scores Heuristic.
The intent system is not promoting Heuristic → Strong when high-confidence signals co-occur.

**Root cause** (inferred from intent.rs structure):
Intent bucket confidence is determined independently per bucket. If most signals in a bucket
are Heuristic-weight, the bucket stays Heuristic even when a few Strong signals reinforce it.

**Fix**:
1. In `intent.rs`, add a confidence promotion rule: if a bucket has score ≥ 4 AND contains
   at least one `Strong` or `Certain` confidence finding, promote bucket confidence to `Probable`.
2. If score ≥ 8 AND at least one `Strong` finding → promote to `Strong`.
3. Add `ExploitPrimitive` triggers for: `polyglot_signature_conflict` (weight 4, Strong),
   `nested_container_chain` with PE/MZ (weight 4, Strong).
4. Add `DenialOfService` bucket (see DET-2).

**Files**: `crates/sis-pdf-core/src/intent.rs`

---

### DET-5: `object_reference_cycle` generates excessive findings

**Severity**: MEDIUM
**Evidence**: Files regularly produce 8–25 `object_reference_cycle` findings, dominating the
finding list. Most are normal PDF parent-child references or annotation `/P` back-links.

**Fix**:
1. Implement three-tier classification:
   - `cycle_type: "page_parent"` (already suppressed at Info) — confirmed benign
   - `cycle_type: "annotation_page_parent"` — standard `/P` back-ref → emit Info, not Medium
   - `cycle_type: "action_cycle"` or `"catalog_cycle"` — suspicious → keep Medium/High
2. Aggregate: when the document has > 5 cycles of the same benign type, emit one summary
   finding instead of N individual findings.
3. In the composite `graph_evasion_with_execute`, count only `action_cycle` type cycles
   toward the evasion score (not page/annotation parent cycles).

**Files**: `crates/sis-pdf-detectors/src/object_cycles.rs`, `crates/sis-pdf-core/src/correlation.rs`

**Success criteria**: Files with 20+ page-tree cycles produce ≤ 3 cycle findings (1 summary + 2 signal).

---

### DET-6: Correlate campaign fails silently due to 10 KB line limit

**Severity**: MEDIUM
**Evidence**: `sis correlate campaign` emits multiple warnings:
`JSONL line exceeds size limit [line=594, max_bytes=10240]`
Rich findings (with JS analysis metadata having 100+ keys) exceed 10 KB. These are silently
dropped. The command outputs `{ "c2_domains": [], "campaigns": [] }` — completely empty.

**Fix**:
1. Increase the JSONL line size limit in `correlate campaign` to 1 MB (most findings are
   under 50 KB even with full JS metadata).
2. Add a `--max-line-bytes` flag to make this configurable.
3. Log a warning at the end: "Skipped N findings due to size limit" instead of per-line warnings.
4. Alternatively: pre-strip JS metadata from findings before passing to correlate (keep only
   structural fields needed for campaign correlation).

**Files**: `crates/sis-pdf/src/cmd/correlate.rs` (or equivalent)

---

## Medium Priority — Coverage and Output

---

### COV-1: `image.decode_skipped` findings are not actionable as singletons

**Severity**: MEDIUM
**Evidence**: `image.decode_skipped` appears 56 times in the batch (3rd most common finding),
always as Low severity, always a singleton chain. The finding adds noise without a correlated
context (what is the image suspected of containing?).

**Fix**:
1. Only emit `image.decode_skipped` when co-located with another image anomaly finding on the
   same object (label mismatch, colour space invalid, suspect dimensions, etc.).
2. When not co-located, suppress or downgrade to Info with a `summary_suppressed` flag.
3. Group co-located image anomalies using Tier B chain merging (from CHAIN-1).

---

### COV-2: False positive JS analysis — PDF dict executed as JS

**Severity**: MEDIUM
**Evidence**: In 9ff24c4, the embedded file target `IEEE.joboptions` is a PDF PostScript preset
file starting with `<< /ASCII85EncodePages false ...`. The JS sandbox attempts to execute it and
fails with "unexpected token '<<'". The finding `js_present/High/Strong` fires correctly, but the
runtime analysis is wasted and the error is misleading.

**Fix**:
1. Before passing an embedded file to the JS analysis path, check the first 16 bytes for PDF
   dictionary markers (`<<`) or PostScript comment (`%!`). If present, skip JS analysis and
   emit `embedded_file_not_js/Info` with note "content appears to be PDF/PS, not JavaScript".
2. Add heuristic: if `js.runtime.errors` contains "unexpected token '<<'", add to finding meta
   `js.likely_non_js: "true"` and downgrade `js_sandbox_exec` confidence from Strong to Tentative.

**Files**: `crates/sis-pdf-detectors/src/js_sandbox.rs`

---

### COV-3: Verdict roll-up missing at report level

**Severity**: MEDIUM
**Evidence**: `sis scan --json` output has no top-level verdict. The `report` command generates
a verdict line ("Verdict: Suspicious (confidence high)") but this is not present in machine-readable
scan output. Downstream consumers must parse the entire findings list to determine risk level.

**Fix**:
1. Add `verdict: VerdictSummary` to the `Report` struct:
   ```
   VerdictSummary {
     label: "Malicious" | "Suspicious" | "Anomalous" | "Clean",
     confidence: Confidence,
     score: f64,          // 0.0 to 1.0
     top_chain_id: Option<String>,
     top_intent: Option<String>,
   }
   ```
2. Compute verdict from: highest chain score, intent bucket scores, and finding severity summary.
3. Expose in `--json`, `--jsonl-findings`, and `--sarif` outputs.
4. Add `sis scan --verdict-only` mode that prints a one-line verdict for rapid triage.

**Files**: `crates/sis-pdf-core/src/report.rs`, `crates/sis-pdf/src/main.rs`

---

### COV-4: `sis query chains` returns empty without `--scan`

**Severity**: MEDIUM
**Evidence**: `sis query <pdf> chains` returns `{"chains": [], "count": 0, "total_chains": 0}`
because the query interface doesn't run the scan pipeline — chains are only available after
a full `sis scan --json`. Users expect `query chains` to trigger a scan and return chains.

**Fix**:
1. In the query handler for `chains`, run a standard (non-deep) scan to generate chains if
   not already cached.
2. Add a scan cache (`--cache-dir`) so repeated `sis query` calls on the same file reuse results.
3. Document the expected workflow: `sis scan --json > results.json; sis query results.json chains`
   vs `sis query <pdf> chains` (triggers scan inline).

---

### COV-5: Correlate is limited to network/C2 clustering only

**Severity**: MEDIUM
**Evidence**: `sis correlate` only has one subcommand (`campaign`) which clusters network intents.
The existing `findings_jsonl` input could support cross-file finding correlation (same kind, same
object patterns, same JS hash, etc.) for campaign attribution.

**Fix**:
1. Add `sis correlate findings --input <jsonl>` that groups findings across files by:
   - Same finding kind + similar severity → cluster
   - Same font object fingerprint across files → "shared font blob"
   - Same embedded file hash (if extractable) → "shared payload"
   - Same URI domain cluster → "campaign"
2. Output: `{clusters: [{kind, count, files, confidence}, ...]}` for triage.
3. Fix the 10 KB line limit (COV-6/DET-6) first so this works reliably.

---

### COV-6: Deep scan and standard scan produce nearly identical output

**Severity**: MEDIUM
**Evidence**: With `--deep`, most files produce the same findings as without. Only XFA→JS
forwarding is gated on deep mode. Deep mode should enable substantively richer analysis.

**Fix** (builds on 20260227 plan item 5.1):
1. Deep mode enables cross-object script extraction (launch `/P` params, annotation tooltips).
2. Deep mode enables full font table scan for shellcode patterns.
3. Deep mode enables multi-revision shadow object comparison.
4. Deep mode enables entropy clustering (flag docs with >30% high-entropy objects).
5. Document the difference in `sis doc deep-mode`.

---

## Performance Benchmarks and SLOs

Based on today's corpus run, establish these per-file SLOs for the `dev` profile build:

| File category | Standard scan | Deep scan |
|---|---|---|
| Small PDF (<50 objects, <500 KB) | < 200 ms | < 500 ms |
| Medium PDF (50–200 objects, <5 MB) | < 1,000 ms | < 3,000 ms |
| Large PDF (200–1,000 objects, <20 MB) | < 3,000 ms | < 10,000 ms |
| Pathological (1,000+ objects or malformed) | < 10,000 ms | < 30,000 ms |

After CRIT-1 and CRIT-2 fixes:
- fb87d8 (717 objects, 6 MB) should scan in < 3,000 ms (was 292,000 ms)
- 5bb77b (187 objects) should scan in < 1,000 ms (was 13,400 ms)
- 11606a (9 objects but complex content) should scan in < 2,000 ms (was 5,035 ms)

---

## Chain Architecture Assessment

The current chain model can represent attack paths but does not populate them correctly.

**What works**:
- Trigger/action/payload role assignment (correct for JS, launch, annotation chains)
- Score computation (chain_score.rs — rules are correct and calibrated)
- Narrative generation (chain_render.rs — produces readable output when data is present)
- Stage tracking (chain.confirmed_stages — used in the booking PDF chain correctly)
- The `ExploitChain` struct has all necessary fields

**What is broken**:
- 98.8% singleton rate (CHAIN-1) — chain building is the core problem
- Finding deduplication across chains (CHAIN-2)
- Completeness always 0.0 (CHAIN-3)
- Missing label/severity on chain (CHAIN-4)
- `edges: []` always empty — graph edges not populated
- `reader_risk: {}` always empty — reader risk model not implemented
- `finding_criticality` always 0.0 for most findings

**Is the model suitable for end-to-end attack paths?**

The trigger→action→payload three-stage model is **too narrow** for real PDF attack paths.
Real attack paths have more stages:

```
Stage 1: Entry/Parse     — PDF structure anomaly, parser confusion
Stage 2: Decode          — filter chain, decompression, font load, image decode
Stage 3: Render/Execute  — content stream execution, JS execution, font rendering
Stage 4: Pivot           — embedded file drop, launch action, URI navigation
Stage 5: Egress          — network connection, file write, registry access
```

The existing `EXPECTED_CHAIN_STAGES = ["input", "decode", "render", "execute", "egress"]`
is exactly right conceptually, but not used to build chains — only to measure completeness.

**Recommendation**: Retain the current `ExploitChain` struct but replace the synthesis approach:

1. **Event-graph-driven chain building**: Use `event_graph.rs` (already implemented) as the
   primary chain source. Walk the event graph from trigger nodes, collect all reachable event
   nodes, map each to its associated finding, and create one chain per connected component.

2. **Finding-cluster chains for homogeneous signal groups**: For findings without event graph
   connections (font anomalies, image anomalies, structural findings), use kind-based clustering
   (Tier A) to create one summary chain per finding type.

3. **Composite-finding chains**: Existing composite findings (correlation.rs) should become
   chains automatically — a composite finding IS a multi-stage chain.

4. **Retire the current phase-2 fallback**: The "every remaining finding becomes a singleton chain"
   fallback should be eliminated. Isolated findings should either be in a cluster chain or
   have no chain (just appear in findings output).

---

## Implementation Order

| ID | Item | Effort | Impact | Prerequisite |
|---|---|---|---|---|
| CRIT-1 | Fix content_stream_exec_uplift O(n²) | Small | Critical | — |
| CRIT-2 | Fix content_phishing size guards | Small | Critical | — |
| CRIT-3 | Per-file scan timeout | Medium | Critical | — |
| CHAIN-1 | Kind-based chain dedup (Tier A) | Small | High | — |
| CHAIN-2 | Finding dedup across chains | Small | High | CHAIN-1 |
| CHAIN-4 | Add label/severity to chain | Small | High | — |
| DET-3 | Font cluster composite finding | Small | High | CHAIN-1 |
| DET-5 | object_reference_cycle dedup | Small | High | — |
| DET-6 | Correlate JSONL line limit fix | Small | Medium | — |
| DET-1 | APT42 polyglot chain correlator | Medium | High | — |
| DET-2 | Decompression DoS intent | Small | High | — |
| DET-4 | Intent confidence promotion | Small | High | — |
| COV-1 | image.decode_skipped suppression | Small | Medium | — |
| COV-2 | JS FP for PDF/PS files | Small | Medium | — |
| COV-3 | Verdict roll-up in report | Medium | High | CHAIN-4 |
| CHAIN-3 | Stage inference in completeness | Medium | High | CHAIN-1 |
| CHAIN-1B | Behavior_summary → chains (Tier B) | Medium | High | CHAIN-1 |
| CHAIN-1C | Event-graph chain building (Tier C) | Large | Critical | CHAIN-1B |
| COV-4 | query chains triggers scan | Medium | Medium | — |
| COV-5 | correlate findings command | Large | Medium | DET-6 |
| COV-6 | Deep mode substantive uplift | Large | Medium | — |

---

## Success Metrics

**After CRIT-1, CRIT-2, CRIT-3**:
- fb87d8 scans in < 3 s (was 292 s)
- Batch of 20 files completes in < 30 s (was 293 s due to hang)
- No file in corpus causes batch to block for > 60 s

**After CHAIN-1, CHAIN-2, CHAIN-4**:
- Singleton chain rate: ≤ 70% (was 98.8%)
- All chains have `label` and `severity` fields (was always "?")
- No finding ID appears in more than one chain

**After DET-1, DET-2, DET-4**:
- APT42 (6648302): `polyglot_dropper_chain/Critical` in top chain; intent `Strong`
- Decompression bomb (11606a): `DenialOfService` intent fires at `Strong`
- RomCom (a99903): intent confidence promotes from Heuristic to Probable

**After COV-3**:
- `sis scan --json` output includes `verdict` field for all files
- `sis scan --verdict-only` produces one-line triage output

**Full completion**:
- Malware sample chain completeness: ≥50% of chains have completeness ≥ 0.2
- Font cluster: Files with 20+ font findings produce ≤ 3 chains (1 cluster + 2 high-signal)
- Image cluster: Files with 10+ image findings produce ≤ 3 chains
- False-positive rate: No new regressions on existing test fixtures

---

## Notes on Prior Plan Integration

This plan supersedes `20260227-corpus-analysis-uplift.md` for the following items:
- **P1 (1.1, 1.2)**: `/Win` dict and URL extraction — still valid, not addressed here
- **P2 (2.1)**: Role mapping expansion — superseded by CHAIN-1C (event-graph approach is better)
- **P2 (2.2)**: Chain merging — addressed here as CHAIN-1 with more detail
- **P2 (2.3)**: Completeness formula — addressed as CHAIN-3 with updated approach
- **P3**: False positive reduction — still valid (3.1–3.5 remain), addressed partially by DET-5
- **P4 (4.1)**: Lure PDF detection — still valid, not addressed in this plan
- **P4 (4.2)**: URI enrichment — still valid, partially addressed by DET-1
- **P5, P6**: Deep mode and CI — still valid, addressed partially by COV-6

Items from the prior plan not covered here remain valid and should proceed independently.

---

## Implementation Update (2026-02-28)

Completed in this iteration:

1. `/Launch /Win` parsing uplift in `crates/sis-pdf-detectors/src/lib.rs`:
   - Parsed `/Win` sub-keys into `launch.win.f`, `launch.win.p`, `launch.win.d`, `launch.win.o`.
   - Preserved `launch.target_path` from `/Win /F`.
   - Added dedicated `launch_win_embedded_url` finding with URI classification metadata and source-offset evidence.

2. Chain role and clustering uplift in `crates/sis-pdf-core/src/chain_synth.rs`:
   - Expanded trigger/action/payload mappings for `action_automatic_trigger`, `annotation_action_chain`,
     `pdfjs_eval_path_risk`, `launch_external_program`, `launch_win_embedded_url`,
     `uri_unc_path_ntlm_risk`, `uri_classification_summary`, `powershell_payload_present`.
   - Added singleton cluster support for `annotation_action_chain` and `decoder_risk_present`.
   - Fixed cluster member counting to use unique finding IDs.

3. Test coverage added/updated:
   - `crates/sis-pdf-detectors/tests/launch_actions.rs`:
     - `launch_action_parses_win_dict_without_payload_error`
     - `launch_action_extracts_embedded_url_from_win_parameters`
   - `crates/sis-pdf-core/tests/chain_grouping.rs`:
     - `launch_url_chain_assigns_trigger_action_payload_and_edges`
   - `crates/sis-pdf-detectors/tests/common.rs`: updated `ScanOptions` fixture (`per_file_timeout_ms`).

Baseline deltas from fresh deep scans:

- `mshta-italian-sandbox-escape-ef6dff9b.pdf`:
  - `launch_win_embedded_url` now present (`count=1`) with Blogspot C2 extracted.
  - Multi-finding chains: `8`; total chains: `16`.
- `url-bombing-25-annotation-9f4e98d1.pdf`:
  - Chain count reduced from fragmented baseline (`38`) to `14`.
  - New cluster chain: `Annotation action cluster (25 links)`.
- `jbig2-zeroclick-cve2021-30860-1c8abb3a.pdf`:
  - Cluster chains present: `Image anomaly cluster`, `Decoder risk cluster`,
    `Stream type mismatch cluster`.
  - Residual gap: cross-cluster fusion with `content_invisible_text` remains.
