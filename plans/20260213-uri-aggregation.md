# URI finding aggregation plan (retire `uri_present`, promote `uri_listing`)

Date: 2026-02-13
Status: In progress (validation gates running)
Owner: `sis-pdf-detectors` + `sis-pdf-core` reporting/query surfaces

## 1) Objective

Retire the legacy `UriDetector` (`uri_present`) and promote the existing `uri_listing` finding as the sole document-level URI presence indicator, while preserving:

1. Per-URI risk granularity (severity/confidence/reasons).
2. Chain and composite correlation quality.
3. Machine-readable query/report stability.

Primary problem: `uri_present` emits one finding per URI (capped at 25), inflating finding counts and polluting reports. The report layer already works around this with `aggregate_uri_present()`, confirming the finding kind is redundant.

## 2) Current-state inventory

The URI detection system already has three detectors:

| Detector | Kind | Per-doc count | Location |
|---|---|---|---|
| `UriDetector` | `uri_present` | 0-25 (capped) | `lib.rs:1865-1958` |
| `UriContentDetector` | `uri_content_analysis` | 0-N (suspicious only) | `uri_classification.rs:939-1152` |
| `UriPresenceDetector` | `uri_listing` | Exactly 1 | `uri_classification.rs:1245-1493` |

### What `uri_listing` already provides

- `uri.count_total`, `uri.count_unique_domains`, `uri.suspicious_count`
- `uri.schemes` (scheme:count pairs)
- `uri.list.N.*` entries (up to 20) with URL, canonical form, scheme, domain, risk score, chain depth, visibility, placement, trigger, automatic flag
- `uri.listing.truncated`, `uri.listing.schema_version`

### What `uri_content_analysis` already provides

- Per-suspicious-URI findings with 40+ metadata fields
- Deep indicator analysis: obfuscation level, phishing indicators, data exfil patterns, IDN lookalikes, hidden annotations, trigger classification
- Risk scoring with composite numeric score
- Only emitted for URIs with interesting signals (not noise)

### Existing workarounds for the `uri_present` problem

- `report.rs:746-823`: `aggregate_uri_present()` collapses multiple `uri_present` into a single `uri_present_aggregate` in focused triage mode.
- `lib.rs:1960-2023`: `URI_FINDING_CAP` (25) with aggregate metadata on first finding when cap exceeded.
- `chain_synth.rs:37-39,155-161`: `uri_present` chains filtered as noise unless `uri_content_analysis` companion exists.

## 3) Target-state model

### 3.1 Sole document-level URI finding: `uri_listing`

No new finding kind. Promote `uri_listing` to be the canonical URI presence finding. Remove `uri_present` entirely.

`uri_content_analysis` remains as a separate finding kind for suspicious URIs. It serves a different purpose: detailed per-URI risk assessment for URIs that warrant individual attention. Folding it into `uri_listing` would lose the signal clarity that makes it useful in chain synthesis and triage.

### 3.2 New metadata fields on `uri_listing`

Add to the existing `uri_listing` metadata (additive only):

1. `uri.max_severity` -- highest severity across all URI assessments.
2. `uri.max_confidence` -- highest confidence across all URI assessments.
3. `uri.risk_band_counts` -- serialised map of high/medium/low/info counts.

All other summary and per-URI fields already exist.

### 3.3 Per-URI entry storage cap

Current cap is 20 entries in `uri.list.N.*` metadata. With `uri_present` retired, `uri_listing` becomes the only source of per-URI detail for URIs that are not individually suspicious (i.e. do not generate `uri_content_analysis`).

Decision required: raise cap or keep at 20.

- Recommendation: raise to 50 for `uri_listing` metadata entries. Documents with 50+ URIs are rare in benign corpora; the truncation flag and count already handle the overflow case. 50 provides adequate forensic coverage without metadata bloat.
- For JSON output mode, consider an unbounded or higher-cap variant (configurable).

### 3.4 Severity/confidence semantics for `uri_listing`

Currently volume-based (10+ URIs = Low, 25+ = Medium, 50+ = High). Enhance to also consider:

1. Base severity = max of (volume-based severity, `uri.max_severity`).
2. Uplift when multiple high-risk URIs with independent indicators exist.
3. Confidence derives from strength of URI-level indicators and cross-signal corroboration.

## 4) Specific migration points

### 4.1 Chain synthesis (`chain_synth.rs`)

| Location | Current behaviour | Migration |
|---|---|---|
| Lines 37-39 | Skips `uri_present` if `!group_has_suspicious_uri` | Remove; `uri_present` no longer emitted |
| Lines 155-161 | `chain_is_noise()` checks `uri_present` action without `uri_content_analysis` | Remove; noise filtering no longer needed for retired kind |
| Line 189-199 | `uri_present` recognised as action type | Replace with `uri_content_analysis` as action source; `uri_listing` does not participate in chains as an action |
| Line 506 | Maps `uri_present` to action label "URI action" | Map `uri_content_analysis` to "URI action" |

### 4.2 Chain scoring (`chain_score.rs`)

| Location | Current behaviour | Migration |
|---|---|---|
| Line 31 | Scores `uri_present` in chain weight | Replace with `uri_content_analysis`; weight by `uri.risk_score` metadata instead of finding count |

### 4.3 Intent scoring (`intent.rs`)

| Location | Current behaviour | Migration |
|---|---|---|
| Lines 56, 134 | `uri_present` sets `has_uri` flag | Check for `uri_listing` or `uri_content_analysis` instead |

### 4.4 Report layer (`report.rs`)

| Location | Current behaviour | Migration |
|---|---|---|
| Lines 649-677 | Collects `uri_present` findings for aggregation | Remove; no `uri_present` to aggregate |
| Lines 746-823 | `aggregate_uri_present()` produces `uri_present_aggregate` | Remove entirely |

### 4.5 Explain layer (`explainability.rs`)

| Location | Current behaviour | Migration |
|---|---|---|
| Line 439 | Humanised description for `uri_content_analysis` | Keep unchanged |
| Lines 1652-1658 | Explanation for `uri_present` | Remove; add explanation for `uri_listing` if not present |

### 4.6 Detector removal (`lib.rs`)

Remove `UriDetector` struct and its `Detector` impl (lines 1865-1958). Remove `URI_FINDING_CAP` constant and associated aggregate-on-cap logic (lines 1960-2023).

## 5) Query/report/explain changes

### 5.1 `findings` output

1. `uri_listing` appears as the sole document-level URI row.
2. `uri_content_analysis` appears for individually suspicious URIs (unchanged).
3. `uri_present` and `uri_present_aggregate` no longer appear.

### 5.2 `explain`

For `uri_listing`:
1. Render summary first (counts, max risk, scheme spread).
2. Render per-URI table (bounded to top-N by risk score in text mode).
3. Include explicit note when truncated, with query hint for full JSON view.

For `uri_content_analysis`: unchanged.

### 5.3 JSON/JSONL output

1. `uri_listing` preserves full per-URI entries in machine-readable form.
2. Deterministic ordering by (severity desc, confidence desc, uri asc).

## 6) Migration strategy

Single-phase migration. No feature flag needed because:
- `uri_listing` already ships alongside `uri_present` -- downstream consumers already handle it.
- `uri_content_analysis` is unchanged.
- The only removal is `uri_present`, which was noise that the report layer was already suppressing.

Steps:
1. Remove `UriDetector` and `uri_present` emission.
2. Update chain/intent/report/explain references (Section 4).
3. Add new metadata fields to `uri_listing` (Section 3.2).
4. Raise per-URI entry cap (Section 3.3).
5. Update `docs/findings.md` with migration note: `uri_present` retired, use `uri_listing` for presence and `uri_content_analysis` for per-URI risk.

## 7) Implementation checklist (PR-sized)

### PR-U1: Retire `uri_present` and uplift `uri_listing`

Detector changes:
1. Remove `UriDetector` struct and impl from `lib.rs`.
2. Remove `URI_FINDING_CAP`, aggregate-on-cap logic.
3. Add `uri.max_severity`, `uri.max_confidence`, `uri.risk_band_counts` to `UriPresenceDetector` metadata emission.
4. Raise per-URI entry cap from 20 to 50 in `UriPresenceDetector`.
5. Enhance `uri_listing` severity derivation per Section 3.4.

Chain/intent/report migration:
1. Update `chain_synth.rs`: remove `uri_present` noise filtering, replace action type mapping with `uri_content_analysis`.
2. Update `chain_score.rs`: replace `uri_present` weight with `uri_content_analysis` + `uri.risk_score`.
3. Update `intent.rs`: replace `uri_present` check with `uri_listing` or `uri_content_analysis`.
4. Remove `aggregate_uri_present()` from `report.rs` and all call sites.
5. Update `explainability.rs`: remove `uri_present` handler, add `uri_listing` explanation.

Tests:
1. Existing chain fixtures retain expected severity/confidence (regression).
2. `uri_listing` metadata includes new fields for mixed-risk URI sets.
3. `uri_listing` entry cap at 50, truncation flag set correctly at 51+.
4. No `uri_present` or `uri_present_aggregate` in any output.
5. Intent scoring unchanged for documents with URIs.
6. Stable ordering snapshot for per-URI entries.

### PR-U2: Documentation and corpus validation

1. Update `docs/findings.md`: retire `uri_present`, document `uri_listing` as canonical, note `uri_content_analysis` role.
2. Update query guide with new metadata field references.
3. Run corpus validation: confirm finding-count reduction and no chain quality regression.
4. Add CLI examples for URI entry inspection via `uri_listing` metadata.

Tests:
1. `findings` output snapshot (text and JSON).
2. `explain` output for `uri_listing` includes summary + per-URI table.
3. JSON schema assertions for new metadata fields.
4. Corpus regression: no detection quality loss.

## 8) Validation gates

### Gate A: Detection fidelity

1. No loss of high-risk URI detection coverage.
2. `uri_content_analysis` emission unchanged for suspicious URIs.
3. `uri_listing` severity at least as high as former `uri_present_aggregate` severity for same documents.

### Gate B: Chain integrity

1. No material drop in known malicious chain detection.
2. Chains previously anchored on `uri_present` now anchor on `uri_content_analysis`.
3. Composite severity drift reviewed: quantify delta on corpus and accept or adjust thresholds.

### Gate C: Output quality

1. Finding count reduction for URI-heavy PDFs (measure: median and p95 finding count on URI-heavy corpus slice).
2. `explain` readability improvement: no duplicated URI findings.
3. `uri_present` and `uri_present_aggregate` absent from all output modes.

### Gate D: Performance

1. No significant scan-time regression on URI-heavy corpus slices (target: <5% p95 delta).
2. Metadata serialisation overhead for 50-entry cap within detector budget.

## 9) Risks and mitigations

1. **Risk:** Chain under-scoring after `uri_present` removal.
   - Mitigation: explicit score recalibration in PR-U1; use `uri.risk_score` and `uri.max_severity` instead of finding count. Validate on existing chain fixtures before merge.

2. **Risk:** Metadata bloat for extreme URI volumes (500+ URIs).
   - Mitigation: 50-entry cap with truncation metadata. Full per-URI detail available in JSON mode via `uri_content_analysis` findings for suspicious URIs and `uri_listing` entries for the top 50.

3. **Risk:** Downstream tooling filtering on `kind == "uri_present"`.
   - Mitigation: document retirement in `docs/findings.md`. `uri_listing` has been emitting alongside `uri_present` already, so consumers should already handle it. No compat flag needed.

4. **Risk:** Intent scoring regression if `has_uri` check is not migrated.
   - Mitigation: explicit migration point in Section 4.3; test coverage in PR-U1.

## 10) Deliverables

1. Code changes: remove `UriDetector`, uplift `uri_listing`, migrate chain/intent/report/explain.
2. Updated docs: `docs/findings.md`, query guide.
3. Integration tests and representative fixtures for mixed URI risk sets.
4. Validation report comparing pre/post:
   - finding-count reduction,
   - chain parity (quantified),
   - runtime impact.

## 11) Gate execution updates (2026-02-13)

### 11.1 Fixed-hash A/B replay (URI-heavy slice)

- Baseline commit: `385d457`
- Current commit line: `07200eb` (includes URI runtime hardening)
- Slice: deterministic URI-heavy fixed-hash sample (10 files).

Results (successful scans only):

- Baseline: `ok=9`, `scan_errors=1`, `findings_total=632`, `uri_present_total=134`, `uri_listing_total=2`, `uri_action_chains_total=0`, `p50_findings=59`, `p95_findings=186`, `p95_runtime_ms=9410`.
- Current: `ok=9`, `scan_errors=1`, `findings_total=498`, `uri_present_total=0`, `uri_listing_total=2`, `uri_action_chains_total=2`, `p50_findings=34`, `p95_findings=161`, `p95_runtime_ms=10069`.

Gate interpretation:

- Gate C (output quality): **PASS** (finding-count reduction and `uri_present` removal confirmed).
- Gate B (chain integrity): **PASS (provisional)** on this slice (`uri_action_chains` retained/improved).
- Gate D (performance): **NEAR PASS / OPEN** (`+7.0%` p95, target `<5%`).

### 11.2 Runtime outlier isolation

Dominant slow file: `tmp/corpus/mwb-2026-02-06/d0552d4acdd6f0df66e3217e8fd685b69011f8ec4ffb4b57a884f97436002706.pdf`.

Observed behaviour:

- Slow in both baseline and current (baseline ~9.4s, current ~10.1s in replay).
- Runtime logs are dominated by repeated font-hinting anomaly processing (`font.ttf_hinting_torture`), not URI listing work.
- URI path was hardened by removing typed-graph construction from `uri_listing`, adding bounded dictionary scan, and emitting `uri.scan.limit`/`uri.scan.truncated`.

Conclusion:

- Remaining Gate D pressure is primarily a non-URI hotspot; URI aggregation path is no longer the dominant contributor.

### 11.3 Labelled replay surrogate (malicious/benign)

Because a formally labelled benign/malicious PDF corpus for this gate is not currently available in-repo, surrogate sets were used:

- Malicious surrogate: 20 URI-heavy files from `tmp/corpus` fixed-hash slice.
- Benign surrogate: 10 stable fixtures from `crates/sis-pdf-core/tests/fixtures` and `crates/sis-pdf-detectors/tests/fixtures`.

Proxy results:

- Malicious surrogate:
  - baseline: URI-surface coverage `78.9%`, URI-action-chain coverage `0.0%`.
  - current: URI-surface coverage `31.6%`, URI-action-chain coverage `31.6%`.
- Benign surrogate:
  - baseline FP proxy (`uri_content_analysis` or `uri_listing>=Medium`): `0/10` (0%).
  - current FP proxy: `0/10` (0%).

Interpretation:

- The URI-surface proxy is not directly comparable because baseline includes retired `uri_present` semantics.
- URI-action-chain coverage increases in current behaviour.
- Benign FP proxy remains stable at 0%.
- Gate A/B remain **provisionally open** pending replay on a formally labelled PDF corpus with explicit ground-truth expectations.

### 11.4 Next closure steps

1. Build a formally labelled benign/malicious PDF validation slice (or import existing labelled set) for final Gate A/B closure.
2. Run targeted non-URI runtime tuning (font hinting hotspot) and re-run the same fixed-hash URI-heavy replay to close Gate D.
3. Freeze acceptance table once Gate D is <= +5% p95 and labelled recall/FP deltas are quantified.
