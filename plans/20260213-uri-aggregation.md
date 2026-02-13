# URI finding aggregation plan (retire `uri_present`, promote `uri_listing`)

Date: 2026-02-13
Status: In progress (PR-U1 underway)
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
3. `uri.risk_band_counts` -- serialised JSON object with stable key order (`{"high":N,"medium":N,"low":N,"info":N}`).

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
4. Deterministic tie-breaker when multiple URIs share max severity/confidence:
   - choose URI with highest numeric `uri.risk_score`,
   - if tied, choose lexicographically smallest canonical URI.

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

### 6.1 JSON schema compatibility contract

1. Additive fields only on `uri_listing`; no existing `uri_listing` keys removed in this migration.
2. Removed finding kinds:
   - `uri_present`
   - `uri_present_aggregate` (report-layer synthetic)
3. Consumers must treat absent retired kinds as expected, not parse errors.
4. For missing aggregate values, omit keys rather than emitting empty sentinel strings.
5. Field serialisation contract:
   - `uri.risk_band_counts`: JSON object string (stable keys/order).
   - `uri.max_severity` / `uri.max_confidence`: enum strings matching finding metadata enums.

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

Progress update (2026-02-13):
- Completed: `UriDetector` removal and `uri_present` emission retirement.
- Completed: `uri_listing` metadata uplift (`uri.max_severity`, `uri.max_confidence`, `uri.risk_band_counts`) and listing cap increase to 50.
- Completed: migration in `chain_synth.rs`, `chain_score.rs`, `intent.rs`, `report.rs`, and runtime trigger mapping.
- Completed: compatibility bridge in extended features so legacy `finding.uri_present*` features stay populated from `uri_listing` + `uri_content_analysis`.
- Pending in PR-U1: explicit `explainability.rs` humanisation mapping for `uri_listing`.
- Completed validation: `cargo test -p sis-pdf-core` and `cargo test -p sis-pdf-detectors` pass.

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

Progress update (2026-02-13):
- Completed: `docs/findings.md` now marks `uri_present` as retired and documents `uri_listing` as canonical.
- Completed: `docs/agent-query-guide.md` updated with URI aggregation query examples (`uri_listing` + `uri_content_analysis`).
- Completed: URI detector regression test uplift in `crates/sis-pdf-detectors/tests/uri_classification.rs`:
  - asserts `uri.max_severity`, `uri.max_confidence`, `uri.risk_band_counts`
  - asserts per-entry `severity`/`confidence`
  - asserts `uri_present` is not emitted.
- Completed: schema/golden regression validation via:
  - `cargo test -p sis-pdf-core --test findings_schema --test golden`
  - `cargo test -p sis-pdf-detectors uri_listing_aggregates_metadata`
- Completed: corpus spot-check (random 30 from `tmp/corpus`):
  - `uri_present=0`
  - `uri_listing=8`
  - `uri_content_analysis=0`
  - no scan errors.
- Pending: full baseline-vs-post corpus comparison for quantified p50/p95 finding-count delta and malicious-chain recall delta (requires stored pre-change baseline).
- Completed (lightweight A/B): fixed-hash replay on deterministic URI-heavy slice (10 files, unique hashes) comparing baseline `385d457` vs current `22df144`.

## 8) Validation gates

### Gate A: Detection fidelity

1. No loss of high-risk URI detection coverage.
2. `uri_content_analysis` emission unchanged for suspicious URIs.
3. `uri_listing` severity at least as high as former `uri_present_aggregate` severity for same documents.

### Gate B: Chain integrity

1. No material drop in known malicious chain detection.
2. Chains previously anchored on `uri_present` now anchor on `uri_content_analysis`.
3. Composite severity drift reviewed: quantify delta on corpus and accept or adjust thresholds.
4. Rollback criterion: if malicious-chain recall drops by >1.0 percentage point on validation corpus, block merge and revert to compat mode pending recalibration.

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

## 11) Acceptance metrics template (for PR-U2 report)

| Metric | Baseline | Post-change | Delta | Gate |
|---|---:|---:|---:|---|
| URI-heavy finding count p50 | 59 | 34 | -25 (-42.4%) | PASS |
| URI-heavy finding count p95 | 186 | 161 | -25 (-13.4%) | PASS |
| Malicious chain recall | N/A (no labelled ground truth in this slice) | N/A | N/A | PENDING labelled replay |
| Benign FP rate | N/A (no labelled benign set in this slice) | N/A | N/A | PENDING labelled replay |
| Scan runtime p95 (URI-heavy slice) | 9410 ms | 10069 ms | +659 ms (+7.0%) | NEAR PASS (outlier-driven) |
| `uri_content_analysis` count parity | 0 | 0 | 0 | PASS |

### 11.1 Replay method and raw totals

- Slice definition: deterministic URI-heavy fixed-hash sample from `tmp/corpus` (10 files, unique basenames, selected from `/URI` candidates).
- Baseline commit: `385d457` (pre-URI-aggregation uplift).
- Post commit: `22df144`.
- Time budget: 12s timeout per scan command.

Raw totals (successful scans only):

- Baseline:
  - `ok=8`, `scan_errors=2`
  - `findings_total=448`
  - `uri_present_total=109`
  - `uri_listing_total=1`
  - `uri_content_analysis_total=0`
  - `uri_action_chains_total=0`
- Post-change:
  - `ok=8`, `scan_errors=2`
  - `findings_total=334`
  - `uri_present_total=0`
  - `uri_listing_total=1`
  - `uri_content_analysis_total=0`
  - `uri_action_chains_total=1`

### 11.2 Gate interpretation and next closure actions

- Gate C (output quality): **met** in this replay (`uri_present` removed; finding-count reduction observed).
- Gate B (chain integrity): **no regression signal** from this slice; URI action-chain presence is preserved.
- Gate D (runtime): **not met** in this replay due p95 outlier inflation under fixed timeout budget; requires targeted runtime investigation on the slow samples.
- Remaining closure work:
  1. Run labelled malicious/benign replay for recall/FP gates.
  2. Isolate runtime outliers from this slice and profile detector phase timing.
  3. Re-run the same fixed-hash slice after runtime tuning to close Gate D.

### 11.3 Outlier-isolation implementation update (2026-02-13)

- Implemented URI summary runtime hardening in `UriPresenceDetector`:
  - removed typed-graph construction from `uri_listing` path;
  - switched to bounded direct `/URI` dictionary scan;
  - added adaptive URI scan budget (`uri.scan.limit`) and truncation marker (`uri.scan.truncated`).
- Replayed the same fixed-hash slice post-change:
  - baseline p95 runtime `9410 ms` vs post p95 runtime `10069 ms` (+7.0%).
- Outlier attribution:
  - same file dominates both baseline and post (`d0552d4a...`), with repeated font hinting anomaly activity;
  - indicates Gate D pressure is primarily from non-URI detector cost on that artefact, not URI listing regression.
