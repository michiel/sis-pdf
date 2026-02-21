# REPL findings cache for interactive query

Date: 2026-02-14
Status: Implemented
Owner: `sis-pdf` (CLI) + `sis-pdf-core` (scan context)

## 1) Problem statement

The interactive query REPL already parses the PDF once and holds a `ScanContext` for the session. However, `findings`-family queries (`findings`, `findings.high`, `findings.composite`, `actions.chains`, etc.) re-run all 40+ detectors and the correlation engine on every invocation. For complex PDFs with deep analysis enabled, this adds hundreds of milliseconds per query that could be avoided by caching the detector output after the first execution.

### What already works

The REPL (`run_query_repl()` in `main.rs:2844-3316`) already:
1. Reads PDF bytes once (line 2870).
2. Builds `ScanContext` once via `build_scan_context_public()` (line 2883).
3. Reuses that context for every query via `execute_query_with_context()` (line 3145).

`ScanContext` already holds lazy-initialised state:
- `decoded: DecodedCache` -- stream decode cache.
- `classifications: OnceLock<ClassificationMap>` -- computed on first access.
- `canonical_view: OnceLock<CanonicalView>` -- computed on first access.

### What does not work

Detector results are not cached. Each `findings` query calls `run_detectors()` (line 2523 in `query.rs`), which runs all detectors, correlates findings, applies caps, and assigns stable IDs from scratch.

## 2) Objective

Cache findings and correlated chain output within the REPL session so that repeated `findings`-family queries return from cache instead of re-running the detector pipeline.

## 3) Constraints

1. No change to finding semantics or detector scoring.
2. No new abstractions or wrapper types around `ScanContext`.
3. No unsafe code, no unbounded cache growth.
4. Cached results must be identical to fresh execution for the same input and options.
5. Cache must invalidate if REPL options change mid-session (e.g. user toggles `--deep`).

## 4) Design

### 4.1 Cache location

Add a `findings_cache: OnceLock<FindingsCache>` field to `ScanContext`, consistent with the existing `OnceLock` pattern used for `classifications` and `canonical_view`.

```rust
struct FindingsCache {
    findings: Vec<Finding>,
    chains: Vec<ExploitChain>,
    option_fingerprint: u64,
}
```

The `option_fingerprint` is a hash of the scan options that affect detector behaviour (deep, strict, recover, etc.). If options change mid-session, the fingerprint mismatches and the cache is bypassed.

### 4.2 Cache population

On the first `findings`-family query:
1. `run_detectors()` executes as today.
2. The result is stored in `findings_cache` via `OnceLock::get_or_init()`.
3. Subsequent queries read from the cache.

### 4.3 Cache invalidation

The REPL session operates on a single immutable PDF. The only mid-session change that could invalidate the cache is an option change. Handle this by:
1. Computing the option fingerprint at cache population time.
2. On each cache read, comparing the current option fingerprint against the cached one.
3. If mismatched, clear the cache (`OnceLock` does not support reset, so use `Mutex<Option<FindingsCache>>` instead if mid-session option changes must be supported).

Decision required: does the REPL allow toggling `--deep` mid-session?
- If no (current behaviour): `OnceLock` is sufficient and simpler.
- If yes (future feature): use `Mutex<Option<FindingsCache>>` with fingerprint check.

Recommendation: use `OnceLock` for now. Mid-session option toggling is not currently supported and can be addressed if added later.

### 4.4 Query routing

Queries that benefit from the cache:
- `findings`, `findings.<severity>`, `findings.kind <KIND>`, `findings.composite`
- `actions.chains`, `actions.chains.*`
- `correlations`
- `chains`

Queries that do not use the cache (operate on parse graph directly):
- `pages`, `objects`, `trailer`, `catalog`, `xref.*`, `revisions.*`
- `js`, `urls`, `embedded`, `xfa.*`, `swf.*`, `images.*`, `media.*`
- `stream`, `object`, `ref`
- `events`, `launch.*`
- `org`, `ir`, `features`

### 4.5 REPL integration

Add a `cache.info` REPL command that prints:
- whether findings cache is populated,
- number of cached findings and chains,
- option fingerprint,
- memory estimate (finding count * approximate size).

No other REPL UX changes needed.

## 5) Implementation

### 5.1 Changes to `ScanContext` (`crates/sis-pdf-core/src/scan.rs`)

1. Add `FindingsCache` struct.
2. Add `findings_cache: OnceLock<FindingsCache>` field to `ScanContext`.
3. Add `pub fn cached_findings(&self, options: &ScanOptions) -> Option<&FindingsCache>` accessor.
4. Add `pub fn populate_findings_cache(&self, findings: Vec<Finding>, chains: Vec<ExploitChain>, options: &ScanOptions)` setter.

### 5.2 Changes to query execution (`crates/sis-pdf/src/commands/query.rs`)

1. In the findings query path, check `ctx.cached_findings()` before calling `run_detectors()`.
2. After `run_detectors()`, call `ctx.populate_findings_cache()` with the results.
3. Apply predicate filtering and format selection on the cached results (not on the cache itself -- filtering is per-query).

### 5.3 Changes to REPL (`crates/sis-pdf/src/main.rs`)

1. Add `cache.info` command handler in the REPL loop.

## 6) Test plan

### Unit tests (`crates/sis-pdf-core/tests/`)

1. `FindingsCache` stores and retrieves findings correctly.
2. Option fingerprint mismatch causes cache bypass.
3. Cache returns identical results to fresh `run_detectors()`.

### Integration tests (`crates/sis-pdf/tests/`)

1. Two consecutive `findings` queries in a REPL-like sequence return identical output.
2. `findings.high` filters cached results correctly.
3. `findings --where "severity == 'High'"` applies predicate on cached results.
4. `actions.chains` uses cached chain data.
5. `cache.info` reports expected cache state after population.

### Performance validation

1. Measure per-query latency for `findings` on a representative fixture:
   - first query (cold): baseline.
   - second query (cached): target significant reduction.
2. Measure memory overhead of cached findings for a high-finding-count PDF.

## 7) Risks and mitigations

1. **Risk:** Stale cache if a future feature allows mid-session option changes.
   Mitigation: `OnceLock` is simple and correct for current behaviour. Document the constraint. If option toggling is added later, migrate to `Mutex<Option<FindingsCache>>` with fingerprint invalidation.

2. **Risk:** Memory overhead for high-finding-count PDFs.
   Mitigation: findings are already materialised in `run_detectors()` and returned as a `Vec`. Caching retains the same allocation instead of discarding and regenerating it. Net memory increase is approximately zero for the common case (one findings query per session). For sessions with no findings queries, the cache is never populated.

3. **Risk:** Cache and fresh execution produce different results.
   Mitigation: integration test asserts equality between cached and fresh results on the same input.

## 8) Exit criteria

1. Repeated `findings`-family queries in the REPL do not re-run detectors.
2. Cached results are identical to fresh execution.
3. `cache.info` reports cache state.
4. No measurable memory regression for sessions that never query findings.
5. Performance improvement measured and documented for at least one representative fixture.

## 9) Implementation status (2026-02-15)

Completed:
1. `ScanContext` now includes a findings cache keyed by option fingerprint.
2. Findings-family query paths use cached detector output after first execution.
3. REPL command `cache.info` is available and reports cache state/count/fingerprint/approximate bytes.
4. Focused tests were added for:
   - cache population + result reuse,
   - severity filtering from cached findings,
   - `cache.info` rendering for empty and populated states.

Scope notes:
- This implementation is intentionally scoped to findings-family query caching in REPL sessions.
- Action-chain graph queries continue to execute through their existing path.

Validation commands:
- `cargo test -p sis-pdf findings_ -- --nocapture`
- `cargo test -p sis-pdf render_repl_cache_info -- --nocapture`
