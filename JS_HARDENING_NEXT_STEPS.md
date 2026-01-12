# JS hardening next steps

Last updated: 2026-01-12

## Current status snapshot

### Recent code changes
- Added NUL stripping fallback in `normalise_js_source`.
- Added invalid escape scrubbing in `attempt_syntax_cleanup`.
- Added callable assignment overrides in `not a callable function` recovery.
- Added `--max-bytes` to `sis sandbox eval` and `scripts/js_sandbox_corpus.py`.
- Added tests in `crates/js-analysis/tests/dynamic_signals.rs` for invalid Unicode escapes.

### Tests
- `cargo test -p js-analysis --test dynamic_signals --features js-sandbox` passes.
- Includes a recovery test for invalid Unicode escape sequences.

### Corpus sweep baseline
Command used:
```
python ./scripts/js_sandbox_corpus.py /home/michiel/src/pdf-corpus/2022/malicious --glob '*' --sis-bin /home/michiel/dev/sis-pdf/target/release/sis --output-dir out/js_sandbox --workers 8
```

Latest counts (before the changes in this document):
- total_failures: 1533
- top signatures:
  - 62 `payload_too_large`
  - 34 `timeout`
  - 25 `Syntax: abrupt end`
  - 18 `Eval error (recovered): unexpected token '?'`
  - 14 `Syntax: unexpected '\0'`
  - 12 `Type: not a callable function`
  - 11 `Eval error (recovered): expected token ';' got ')'`
  - 11 `Syntax: unterminated string literal`
  - 10 `Type: cannot convert 'null' or 'undefined' to object`
  - 8 `Syntax: invalid Unicode escape sequence`

## Artifacts and locations
- Failure payloads: `out/js_sandbox/failure_payloads/`
- Failure list: `out/js_sandbox/failures.jsonl`
- Results list: `out/js_sandbox/results.jsonl`

## Example failure payloads
- Abrupt end example: `out/js_sandbox/failure_payloads/53effaba3261935c.js` (truncated `function` definition).
- Not callable function example: `out/js_sandbox/failure_payloads/469f688f7d9796d7.js` (reassigns call targets like `mouwx`).
- Unexpected token `?` example: `out/js_sandbox/failure_payloads/e603ca03ec40db79.js` (large obfuscated array payload).
- Unexpected `\0` example: pick any entry from `failures.jsonl` matching `unexpected '\0'`.

## Open work items (continue in this order)

### 1) Validate NUL stripping impact
Goal: confirm the new NUL filtering reduces `Syntax: unexpected '\0'`.

Validation:
- Rebuild release `sis`.
- Re-run corpus sweep.
- Confirm `unexpected '\0'` count drops.

### 2) Validate invalid escape scrub impact
Goal: confirm `invalid Unicode escape sequence` errors drop.

Validation:
- Re-run sandbox corpus sweep.
- If counts remain, adjust scrubber to cover more malformed sequences.

### 3) Reduce `payload_too_large`
Goal: reduce skipped payloads.

Where:
- `DynamicOptions.max_bytes` and `scripts/js_sandbox_corpus.py`.

Suggested change:
- Use `--max-bytes` (now supported in `sis sandbox eval` and `js_sandbox_corpus.py`) to raise the limit for larger payloads.
- If large payloads still fail, add chunked evaluation (split on statement boundaries).

Validation:
- Re-run sweep and confirm `payload_too_large` count drops.

### 4) Verify callable assignment overrides
Goal: ensure reassigned call targets are handled.

Validation:
- Use `out/js_sandbox/failure_payloads/469f688f7d9796d7.js` and re-run `sis sandbox eval`.
- Re-run sweep and compare `not a callable function` counts.

## How to continue
1) Implement items in order above.
2) Rebuild release `sis` and run the corpus sweep.
3) Update this document with new counts and examples.
4) Add targeted tests for each new recovery path.

## Notes
- Keep Australian English spelling.
- Avoid emojis.
- When updating docs in `docs/`, use `sis` command invocation (not `cargo run`).
