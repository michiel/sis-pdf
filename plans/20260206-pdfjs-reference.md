# PDF.js reference corpus evaluation (2026-02-05)

**Command:** `sis scan --path tmp/pdf.js/test/pdfs/`

## Summary
- The directory contains the full pdf.js regression corpus (hundreds of intentionally malformed or unsupported samples).
- The scan completes with hundreds of warnings (font hinting errors, trailer/object inconsistencies) and ultimately aborts with a stack overflow inside the hinting interpreter. The baseline exit is non-zero.

## Observed issues
1. **Font hinting interpreter noise** – Numerous `Hinting program execution failed` warnings (stack underflow/overflow, unmatched FDEF/IF/ELSE, division by zero, reference cycles) occur per sample. The errors primarily originate from Type 1/TTF hinting programs designed to stress the interpreter. They are logged repeatedly but at least one sample triggers the interpreter stack overflow exception (`thread '<unknown>' (555933) has overflowed its stack`), killing the scan.
2. **Structural parsing faults** – Several PDFs exhibit trailer dictionary `Size` entries that do not match the actual object count, missing stream `/Length` entries (`stream dictionary of '5 0 R' is missing the Length entry`), object streams reporting wrong `N`, and `xref_offset_oob`. These lead to `Object load error` diagnostics and increase noise.
3. **Encrypted & malformed streams** – A subset of files are encrypted or use ASCII85 streams without EOD markers, generating `PDF is encrypted and requires a password` or `ASCII85 stream is missing its EOD marker` warnings while preventing any further decoding of those assets.

## Latest debug run (debug build artifact)
- Re-ran `target/debug/sis scan --path tmp/pdf.js/test/pdfs/`. The scan still floods the log with hinting failures (stack underflows/overflows, unmatched FDEF/IF/ELSE, division by zero) and the process aborts with the same interpreter stack overflow once ObjStm-heavy fonts repeatedly trigger `high_objstm_count` warnings, `Encrypt` fallbacks, and Flate recovery paths.
- The structural/stream findings now fire on this corpus, so we already see `pdf.trailer_inconsistent`, `stream_missing_length`, `stream_ascii85_missing_eod`, `stream.obfuscated_concealment`, and `stream.object_stream_count_mismatch`. That’s useful, but the fatal stack overflow still prevents finishing the corpus to establish a clean warning baseline.

## Timeline checklist
- [x] **Baseline scan** – captured stderr/warnings from initial `sis scan --path tmp/pdf.js/test/pdfs/`, noted hinting noise and stack overflow (Feb 5).  
- [x] **Detection updates** – added `font.ttf_hinting_torture`, structural/stream detectors, ObjStm mismatch finding, and regression coverage (Feb 5–6).  
- [x] **Debug rerun** – executed debug build scan, confirmed warnings still fire while new findings appear, stack overflow persists (Feb 5, evening).  
- [x] **Hinting guard hardening** – implemented early exit for repeated stack issues and now have the ObjStm torture aggregate detector; trend instrumentation via `font.ttf_hinting_torture` logging is ready to capture counts.  
- [ ] **Corpus regression job** – automate nightly or pre-release run of the pdf.js corpus to confirm the tip baseline remains stable and no new crashes occur.  
- [ ] **Documentation & baseline** – record expected warning counts/summary entries for the pdf.js run so future contributors can quickly recognize regressions.  

## Remediation plan
1. **Harden the hinting interpreter**
   - Add explicit stack/budget guards to the hinting program executor so it rejects suspicious programs (` instruction_count > threshold`, unmatched control flow, etc.) before overflowing. Gracefully abort with a deterministic error rather than letting the thread crash.
   - Introduce caching/log deduplication for recurring hinting failures so that the corpus run remains readable. Consider chunking by glyph to surface one summary warning per font instead of per glyph.
   - Add a regression fixture (or reuse the offending pdf) that reproduces the stack overflow; ensure `cargo test -p font-analysis` or a new integration verifies the guard disables the crash.
2. **Improve structural resilience**
   - When encountering inconsistent `Size` entries, missing `/Length`, or xref offsets, fall back to best-effort heuristics (e.g., derive length from next object or stream terminator) but keep reporting a single warning per file rather than repeating for every object.
   - Ensure object load errors stay confined to the affected object and do not abort the entire scan; treat them as non-fatal and continue processing other objects.
   - Validate `Object load error` details (offset, target object) in a dedicated regression to avoid panics when pdf.js uses intentionally weird xref tables.
3. **Handle encrypted streams & missing markers**
   - Recognise the pdf.js corpus contains encrypted and truncated ASCII85 streams; after logging that the content is unreadable, skip the payload decoding path so the scan continues.
   - Document these cases when sharing the corpus results so analysts know these warnings are expected.
4. **Regression coverage & automation**
   - Add a nightly or lint job that replays `sis scan --path tmp/pdf.js/test/pdfs/ --report-verbosity compact` to detect regressions early. When the stack overflow fix is in place, this job should exit cleanly with warnings only.
   - Update `plans/` or `docs/` with the known expected warnings so future contributors understand why the run is noisy.

## Next steps
- Pinpoint the sample(s) that still overflow the hinting interpreter in the debug run (likely identical to the earlier Type 1 fonts) and add them to `crates/font-analysis/tests/fixtures` for regression coverage.  
- Re-run the pdf.js corpus once the guard is stable (deployed now) and document the expected noise captured by the new structural/stream findings so future runs only flag meaningful regressions.  

## Progress
- Added an aggregate hinting detection (`font.ttf_hinting_torture`) that fires whenever multiple hinting programs exhaust interpreter budgets or hit the configured stack/instruction thresholds; regression tests now cover the new heuristic.
- Implemented structural/stream findings for trailer `/Size` mismatches, out-of-range `startxref` offsets, missing `/Length`, truncated ASCII85 payloads, combined obfuscation indicators, and ObjStm header/count disagreements along with regression tests to keep the new detections exercised.
- Introduced the `objstm.torture` aggregate finding, guarding hinting analysis with an early-exit after excessive warnings, and surfaced the hinting/trend instrumentation so the new `font.ttf_hinting_torture` counts can be graphed across corpora.

## Security finding opportunities
- **Hinting interpreter abuse**: the stack underflow/overflow and unmatched control flow errors are exactly the type of PostScript hinting abuse seen in real exploits (BLEND-style). Add findings that flag fonts hitting the guard thresholds (excessive stack, unmatched FDEF, division by zero) even when the interpreter survives, with `severity=Medium` and `impact=High` to highlight potential interpreter exploits.
- **Malformed trailer/xref as indicators**: repeated wrong `Size` entries, missing `/Length`, and xref offsets out of range often accompany malware that corrupts object tables. Emit findings (even `Low`/`Info`) when trailer metadata doesn't match actual counts or cross-reference pointers to emphasise tampering. These can feed correlation patterns linking to object stream misuse or exploits targeting header parsing.
- **Encrypted/truncated assets**: detecting ASCII85 streams missing EOD or missing Length entries combined with warnings about encryption could form a `font.type1_concealed_payload` or `stream.malformed_encrypted` finding. Mark these as `Medium` severity with `confidence=Probable` since such anomalies are common in obfuscated/silent payloads.
- **Glyph/hinting anomaly scoring**: aggregate hinting failures per font and emit a `font.type1_hinting_torture` finding when many glyphs trigger stack or control-flow errors; capture counts and max stack depth so analysts understand which fonts are actively abusing the interpreter.
- **Object stream abuse detection**: when object streams report wrong `/Count`/`N` values compared to the parsed entries, raise a `stream.object_stream_count_mismatch` finding (`severity=Low`/`Medium`, `impact=Medium`). This highlights tampering of object tables that often precedes exploitation attempts.
- **Trailer/xref discrepancy finding**: create `pdf.trailer_inconsistent` when trailers report a `Size` that disagrees with parsed objects or when xref entries point outside the file bounds; severity `Medium`, confidence `Strong`.
- **Encrypted + malformed chain**: correlate encryption warnings with missing `/Length` or truncated ASCII85 so the pipeline surfaces a `stream.obfuscated_concealment` finding reporting both the reason and the affected object; severity `Medium`, confidence `Probable`.
- **High ObjStm count aggregate**: add `objstm.torture` (or similar) to score ObjStm-heavy files by combining high counts with header mismatch/filters so ObjStm tampering appears alongside `stream.object_stream_count_mismatch`.
- **Hinting trend monitoring**: capture `font.ttf_hinting_torture` counts across pdf.js runs (perhaps via histogram or checksum) to detect regressions early and keep accuracy/robustness high whenever we re-run the corpus.
- **Hinting guard hardening**: extend the interpreter guard so repeated stack errors abort gracefully before crashing (e.g., limit recursion depth, stop the glyph, or exit with deterministic error) and document the expected log noise/baseline in this plan so future corpus runs stay controlled.
