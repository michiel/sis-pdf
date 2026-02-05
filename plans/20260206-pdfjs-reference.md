# PDF.js reference corpus evaluation (2026-02-05)

**Command:** `sis scan --path tmp/pdf.js/test/pdfs/`

## Summary
- The corpus still kills `sis scan` when a Type 1 font triggers enough stack underflows/overflows to exhaust the interpreter. Logs show `hinting program execution failed` errors (stack underflows/overflows, unmatched IF/ELSE/FDEF, division by zero) on nearly every Type 1 font before the fatal stack overflow occurs.
- Structural anomalies dominate the diagnostic stream: trailer `Size` entries disagree with object totals, objstm headers declare the wrong count (`stream.object_stream_count_mismatch`), xref offsets go out of range, streams omit `/Length`, and ASCII85 streams drop their EOD markers. ObjStm-heavy files also raise `objstm.torture` and multiple `high_objstm_count` warnings.
- The scan is resilient enough to highlight encrypted/truncated streams (`PDF is encrypted and requires a password`, `ASCII85 stream is missing its EOD marker`) but still aborts before processing every file.

## Timeline checklist
- [x] **Baseline scan** – initial release scan (`target/release/sis`) recorded numerous hinting warnings and stack overflow crash (Feb 5).  
- [x] **Debug scan** – rerun with `target/debug/sis` to capture identical hinting logs plus structural findings (Feb 5 evening).  
- [x] **Evidence capture** – `tmp/pdf.js/test/pdfs/160F-2019.pdf` reproduces the crash; copied to `crates/font-analysis/tests/fixtures/pdfjs` for regression coverage.  
- [x] **Docs & workflow updates** – expanded `docs/agent-query-guide.md` with deeper object inspection, stream dumping, and scope exercises referencing the pdf.js corpus.  
- [x] **Plan coverage** – enumerated current remediations/opportunities (Feb 6).  
- [ ] **Nightly regression job** – add an automated job that runs the pdf.js corpus, comparing each finding/chain count to the documented baseline.  
- [x] **Hinting guard regression** – added stack-error guard and unit tests that skip further hinting tables once the guard triggers; log baseline documented here.  
- [ ] **Trend instrumentation** – log `font.ttf_hinting_torture` counts and `objstm` metrics so nightly jobs can detect regressions in hinting and object stream behaviour.

## Remediations & findings
1. **Hinting interpreter guard** – add stack/budget guards so repeated underflows/overflows abort gracefully (without crashing the scanner) and emit deterministic `font.type1_hinting_torture`/related findings summarising the anomaly. Include regression coverage anchored to the crashing sample and document the expected warning volume in this plan (goal: keep scan noise controlled for nightly comparisons).  
2. **Object stream resilience** – surface `stream.object_stream_count_mismatch` and `objstm.torture` (including header mismatches/filters) as early-warning findings. Track ObjStm-heavy files for suspicious header/filters, so these structural anomalies get correlated with other warnings.  
3. **Structural & stream fallbacks** – when encountering wrong `/Size`, missing `/Length`, or `xref_offset_oob`, record what was seen and continue processing other objects using heuristics (estimate stream lengths, clamp offsets, mark `Object load error` non-fatal).  
4. **Encrypted/malformed streams** – log and skip unreadable encrypted streams or truncated ASCII85 segments; tie these warnings to findings like `stream.obfuscated_concealment` or a new `stream.malformed_encrypted` flag so analysts know what to expect.  
5. **Trend-driven detectability** – instrument daily runs to record counts for `font.ttf_hinting_torture`, ObjStm metrics, and these new structural warnings so we can spot regressions in accuracy, robustness, or noise volume.

## Opportunity backlog
- **objstm.torture finding refinement** – aggregate high ObjStm counts plus header mismatches/filters so ObjStm-heavy tampering surfaces alongside `stream.object_stream_count_mismatch`.  
- **Hinting anomaly trends** – log histograms of `font.ttf_hinting_torture` counts across nightly pdf.js replays to detect regressions (stack errors should not spike unexpectedly).  
- **Hinting guard hardening** – tighten the interpreter guard so repeated stack errors abort early, document a log baseline for these cases in this plan, and add sensors that warn when the actual log volume deviates from the baseline.
- **Security finding proposals** – develop new findings (e.g., `font.type1_hinting_torture`, `stream.malformed_encrypted`, `pdf.trailer_inconsistent`, `font.type1_concealed_payload`) that capture hinting/structural abuse patterns discovered during the corpus runs.  
- **Nightly baseline automation** – run `sis scan --path tmp/pdf.js/test/pdfs/ --report-verbosity compact --json` nightly with recorded warning counts; fail the job when new `critical/high` findings appear or when stack overflow returns.  
- **Regressions in ObjStm trends** – once instrumentation exists, monitor ObjStm header mismatch counts, filter counts, and `objstm.torture` severity to catch regressions when the pdf.js corpus is rerun after code changes.
