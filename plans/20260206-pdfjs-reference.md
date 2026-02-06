# PDF.js reference corpus evaluation (2026-02-05)

**Command:** `sis scan --path tmp/pdf.js/test/pdfs/`

## Summary
- **Stack overflow resolved (2026-02-06)** - The corpus now completes without crashing. GDB tracing revealed the actual crash was in `sis_pdf_core::page_tree::walk_pages` (recursive page tree traversal), not the hinting interpreter. Added depth limiting (128 levels) and cycle detection to both the core page_tree module and the detector.
- Structural anomalies dominate the diagnostic stream: trailer `Size` entries disagree with object totals, objstm headers declare the wrong count (`stream.object_stream_count_mismatch`), xref offsets go out of range, streams omit `/Length`, and ASCII85 streams drop their EOD markers. ObjStm-heavy files also raise `objstm.torture` and multiple `high_objstm_count` warnings.
- The scan is now resilient enough to process the entire pdf.js corpus (896 PDFs) without crashing, highlighting encrypted/truncated streams and other anomalies as it processes each file.
- Hinting guards (`font.ttf_hinting_push_loop`, `font.ttf_hinting_control_flow_storm`, `font.ttf_hinting_call_storm`) continue to fire for dense push/call sequences, providing early warning before resource exhaustion.
- New findings: `page_tree_cycle` (circular references) and `page_tree_depth_exceeded` (excessive nesting) now surface when malformed PDFs attempt DoS via page tree traversal.

## Timeline checklist
- [x] **Baseline scan** – initial release scan (`target/release/sis`) recorded numerous hinting warnings and stack overflow crash (Feb 5).  
- [x] **Debug scan** – rerun with `target/debug/sis` to observe the recurring hinting stack underflow/overflow storm and confirm the crash reproduced on 2026-02-06.  
- [x] **Evidence capture** – `tmp/pdf.js/test/pdfs/160F-2019.pdf` reproduces the crash; copied to `crates/font-analysis/tests/fixtures/pdfjs` for regression coverage.  
- [x] **Docs & workflow updates** – expanded `docs/agent-query-guide.md` with deeper object inspection, stream dumping, and scope exercises referencing the pdf.js corpus.  
- [x] **Plan coverage** – enumerated current remediations/opportunities (Feb 6).  
- [ ] **Nightly regression job** – add an automated job that runs the pdf.js corpus, comparing each finding/chain count to the documented baseline.  
- [x] **Hinting guard regression** – added stack-error guard and unit tests that skip further hinting tables once the guard triggers; log baseline documented here.  
- [x] **Hinting instrumentation** – log control depth, stack pressure, and recent opcode history inside the TrueType VM so aggregated findings include the sequence that triggered the failure.  
- [x] **Push-loop guard** – added density tracking for `PUSHW`/`PUSHB` instructions and emit `font.ttf_hinting_push_loop` before the OS stack overflows; recognition still needs tuning to cover all crash paths.  
- [x] **Control-flow/call guard** – expanded the interpreter guard so repeated IF/ELSE/FDEF sequences and dense CALL streams now raise `font.ttf_hinting_control_flow_storm`/`font.ttf_hinting_call_storm` before the OS stack is exhausted.  
- [x] **Crash trace capture** – recorded the failing glyph stack trace with GDB (`/tmp/sis-gdb.log`), which narrows the crash to `memchr::memmem::find` in `sis_pdf_pdf::xref::parse_xref_table` while searching for `trailer` near offset 372723.  
- [x] **Xref scan hardening** – guard memchr/trailer scans when the haystack length is zero (or `trailer` is missing) so the parser reports `xref.trailer_search_invalid`, logs a deviation, and continues using the existing recovery heuristics instead of panicking.
- [x] **Page tree traversal hardening** – GDB trace revealed the actual crash was in `walk_pages` (not xref/hinting). Added depth limit (128) and cycle detection via `HashSet<(u32,u16)>` in both `sis_pdf_core::page_tree` and the detector. New findings: `page_tree_depth_exceeded` and enriched `page_tree_cycle` now surface malformed/malicious page trees.
- [ ] **Trend instrumentation** – log `font.ttf_hinting_torture` counts and `objstm` metrics so nightly jobs can detect regressions in hinting and object stream behaviour.

## Remediations & findings
1. **Hinting interpreter guard** – the guards now cover stack/budget errors, repeated control flow, and dense CALL sequences so underflows/overflows abort gracefully (without crashing the scanner) and emit deterministic `font.ttf_hinting_push_loop`, `font.ttf_hinting_control_flow_storm`, and `font.ttf_hinting_call_storm` findings. Include regression coverage anchored to the crashing glyph, and document the expected warning volume in this plan (goal: keep nightly noise controlled).  
2. **Object stream resilience** – surface `stream.object_stream_count_mismatch` and `objstm.torture` (including header mismatches/filters) as early-warning findings. Track ObjStm-heavy files for suspicious header/filters, so these structural anomalies get correlated with other warnings.  
3. **Structural & stream fallbacks** – when encountering wrong `/Size`, missing `/Length`, or `xref_offset_oob`, record what was seen and continue processing other objects using heuristics (estimate stream lengths, clamp offsets, mark `Object load error` non-fatal).  
4. **Encrypted/malformed streams** – log and skip unreadable encrypted streams or truncated ASCII85 segments; tie these warnings to findings like `stream.obfuscated_concealment` or a new `stream.malformed_encrypted` flag so analysts know what to expect.  
5. **Trend-driven detectability** – instrument daily runs to record counts for `font.ttf_hinting_torture`, ObjStm metrics, and these new structural warnings so we can spot regressions in accuracy, robustness, or noise volume.
6. **Hinting interpreter instrumentation** – capture recursion depth, call stack pressure, and instruction counts inside the hinting interpreter so we can map the precise sequence leading up to the overflow; use this data to abort before a fatal crash, and seed `font.type1_hinting_torture`/`font.ttf_hinting_torture` metadata with the control depth and recent opcode history for trend comparisons.
7. **Push-loop guard** – density tracking for recent `PUSHW`/`PUSHB` instructions now triggers a `VmError::PushLoopDetected` before those loops can escalate to a fatal OS stack overflow and emits `font.ttf_hinting_push_loop` (metadata includes the opcode history and push count).  This guard still needs threshold tuning because the pdf.js run keeps crashing elsewhere, so the next step is to expand the detection corridor and verify the log baseline for the new finding.
8. **Xref search guard** – the GDB trace showed a crash inside `memchr::memmem::find` while `sis_pdf_pdf::xref::parse_xref_table` searched for `trailer` near offset 372723 with an empty haystack iterator. Hardened the parser so it emits `xref.trailer_search_invalid` (with a deviation) whenever the trailer search either hits an empty remainder or cannot find the keyword, logs the event, and falls back to the normal recovery heuristics instead of panicking.
9. **Page tree traversal guard** – GDB trace of actual crash pointed to `sis_pdf_core::page_tree::walk_pages` in unbounded recursion, not xref/hinting. Added `MAX_PAGE_TREE_DEPTH=128` constant, depth parameter tracking, and `HashSet<(u32,u16)>` cycle detection to both the core module and detector. New findings:
   - `page_tree_depth_exceeded` (Severity::Medium) – emitted when page tree nesting exceeds 128 levels, indicating malformed/malicious PDF designed to exhaust parser resources.
   - `page_tree_cycle` (enriched) – now includes `page_tree.cycle_node` and `page_tree.stack_depth` metadata for forensic analysis of circular references.

## Opportunity backlog
- **objstm.torture finding refinement** – aggregate high ObjStm counts plus header mismatches/filters so ObjStm-heavy tampering surfaces alongside `stream.object_stream_count_mismatch`.  
- **Hinting anomaly trends** – log histograms of `font.ttf_hinting_torture` counts across nightly pdf.js replays to detect regressions (stack errors should not spike unexpectedly).  
- **Hinting guard hardening** – tighten the interpreter guard so repeated stack errors abort early, document a log baseline for these cases in this plan, and add sensors that warn when the actual log volume deviates from the baseline.
- **Security finding proposals** – develop new findings (e.g., `font.type1_hinting_torture`, `stream.malformed_encrypted`, `pdf.trailer_inconsistent`, `font.type1_concealed_payload`) that capture hinting/structural abuse patterns discovered during the corpus runs.  
- **Push-loop baseline monitoring** – record nightly counts for `font.ttf_hinting_push_loop` findings so the new guard’s noise stays predictable and we can tune `PUSH_LOOP_WINDOW_THRESHOLD`/`PUSH_LOOP_RUN_THRESHOLD` without regressing scan stability.
- **Nightly baseline automation** – run `sis scan --path tmp/pdf.js/test/pdfs/ --report-verbosity compact --json` nightly with recorded warning counts; fail the job when new `critical/high` findings appear or when stack overflow returns.  
- **Regressions in ObjStm trends** – once instrumentation exists, monitor ObjStm header mismatch counts, filter counts, and `objstm.torture` severity to catch regressions when the pdf.js corpus is rerun after code changes.
- **Control-flow storm trend telemetry** – log `font.ttf_hinting_control_flow_storm`/`font.ttf_hinting_call_storm` findings with their recent opcode history so nightly regressions in the guard thresholds are detectable just like the other hinting metrics.
- **Xref search resilience** – record nightly counts for `xref.trailer_search_invalid` (and the related `xref_offset_oob` warning) so the regression job can flag any spike in trailer-haystack failures before the parser panic returns.
