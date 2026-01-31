# Next Steps (2026-01-31)

1. Keep the Stage 7 documentation and integration sweep on the radar: add any remaining instrumentation narratives or release notes to `docs/performance.md`/`docs/analysis.md`, and capture additional profiling runs for other fixtures if the SLO table needs further validation.
2. Maintain the Stage 7.5 query coverage: extend the regression harness (`crates/sis-pdf/src/commands/query.rs:7238-7327`) and documentation whenever new findings or shortcuts arrive so the `--where` guard list never regresses.
3. Plot the Stage 8/9 follow-up work for the 83-element feature vector and the optional correlation exports (dashboard, CSV/JSONL helpers) so the ML/feature pipeline can pick up where Stage 8 left off without chasing outdated schema notes.
