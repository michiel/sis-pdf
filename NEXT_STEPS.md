# Next Steps (2026-01-31)

1. Keep Stage 7 artefacts up to date: the instrumentation narratives and tables now include the XFA/filter/SWF runs in `docs/performance.md`, so continue adding release-note text or regression warnings there or in `docs/analysis.md` whenever new fixtures shift the SLO profile.
2. Solidify Stage 7.5 query coverage: guard-list logic and predicate documentation live in `crates/sis-pdf/src/commands/query.rs:7238-7327` and `docs/query-predicates.md`, so treat those files as the reference when adding new shortcuts or composite queries to keep `--where` coverage intact.
3. Prepare Stage 8/9 by auditing the ML feature vector schema (`docs/ml-features.md`, `crates/sis-pdf-core/src/features.rs`) and the correlation patterns so the 83-feature export and composite findings can be locked down without relearning obsolete schema notes.
