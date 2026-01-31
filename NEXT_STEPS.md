# Next Steps (2026-01-31)

1. Capture the Stage 0.5 performance profile table by wiring proper `--profile` instrumentation into `sis`, running it against a representative CVE fixture, and documenting the latency/SLO results (per `plans/20260120-next-analysis-phases.md:1583-1586`) so the performance story can land in `docs/performance.md` or `docs/analysis.md`.
2. Finish the deferred query/predicate documentation and coverage work described around `plans/20260120-next-analysis-phases.md:1547-1597`: update the `docs/query-interface.md`/`docs/query-predicates.md` examples with the new composite shortcuts and predicate metadata, surface the predicate-aware batch and REPL workflows, and note the new regression tests.
3. Sketch the follow-up items for Stage 5+/ML/feature-vector work so we can immediately pick up where Stage 8/9 left off once the profiling/docs pieces are done.
