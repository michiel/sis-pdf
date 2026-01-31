# Next Steps (2026-01-31)

1. Add the batch/REPL regression tests described around `plans/20260120-next-analysis-phases.md:1667-1677` so every new query (including the `findings.composite` shortcuts and predicate fields) runs cleanly in both `--path` and REPL modes, revealing any remaining gaps before we ship.
2. Capture the Stage 0.5 performance profile table by wiring proper `--profile` instrumentation into `sis`, running it against a CVE fixture (per `plans/20260120-next-analysis-phases.md:1583-1586`), and documenting the latency/SLO results for inclusion in the future `docs/performance` or `docs/analysis` sections.
3. Follow through with the deferred query/predicate documentation/coverage items at `plans/20260120-next-analysis-phases.md:1547-1597`—add metadata examples, refresh predicate guidance, and lock down the remaining predicate filtering tests now that the feature vector and correlation data are settled.
