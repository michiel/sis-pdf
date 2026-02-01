# Threat Intelligence Tracker

Use this tracker to record CVEs, research findings, and attack chains that require detector or documentation updates.

| Date | CVE / Finding | Attack Surface | Detector(s) | Severity | Impact | Confidence | Notes |
|------|---------------|----------------|-------------|----------|--------|------------|-------|
| 2026-02-01 | CVE-2025-27363 (FreeType subglyph parsing) | Font parsing / variable fonts | `font-analysis::variable_fonts`, `FontExploitDetector` | High | High | Strong | Added gvar glyph count/order heuristics, document in `docs/findings.md`. |
| 2026-02-01 | JBIG2 filter chain + ASCII obfuscation (FORCEDENTRY derivative) | Image codecs / filter obfuscation | `FilterChainAnomalyDetector` | Medium | Medium | Probable | Flagged via `filter_chain_jbig2_obfuscation` with CVE references. |
| 2026-02-01 | Incremental update action redefinition | Actions / OpenAction | `ActionTriggerDetector` | Medium | Medium | Probable | Ensured telemetry captures latest target metadata and action initiation. |

## Process

1. Review CVE feeds (CISA KEV, Google TAG, Adobe advisory) every Friday.
2. Record sighted findings here, include detection owner and expected docs to update.
3. After implementing detector/enhancement, update the `Notes` column and reference the docs that describe the change (e.g., `docs/js-detection-*.md`, `docs/findings.md`).
4. Mention major updates in release notes and the sprint board so analysts know about the coverage shift.
