# Threat Intelligence Tracker

Use this tracker to record CVEs, research findings, and attack chains that require detector or documentation updates.

| Date | CVE / Finding | Attack Surface | Detector(s) | Severity | Impact | Confidence | Notes |
|------|---------------|----------------|-------------|----------|--------|------------|-------|
| 2026-02-01 | CVE-2025-27363 (FreeType subglyph parsing) | Font parsing / variable fonts | `font-analysis::variable_fonts`, `FontExploitDetector` | High | High | Strong | Added gvar glyph count/order heuristics; fixture `crates/font-analysis/tests/fixtures/cve/gvar-glyph-count-mismatch.ttf` exercises the primitive and documents `meta.cve`. Verified by `crates/font-analysis/tests/integration_tests.rs::test_gvar_glyph_count_mismatch_metadata`. |
| 2026-02-01 | JBIG2 filter chain + ASCII obfuscation (FORCEDENTRY derivative) | Image codecs / filter obfuscation | `FilterChainAnomalyDetector` | Medium | Medium | Probable | Heuristic `filter_chain_jbig2_obfuscation` normalises canonical filter chains (see `plans/20260201-triage.md`) and hyperlinks to fixture `crates/sis-pdf-core/tests/fixtures/images/cve-2009-0658-jbig2.pdf`. Verified by `crates/sis-pdf-core/tests/image_analysis.rs::cve_2009_0658_jbig2_static` so canonical diff/metadata stay stable. |
| 2026-02-02 | CVE-2021-30860 zero-click JBIG2 strip | Image codecs / zero-click JBIG2 | `FilterChainAnomalyDetector`, `ImageAnalysisDetector` | High | High | Strong | Zero-click JBIG2 detection (1×N strips) added, emits `meta.cve=CVE-2021-30860`/`meta.attack_surface=Image codecs / zero-click JBIG2` and ties back to `crates/sis-pdf-core/tests/fixtures/images/cve-2021-30860-jbig2.pdf`. Verified by `crates/sis-pdf-core/tests/image_analysis.rs::cve_2021_30860_jbig2_dynamic`, ensuring the metadata end-to-end. |
| 2026-02-03 | CVE-2022-38171 (JBIG2 count), CVE-2021-30860 clone | Image codecs / JBIG2 logic decoding | `FilterChainAnomalyDetector`, `ImageAnalysisDetector` | High | High | Strong | Canonical filter diff now records the same JBIG2 chain for both CVEs; the tracker entry references the shared JBIG2 fixture and clarifies that `meta.cve` lists both IDs. Use `sis query canonical-diff crates/sis-pdf-core/tests/fixtures/images/cve-2009-0658-jbig2.pdf` plus the zero-click fixture to audit normalized filter names ahead of detection. |
| 2026-02-01 | CVE-2023-26369 (EBDT bitmap merge) | Font parsing / EBDT | `font-analysis::variable_fonts`, `FontExploitDetector` | High | High | Strong | Signature-driven detection (fixtures: `crates/font-analysis/tests/fixtures/cve/cve-2023-26369-ebsc-oob.ttf`) adds documentation to `docs/findings.md` and links to `plans/20260201-next-steps.md`. |
| 2026-02-01 | Incremental update action redefinition | Actions / OpenAction | `ActionTriggerDetector` | Medium | Medium | Probable | Ensured telemetry captures latest target metadata and action initiation. |

## Process

1. Review CVE feeds (CISA KEV, Google TAG, Adobe advisory) every Friday.
2. Record sighted findings here, include detection owner and expected docs to update.
3. After implementing detector/enhancement, update the `Notes` column and reference the docs that describe the change (e.g., `docs/js-detection-*.md`, `docs/findings.md`).
4. Mention major updates in release notes and the sprint board so analysts know about the coverage shift.
5. Each weekly `cve-update` run appends placeholder rows; review those rows before merging so you can assign the detector owner, severity, impact, and confidence (the automation leaves `Detector(s) = TBD` and `Confidence = Probable` by default).
