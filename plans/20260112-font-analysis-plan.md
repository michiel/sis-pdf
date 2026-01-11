Plan for Font Analysis Workspace Crate Using Skrifa

Overview
This plan defines a new workspace crate, font-analysis, that implements the recommendations from the embedded font exploitation background plan. The crate focuses on detecting malicious or malformed embedded fonts in PDFs using a hybrid approach:
- Static heuristics over font structures and metadata.
- Dynamic analysis using skrifa as a memory-safe font engine.
- Correlation with existing detections in sis-pdf.

Progress (2026-01-12)
- Completed: workspace crate added with static analysis, dynamic analysis (feature-gated), and risk scoring.
- Completed: detector integration to extract embedded font streams and emit findings with object id and font name.
- Completed: configuration support in config file and defaults, including limits and timeouts.
- Completed: findings documentation and basic static analysis tests.
- Completed: correlation rule that flags combined JavaScript and font findings.

Goals
- Provide accurate, defensible font findings with low false positives.
- Keep analysis safe by default and resistant to hostile inputs.
- Integrate findings into the existing reporting pipeline.
- Make dynamic analysis opt-in or gated for performance and resource control.

Non-goals
- Rendering or displaying fonts.
- Replacing existing PDF parsing logic.
- Full font coverage for every format on day one.

Suggestions
- Start with TrueType and OpenType (TTF/OTF) as they dominate modern embedded fonts and align with skrifa support.
- Treat Type1 and CID-keyed fonts as a separate static-only phase until a safe dynamic engine is available.
- Define findings that map to concrete attacker tactics so they are easy to explain in reports.
- Gate dynamic analysis on static risk scoring to avoid unnecessary runtime cost.
- Use a strict timeout budget per font to prevent analysis stalls.

Recommendations
- Adopt a two-tier signal model: low-level signals (table-level anomalies) and higher-level combined findings (multiple anomalies, JS correlation).
- Ensure deterministic outputs by normalising error messages from external libraries.
- Add a minimal corpus of known-bad fonts and regression fixtures before enabling dynamic analysis by default.
- Keep all font analysis in a dedicated crate to avoid cross-crate coupling, with a narrow API in sis-pdf-core.
- Add structured telemetry for detection tuning (counts of rejections, crash-like outcomes, and timeout rates).

Architecture and Crate Layout
- New crate: crates/font-analysis/
  - lib.rs: public API, entry points, and configuration.
  - model.rs: findings, severity, and metadata structures.
  - static_scan/
    - mod.rs: scanning orchestration.
    - ttf.rs: table inspection for TTF/OTF.
    - type1.rs: basic parsing hooks and heuristics (static only).
  - dynamic/
    - mod.rs: runtime analysis orchestration.
    - skrifa.rs: dynamic checks using skrifa.
  - tests/
    - fixtures/: benign fonts, malformed fonts, small known-bad samples.
    - static_tests.rs: static rule coverage.
    - dynamic_tests.rs: controlled dynamic analysis tests.

Integration Points
- crates/sis-pdf-core: add a new analysis stage that extracts embedded font streams and invokes font-analysis.
- crates/sis-pdf-detectors: add any rule mapping if findings must align with existing detector naming conventions.
- docs/: document new findings and configuration flags.

Configuration
- Ensure all items are configurable via configuration file as well as CLI flags where relevant.
- font-analysis.enabled: default true for static analysis.
- font-analysis.dynamic_enabled: default false or guarded by a CLI flag.
- font-analysis.dynamic_timeout_ms: default 50-200 ms per font, configurable.
- font-analysis.max_fonts: guard for malicious PDFs that embed thousands of fonts.

Findings and Signals
Define new findings under a font.* namespace with clear intent:
- font.invalid_structure: font parsing rejected by basic validation.
- font.anomalous_table_size: tables with suspicious sizes or offsets.
- font.inconsistent_table_layout: directory references inconsistent or overlapping ranges.
- font.suspicious_hinting: large or unusual hinting bytecode or charstrings.
- font.dynamic_parse_failure: skrifa rejects or fails to parse a font that otherwise looks valid.
- font.dynamic_timeout: dynamic analysis exceeded time budget.
- font.multiple_vuln_signals: combined meta-signal when multiple high-risk signals co-occur.

Detailed Technical Plan
1) Workspace and dependencies
- Add crates/font-analysis to the Cargo workspace.
- Add skrifa dependency behind a feature flag (font-analysis-dynamic).
- Add optional dependencies for static validation if needed (e.g. read-fonts or ots bindings if chosen).

2) Data model
- Define a FontFinding struct with:
  - id (string, e.g. font.invalid_structure)
  - severity (enum aligned with existing reporting)
  - summary (short human-readable label)
  - detail (structured data, JSON-serialisable)
  - evidence (offsets, table tags, byte counts)
- Provide a stable mapping to sis-pdf-core report model.

3) Font extraction pipeline
- In sis-pdf-core, extend the PDF analysis stage to:
  - identify embedded font streams (FontFile, FontFile2, FontFile3)
  - extract raw bytes (with size caps)
  - associate fonts with object identifiers for evidence tracking

4) Static analysis implementation
- For TTF/OTF:
  - parse the sfnt header and table directory.
  - verify offsets and lengths are in bounds.
  - detect overlapping or duplicate tables.
  - apply thresholds for table sizes and glyph counts.
  - inspect hinting program length in glyf/loca or cff (as available).
- For Type1:
  - basic header validation and length checks.
  - flag unusual or non-conforming charstring lengths.
- Emit findings with clear evidence and avoid noisy failures.

5) Dynamic analysis with skrifa
- Use skrifa to parse and shape glyphs from the font.
- Execute a minimal set of operations that exercises parsing:
  - load a small set of glyphs (e.g. .notdef, A, B, C where present).
  - if variable font, exercise a default axis location.
- Capture and normalise errors into font.dynamic_parse_failure.
- Enforce a hard timeout budget using a watchdog in the calling layer.
- Gate dynamic analysis on a static risk score to contain cost.

6) Risk scoring and gating
- Compute a risk score based on:
  - invalid structure or offset anomalies
  - extreme sizes or counts
  - suspicious hinting metrics
- Only enable dynamic analysis if score >= threshold or explicit CLI flag set.

7) Reporting and correlation
- Surface font findings in the main report with object references.
- Add a correlation rule in sis-pdf-core for:
  - font.multiple_vuln_signals
  - font anomalies combined with JS suspicious findings

8) Tests and fixtures
- Add benign font fixtures (small TTF/OTF) for baseline.
- Add malformed fonts for static detection.
- Add one or two known-bad samples if licensing allows, otherwise synthetic.
- Ensure tests cover:
  - correct offset detection
  - table overlap detection
  - dynamic parse failure mapping
  - timeout handling

9) Documentation
- Add entries in docs/findings.md for each font finding.
- Add a font analysis overview in docs/ with usage instructions.
- Update any CLI or report format notes if new fields are added.

10) Rollout and safety checks
- Ship static analysis first.
- Keep dynamic analysis feature-gated until coverage and tests stabilise.
- Track false positives and add suppression mechanisms as needed.

Open Questions
- Which PDF font types are most prevalent in recent samples to prioritise first?
- Prefer native Rust validation libraries only; avoid C or C++ dependencies such as OpenType Sanitizer.
- In-process dynamic analysis is acceptable provided timeouts are enforced.
- Represent font identifiers with both object id and font name in reports.

Implementation Milestones
- M1: crate skeleton, configuration, and static TTF/OTF checks.
- M2: integrate with sis-pdf-core extraction pipeline and reporting.
- M3: skrifa-based dynamic analysis behind feature flag.
- M4: fixtures, tests, documentation, and tuning.
