# Review: Research Document and Modernisation Plan

Date: 2026-02-13
Reviewer: Claude
Input: `docs/research/2026013-pdf-malware-evolution.md`, `plans/20260213-modenisation.md`

## A. Research Document Critique

### Strengths
- Covers the major contemporary attack classes comprehensively (RenderShock, polyglots, fountain codes, remote template injection, XFA/XXE, 3D surfaces, AI-driven metamorphism).
- Good use of primary sources (CyFirma, Check Point, MDPI, arXiv, NIST, Picus).
- CVE-2025-66516 case study is concrete and actionable.

### Weaknesses and concerns

1. **Unverifiable CVE reference.** CVE-2025-66516 does not follow standard CVE numbering (CVE IDs in 2025 would not reach the 66000 range under current MITRE allocation). This may be a hallucinated or speculative reference. The plan directly builds PR-M3 around this. If the CVE is fabricated, the urgency framing weakens, though the underlying XXE risk class is real regardless.

2. **PROMPTFLUX lacks sourcing depth.** The "PROMPTFLUX" dropper (line 98) is attributed loosely to Google GTIG [ref 23], but the linked post covers general AI tool usage by threat actors, not a specific tracked dropper. This risks overstating the maturity of AI-generated metamorphic PDF malware as an in-the-wild threat today versus a research concern.

3. **Statistics are mixed in provenance.** The 82% email delivery stat [ref 3] and the sector-specific figures [ref 4] come from different vendors' reports with different methodologies. Presenting them in a single table without noting the sourcing mismatch creates a false impression of unified data.

4. **Image references are broken.** Lines 37-46 use `![][imageN]` references to inline base64 PNGs for mathematical notation. These render in some markdown viewers but not others, and are unreadable in plain text review. The formulas should be expressed in LaTeX/Unicode or described textually for portability.

5. **Missing attack class: annotation/overlay abuse.** The research omits content-layer phishing via annotation overlays (invisible clickable regions over visible text), which is an active 2024-2025 campaign technique. The codebase already has `content_overlay_link` and `content_phishing` detectors, but the research does not map this class.

6. **Missing attack class: embedded file / polyglot archive chains.** MalDoc-in-PDF (embedding maldocs inside PDF objects) is a significant 2023-2025 technique (JPCERT documented this). Not covered in the research.

## B. Modernisation Plan Critique

### What the plan gets right

- The gap analysis (Section 2) is honest and well-calibrated against actual codebase state.
- PR sizing is sensible -- each PR has a focused scope.
- Cross-cutting requirements (Section 5) align well with AGENTS.md and CLAUDE.md constraints.
- Validation gates are structured and measurable.
- Implementation ordering is sound (passive render first = highest near-term risk reduction).

### Critical gaps and risks

**1. PR-M1 largely duplicates existing work.**

The codebase already has a substantial `passive_render_pipeline.rs` detector that emits:
- `passive_external_resource_fetch`
- `passive_credential_leak_risk`
- `passive_render_pipeline_risk_composite`

It already classifies UNC/SMB/HTTP protocols, correlates with auto-triggers (OpenAction, AA, PageAction), identifies preview-prone surfaces, and differentiates reader impacts. The plan's Section 2 rates this as "Partial" but the codebase evidence suggests it is closer to "Strong-Partial" or even "Strong" for detection. What is genuinely missing is:
- Indexer/search-service trigger modelling (Windows Search, Spotlight)
- NTLMv2 hash leak specificity (vs generic credential-leak risk)

Risk: PR-M1 as scoped would be largely redundant work. It should be rescoped to incremental uplift of the existing detector rather than a ground-up build.

**2. PR-M2 (cross-renderer differential) is architecturally ambitious with unclear value.**

The plan proposes renderer profile abstractions (Adobe-like, PDFium-like, Preview-like, Foxit-like) and behaviour deltas per profile. However:
- Without actually running multiple renderers, these profiles will be specification-based heuristics, not empirical differentials.
- The existing `ReaderProfile` system (Acrobat/Pdfium/Preview) already provides per-reader impact annotations on findings.
- True differential rendering requires rendering infrastructure (headless PDF renderers), which conflicts with the "Rust-native crates only" constraint.

Risk: This PR could become a large speculative abstraction layer that produces low-confidence findings. Consider deferring or narrowing to specific known divergence patterns (e.g., JavaScript execution policy differences, action handling differences) rather than a general "renderer semantics engine."

**3. PR-M3 (XFA/XXE) underestimates existing XFA capability.**

The codebase has XFA parsing (`xfa.rs`), XFA script extraction, XFA image payload extraction, and XFA-specific test suites (`xfa_forms.rs`, `xfa_js.rs`). The genuine gap is:
- DOCTYPE/DTD/external entity pattern detection in XML streams
- Backend ingest risk scoring

This is a smaller, more targeted PR than described. The plan should acknowledge the existing base.

**4. PR-M4 (staged remote template) overlaps with existing supply chain findings.**

The codebase already has:
- `supply_chain_staged_payload`
- `supply_chain_update_vector`
- `multi_stage_attack_chain`
- `action_payload_path`

The plan should map specifically what is missing versus what exists, rather than proposing a new finding family that may conflict with established naming.

**5. PR-M5 (U3D/PRC deep analysis) has minimal test corpus availability.**

Deep U3D/PRC structural validation requires well-formed and malformed 3D sample PDFs. These are rare in public malware corpora. The plan's test/fixture requirement ("U3D/PRC benign fixtures and malformed edge cases") does not address how these will be sourced or synthesised.

Risk: This PR may be blocked on fixture availability and deliver only trivial structural checks.

**6. PR-M7 (CDR mode) is underscoped for the complexity involved.**

CDR is not just "strip active content and rebuild." A correct CDR implementation must:
- Rebuild the xref table and trailer
- Reserialise the object graph without broken references
- Handle incremental updates correctly
- Preserve document structure (pages, fonts, images) while removing threats
- Handle encrypted documents
- Validate output is a well-formed PDF

This is a multi-month engineering effort for a PDF parser, not a single PR. The plan should either scope this as a multi-PR epic or explicitly limit it to a "strip and report" mode that produces a degraded but safe output.

**7. PR-M8 (sandbox adaptive profiles) is vague.**

"Expand browser/PDF-reader profile matrices" and "event-simulation packs" are underspecified. The JS sandbox already has extensive evasion detection (150+ static signals, dynamic V8 execution). What specific profile gaps exist? What events are not simulated? Without this specificity, the PR is hard to estimate or validate.

**8. No priority for annotation/overlay phishing uplift.**

The codebase has `content_phishing` and `content_overlay_link` detectors, but neither the research nor the plan assess whether these are sufficient against current campaign techniques (e.g., QR-code overlay phishing, invisible annotation chains).

**9. No consideration of font-based attack surface evolution.**

The codebase has a dedicated `font-analysis` crate with CVE signatures, Type1 eexec analysis, WOFF decompression bomb detection, and font exploitation bridge findings. The research mentions font-based external resource loading as a RenderShock vector, but the plan does not assess whether existing font analysis covers this or needs uplift.

### Structural/process concerns

**10. Missing dependency graph between PRs.**

PR-M4 (staged template) logically depends on PR-M1 (passive render) for trigger context. PR-M6 (fountain codes) could benefit from PR-M3's stream analysis improvements. PR-M7 (CDR) depends on the detection completeness of PR-M1 through PR-M6. These dependencies should be explicit.

**11. No false-positive budget per PR.**

Gate B says "benign corpus false-positive rate does not increase beyond agreed threshold" but does not state the threshold or allocate a per-PR budget. New composite findings (especially PR-M1, PR-M4, PR-M6) are high FP-risk and need explicit FP targets.

**12. No performance budget per PR.**

Gate C allows 10% p95 regression overall, but does not allocate per-PR. If each of 8 PRs adds 5% overhead, the cumulative effect far exceeds 10%.

## C. Recommended adjustments

1. **Rescope PR-M1** to incremental uplift of existing `passive_render_pipeline.rs` -- add indexer triggers, NTLMv2 specificity, and external font/image passive fetch patterns. Do not rebuild from scratch.

2. **Defer or narrow PR-M2** to a catalogue of known renderer behaviour differences (actionable lookup table) rather than a speculative "semantics engine."

3. **Tighten PR-M3 and PR-M4** scope to what is genuinely missing vs what exists. Map each proposed finding against existing finding kinds.

4. **Split PR-M7** (CDR) into phases: (a) strip-and-report, (b) safe rebuild with xref reconstruction.

5. **Add a PR-M0**: existing detector audit -- validate that current passive render, supply chain, XFA, and content phishing detectors cover the research's threat model before building new ones. This prevents building redundant capability.

6. **Add annotation/overlay phishing and MalDoc-in-PDF** to the research and plan coverage map.

7. **Set explicit per-PR FP and performance budgets** in the validation gates.

8. **Verify CVE-2025-66516** sourcing before using it to justify PR priority.
