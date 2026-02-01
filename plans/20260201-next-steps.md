# 20260201 Next Steps

## Evaluation
- The 2026 attack-surface research reiterates that fonts, image codecs, JavaScript engines, parser structures, actions/embedded content, encryption/signatures, reader-specific features, and obfuscation techniques remain the primary categories for PDF exploitation, with multiple critical CVEs still being chained in the wild. sis already targets several of these via the detectors in `crates/sis-pdf-detectors` (JavaScript heuristics, metadata extraction, embedded stream decoding) and the JS-analysis/ font-analysis crates, so we have a solid foothold in image and script-driven categories, but the research warns that every category can shift to zero-click exploitation or multi-stage chains, so we must stay attentive to emergence across the taxonomy.
- The document emphasises the perennial and evolving severity of font parsing (FreeType, CoolType, variable fonts) and image codecs (JBIG2, JPEG2000, OpenJPEG, libpng), most recently exemplified by CVE-2025-27363 and the multi-stage FORCEDENTRY attack. sis’s font analysis and AI-driven heuristics already flag suspicious charstring and encoding behaviour, yet the research shows that entirely new primitives (e.g. JBIG2 virtual CPUs and zero-click payloads) can bypass defenses if we rely only on pattern matching rather than semantics or contextual anomaly scoring.
- The research also notes parser differential and obfuscation tactics (filter chains, polyglots, incremental updates, shadow attacks) that evade signature-based extraction. Our pipeline’s current content-first decoding and query predicates give us visibility, but we need more robust sanitisation/normalisation (e.g. stripping incremental updates, canonicalising names) before either detection or downstream data modelling.
- Reader-specific sandboxes and action types are highlighted as exploitable vectors: NTLM theft via `/GoToE`, `/Launch`, embedded 3D/U3D, and weak JavaScript APIs. sis focuses on detection rather than mitigation, so our posture depends on comprehensive action/exploit metadata in reports so that downstream consumers (EDR, analysts) can tune policies with those priorities.

## Recommendations
1. **Prioritise coverage of emerging primitives** (font and image layers) by expanding heuristic signals that encode stateful semantics instead of just lexical patterns. Map new CVEs (e.g. CVE-2025-27363 on FreeType subglyph parsing and continuing JBIG2 integer overflow chains) to dedicated detectors or anomaly scores so we maintain parity with research-driven threat models.
2. **Hardening against obfuscation and differential parsing**: implement a canonicalisation stage that normalises `/OpenAction`-style names, linearises filter chains, and optionally removes incremental updates to present a deterministic stream to detection layers, limiting the 100% evasion paths described in the whitepaper.
3. **Action/embedded content telemetry**: extend reporting so every finding includes the action type (`/Launch`, `/GoToE`, `/JS`, `/EmbeddedFile`) and any redirection targets, enabling policy enforcement and making it easier for downstream tooling to prioritise high-impact flows highlighted by NTLM credential theft research.
4. **Reader-contextual scoring**: align detection severity with the affected reader surface (e.g. Font/codec bugs that target core graphics stacks vs. JS issues that only hit Reader/Acrobat). This will help analysts understand that the same finding may be `Critical` for Adobe Acrobat but `Medium` for a sandboxed PDFium embed.
5. **Threat intelligence cadence**: create a lightweight process for curating new relevant CVEs and attack chain findings from the research (fonts, JBIG2, Zero-click chains) into the detectors and into docs/alerts inside `docs/js-detection-*.md` and `docs/findings.md`, ensuring the physical descriptions and severity/impact/confidence metadata stay current as the attack surface evolves.
6. **Validation via fixtures**: add targeted fixtures exercising recent attack primitives (variable fonts, JBIG2 streams with chained filter obfuscation, incremental update modifications) in `crates/sis-pdf-core/tests/fixtures` and corresponding integration tests to ensure the new detectors maintain coverage without regressing existing flows.

## Implementation plan
1. **Prioritise emerging primitives**
   - Catalogue the CVEs and research primitives called out in the report (FreeType subglyph parsing, JBIG2 integer overflows, chained codecs) and map each to the most relevant detector module inside `crates/sis-pdf-detectors`, `crates/font-analysis`, or `crates/js-analysis`.
   - For each primitive, design semantic heuristics (e.g., operand-stack anomalies for font blending; JBIG2 segment graph sanity checks) that capture the exploit semantics rather than just byte sequences, then implement the heuristics with supporting unit tests and `crates/sis-pdf-detectors/tests`.
   - Update the detector metadata so each heuristic lists the CVE(s) and attack surface element it addresses, enabling clearer telemetry when a match fires.
2. **Hardening canonicalisation**
   - Add a canonicalisation pass early in `crates/sis-pdf-core` that normalises names (`/Open#41ction` → `/OpenAction`), expands/linearises filter chains, and optionally strips incremental updates before handing data to detectors.
   - Ensure the pass emits diff-friendly metadata so downstream queries understand what was changed and why; cover the new logic with regression tests that feed obfuscated samples and verify the canonicalised output.
   - Coordinate with the detection team to rely on the canonical source for all heuristics, preventing inconsistent parsing across modules.
3. **Action/embedded content telemetry**
   - Extend the observation schema (likely `crates/sis-pdf-core/src/report.rs` or similar) so every finding records `action_type`, `action_target`, and whether the action is automatic or user-initiated.
   - Retrofit detectors that currently flag embedded content so they populate these fields; ensure JSON and textual report sinks surface the extra metadata via new CLI flags/examples in `docs/js-detection-*.md`.
   - Add integration tests that open sample PDFs containing `/Launch`, `/GoToE`, and embedded file actions to assert the telemetry fields are populated with the expected values.
4. **Reader-contextual scoring**
   - Define reader profiles (e.g., Acrobat/Reader with JavaScript, PDFium sandbox with no JS, Preview w/out sandbox) and add a mapping table that indicates which primitives are `Critical` vs `Medium` for each profile.
   - Update the scoring engine (maybe `crates/sis-pdf-core/src/severity.rs` or similar) to incorporate the reader profile metadata when emitting a finding, allowing reports to state “critical for Acrobat, medium for PDFium”.
   - Document the reader-aware scoring approach in `docs/findings.md` so analysts understand how severity/impact/confidence shift depending on the target application.
5. **Threat intelligence cadence**
   - Establish a lightweight triage workflow (e.g., a weekly review of CVE feeds for fonts, JBIG2, image codecs) and log the findings in a dedicated tracker (could live under `docs/` or `plans/`), noting which detectors need updates.
   - Assign ownership for updating detectors and documentation (docs/js-detection-*.md, docs/findings.md) whenever a new primitive is added; include CI or checklist items ensuring new CVE entries contain `severity`, `impact`, `confidence`.
   - Automate or script the ingestion of the tracker into release notes or alerts so analysts learn about the new capabilities as soon as they land.
6. **Validation via fixtures**
   - Develop fixtures that encode the researched edge cases: variable-font glyph programs, JBIG2 streams that rely on chained filters, incremental update manipulations, and any new obfuscation styles introduced by canonicalisation.
   - Place the fixtures into `crates/sis-pdf-core/tests/fixtures` with descriptive names and reference them from integration tests that run `sis` in CI via `crates/sis-pdf/tests` or test harnesses under `plans/`.
   - Tie each fixture to the detector that should fire and assert that the stats (e.g., detection labels, severity) remain consistent even after canonicalisation and new heuristics are applied.

## Next actions
- Schedule time in the sprint to align the font/image detectors with the new CVEs and to surface obfuscation normalisation logic for review; tie the work to test cases from the research so QA can validate them automatically.
- Update `docs/js-detection-*.md` and `docs/findings.md` explaining the new primitives and their detection approach so analysts understand how sis interprets the emergent threats described in the research.
- Drive the new threat intelligence cadence (`plans/20260201-threat-intel-cadence.md`) so every CVE entry flows through `docs/threat-intel-tracker.md`, the helper script (`scripts/threat_intel_summary.py`), and the docs/detectors that implement it.
