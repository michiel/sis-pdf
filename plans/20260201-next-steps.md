# 20260201 Next Steps

## Evaluation
- The 2026 attack-surface research confirms that PDFs continue to present danger across fonts, image codecs, JavaScript, parser structure, actions, signatures, and reader-specific sandboxes. sis already covers many of these areas via the detectors in `crates/sis-pdf-detectors`, the font/image analysis crates, and the JS-analysis pipeline, but the paper emphasises that the same primitives can suddenly reappear as zero-click chains or sandbox bypasses, so we must favour semantics (operand stacks, filter graphs, action flows) over brittle literals.
- Font parsing remains a critical vector—FreeType’s variable-font CVEs (CVE-2025-27363) and JBIG2 virtual-CPU chains (CVE-2021-30860, CVE-2022-38171) are still exploited in the wild. Our font analysis heuristics already flag anomalous tables, but we need to capture the semantics behind new primitives (gvar glyph count mismatches, chained ASCII/JBIG2 filters) and annotate detections with the CVE and attack surface metadata called out in the research.
- Parser-level obfuscation (escaped names, filter chaining, incremental updates, polyglots) plus reader differences (Acrobat vs PDFium vs Preview) allows adversaries to evade detection. The whitepaper’s differential parsing examples demonstrate that we should canonicalise documents before analysis and mark every finding with the canonical metadata so downstream tooling sees exactly what changed.
- Action/embedded content telemetry is essential for SOC tuning: `/Launch`, `/GoToE`, embedded files, and automatic actions are repeatedly cited in NTLM credential theft and zero-click cases, so our reports must surface structured fields (`action_type`, `action_target`, `action_initiation`) to make the priority visible at a glance.

## Recommendations
1. **Strengthen emerging-primitive heuristics**—capture the semantics behind new CVEs (variable-font gvar mismatches, JBIG2 filter graph anomalies, zero-click images) in `crates/sis-pdf-detectors`, `crates/font-analysis`, and `crates/image-analysis` so every exploit vector surfaces with CVE metadata, not just raw patterns.
2. **Canonicalise before detection**—normalise object names (`/Open#41ction` → `/OpenAction`), linearise filter chains, and prefer the latest object version so detectors operate on a consistent view even when adversaries rely on incremental updates or escaped names.
3. **Surface action telemetry**—propagate structured fields (`action_type`, `action_target`, `action_initiation`) into every finding so JSON and text reports (and downstream tooling) can react to `/Launch`, `/GoToE`, `/EmbeddedFile`, and similar actions without re-parsing metadata keys.
4. **Reader-aware scoring**—attach reader-impact metadata (e.g., Acrobat `critical`, PDFium `medium`, Preview `low`) to each finding so analysts know whether the primitive matters for their chosen viewer; surface the same data in reports and docs.
5. **Maintain the threat-intel cadence**—continue curating CVEs (fonts, JBIG2, codecs, javascript) in `docs/threat-intel-tracker.md`, linking each entry back to the detectors/docs it affects so every CVE flows through the triage, implementation, and documentation workflow.
6. **Validate with fixtures**—encode the researched edge cases (variable fonts, chained JBIG2, incremental updates) into fixtures/tests so we can assert that canonicalisation, heuristics, and reader scoring stay stable as the code evolves.

## Implementation plan
1. **Emerging primitives**
   - Map the CVEs and primitives called out in the research to detector modules inside `crates/sis-pdf-detectors`, `crates/font-analysis`, and `crates/image-analysis`.
   - Add or expand semantic heuristics (gvar glyph count mismatches, chained ASCII/JBIG2 filters) and document the CVE/attack-surface metadata each one addresses.
   - Cover the heuristics with unit/integration tests so the new primitives stay observable in CI.
2. **Canonicalisation pass**
   - Extend `sis_pdf_core` with a canonicalisation snapshot that strips incremental updates, normalises names, linearises filter chains, and tracks diff-friendly metadata.
   - Expose the snapshot’s indices to detectors so every detector reuses the same canonical object list.
   - Surface the canonical metadata (`incremental_updates_removed`, name corrections) inside the structural summary and add regression tests that feed obfuscated samples.
3. **Action telemetry**
   - Add `action_type`, `action_target`, and `action_initiation` fields to `Finding`, populate them from existing metadata helpers, and ensure all output formats surface them.
   - Highlight the new fields in `docs/findings.md` and query documentation so analysts can reference them via `action_target` or `meta.action.*`.
   - Confirm embedded-action detectors continue to provide the metadata so the fields stay populated.
4. **Reader-context scoring**
   - Expand `reader_context` to emit a `reader_impacts` list in addition to the existing `reader.impact.<profile>` metadata (Acrobat, PDFium, Preview).
   - Document how severity shifts per reader profile in `docs/findings.md` so analysts understand the significance.
5. **Threat-intel cadence & docs**
   - Keep driving the weekly triage workflow in `plans/20260201-threat-intel-cadence.md`, ensuring every CVE entry references relevant detectors/docs and includes severity/impact/confidence.
   - Automate reminder/checklist hooks so new CVEs trigger updates to detectors/docs and surface in release notes.
6. **Validation fixtures**
   - Add fixtures for variable fonts, chained JBIG2 streams, and incremental update tricks to `crates/sis-pdf-core/tests/fixtures`.
   - Create integration tests that run the runner against those fixtures to verify canonicalisation, heuristics, and scoring stay stable.

## CVE automation plan
1. **Scope and cadence**
   - Rework the CVE tool to only fetch NVD data for the last 7 days by default (configurable via `--days`/`--since`/`--until`).
   - Broaden the keyword list to encompass our full attack surface (fonts, image codecs, JavaScript, actions) and surface the matched categories alongside each CVE entry.
   - Continue writing placeholder artifacts into the shared workspace directory (e.g., `docs/threat-intel-tracker.md` or a signature directory) so the automation can seed further detector work.
2. **Workflow resilience**
   - Update `.github/workflows/cve-update.yml` so it runs the new tool with the short window, is idempotent (skips files that already exist), and can run multiple times per week without hitting API limits.
   - Surface any 4xx/5xx NVD responses or skipped ranges in the workflow logs so reviewers know when to adjust windows or add API keys.
3. **Risks, gaps, opportunities**
   - API rate limits still exist—retain exponential backoff and consider running during off-peak hours if 429s persist.
   - Keyword matching may surface false positives; pair the automation with a brief human triage checklist before adding CVEs to detectors.
   - Once the tool spans all attack surfaces we can auto-generate tracker rows and notify detector owners (via release notes or issue templates) to close the loop faster.

## Next actions
- Schedule sprint capacity to land the canonicalisation pass, action telemetry, and reader-impact updates so the fixtures/tests can validate them automatically.
- Refresh `docs/findings.md` (and the query docs) with the new action/readout metadata so analysts know how to consume those fields; mention the `sis version` command as a quick check for release alignment.
- Keep the threat-intel cadence active so every CVE feeds through `docs/threat-intel-tracker.md`, the automation, the detectors, and the documentation defined above.
