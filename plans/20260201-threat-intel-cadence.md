# 20260201 Threat Intelligence Cadence

## Objective
Establish an ongoing workflow so CVEs, zero-click chains, and other emerging findings are triaged and tracked, ensuring the detectors/docs stay aligned with the research referenced in `docs/research/202602-pdf-attack-surface-breakdown.md`.

## Weekly workflow
1. **Signal capture (Friday)** – Security engineer reviews CISA KEV, Google TAG, Adobe/Chrome advisories for fonts, JBIG2/image codecs, JavaScript, and actions. Flag any high-impact CVEs or unusual primitives.
2. **Tracker update** – Add a row to `docs/threat-intel-tracker.md`. Assign the responsible detector(s) and note the desired severity/impact/confidence so it flows into reports.
3. **Implementation plan** – Link the tracker entry back to `plans/20260201-next-steps.md` (or relevant follow-up plan) with the owner(s), tests, and documentation actions.
4. **Documentation update** – When the detector is updated, extend `docs/findings.md` and the relevant `docs/js-detection-*.md` so analysts know how sis maps the CVE to severity/impact/confidence.
5. **Release note / sprint sync** – Summarise the tracker items in the sprint update or release notes, mentioning the new heuristics and CVEs covered.

## Automation hooks
 - Build a small helper script (`scripts/threat_intel_summary.py`) that reads `docs/threat-intel-tracker.md` and prints the new entries since the last release so we can drop them into release notes.
 - Bake a reminder (calendar or task) for the weekly triage so the cadence stays consistent.

## CVE automation refresh
 - Re-evaluate the existing `.github/workflows/cve-update.yml` hook and the `tools/cve-update` binary so the automation fetches only the last seven days of CVEs, can be re-run without generating duplicate files/PRs, and broadens the keyword list beyond fonts to cover all project-relevant attack surfaces.
 - Ensure the workflow captures API failures (404, 429) in the log output and exposes the window (`--days`, `--since`, `--until`) so reviewers can adjust the date range without hunting through code.
 - Treat the automation as a feed for `docs/threat-intel-tracker.md` (or an equivalent tracker) so each CVE entry already carries the `severity/impact/confidence` metadata and the detector owner is referenced, keeping the triage, docs, and release notes in sync.

## Ownership
Each detector maintains ownership of the CVEs it covers. When new entries are added, the owner assigns `severity`, `impact`, and `confidence` inside the tracker and ensures tests (fixtures or unit tests) exist for the new primitives.
