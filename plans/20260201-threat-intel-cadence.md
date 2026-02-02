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
- The `.github/workflows/cve-update.yml` job now calls `tools/cve-update` with `--days 7` and `--tracker docs/threat-intel-tracker.md`, so every run writes new rows into the tracker and keeps the signature directory in sync without duplicating YAML files.
- The tool's keyword list now spans fonts, image codecs, JS, actions, structures, and filter chains; `404 Not Found` responses are treated as empty result sets so short windows do not abort the job, while `--since`/`--until` still let analysts expand the window if needed.
- Treat the tracker rows as the automation feed: each generated row comes with placeholder `severity`, `impact`, `confidence = Probable`, `Detector(s) = TBD`, and a note linking to the NVD detail for rapid triage before assigning the owner.

## Ownership
Each detector maintains ownership of the CVEs it covers. When new entries are added, the owner assigns `severity`, `impact`, and `confidence` inside the tracker and ensures tests (fixtures or unit tests) exist for the new primitives.
