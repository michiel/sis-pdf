# Reader Profile Notes

This document preserves historical reader-profile severity cap logic that was previously applied as finding enrichment.

As of 2026-02-21 pre-release changes, reader-specific impact assignment is no longer emitted into finding payloads.

## Historical cap behaviour

For reference, the removed enrichment logic applied these caps:

- `Acrobat`: no cap (base finding severity used as-is).
- `Pdfium`:
  - `JavaScript` capped at `medium`.
  - `EmbeddedFiles` capped at `high`.
- `Preview`:
  - `JavaScript` capped at `low`.
  - `Actions` capped at `medium`.
  - `EmbeddedFiles` capped at `medium`.

All other surfaces retained the base finding severity.

## Current behaviour

- Findings no longer include `reader_impacts`.
- Findings no longer include `reader.impact.<profile>` metadata keys.
- Findings no longer include `reader.impact.summary` metadata.

If per-reader triage views are needed later, they should be reintroduced behind an explicit opt-in output mode.
