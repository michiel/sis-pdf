# 20260202 Chain detail enhancement plan

## Context

Chain reports currently surface minimal context for each linked finding: a generic path (Trigger/Action/Payload mostly unknown), boilerplate narrative that recites the action type once, a raw object node path, and two very terse score reasons. Analysts rely on these chains to triage suspicious workflow, but the current output forces them to re-open the base findings to understand what triggered the chain, which defeats the purpose of the summary.

## Goals

1. Surface the most relevant finding titles/labels within the chain path so the trigger/action/payload slots immediately say why the chain smells suspicious.
2. Use linked findings themselves to build richer narratives (who triggers what, what payload is delivered) instead of canned sentences about action types.
3. Turn the `Nodes` and `Score reasons` sections into actionable cues by summarising node findings and enumerating which specific findings contributed to the score.

## Proposed steps

1. **Capture descriptive notes while chaining.** Find every place we build a chain and, when a finding is attached (e.g., URI finding, embedded payload, JS execution), populate `chain.notes["trigger.label"]`, `action.label`, and `payload.label` with the finding title/description (or a short summary). Consider also recording `chain.notes["action.target"]`, `payload.summary`, etc.
2. **Augment `chain_execution_narrative`.** Change that helper to first gather up the actual findings referenced by `chain.findings`, extract their titles/descriptions/metadata, and weave them into the narrative (e.g., “URI action `https://…` triggers embedded payload `…`”). Fall back to the current canned sentences only when there are no descriptive findings.
3. **Improve node rendering.** When listing `chain.nodes`, look up each node‘s linked findings and include a preview like “Annotation Link (uri_present, finding: URI present)” instead of the raw doc path. You can reuse `position_previews` to store these richer strings.
4. **Enrich `chain.reasons`.** Instead of “Structure: X suspicious finding(s)”, emit per-finding reasons by inspecting `chain.findings` and summarising them (e.g., “References uri_present -> external navigation”). This may require adjusting the chain builder to push these strings while it aggregates findings.
5. **Document the new behaviour.** Update `docs/sis-pdf-spec.md` (or another appropriate docs file) to describe the richer chain output so analysts know what each bullet now means.

## Implementation status

- [x] Capture descriptive chain notes and expose labels/summary metadata via `chain.notes`.
- [x] Use the rich notes when generating the narrative so it cites the actual findings and payload information.
- [x] Enhance node previews and score reasons to surface the actual findings behind each chain step.
- [x] Document the improved chain reporting.
- [x] Preserve detector-supplied labels when rendering so rich notes survive fallback.
- [x] Add regression tests proving that chain notes and the narrative surface the custom labels.

## Next steps

- None; the new label-preservation safeguards and tests keep the richer context intact.

## Testing

- `cargo test -p sis-pdf-core` (chains affect stage 9 reporting).  
- `cargo test -p sis-pdf` (ensure CLI output changes don’t regress formatting tests).

## Risks

- If `chain.notes` are populated too aggressively, low-value findings could clutter the path text; gating the logic on high-confidence findings or prioritising by score can mitigate that.
- Chain-building happens in multiple detectors; we must ensure the new note fields stay populated consistently across them to avoid partial summaries. 
