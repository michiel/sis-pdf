# Events CSV Schema (Planned Contract)

Date: 2026-02-22
Status: Pre-release schema contract (export implementation pending)

This document defines the CSV column contract for future `sis query events`
CSV export so downstream tooling can prepare stable parsing logic early.

## Scope

- Rows represent EventGraph event nodes (`kind=event`) only.
- Outcome detail is flattened into summarised columns for CSV safety.
- Full forensic detail remains available via JSON/JSONL (`events.full`).

## Columns

1. `node_id`
2. `event_type`
3. `label`
4. `trigger`
5. `source_object`
6. `execute_target_count`
7. `execute_targets`
8. `outcome_count`
9. `outcome_types`
10. `outcome_confidence_max`
11. `outcome_severity_hints`
12. `linked_finding_count`
13. `linked_finding_ids`
14. `mitre_techniques`
15. `event_key`
16. `initiation`
17. `branch_index`

## Normalisation rules

1. `source_object` is `obj:gen` or empty string when absent.
2. Multi-value fields are comma-separated, sorted, and deduplicated:
   - `execute_targets`
   - `outcome_types`
   - `outcome_severity_hints`
   - `linked_finding_ids`
   - `mitre_techniques`
3. `outcome_confidence_max` is the highest numeric confidence across outcomes,
   or empty string when none exists.
4. Count columns are decimal integers (`0` when empty).
5. Empty optional fields (`event_key`, `initiation`, `branch_index`) are blank.

## Compatibility

- Pre-release: this schema may evolve, but field names should remain stable
  where possible.
- JSON/JSONL remains the authoritative forensic format for nested detail.
