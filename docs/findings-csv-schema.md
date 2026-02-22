# Findings CSV Schema

This document defines the CSV schema for findings query exports.

## Commands

```bash
sis query sample.pdf findings.csv
sis query sample.pdf findings.composite.csv
sis query sample.pdf findings --format csv
sis query sample.pdf findings.composite --format csv
```

## Schema version

- `schema_version=1` (documented version for the current column layout).

## Columns

1. `id`
2. `kind`
3. `severity`
4. `impact`
5. `confidence`
6. `surface`
7. `title`
8. `description`
9. `objects`
10. `evidence_count`
11. `remediation`
12. `meta_json`

## Field notes

- `objects` uses `|` as a stable internal delimiter for multi-object findings.
- `meta_json` is a JSON-encoded object with deterministic key ordering.
- Values are RFC 4180 escaped when needed (comma, quote, newline).
- `impact` is empty when no explicit impact was assigned.

## Compatibility

- New columns, when added, should be appended to preserve existing ingestion.
- Existing column names and order should remain stable for `schema_version=1`.
