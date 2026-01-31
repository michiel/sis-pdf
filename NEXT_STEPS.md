# Next Steps (2026-01-30)

1. Document the completed Stage 9 correlation layer (config knobs, composite IDs, and regression tests) so future reviewers can trace the new composite findings back to the configuration docs and test matrix.
2. Validate the remaining data paths introduced by the new findings: run `sis query features --format jsonl` to ensure the 76 feature columns (including correlation metadata) appear, refresh `docs/ml-features.md` with the updated feature index, and double-check JSONL/csv exports still match the schema.
3. Continue Stage 8 Feature Vector integration and cross-finding QA: lock down the feature ordering, confirm the JSONL & CSV exporters reference the new fields, and plan follow-up query documentation for the correlation shortcuts introduced today.
