# Next Steps (2026-01-30)

1. Finalise Stage 3 (XFA forms): ensure detectors emit `xfa_*` findings with submit/sensitive metadata, tighten parsing limits, and cover script extraction metadata in docs.
2. Sync Stage 3 query updates with `actions.triggers` so filters like `xfa.scripts` and `xfa.submit` expose metadata for predicate filtering, export, and ML ingestion.
3. Prepare for Stage 4 (rich media and SWF) by auditing current SWF helpers and planning metadata/feature hooks for `swf_embedded` and `swf_actionscript_detected`.
