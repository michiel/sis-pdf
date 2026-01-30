# Next Steps (2026-01-30)

1. Lock down Stage 8 feature exports: verify `features`/`export-features` support CSV, JSON and JSONL modes including batch streaming, confirm the CSV/JSON headers cover the 76-feature vector, and highlight the encryption/filter/XFA inputs in `docs/query-interface.md`, `docs/query-predicates.md` and the forthcoming `docs/ml-features.md`.
2. Start Stage 9 correlation planning: define the `FindingCorrelator` API, enumerate composite finding IDs that link XFA, encryption and filter signals (e.g., obfuscated payload delivery), and map CVE fixtures/tests that exercise each correlation pattern.
3. Ensure the audit trail keeps pace by logging any remaining validation work (JSONL export tests, ML schema updates, cross-finding scenarios) so the next iteration can follow the same cadence.
