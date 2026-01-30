# Next Steps (2026-01-30)

1. Complete Stage 5 (Encryption & Obfuscation) by enriching `crypto_weak_algo` metadata (algorithm/key length fields), wiring `streams.high-entropy` + `encryption.weak` queries/predicates, and adding tests/fixtures that prove high-entropy streams and encrypted embedded files surface expected findings.
2. Lock down Stage 8 feature export coverage: verify the `features` query exports all 76 values in CSV/JSON/JSONL modes, document the new encryption/stream fields in `docs/query-interface.md` and `docs/query-predicates.md`, and make sure the ML feature schema notes the added encryption/filter inputs.
3. Begin Stage 9 cross-finding correlation by outlining how XFA, encryption, and filter-chain signals feed multi-stage scoring while collecting the remaining CVE fixtures/tests that tie these surfaces together.
