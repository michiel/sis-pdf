# Next Steps (2026-01-30)

1. Implement Stage 9 correlation plumbing: scaffold `FindingCorrelator`, wire the composite finding IDs (`launch_obfuscated_executable`, `action_chain_malicious`, etc.), and ensure correlation configuration (pattern enablement, entropy/depth thresholds) is plumbed through the pipeline.
2. Flesh out the Stage 9 regression coverage by linking each correlation pattern to its CVE fixtures/tests, then build the unit/integration skeletons that prove `launch_obfuscated_executable`, `xfa_data_exfiltration_risk`, `obfuscated_payload` and the rest fire when expected.
3. Capture the remaining validation tasks (JSONL export streaming, ML schema updates, cross-finding QA) so the next work cycle can pick up exactly where Stage 9 leaves off.
