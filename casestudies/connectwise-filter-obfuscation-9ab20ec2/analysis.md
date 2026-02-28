# Case Study: ConnectWise Filter Obfuscation with External Installer Lure

**Fixture**: `crates/sis-pdf-core/tests/fixtures/corpus_captured/connectwise-filter-obfuscation-9ab20ec2.pdf`  
**SHA256**: `9ab20ec2ce6e78ca129ebfd4e0d1e844de1b03c7fbac9ea9a681d0dd6383029d`  
**Classification**: Malicious | DataExfiltration + Obfuscation

## Threat Summary

This sample blends structure-level obfuscation signals with mass external URI actions and an installer lure. The notable target is a ScreenConnect MSI URL (`.../ScreenConnect.ClientSetup.msi?...`). It is an operational phishing/dropper pattern where many low/medium signals combine into a high-confidence malicious verdict.

## File Structure

- Objects: 102
- Trailers: 2 (`secondary_parser.trailer_count=4`)
- ObjStm count: 1
- Incremental updates and trailer divergence present

## Detection Chain

Primary findings:
- `annotation_action_chain` x20
- `uri_classification_summary` x20
- `object_reference_cycle` x25
- `content_overlay_link` (High)
- `font_exploitation_cluster` (High)

Intent:
- `DataExfiltration` score 40 (Strong)
- `ExploitPrimitive` score 7 (Strong)
- `Phishing` score 2 (Heuristic)

Runtime profile:
- Total deep scan runtime: ~1.56 s
- `content_first_stage1`: ~1.51 s hotspot

## Evasion Techniques

- Incremental/trailer churn and graph-cycle noise to obstruct deterministic parsing.
- High-volume annotation URI surfaces to distribute payload targets.
- Incremental/trailer complexity to increase parser divergence noise.

## Key Indicators

- Installer lure URL: `https://wakilamakila.com/Bin/ScreenConnect.ClientSetup.msi?...`
- High URI-action density with external MSI lure target
- Combined URI-action and obfuscation indicators in the same document

## Regression Coverage

- `connectwise_filter_obfuscation_fixture_stays_stable`

## Chain Assessment

The chain model still under-represents this attack path end-to-end. Although one URI-related multi-finding chain exists, top-ranked chains are dominated by singleton structural findings (`xref_conflict`, `parser_trailer_count_diff`, `incremental_update_chain`). A dedicated "mass external action + filter obfuscation" composite chain would improve triage accuracy.
