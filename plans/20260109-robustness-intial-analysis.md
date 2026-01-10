# Robustness Initial Analysis (2026-01-09)

This document summarises the first pass of stages 1–3 from `plans/20260109-robustness.md` using the outputs in `/home/michiel/dev/sis-training/research-out`.

## Stage 1: Corpus Scan + Intents

Corpus size:
- 1,000 PDFs in `./corpus` (confirmed via `features.jsonl` entries).

Findings coverage:
- `corpus.findings.jsonl`: 13,155 findings across 998 files.
- `corpus.strict.jsonl`: 2,917,407 findings across 1,000 files.

Intent extraction:
- `intents.jsonl`: 5,765 intent entries from 728 files.
- 940 unique domains detected.

Observations:
- Strict mode output is dominated by strict parser deviations, inflating JSONL output volume.
- Intent extraction now finds activity in most files, but still needs careful filtering (tracked separately).

## Stage 2: Detection Robustness and Mode Sensitivity

Standard vs deep:
- 759 files change their finding sets.
- 780 deep-only finding kinds added; no removals.
- Deep-only additions are dominated by `js_sandbox_exec` (679 files), followed by `js_runtime_file_probe`, `objstm_embedded_summary`, and `decompression_ratio_suspicious`.

Standard vs strict:
- 1,000 files change their finding sets.
- 3,774 strict-only finding kinds added; no removals.
- Strict mode adds a large volume of low-severity deviations that overwhelm other signals.

Severity mix:
- Standard: 1,683 High / 10,012 Medium / 1,460 Low.
- Deep: 1,751 High / 10,057 Medium / 1,472 Low / 842 Info.
- Strict: 2,522 High / 22,746 Medium / 2,892,139 Low.

## Stage 3: Feature Coverage

Dead features (never observed in 1,000 files):
- `graph.uri_target_edges`
- `graph.launch_target_edges`
- `graph.external_chain_count`
- `graph.multi_stage_indicators`
- `attack_surfaces.metadata_count`
- `severity_dist.total_critical`
- `severity_dist.total_info`
- `confidence_dist.heuristic_high_severity`
- `finding.objstm_embedded_summary`
- `finding.objstm_action_chain`
- `finding.orphan_payload_object`
- `finding.shadow_payload_chain`
- `finding.decompression_ratio_suspicious`
- `finding.huge_image_dimensions`
- `finding.icc_profile_oversized`
- `finding.gotor_present`
- `finding.submitform_present`
- `finding.external_action_risk_context`
- `finding.js_multi_stage_decode`
- `finding.js_runtime_file_probe`
- `finding.js_runtime_network_intent`
- `finding.crypto_mining_js`
- `finding.js_sandbox_result`
- `finding.uri_content_analysis`
- `finding.uri_presence_summary`
- `finding.action_payload_path`
- `finding.richmedia_present`
- `finding.sound_movie_present`
- `finding.font_payload_present`
- `finding.fontmatrix_payload_present`
- `finding.dss_present`
- `finding.content_html_payload`
- `finding.content_invisible_text`
- `finding.annotation_attack`
- `finding.page_tree_cycle`
- `finding.page_tree_manipulation`
- `finding.supply_chain_persistence`
- `finding.supply_chain_staged_payload`
- `finding.supply_chain_update_vector`
- `finding_count.objstm_embedded_summary`
- `finding_count.objstm_action_chain`
- `finding_count.orphan_payload_object`
- `finding_count.shadow_payload_chain`
- `finding_count.decompression_ratio_suspicious`
- `finding_count.huge_image_dimensions`
- `finding_count.icc_profile_oversized`
- `finding_count.gotor_present`
- `finding_count.submitform_present`
- `finding_count.external_action_risk_context`
- `finding_count.js_multi_stage_decode`
- `finding_count.js_runtime_file_probe`
- `finding_count.js_runtime_network_intent`
- `finding_count.crypto_mining_js`
- `finding_count.js_sandbox_result`
- `finding_count.uri_content_analysis`
- `finding_count.uri_presence_summary`
- `finding_count.action_payload_path`
- `finding_count.richmedia_present`
- `finding_count.sound_movie_present`
- `finding_count.font_payload_present`
- `finding_count.fontmatrix_payload_present`
- `finding_count.dss_present`
- `finding_count.content_html_payload`
- `finding_count.content_invisible_text`
- `finding_count.annotation_attack`
- `finding_count.page_tree_cycle`
- `finding_count.page_tree_manipulation`
- `finding_count.supply_chain_persistence`
- `finding_count.supply_chain_staged_payload`
- `finding_count.supply_chain_update_vector`
- `js_signals.max_obfuscation_score`
- `js_signals.avg_obfuscation_score`
- `js_signals.total_eval_count`
- `js_signals.max_eval_count`
- `js_signals.max_string_concat_layers`
- `js_signals.max_unescape_layers`
- `js_signals.time_evasion_present`
- `js_signals.env_probe_present`
- `js_signals.multi_stage_decode`
- `js_signals.sandbox_executed`
- `js_signals.sandbox_timeout`
- `js_signals.runtime_file_probe`
- `js_signals.runtime_network_intent`
- `js_signals.crypto_mining_detected`
- `js_signals.js_in_openaction`
- `js_signals.js_in_aa`
- `js_signals.js_in_annotation`
- `js_signals.js_in_field`
- `js_signals.fromcharcode_count`
- `js_signals.multiple_keys_present`
- `js_signals.ref_chain_depth`
- `js_signals.array_fragment_count`
- `uri_signals.unique_domains`
- `uri_signals.max_risk_score`
- `uri_signals.avg_risk_score`
- `uri_signals.javascript_uri_count`
- `uri_signals.file_uri_count`
- `uri_signals.http_count`
- `uri_signals.https_count`
- `uri_signals.ip_address_count`
- `uri_signals.suspicious_tld_count`
- `uri_signals.obfuscated_count`
- `uri_signals.data_exfil_pattern_count`
- `uri_signals.hidden_annotation_count`
- `uri_signals.automatic_trigger_count`
- `uri_signals.js_triggered_count`
- `uri_signals.tracking_params_count`
- `uri_signals.max_url_length`
- `uri_signals.phishing_indicators`
- `uri_signals.external_dependency_count`
- `uri_signals.mixed_content_present`
- `content_signals.invisible_text_pages`
- `content_signals.overlay_link_count`
- `content_signals.image_only_pages`
- `content_signals.html_payload_present`
- `content_signals.hidden_annotation_count`
- `content_signals.suspicious_font_count`
- `content_signals.text_rendering_anomalies`
- `content_signals.color_manipulation_count`
- `content_signals.whitespace_abuse_count`
- `content_signals.unicode_rtlo_count`
- `content_signals.homoglyph_count`
- `content_signals.zero_width_char_count`
- `content_signals.text_direction_abuse`
- `supply_chain.persistence_mechanisms`
- `supply_chain.staged_payload_count`
- `supply_chain.multi_stage_chains`
- `supply_chain.command_control_indicators`
- `supply_chain.lateral_movement_indicators`
- `supply_chain.data_staging_indicators`
- `supply_chain.exfiltration_indicators`
- `supply_chain.anti_forensics_techniques`
- `structural_anomalies.objstm_density`
- `structural_anomalies.filter_chain_max_depth`
- `structural_anomalies.decompression_max_ratio`
- `structural_anomalies.parser_deviations`
- `structural_anomalies.trailer_anomalies`
- `structural_anomalies.catalog_anomalies`
- `structural_anomalies.cross_ref_stream_anomalies`
- `structural_anomalies.orphaned_objects`
- `structural_anomalies.circular_references`
- `structural_anomalies.invalid_object_refs`
- `structural_anomalies.unusual_object_sizes`
- `structural_anomalies.object_id_gaps`
- `structural_anomalies.generation_number_anomalies`
- `crypto_signals.signature_validation_failed`
- `crypto_signals.timestamp_anomalies`
- `crypto_signals.revocation_check_failed`
- `crypto_signals.self_signed_cert`
- `crypto_signals.encryption_weakness_score`
- `embedded_content.pe_executable_count`
- `embedded_content.encrypted_container_count`
- `embedded_content.double_extension_count`
- `embedded_content.flash_content_count`
- `embedded_content.suspicious_mime_types`
- `embedded_content.mismatched_extensions`
- `embedded_content.archive_count`
- `embedded_content.nested_archive_depth`
- `embedded_content.password_protected_count`
- `embedded_content.macro_enabled_count`

## JSONL Integrity

Issue:
- `findings.*.jsonl` outputs previously included a trailing non‑JSON line (`# sis-pdf Batch Report`), which caused parse errors.

Fix:
- Batch scans now return early when `--jsonl-findings` is active, preventing markdown summaries from being appended.
- Re-run outputs have zero JSON parse errors.

## Implemented Recommendations

1) Strict deviation summary mode:
- Added `--strict-summary` to emit a single summary finding instead of one per deviation.
- Summary includes total deviations, unique kinds, and top counts.

2) Deep‑mode delta investigation support:
- Added `scripts/compare_findings.py` to compare two JSONL outputs (e.g. standard vs deep) and report top additions/removals per finding kind.

4) JSONL output integrity:
- Batch scans no longer append markdown summaries to JSONL findings output.

## Next Questions

- Are the deep‑mode additions (especially `js_sandbox_exec`) true positives or decoder side‑effects?
- Should strict deviations be summarised in a separate report object for downstream systems?
- Do the dead features require detector or corpus expansion, or should they be gated or removed?

## Deep vs Standard Delta Summary (Follow‑up)

Using `scripts/compare_findings.py` on the latest outputs:
- 759 files differ between standard and deep.
- Top deep‑only additions: `js_sandbox_exec` (679 files), `js_runtime_file_probe` (45), `objstm_embedded_summary` (34), `decompression_ratio_suspicious` (16), `js_sandbox_skipped` (5), `js_runtime_network_intent` (1).
- No removals from standard to deep in this corpus.
