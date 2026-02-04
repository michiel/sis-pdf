# Analysis Guide

This guide describes the analysis phases, detection coverage by component layer,
and correlation logic used in SIS-PDF. It is intended for operators and developers
who need to understand how findings are produced and how to interpret them.

## 1) Analysis Phases

### Phase A: Parsing and Structure Recovery
- Parse the file into an `ObjectGraph` with recovery scanning enabled by default.
- Build object index, xref/trailer view, and deviations if strict mode is on.
- Expand `/ObjStm` in deep mode with budgets and recursion guards.

Outputs:
- Object graph with spans, object ids, and trailer metadata.
- Parser deviations (`strict_parse_deviation`) in strict mode.
- Structural counters for `startxref`, trailers, object totals, ObjStm density.

### Phase B: Fast Triage Detectors
- Cheap detectors run regardless of deep mode; designed for quick triage.
- Examples: `/OpenAction`, `/AA`, `/JavaScript`, xref conflicts, shadowing.

Outputs:
- Action presence findings (`open_action_present`, `aa_present`).
- Structural anomalies (`xref_conflict`, `incremental_update_chain`).

### Phase C: Deep Decoding and Stream Analysis
- Enabled with `--deep` or for specific detectors.
- Decodes selected streams with budget checks.
- Measures filter chains and decompression ratios.
- Performs bounded image decoding for high-risk formats (JBIG2, JPX, JPEG, PNG).

Outputs:
- `decompression_ratio_suspicious`, `decoder_risk_present`.
- Embedded file decoding details (hashes, magic, size, preview).
- Image decoding findings (`image.decode_failed`, `image.jbig2_malformed`).

### Phase D: Intent, Behavior, and Correlation
- Findings are grouped and correlated into higher-level summaries.
- Exploit chains are synthesized from shared action/payload signals.
- Intent buckets classify likely goals (e.g. data exfiltration).

Outputs:
- `intent_summary` with buckets and signals.
- `behavior_summary` for clusters of related findings.
- `chains` and `chain_templates` for attack path grouping.

### Phase E: Optional IR/ORG Static Graph Analysis (`--ir`)
- Builds PDFObj IR per object and ORG (object reference graph).
- Runs static graph detectors for action-to-payload paths and orphans.

Outputs:
- `action_payload_path`, `orphan_payload_object`, `shadow_payload_chain`.
- `objstm_action_chain` when payloads are embedded in ObjStm spans.

### Phase F: Optional ML Classification (`--ml`)
- Traditional stacking classifier uses handcrafted features.
- Graph ML mode (`--ml-mode graph`) uses IR/ORG and GNN model.

Outputs:
- `ml_malware_score_high` (traditional) or `ml_graph_score_high` (graph).
- `ml_summary` for reporting and JSON.

## 2) Detections by Component Layer

### Syntactic Layer
Focus: file headers, EOF markers, parser deviations, polyglots.
- `missing_pdf_header`, `header_offset_unusual`, `missing_eof_marker`, `eof_offset_unusual`.
- `polyglot_signature_conflict` detects multiple magic headers.
- `strict_parse_deviation`, `parser_deviation_in_action_context` (strict mode).

### Structural Layer
Focus: xref chains, object graph integrity, shadowing, ObjStm density.
- `xref_conflict`, `incremental_update_chain`.
- `object_id_shadowing`, `object_shadow_mismatch` (diff parser).
- `objstm_density_high`, `objstm_embedded_summary` (deep).

### Interactive Layer
Focus: automatic triggers and JS execution.
- `open_action_present`, `aa_present`, `aa_event_present`.
- `action_chain_complex`, `action_hidden_trigger`, `action_automatic_trigger`.
- `js_present` plus JS behavior detectors (`js_time_evasion`, `js_env_probe`).

### External Layer
Focus: outbound actions and remote resources.
- `uri_present`, `gotor_present`, `launch_action_present`, `submitform_present`.
- `external_action_risk_context` correlates outbound actions + obfuscation.

### Resource Layer
Focus: streams, filters, embedded objects, media.
- `decompression_ratio_suspicious`, `decoder_risk_present`.
- `filter_chain_depth_high`.
- `filter_chain_unusual`, `filter_order_invalid`, `filter_combination_unusual`.
- `embedded_file_present`, `filespec_present`, `richmedia_present`, `3d_present`, `sound_movie_present`.
- `embedded_executable_present`, `embedded_script_present`, `embedded_archive_encrypted`, `embedded_double_extension`.
- `swf_embedded`.
- `icc_profile_anomaly`, `font_table_anomaly`.
- `image.jbig2_present`, `image.jpx_present`, `image.ccitt_present`.
- `image.extreme_dimensions`, `image.pixel_count_excessive`, `image.decode_failed`.

### Crypto / Signature Layer
Focus: signatures and encryption anomalies.
- `signature_present`, `crypto_weak_algo`, `crypto_cert_anomaly`, `crypto_mining_js`.
- `encryption_key_short`, `stream_high_entropy`, `embedded_encrypted`.

### Forms Layer
Focus: AcroForm/XFA structures and submissions.
- `xfa_present`, `xfa_script_present`, `xfa_submit`, `xfa_sensitive_field`.
- `xfa_too_large`, `xfa_script_count_high`.

### Content / Phishing Layer
Focus: textual cues and overlay links.
- `content_phishing`, `content_html_payload`, `content_deception_overlay`.

## 3) Correlation and Chain Synthesis

### Action Chain Synthesis
- Chains link `trigger -> action -> payload` using findings and metadata.
- Object-level correlation groups findings that share the same object id.
- `correlation.action_payload` indicates action+payload in same object chain.

### Behavioral Correlation
- Findings are clustered by shared object or shared kind.
- `behavior_summary` highlights repeated patterns such as multiple JS findings in one object.

### Intent Buckets
- Signals from findings map into intent buckets (exfiltration, phishing, sandbox escape).
- The highest scoring buckets are surfaced in the report summary.

### Network Intent Correlation
- Extract URLs from actions, JS, and payload previews.
- `network_intents` provides a cross-file correlation surface.

### Stage 9: Composite Correlation Layer
- `sis` runs the optional Stage 9 correlator after detectors resolve, composing higher-level findings from multiple signals. The configuration knobs live under `[scan.correlation]` in `docs/configuration.md`, and the Rust `CorrelationOptions` struct (defaults shown there) lets operators tune entropy, chain depth and sensitive-field thresholds while enabling or disabling each pattern individually.
- Composite findings correspond to the Stage 9 patterns: `launch_obfuscated_executable`, `action_chain_malicious`, `xfa_data_exfiltration_risk`, `encrypted_payload_delivery`, and `obfuscated_payload`. Each one reuses the evidence spans from the contributing findings (launch targets, embedded executables, action chains, XFA submissions, filters and entropy) so triage workflows can trace the full attack path back through the base findings listed above.
- Regression coverage lives in `crates/sis-pdf-core/tests/correlation.rs` and the fixtures referenced there. Those tests exercise every correlation pattern, including the no-op guardrail that ensures benign PDFs do not emit composite findings, and integration suites such as `tests/action_triggers.rs`, `tests/embedded_files.rs`, and `tests/encryption_obfuscation.rs` validate the correlated findings when the inputs span multiple modules.

## 4) IR/ORG Static Graph Detectors (No ML)

### Action-to-Payload Path
- Identifies ORG paths from action nodes to payload-like nodes.
- Emits `action_payload_path` with object ids and evidence spans.

### Orphaned Payload Objects
- Payload-like nodes not reachable from `/Root`.
- Emits `orphan_payload_object` with object ids.

### Shadowed Payload Chains
- Shadowed object ids containing payload-like IR tokens.
- Emits `shadow_payload_chain` to flag hidden revisions.

### ObjStm Payload Chains
- Payload-like objects whose spans overlap ObjStm streams.
- Emits `objstm_action_chain` for embedded payload risks.

## 5) Reporting and Evidence

### Evidence Spans
- File-backed evidence: absolute byte offsets in the PDF.
- Decoded evidence: includes `origin` to map back to raw bytes.

### Report Verbosity
- Use `--report-verbosity [compact|standard|verbose]` to control how findings are presented in the CLI/REPL tables. `compact` drops `Info`/`Low` severity entries from the textual/readable outputs while JSON, JSONL, and YAML outputs retain the full set of findings so your dashboards and automations continue to see every record.
- `--chain-summary [minimal|events|full]` shrinks textual action-chain output when you only care about suspicious triggers/payloads. JSON/JSONL/YAML outputs always emit the full chain, but text/readable tables show the filtered edges plus a small `edges_summary` digest.
- JSON-based `findings` exports now add a `summary` object with severity/surface counts so dashboards ingest a digest without scanning every finding.

### Structural Summary
- `structural_summary` includes xref counts, ObjStm ratios, header/EOF offsets,
  and polyglot risk.

### ML Summary
- `ml_summary` provides score/threshold/label for traditional or graph ML.
- Graph ML packaging schema: `docs/graph-model-schema.md`.

## 6) Operator Workflow

### Triage
1) `sis scan file.pdf`
2) Review grouped findings and high severity alerts.
3) If structural anomalies or ObjStm density is present, run deep scan.

For complete end-to-end workflows, see `docs/scenarios.md`.

### Deep Analysis
1) `sis scan file.pdf --deep --diff-parser`
2) Extract JS and embedded files as needed.
3) Export ORG if path analysis is required: `sis export-org file.pdf --format json`.

### IR/ORG Static Analysis
1) `sis scan file.pdf --ir`
2) Review action->payload path findings and orphans.

### ML Classification
1) `sis scan file.pdf --ml --ml-model-dir models`
2) For graph ML: `--ml-mode graph` with `--features ml-graph`.

## 7) Troubleshooting

- Missing findings in deep mode: ensure `--deep` and budgets allow decoding.
- Graph ML unavailable: compile with `--features ml-graph`.
- Strict deviations in action context: investigate parser divergence and shadowed objects.
