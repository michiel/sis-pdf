Implementation Plan for New sis-pdf Analysis Modules

Goal: deliver six new analysis modules in staged, executable increments with clear acceptance checklists, tests, and documentation updates. Stages are ordered to unlock reuse (e.g. shared stream metadata and attachment parsing). All work uses Australian English spelling and follows sis-pdf logging and finding metadata conventions.

Stage 0: Alignment, scope, and baseline

Scope: establish shared utilities, findings registry updates, and test scaffolding that subsequent stages reuse.

Checklist
- Confirm existing findings and schemas to extend (docs/findings.md, any finding registry in code).
- Record which planned findings already exist vs need new IDs (keep a short mapping in this plan).
- Identify shared helper needs (stream magic, hashing, entropy, filter parsing) and create a small shared module if required.
- Add or update fixtures in crates/sis-pdf-core/tests/fixtures/ for attachments, actions, and media as needed.
- Add test skeletons in crates/sis-pdf-detectors/tests/ (or relevant crates) for each module with TODO markers removed.
- Verify baseline tests pass after any scaffolding changes.

Acceptance
- Shared helpers and fixtures are in place.
- No new findings are emitted yet.
- Tests compile and run, even if some are pending data.

Findings inventory (initial mapping)
- Existing IDs: embedded_file_present, filespec_present, launch_action_present, aa_present, aa_event_present, open_action_present, annotation_action_chain, action_payload_path, gotor_present, submitform_present, uri_present, xfa_present, xfa_script_present, actionscript_present, swf_url_iocs, richmedia_present, 3d_present, sound_movie_present, encryption_present, crypto_weak_algo, quantum_vulnerable_crypto, filter_chain_depth_high, declared_filter_invalid, undeclared_compression_present, label_mismatch_stream_type.
- Likely new IDs (if distinct from metadata): embedded_executable_present, embedded_script_present, embedded_archive_encrypted, embedded_double_extension, launch_external_program, launch_embedded_file, action_chain_complex, action_hidden_trigger, action_automatic_trigger, xfa_submit, xfa_sensitive_field, xfa_too_large, swf_embedded, stream_high_entropy, embedded_encrypted, encryption_key_short, filter_chain_unusual, filter_order_invalid, filter_combination_unusual.

Stage 1: Embedded Files and Launch Actions

Scope: detect and enrich embedded file findings; correlate /Launch actions with embedded attachments and external program invocations.

Checklist
- Implement EmbeddedFileDetector in crates/sis-pdf-detectors with SHA-256, size, filename, and magic-type extraction.
- Implement LaunchActionDetector or extend EmbeddedFileDetector to parse /Launch in /Action, /AA, and /OpenAction.
- Correlate Launch actions to embedded files via file spec or object reference.
- Add findings for embedded executable, embedded script, encrypted archive, double extension, and launch of external program.
- Ensure structured evidence fields include object ids, filenames, file types, hashes, and launch targets.
- Register detector(s) in crates/sis-pdf-detectors/lib.rs and wire into Phase C (or earlier for action-only parsing).

Tests
- Integration tests with synthetic PDFs: embedded EXE, embedded ZIP (with and without password), embedded script, and Launch action referencing attachment.
- Assert findings include severity/impact/confidence and expected evidence fields.

Acceptance
- Deep scan emits attachment findings with metadata and correlates Launch actions.
- Tests cover all new findings and pass locally.

Stage 2: Actions and Triggers

Scope: build action-trigger chain mapping and flag complex or hidden action paths.

Checklist
- Implement ActionTriggerDetector to walk /OpenAction, /AA, annotation actions, and AcroForm triggers.
- Build a bounded action chain tracker (configurable max depth).
- Add findings for complex chains, hidden triggers, and unusual automatic triggers.
- Ensure structured evidence includes event types, object ids, and chain path.
- Register detector and integrate with any existing IR graph where feasible.

Tests
- PDFs with annotation /AA to JavaScript, hidden widgets with actions, and multi-step chains.
- Verify no false positives for benign hyperlink annotations.

Acceptance
- Chain findings surface in deep scan with stable evidence fields.
- Tests pass and cover benign and malicious action patterns.

Stage 3: XFA Forms

Scope: parse XFA XML, detect embedded scripts and submissions, and enumerate sensitive fields.

Checklist
- Implement XfaFormDetector to extract /XFA streams and parse XML.
- Identify <script> tags and emit xfa_script_present with code excerpts or identifiers.
- Detect submit actions and emit xfa_submit with target URLs.
- Flag sensitive field names with xfa_sensitive_field based on simple heuristics.
- Enforce XFA size limits with xfa_too_large if exceeded.
- Register detector in Phase C and ensure it only runs when XFA exists.

Tests
- PDF with simple XFA containing a script and submit action.
- PDF with large XFA to validate size cutoff handling.

Acceptance
- XFA findings appear with evidence and no parsing crashes on malformed XML.
- Tests cover script, submit, and size-limit behaviour.

Stage 4: Rich Media Content

Scope: inspect embedded SWF and other rich media streams for script tags and risky indicators.

Checklist
- Implement RichMediaDetector to identify SWF by magic (FWS/CWS) and emit swf_embedded.
- Parse SWF tags (DoAction/DoABC) and emit flash_actionscript_present where applicable.
- Detect basic 3D/media types (U3D/PRC/MP3/MP4) and emit presence findings with size metadata.
- Guard parsing with size limits and stream budgets.
- Register detector in Phase C.

Tests
- PDF with embedded SWF that includes ActionScript.
- PDF with embedded audio or 3D content.

Acceptance
- SWF detection and ActionScript findings appear reliably.
- Tests cover SWF and at least one other media type.

Stage 5: Encryption and Obfuscation

Scope: broaden encryption metadata checks and stream entropy detection.

Checklist
- Implement EncryptionDetector to inspect /Encrypt dictionary and emit encryption_present plus weak algorithm findings.
- Compute stream entropy for decoded streams and emit stream_high_entropy where thresholds are exceeded.
- Flag embedded encrypted archives or uncommon /Crypt filter usage.
- Add configuration for entropy thresholds and per-stream limits.
- Register detector in Phase C (and Phase A/B for trailer-level encryption if needed).

Tests
- PDFs with RC4-40 and AES-128/256 encryption settings.
- PDF with high-entropy stream to validate thresholds.

Acceptance
- Encryption and high-entropy findings are emitted with clear evidence.
- Tests cover at least one weak and one strong encryption case.

Stage 6: Filter Chain Anomaly Detection

Scope: detect unusual or invalid filter sequences beyond depth-only heuristics.

Checklist
- Implement FilterChainDetector to validate filter order and flag uncommon combinations.
- Maintain a small allowlist of normal chains and emit filter_chain_unusual for deviations.
- Flag invalid filter ordering (ASCIIHex/ASCII85 inner filters) and repeated filters beyond a small count.
- Register detector in Phase C and ensure it does not clash with existing filter_chain_depth_high logic.

Tests
- PDFs with valid filter chains (should not trigger).
- PDFs with exotic or invalid filter sequences (should trigger).

Acceptance
- Findings are emitted only for anomalous filter sequences.
- Tests cover valid and invalid cases.

Stage 7: Documentation and integration sweep

Scope: keep documentation consistent, and verify end-to-end behaviour.

Checklist
- Update docs/findings.md with new finding ids, severity/impact/confidence guidance, and evidence fields.
- Add or update documentation in docs/ for new analysis features if user-facing.
- Ensure findings are wired into any reporting or JSON schema documentation.
- Run full test suite and targeted scans on sample PDFs.

Acceptance
- Documentation matches emitted findings.
- Tests pass and sample scans show expected output using `sis` invocation syntax.

Notes on staged execution
- Each stage should be merged only when tests pass and findings have defined metadata.
- Keep new detectors within crates/sis-pdf-detectors and reuse existing parsing utilities rather than adding new parsers unless required.
- Avoid logging sensitive content; keep evidence concise and structured.
