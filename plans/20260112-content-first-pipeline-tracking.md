# Content-first pipeline tracking checklist

## Phase 1 — Core pipeline

- [x] Define `Blob`, `BlobOrigin`, and `BlobPathStep` types
- [x] Add `DecodeMeta`, `DecodeOutcome`, and decode limits
- [x] Implement bounded decode service with mismatch detection
- [x] Add basic signature classifier (PE/ELF/ZIP/PDF/SWF/JPEG/PNG/XML/HTML)
- [x] Emit findings: `label_mismatch_stream_type`, `undeclared_compression_present`, `declared_filter_invalid`
- [x] Add fixtures for `/Subtype` mismatch and bad filter cases

## Phase 2 — Carving and nested extraction

- [x] Add magic-carver for decoded blobs
- [x] Add ZIP container walker (bounded)
- [x] Emit `embedded_payload_carved`, `nested_container_chain`

## Phase 3 — Script expansion

- [x] Add script text classifiers (VBScript, PowerShell, bash, cmd, AppleScript)
- [x] Add XFA/XML `<script>` detection
- [x] Emit `vbscript_payload_present`, `powershell_payload_present`, `xfa_script_present`

## Phase 4 — SWF/ActionScript deep scan

- [x] Parse SWF tags and detect `DoABC` / `DoABC2`
- [x] Extract strings and IOCs
- [x] Emit `actionscript_present`, `swf_url_iocs`

## Phase 5 — Structural hardening and multi-parse reconciliation

- [x] Add carve-based parser mode and object provenance
- [x] Analyse shadow objects automatically
- [x] Emit `shadow_object_payload_divergence`, `parse_disagreement`

## Phase 6 — Benchmark harness

- [x] Build corpus runner
- [x] Compare against `pdfid` / `pdf-parser` output
- [x] Track regressions and mismatches
