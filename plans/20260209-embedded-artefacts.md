# Embedded artefact consistency remediation plan

Date: 2026-02-09  
Owner: sis-pdf maintainers  
Status: Proposed

## 1. Problem statement

Embedded script detection is inconsistent across attached artefacts in PDFs where script identity is split across:

- `/EmbeddedFile` stream bytes
- `/Filespec` metadata (`/F`, `/UF`)
- Name-tree references (`/Names` → `/EmbeddedFiles`)

Observed effect (sample `tmp/pentest-pdf-collection/pdf_files/20250820_143923_attach_scripts.pdf`):

- `hello.sh` is identified as script.
- `hello.bat` and `hello.ps1` are not consistently identified as scripts.

This causes incomplete findings and weak analyst traceability.

## 2. Root cause summary

1. `embedded_script_present` currently depends on `magic_type == "script"` from stream bytes.
2. Stream magic detection recognises shebang scripts (`#!`) but not command/PowerShell script headers.
3. Embedded filename enrichment is stream-local and misses filename context held on linked `/Filespec` objects.
4. Script heuristics are split across detectors with different criteria and metadata models.

## 3. Goals

1. Detect script attachments consistently across `sh`, `bat/cmd`, and `ps1` classes.
2. Normalise embedded artefact metadata across findings (`filename`, `filespec`, stream ref, hashes).
3. Preserve low false-positive rate via multi-signal scoring.
4. Ensure query/report output supports manual exploration from finding to object graph.

## 4. Non-goals

- Full interpreter-level script emulation.
- Replacing all existing `content_first` script heuristics for non-embedded streams.

## 5. Design

## 5.1 Embedded artefact index (single source of truth)

Introduce a shared indexed model (detector crate scope) for embedded artefacts:

- `stream_ref` (`obj gen`)
- `filespec_ref` (`obj gen`, optional)
- `filename` (resolved canonical name from Filespec/Name tree)
- `decoded_bytes` / `raw_bytes` stats
- hashes (`sha256`, `blake3`)
- `magic_type`, extension, subtype hints

Resolution order for filename:

1. `/Filespec /UF`
2. `/Filespec /F`
3. stream-local `/UF` or `/F` (fallback only)

## 5.2 Multi-signal script classification

Compute script confidence from weighted evidence:

- Extension signal: `.sh`, `.bash`, `.zsh`, `.bat`, `.cmd`, `.ps1`, `.psm1`
- Header signal: shebang, `@echo off`, `powershell`, `Write-Host`, etc.
- Lexical signal: command/script keywords with printable-text ratio gate
- Optional subtype signal: JavaScript/ECMAScript marker in metadata

Classification output:

- `is_script` boolean
- `script_family` (`shell`, `cmd`, `powershell`, `vbscript`, `javascript`, `unknown_script`)
- `script_confidence` (`strong`, `probable`, `tentative`)
- evidence list of matched signals

## 5.3 Detector integration

Refactor `EmbeddedFileDetector` to use the index + classifier for:

- `embedded_file_present` (always)
- `embedded_script_present` (script classifier-driven)
- existing executable/archive/double-extension findings

Add metadata keys:

- `embedded.filename`
- `embedded.filespec_ref`
- `embedded.stream_ref`
- `embedded.script_family`
- `embedded.script_confidence`
- `embedded.script_signals`
- `query.next` (e.g., `object 10 0`, `object 11 0`)

## 5.4 Query output improvements

Update `query embedded` output to include filename when available and keep object linkage explicit:

- current: `embedded_11_0.bin (11_0, 29 bytes)`
- target: `hello.bat (stream 11_0, filespec 10_0, 29 bytes)`

## 6. Implementation work plan

### Step 1: Build shared embedded artefact indexing helper

Files:

- `crates/sis-pdf-detectors/src/lib.rs` (or new `embedded_index.rs`)

Tasks:

- Build stream↔filespec↔name-tree mapping once per scan context.
- Expose helper for detectors.

### Step 2: Implement script classifier for embedded artefacts

Files:

- `crates/sis-pdf-detectors/src/lib.rs` (or new `embedded_script_classifier.rs`)

Tasks:

- Add extension + lexical + header signal fusion.
- Return stable metadata payload.

### Step 3: Refactor embedded detector paths

Files:

- `crates/sis-pdf-detectors/src/lib.rs`

Tasks:

- Replace single magic-based script check with classifier result.
- Ensure `embedded_script_present` is emitted for bat/ps1 cases when signals meet threshold.
- Keep existing severity/confidence alignment policy.

### Step 4: Update query rendering for embedded artefacts

Files:

- `crates/sis-pdf/src/commands/query.rs`

Tasks:

- Display canonical filenames and refs in `embedded` results.

### Step 5: Add regression tests and fixture assertions

Files:

- `crates/sis-pdf-detectors/tests/embedded_files.rs`
- `crates/sis-pdf-core/tests` (fixture-based integration test)

Tests:

1. Sample attachment PDF reports three `embedded_file_present`.
2. Sample attachment PDF reports three `embedded_script_present`.
3. Script family metadata is correct per attachment (`shell`, `cmd`, `powershell`).
4. Query output includes resolved filenames.

## 7. Acceptance criteria

1. `hello.sh`, `hello.bat`, and `hello.ps1` all produce script findings.
2. Findings include object + filespec traceability metadata.
3. No regressions in existing embedded executable/archive detections.
4. Query output for `embedded` is filename-aware and reproducible.

## 8. Risks and mitigations

1. **Risk**: false positives from short text files.  
   **Mitigation**: require multi-signal threshold and textuality gating.

2. **Risk**: metadata conflicts between stream and Filespec names.  
   **Mitigation**: explicit precedence order and metadata note for conflicts.

3. **Risk**: duplicated logic with `content_first` script heuristics.  
   **Mitigation**: isolate embedded-specific classifier and avoid cross-surface overloading.

