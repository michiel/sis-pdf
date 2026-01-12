# Content-first pipeline plan (2026-01-12)

This plan closes scripting/media gaps and stops trusting PDF self-description (for example `/Subtype /Image`) by moving to a content-first classification pipeline.

## 1) Design goals and threat model

Goals:
- Assume adversarial structure: dictionaries, `/Type`, `/Subtype`, `/Filter`, and even xref may be misleading.
- Classify by bytes first: treat PDF labels as hints, not truth.
- Targeted content checks: for each extracted blob/stream, run a cascade of deterministic checks (signatures → lightweight parsing → deeper parsing where warranted).
- Evidence graph: every finding ties back to concrete object refs, offsets (when possible), and extraction path.
- Safe and bounded: resist zip bombs, filter bombs, deep recursion, pathological xref cycles.

Non-goals:
- Full dynamic emulation of PDF viewer behaviour (remain static).
- Perfect recovery from totally broken PDFs (best-effort with explicit uncertainty).

## 2) Architecture shift: Decode → Classify → Inspect

### 2.1 Unified extraction model

Create a single internal representation for “byte-bearing things”:

```rust
struct Blob {
  origin: BlobOrigin,        // Stream, string, embedded file, xref span, etc.
  pdf_path: Vec<PathStep>,   // Obj(12) -> Key("AA") -> Ref(77) -> Stream
  raw: BytesRef,             // raw bytes as in file (or recovered span)
  decoded: Option<Vec<u8>>,  // after filter decode (bounded)
  decode_meta: DecodeMeta,   // filters used, failures, truncation flags
}
```

`BlobOrigin` should include:
- `Stream { obj_ref }`
- `EmbeddedFile { obj_ref }`
- `String { obj_ref, key }` (for JS in strings or name trees)
- `XrefSpan { offsets }` (structure repair or shadow objects)
- `Recovered { heuristic }` (from carving)

This reduces trust in structure because detectors operate on `Blob.decoded` or `Blob.raw`, not dictionary labels.

### 2.2 Filter decoding as a best-effort service

Implement a decoding service that:
- Applies declared `/Filter` but can also try common decoders when filters are inconsistent.
- Enforces bounds: `max_decoded_bytes`, `max_filter_chain_depth`, `max_cpu_time_per_blob`, `max_memory_per_blob`.
- Records outcomes: `Ok`, `Truncated`, `Failed(filter, reason)`, `SuspectMismatch`.

Add mismatch signals:
- Declared `/DCTDecode` but bytes do not start with JPEG SOI.
- Declared `/FlateDecode` but inflation fails early or data is not zlib-like.

## 3) Content-first type classification (stop trusting `/Subtype`)

### 3.1 Classifier pipeline (fast → slower)

For every `Blob` (decoded if available; otherwise raw), run:

Stage A: Magic/signature checks (O(1) prefix)
- Executables: PE (MZ), ELF, Mach-O
- Archives: ZIP, RAR, 7z, gzip, bzip2, xz, Zstd
- Office: OLE2 / CFBF; OOXML (ZIP + `[Content_Types].xml`)
- Flash: SWF (FWS, CWS, ZWS)
- Images: JPEG, PNG, GIF, BMP, TIFF, WebP, JP2/JPX
- Fonts: TrueType/OTF (`\0\1\0\0`, `OTTO`), Type1 (`%!PS-AdobeFont`), WOFF/WOFF2
- Media: MP4/ISO BMFF (`ftyp`), AVI (`RIFF....AVI `), WAV, MP3 (`ID3`), MKV (`1A45DFA3`)
- 3D: U3D (header patterns), PRC (signature patterns; if uncertain, mark “maybe PRC”)
- Markup: XML/HTML markers (`<?xml`, `<x:xmpmeta`, `<html`, `<script`)

Stage B: Lightweight structural validation
- JPEG: marker sequence; ensure EOI within bounds.
- PNG: validate IHDR; chunk CRC optional (cheap).
- ZIP: central directory sanity (within bounds).
- SWF: parse header, version, file length, compression type.

Stage C: Heuristic classification
- Entropy, high-entropy segments, long runs.
- “Looks like text” classifier (UTF-8 ratio, null byte rate).
- Token scanning: JS/VBScript/PowerShell/bash patterns, URLs, base64 blocks, hex blobs.
- “Container suspicion”: blob begins with zlib stream but filter claims none.

Output:

```rust
enum BlobKind {
  Pdf, Zip, Ooxml, Ole2, Pe, Elf, ScriptText(ScriptKindGuess),
  Jpeg, Png, Gif, Tiff, Swf, Xml, Html, Font(FontKind),
  Media(MediaKind),
  Unknown,
}
```

### 3.2 Label mismatch findings (core detection primitive)

Whenever PDF labels conflict with observed `BlobKind`, emit:
- `label_mismatch_stream_type`
- Evidence: obj ref, declared `/Subtype`, observed kind, confidence, bytes prefix sample
- Severity: Medium → High (if executable or container)

## 4) Targeted content checks to fill gaps

### 4.1 ActionScript / Flash (SWF) deep inspection

When `BlobKind::Swf`:
- Extract SWF tags list (no full AVM required initially).
- Flag: `DoABC` or `DoABC2` tags, URLs/domains in strings, suspicious tags (`FileAttributes` with `useNetwork`, `DefineBinaryData`).
- Detect compression anomalies (CWS/ZWS) and decompression failures.

Optional next step:
- Integrate ABC parser for method and string extraction (static only).
- Heuristics for exploit patterns (heap spray strings, repeated NOP-like sequences).

Findings:
- `swf_present`
- `actionscript_present`
- `swf_suspicious_strings`
- `swf_url_iocs`

### 4.2 VBScript / Windows Script Host content

Attackers use PDFs to deliver or invoke VBScript (attachments + Launch, or embedded scripts).

Add ScriptText detectors:
- VBScript tokens: `CreateObject`, `WScript.Shell`, `Shell`, `Execute`, `Eval`, `GetObject`
- COM abuse: `Scripting.FileSystemObject`, `ADODB.Stream`, `MSXML2.XMLHTTP`
- Obfuscation: `Chr`, `ChrW`, string concatenation storms

Findings:
- `vbscript_payload_present`
- `wsh_com_abuse_indicators`

### 4.3 Generic script detectors (batch)

Classify script-like text blobs into:
- `powershell`, `batch/cmd`, `bash/sh`, `python`, `js`, `vbscript`, `applescript`, `unknown_script`

Use n-gram or keyword sets with minimal parsing (no execution).

Key wins:
- Attachments with `#!` or text will be detected even if named innocuously.
- Streams masquerading as images but containing scripts will surface.

### 4.4 Media parsing expansion

For `BlobKind::Media`:
- Identify container and list tracks/boxes (MP4) or chunks (RIFF) lightly.
- Scan metadata strings for URLs and suspicious domains.
- Flag unusually large embedded media streams, truncation, or inconsistencies.

Findings:
- `embedded_media_present` (already)
- `media_container_mismatch` (labelled image but MP4)
- `media_metadata_iocs`

### 4.5 XFA/XML hardening

For `BlobKind::Xml` (or XFA-related):
- Parse with secure XML parser (no external entities).
- Scan for `<script>` blocks, URL IOCs, base64 blobs, suspicious namespaces, event triggers.

Findings:
- `xfa_script_present`
- `xml_embedded_payload_suspected`

## 5) Object stream type determination beyond structure

### 5.1 Treat ObjStm contents as first-class blobs

When inflating `/ObjStm`, each contained object can produce:
- A `Blob` for each embedded stream or string value in that object.
- A synthetic “object bytes blob” for the object itself (for carving).

Then run the same classify/inspect pipeline.

### 5.2 Carving hidden streams inside decoded data

Add a bounded carver:
- Scan decoded bytes for magic numbers (PDF/ZIP/PE/SWF/JPEG/PNG/XML/HTML).
- If found, extract a window around it and attempt parsing or container walk.
- Record `BlobOrigin::Recovered { heuristic: MagicCarve }`.

Findings:
- `embedded_payload_carved`
- `nested_container_chain` (for example PDF stream → ZIP → JS/VBS)

### 5.3 Cross-check declared stream filters vs actual compression

If stream declares no filter but data looks like zlib/deflate/gzip:
- Attempt decode in “try” mode.
- If successful, emit `undeclared_compression_present`.

If declared compression fails repeatedly:
- Emit `declared_filter_invalid`.

## 6) Structural evasion resistance

### 6.1 Multi-parse and reconcile

Parsing modes:
- Strict (spec-compliant)
- Lenient (repair xref, tolerate missing EOF)
- Carve-based (scan for `obj` / `endobj` / `stream` / `endstream` markers)

Reconcile into a unified object universe with provenance:
- `ObjectSource::Xref` | `Repaired` | `Carved`

Detect conflicts and shadowing explicitly (expand existing logic).

### 6.2 Always analyse shadow objects

When object ID shadowing exists:
- Analyse all versions, not only the one referenced by xref.
- Show diffs: dictionary keys changed, stream content hashes differ.

Finding:
- `shadow_object_payload_divergence`

### 6.3 Bounded graph traversal

When building reference graphs:
- Enforce max depth and max node count.
- Cycle detection with explicit `cycle_found` finding.
- Keep traversing by content blobs even if object graph loops (avoid infinite traversal).

## 7) Scoring and reporting changes

Add “evasion posture” score components:
- Label mismatches
- Undeclared compression
- Filter failures
- Carved nested payloads
- Shadow object divergences
- Parse disagreement on object layout

Expose per-finding confidence:
- High: signature plus validation success
- Medium: signature only
- Low: heuristic only

## 8) Implementation roadmap

Phase 1 — Core pipeline (high value, low complexity)
- Introduce `Blob` abstraction and decode service with bounds.
- Implement magic and lightweight validation for PE/ELF/ZIP/PDF/SWF/JPEG/PNG/XML/HTML.
- Emit `label_mismatch_stream_type`, `undeclared_compression_present`, `declared_filter_invalid`.

Phase 2 — Carving and nested extraction
- Add magic-carver over decoded blobs.
- Add container walkers: ZIP listing and small entry extraction (bounded).
- Emit `embedded_payload_carved`, `nested_container_chain`.

Phase 3 — Script expansion
- Add script text classifiers (VBScript, PowerShell, bash, cmd, AppleScript).
- Add XFA/XML `<script>` detection.
- Emit `vbscript_payload_present`, `powershell_payload_present`, `xfa_script_present`.

Phase 4 — SWF/ActionScript deep scan
- Parse SWF tags, detect `DoABC` or `DoABC2`.
- Extract strings and IOCs.
- Emit `actionscript_present`, `swf_url_iocs`.

Phase 5 — Structural hardening and multi-parse reconciliation
- Add carve-based parser mode and object provenance.
- Analyse all shadow objects automatically.
- Emit `shadow_object_payload_divergence`, `parse_disagreement`.

Phase 6 — Benchmark harness
- Build corpus runner comparing sis-pdf against:
  - `pdfid` or `pdf-parser` output (keyword counts)
  - `peepdf` results (where available)
- Track regression: missed JS triggers, missed embedded binaries, mismatches.

Phase 7 — Optional type inference for unknown blobs
- Add an optional `infer`-backed classifier used only when Stage A returns `Unknown`.
- Keep behind a feature flag and document signature sources for auditability.

## 9) Concrete test cases to drive correctness

Create a test corpus (generated and real):
- `/Subtype /Image` stream contains:
  - `MZ` PE
  - `PK` ZIP with JS
  - `FWS/CWS` SWF
  - `<script>` HTML phishing page
- Streams with incorrect `/Filter`
- Hidden payload with no xref entry (carve-only discoverable)
- `/ObjStm` containing malicious action dictionaries and embedded files
- Multi-revision PDFs where benign latest xref hides earlier malicious objects

Each test asserts:
- Pipeline extracts blob
- Classifier identifies kind
- Mismatch finding fires
- Path-to-payload is reported

## 10) Implementation preparation checklist

Before code changes:
- Confirm target crates and modules:
  - Blob model and decode service in `crates/sis-pdf-pdf` and `crates/sis-pdf-core`.
  - New detectors and findings in `crates/sis-pdf-detectors`.
  - Reporting changes in `crates/sis-pdf-core/src/report.rs`.
- Define metadata keys for new findings and update `docs/findings.md` and `docs/uri-classification.md` as needed.
- Decide feature extraction impact (for example, new `uri_signals` or content signals) and update ML vector size.
- Add fixtures to `crates/sis-pdf-core/tests/fixtures/` for mismatch, carving, and script detection.

Ready-to-start tasks:
1. Specify `Blob` and `DecodeMeta` in `crates/sis-pdf-pdf` and thread through the scan pipeline.
2. Add a dedicated decode service with bounds and mismatch detection.
3. Implement Stage A signatures and minimal validations (PE/ELF/ZIP/PDF/SWF/JPEG/PNG/XML/HTML).
4. Add `label_mismatch_stream_type`, `undeclared_compression_present`, `declared_filter_invalid` findings.
5. Create a small synthetic test set to validate blob extraction, classification, and mismatch evidence paths.
