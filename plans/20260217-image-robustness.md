# Image Robustness Hardening Plan

Date: 2026-02-17  
Status: Planned  
Scope: `image-analysis`, `sis-pdf-gui`, detector mapping, findings documentation, fuzzing/tests

## Objective

Harden image parsing, preview, and finding generation against malicious image bytes and malicious image metadata while preserving safety, correctness, and throughput.

This plan addresses all reviewed gaps and extends coverage to adjacent pre-existing attack surfaces.

## Security Priorities

1. Prevent parser/preview crashes and memory exhaustion from hostile inputs.
2. Ensure findings reflect true decoded semantics (avoid false negatives and noisy false positives).
3. Expand detection for hostile metadata structures (PDF image metadata and embedded image metadata).
4. Keep behaviour deterministic and bounded under large-corpus workloads.

## Current Gaps to Close

1. Unbounded recursion risk in `/ColorSpace` and palette dereference chains.
2. GUI JPEG preview decode path lacks explicit resource limits.
3. `image.pixel_data_size_mismatch` currently checks raw bytes in dynamic flow and can misclassify.
4. `/Decode` parsing can truncate on non-numeric entries and accidentally pass validation.
5. No dedicated findings for suspicious embedded metadata payloads (EXIF/XMP/IPTC/text chunks) or metadata inflation patterns.
6. Test/fuzz coverage is thin on cyclic object graphs, malformed metadata structures, and mixed-format edge cases.

## Implementation Stages

## Stage 1: Cycle-Safe Colour Space and Palette Resolution

**Goal**: Remove stack-overflow/DoS vectors from metadata reference traversal.

### Changes

- `crates/image-analysis/src/colour_space.rs`
  - Add visited-set and strict depth controls for indirect references in:
    - `resolve_cs_value`
    - `extract_palette_bytes`
  - Count both array nesting and indirect ref hops toward limits.
  - Return stable `Unknown(...)` reasons for:
    - `ref_cycle_detected`
    - `ref_depth_exceeded`
    - `palette_ref_cycle_detected`
- Ensure no recursive call path can execute without bound.

### Tests

- Add unit tests for:
  - Self-referential `/ColorSpace` ref.
  - Two-node cycle (`A -> B -> A`).
  - Deep ref chain above cap.
  - Palette ref cycle.

### Acceptance

- No unbounded recursion possible in colour space/palette resolution.
- Cycles/depth excess produce deterministic `Unknown(...)` outputs.

## Stage 2: Hardened GUI Preview Decode Limits

**Goal**: Ensure Object Inspector preview cannot be used for decode-bomb style resource exhaustion.

### Changes

- `crates/sis-pdf-gui/src/object_data.rs`
  - Replace unbounded `image::load_from_memory_with_format` JPEG preview path with bounded decode flow.
  - Enforce explicit caps before full decode:
    - max dimensions
    - max pixel count
    - max preview buffer bytes
  - Fail closed (no preview) on cap exceed with safe logging/telemetry only.
- `crates/sis-pdf-gui/src/app.rs` or GUI config module
  - Add preview safety constants or config wiring for caps.

### Tests

- Add GUI/unit tests for:
  - Oversized declared JPEG dimensions -> preview skipped.
  - Valid small JPEG -> preview still generated.
  - Malformed JPEG -> graceful skip, no panic.

### Acceptance

- Preview generation remains bounded for hostile images.
- No regressions to normal preview rendering.

## Stage 3: Correct Pixel Size Mismatch Semantics

**Goal**: Ensure `image.pixel_data_size_mismatch` reflects decoded pixel stream reality.

### Changes

- `crates/image-analysis/src/dynamic.rs`
  - Rework mismatch logic to compare expected bytes against decoded stream bytes (not raw source bytes).
  - Restrict check to raw-pixel families where expected-length comparison is semantically valid.
  - Add metadata clarifying basis:
    - `image.size_check_basis` = `decoded_raw_pixels`
    - `image.size_check_filters`.
  - Keep behaviour strict but avoid noisy mismatches for container formats.

### Tests

- Add dynamic tests:
  - Correct raw-pixel stream -> no mismatch.
  - Appended trailing bytes in decoded raw-pixel stream -> mismatch.
  - Truncated decoded raw-pixel stream -> mismatch.
  - JPEG/PNG container paths do not emit this mismatch.

### Acceptance

- Finding aligns with documented meaning and avoids known false classifications.

## Stage 4: Strict `/Decode` Array Parsing and Validation

**Goal**: Block malformed numeric arrays from bypassing validation.

### Changes

- `crates/image-analysis/src/util.rs`
  - Replace permissive `dict_f64_array` behaviour with strict parse result:
    - either all numeric values parsed
    - or explicit invalid indicator.
- `crates/image-analysis/src/pixel_buffer.rs`
  - Treat non-numeric, NaN, and infinity as invalid.
- `crates/image-analysis/src/static_analysis.rs`
  - Emit `image.decode_array_invalid` for non-numeric entries, not only length mismatch.
  - Include reason metadata:
    - `image.decode_array_issue`.

### Tests

- Non-numeric `/Decode` entry triggers invalid finding/error.
- Mixed numeric + non-numeric array triggers invalid finding/error.
- Existing valid `/Decode` cases remain green.

### Acceptance

- `/Decode` validation is strict and non-bypassable.

## Stage 5: Hostile Image Metadata Findings Expansion

**Goal**: Detect suspicious embedded metadata patterns beyond structural decode success/failure.

### New Findings (proposed)

1. `image.metadata_oversized`
   - **Severity**: Medium
   - **Impact**: Medium
   - **Confidence**: Strong
   - Trigger: metadata segment/chunk/profile exceeds configured safe threshold.

2. `image.metadata_malformed`
   - **Severity**: Medium
   - **Impact**: Medium
   - **Confidence**: Probable
   - Trigger: parser rejects EXIF/XMP/IPTC/ICC metadata structures in otherwise recognised image payloads.

3. `image.metadata_suspicious_density`
   - **Severity**: Low
   - **Impact**: Low
   - **Confidence**: Probable
   - Trigger: metadata-to-pixel ratio or metadata-to-file ratio exceeds suspicious threshold.

4. `image.metadata_scriptable_content`
   - **Severity**: Medium
   - **Impact**: Medium
   - **Confidence**: Tentative
   - Trigger: scriptable/active markers in metadata payload text (heuristic, gated to minimise noise).

### Changes

- `crates/image-analysis/src/dynamic.rs`
  - Add lightweight metadata segment inspection for JPEG/PNG/TIFF decode paths.
  - Enforce hard byte ceilings per metadata unit before deeper parse.
- `crates/sis-pdf-detectors/src/image_analysis.rs`
  - Map new finding IDs with severity/impact/confidence and remediation text.
- `docs/findings.md`
  - Document new IDs and metadata keys.

### Tests

- Add fixtures/unit tests for:
  - Oversized metadata segment.
  - Malformed EXIF/XMP container.
  - Suspicious ratio case.
  - Benign metadata case (no finding).

### Acceptance

- Metadata abuse is surfaced as first-class findings with controlled false-positive rate.

## Stage 6: Supply-Chain and Decoder Guardrails

**Goal**: Reduce risk from vulnerable/behaviour-changing decoder dependencies.

### Changes

- Audit and align decoder crate versions used across workspace (notably dual `tiff` versions via transitive dependencies).
- Where feasible, standardise on current maintained versions and document rationale when duplicates remain unavoidable.
- Add CI check for known-vulnerable decoder crates (advisory scan).

### Tests

- CI job: `cargo audit` (or existing equivalent policy gate).
- Regression run for image-analysis tests after dependency updates.

### Acceptance

- Decoder dependency posture documented and continuously checked.

## Stage 7: Fuzzing and Regression Corpus Expansion

**Goal**: Increase confidence against hostile image and metadata inputs at scale.

### Changes

- Add/extend fuzz targets under `fuzz/` for:
  - colour space resolution (including ref graphs)
  - pixel buffer reconstruction
  - metadata chunk parsing paths
- Add curated hostile fixtures under:
  - `crates/sis-pdf-core/tests/fixtures/corpus_captured/`
  - update `manifest.json` with sha256 + provenance + regression targets.

### Tests

- `cargo test -p image-analysis --tests`
- targeted `sis-pdf-core` regression modules covering new findings
- fuzz smoke runs in CI for short deterministic budgets

### Acceptance

- New fuzz targets exist and run.
- Corpus fixtures cover each new finding path.

## Stage 8: Performance and Operational Safety Validation

**Goal**: Preserve throughput while adding hardening.

### Changes

- Measure delta using existing runtime profile workflow:
  - `sis scan <fixture> --deep --runtime-profile --runtime-profile-format json`
- Validate no unacceptable regressions in parse/detection SLO bands.
- Add explicit telemetry counters for skipped previews and metadata-limit triggers.

### Acceptance

- Safety checks do not materially regress defined performance SLOs.
- Operational signals are visible for tuning.

## Deliverables

1. Code hardening across image metadata and preview paths.
2. Expanded findings coverage for malicious metadata behaviours.
3. Updated `docs/findings.md` entries.
4. New/updated tests and corpus fixtures with manifest/provenance updates.
5. Fuzz targets and CI gates for decoder/input robustness.
6. Performance validation notes appended to active plan/worklog.

## Execution Order

1. Stage 1 (cycle safety)  
2. Stage 4 (`/Decode` strictness)  
3. Stage 3 (size mismatch correctness)  
4. Stage 2 (GUI preview bounds)  
5. Stage 5 (metadata findings expansion)  
6. Stage 6 (supply-chain guardrails)  
7. Stage 7 (fuzz + corpus)  
8. Stage 8 (performance validation)

Rationale: eliminate crash/DoS classes first, then fix correctness semantics, then expand detection and operational hardening.
