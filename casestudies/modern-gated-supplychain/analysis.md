# Modern Gated Supply Chain Update Vector

## Threat Summary

This sample exhibits a dormant JavaScript runtime with a supply chain update pathway, combined with 21
image objects carrying invalid colour space definitions. The JavaScript runtime profile shows
`profile_calls_ratio=0.00`, meaning no JS functions were called during static analysis — consistent
with gated or conditionally-triggered execution that only activates in specific environments.

The supply chain update vector signal indicates that the PDF contains patterns associated with
software update delivery mechanisms embedded in documents: references to external update endpoints,
version-check structures, or staged payload delivery indicators. These patterns, when combined with
a dormant JS runtime that avoids static detection, suggest the document may be designed to deliver a
software update payload selectively based on environmental conditions.

The verdict is Suspicious rather than Malicious because the actual payload is not recoverable from
static analysis — the gating condition that would trigger execution is environment-dependent, and
false positives from the embedded .joboptions file affected two of the JS signals (now fixed in
Stage 4.3).

## File Structure

The document has several notable structural components:

**Embedded IEEE .joboptions file**: The document contains a `.joboptions` file (an Adobe Distiller
job options configuration format) stored as a PDF dictionary object, not as a file attachment or
embedded executable. The `.joboptions` format uses PDF dictionary syntax (`<< /Key Value >>`). Before
Stage 4.3, the JS analyzer incorrectly treated this dictionary as JavaScript source, producing false
positive findings. After the fix, content beginning with `<<` is correctly identified as PDF dict
format and excluded from JS analysis.

**21 image objects with colour_space_invalid**: The document contains 21 image XObjects, each with an
invalid or unsupported colour space specification. All 21 trigger `image.colour_space_invalid`
(medium/strong). The same 21 objects also produce `image.decode_skipped` findings because the decoder
refuses to process images with invalid colour space metadata. These `decode_skipped` findings are
co-located with `colour_space_invalid` on the same objects and are preserved (not suppressed by the
COV-1 co-location suppression rule, which only suppresses when a higher-severity finding on the same
object makes the lower-severity one redundant — in this case both carry diagnostic value).

**JavaScript runtime**: A JS action is present but exhibits a dormant execution profile.
`profile_calls_ratio=0.00` indicates no function calls were executed in the static JS emulation pass.
This can mean the JS is gated behind a condition (e.g., checking the OS version, a registry key, or
a network response) that was not satisfied during analysis.

**PDF.js eval path**: The `pdfjs_eval_path_risk` (info/strong) finding indicates the document
exercises a code path in PDF.js that involves `eval()` or equivalent dynamic execution. This is an
informational finding — it means the document stresses a known risky code path in the reference
renderer, which may have security implications depending on PDF.js version.

## Detection Chain

The detection chain proceeds from structural anomaly to behavioural inference:

1. **pdfjs_eval_path_risk (info/strong)**: The document structure exercises a PDF.js eval code path.
   This is the lowest-severity finding and primarily serves as a corroborating signal. Alone it
   indicates only that the document uses advanced PDF features.

2. **js_runtime_dormant_or_gated_execution (low/tentative)**: Static JS emulation finds a runtime
   present but with zero function calls. The tentative confidence reflects that dormant JS is common
   in legitimate interactive documents where scripts wait for user events. The combination with
   supply chain indicators raises the suspicion level.

3. **supply_chain_update_vector (medium/heuristic)**: Structural patterns in the document match
   known supply chain update delivery mechanisms. The heuristic confidence indicates pattern
   matching rather than definitive behavioural evidence. The PDF contains structures (update endpoint
   references, version comparison patterns, or staged delivery markers) consistent with software
   supply chain abuse.

4. **image.colour_space_invalid (medium/strong x21)**: The 21 invalid-colour-space image objects
   contribute to the Obfuscation intent bucket. Bulk image anomalies across many objects are
   consistent with a document that has been synthetically constructed or processed in a non-standard
   way, which can indicate tampering or obfuscated content delivery.

The combined signals accumulate in the Obfuscation intent bucket. No ExploitPrimitive or executable
payload signals are present, keeping the verdict at Suspicious.

## False Positive Notes

Stage 4.3 (implemented 2026-02-28) introduced a critical fix for JS false positives affecting this
sample:

**Problem**: The JS source extractor was passing raw stream content to the JS static analyzer without
first checking the content type. The embedded `.joboptions` file is stored as a stream object and
begins with `<<` (PDF dictionary syntax). The JS analyzer treated this as obfuscated JS source,
producing false positive findings for `supply_chain_update_vector` and `js_runtime_dormant_or_gated_execution`.

**Fix**: A pre-analysis content check now identifies streams beginning with `<<` as PDF dictionary
format and excludes them from JS analysis. This correctly suppresses both false positive findings
for the `.joboptions` content while preserving genuine JS findings from other streams.

**Impact on this sample**: After Stage 4.3, `supply_chain_update_vector` and
`js_runtime_dormant_or_gated_execution` are only emitted if genuine JavaScript source is present.
The baseline regression test (`corpus_captured_modern_gated_supply_chain_baseline_stays_stable`)
locks in the post-fix expected finding set to prevent regressions back to the false-positive state.

## Image Analysis

All 21 image objects share a common anomaly pattern:

- `image.colour_space_invalid` (medium/strong): The colour space specification in the image
  dictionary references a colour space name or profile that is not valid per the PDF specification.
  This may indicate the images were generated by non-standard tooling, that the document has been
  partially corrupted, or that the colour space definitions are intentionally malformed to trigger
  specific decoder code paths.

- `image.decode_skipped` (co-located): The image decoder skips processing for each of the 21
  objects because it cannot safely handle an invalid colour space. These findings are preserved in
  the output alongside `colour_space_invalid` because they provide additional diagnostic signal
  (confirming that the images could not be decoded, which affects downstream content analysis).

The 21-object pattern suggests bulk generation — either an automated tool produced these images with
consistent (mis)configuration, or the document was assembled from a template that contains a
systematic colour space error.

## Key Indicators

- **SHA256**: `9ff24c464780feb6425d0ab1f30a74401e228b9ad570bb25698e31b4b313a4f4`
- **JS runtime profile**: `profile_calls_ratio=0.00` (dormant, no calls observed)
- **Embedded artefact**: IEEE .joboptions file (PDF dict format, not executable)
- **Image anomalies**: 21 objects with `colour_space_invalid` + `decode_skipped`
- **PDF.js risk**: eval path exercised (info/strong)
- **MITRE ATT&CK**: T1195 (Supply Chain Compromise), T1059.007 (JS), T1036 (Masquerading)

## Regression Coverage

- **`corpus_captured_modern_gated_supply_chain_baseline_stays_stable`**: Locks the expected finding
  set after Stage 4.3 false-positive fix. Verifies that `supply_chain_update_vector` and
  `js_runtime_dormant_or_gated_execution` are NOT emitted for the .joboptions content, and that the
  21 `colour_space_invalid` findings are present.

- **`cov1_colocated_decode_skipped_preserved_in_supply_chain_fixture`**: Verifies the COV-1
  suppression rule does not incorrectly suppress `decode_skipped` findings that are co-located with
  `colour_space_invalid` on the same image objects. Both finding types must appear in the output for
  all 21 affected objects.
