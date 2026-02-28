# RomCom Embedded JPEG Payload PDF

## Threat Summary

This sample is attributed to RomCom, a threat actor (also tracked as Tropical Scorpius / UNC2596)
known for targeting defence, government, and critical infrastructure sectors. The PDF contains two
payloads embedded within image streams and carved out as JPEG-kind artefacts. Network exfiltration
indicators in the document suggest the PDF participates in a larger infection chain — either calling
home to a C2 server or redirecting to a staging infrastructure.

The verdict is Suspicious rather than Malicious because the carved payloads, while strongly
indicative of a dropper, were not successfully executed in static analysis. The ExploitPrimitive
intent reached Strong confidence (score=4) after the Stage 3 intent accumulation fix, reflecting
that two independent carved payload findings constitute definitive evidence of malicious intent even
without dynamic execution confirmation.

## File Structure

The document contains at least two image XObjects whose streams contain embedded payloads carved as
JPEG-kind artefacts:

**Carved payload 1**: An image stream that, when decoded, contains data beyond the image boundary.
The payload carver identifies a JPEG-format embedded object within the stream data. The JPEG
container is a delivery vehicle — the actual payload may be appended to or interleaved with a
legitimate JPEG image, exploiting the loose termination semantics of the JPEG format (data after the
EOI marker is ignored by image decoders but accessible to a secondary parser).

**Carved payload 2**: A second independent image stream on a different PDF object carrying the same
JPEG-kind embedded payload pattern. The presence of two separate carved findings on different objects
indicates a redundant delivery structure — if one payload is intercepted or fails to execute, the
second provides a backup delivery mechanism. This redundancy is characteristic of sophisticated
threat actors who build resilience into their loaders.

**Network intent indicators**: The document contains annotation actions, form actions, or JavaScript
that reference external network resources. These network indicators are consistent with a C2 beacon
or staging URL used to download a second-stage payload, validate the victim environment, or exfiltrate
initial reconnaissance data.

The PDF structure is otherwise unremarkable. The malicious content is entirely within the image
streams, making the document appear to be a normal document with embedded images when examined at
the object-graph level without payload carving.

## Detection Chain

Detection proceeds from individual payload findings through intent score accumulation to a Strong
confidence verdict:

1. **embedded_payload_carved (first instance, jpeg kind)**: The payload carver processes the first
   image stream and identifies a JPEG-format embedded payload. The finding is emitted with the
   metadata `carve.kind=jpeg`, recording the format of the carved artefact. This finding alone is
   significant — a carved payload in an image stream is uncommon in legitimate documents.

2. **embedded_payload_carved (second instance, jpeg kind)**: The payload carver finds a second
   JPEG-kind carved payload in a different image object. The second independent finding is critical
   for intent accumulation: each `embedded_payload_carved` finding contributes to the ExploitPrimitive
   intent score, and two findings from Strong-confidence detectors accumulate to score=4.

3. **network_intents present**: The network intent extractor identifies external resource references.
   These are recorded as DataExfiltration indicators. The network indicators corroborate the
   ExploitPrimitive findings — a dropper without a network endpoint is a delivery mechanism without
   a command channel, which is less characteristic of a sophisticated threat actor.

4. **Intent promotion (ExploitPrimitive score=4, Strong confidence)**: The intent scoring engine
   accumulates the two carved payload findings (each contributing score=2 at Strong confidence) to
   reach a total ExploitPrimitive score of 4. Per the `promote_bucket_confidence()` logic introduced
   in Stage 3, a score>=4 with at least one Strong-confidence contributing finding promotes the bucket
   confidence from Heuristic to Strong. This promotion is what changes the verdict from Suspicious-
   with-weak-evidence to Suspicious-with-strong-evidence (approaching Malicious).

## Historical Note

Before the Stage 3 intent uplift (implemented 2026-02-28), the ExploitPrimitive intent bucket for
this sample stayed at Heuristic confidence despite two carved JPEG payload findings. The accumulation
logic did not correctly sum contributions from multiple instances of the same finding kind — it only
counted the first instance. This meant that the second carved payload finding was ignored for intent
scoring purposes, and the bucket score never rose high enough to trigger confidence promotion.

The accumulation fix (Stage 3, `promote_bucket_confidence()`) correctly groups multiple findings of
the same kind and sums their contributions. Two `embedded_payload_carved` findings (each contributing
score=2) now correctly produce score=4, which meets the promotion threshold. This fix was validated
against this sample specifically: the regression test `romcom_embedded_payload_detections_present`
verifies score=4 and Strong confidence.

This historical note is preserved because it illustrates an important principle: multi-instance
findings (where the same detector fires on multiple objects) must accumulate additively in the intent
engine. A single finding and two identical findings should produce different confidence outcomes if
the evidence is genuinely independent (different objects, different streams).

## Key Indicators

- **SHA256**: `a99903938bf242ea6465865117561ba950bd12a82f41b8eeae108f4f3d74b5d1`
- **Carved payload count**: 2 (jpeg kind, on separate PDF objects)
- **ExploitPrimitive score**: 4, confidence=Strong (post Stage 3 fix)
- **Network indicators**: Present (C2 or staging URL in annotation/form/JS)
- **Threat actor**: RomCom (Tropical Scorpius / UNC2596)
- **MITRE ATT&CK**: T1027 (Obfuscated Files), T1566.001 (Spearphishing Attachment),
  T1071 (Application Layer Protocol for C2)

No specific C2 domain is listed here because the network indicator data from the static analysis may
reflect infrastructure that has been sinkholed or rotated since initial analysis.

## Regression Coverage

- **`romcom_embedded_payload_detections_present`**: Verifies that two `embedded_payload_carved`
  findings with `carve.kind=jpeg` are present on separate PDF objects, that network intents are
  extracted, that the ExploitPrimitive bucket reaches score=4 with Strong confidence, and that the
  DataExfiltration intent bucket is activated. Also verifies that the verdict is Suspicious. This
  test was updated during Stage 3 implementation to reflect the corrected intent accumulation
  behaviour — the expected confidence is Strong, not Heuristic.
