# Modern Renderer-Divergence Revision Shadow Attack

## Threat Summary

This sample exploits differences in PDF renderer behaviour across incremental revisions to present
different content to different PDF readers. By using the PDF incremental update mechanism to shadow
objects in earlier revisions, the attacker can create a document that appears benign to a digital
signature validator (which reads the original revision) while presenting malicious content to a
victim's PDF reader (which processes the latest revision). This is a shadow attack on the PDF revision
mechanism, a class of attack documented in academic research on PDF signing security.

The verdict is Suspicious because the structural evidence (annotation count change, renderer
divergence path, exploitation chain) is strong, but no executable payload has been recovered from
the shadowed content. The attack structure is definitively present; the payload delivered by the
structure remains unconfirmed by static analysis.

## File Structure

The document uses multiple incremental revisions. Incremental updates are a legitimate PDF feature
that allows efficient modification without rewriting the entire document — each update appends a new
xref section and body. However, the revision mechanism can be abused to shadow (replace) objects
from earlier revisions with new objects that have different content.

Key structural observations:

**Revision forensics**: The revision forensics detector identifies that annotations changed
significantly across revisions. 20 or more annotations were modified between the original revision
and the final revision. This large-scale annotation change is abnormal for a legitimate document
workflow (which might change a few annotations) and is characteristic of a wholesale replacement of
document content.

**Object 14 0 (evidence jump)**: Object 14 0 shows evidence of an incremental revision jump — its
content in the latest revision differs from its content in an earlier revision in a way that is
consistent with shadow attack staging. The object appears in multiple revisions with divergent
semantics.

**Renderer divergence**: The renderer behaviour divergence detector identifies that the document
exercises a known-bad code path difference between compliant and non-compliant PDF readers. Compliant
readers (those implementing the PDF specification's revision handling correctly) would show one
version of the document; non-compliant or legacy readers may follow object references in a way that
exposes shadowed (earlier-revision) content.

**Annotation shadowing**: The 20+ annotation changes across revisions include at minimum one
annotation override — where a benign annotation in the final revision shadows a potentially malicious
annotation in an earlier revision. A signing validator sees only the final revision and confirms the
signature; a reader exploiting a rendering quirk may display the earlier annotation.

## Detection Chain

Detection proceeds through four signals escalating from structural anomaly to exploitation chain
classification:

1. **revision_anomaly_scoring (low/tentative)**: The revision structure is scored for anomaly
   indicators: unusually large xref sections in incremental updates, object count changes inconsistent
   with normal editing, and cross-revision reference patterns. The low severity and tentative
   confidence reflect that incremental revisions are common in legitimate documents.

2. **revision_annotations_changed (medium/probable)**: The forensic diff of annotation objects
   across revisions identifies 20+ changed annotations. The threshold of 20 is calibrated to
   distinguish bulk replacement (shadow attack) from normal annotation editing (0-5 changes in
   typical workflows). The probable confidence acknowledges that large-scale annotation changes can
   occur in legitimate batch-processing workflows.

3. **renderer_behavior_divergence_known_path (high/strong)**: The renderer divergence detector
   identifies that the document exercises a specific code path known to produce different rendering
   outcomes across PDF implementations. The strong confidence is based on a signature match against
   a catalogued set of divergence-triggering patterns — this is not heuristic detection but pattern
   matching against known exploitation techniques.

4. **renderer_behavior_exploitation_chain (high/strong)**: The exploitation chain composite finding
   combines `revision_annotations_changed` with `renderer_behavior_divergence_known_path` to
   conclude that the revision structure and the renderer divergence are not independent — they form
   a coherent exploitation chain. An attacker who modifies 20+ annotations and also exercises a
   renderer divergence path is constructing a shadow attack. This finding drives the ExploitPrimitive
   intent bucket.

Intent accumulation: `renderer_behavior_exploitation_chain` (high/strong) contributes strongly to
ExploitPrimitive. The revision shadowing structure contributes to Obfuscation (hiding content from
validators). The combined bucket scores produce the Suspicious verdict.

## Evasion Techniques

**PDF incremental update mechanism**: The PDF incremental update feature is a legitimate, widely
supported capability. PDF editors use it routinely. Using a legitimate mechanism for malicious
purposes makes the attack harder to detect via simple structural checks — the PDF is technically
well-formed.

**Digital signature bypass**: The primary goal of revision shadowing is to defeat digital signature
validation. A signed PDF with incremental updates that shadow the signed content can appear to bear
a valid signature (the signed revision is intact) while presenting unsigned, potentially malicious
content to the reader (via the post-signature revision). Certificate-based trust in the signature is
thus misdirected.

**Renderer divergence exploitation**: By targeting specific differences in how PDF readers handle
revision object resolution, the attacker ensures that the malicious content is only shown to target
readers (those with the divergence behaviour) and not to analysis tools or validators (which may use
different, more compliant code paths). This selective rendering makes the attack less likely to be
caught in automated analysis.

**Annotation-based content delivery**: Using annotations (rather than page content streams) to carry
the shadowed content means the malicious material is in a layer that some renderers treat
differently from main page content, providing additional evasion opportunity against content-stream-
focused scanners.

## Key Indicators

- **SHA256**: `8d42d425d003480d1acc9082e51cb7a2007208ebef715493836b6afec9ce91bc`
- **Revision structure**: Multi-revision PDF with 20+ annotation changes across revisions
- **Object of interest**: Object 14 0 — shows evidence jump consistent with shadow attack staging
- **Renderer divergence**: Known-path divergence pattern (signature match, strong confidence)
- **Attack class**: PDF shadow attack (revision-based object shadowing)
- **MITRE ATT&CK**: T1036.007 (Masquerading: Double File Extension), T1027 (Obfuscated Files),
  T1564 (Hide Artifacts)

## Regression Coverage

- **`corpus_captured_modern_renderer_revision_baseline_stays_stable`**: Verifies that
  `renderer_behavior_divergence_known_path` (high/strong), `renderer_behavior_exploitation_chain`
  (high/strong), `revision_annotations_changed` (medium/probable), and `revision_anomaly_scoring`
  (low/tentative) are all present with the expected severity and confidence levels. Also verifies
  that ExploitPrimitive and Obfuscation intent buckets are activated and the verdict is Suspicious.
  The test locks in the finding set to prevent regressions when revision forensics or renderer
  divergence detectors are modified.
