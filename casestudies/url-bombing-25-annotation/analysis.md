# Case Study: URL Bombing via Mass Annotation Injection (25 domains)

**Fixture**: `crates/sis-pdf-core/tests/fixtures/corpus_captured/url-bombing-25-annotation-9f4e98d1.pdf`
**SHA256**: `9f4e98d10a0951edaa4f4061b06cf3ff0ca87af4cd417fdb5a59e5dcad5ee0d0`
**Classification**: Suspicious | DataExfiltration + Phishing

---

## Threat Summary

A PDF that injects 25 annotation link actions pointing to 25 distinct external domains, functioning as a "URL bomb" for mass phishing and malware distribution. The PDF displays as an image-only document (content is a single image per page with overlay links) with no visible text, hiding the annotation links from inspection. Targeted domains span suspicious/malicious categories including adult content, known malware distribution domains, and generic phishing landing pages. The intent scoring correctly elevates this to DataExfiltration (score=50, Strong) based on the sheer volume of URI signals, but the verdict remains Suspicious due to the lack of explicit exploit primitives. This sample exposes a critical chain architecture failure: 38 findings produce 38 singleton chains (1:1 ratio), with 25 of those chains being separate per-annotation chains rather than a single "mass URL injection" cluster.

---

## File Structure

- **Trailers**: 1; **XRef sections**: 1; **Revisions**: 1
- **Page count**: ~25 pages (inferred from 25 annotations)
- **Content type**: Image-only pages — no visible text rendered
- **Annotation layer**: 25 `/Link` annotations with `/A` dictionaries containing `/URI` actions
- **Additional structures**: 1 embedded XML payload (carved from stream), ToUnicode CMap with overlapping bfranges, image overlay links
- **Resource anomalies**: 2 operator usage anomalies (operator used outside expected contexts)

Targeted domain sample:
`3dfinance.net`, `4o64flb.com`, `aemoban.com`, `aphroditeporntube.com`, `buscandonovasaguas.com`,
`f2ew.xyz`, `forest-up.com`, `ir-cdn.co`, `javhard.net`, `kusorape.com`, `mchacks.net`, `mix.tj`,
`myftpupload.com`, `pulsetv.com`, `shwelayoung.com`, `thecannifornian.com`, `tezukayama.com`,
`zuoche.com` (plus 7 others including some apparently legitimate domains used as cover).

---

## Detection Chain

**Primary attack layer — 25 annotation URI injections**:
- `annotation_action_chain` (Medium/Strong) x25 — one finding per annotation, each with a distinct external domain
- Intent contribution: 25 x `/URI action` (weight 2) + 25 x `External target` (weight 2) = DataExfiltration score 50 (Strong)

**Structural evasion**:
- `content_image_only_page` (Medium/Heuristic) — no text content; annotations are invisible without inspection
- `content_overlay_link` (Medium/Probable) — link overlaid on top of image content
- `composite.graph_evasion_with_execute` (High/Probable) — evasion indicators co-located with executable surfaces
- `object_reference_cycle` (Medium/Strong) — circular reference in document structure

**Font manipulation**:
- `font.cmap_range_overlap` (Medium/Strong) — ToUnicode CMap has overlapping bfrange intervals

**Embedded payload**:
- `embedded_payload_carved` (Medium/Strong) — XML payload in stream (XML could be XFA form data)

**Resource anomalies**:
- `resource.operator_usage_anomalous` (Medium/Strong) x2 — operators used outside expected contexts

**Intent resolution**:
- `DataExfiltration`: score=50 Strong (overwhelming URI injection volume)
- `Phishing`: score=4 Probable (content deception, overlay links)
- `ExploitPrimitive`: score=4 Strong (CMap, embedded payload)
- Verdict: Suspicious/Probable/0.75

---

## Evasion Techniques

1. **Image-only pages**: All content is rendered as images, making the annotation layer invisible without structural analysis. Standard text-matching scans find no content.
2. **Mass injection as noise**: 25 URLs with mixed-reputation domains (some apparently legitimate like `manipal.edu`, `drogasil.com.br`) create noise that may overwhelm manual URL reputation review.
3. **CMap manipulation**: Overlapping bfrange intervals in the ToUnicode CMap confuse text extraction tools, preventing them from reading any embedded text.
4. **Content overlay link**: Annotation is positioned over the full image area, making user click anywhere a potential trigger.
5. **Circular document structure**: Object reference cycles complicate automated structure traversal.
6. **Mixed-reputation domain list**: Including some apparently legitimate domains (`manipal.edu`, `drogasil.com.br`, `pulsetv.com`) alongside malicious ones suggests domain reputation evasion or a test list.

---

## Key Indicators

| Indicator | Type | Value |
|---|---|---|
| Annotation count | Structure | 25 `/Link` annotations |
| Domain count | Network | 25 distinct domains |
| Suspicious domains | IOC | `ir-cdn.co`, `f2ew.xyz`, `mchacks.net`, `aphroditeporntube.com`, `kusorape.com` |
| CMap anomaly | Font | ToUnicode bfrange overlap |
| Content type | Document | Image-only, no text |
| DataExfiltration score | Intent | 50 (Strong) — highest in this sample set |

---

## Regression Coverage

- `url_bombing_25_annotation_detections_present` — asserts:
  - At least 20 `annotation_action_chain` findings (allowing some suppression)
  - `DataExfiltration` intent bucket fires at score >= 40
  - Verdict is Suspicious or Malicious

---

## Chain Assessment

Updated deep scan on 2026-02-28 (post-uplift) confirms the primary chain-fragmentation gap is closed.

**Current state**:
- `Annotation action cluster (25 links)` now appears as a single cluster chain (`len=25`, `score=0.6`, `edges=5`)
- Total chains dropped to 14 from the earlier 38-chain fragmented baseline
- The 25 annotation findings are no longer represented only as 25 isolated singleton chains

Residual gap: the top-ranked chain is still `embedded_payload_carved` (`score=0.75`), so the mass-annotation cluster is not yet consistently the top triage chain. Cross-linking from the annotation cluster to `content_overlay_link` and `content_image_only_page` remains partial.

This case now validates the "same-kind bulk findings -> cluster chain" uplift item in `plans/20260228-corpus-perf-chain-uplift.md`.
