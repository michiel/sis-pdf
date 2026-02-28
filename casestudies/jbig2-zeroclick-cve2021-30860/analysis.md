# Case Study: JBIG2 Zero-Click Exploit (CVE-2021-30860)

**Fixture**: `crates/sis-pdf-core/tests/fixtures/corpus_captured/jbig2-zeroclick-cve2021-30860-1c8abb3a.pdf`
**SHA256**: `1c8abb3abe62b99d85037f31c9e3cdc424cda2efe3ab8436062090fc1e9cb341`
**Classification**: Malicious | ExploitPrimitive + Phishing

---

## Threat Summary

This PDF exploits the JBIG2 image codec vulnerability CVE-2021-30860 (FORCEDENTRY), originally discovered in Apple's CoreGraphics and later found in PDF readers including Acrobat. The attack embeds five JBIG2-encoded images with extreme full-page strip dimensions (approximately 2551-2569 x 3257-3297 pixels) that trigger out-of-bounds write conditions during JBIG2 decoder processing. A secondary phishing layer of invisible-text overlays on five pages provides social-engineering context. The file was captured from corpus batch mwb-2026-02-23 and appears to be a recent campaign reusing this well-known zero-click exploit pattern.

---

## File Structure

- **Trailers**: 1; **XRef sections**: 1; **Revisions**: 1
- **Total objects**: ~50 (based on scanner observation)
- **Image streams**: 5 JBIG2-encoded XObjects, each with JBIG2Decode + DecodeParms
- **Stream pattern**: Each JBIG2 stream is 8-13KB compressed, decoding to full-page bitmaps (~8.3-8.5M pixels)
- **Text content**: 5 pages contain zero-coordinate invisible-text overlays (phishing)
- **Embedded payload**: One JPEG image (380x708 pixels, DeviceRGB, 35KB) embedded as an XObject
- **Label mismatches**: 5 streams show declared stream type mismatching actual content

Key objects:
- Objects 9, 31, 42, 56 (estimated): JBIG2 XObject streams
- Object with JPEG: standard DCTDecode image overlay

---

## Detection Chain

**Tier 1 — Image codec attack surface**:
- `image.jbig2_present` (Low/Probable) x5 — baseline JBIG2 presence flag
- `image.suspect_strip_dimensions` (Medium/Probable) x5 — dimensions outside normal document range
- `image.zero_click_jbig2` (High/Strong) x5 — extreme dimensions matching CVE-2021-30860 exploitation pattern; CVE tag attached

**Tier 2 — Decoder risk**:
- `decoder_risk_present` (High/Probable) x5 — `/JBIG2Decode` filter classified as high-risk decoder
- `label_mismatch_stream_type` (High/Strong) x5 — stream content does not match declared structure

**Tier 3 — Dual-use phishing overlay**:
- `content_invisible_text` (Low/Heuristic) x5 — zero-coordinate text on each exploit page
- Intent bucket `Phishing` scores 10 (Strong) — 5 signals x2 weight

**Intent resolution**:
- `ExploitPrimitive`: score=14 (Strong) — carved payload (2) + 5 decoder risks (5x2) + parser differential (2)
- `Phishing`: score=10 (Strong) — 5 content deception signals
- Verdict: Malicious/Strong/0.9

**Chain status (2026-02-28 uplift run)**: the major singleton-fragmentation gap is partially closed. Chain output now includes:
- `Image anomaly cluster (17 images)`
- `Decoder risk cluster (5 streams)`
- `Stream type mismatch cluster (5 streams)`

Residual gap: these clusters are still separate from the phishing-overlay (`content_invisible_text`) path, so one single end-to-end JBIG2+phishing narrative chain is not yet produced.

---

## Evasion Techniques

1. **JBIG2 over JPEG**: The exploit uses JBIG2 (rarely seen in benign PDFs) to target the narrower, historically under-fuzzed JBIG2 decoder rather than the better-tested JPEG decoder.
2. **Extreme dimensions as trigger**: The strip dimensions (width ~2555, height ~3297 at 1bpp) exceed safe allocation limits in vulnerable decoders, causing a heap overflow without requiring any user interaction.
3. **Legitimate JPEG overlay**: A genuine JPEG image (380x708) provides plausible document cover — the file renders as a visible document page.
4. **Label mismatches**: Stream type labels differ from actual content, complicating signature-based detection that relies on declared filters.
5. **Invisible text**: Zero-coordinate invisible text adds structural complexity and potentially triggers different code paths in readers that process text before images.

---

## Key Indicators

| Indicator | Type | Value |
|---|---|---|
| JBIG2 stream dimensions | Image metadata | ~2555x3297, ~2569x3297, ~2551x3257 (full-page) |
| CVE reference | Exploit | CVE-2021-30860 (FORCEDENTRY) |
| Attack surface | Codec | JBIG2Decode filter in image XObjects |
| Phishing overlay | Content | Invisible text at x=0.00, y=0.00 on 5 pages |
| JPEG cover image | Benign cover | 380x708 DeviceRGB JPEG |
| Scan time | Performance | ~645ms (release binary) for 229KB |

---

## Regression Coverage

- `jbig2_zeroclick_cve2021_30860_detections_present` — asserts:
  - At least 5 `image.zero_click_jbig2` findings at High/Strong
  - At least 5 `decoder_risk_present` findings
  - `ExploitPrimitive` intent bucket fires
  - Verdict is Malicious

---

## Chain Assessment

The chain synthesiser now groups JBIG2-adjacent findings into dedicated clusters, which closes the original "5 fully isolated singleton chains" failure mode. Remaining work is cross-cluster correlation so `image.zero_click_jbig2`, `decoder_risk_present`, and `content_invisible_text` appear in a unified exploit narrative.

Related plan tracking: `plans/20260228-corpus-perf-chain-uplift.md`.
