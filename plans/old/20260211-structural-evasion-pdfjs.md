# PDF Structural Evasion and Browser PDF.js Detection Plan

Date: 2026-02-11
Status: Not Started
Scope: `crates/sis-pdf-detectors/`, `crates/sis-pdf-pdf/`, `crates/font-analysis/`, test infrastructure
Companion: `plans/20260211-modernisation-js.md` (JavaScript detection modernisation)

---

## 1. Situation Assessment

### 1.1 Current structural evasion detection

The detector suite (`crates/sis-pdf-detectors/src/lib.rs`, ~18,600 lines) already provides a foundation of structural analysis:

| Detector ID | What it detects | Status |
|-------------|----------------|--------|
| `xref_conflict` | Multiple startxref markers with integrity assessment (coherent/warning/broken) | Implemented, refined (20260208) |
| `incremental_update_chain` | Multiple startxref markers indicating incremental updates | Implemented |
| `object_id_shadowing` | Duplicate object IDs across revisions (count-based severity) | Implemented |
| `shadow_object_payload_divergence` | Content differences between shadowed objects | Implemented |
| `objstm_density_high` | High ratio of ObjStm objects (>30%) | Implemented |
| `fontmatrix_payload_present` | Non-numeric entries in FontMatrix arrays (CVE-2024-4367 pattern) | Implemented |
| `open_action_present` | OpenAction triggers on PDF open | Implemented |
| `aa_present` / `aa_event_present` | Additional Actions (AA) triggers | Implemented |
| `crypto_signatures` | Digital signature presence | Implemented |
| `ocg_present` | Optional Content Groups (layer visibility) | Implemented |
| `decoder_risk_present` | Risky stream filter chains | Implemented |
| `decompression_ratio_suspicious` | Decompression bomb detection | Implemented |
| `page_tree_cycle` / `page_tree_depth_exceeded` | Malformed page tree traversal | Implemented (20260206) |

### 1.2 Current font/PDF.js detection

The `font-analysis` crate provides:
- TrueType hinting interpreter with push-loop, control-flow-storm, and call-storm guards.
- CVE signature matching system (YAML-based) with pattern types: TableLengthMismatch, GlyphCountMismatch, and more.
- Font-specific findings: `font.ttf_hinting_push_loop`, `font.ttf_hinting_control_flow_storm`, `font.ttf_hinting_call_storm`.
- PDF.js test corpus baseline (896 PDFs processed without crashes).
- One PDF.js regression fixture: `crates/font-analysis/tests/fixtures/pdfjs/160F-2019.pdf`.

The `fontmatrix_payload_present` detector specifically targets the CVE-2024-4367 pattern (non-numeric FontMatrix entries enabling arbitrary JavaScript execution in PDF.js).

### 1.3 What is not detected

**PDF structural evasion (SETPA framework techniques):**
- Empty object streams injected as padding/confusion
- Fake XREF table entries pointing to non-existent objects
- Benign metadata injection to dilute malicious signal density
- Empty streams added alongside malicious streams
- Non-functional font/image objects used as decoys
- Null/fake objects with valid structure but no function
- Trailer injection with conflicting /Root entries

**Shadow attack variants (NDSS 2021):**
- Hide: Content hidden behind overlay annotations/forms
- Replace: Incremental update replaces visible content while preserving signature
- Hide-and-Replace: Combination using interactive forms to mask content swap
- Evil Annotation Attack (EAA): Annotation overlay on certified documents
- Sneaky Signature Attack (SSA): Signature field overlay on certified documents

**Cross-revision content analysis:**
- Page content stream comparison across revisions (what changed visually)
- Annotation set comparison across revisions (what was added/removed)
- Catalog/page tree structural diff (was the document tree reorganised)
- Form field value extraction across revisions (was form data modified)

**PDF.js-specific attack surface:**
- Font glyph rendering code injection beyond FontMatrix (other font table abuse)
- eval-based rendering path detection (isEvalSupported default-true)
- Annotation rendering XSS vectors
- Form field rendering injection
- Image codec handling differences (browser vs native)

---

## 2. Threat Model

### 2.1 PDF structural evasion

Structural evasion manipulates PDF file format features to confuse, mislead, or defeat detection tools without altering malicious payload behaviour. Eight techniques documented in the SETPA framework (2025) demonstrate that simple structural injections can reduce detection rates across ML-based and heuristic systems by 30-60%.

**Key insight**: The sis-pdf parser already handles these structures correctly (it parses them). The gap is in the detector layer: we lack signals that flag when these structures are used evasively rather than legitimately.

### 2.2 Shadow attacks on signed documents

Shadow attacks exploit the incremental update mechanism in signed PDFs. The existing `xref_conflict`, `incremental_update_chain`, and `object_id_shadowing` detectors provide building blocks, but no detector currently compares pre-signature and post-signature content to identify shadow manipulation.

**Key insight**: Shadow attacks are detectable by comparing the document state at the point of signature to the current state. The parser already exposes revision information via the xref chain.

### 2.3 PDF.js browser-specific attacks

PDF.js processes PDFs in a JavaScript context where type confusion and injection attacks have different consequences than in native readers. The `fontmatrix_payload_present` detector covers the most prominent CVE (CVE-2024-4367), but the broader attack surface (font rendering, annotation handling, form processing) is not covered.

**Key insight**: PDF.js vulnerabilities manifest as crafted PDF structures that look benign to native readers but trigger code injection in JavaScript-based rendering. Detection requires understanding what PDF.js processes differently from Acrobat.

---

## 3. Uplift Plan

### Stage 1: Structural Evasion Indicators (SETPA Coverage)

**Goal**: Detect the eight structural evasion techniques from the SETPA framework. These are format-level anomalies that, when present in combination with malicious content, increase confidence that evasion was intentional.

**Deliverables**:

| Item | Description |
|------|-------------|
| S1-1 | **Empty object stream detector** (`empty_objstm_padding`). Detect ObjStm objects that contain zero or very few actual objects relative to their declared count, or that contain only trivial/null objects. These serve as confusion padding. Distinguish from legitimate empty ObjStm (rare). |
| S1-2 | **Fake XREF entry detector** (`xref_phantom_entries`). Detect XREF entries that reference byte offsets where no valid object definition exists, or where the referenced object number/generation does not match what is found at that offset. Extends existing xref deviation tracking. |
| S1-3 | **Decoy object detector** (`structural_decoy_objects`). Detect objects that are structurally valid but never referenced from the page tree, catalog, or any action chain. High count of unreferenced objects combined with active malicious content (JS, actions) is an evasion indicator. Requires object graph reachability analysis. |
| S1-4 | **Trailer conflict detector** (`trailer_root_conflict`). Detect multiple trailer dictionaries with conflicting /Root entries. The existing xref_conflict assessment already tracks `root_mismatch`; surface this as a dedicated finding when combined with incremental updates. |
| S1-5 | **Null object density detector** (`null_object_density`). Detect high density of null objects (obj ... endobj with only `null` as body) relative to total object count. Null injection is a simple structural padding technique. |
| S1-6 | **Evasion composite signal** (`structural_evasion_composite`). Aggregate signal that fires when 3+ individual structural evasion indicators are present in the same document. Individual indicators at Low severity; composite escalates to Medium or High. Reduces false-positive noise from benign structural quirks while flagging deliberate evasion. |

**Implementation notes**:
- S1-3 (decoy objects) requires a reachability walk from the catalog root. This is the most expensive detector in this stage. Consider implementing as a `Cost::Moderate` detector that only runs when other signals are present.
- All detectors should emit metadata keys prefixed with `evasion.*` for queryability.

**Success criteria**: Detection of 6/8 SETPA techniques. Zero false positives on the PDF.js test corpus (896 benign PDFs). Existing `xref_conflict` and `object_id_shadowing` tests continue passing.

---

### Stage 2: Shadow Attack Detection

**Goal**: Detect the three shadow attack variants (Hide, Replace, Hide-and-Replace) and the two certified document attacks (EAA, SSA) on signed PDFs.

**Approach**: Compare document state across signature boundaries using the existing xref revision chain.

**Deliverables**:

| Item | Description |
|------|-------------|
| S2-1 | **Revision content extractor**. Utility that, given a signed PDF with incremental updates, can identify the byte range covered by each signature and extract the logical document state at each signature point. Uses existing `ByteRange` from `crypto_signatures` detector and xref `/Prev` chain. Not a detector itself; a building block. |
| S2-2 | **Shadow hide detector** (`shadow_hide_attack`). Detect the Hide variant: content that existed at signature time is obscured in the current revision by overlay annotations, forms with opaque backgrounds, or modified OCG (Optional Content Group) visibility. Compare page content references and annotation sets across revisions. |
| S2-3 | **Shadow replace detector** (`shadow_replace_attack`). Detect the Replace variant: content streams or page references changed in a post-signature incremental update. Compare /Contents references, /MediaBox, and /Resources across the revision boundary. Flag when visible content differs from signed content. |
| S2-4 | **Shadow hide-and-replace detector** (`shadow_hide_replace_attack`). Detect the combined variant: interactive form fields (with appearances) used to overlay content that was not part of the signed document. Detect form field additions in post-signature updates where the field has a visual appearance (/AP) that covers page content. |
| S2-5 | **Certified document attack detector** (`certified_doc_manipulation`). Detect EAA and SSA attacks on certified (not just signed) documents. Check if post-certification incremental updates add annotations or signature fields with visual appearances. Certified documents declare permission levels (P1-P3); compare actual changes against declared permissions. |
| S2-6 | **Cross-revision diff summary**. When shadow-related findings are emitted, include metadata summarising the structural diff: objects added, objects modified, objects removed, annotations added, form fields added. Aids analyst investigation. |

**Implementation notes**:
- S2-1 must be robust against malformed ByteRange values (attacker-controlled).
- Shadow detection fundamentally requires processing the document at two points in time (at-signature and current). This is architecturally new for the detector framework. The simplest approach is to parse object references from the earlier xref section without re-parsing the entire document.
- Detection precision depends on the existing `object_id_shadowing` and `shadow_object_payload_divergence` detectors providing the object-level diff. This stage adds the semantic layer (what do the diffs mean visually).

**Success criteria**: Detection of all three shadow attack variants on synthetic test fixtures. No false positives on legitimately incrementally-updated signed documents (e.g., form fill + sign workflows).

---

### Stage 3: PDF.js Attack Surface Detection

**Goal**: Detect PDF structures that are specifically dangerous when processed by browser-based PDF.js viewers, beyond the existing `fontmatrix_payload_present` detector.

**Rationale**: CVE-2024-4367 demonstrated that a single missing type check in PDF.js font rendering allowed arbitrary JavaScript execution, potentially affecting millions of websites. The attack surface extends beyond FontMatrix to any PDF structure where PDF.js uses `eval()` or `new Function()` for performance optimisation.

**Deliverables**:

| Item | Description |
|------|-------------|
| S3-1 | **Font rendering injection detector** (`pdfjs_font_injection`). Extend `fontmatrix_payload_present` to cover additional font table fields that PDF.js processes via eval-based code paths. Check for non-numeric values in: (a) /FontMatrix arrays, (b) /FontBBox arrays, (c) CMap stream commands, (d) Type1 font dict /Encoding entries that contain string values where integers are expected. Each triggers a dedicated sub-finding. |
| S3-2 | **Annotation rendering injection detector** (`pdfjs_annotation_injection`). Detect annotations with appearance streams (/AP) containing embedded JavaScript-like content in text operators (Tj, TJ, Tm). PDF.js renders these via canvas operations; malformed operator arguments could trigger injection in versions with insufficient sanitisation. |
| S3-3 | **Form field injection detector** (`pdfjs_form_injection`). Detect form fields where /V (value), /DV (default value), or /AP (appearance) dictionaries contain content that resembles JavaScript injection payloads. PDF.js renders form field values in the browser DOM; unsanitised values could trigger XSS. |
| S3-4 | **PDF.js eval-path indicator** (`pdfjs_eval_path_risk`). Meta-detector that flags documents containing structures known to be processed by PDF.js's eval-based code paths. Presence of Type1 fonts with custom charsets, CFF fonts with complex Charstring programs, or fonts with custom encoding arrays all trigger this indicator. Severity: Info (structural awareness, not necessarily malicious). |
| S3-5 | **Font-to-JS bridge detector** (`font_js_exploitation_bridge`). Cross-crate detector that correlates font-analysis findings (malformed font tables, CVE signature matches, hinting anomalies) with js-analysis findings (JavaScript presence, eval usage) in the same document. When both a suspicious font and suspicious JavaScript are present, escalate confidence. This bridges the gap between the font-analysis and js-analysis crates. |
| S3-6 | **Test fixtures**. Create synthetic PDFs containing: (a) CVE-2024-4367 FontMatrix payload, (b) FontBBox injection payload, (c) Annotation AP stream with injection, (d) Form field value injection, (e) Benign Type1 font for false-positive validation. |

**Implementation notes**:
- PDF.js-specific detectors should set a `reader_impacts` field indicating which PDF readers are affected (`pdf.js < 4.2.67` for CVE-2024-4367). This helps analysts triage based on their environment.
- The font-to-JS bridge detector (S3-5) requires cross-crate finding correlation. The simplest approach is to implement it in `sis-pdf-detectors` which already depends on both `js-analysis` and `font-analysis`.
- PDF.js attack surface evolves with PDF.js versions. Consider versioning the detection (e.g., `pdfjs_font_injection` marks which PDF.js versions are affected).

**Success criteria**: Detection of CVE-2024-4367 pattern and 3+ additional injection vectors. Font-to-JS bridge correlation fires on documents combining malformed fonts with JavaScript. No false positives on the 896-PDF pdf.js test corpus.

---

### Stage 4: Advanced Cross-Revision Analysis

**Goal**: Provide deeper forensic analysis of incremental updates for analyst investigation and automated triage.

**Deliverables**:

| Item | Description |
|------|-------------|
| S4-1 | **Revision timeline reconstruction**. For documents with multiple revisions, reconstruct a timeline showing: revision number, byte range, objects added/modified/removed, whether a signature covers this revision, and what structural changes occurred. Expose via `sis query revisions --detail`. |
| S4-2 | **Page visual diff indicator** (`revision_page_content_changed`). Detect when page /Contents streams differ between revisions. Does not require rendering; compares stream references and (optionally) stream content hashes. Flags pages where visible content was likely modified after signing. |
| S4-3 | **Annotation diff indicator** (`revision_annotations_changed`). Track annotation additions, removals, and modifications across revisions. Flag annotations added post-signature that have visual appearance streams (potential overlay attacks). |
| S4-4 | **Catalog diff indicator** (`revision_catalog_changed`). Track changes to the document catalog (/Root) across revisions: page tree modifications, action additions, name tree changes, metadata modifications. Flag structural changes that could alter document behaviour. |
| S4-5 | **Revision anomaly scoring**. Assign an anomaly score to each incremental update based on: (a) number of objects changed, (b) types of objects changed (actions and JS get higher weight), (c) whether the update is covered by a signature, (d) whether the changes are consistent with typical editing patterns (form fill, annotation add) vs atypical patterns (page tree restructure, catalog modification). |

**Implementation notes**:
- This stage builds on Stage 2's revision content extractor.
- Performance: Cross-revision analysis on documents with many revisions (10+) could be expensive. Cap analysis at 32 revisions and emit a warning if more exist.
- The revision timeline should be queryable via the existing `sis query` infrastructure.

**Success criteria**: Revision timeline correctly reconstructed for documents with 2-10 revisions. Anomaly scoring distinguishes benign form-fill updates from structural manipulation.

---

### Stage 5: Linearisation and Parser Divergence Detection

**Goal**: Detect linearisation abuse and structures that cause different PDF readers to render different content (parser divergence attacks).

**Deliverables**:

| Item | Description |
|------|-------------|
| S5-1 | **Linearisation integrity detector** (`linearization_integrity`). Validate linearisation dictionaries: (a) /L matches actual file size, (b) hint table offsets are valid, (c) first-page xref is consistent with main xref, (d) object ordering matches linearisation requirements. Malformed linearisation can cause readers to display different first pages or skip objects. |
| S5-2 | **Duplicate stream filter detector** (`duplicate_stream_filters`). Detect objects with identical stream content but different filter chains, or objects where the filter chain produces different output depending on parser implementation (e.g., chaining ASCIIHexDecode with an intentional error mid-stream that some parsers tolerate and others abort on). |
| S5-3 | **Parser divergence indicator** (`parser_divergence_risk`). Heuristic detector that flags documents containing structures known to be parsed differently by Acrobat, Foxit, PDF.js, and Chrome's PDFium. Known divergence points: (a) malformed content streams with recovery-dependent rendering, (b) conflicting encoding declarations, (c) overlapping object definitions where "last wins" vs "first wins" differs by reader. |
| S5-4 | **Content stream syntax anomaly detector** (`content_stream_anomaly`). Detect malformed PDF content stream operators: (a) operators with wrong argument counts, (b) unknown operators, (c) operator sequences that produce different results depending on error recovery. Flag as potential parser divergence vector. |

**Implementation notes**:
- Parser divergence is inherently difficult to detect without running multiple parsers. These detectors flag known divergence patterns rather than guaranteeing divergence.
- Linearisation validation requires reading the linearisation dictionary, which is already parsed by `sis-pdf-pdf`. The gap is in validation, not parsing.

**Success criteria**: Linearisation integrity validated on 50+ linearised PDFs. Parser divergence indicator fires on at least 3 known divergence patterns from published research.

---

## 4. Execution Order and Dependencies

```
Stage 1 (Structural Evasion Indicators)
    |
    +---> Stage 2 (Shadow Attack Detection)
    |         |
    |         v
    |    Stage 4 (Cross-Revision Analysis)
    |
    +---> Stage 3 (PDF.js Attack Surface)
    |
    +---> Stage 5 (Linearisation / Parser Divergence)
```

- Stage 1 is foundational (no dependencies beyond existing detectors).
- Stage 2 depends on Stage 1 for evasion context (shadow attacks often use structural evasion techniques).
- Stage 3 is independent of Stages 1-2 (different attack surface).
- Stage 4 depends on Stage 2 (extends the revision extraction utility).
- Stage 5 is independent of other stages but lower priority.

Stages 1, 3, and 5 can proceed in parallel.

---

## 5. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| False positives on legitimately incrementally-updated PDFs | High | Medium | Require combination of multiple indicators; use existing `has_signature` flag to adjust thresholds; validate against large benign corpus |
| Reachability analysis (S1-3) is too expensive for large documents | Medium | Medium | Gate behind `Cost::Moderate`; cap at 10,000 objects; skip when no other evasion signals present |
| Shadow attack detection triggers on legitimate form-fill-then-sign workflows | High | High | Whitelist common form-field modifications in post-signature updates; require structural changes (not just value changes) to trigger |
| PDF.js-specific detectors become outdated as PDF.js evolves | Medium | Low | Version-tag affected PDF.js versions in findings; document which code paths are checked |
| Cross-revision parsing of attacker-controlled ByteRange values | Medium | High | Validate ByteRange bounds strictly; refuse to process overlapping or out-of-bounds ranges |
| Linearisation validation false positives on sloppy PDF generators | Medium | Medium | Distinguish between spec-violating-but-benign and actively malicious linearisation; use Info severity for minor violations |

---

## 6. Metrics and Success Criteria

### Detection coverage targets

| Technique family | Current detection | Target detection |
|-----------------|-------------------|-----------------|
| SETPA structural evasion (8 techniques) | 2/8 (ObjStm density, object shadowing) | 6/8 |
| Shadow attack variants (3 variants) | Partial (object-level shadowing) | 3/3 with semantic understanding |
| Certified document attacks (EAA, SSA) | None | 2/2 |
| PDF.js font injection (CVE-2024-4367 class) | 1/4+ (FontMatrix only) | 4/4+ |
| Font-to-JS bridge correlation | None | Implemented |
| Linearisation abuse | None | Basic validation |
| Parser divergence | None | 3+ known patterns |

### Quality targets

| Metric | Current | Target |
|--------|---------|--------|
| PDF.js corpus false positive rate | Not measured | <2% |
| Signed PDF false positive rate (form-fill workflows) | Not measured | <5% |
| Cross-revision analysis coverage | Object-level only | Semantic (page, annotation, catalog) |
| Font-to-JS finding correlation | None | Automatic |

---

## 7. Out of Scope

- **PDF rendering/visualisation** - Detection is structural, not visual. We do not render PDFs to compare visual output.
- **PDF.js source code analysis** - We detect PDF structures that are dangerous to PDF.js, not vulnerabilities in PDF.js itself.
- **Signature validation** - We detect structural manipulation around signatures, not whether signatures are cryptographically valid.
- **Machine learning-based structural classification** - All detectors use deterministic heuristics.
- **PDF/A, PDF/X, PDF/UA compliance** - Compliance checking is out of scope.

---

## 8. Relationship to JS Modernisation Plan

This plan complements `plans/20260211-modernisation-js.md`:

- **JS plan Stage 3** (heap exploitation) detects JavaScript-side exploitation patterns. This plan's **Stage 3** (PDF.js) detects PDF-structure-side injection patterns. Together they cover both sides of the font-JS attack chain.
- **JS plan Stage 5** (behavioural resilience) improves dynamic analysis. This plan's **Stage 2** (shadow attacks) improves static structural analysis. They address different layers.
- The **font-to-JS bridge detector** (S3-5) explicitly creates a cross-cutting finding that links the two domains.

---

## 9. References

- [Shadow Attacks: Hiding and Replacing Content in Signed PDFs (NDSS 2021)](https://www.ndss-symposium.org/wp-content/uploads/ndss2021_1B-4_24117_paper.pdf)
- [Detecting PDF Shadow Attacks with iText 7 (PDF Association)](https://pdfa.org/detecting-pdf-shadow-attacks-with-itext-7/)
- [PDF Insecurity Website](https://pdf-insecurity.org/)
- [SETPA: Structural Evasion Techniques for PDF Malware Detection Systems (ScienceDirect, 2025)](https://www.sciencedirect.com/science/article/abs/pii/S016740482500464X)
- [Increased Evasion Resilience in Modern PDF Malware (Diva Portal, 2022)](http://www.diva-portal.org/smash/get/diva2:1678561/FULLTEXT01.pdf)
- [CVE-2024-4367: Arbitrary JavaScript Execution in PDF.js (Codean Labs)](https://codeanlabs.com/blog/research/cve-2024-4367-arbitrary-js-execution-in-pdf-js/)
- [CVE-2024-4367 NVD Entry](https://nvd.nist.gov/vuln/detail/cve-2024-4367)
- [CVE-2025-47943: Stored XSS in Gogs via PDF (Hacktive Security)](https://www.hacktivesecurity.com/blog/2025/07/15/cve-2025-47943-stored-xss-in-gogs-via-pdf/)
- [CVE-2023-26369: Adobe Acrobat Reader RCE (Project Zero)](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2023/CVE-2023-26369.html)
- [PDF-Malware: An Overview on Threats, Detection and Evasion Attacks (arXiv, 2021)](https://arxiv.org/pdf/2107.12873)
- Internal: `plans/20260208-xref-conflict-refinement.md` (xref integrity assessment)
- Internal: `plans/old/20260206-pdfjs-reference.md` (PDF.js corpus evaluation)
- Internal: `docs/research/202602-pdf-attack-surface-breakdown.md` (comprehensive threat model)
