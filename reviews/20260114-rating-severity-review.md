# Deep Review of Rating and Classification Process (2026-01-14)

This document summarizes a deep review of the `sis-pdf` project's finding rating and classification process, focusing on the assignment of `Severity`, `Impact`, and `Confidence` by various detectors. The review aims to identify areas for improvement in accuracy and noise reduction.

## Overview of Rating System

The project utilizes the following rating components:
*   **Severity:** Critical, High, Medium, Low, Info
*   **Impact:** Derived from Severity (Info->None, Low->Low, Medium->Medium, High->High, Critical->Critical)
*   **Confidence:** Strong, Probable, Heuristic (previously Tentative)

## Detector-Specific Review

### 1. ContentFirstDetector

*   **Purpose:** Initial scan of stream/string content for blob classification and various indicators.
*   **Key Findings & Ratings:**
    *   `label_mismatch_stream_type`: Severity ranges from `High` (executable masquerading as image) to `Info` (benign image dict with unknown signature), with `Medium` for other mismatches.
    *   `declared_filter_invalid`, `undeclared_compression_present`, `embedded_payload_carved`: Primarily `High` severity, indicating potential obfuscation or hidden payloads.
    *   `script_payload_present` (e.g., `cmd_payload_present`): Severity is `High` by default, but adjusted to `Low` if the payload is found within known benign contexts like images, XML, HTML, or `Unknown` blobs.
*   **Improvements Made:** Contextualized `script_payload_present` severity based on `BlobKind` to reduce false positives.

### 2. ObjectReferenceCycleDetector

*   **Purpose:** Detects circular references and excessive reference depth in the PDF object graph.
*   **Key Findings & Ratings:**
    *   `object_reference_cycle`: Severity ranges from `High` (self-reference, large cycles) to `Info` (benign page tree cycles) based on cycle length and object types.
    *   `object_reference_depth_high`: `Medium` for depths > 20, `High` for depths > 50.
*   **Improvements Made:** Modified to assign `Severity::Critical` for extremely large cycles (>100 objects) to cover a broader risk spectrum.

### 3. MetadataAnalysisDetector

*   **Purpose:** Analyzes `/Info` dictionary and XMP metadata for suspicious content or size.
*   **Key Findings & Ratings:**
    *   `info_dict_oversized`: `Low` severity for dicts with >20 keys.
    *   `info_dict_suspicious`: `Medium` severity for suspicious `Producer`/`Creator` strings or unusual keys.
    *   `xmp_oversized`: `Low` severity for XMP streams >100KB.
*   **Improvements Made:** Refined `is_suspicious_producer` patterns to reduce false positives by removing common, benign software names.

### 4. UriContentDetector

*   **Purpose:** Deep analysis of individual URIs, assigning a risk score based on numerous content, context, and trigger factors.
*   **Key Findings & Ratings:** `uri_content_analysis` with severity from `Info` to `High` based on a calculated risk score. Examples: `javascript:` URIs score very high.
*   **Recommendations:** Scoring system is comprehensive, and severity mapping is well-designed. No immediate changes recommended.

### 5. UriPresenceDetector

*   **Purpose:** Summarizes overall URI presence in the document.
 *   **Key Findings & Ratings:** `uri_listing` with the same severity scaling, but now consolidates all URIs into one finding while tracking canonical forms, suspicious counts, and the first 20 URI contexts.
*   **Recommendations:** Severity scaling is a good heuristic for identifying extensive external linking. No immediate changes recommended.

### 6. JavaScriptDetector

*   **Purpose:** Detects presence of JavaScript and performs static analysis.
*   **Key Findings & Ratings:** `js_present` with `Severity::High` and `Confidence::Strong`.
*   **Recommendations:** Robust detection logic and useful metadata enrichment through static analysis. No immediate changes recommended.

### 7. OpenActionDetector

*   **Purpose:** Detects document-level actions triggered on opening.
*   **Key Findings & Ratings:** `open_action_present` with `Severity::Medium` and `Confidence::Strong`.
*   **Recommendations:** Provides contextual information about the action. No immediate changes recommended.

### 8. AAPresentDetector and AAEventDetector

*   **Purpose:** Detects and analyzes Additional Actions set to trigger on specific events.
*   **Key Findings & Ratings:** `aa_present` (overall presence) and `aa_event_present` (specific event actions), both `Severity::Medium` with `Strong` or `Probable` confidence.
*   **Recommendations:** Good contextual data for event-driven actions. No immediate changes recommended.

### 9. LaunchActionDetector

*   **Purpose:** Detects `/Launch` actions, which can execute external applications or files.
*   **Key Findings & Ratings:** `launch_action_present` with `Severity::Medium` and `Confidence::Probable`.
*   **Recommendations:** Appropriate rating for a feature with significant security implications. No immediate changes recommended.

### 10. UriDetector

*   **Purpose:** Detects explicit `/URI` actions, including those within annotations.
*   **Key Findings & Ratings:** `uri_present` with `Severity::Medium` and `Confidence::Strong`/`Probable`.
*   **Recommendations:** Appropriate rating for external links. No immediate changes recommended.

### 11. FontMatrixDetector

*   **Purpose:** Detects suspicious non-numeric entries in `FontMatrix` arrays, which could indicate script injection.
*   **Key Findings & Ratings:** `fontmatrix_payload_present` with `Severity::Medium` and `Confidence::Probable`.
*   **Recommendations:** Appropriate rating for a potential script injection vector. No immediate changes recommended.

### 12. SubmitFormDetector

*   **Purpose:** Detects `SubmitForm` actions, which can exfiltrate form data to external endpoints.
*   **Key Findings & Ratings:** `submitform_present` with `Severity::Medium` and `Confidence::Probable`.
*   **Recommendations:** Appropriate rating for a potential data exfiltration vector. No immediate changes recommended.

### 13. GoToRDetector

*   **Purpose:** Detects `GoToR` actions, which can open remote documents or resources.
*   **Key Findings & Ratings:** `gotor_present` with `Severity::Medium` and `Confidence::Probable`.
*   **Recommendations:** Appropriate rating for a potential external resource loading vector. No immediate changes recommended.

### 14. EmbeddedFileDetector

*   **Purpose:** Detects embedded files within the PDF.
*   **Key Findings & Ratings:** `embedded_file_present` with `Severity::High` and `Confidence::Probable`. Enriches with filename, hash, magic type, and decode ratio.
*   **Recommendations:** Appropriate rating for a common malware vector. No immediate changes recommended.

### 15. RichMediaDetector

*   **Purpose:** Detects RichMedia content (e.g., annotations, dictionaries).
*   **Key Findings & Ratings:** `richmedia_present` with `Severity::Medium` and `Confidence::Probable`.
*   **Recommendations:** Appropriate rating for interactive or multimedia elements that can expand the attack surface. No immediate changes recommended.

### 16. ThreeDDetector

*   **Purpose:** Detects 3D content (U3D/PRC).
*   **Key Findings & Ratings:** `3d_present` with `Severity::Medium` and `Confidence::Probable`.
*   **Recommendations:** Appropriate rating for complex content that can be potentially exploited. No immediate changes recommended.

### 17. SoundMovieDetector

*   **Purpose:** Detects sound or movie content.
*   **Key Findings & Ratings:** `sound_movie_present` with `Severity::Medium` and `Confidence::Probable`.
*   **Recommendations:** Appropriate rating for embedded media objects. No immediate changes recommended.

### 18. FileSpecDetector

*   **Purpose:** Detects file specifications or associated files.
*   **Key Findings & Ratings:** `filespec_present` with `Severity::Medium` and `Confidence::Probable`.
*   **Recommendations:** Appropriate rating for external file references. No immediate changes recommended.

### 19. CryptoDetector

*   **Purpose:** Detects cryptographic features, including encryption, digital signatures, and DSS structures.
*   **Key Findings & Ratings:**
    *   `encryption_present`: `Severity::Medium`, `Confidence::Strong`.
    *   `signature_present`: `Severity::Low`, `Confidence::Strong`.
    *   `dss_present`: `Severity::Low`, `Confidence::Probable`.
*   **Recommendations:** Appropriate ratings for various cryptographic indicators. No immediate changes recommended.

### 20. XfaDetector

*   **Purpose:** Detects XFA forms.
*   **Key Findings & Ratings:** `xfa_present` with `Severity::Medium` and `Confidence::Strong`.
*   **Recommendations:** Appropriate rating for XFA forms that can expand the attack surface. No immediate changes recommended.

### 21. AcroFormDetector

*   **Purpose:** Detects AcroForm presence.
*   **Key Findings & Ratings:** `acroform_present` with `Severity::Medium` and `Confidence::Strong`.
*   **Recommendations:** Appropriate rating for interactive form fields and scripts. No immediate changes recommended.

### 22. OCGDetector

*   **Purpose:** Detects Optional Content Groups (OCG).
*   **Key Findings & Ratings:** `ocg_present` with `Severity::Low` and `Confidence::Probable`.
*   **Recommendations:** Appropriate rating for OCGs that can influence viewer behavior. No immediate changes recommended.

### 23. DecoderRiskDetector

*   **Purpose:** Detects streams using high-risk decoders (e.g., JBIG2Decode, JPXDecode).
*   **Key Findings & Ratings:** `decoder_risk_present` with `Severity::High` and `Confidence::Probable`.
*   **Recommendations:** Appropriate rating for decoders known to have a higher risk of vulnerabilities. No immediate changes recommended.

### 24. DecompressionRatioDetector

*   **Purpose:** Detects streams with a suspiciously high decompression ratio.
*   **Key Findings & Ratings:** `decompression_ratio_suspicious` with `Severity::High` and `Confidence::Probable`.
*   **Recommendations:** Appropriate rating for potential decompression bombs. No immediate changes recommended.

### 25. HugeImageDetector

*   **Purpose:** Flags images with excessively large dimensions.
*   **Key Findings & Ratings:** `huge_image_dimensions` with `Severity::Medium` and `Confidence::Probable`.
*   **Recommendations:** Appropriate rating for potential resource abuse. No immediate changes recommended.

### 26. LinearizationDetector

*   **Purpose:** Detects anomalies in PDF linearization.
*   **Key Findings & Ratings:**
    *   `linearization_multiple`: `Severity::Medium`, `Confidence::Probable`.
    *   `linearization_invalid`: `Severity::Medium`, `Confidence::Probable`.
    *   `linearization_hint_anomaly`: `Severity::Low`, `Confidence::Heuristic`.
*   **Recommendations:** Appropriate ratings for potential manipulation or parser confusion. No immediate changes recommended.

### 27. StrictParseDeviationDetector

*   **Purpose:** Detects deviations from strict PDF parsing rules and anomalies in PDF header/EOF.
*   **Key Findings & Ratings:** Severity ranges from `Low` to `High` depending on the deviation, with `High` for deviations in action contexts.
*   **Recommendations:** Appropriate ratings for structural integrity and parsing behavior. No immediate changes recommended.

### 28. ICCProfileDetector

*   **Purpose:** Detects anomalies in embedded ICC profiles.
*   **Key Findings & Ratings:** `icc_profile_oversized` and `icc_profile_anomaly`, both `Severity::Medium`, `Confidence::Probable`.
*   **Recommendations:** Appropriate ratings for potential obfuscation or vulnerabilities. No immediate changes recommended.

### 29. IrGraphStaticDetector

*   **Purpose:** Static analysis on the PDF's Intermediate Representation (IR) graph to identify suspicious object relationships.
*   **Key Findings & Ratings:** Severity ranges from `Low` to `Medium` for various payload-related paths and orphaned/shadowed objects.
*   **Recommendations:** Appropriate ratings for detecting complex attacks. No immediate changes recommended.

### 30. JsPolymorphicDetector

*   **Purpose:** Detects polymorphic or multi-stage JavaScript patterns.
*   **Key Findings & Ratings:** `js_polymorphic` and `js_multi_stage_decode` (`Severity::Medium`, `Confidence::Probable`), `js_obfuscation_deep` (`Severity::Low`, `Confidence::Heuristic`).
*   **Recommendations:** Appropriate ratings for sophisticated JavaScript obfuscation. No immediate changes recommended.

### 31. JavaScriptSandboxDetector

*   **Purpose:** Executes JavaScript payloads in a sandbox to observe runtime behavior.
*   **Key Findings & Ratings:** `Severity` ranges from `Info` (skipped/executed without risky calls) to `High` (network intent, risky calls).
*   **Recommendations:** Appropriate ratings for dynamic analysis of JavaScript. No immediate changes recommended.

### 32. MultiStageDetector

*   **Purpose:** Detects indicators of a multi-stage attack chain (JavaScript, embedded content, external action).
*   **Key Findings & Ratings:** `multi_stage_attack_chain` with `Severity::High`, `Confidence::Probable`.
*   **Recommendations:** Appropriate rating for a high-risk attack pattern. No immediate changes recommended.

### 33. PolyglotDetector

*   **Purpose:** Detects if a PDF file is also a valid file of another type.
*   **Key Findings & Ratings:** `polyglot_signature_conflict` with `Severity::Medium` (strong conflict) or `Low` (weaker conflict).
*   **Recommendations:** Appropriate ratings for a sophisticated evasion technique. No immediate changes recommended.

### 34. TimingEvasionDetector

*   **Purpose:** Detects JavaScript code that uses timing-related APIs for evasion.
*   **Key Findings & Ratings:** `js_time_evasion` with `Severity::Medium`, `Confidence::Probable`.
*   **Recommendations:** Appropriate rating for a common evasion technique. No immediate changes recommended.

### 35. EnvProbeDetector

*   **Purpose:** Detects JavaScript code that queries environment or viewer properties for evasion.
*   **Key Findings & Ratings:** `js_env_probe` with `Severity::Medium`, `Confidence::Probable`.
*   **Recommendations:** Appropriate rating for a common evasion technique. No immediate changes recommended.

### 36. AdvancedCryptoDetector

*   **Purpose:** Detects advanced cryptographic anomalies.
*   **Key Findings & Ratings:** `crypto_weak_algo` (`Severity::Medium`), `crypto_cert_anomaly` (`Severity::Low`), `crypto_mining_js` (`Severity::High`).
*   **Recommendations:** Appropriate ratings for various cryptographic risks. No immediate changes recommended.

### 37. AnnotationAttackDetector

*   **Purpose:** Detects suspicious characteristics in PDF annotations.
*   **Key Findings & Ratings:** `annotation_hidden` (`Severity::Low`), `annotation_action_chain` (`Severity::Medium`).
*   **Recommendations:** Appropriate ratings for potential attack vectors. No immediate changes recommended.
