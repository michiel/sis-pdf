# Findings Reference

This document describes every finding ID that `sis-pdf` can emit. Each entry includes a label, a short description, tags for quick grouping, and details on relevance, meaning, and exploit-chain usage.

---

## Evasion-Resistant Metadata Fields

As of 2026-01-08, sis-pdf includes enhanced payload reconstruction capabilities to detect evasively-hidden JavaScript. The following metadata fields are added to findings when evasion techniques are detected or payloads are reconstructed:

### Payload Reconstruction Metadata

**payload.type**
- Values: `string`, `stream`, `array[N]` where N is the number of fragments
- Meaning: Indicates how the payload was extracted
- Example: `array[3]` means the payload was reconstructed from 3 array elements

**payload.ref_chain**
- Values: Reference chain like `10 0 R -> 11 0 R -> 12 0 R` or `-` for direct payloads
- Meaning: Shows the indirect reference chain followed to resolve the payload
- Example: `10 0 R -> array[3]` indicates object 10 contained an array of 3 fragments

**payload.fromCharCode_reconstructed**
- Values: `true` or absent
- Meaning: JavaScript payload contains reconstructed String.fromCharCode(...) calls
- Detection: Static analysis found and decoded character code arrays

**payload.fromCharCode_count**
- Values: Integer count
- Meaning: Number of fromCharCode strings successfully reconstructed
- Example: `3` means 3 separate fromCharCode calls were decoded

**payload.fromCharCode_preview**
- Values: String (max 200 characters)
- Meaning: Preview of first reconstructed fromCharCode payload
- Example: `app.alert('malicious')` shows the decoded function call

### Multiple Key Detection

**js.multiple_keys**
- Values: `true` or absent
- Meaning: Dictionary contains multiple JavaScript keys (evasion technique)
- Detection: More than one /JS, /JavaScript, or /JScript key found

**js.multiple_keys_count**
- Values: Integer count
- Meaning: Total number of JavaScript keys in dictionary
- Example: `2` indicates two separate JS keys (suspicious)

**payload_key_N**
- Values: Key name string (e.g., `/JavaScript`, `/#4A#53`)
- Meaning: Additional JavaScript key names beyond the first
- Example: `payload_key_2: /JScript` shows second key

### Enhanced Error Reporting

**js.stream.decode_error**
- Additional error types:
  - `circular reference detected: N M R` - Reference loop found
  - `max resolution depth 10 exceeded` - Too many reference hops
  - `array too large: 1234 elements (max 1000)` - Array size limit exceeded
  - `array payload reconstruction failed: ...` - Array reconstruction error

### Action & Reader Telemetry Fields

**impact**
- Values: `critical`, `high`, `medium`, `low`, `none`.
- Meaning: Coarse impact bucket describing the fallout if the finding is exploited; derived from the adjusted severity so downstream tools can rely on a stable impact label.
- Example: `high` for an action that launches an external payload.

**action_type**
- Values: Strings such as `Launch`, `JavaScript`, `GoTo`, `RichMedia`, `EmbeddedFile`.
- Meaning: The category of action path that produced the finding.
- Example: `Launch` for a `/Launch` entry that starts a child process.

**action_target**
- Values: Convenient descriptors like `uri:http://example.com/malware.exe`, `file:payload.exe`, `object:15 0 R`.
- Meaning: Where the action is attempting to go or what it is invoking.

**action_initiation**
- Values: `automatic`, `user`, `hidden`, `deep`.
- Meaning: Describes whether the action fires automatically on open, requires user interaction, or is hidden.

**reader_impacts**
- Values: An array of reader-scored entries with keys `profile`, `surface`, `severity`, `impact`, and optional `note`.
- Meaning: Details how severity and impact shift for each supported reader (`acrobat`, `pdfium`, `preview`).
- Example: `[{ "profile": "preview", "surface": "Actions", "severity": "low", "impact": "low", "note": "Severity capped for preview limits" }]`.
- Notes:
  - `surface` is repeated for clarity even though the finding already declares it.
  - `note` appears whenever the reader-specific score diverges from the base severity.

**reader.impact.<profile>**
- Values: `info`, `low`, `medium`, `high`, `critical`.
- Meaning: Mirrors each reader's severity bucket and is populated for the same profiles above.

**reader.impact.summary**
- Values: A comma-separated string of `<profile>:<severity>/<impact>` pairs (e.g., `acrobat:critical/critical,pdfium:low/low`).
- Meaning: Quick reference for analyst workflows that only need a textual summary of reader divergence.

### Evasion Techniques Detected

The enhanced analysis now detects and reconstructs:
1. **Array-based fragmentation**: JavaScript split across array elements
2. **Multi-hop references**: Payload hidden through reference chains (up to 10 hops)
3. **Hex-encoded keys**: `/JS` encoded as `/#4A#53` or similar
4. **Name variants**: `/JavaScript`, `/JScript` keys now recognized
5. **Multiple keys**: Duplicate /JS keys in same dictionary
6. **Character code obfuscation**: `String.fromCharCode(...)` decoded to strings
7. **Object streams**: Always expanded to find hidden content (no --deep flag required)
8. **Object shadowing**: Latest object version used (incremental updates)

For implementation details, see `plans/review-evasive.md` and `plans/evasion-implementation-summary.md`.

---

## 3d_present

- ID: `3d_present`
- Label: 3D content present
- Description: 3D content or stream detected (U3D/PRC).
- Tags: feature
- Details:
  - Relevance: expanded attack surface.
  - Meaning: feature increases parsing or interaction complexity.
  - Chain usage: used as supporting context for delivery or exploitation stages.

## aa_event_present

- ID: `aa_event_present`
- Label: AA event action present
- Description: Detected aa event action present.
- Tags: action
- Details:
  - Relevance: specific event-driven execution.
  - Meaning: an AA event entry is present.
  - Chain usage: signals a trigger edge into action/payload nodes.

## aa_present

- ID: `aa_present`
- Label: Additional Actions present
- Description: Additional Actions can execute on user events.
- Tags: action
- Details:
  - Relevance: event-driven execution.
  - Meaning: Additional Actions can fire on viewer events.
  - Chain usage: used as a trigger for action/payload chains.

## acroform_present

- ID: `acroform_present`
- Label: AcroForm present
- Description: Interactive AcroForm dictionaries detected.
- Tags: feature
- Details:
  - Relevance: expanded attack surface.
  - Meaning: feature increases parsing or interaction complexity.
  - Chain usage: used as supporting context for delivery or exploitation stages.

## action_payload_path

- ID: `action_payload_path`
- Label: Action path reaches payload
- Description: Detected action path reaches payload.
- Tags: chain
- Details:
  - Relevance: direct execution path.
  - Meaning: an action node reaches a payload-like object in the graph.
  - Chain usage: used to connect actions to payloads in the synthesized chain.

## action_chain_complex

- ID: `action_chain_complex`
- Label: Complex action chain
- Description: Action chain depth exceeds expected threshold.
- Tags: action, chain
- Details:
  - Relevance: chained actions can hide payload staging.
  - Meaning: action chains increase execution complexity.
  - Chain usage: treated as a higher-risk action staging indicator.

## action_hidden_trigger

- ID: `action_hidden_trigger`
- Label: Hidden action trigger
- Description: Action triggered from hidden or non-visible annotation.
- Tags: action, evasion
- Details:
  - Relevance: hidden triggers can bypass user awareness.
  - Meaning: actions may execute without user interaction.
  - Chain usage: raises confidence for action-driven payloads.

## action_automatic_trigger

- ID: `action_automatic_trigger`
- Label: Automatic action trigger
- Description: Action triggers without explicit user interaction.
- Tags: action
- Details:
  - Relevance: automatic triggers execute actions on open or visibility changes.
  - Meaning: viewer may execute actions without user intent.
  - Chain usage: treated as trigger stage in action chains.

## annotation_action_chain

- ID: `annotation_action_chain`
- Label: Annotation action chain
- Description: Annotation contains /A or /AA action entries.
- Tags: feature
- Details:
  - Relevance: expanded attack surface.
  - Meaning: feature increases parsing or interaction complexity.
  - Chain usage: used as supporting context for delivery or exploitation stages.

## annotation_hidden

- ID: `annotation_hidden`
- Label: Hidden annotation
- Description: Annotation rectangle has near-zero size.
- Tags: feature
- Details:
  - Relevance: expanded attack surface.
  - Meaning: feature increases parsing or interaction complexity.
  - Chain usage: used as supporting context for delivery or exploitation stages.

## content_html_payload

- ID: `content_html_payload`
- Label: HTML-like payload in content
- Description: Content contains HTML or javascript-like sequences.
- Tags: content, phishing
- Details:
  - Relevance: social-engineering signal.
  - Meaning: content patterns resemble phishing or UI deception.
  - Chain usage: used to explain user-targeted stages alongside action findings.

## content_image_only_page

- ID: `content_image_only_page`
- Label: Image-only page
- Description: Page content contains images without detectable text.
- Tags: content, phishing
- Details:
  - Relevance: decoy or lure page.
  - Meaning: page contains images without text.
  - Chain usage: supports social-engineering chain stages.

## content_invisible_text

- ID: `content_invisible_text`
- Label: Invisible text rendering
- Description: Content stream suggests invisible text rendering mode.
- Tags: content, phishing
- Details:
  - Relevance: hidden content.
  - Meaning: invisible text can carry scripts or phishing keywords.
  - Chain usage: used as stealth content signal in chains.

## content_overlay_link

- ID: `content_overlay_link`
- Label: Potential overlay link
- Description: Page combines image content with URI annotations.
- Tags: content, phishing, ui
- Details:
  - Relevance: click-through lure.
  - Meaning: image-only content with URI overlays suggests deception.
  - Chain usage: used to model user-driven trigger steps.

## content_phishing

- ID: `content_phishing`
- Label: Potential phishing content
- Description: Detected phishing-like keywords alongside external URI actions.
- Tags: content, phishing
- Details:
  - Relevance: social-engineering signal.
  - Meaning: content patterns resemble phishing or UI deception.
  - Chain usage: used to explain user-targeted stages alongside action findings.

## crypto_cert_anomaly

- ID: `crypto_cert_anomaly`
- Label: Signature chain anomaly
- Description: Detected signature chain anomaly.
- Tags: crypto
- Details:
  - Relevance: cryptographic structures or misuse.
  - Meaning: signatures/encryption/crypto anomalies change trust or hide content.
  - Chain usage: used as staging or trust-evasion context in chains.

## crypto_mining_js

- ID: `crypto_mining_js`
- Label: Cryptomining JavaScript
- Description: JavaScript includes cryptomining indicators.
- Tags: crypto
- Details:
  - Relevance: cryptographic structures or misuse.
  - Meaning: signatures/encryption/crypto anomalies change trust or hide content.
  - Chain usage: used as staging or trust-evasion context in chains.

## crypto_weak_algo

- ID: `crypto_weak_algo`
- Label: Weak cryptography settings
- Description: Detected weak cryptography settings.
- Tags: crypto
- Details:
  - Relevance: cryptographic structures or misuse.
  - Meaning: signatures/encryption/crypto anomalies change trust or hide content.
  - Chain usage: used as staging or trust-evasion context in chains.

## decoder_risk_present

- ID: `decoder_risk_present`
- Label: High-risk decoder present
- Description: Detected high-risk decoder present.
- Tags: decoder, resource
- Details:
  - Relevance: parser/decoder risk.
  - Meaning: content can trigger heavy decoding or edge-case behavior.
  - Chain usage: used as a payload delivery or exploitation path indicator.

## decompression_ratio_suspicious

- ID: `decompression_ratio_suspicious`
- Label: Suspicious decompression ratio
- Description: Detected suspicious decompression ratio.
- Tags: decoder, resource
- Details:
  - Relevance: parser/decoder risk.
  - Meaning: content can trigger heavy decoding or edge-case behavior.
  - Chain usage: used as a payload delivery or exploitation path indicator.

## dss_present

- ID: `dss_present`
- Label: DSS structures present
- Description: Document Security Store (DSS) entries detected.
- Tags: crypto
- Details:
  - Relevance: cryptographic structures or misuse.
  - Meaning: signatures/encryption/crypto anomalies change trust or hide content.
  - Chain usage: used as staging or trust-evasion context in chains.

## embedded_file_present

- ID: `embedded_file_present`
- Label: Embedded file stream present
- Description: Embedded file detected inside PDF.
- Tags: feature
- Details:
  - Relevance: expanded attack surface.
  - Meaning: feature increases parsing or interaction complexity.
  - Chain usage: used as supporting context for delivery or exploitation stages.

## embedded_executable_present

- ID: `embedded_executable_present`
- Label: Embedded executable present
- Description: Embedded file appears to be an executable.
- Tags: payload, embedded
- Details:
  - Relevance: executable payloads can run arbitrary code.
  - Meaning: embedded executable increases compromise risk.
  - Chain usage: payload delivery stage.

## embedded_script_present

- ID: `embedded_script_present`
- Label: Embedded script present
- Description: Embedded file appears to be a script.
- Tags: script, embedded
- Details:
  - Relevance: scripts can execute commands or fetch payloads.
  - Meaning: embedded scripts increase execution risk.
  - Chain usage: payload execution or staging stage.

## vector_graphics_anomaly

- ID: `vector_graphics_anomaly`
- Label: Vector graphics anomaly
- Severity: Medium
- Description: Content stream contains an unusually dense mix of vector drawing operators, tiny clipping areas, or spot colors.
- Tags: vector, graphics, images
- Details:
  - Relevance: vector-heavy paths can hide payloads, obfuscate data, or embed attack flows inside otherwise-normal drawings.
  - Meaning: high operator counts, repeated rectangles, or spot-indexed colour spaces raise suspicion for manipulated Illustrator/EPS/SVG content.
  - Chain usage: treated as an action/payload stage that may point to obfuscated delivery or triggering drawing code.

## embedded_archive_encrypted

- ID: `embedded_archive_encrypted`
- Label: Embedded archive encrypted
- Description: Embedded archive indicates encryption flags.
- Tags: evasion, embedded
- Details:
  - Relevance: encrypted containers can hide payloads.
  - Meaning: embedded archive may require passwords or manual analysis.
  - Chain usage: used as evasion context that can hide payloads.

## embedded_double_extension

- ID: `embedded_double_extension`
- Label: Embedded file uses double extension
- Description: Embedded filename uses multiple extensions.
- Tags: evasion, embedded
- Details:
  - Relevance: double extensions can disguise executable payloads.
  - Meaning: embedded filename attempts to appear benign.
  - Chain usage: used as evasion context for payload delivery.

## embedded_encrypted

- ID: `embedded_encrypted`
- Label: Embedded file appears encrypted
- Description: Embedded file has high entropy with unknown magic.
- Tags: embedded, crypto
- Details:
  - Relevance: encrypted payloads can hide malicious content.
  - Meaning: embedded file likely requires decryption to inspect.
  - Chain usage: evasion context for payload delivery.
  - Metadata:
    - `entropy`: observed entropy value
    - `entropy_threshold`: configured detection threshold
    - `sample_size_bytes`: bytes used to compute entropy
    - `stream.magic_type`: classifier label emitted by the stream analysis
    - `stream.sample_timed_out`: `true` when sampling hit the timeout limit

## encryption_present

- ID: `encryption_present`
- Label: Encryption dictionary present
- Description: Trailer indicates encrypted content via /Encrypt.
- Tags: crypto
- Details:
  - Relevance: cryptographic structures or misuse.
  - Meaning: signatures/encryption/crypto anomalies change trust or hide content.
  - Chain usage: used as staging or trust-evasion context in chains.

## encryption_key_short

- ID: `encryption_key_short`
- Label: Encryption key length short
- Description: Encryption key length is below recommended threshold.
- Tags: crypto
- Details:
  - Relevance: weak encryption settings reduce trust.
  - Meaning: encrypted content uses short keys.
  - Chain usage: crypto weakness context for trust evaluation.

## stream_high_entropy

- ID: `stream_high_entropy`
- Label: High entropy stream
- Description: Stream entropy exceeds expected threshold.
- Tags: decoder, evasion
- Details:
  - Relevance: high entropy indicates compression or encryption.
  - Meaning: payload may be obfuscated or encrypted.
  - Chain usage: evasion context for hidden payloads.
  - Metadata:
    - `entropy`: computed entropy value (0-8)
    - `entropy_threshold`: threshold that triggered the finding
    - `sample_size_bytes`: bytes consumed for entropy sampling
    - `stream.magic_type`: detected magic label (`zip`, `rar`, `unknown`, etc.)
    - `stream.sample_timed_out`: indicates sampling was stopped due to the timeout budget

## eof_offset_unusual

- ID: `eof_offset_unusual`
- Label: EOF marker far from file end
- Description: Detected eof marker far from file end.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## external_action_risk_context

- ID: `external_action_risk_context`
- Label: External action with obfuscation context
- Description: External action targets are present alongside obfuscation markers (hex-encoded names or deep filter chains).
- Tags: context
- Details:
  - Relevance: risky action context.
  - Meaning: external actions coincide with obfuscation markers.
  - Chain usage: raises confidence on action-to-payload chains.

## filespec_present

- ID: `filespec_present`
- Label: File specification present
- Description: Filespec or associated files detected.
- Tags: feature
- Details:
  - Relevance: expanded attack surface.
  - Meaning: feature increases parsing or interaction complexity.
  - Chain usage: used as supporting context for delivery or exploitation stages.

## filter_chain_depth_high

- ID: `filter_chain_depth_high`
- Label: Deep filter chain
- Description: Detected deep filter chain.
- Tags: decoder, resource
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## filter_chain_unusual

- ID: `filter_chain_unusual`
- Label: Unusual filter chain
- Description: Filter chain uses uncommon or unexpected combinations.
- Tags: decoder, evasion
- Metadata:
  - `filters`: Filter list encoded as JSON array string.
  - `filter_count`: Number of filters in the chain.
  - `allowlist_match`: Whether the chain matched the allowlist.
  - `violation_type`: `allowlist_miss`, `unknown_filter`, or `strict_mode`.
  - `stream.filter_chain`: Human-readable filter chain.
  - `stream.filter_depth`: Filter chain length.
- Details:
  - Relevance: unusual filters can hide payloads.
  - Meaning: stream decoding is non-standard.
  - Violation types: `allowlist_miss`, `unknown_filter`, `strict_mode`, `image_with_compression`.
  - Example chain: `ASCIIHexDecode -> FlateDecode`.
  - Example metadata: `filters = ["ASCIIHexDecode", "FlateDecode"]`, `stream.filter_chain = ASCIIHexDecode -> FlateDecode`.
  - Chain usage: evasion context for hidden payloads.

## filter_order_invalid

- ID: `filter_order_invalid`
- Label: Invalid filter order
- Description: ASCII filters appear after binary filters.
- Tags: decoder, evasion
- Metadata:
  - `filters`: Filter list encoded as JSON array string.
  - `filter_count`: Number of filters in the chain.
  - `allowlist_match`: Whether the chain matched the allowlist.
  - `violation_type`: `ascii_after_binary` or `crypt_not_outermost`.
  - `stream.filter_chain`: Human-readable filter chain.
  - `stream.filter_depth`: Filter chain length.
- Details:
  - Relevance: invalid order can indicate obfuscation.
  - Meaning: stream decoding order is inconsistent.
  - Violation types: `ascii_after_binary`, `crypt_not_outermost`.
  - Example chain: `FlateDecode -> ASCII85Decode`.
  - Example metadata: `filters = ["FlateDecode", "ASCII85Decode"]`, `stream.filter_chain = FlateDecode -> ASCII85Decode`.
  - Chain usage: evasion context for hidden payloads.

## filter_combination_unusual

- ID: `filter_combination_unusual`
- Label: Repeated filters in chain
- Description: Filter chain repeats the same filter multiple times.
- Tags: decoder, evasion
- Metadata:
  - `filters`: Filter list encoded as JSON array string.
  - `filter_count`: Number of filters in the chain.
  - `allowlist_match`: Whether the chain matched the allowlist.
  - `violation_type`: `duplicate_filters`.
  - `stream.filter_chain`: Human-readable filter chain.
  - `stream.filter_depth`: Filter chain length.
- Details:
  - Relevance: redundant filters can hide payloads.
  - Meaning: stream decoding is likely obfuscated.
  - Violation types: `duplicate_filters`.
  - Example chain: `ASCII85Decode -> FlateDecode -> FlateDecode`.
  - Example metadata: `filters = ["ASCII85Decode", "FlateDecode", "FlateDecode"]`, `stream.filter_chain = ASCII85Decode -> FlateDecode -> FlateDecode`.
  - Chain usage: evasion context for hidden payloads.

## filter_chain_jbig2_obfuscation

- ID: `filter_chain_jbig2_obfuscation`
- Label: JBIG2 filter chain obfuscation
- Description: JBIG2 streams are wrapped inside ASCII/binary filters, matching FORCEDENTRY-style padding of the JBIG2 decoder with 1×N strips.
- Tags: decoder, evasion, cve
- Metadata:
  - `filters`: Filter list encoded as JSON array string.
  - `filter_count`: Number of filters in the chain.
  - `stream.filter_chain`: Human-readable filter chain.
  - `stream.filter_depth`: Filter chain length.
  - `violation_type`: `jbig2_obfuscation`.
  - `cve`: `CVE-2021-30860,CVE-2022-38171`.
  - `jbig2.cves`: Comma-separated CVE IDs matching `cve`.
  - `attack_surface`: `Image codecs / filter obfuscation`.
- Details:
  - Relevance: JBIG2 obfuscation powers modern zero-click payloads.
  - Meaning: stream decoding layers hide JBIG2Decode behind ASCII/Flate filters.
  - Example chain: `ASCIIHexDecode -> ASCII85Decode -> JBIG2Decode`.
  - Chain usage: high-confidence context for JBIG2 pipelines; metadata and fixtures (`crates/sis-pdf-core/tests/fixtures/filters/jbig2_ascii_obfuscation.pdf`) guide remediation.

## font_payload_present

- ID: `font_payload_present`
- Label: Large embedded font payload
- Description: Embedded font stream size exceeds expected bounds.
- Tags: font
- Details:
  - Relevance: font parsing attack surface.
  - Meaning: embedded fonts can trigger vulnerable code paths.
  - Chain usage: treated as a payload stage targeting renderer vulnerabilities.

## font_table_anomaly

- ID: `font_table_anomaly`
- Label: Suspicious font table signature
- Description: Font stream contains CFF/OTF markers that warrant inspection.
- Tags: font
- Details:
  - Relevance: font parsing attack surface.
  - Meaning: embedded fonts can trigger vulnerable code paths.
  - Chain usage: treated as a payload stage targeting renderer vulnerabilities.

## font.invalid_structure

- ID: `font.invalid_structure`
- Label: Invalid font structure
- Description: Font parsing rejected due to invalid structure or offsets.
- Tags: font
- Details:
  - Relevance: font parsing attack surface.
  - Meaning: malformed fonts can trigger parser instability or bypass checks.
  - Chain usage: treated as a payload stage targeting renderer vulnerabilities.

## font.anomalous_table_size

- ID: `font.anomalous_table_size`
- Label: Anomalous font table sizes
- Description: Font tables exceed expected size limits or are oversized.
- Tags: font
- Details:
  - Relevance: font parsing attack surface.
  - Meaning: oversized tables can signal overflow or parser stress attempts.
  - Chain usage: treated as a payload stage targeting renderer vulnerabilities.

## font.inconsistent_table_layout

- ID: `font.inconsistent_table_layout`
- Label: Inconsistent font table layout
- Description: Font table directory contains overlapping or duplicate entries.
- Tags: font
- Details:
  - Relevance: font parsing attack surface.
  - Meaning: inconsistent layouts can exploit parser assumptions.
  - Chain usage: treated as a payload stage targeting renderer vulnerabilities.

## font.suspicious_hinting

- ID: `font.suspicious_hinting`
- Label: Suspicious hinting programs
- Description: Hinting programs are unusually large or complex.
- Tags: font
- Details:
  - Relevance: font parsing attack surface.
  - Meaning: hinting bytecode can stress or exploit interpreter paths.
  - Chain usage: treated as a payload stage targeting renderer vulnerabilities.

## font.ttf_hinting_suspicious

- ID: `font.ttf_hinting_suspicious`
- Label: Suspicious TrueType hinting
- Description: Hinting program execution triggered a security check (stack limits, division-by-zero, budget, unmatched control-flow, etc.).
- Tags: font, dynamic
- Details:
  - Relevance: dynamic font validation.
  - Meaning: the TrueType virtual machine observed anomalies while parsing `fpgm`/`prep` tables. Most stack underflow/overflow occurrences are marked as low-severity heuristics unless additional anomalies accompany them; other runtime errors remain medium severity.
  - Chain usage: treated as a renderer-targeting payload signal when medium/high variants surface.

## font.dynamic_parse_failure

- ID: `font.dynamic_parse_failure`
- Label: Font parsing failed
- Description: Dynamic font parsing failed in the runtime engine.
- Tags: font, dynamic
- Details:
  - Relevance: dynamic validation step.
  - Meaning: runtime parser errors can signal malformed or hostile fonts.
  - Chain usage: treated as a payload stage targeting renderer vulnerabilities.
  - Context: `UnknownMagic` errors often accompany renderer-generated FontFile3/CFF blobs, so these failures are now flagged with lower severity unless backed by other anomalies.

## font.dynamic_renderer_font

- ID: `font.dynamic_renderer_font`
- Label: Renderer font skipped
- Description: Renderer-generated Cairo Type1/CFF blob is handled by the Type 1 analyzer instead of the strict dynamic parser.
- Tags: font, dynamic, info
- Details:
  - Relevance: dynamic validation step.
  - Meaning: the font matched the renderer-produced Cairo Type1/CFF pattern (`CairoFont`, header byte `0x01`), so we skip the parser and rely on deterministic Type 1 analysis.
  - Chain usage: treated as an informational signal; it documents the trusted path without escalating severity.

## font.dynamic_timeout

- ID: `font.dynamic_timeout`
- Label: Font analysis timeout
- Description: Dynamic font analysis exceeded the configured timeout.
- Tags: font, dynamic
- Details:
  - Relevance: dynamic validation step.
  - Meaning: long-running font parsing can indicate DoS or complexity abuse.
  - Chain usage: treated as an evasion or payload stage indicator.

## font.multiple_vuln_signals

- ID: `font.multiple_vuln_signals`
- Label: Multiple font anomalies
- Description: Font exhibits multiple anomalous signals.
- Tags: font
- Details:
  - Relevance: combined font exploitation signals.
  - Meaning: multiple anomalies increase confidence of malicious intent.
  - Chain usage: raises confidence on payload stages targeting renderer vulnerabilities.

## font.type1_dangerous_operator

- ID: `font.type1_dangerous_operator`
- Label: Type 1 font with dangerous operators
- Description: PostScript Type 1 font contains dangerous operators (callothersubr, blend, pop, return, put, store).
- Tags: font, type1, exploit
- Details:
  - Relevance: PostScript Type 1 exploitation surface.
  - Meaning: dangerous operators can trigger stack manipulation or arbitrary code execution in font renderers.
  - Context: attackers use these primitives (callothersubr/pop/return/put/store/blend) to corrupt interpreter stack/memory or escape to arbitrary execution paths (see BLEND/2015).
  - Chain usage: treated as a payload stage targeting Type 1 font parser vulnerabilities.
  - Severity: MEDIUM (downgrades to LOW when only stack-manipulating operators `pop`, `put`, `return` are present; escalates to HIGH when `callothersubr`, `store`, or `blend` operators appear)
  - Introduced: Font analysis enhancement (2026-01-17)

## font.type1_excessive_stack

- ID: `font.type1_excessive_stack`
- Label: Type 1 font with excessive stack usage
- Description: Type 1 charstrings use excessive stack depth (>100 entries).
- Tags: font, type1, resource
- Details:
  - Relevance: stack overflow or parser stress attempts.
  - Meaning: excessive stack usage may trigger buffer overflows or denial of service.
  - Chain usage: treated as a payload delivery or exploitation preparation stage.
  - Severity: LOW
  - Introduced: Font analysis enhancement (2026-01-17)

## font.type1_large_charstring

- ID: `font.type1_large_charstring`
- Label: Type 1 font with large charstring program
- Description: Type 1 font contains unusually large charstring programs (>10,000 operators).
- Tags: font, type1, resource
- Details:
  - Relevance: complexity or resource exhaustion.
  - Meaning: large charstring programs can stress parsers or hide malicious code.
  - Chain usage: used as a parser stress or obfuscation technique.
  - Severity: LOW
  - Introduced: Font analysis enhancement (2026-01-17)

## font.type1_blend_exploit

- ID: `font.type1_blend_exploit`
- Label: Type 1 BLEND exploit pattern detected
- Description: Font contains the signature pattern of the 2015 BLEND exploit (multiple callothersubr/return sequences).
- Tags: font, type1, exploit, cve
- Details:
  - Relevance: known PostScript Type 1 exploit pattern.
  - Meaning: BLEND exploit manipulates PostScript interpreter stack to execute arbitrary code.
  - Chain usage: treated as a high-confidence exploitation attempt.
  - Severity: HIGH
  - CVE: CVE-2015-XXXX (BLEND exploit family)
  - Introduced: Font analysis enhancement (2026-01-17)

## font.cve_2025_27163

- ID: `font.cve_2025_27163`
- Label: CVE-2025-27163: hmtx/hhea table mismatch
- Description: TrueType/OpenType hmtx table length is smaller than required based on hhea.numberOfHMetrics.
- Tags: font, truetype, cve, vulnerability
- Details:
  - Relevance: known TrueType table parsing vulnerability.
  - Meaning: table length mismatch leads to out-of-bounds reads when accessing horizontal metrics.
  - Chain usage: treated as a known vulnerability exploitation attempt.
  - Severity: HIGH
  - CVE: CVE-2025-27163
  - Introduced: Font analysis enhancement (2026-01-17)

## font.cve_2025_27164

- ID: `font.cve_2025_27164`
- Label: CVE-2025-27164: CFF2/maxp glyph count mismatch
- Description: OpenType/CFF2 maxp.num_glyphs exceeds CFF2 charstring count.
- Tags: font, opentype, cff, cve, vulnerability
- Details:
  - Relevance: known OpenType/CFF2 parsing vulnerability.
  - Meaning: glyph count mismatch leads to buffer overflow when accessing glyph data beyond charstring array bounds.
  - Chain usage: treated as a known vulnerability exploitation attempt.
  - Severity: HIGH
  - CVE: CVE-2025-27164
  - Introduced: Font analysis enhancement (2026-01-17)

## font.cve_2023_26369

- ID: `font.cve_2023_26369`
- Label: CVE-2023-26369: EBSC table out-of-bounds
- Description: TrueType EBSC (Embedded Bitmap Scaling Control) table is too small or contains invalid offsets.
- Tags: font, truetype, cve, vulnerability
- Details:
  - Relevance: known TrueType EBSC table vulnerability.
  - Meaning: malformed EBSC table causes out-of-bounds reads when processing embedded bitmap scaling data.
  - Chain usage: treated as a known vulnerability exploitation attempt.
  - Severity: HIGH
  - CVE: CVE-2023-26369
  - Introduced: Font analysis enhancement (2026-01-17)

## font.anomalous_variation_table

- ID: `font.anomalous_variation_table`
- Label: Anomalous gvar table size
- Description: Variable font gvar (Glyph Variation) table exceeds expected size limits (>10MB).
- Tags: font, variable, resource
- Details:
  - Relevance: variable font parsing stress or exploitation.
  - Meaning: excessively large gvar tables may trigger buffer overflows, memory exhaustion, or parser vulnerabilities.
  - Chain usage: used as a payload delivery or parser stress technique.
  - Severity: MEDIUM
  - Introduced: Font analysis enhancement (2026-01-17)

## fontmatrix_payload_present

- ID: `fontmatrix_payload_present`
- Label: Suspicious FontMatrix payload
- Description: FontMatrix contains non-numeric entries, suggesting script injection.
- Tags: font
- Details:
  - Relevance: font parsing attack surface.
  - Meaning: embedded fonts can trigger vulnerable code paths.
  - Chain usage: treated as a payload stage targeting renderer vulnerabilities.

## gotor_present

- ID: `gotor_present`
- Label: GoToR action present
- Description: Action dictionary with /S /GoToR.
- Tags: action, external
- Details:
  - Relevance: executable action surface.
  - Meaning: viewer can perform external or privileged actions.
  - Chain usage: treated as an action node that can be linked to triggers and payloads.

## header_offset_unusual

- ID: `header_offset_unusual`
- Label: PDF header offset unusual
- Description: Detected pdf header offset unusual.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## huge_image_dimensions

- ID: `huge_image_dimensions`
- Label: Huge image dimensions
- Description: Detected huge image dimensions.
- Tags: decoder, resource
- Details:
  - Relevance: parser/decoder risk.
  - Meaning: content can trigger heavy decoding or edge-case behavior.
  - Chain usage: used as a payload delivery or exploitation path indicator.

## icc_profile_anomaly

- ID: `icc_profile_anomaly`
- Label: ICC profile header anomaly
- Description: Detected icc profile header anomaly.
- Tags: color
- Details:
  - Relevance: color profile parsing risk.
  - Meaning: malformed or oversized ICC profiles can stress parsers.
  - Chain usage: used as a payload signal for renderer exploitation.

## icc_profile_oversized

- ID: `icc_profile_oversized`
- Label: Oversized ICC profile
- Description: ICC profile stream exceeds expected size bounds.
- Tags: color
- Details:
  - Relevance: color profile parsing risk.
  - Meaning: malformed or oversized ICC profiles can stress parsers.
  - Chain usage: used as a payload signal for renderer exploitation.

## image.ccitt_malformed

- ID: `image.ccitt_malformed`
- Label: CCITT decode failed
- Description: CCITT image data failed to decode.
- Tags: image, decoder
- Details:
  - Relevance: decoder attack surface.
  - Meaning: CCITT payload may be malformed or exploit-like.
  - Chain usage: used as a payload signal for image decoder risk.

## image.ccitt_present

- ID: `image.ccitt_present`
- Label: CCITT image present
- Description: CCITT-compressed image data detected.
- Tags: image, decoder
- Details:
  - Relevance: decoder attack surface.
  - Meaning: CCITT images increase decoding complexity.
  - Chain usage: used as supporting context for payload delivery.

## image.decode_failed

- ID: `image.decode_failed`
- Label: Image decode failed
- Description: Image stream failed to decode.
- Tags: image, decoder
- Details:
  - Relevance: decoder attack surface.
  - Meaning: malformed or unsupported image data.
  - Chain usage: used as a payload indicator for decoder anomalies.

## image.decode_skipped

- ID: `image.decode_skipped`
- Label: Image decode skipped
- Description: Image decode was skipped due to policy or format limits.
- Tags: image, decoder
- Details:
  - Relevance: analysis coverage.
  - Meaning: decoding was intentionally skipped.
  - Chain usage: used to explain missing decoder evidence.

## image.decode_too_large

- ID: `image.decode_too_large`
- Label: Image decode skipped due to size
- Description: Image exceeded configured decode limits.
- Tags: image, resource
- Details:
  - Relevance: resource constraints.
  - Meaning: decoding was skipped to protect runtime limits.
  - Chain usage: used to explain skipped payload analysis.

## image.extreme_dimensions

- ID: `image.extreme_dimensions`
- Label: Image dimensions exceed limits
- Description: Image dimensions exceed configured thresholds.
- Tags: image, resource
- Details:
  - Relevance: resource abuse or exploit shaping.
  - Meaning: oversized images can stress decoders.
  - Chain usage: used as a payload signal for decoder abuse.

## image.jbig2_malformed

- ID: `image.jbig2_malformed`
- Label: JBIG2 decode failed
- Description: JBIG2 image data failed to decode.
- Tags: image, decoder
- Details:
  - Relevance: decoder attack surface.
  - Meaning: JBIG2 payload may be malformed or exploit-like.
  - Chain usage: used as a payload signal for high-risk decoder issues.

## image.jbig2_present

- ID: `image.jbig2_present`
- Label: JBIG2 image present
- Description: JBIG2-compressed image data detected.
- Tags: image, decoder
- Details:
  - Relevance: decoder attack surface.
  - Meaning: JBIG2 images increase decoding risk.
  - Chain usage: used as supporting context for payload delivery.

## image.jpeg_malformed

- ID: `image.jpeg_malformed`
- Label: JPEG decode failed
- Description: JPEG image data failed to decode.
- Tags: image, decoder
- Details:
  - Relevance: decoder attack surface.
  - Meaning: JPEG payload may be malformed or exploit-like.
  - Chain usage: used as a payload signal for decoder anomalies.

## image.jpx_malformed

- ID: `image.jpx_malformed`
- Label: JPEG2000 decode failed
- Description: JPEG2000 image data failed to decode.
- Tags: image, decoder
- Details:
  - Relevance: decoder attack surface.
  - Meaning: JPX payload may be malformed or exploit-like.
  - Chain usage: used as a payload signal for high-risk decoder issues.

## image.jpx_present

- ID: `image.jpx_present`
- Label: JPEG2000 image present
- Description: JPEG2000-compressed image data detected.
- Tags: image, decoder
- Details:
  - Relevance: decoder attack surface.
  - Meaning: JPX images increase decoding risk.
  - Chain usage: used as supporting context for payload delivery.

## image.multiple_filters

- ID: `image.multiple_filters`
- Label: Image uses multiple filters
- Description: Image stream uses a filter chain.
- Tags: image, evasion
- Details:
  - Relevance: decoder complexity.
  - Meaning: filter chains can obscure payloads.
  - Chain usage: used as a payload obfuscation signal.

## image.pixel_count_excessive

- ID: `image.pixel_count_excessive`
- Label: Image pixel count exceeds limits
- Description: Image pixel count exceeds configured thresholds.
- Tags: image, resource
- Details:
  - Relevance: resource abuse or exploit shaping.
  - Meaning: excessive pixels can stress decoders.
  - Chain usage: used as a payload signal for decoder abuse.

## image.suspect_strip_dimensions

- ID: `image.suspect_strip_dimensions`
- Label: Image has suspect strip dimensions
- Description: Image uses thin strip dimensions that may hide payloads.
- Tags: image, evasion
- Details:
  - Relevance: steganography or payload concealment.
  - Meaning: extreme aspect ratios can hide data.
  - Chain usage: used as a payload obfuscation signal.

## image.zero_click_jbig2

- ID: `image.zero_click_jbig2`
- Label: Zero-click JBIG2 payload
- Description: JBIG2 stream uses narrow-strip dimensions resembling FORCEDENTRY-style payloads.
- Tags: image, decoder, exploit
- Details:
  - Relevance: zero-click decoder attack surface (CVE-2021-30860).
  - Meaning: JBIG2 payload encodes data in 1×N strips to drive virtual CPU logic.
  - Chain usage: used as a high-confidence zero-click exploit vector; meta includes `cve=CVE-2021-30860` and `attack_surface=Image codecs / zero-click JBIG2`.
  - Fixture: `crates/sis-pdf-core/tests/fixtures/images/cve-2021-30860-jbig2.pdf`.

## image.xfa_decode_failed

- ID: `image.xfa_decode_failed`
- Label: XFA image decode failed
- Description: Image embedded in XFA content failed to decode.
- Tags: image, forms
- Details:
  - Relevance: form rendering risk.
  - Meaning: malformed XFA image content.
  - Chain usage: used as a payload signal for XFA processing.

## image.xfa_image_present

- ID: `image.xfa_image_present`
- Label: XFA image present
- Description: Image embedded in XFA form data.
- Tags: image, forms
- Details:
  - Relevance: form rendering risk.
  - Meaning: XFA images expand rendering attack surface.
  - Chain usage: used as supporting context for XFA payloads.

## incremental_update_chain

- ID: `incremental_update_chain`
- Label: Incremental update chain present
- Description: Detected incremental update chain present.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## js_custom_decoder

- ID: `js_custom_decoder`
- Label: Custom decoder implementation
- Description: JavaScript implements custom decoding routines (Base64, character codes, hex).
- Tags: evasion, javascript
- Details:
  - Relevance: evasion via custom encoding.
  - Meaning: custom decoders hide malicious payloads from static analysis.
  - Chain usage: used as an obfuscation/evasion stage before payload execution.

## js_env_probe

- ID: `js_env_probe`
- Label: Environment probe in JavaScript
- Description: JavaScript queries viewer or environment properties.
- Tags: evasion, javascript
- Details:
  - Relevance: scriptable execution.
  - Meaning: JavaScript executes in the viewer context and may be obfuscated or evasive.
  - Chain usage: used as the action/payload stage and to model evasive or staged execution.

## js_excessive_string_allocation

- ID: `js_excessive_string_allocation`
- Label: Excessive string allocation
- Description: JavaScript performs large-scale string allocation or concatenation.
- Tags: javascript, resource
- Details:
  - Relevance: resource exhaustion or heap spray precursor.
  - Meaning: large string operations can cause DoS or prepare heap spray attacks.
  - Chain usage: used as a payload delivery or exploitation preparation stage.

## js_function_introspection

- ID: `js_function_introspection`
- Label: Function source introspection
- Description: JavaScript uses arguments.callee or Function.toString() for self-inspection.
- Tags: evasion, javascript
- Details:
  - Relevance: polymorphic or self-modifying code.
  - Meaning: code inspects its own source to build dynamic payloads.
  - Chain usage: used as an obfuscation/evasion technique in payload stages.

## js_heap_spray

- ID: `js_heap_spray`
- Label: Heap spray pattern detected
- Description: JavaScript exhibits heap spray characteristics (large string padding, repeated allocations).
- Tags: exploit, javascript
- Details:
  - Relevance: memory corruption exploitation.
  - Meaning: heap spray prepares memory for vulnerability exploitation.
  - Chain usage: used as the exploitation stage targeting renderer memory corruption.

## js_multi_stage_decode

- ID: `js_multi_stage_decode`
- Label: Multi-stage JavaScript decoding
- Description: JavaScript contains multiple decoding layers.
- Tags: evasion, javascript
- Details:
  - Relevance: scriptable execution.
  - Meaning: JavaScript executes in the viewer context and may be obfuscated or evasive.
  - Chain usage: used as the action/payload stage and to model evasive or staged execution.

## js_obfuscation_deep

- ID: `js_obfuscation_deep`
- Label: Deep JavaScript deobfuscation
- Description: Deobfuscation produced a simplified payload variant.
- Tags: evasion, javascript
- Details:
  - Relevance: scriptable execution.
  - Meaning: JavaScript executes in the viewer context and may be obfuscated or evasive.
  - Chain usage: used as the action/payload stage and to model evasive or staged execution.

## js_polymorphic

- ID: `js_polymorphic`
- Label: Polymorphic JavaScript patterns
- Description: JavaScript shows traits of polymorphic or staged code.
- Tags: evasion, javascript
- Details:
  - Relevance: scriptable execution.
  - Meaning: JavaScript executes in the viewer context and may be obfuscated or evasive.
  - Chain usage: used as the action/payload stage and to model evasive or staged execution.

## js_present

- ID: `js_present`
- Label: JavaScript present
- Description: Inline or referenced JavaScript detected.
- Tags: javascript
- Details:
  - Relevance: scriptable execution.
  - Meaning: JavaScript executes in the viewer context and may be obfuscated or evasive.
  - Chain usage: used as the action/payload stage and to model evasive or staged execution.

## js_runtime_file_probe

- ID: `js_runtime_file_probe`
- Label: Runtime file or object probe
- Description: JavaScript invoked file or object-related APIs during sandboxed execution.
- Tags: filesystem, javascript, runtime
- Details:
  - Relevance: scriptable execution.
  - Meaning: JavaScript executes in the viewer context and may be obfuscated or evasive.
  - Chain usage: used as the action/payload stage and to model evasive or staged execution.

## js_runtime_network_intent

- ID: `js_runtime_network_intent`
- Label: Runtime network intent
- Description: JavaScript invoked network-capable APIs during sandboxed execution.
- Tags: javascript, network, runtime
- Details:
  - Relevance: scriptable execution.
  - Meaning: JavaScript executes in the viewer context and may be obfuscated or evasive.
  - Chain usage: used as the action/payload stage and to model evasive or staged execution.

## js_time_evasion

- ID: `js_time_evasion`
- Label: Time-based evasion in JavaScript
- Description: JavaScript references timing APIs that can delay execution.
- Tags: evasion, javascript
- Details:
  - Relevance: scriptable execution.
  - Meaning: JavaScript executes in the viewer context and may be obfuscated or evasive.
  - Chain usage: used as the action/payload stage and to model evasive or staged execution.

## js_whitespace_evasion

- ID: `js_whitespace_evasion`
- Label: Whitespace-based obfuscation
- Description: JavaScript uses excessive whitespace padding to evade pattern matching.
- Tags: evasion, javascript
- Details:
  - Relevance: static analysis evasion.
  - Meaning: code spread across many lines with whitespace to avoid detection.
  - Chain usage: used as an obfuscation technique to hide malicious patterns.

## js_annotation_abuse

- ID: `js_annotation_abuse`
- Label: PDF annotation manipulation
- Description: JavaScript manipulates PDF annotations for exploitation or data hiding.
- Tags: exploit, javascript, pdf
- Details:
  - Relevance: PDF-specific exploitation.
  - Meaning: annotation objects can hide payloads or be exploited for code execution.
  - Chain usage: used as a payload delivery or hiding mechanism in PDF exploits.

## js_array_manipulation_exploit

- ID: `js_array_manipulation_exploit`
- Label: Suspicious array manipulation
- Description: JavaScript exhibits high density of array operations suggesting exploitation.
- Tags: exploit, javascript
- Details:
  - Relevance: memory corruption precursor.
  - Meaning: excessive array operations can indicate type confusion or memory manipulation attempts.
  - Chain usage: used as a setup stage for memory corruption exploits.

## js_beaconing_pattern

- ID: `js_beaconing_pattern`
- Label: Network beaconing detected
- Description: JavaScript shows patterns of regular network communication (beaconing).
- Tags: c2, javascript, network
- Details:
  - Relevance: command and control communication.
  - Meaning: multiple network operations suggest C2 beaconing or data exfiltration.
  - Chain usage: used as a C2 communication or data exfiltration stage.

## js_c2_beaconing

- ID: `js_c2_beaconing`
- Label: C2 beaconing pattern
- Description: JavaScript exhibits command and control beaconing behavior.
- Tags: c2, javascript, network
- Details:
  - Relevance: command and control.
  - Meaning: regular network requests suggest C2 communication.
  - Chain usage: used as ongoing C2 communication stage.

## js_control_flow_flattening

- ID: `js_control_flow_flattening`
- Label: Control flow flattening obfuscation
- Description: JavaScript uses control flow flattening with dispatcher patterns.
- Tags: evasion, javascript
- Details:
  - Relevance: advanced obfuscation.
  - Meaning: large switch statements or dispatchers hide actual program flow.
  - Chain usage: used as an obfuscation technique to evade analysis.

## js_credential_harvesting

- ID: `js_credential_harvesting`
- Label: Credential harvesting attempt
- Description: JavaScript attempts to collect user credentials or sensitive input.
- Tags: exfiltration, javascript
- Details:
  - Relevance: data theft.
  - Meaning: password fields or input listeners suggest credential collection.
  - Chain usage: used as a data collection stage before exfiltration.

## js_cryptomining_library

- ID: `js_cryptomining_library`
- Label: Cryptomining library detected
- Description: JavaScript references known cryptomining libraries or signatures.
- Tags: cryptomining, javascript
- Details:
  - Relevance: resource abuse.
  - Meaning: presence of mining libraries indicates cryptojacking attempt.
  - Chain usage: used as a payload stage for cryptocurrency mining.

## js_debugger_detection

- ID: `js_debugger_detection`
- Label: Debugger detection techniques
- Description: JavaScript attempts to detect debugging or analysis tools.
- Tags: evasion, javascript
- Details:
  - Relevance: anti-analysis.
  - Meaning: debugger checks allow malware to evade analysis.
  - Chain usage: used as an evasion layer before malicious payload execution.

## js_dga_pattern

- ID: `js_dga_pattern`
- Label: Domain generation algorithm
- Description: JavaScript uses algorithmic domain generation (DGA).
- Tags: c2, evasion, javascript
- Details:
  - Relevance: command and control evasion.
  - Meaning: algorithmically generated domains evade blocklists.
  - Chain usage: used to establish resilient C2 communication channels.

## js_encoded_transmission

- ID: `js_encoded_transmission`
- Label: Encoded data transmission
- Description: JavaScript encodes data before network transmission.
- Tags: exfiltration, javascript
- Details:
  - Relevance: data exfiltration.
  - Meaning: encoding before transmission hides exfiltrated data.
  - Chain usage: used as an exfiltration technique to evade detection.

## js_exception_abuse

- ID: `js_exception_abuse`
- Label: Exception handling abuse
- Description: JavaScript uses excessive exception handling for control flow.
- Tags: evasion, javascript
- Details:
  - Relevance: control flow obfuscation.
  - Meaning: try-catch blocks used for obfuscation rather than error handling.
  - Chain usage: used as an obfuscation technique.

## js_exploit_chain_multi_stage

- ID: `js_exploit_chain_multi_stage`
- Label: Multi-stage exploit chain
- Description: JavaScript exhibits multiple stages of exploitation (probe, exploit, payload).
- Tags: chain, exploit, javascript
- Details:
  - Relevance: coordinated exploitation.
  - Meaning: multiple exploit stages suggest sophisticated attack.
  - Chain usage: represents complete attack chain from reconnaissance to payload.

## js_font_exploitation

- ID: `js_font_exploitation`
- Label: Font parser exploitation
- Description: JavaScript manipulates font structures for exploitation.
- Tags: exploit, javascript, pdf
- Details:
  - Relevance: PDF font parser exploitation.
  - Meaning: font manipulation can trigger renderer vulnerabilities.
  - Chain usage: used as an exploitation technique targeting font parsers.

## js_form_manipulation

- ID: `js_form_manipulation`
- Label: Dynamic form manipulation
- Description: JavaScript dynamically creates or manipulates forms.
- Tags: exfiltration, javascript, phishing
- Details:
  - Relevance: data collection.
  - Meaning: dynamic forms can collect data for exfiltration.
  - Chain usage: used as a data collection mechanism.

## js_geofencing

- ID: `js_geofencing`
- Label: Geographic targeting
- Description: JavaScript checks locale or language for conditional execution.
- Tags: evasion, javascript
- Details:
  - Relevance: targeted attacks.
  - Meaning: region-based execution limits malware exposure.
  - Chain usage: used as a targeting filter before payload delivery.

## js_homoglyph_attack

- ID: `js_homoglyph_attack`
- Label: Homoglyph character substitution
- Description: JavaScript uses look-alike Unicode characters for obfuscation.
- Tags: evasion, javascript
- Details:
  - Relevance: obfuscation via Unicode.
  - Meaning: homoglyphs evade string-based detection.
  - Chain usage: used as an obfuscation layer.

## js_identifier_mangling

- ID: `js_identifier_mangling`
- Label: Extreme identifier obfuscation
- Description: JavaScript uses heavily mangled or obfuscated variable names.
- Tags: evasion, javascript
- Details:
  - Relevance: code obfuscation.
  - Meaning: mangled identifiers hinder analysis.
  - Chain usage: used as an obfuscation technique.

## js_integer_overflow_setup

- ID: `js_integer_overflow_setup`
- Label: Integer overflow exploitation setup
- Description: JavaScript contains patterns suggesting integer overflow exploitation.
- Tags: exploit, javascript
- Details:
  - Relevance: memory corruption.
  - Meaning: large constants with bitwise operations suggest overflow exploits.
  - Chain usage: used as a setup stage for memory corruption.

## js_nop_sled

- ID: `js_nop_sled`
- Label: NOP sled in shellcode
- Description: JavaScript contains NOP sled patterns in character code sequences.
- Tags: exploit, javascript, shellcode
- Details:
  - Relevance: shellcode delivery.
  - Meaning: NOP sleds are classic shellcode patterns for reliable exploitation.
  - Chain usage: used as part of shellcode payload delivery.

## js_opaque_predicates

- ID: `js_opaque_predicates`
- Label: Opaque predicate obfuscation
- Description: JavaScript uses always-true or always-false conditions for obfuscation.
- Tags: evasion, javascript
- Details:
  - Relevance: control flow obfuscation.
  - Meaning: opaque predicates hide actual program logic.
  - Chain usage: used as an obfuscation technique.

## js_rop_chain

- ID: `js_rop_chain`
- Label: ROP chain pattern detected
- Description: JavaScript contains return-oriented programming patterns.
- Tags: exploit, javascript
- Details:
  - Relevance: advanced exploitation.
  - Meaning: ROP chains bypass DEP/NX protections.
  - Chain usage: used as an exploitation technique for code execution.

## js_rtl_override

- ID: `js_rtl_override`
- Label: Right-to-left override character
- Description: JavaScript contains RTL override Unicode character for obfuscation.
- Tags: evasion, javascript
- Details:
  - Relevance: visual obfuscation.
  - Meaning: RTL override can hide malicious code in source view.
  - Chain usage: used as an obfuscation technique.

## js_sandbox_evasion

- ID: `js_sandbox_evasion`
- Label: Sandbox environment detection
- Description: JavaScript attempts to detect sandbox or analysis environment.
- Tags: evasion, javascript
- Details:
  - Relevance: anti-analysis.
  - Meaning: environment detection allows malware to evade sandboxes.
  - Chain usage: used as an evasion layer before payload execution.

## js_shellcode_pattern

- ID: `js_shellcode_pattern`
- Label: Shellcode patterns detected
- Description: JavaScript contains byte patterns matching shellcode signatures.
- Tags: exploit, javascript, shellcode
- Details:
  - Relevance: code execution payload.
  - Meaning: shellcode patterns indicate exploit payload.
  - Chain usage: used as the exploitation payload stage.

## js_time_bomb

- ID: `js_time_bomb`
- Label: Time-based conditional execution
- Description: JavaScript uses date/time checks for conditional execution.
- Tags: evasion, javascript
- Details:
  - Relevance: delayed or targeted execution.
  - Meaning: time-based execution evades immediate analysis.
  - Chain usage: used as a trigger mechanism for delayed payload.

## js_type_confusion

- ID: `js_type_confusion`
- Label: Type confusion exploitation
- Description: JavaScript exhibits type confusion patterns targeting JavaScript engine.
- Tags: exploit, javascript
- Details:
  - Relevance: memory corruption.
  - Meaning: type confusion can lead to arbitrary code execution.
  - Chain usage: used as a vulnerability exploitation technique.

## js_unicode_obfuscation

- ID: `js_unicode_obfuscation`
- Label: Unicode-based obfuscation
- Description: JavaScript uses non-ASCII characters for obfuscation.
- Tags: evasion, javascript
- Details:
  - Relevance: encoding obfuscation.
  - Meaning: Unicode characters evade ASCII-based analysis.
  - Chain usage: used as an obfuscation layer.

## js_use_after_free

- ID: `js_use_after_free`
- Label: Use-after-free pattern
- Description: JavaScript contains use-after-free exploitation patterns.
- Tags: exploit, javascript
- Details:
  - Relevance: memory corruption.
  - Meaning: use-after-free can lead to arbitrary code execution.
  - Chain usage: used as a vulnerability exploitation technique.

## js_wasm_mining

- ID: `js_wasm_mining`
- Label: WebAssembly-based cryptomining
- Description: JavaScript uses WebAssembly for cryptocurrency mining.
- Tags: cryptomining, javascript
- Details:
  - Relevance: resource abuse.
  - Meaning: WebAssembly provides high-performance mining.
  - Chain usage: used as a cryptomining payload.

## js_xfa_exploitation

- ID: `js_xfa_exploitation`
- Label: XFA form exploitation
- Description: JavaScript manipulates XFA forms for exploitation.
- Tags: exploit, javascript, pdf
- Details:
  - Relevance: PDF XFA exploitation.
  - Meaning: XFA manipulation can trigger parser vulnerabilities.
  - Chain usage: used as an exploitation vector in PDF files.

## js_infinite_loop_risk

- ID: `js_infinite_loop_risk`
- Label: Infinite loop detected
- Description: JavaScript contains patterns indicative of infinite loops.
- Tags: dos, javascript, resource-exhaustion
- Details:
  - Relevance: denial of service attack.
  - Meaning: infinite loops can hang execution or exhaust resources.
  - Chain usage: used to cause DoS during analysis or execution.

## js_memory_bomb

- ID: `js_memory_bomb`
- Label: Memory bomb pattern
- Description: JavaScript contains patterns that allocate excessive memory.
- Tags: dos, javascript, resource-exhaustion
- Details:
  - Relevance: memory exhaustion attack.
  - Meaning: rapid memory allocation can crash analysis tools or systems.
  - Chain usage: used to evade analysis or cause system failure.

## js_computational_bomb

- ID: `js_computational_bomb`
- Label: Computational bomb detected
- Description: JavaScript contains computationally expensive patterns.
- Tags: dos, javascript, resource-exhaustion
- Details:
  - Relevance: CPU exhaustion attack.
  - Meaning: nested loops or complex operations consume excessive CPU.
  - Chain usage: used to slow or crash analysis infrastructure.

## js_recursive_bomb

- ID: `js_recursive_bomb`
- Label: Recursive bomb pattern
- Description: JavaScript contains recursive functions without proper termination.
- Tags: dos, javascript, resource-exhaustion
- Details:
  - Relevance: stack exhaustion attack.
  - Meaning: uncontrolled recursion can cause stack overflow.
  - Chain usage: used as denial of service mechanism.

## js_redos_pattern

- ID: `js_redos_pattern`
- Label: ReDoS pattern detected
- Description: Regular expression with catastrophic backtracking.
- Tags: dos, javascript, regex
- Details:
  - Relevance: regex denial of service.
  - Meaning: nested quantifiers can cause exponential execution time.
  - Chain usage: used to hang regex engines during analysis.

## js_dom_xss_sink

- ID: `js_dom_xss_sink`
- Label: DOM XSS sink detected
- Description: JavaScript uses DOM manipulation sinks that enable XSS.
- Tags: injection, javascript, xss
- Details:
  - Relevance: code injection vector.
  - Meaning: innerHTML and similar sinks allow script injection.
  - Chain usage: used to inject malicious code into DOM.

## js_innerHTML_injection

- ID: `js_innerHTML_injection`
- Label: innerHTML injection detected
- Description: JavaScript sets innerHTML with potentially malicious content.
- Tags: injection, javascript, xss
- Details:
  - Relevance: HTML injection attack.
  - Meaning: innerHTML with script tags enables code execution.
  - Chain usage: primary vector for DOM-based XSS attacks.

## js_prototype_pollution_gadget

- ID: `js_prototype_pollution_gadget`
- Label: Prototype pollution detected
- Description: JavaScript modifies object prototypes maliciously.
- Tags: exploit, javascript, pollution
- Details:
  - Relevance: prototype chain manipulation.
  - Meaning: polluting prototypes enables gadget chain exploitation.
  - Chain usage: used to bypass security checks or trigger exploits.

## js_script_injection

- ID: `js_script_injection`
- Label: Dynamic script injection
- Description: JavaScript dynamically creates and injects script elements.
- Tags: injection, javascript
- Details:
  - Relevance: code injection vector.
  - Meaning: createElement('script') enables loading external code.
  - Chain usage: used to load malicious scripts from remote sources.

## js_eval_sink

- ID: `js_eval_sink`
- Label: Eval sink with user input
- Description: JavaScript uses eval or Function with variables.
- Tags: injection, javascript, eval
- Details:
  - Relevance: arbitrary code execution.
  - Meaning: eval with variables enables code injection.
  - Chain usage: primary method for executing dynamically constructed code.

## js_angler_ek

- ID: `js_angler_ek`
- Label: Angler Exploit Kit detected
- Description: JavaScript matches Angler EK patterns.
- Tags: exploit-kit, javascript, threat
- Details:
  - Relevance: known exploit framework.
  - Meaning: Angler EK is a sophisticated exploit delivery system.
  - Chain usage: identifies known malware campaign infrastructure.

## js_magnitude_ek

- ID: `js_magnitude_ek`
- Label: Magnitude Exploit Kit detected
- Description: JavaScript matches Magnitude EK patterns.
- Tags: exploit-kit, javascript, threat
- Details:
  - Relevance: known exploit framework.
  - Meaning: Magnitude EK uses RC4 encryption for payload delivery.
  - Chain usage: identifies specific exploit kit infrastructure.

## js_rig_ek

- ID: `js_rig_ek`
- Label: RIG Exploit Kit detected
- Description: JavaScript matches RIG EK patterns.
- Tags: exploit-kit, javascript, threat
- Details:
  - Relevance: known exploit framework.
  - Meaning: RIG EK uses multi-stage loading and plugin detection.
  - Chain usage: identifies exploit kit delivery mechanism.

## js_exploit_kit_pattern

- ID: `js_exploit_kit_pattern`
- Label: Generic exploit kit pattern
- Description: JavaScript matches generic exploit kit indicators.
- Tags: exploit-kit, javascript, threat
- Details:
  - Relevance: exploit framework detection.
  - Meaning: generic patterns shared across multiple exploit kits.
  - Chain usage: identifies potential exploit delivery infrastructure.

## js_file_enumeration

- ID: `js_file_enumeration`
- Label: File enumeration detected
- Description: JavaScript enumerates files or directories.
- Tags: ransomware, javascript, reconnaissance
- Details:
  - Relevance: file system reconnaissance.
  - Meaning: enumerating files precedes encryption or exfiltration.
  - Chain usage: initial phase of ransomware or data theft.

## js_bulk_encryption

- ID: `js_bulk_encryption`
- Label: Bulk encryption pattern
- Description: JavaScript encrypts multiple files in a loop.
- Tags: ransomware, javascript, encryption
- Details:
  - Relevance: ransomware behavior.
  - Meaning: bulk encryption indicates ransomware-like activity.
  - Chain usage: execution phase of ransomware attack.

## js_ransom_note

- ID: `js_ransom_note`
- Label: Ransom note keywords
- Description: JavaScript contains ransom-related keywords.
- Tags: ransomware, javascript, extortion
- Details:
  - Relevance: ransomware indicator.
  - Meaning: ransom keywords indicate extortion attempt.
  - Chain usage: final phase where ransom demand is displayed.

## js_bitcoin_address

- ID: `js_bitcoin_address`
- Label: Cryptocurrency address present
- Description: JavaScript contains Bitcoin or cryptocurrency addresses.
- Tags: ransomware, javascript, payment
- Details:
  - Relevance: payment mechanism.
  - Meaning: cryptocurrency addresses indicate ransom payment method.
  - Chain usage: used for receiving ransom payments.

## js_jit_spray

- ID: `js_jit_spray`
- Label: JIT spray detected
- Description: JavaScript contains patterns for JIT compiler spraying.
- Tags: exploit, javascript, shellcode
- Details:
  - Relevance: advanced exploitation technique.
  - Meaning: JIT spray places shellcode in predictable memory.
  - Chain usage: used in browser exploitation and memory corruption attacks.

## js_unicode_shellcode

- ID: `js_unicode_shellcode`
- Label: Unicode-encoded shellcode
- Description: JavaScript contains Unicode escapes that decode to shellcode.
- Tags: exploit, javascript, shellcode, encoding
- Details:
  - Relevance: obfuscated exploitation payload.
  - Meaning: Unicode encoding hides x86/x64 instructions.
  - Chain usage: used to deliver shellcode while evading detection.

## js_constant_spray

- ID: `js_constant_spray`
- Label: Constant spray pattern
- Description: JavaScript contains many large numeric constants.
- Tags: exploit, javascript, spray
- Details:
  - Relevance: heap spray technique.
  - Meaning: numeric constants fill memory with exploit payloads.
  - Chain usage: used in exploitation to control memory layout.

## js_fingerprint_check

- ID: `js_fingerprint_check`
- Label: Environment fingerprinting
- Description: JavaScript fingerprints browser or system environment.
- Tags: evasion, javascript, fingerprinting
- Details:
  - Relevance: targeted execution.
  - Meaning: fingerprinting enables attacks on specific configurations.
  - Chain usage: used to evade sandboxes or target specific victims.

## js_timing_evasion

- ID: `js_timing_evasion`
- Label: Timing-based evasion
- Description: JavaScript uses timing to detect analysis environments.
- Tags: evasion, javascript, anti-analysis
- Details:
  - Relevance: sandbox detection.
  - Meaning: timing checks differentiate real systems from sandboxes.
  - Chain usage: used to evade automated analysis.

## js_interaction_required

- ID: `js_interaction_required`
- Label: User interaction required
- Description: JavaScript requires user interaction to execute payload.
- Tags: evasion, javascript, behavioral
- Details:
  - Relevance: behavioral evasion.
  - Meaning: requiring clicks/movement evades automated analysis.
  - Chain usage: used to bypass sandboxes that don't simulate interaction.

## js_targeted_execution

- ID: `js_targeted_execution`
- Label: Targeted execution detected
- Description: JavaScript executes only for specific targets.
- Tags: evasion, javascript, targeting
- Details:
  - Relevance: victim targeting.
  - Meaning: targeting by timezone/language limits victim pool.
  - Chain usage: used in targeted attacks or APT campaigns.

## js_localStorage_write

- ID: `js_localStorage_write`
- Label: localStorage write detected
- Description: JavaScript writes to browser localStorage.
- Tags: persistence, javascript, storage
- Details:
  - Relevance: persistent storage.
  - Meaning: localStorage enables persistence across sessions.
  - Chain usage: used to maintain infection or track victims.

## js_cookie_manipulation

- ID: `js_cookie_manipulation`
- Label: Cookie manipulation detected
- Description: JavaScript creates or modifies cookies.
- Tags: persistence, javascript, tracking
- Details:
  - Relevance: session persistence.
  - Meaning: cookie manipulation enables tracking or session hijacking.
  - Chain usage: used for persistence or credential theft.

## js_global_pollution

- ID: `js_global_pollution`
- Label: Global namespace pollution
- Description: JavaScript pollutes global namespace.
- Tags: persistence, javascript, pollution
- Details:
  - Relevance: state manipulation.
  - Meaning: global pollution can affect other scripts or bypass checks.
  - Chain usage: used to maintain state or interfere with security checks.

## js_history_manipulation

- ID: `js_history_manipulation`
- Label: History manipulation detected
- Description: JavaScript manipulates browser history.
- Tags: phishing, javascript, navigation
- Details:
  - Relevance: navigation hijacking.
  - Meaning: history manipulation can hide malicious URLs.
  - Chain usage: used in phishing attacks to disguise destination.

## js_dynamic_import

- ID: `js_dynamic_import`
- Label: Dynamic import detected
- Description: JavaScript uses dynamic import or require.
- Tags: supply-chain, javascript, loading
- Details:
  - Relevance: dependency loading.
  - Meaning: dynamic imports can load untrusted code.
  - Chain usage: used in supply chain attacks or code injection.

## js_remote_script_load

- ID: `js_remote_script_load`
- Label: Remote script loading
- Description: JavaScript loads scripts from remote URLs.
- Tags: supply-chain, javascript, remote
- Details:
  - Relevance: external code loading.
  - Meaning: remote script loading introduces supply chain risk.
  - Chain usage: used to load malicious code from attacker infrastructure.

## js_suspicious_package

- ID: `js_suspicious_package`
- Label: Suspicious package reference
- Description: JavaScript references suspicious package names or versions.
- Tags: supply-chain, javascript, typosquatting
- Details:
  - Relevance: dependency confusion.
  - Meaning: unusual versions or private scopes indicate attack.
  - Chain usage: used in supply chain attacks via dependency confusion.

## js_port_scan

- ID: `js_port_scan`
- Label: Port scanning detected
- Description: JavaScript attempts to scan network ports.
- Tags: reconnaissance, javascript, network
- Details:
  - Relevance: network enumeration.
  - Meaning: port scanning identifies vulnerable services.
  - Chain usage: used for reconnaissance before lateral movement.

## js_internal_probe

- ID: `js_internal_probe`
- Label: Internal network probing
- Description: JavaScript probes internal network addresses.
- Tags: reconnaissance, javascript, network
- Details:
  - Relevance: internal reconnaissance.
  - Meaning: probing private IPs indicates lateral movement attempt.
  - Chain usage: used to map internal network topology.

## js_dns_rebinding

- ID: `js_dns_rebinding`
- Label: DNS rebinding attack
- Description: JavaScript pattern suggests DNS rebinding attack.
- Tags: network, javascript, attack
- Details:
  - Relevance: same-origin bypass.
  - Meaning: DNS rebinding circumvents same-origin policy.
  - Chain usage: used to access internal services from external attacker.

## js_comment_payload

- ID: `js_comment_payload`
- Label: Payload in comments
- Description: JavaScript hides executable code in comments.
- Tags: steganography, javascript, obfuscation
- Details:
  - Relevance: covert storage.
  - Meaning: comments can store and extract hidden payloads.
  - Chain usage: used to evade signature-based detection.

## js_zero_width_chars

- ID: `js_zero_width_chars`
- Label: Zero-width characters detected
- Description: JavaScript contains zero-width Unicode characters.
- Tags: steganography, javascript, encoding
- Details:
  - Relevance: hidden data encoding.
  - Meaning: zero-width chars encode data invisibly.
  - Chain usage: used for steganographic communication or obfuscation.

## js_canvas_decode

- ID: `js_canvas_decode`
- Label: Canvas data extraction
- Description: JavaScript extracts data from canvas pixels.
- Tags: steganography, javascript, extraction
- Details:
  - Relevance: image steganography.
  - Meaning: extracting pixel data reveals hidden payloads.
  - Chain usage: used to decode images containing malicious code.

## js_polyglot_pdf

- ID: `js_polyglot_pdf`
- Label: PDF/JavaScript polyglot
- Description: Code valid as both PDF and JavaScript.
- Tags: polyglot, javascript, pdf, evasion
- Details:
  - Relevance: format confusion attack.
  - Meaning: polyglot files bypass format-specific filters.
  - Chain usage: used to evade detection and analysis tools.

## js_polyglot_html

- ID: `js_polyglot_html`
- Label: HTML/JavaScript polyglot
- Description: Code valid as both HTML and JavaScript.
- Tags: polyglot, javascript, html, evasion
- Details:
  - Relevance: multi-format evasion.
  - Meaning: polyglot structure confuses parsers and scanners.
  - Chain usage: used to bypass content filters.

## js_canvas_fingerprint

- ID: `js_canvas_fingerprint`
- Label: Canvas fingerprinting detected
- Description: JavaScript uses canvas for browser fingerprinting.
- Tags: fingerprinting, javascript, privacy
- Details:
  - Relevance: tracking mechanism.
  - Meaning: canvas rendering differences enable unique identification.
  - Chain usage: used for tracking users across sessions.

## js_webgl_fingerprint

- ID: `js_webgl_fingerprint`
- Label: WebGL fingerprinting detected
- Description: JavaScript uses WebGL for device fingerprinting.
- Tags: fingerprinting, javascript, privacy
- Details:
  - Relevance: hardware identification.
  - Meaning: WebGL capabilities create unique device signatures.
  - Chain usage: used for persistent tracking and identification.

## js_font_enumeration

- ID: `js_font_enumeration`
- Label: Font enumeration detected
- Description: JavaScript enumerates installed fonts.
- Tags: fingerprinting, javascript, privacy
- Details:
  - Relevance: system fingerprinting.
  - Meaning: installed fonts reveal system configuration.
  - Chain usage: used as part of comprehensive fingerprinting.

## launch_action_present

- ID: `launch_action_present`
- Label: Launch action present
- Description: Action dictionary with /S /Launch.
- Tags: action, external
- Details:
  - Relevance: executable action surface.
  - Meaning: viewer can perform external or privileged actions.
  - Chain usage: treated as an action node that can be linked to triggers and payloads.

## launch_external_program

- ID: `launch_external_program`
- Label: Launch action targets external program
- Description: Launch action targets an external program or file path.
- Tags: action, external
- Details:
  - Relevance: executable action surface.
  - Meaning: viewer may run external programs or open local files.
  - Chain usage: treated as an action node with elevated execution risk.

## launch_embedded_file

- ID: `launch_embedded_file`
- Label: Launch action targets embedded file
- Description: Launch action targets an embedded file specification.
- Tags: action, external
- Details:
  - Relevance: executable action surface.
  - Meaning: viewer may open or execute embedded payloads.
  - Chain usage: treated as an action node that links to embedded payload delivery.

## linearization_hint_anomaly

- ID: `linearization_hint_anomaly`
- Label: Linearization hint tables present
- Description: Linearization hint tables may hide malformed offsets.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## linearization_invalid

- ID: `linearization_invalid`
- Label: Linearization values inconsistent
- Description: Linearization dictionary fields do not match file layout.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## linearization_multiple

- ID: `linearization_multiple`
- Label: Multiple linearization dictionaries
- Description: Detected multiple linearization dictionaries.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## missing_eof_marker

- ID: `missing_eof_marker`
- Label: Missing EOF marker
- Description: EOF marker not found near end of file.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## missing_pdf_header

- ID: `missing_pdf_header`
- Label: Missing PDF header
- Description: PDF header not found at start of file.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## invalid_pdf_header

- ID: `invalid_pdf_header`
- Label: Invalid PDF header
- Description: File identified as a PDF (extension/path) but the binary lacks a valid `%PDF-` header and is treated as malformed.
- Tags: evasion, structure
- Details:
  - Relevance: high-risk heuristic encountered before detection execution.
  - Meaning: the payload is hiding behind a PDF extension but is actually another format (HTML/JS/VBScript, etc.).
  - Chain usage: reported independently so downstream analyses know the file never reached full parsing; correlates with parser failures and triggers early alerts.

## ml_adversarial_suspected

- ID: `ml_adversarial_suspected`
- Label: Potential adversarial ML sample
- Description: Feature profile suggests adversarial manipulation attempts.
- Tags: classification, ml
- Details:
  - Relevance: ML classification signal.
  - Meaning: model scored the file as malicious or adversarial.
  - Chain usage: used as a confidence booster for suspicious chains rather than a direct action node.

## ml_graph_score_high

- ID: `ml_graph_score_high`
- Label: Graph ML classifier score high
- Description: Detected graph ml classifier score high.
- Tags: classification, ml
- Details:
  - Relevance: ML classification signal.
  - Meaning: model scored the file as malicious or adversarial.
  - Chain usage: used as a confidence booster for suspicious chains rather than a direct action node.

## ml_malware_score_high

- ID: `ml_malware_score_high`
- Label: ML classifier score high
- Description: Detected ml classifier score high.
- Tags: classification, ml
- Details:
  - Relevance: ML classification signal.
  - Meaning: model scored the file as malicious or adversarial.
  - Chain usage: used as a confidence booster for suspicious chains rather than a direct action node.

## ml_model_error

- ID: `ml_model_error`
- Label: ML model load failed
- Description: Detected ml model load failed.
- Tags: classification, ml
- Details:
  - Relevance: ML classification signal.
  - Meaning: model scored the file as malicious or adversarial.
  - Chain usage: used as a confidence booster for suspicious chains rather than a direct action node.

## multi_stage_attack_chain

- ID: `multi_stage_attack_chain`
- Label: Multi-stage attack chain indicators
- Description: Detected JavaScript, embedded content, and outbound action indicators.
- Tags: chain
- Details:
  - Relevance: coordinated behavior.
  - Meaning: multiple stages (script, payload, outbound actions) are present.
  - Chain usage: used as a high-confidence chain-level signal.

## object_count_exceeded

- ID: `object_count_exceeded`
- Label: Object count exceeds budget
- Description: Detected object count exceeds budget.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## object_id_shadowing

- ID: `object_id_shadowing`
- Label: Duplicate object IDs detected
- Description: Detected duplicate object ids detected.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## object_shadow_mismatch

- ID: `object_shadow_mismatch`
- Label: Object shadow mismatch
- Description: Detected object shadow mismatch.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## objstm_action_chain

- ID: `objstm_action_chain`
- Label: Payload in ObjStm
- Description: Detected payload in objstm.
- Tags: chain
- Details:
  - Relevance: payload hidden in object streams.
  - Meaning: action-linked payload is stored in ObjStm.
  - Chain usage: indicates obfuscation of the payload stage.

## objstm_density_high

- ID: `objstm_density_high`
- Label: High object stream density
- Description: Detected high object stream density.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## objstm_embedded_summary

- ID: `objstm_embedded_summary`
- Label: ObjStm embedded object summary
- Description: Detected objstm embedded object summary.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## ocg_present

- ID: `ocg_present`
- Label: Optional content group present
- Description: OCG/OCProperties detected; may influence viewer behaviour.
- Tags: feature
- Details:
  - Relevance: expanded attack surface.
  - Meaning: feature increases parsing or interaction complexity.
  - Chain usage: used as supporting context for delivery or exploitation stages.

## open_action_present

- ID: `open_action_present`
- Label: Document OpenAction present
- Description: OpenAction triggers when the PDF opens.
- Tags: action
- Details:
  - Relevance: automatic execution trigger.
  - Meaning: OpenAction runs on document open.
  - Chain usage: treated as the trigger node that links to actions or payloads.

## orphan_payload_object

- ID: `orphan_payload_object`
- Label: Orphaned payload object
- Description: Detected orphaned payload object.
- Tags: chain
- Details:
  - Relevance: hidden payload staging.
  - Meaning: payload-like object is not reachable from roots.
  - Chain usage: indicates a staged payload that requires alternate access paths.

## page_tree_cycle

- ID: `page_tree_cycle`
- Label: Page tree cycle detected
- Description: Page tree contains a cycle, which can confuse traversal.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## page_tree_mismatch

- ID: `page_tree_mismatch`
- Label: Page tree count mismatch
- Description: Page tree /Count does not match actual leaf pages.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## parser_deviation_cluster

- ID: `parser_deviation_cluster`
- Label: High deviation count
- Description: Detected high deviation count.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## parser_deviation_in_action_context

- ID: `parser_deviation_in_action_context`
- Label: Parser deviations with action context
- Description: Parser deviations present alongside JavaScript or Action objects.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## parser_diff_structural

- ID: `parser_diff_structural`
- Label: Structural parser differential
- Description: Detected structural parser differential.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## parser_object_count_diff

- ID: `parser_object_count_diff`
- Label: Parser object count mismatch
- Description: Detected parser object count mismatch.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## parser_trailer_count_diff

- ID: `parser_trailer_count_diff`
- Label: Parser trailer count mismatch
- Description: Detected parser trailer count mismatch.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## polyglot_signature_conflict

- ID: `polyglot_signature_conflict`
- Label: Polyglot signature conflict
- Severity: High
- Description: Detected polyglot signature conflict.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing; polyglots are almost certainly malicious.
  - Chain usage: used as evasion context that can hide payloads or actions.

## quantum_vulnerable_crypto

- ID: `quantum_vulnerable_crypto`
- Label: Quantum-vulnerable cryptography
- Description: Signature algorithms are vulnerable to post-quantum attacks.
- Tags: crypto
- Details:
  - Relevance: cryptographic structures or misuse.
  - Meaning: signatures/encryption/crypto anomalies change trust or hide content.
  - Chain usage: used as staging or trust-evasion context in chains.

## richmedia_present

- ID: `richmedia_present`
- Label: RichMedia content present
- Description: RichMedia annotations or dictionaries detected.
- Tags: feature
- Details:
  - Relevance: expanded attack surface.
  - Meaning: feature increases parsing or interaction complexity.
  - Chain usage: used as supporting context for delivery or exploitation stages.

## swf_embedded

- ID: `swf_embedded`
- Label: SWF content embedded
- Description: Stream data matches SWF magic header.
- Tags: swf, richmedia
- Details:
  - Relevance: SWF content can contain ActionScript payloads.
  - Meaning: embedded SWF increases execution risk.
  - Chain usage: payload delivery or staging via SWF content.

## secondary_parser_failure

- ID: `secondary_parser_failure`
- Label: Secondary parser failed
- Description: Detected secondary parser failed.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## shadow_payload_chain

- ID: `shadow_payload_chain`
- Label: Shadowed payload object
- Description: Detected shadowed payload object.
- Tags: chain
- Details:
  - Relevance: shadowed content.
  - Meaning: payload-like objects appear in shadowed or alternate revisions.
  - Chain usage: used as a stealth payload indicator in chain synthesis.

## shadow_object_payload_divergence

- ID: `shadow_object_payload_divergence`
- Label: Shadowed object payload divergence
- Description: Shadowed object revisions contain differing payload signatures.
- Tags: evasion, structure
- Details:
  - Relevance: divergent revisions suggest hidden payloads or parser targeting.
  - Meaning: object bodies disagree on detected content type.
  - Chain usage: signals evasive or staged payload tactics.

## parse_disagreement

- ID: `parse_disagreement`
- Label: Parser disagreement detected
- Description: Carved objects disagree with parsed revisions.
- Tags: evasion, structure
- Details:
  - Relevance: parser disagreement can indicate hidden revisions or parsing tricks.
  - Meaning: carved object definitions differ from the primary parser view.
  - Chain usage: highlights stealthy payload delivery.

## signature_present

- ID: `signature_present`
- Label: Digital signature present
- Description: Signature dictionaries or ByteRange entries detected.
- Tags: crypto
- Details:
  - Relevance: cryptographic structures or misuse.
  - Meaning: signatures/encryption/crypto anomalies change trust or hide content.
  - Chain usage: used as staging or trust-evasion context in chains.

## sound_movie_present

- ID: `sound_movie_present`
- Label: Sound or movie content present
- Description: Sound/Movie/Rendition objects detected.
- Tags: feature
- Details:
  - Relevance: expanded attack surface.
  - Meaning: feature increases parsing or interaction complexity.
  - Chain usage: used as supporting context for delivery or exploitation stages.

## stream_length_mismatch

- ID: `stream_length_mismatch`
- Label: Stream length mismatch
- Description: Detected stream length mismatch.
- Tags: decoder, resource
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## label_mismatch_stream_type

- ID: `label_mismatch_stream_type`
- Label: Stream label mismatch
- Description: Stream subtype does not match observed content signature.
- Tags: evasion, stream
- Details:
  - Relevance: explicit structure deception and payload hiding.
  - Meaning: stream bytes contradict declared `/Subtype` or `/Type`.
  - Chain usage: increases evasion posture and payload suspicion.

## declared_filter_invalid

- ID: `declared_filter_invalid`
- Label: Declared filter invalid
- Description: Declared filters failed to decode or do not match stream data.
- Tags: evasion, decoder
- Details:
  - Relevance: filter mismatch indicates obfuscation or corruption.
  - Meaning: declared compression or encoding is inconsistent with bytes.
  - Chain usage: supports evasion or hiding additional payloads.

## undeclared_compression_present

- ID: `undeclared_compression_present`
- Label: Undeclared compression present
- Description: Stream data looks compressed despite no declared filters.
- Tags: evasion, decoder
- Details:
  - Relevance: suggests hidden compression to evade detection.
  - Meaning: stream data appears compressed without `/Filter`.
  - Chain usage: used as evasion context that can hide payloads.

## content_validation_failed

- ID: `content_validation_failed`
- Label: Content validation failed
- Description: Stream signature matched, but lightweight validation failed.
- Tags: decoder, evasion
- Details:
  - Relevance: signature-level matches with invalid structure can indicate malformed payloads or evasive content.
  - Meaning: quick sanity checks failed (for example missing JPEG EOI or ZIP central directory).
  - Chain usage: raises confidence of deceptive or corrupted payloads.

## embedded_payload_carved

- ID: `embedded_payload_carved`
- Label: Embedded payload carved
- Description: Embedded payload signatures detected inside another object; the description varies depending on whether the declared filter matched the detected bytes.
- Tags: evasion, stream
- Details:
  - Relevance: embedded payloads suggest polyglot or hidden content.
  - Meaning: byte sequences indicate a secondary file signature within the object data.
  - Meaning (match): when the declared filter matches the signature (for example, `/DCTDecode` and `carve.kind=jpeg`), the finding is informational and reads “Embedded JPEG signature matches declared filter /DCTDecode.”
  - Meaning (mismatch): when the declared filter does not match, the description reads “Found a {carve.kind} signature in a stream where we expected {carve.expected_kind}.”
  - Chain usage: increases suspicion of hidden payload delivery.
  - Metadata:
    * `carve.kind` – detected signature (jpeg, zip, etc.).
    * `carve.offset` – offset inside the stream where the signature was observed.
    * `carve.filter` – the first filter that carried an expectation (e.g., `/DCTDecode` or `/CCITTFaxDecode`).
    * `carve.expected_kind` – the format implied by the `carve.filter`.
    * `carve.match` – `true` when the detected signature matches the expectation, `false` otherwise.

## nested_container_chain

- ID: `nested_container_chain`
- Label: Nested container chain detected
- Description: ZIP entry contains a nested file signature.
- Tags: evasion, stream
- Details:
  - Relevance: nested containers can hide staged payloads.
  - Meaning: archive entries appear to embed another file type.
  - Chain usage: indicates multi-stage payload delivery.

## vbscript_payload_present

- ID: `vbscript_payload_present`
- Label: VBScript payload present
- Description: VBScript indicators detected in content.
- Tags: script, evasion
- Details:
  - Relevance: VBScript can run in viewer or embedded contexts.
  - Meaning: script content suggests execution or exploitation intent.
  - Chain usage: potential payload execution stage.

## powershell_payload_present

- ID: `powershell_payload_present`
- Label: PowerShell payload present
- Description: PowerShell indicators detected in content.
- Tags: script, evasion
- Details:
  - Relevance: PowerShell payloads often deliver secondary stages.
  - Meaning: script content indicates potential external execution.
  - Chain usage: payload execution or delivery stage.

## bash_payload_present

- ID: `bash_payload_present`
- Label: Shell payload present
- Description: Shell script indicators detected in content.
- Tags: script, evasion
- Details:
  - Relevance: shell scripts can execute arbitrary commands.
  - Meaning: content suggests command execution instructions.
  - Chain usage: payload execution stage.

## cmd_payload_present

- ID: `cmd_payload_present`
- Label: Command payload present
- Description: Command shell indicators detected in content.
- Tags: script, evasion
- Details:
  - Relevance: command shells provide direct execution capability.
  - Meaning: content suggests command invocation instructions.
  - Chain usage: payload execution stage.

## applescript_payload_present

- ID: `applescript_payload_present`
- Label: AppleScript payload present
- Description: AppleScript indicators detected in content.
- Tags: script, evasion
- Details:
  - Relevance: AppleScript can automate applications or execute actions.
  - Meaning: content suggests scripted execution on macOS systems.
  - Chain usage: payload execution stage.

## xfa_script_present

- ID: `xfa_script_present`
- Label: XFA/XML script present
- Description: Script tags detected inside XFA/XML content.
- Tags: script, xfa
- Details:
  - Relevance: scripts inside forms can trigger viewer execution paths.
  - Meaning: embedded XFA/XML scripts increase attack surface.
  - Chain usage: triggers or payload staging within form content.
  - Metadata:
    - `xfa.script.preview` (string): preview of the first script block (trimmed to 120 characters).
    - `xfa.script_count` (int): total script blocks observed in the payload.
    - `xfa.size_bytes` (int): total XFA payload size measured in bytes.

## xfa_submit

- ID: `xfa_submit`
- Label: XFA submit action present
- Description: XFA form contains a submit action with target URL.
- Tags: xfa, external
- Details:
  - Relevance: XFA can submit data to external endpoints.
  - Meaning: submission targets may exfiltrate form data.
  - Chain usage: external action stage for form data.
  - Metadata:
    - `xfa.submit.url` (string): one of the submit targets discovered in the form.
    - `xfa.submit_urls` (array of strings): aggregated submit URLs captured during parsing.
    - `xfa.script_count` (int): scripts evaluated when the submit action was found.
    - `xfa.size_bytes` (int): XFA payload byte size.

## xfa_sensitive_field

- ID: `xfa_sensitive_field`
- Label: XFA sensitive field present
- Description: XFA form contains a sensitive field name.
- Tags: xfa
- Details:
  - Relevance: sensitive fields increase data exposure risk.
  - Meaning: field names suggest collection of credentials or personal data.
  - Chain usage: indicates data collection intent.
  - Metadata:
    - `xfa.field.name` (string): sensitive field that matched one of the heuristics.
    - `xfa.sensitive_fields` (array of strings): all sensitive field names detected in the XFA payload.
    - `xfa.size_bytes` (int): total XFA payload byte size.

## xfa_too_large

- ID: `xfa_too_large`
- Label: XFA content too large
- Description: XFA content exceeds size limits.
- Tags: xfa, evasion
- Details:
  - Relevance: oversized forms can hide payloads or trigger resource exhaustion.
  - Meaning: XFA content size is unusually large.
  - Chain usage: evasion context for hidden payload staging.
  - Metadata:
    - `xfa.size_bytes` (int): total byte size measured on the XFA stream.
    - `xfa.size_limit_bytes` (int): configured limit (1,048,576 by default).

## xfa_script_count_high

- ID: `xfa_script_count_high`
- Label: XFA script count high
- Description: XFA contains an unusually high number of script blocks.
- Tags: xfa, script
- Details:
  - Relevance: multiple scripts can indicate staged behaviour.
  - Meaning: excessive script count raises suspicion of hidden logic.
  - Chain usage: payload staging signal.
  - Metadata:
    - `xfa.script_count` (int): number of `<script>` or `<execute>` nodes detected.
    - `xfa.script_preview` (string): bounded preview of a representative script or execute block.
    - `xfa.size_bytes` (int): total XFA payload byte size.

## actionscript_present

- ID: `actionscript_present`
- Label: ActionScript present
- Description: SWF tags indicate embedded ActionScript bytecode.
- Tags: script, swf
- Details:
  - Relevance: ActionScript executes in the SWF runtime context.
  - Meaning: bytecode indicates executable content embedded in the PDF.
  - Chain usage: payload execution or staging via SWF content.

## swf_url_iocs

- ID: `swf_url_iocs`
- Label: SWF URL indicators
- Description: Embedded URLs detected in SWF tag payloads.
- Tags: swf, external
- Details:
  - Relevance: SWF URLs can direct viewers to external resources.
  - Meaning: embedded URLs suggest external communication or payload fetching.
  - Chain usage: delivery or command and control stage.

## strict_parse_deviation

- ID: `strict_parse_deviation`
- Label: Strict Parse Deviation
- Description: Detected strict parse deviation.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## submitform_present

- ID: `submitform_present`
- Label: SubmitForm action present
- Description: Action dictionary with /S /SubmitForm.
- Tags: action, external
- Details:
  - Relevance: executable action surface.
  - Meaning: viewer can perform external or privileged actions.
  - Chain usage: treated as an action node that can be linked to triggers and payloads.

## supply_chain_persistence

- ID: `supply_chain_persistence`
- Label: Persistence-related JavaScript
- Description: JavaScript references persistence-like viewer hooks.
- Tags: general
- Details:
  - Relevance: supply-chain style behavior.
  - Meaning: indicators suggest staged download/update/persistence logic.
  - Chain usage: used as multi-step delivery or persistence stages.

## supply_chain_staged_payload

- ID: `supply_chain_staged_payload`
- Label: Staged payload delivery
- Description: JavaScript indicates download or staged payload execution.
- Tags: general
- Details:
  - Relevance: supply-chain style behavior.
  - Meaning: indicators suggest staged download/update/persistence logic.
  - Chain usage: used as multi-step delivery or persistence stages.

## supply_chain_update_vector

- ID: `supply_chain_update_vector`
- Label: Update mechanism references
- Description: JavaScript references update or installer logic.
- Tags: general
- Details:
  - Relevance: supply-chain style behavior.
  - Meaning: indicators suggest staged download/update/persistence logic.
  - Chain usage: used as multi-step delivery or persistence stages.

## uri_present

- ID: `uri_present`
- Label: URI present
- Severity: Info
- Description: External URI action detected.
- Tags: action, external
- Details:
  - Relevance: executable action surface.
  - Meaning: viewer can perform external or privileged actions.
  - Chain usage: treated as an action node that can be linked to triggers and payloads.

## uri_listing

- ID: `uri_listing`
- Label: URI(s) present
- Severity: Info → Low → Medium → High (volume/domains thresholds)
- Description: Aggregated URI listing; records every discovered URI plus contextual flags for the first 20 entries while still escalating severity when URI volume/diversity grows.
- Tags: action, external, summary
- Details:
  - Relevance: documents with many URIs increase attack surface, but per-URI noise is captured centrally.
  - Meaning: the finding collects `uri.count_*`, `uri.schemes`, and `uri.domains_sample` plus `uri.list.*` metadata (preview/canonical/chain_depth/visibility/trigger/suspicious) so downstream consumers can inspect every URI without flooding the report. `uri.suspicious_count` highlights how many URIs matched the `UriContentDetector` heuristics.
  - Chain usage: acts as a summary node that can be joined with other findings (e.g., suspicious URIs, action chains) and remains low-noise even when hundreds of links are present.

## xfa_present

- ID: `xfa_present`
- Label: XFA form present
- Description: XFA forms can expand attack surface.
- Tags: feature
- Details:
  - Relevance: expanded attack surface.
  - Meaning: feature increases parsing or interaction complexity.
  - Chain usage: used as supporting context for delivery or exploitation stages.

## xref_conflict

- ID: `xref_conflict`
- Label: Multiple startxref entries
- Description: Detected multiple startxref entries.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.

## launch_obfuscated_executable

- ID: `launch_obfuscated_executable`
- Label: Correlated obfuscated executable launch
- Description: Launch action targets an embedded executable with high entropy.
- Tags: action, embedded, correlation
- Details:
  - Relevance: automatic execution tied to obfuscated payloads is high risk.
  - Meaning: correlation of launch and embedded executable strengthens confidence.
  - Chain usage: delivery/execution stage.

## action_chain_malicious

- ID: `action_chain_malicious`
- Label: Malicious automatic action chain
- Description: Complex action chain triggers automatically and executes JavaScript.
- Tags: action, chain, correlation
- Details:
  - Relevance: automatic chains are a hallmark of malware.
  - Meaning: combined evidence of chain depth, trigger, and JS increases signal.
  - Chain usage: multi-stage activation without user interaction.

## xfa_data_exfiltration_risk

- ID: `xfa_data_exfiltration_risk`
- Label: XFA data exfiltration risk
- Description: XFA form submits sensitive fields to an external endpoint.
- Tags: xfa, data, correlation
- Details:
  - Relevance: sensitive fields plus external submits indicate theft.
  - Meaning: correlation of submit URLs with sensitive fields raises confidence.
  - Chain usage: data exfiltration stage.

## encrypted_payload_delivery

- ID: `encrypted_payload_delivery`
- Label: Encrypted payload delivery
- Description: Encrypted archive delivery is coupled with launch or SWF actions.
- Tags: embedded, crypto, correlation
- Details:
  - Relevance: encrypted containers hide payloads while launch/SWF triggers delivery.
  - Meaning: correlation shows encrypted payload ready for execution.
  - Chain usage: obfuscated delivery stage.

## obfuscated_payload

- ID: `obfuscated_payload`
- Label: Obfuscated payload
- Description: High entropy stream coincides with unusual filter chain.
- Tags: filters, entropy, correlation
- Details:
  - Relevance: unusual filter order with high entropy indicates obfuscation.
  - Meaning: combined signal is more reliable than individual findings.
  - Chain usage: obfuscation context within delivery or staging phases.
