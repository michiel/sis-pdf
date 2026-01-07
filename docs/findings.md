# Findings Reference

This document describes every finding ID that `sis-pdf` can emit. Each entry includes a label, a short description, tags for quick grouping, and details on relevance, meaning, and exploit-chain usage.

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

## encryption_present

- ID: `encryption_present`
- Label: Encryption dictionary present
- Description: Trailer indicates encrypted content via /Encrypt.
- Tags: crypto
- Details:
  - Relevance: cryptographic structures or misuse.
  - Meaning: signatures/encryption/crypto anomalies change trust or hide content.
  - Chain usage: used as staging or trust-evasion context in chains.

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

## launch_action_present

- ID: `launch_action_present`
- Label: Launch action present
- Description: Action dictionary with /S /Launch.
- Tags: action, external
- Details:
  - Relevance: executable action surface.
  - Meaning: viewer can perform external or privileged actions.
  - Chain usage: treated as an action node that can be linked to triggers and payloads.

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
- Description: Detected polyglot signature conflict.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
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
- Description: External URI action detected.
- Tags: action, external
- Details:
  - Relevance: executable action surface.
  - Meaning: viewer can perform external or privileged actions.
  - Chain usage: treated as an action node that can be linked to triggers and payloads.

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
