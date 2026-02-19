# Findings Reference

This document describes every finding ID that `sis-pdf` can emit. Each entry includes a label, a short description, tags for quick grouping, and details on relevance, meaning, and exploit-chain usage.

## Chain Query Output

`sis query <file.pdf> findings --with-chain --format json` returns a chain-augmented findings payload.

Schema:
- `type`: `findings_with_chain`
- `count`: number of findings in `findings`
- `chain_count`: number of correlated chains in `chains`
- `findings`: standard findings array (same shape as `sis query ... findings`)
- `chains`: correlated chain array. Each chain includes:
  - `id`, `group_id`, `group_count`, `group_members`
  - `path`, `score`, `reasons`
  - `ordered_stages`: ordered chain stages (for example `decode`, `render`, `execute`, `egress`)
  - `stage_nodes`: per-stage object reference map used to explain stage transitions
  - `shared_object_refs`: deduplicated object references used by contributing findings
  - `contributing_findings`: finding summaries (`id`, `kind`, `severity`, `confidence`, `objects`, chain hints)
  - `edge`: edge metadata (`reason`, `confidence`, `from`, `to`, `shared_objects`)
  - `exploit`: exploit context (`preconditions`, `blockers`, `outcomes`)
  - `scatter` (optional): scatter-chain context:
    - `fragment_count`
    - `object_refs`
  - `notes`: raw synthesised chain notes

Text output summary for `--with-chain` includes:
- Findings count
- Chain count
- Up to eight concise potential-chain lines:
  - `Potential chain: decode -> render -> egress [scatter_to_injection] (id=chain-...)`

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
  - Relevance: viewer-dependent 3D runtimes add execution-adjacent attack surface.
  - Meaning: 3D object structures (`/3D`, `/U3D`, `/PRC`) are present.
  - Chain usage: render-stage contextual signal; keep severity conservative unless corroborated by execute findings.
  - Metadata:
    - `viewer.feature=3d`
    - `viewer.support_required=true`
    - `viewer.support_matrix=viewer_dependent_3d_runtime`
    - `renderer.profile=3d_viewer`
    - `renderer.precondition=3d_runtime_enabled`
    - `chain.stage=render`, `chain.capability=3d_surface`, `chain.trigger=viewer_feature`

## aa_event_present

- ID: `aa_event_present`
- Label: AA event action present
- Description: Detected aa event action present.
- Tags: action
- Details:
  - Relevance: specific event-driven execution.
  - Meaning: an AA event entry is present.
  - Chain usage: signals a trigger edge into action/payload nodes.
  - Metadata:
    - `action.trigger_context=aa`
    - `action.trigger_event`, `action.trigger_event_normalised`
    - `action.trigger_type` (`automatic` for `/O`, `/C`, `/PV`, `/PI`, `/V`, `/PO`; otherwise `user`)
    - `chain.stage=execute`, `chain.capability=action_trigger_chain`, `chain.trigger=additional_action`

## aa_present

- ID: `aa_present`
- Label: Additional Actions present
- Description: Additional Actions can execute on user events.
- Tags: action
- Details:
  - Relevance: event-driven execution.
  - Meaning: Additional Actions can fire on viewer events.
  - Chain usage: used as a trigger for action/payload chains.
  - Metadata:
    - `action.trigger_context=aa`
    - `action.trigger_event_normalised=/AA`
    - `chain.stage=execute`, `chain.capability=action_trigger_chain`, `chain.trigger=additional_action`

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
  - Metadata:
    - `action.trigger_context`: normalised trigger surface (`open_action`, `aa`, `annotation_action`, `field_action`, `field_aa`)
    - `action.trigger_event_normalised`: normalised trigger key (`/OpenAction`, `/O`, `/K`, etc.)
    - `action.next.depth`, `action.next.branch_count`, `action.next.max_fanout`
    - optional `action.next.has_cycle=true` when `/Next` traversal detects a cycle
    - `chain.stage=execute`, `chain.capability=action_trigger_chain`

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
  - Metadata:
    - `action.trigger_context`: normalised trigger surface
    - `action.trigger_event_normalised`: normalised trigger key
    - `action.trigger_type`: initiation class (`automatic`, `user`, `hidden`)
    - `/Next` telemetry keys when present:
      - `action.next.depth`
      - `action.next.branch_count`
      - `action.next.max_fanout`
      - optional `action.next.has_cycle=true`
    - `chain.stage=execute`, `chain.capability=action_trigger_chain`, `chain.trigger` normalised by trigger context

## acroform_field_action

- ID: `acroform_field_action`
- Label: AcroForm field JavaScript action
- Description: Per-field `/AA` event (`/K`, `/F`, `/V`, `/C`) executes JavaScript in a widget field context.
- Tags: action, forms, javascript
- Details:
  - Relevance: field-level handlers trigger during typing, formatting, validation, or calculation and are often overlooked compared with document-level actions.
  - Meaning: interaction or calculation events on form widgets carry JavaScript action dictionaries.
  - Chain usage: execute-stage signal for form-driven exploit or credential-capture paths.
  - Metadata:
    - `action.field_name`
    - `action.field_event`
    - `action.field_event_class` (`keystroke`, `format`, `validate`, `calculate`)
    - `chain.stage=execute`, `chain.capability=acroform_field_action`, `chain.trigger=acroform_field_aa`

## annotation_action_chain

- ID: `annotation_action_chain`
- Label: Annotation action chain
- Description: Annotation contains /A or /AA action entries.
- Tags: feature
- Details:
  - Relevance: expanded attack surface.
  - Meaning: feature increases parsing or interaction complexity.
  - Chain usage: execute-stage action trigger signal for annotation-driven exploit paths.
  - Metadata:
    - `annot.subtype`
    - `annot.trigger_context` (`annotation_action`, `annotation_aa`)
    - `action.trigger_event`, `action.trigger_event_normalised`
    - `action.trigger_type`
    - `chain.stage=execute`, `chain.capability=action_trigger_chain`, `chain.trigger=annotation_action`

## annotation_hidden

- ID: `annotation_hidden`
- Label: Hidden annotation
- Description: Annotation rectangle has near-zero size.
- Tags: feature
- Details:
  - Relevance: expanded attack surface.
  - Meaning: feature increases parsing or interaction complexity.
  - Chain usage: used as supporting context for delivery or exploitation stages.
  - Metadata:
    - `annot.subtype`
    - `annot.width`, `annot.height`
    - `annot.trigger_context=annotation_geometry`

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

## embedded_type_mismatch

- ID: `embedded_type_mismatch`
- Label: Embedded file type mismatch
- Description: Embedded file extension, declared subtype, and decoded magic markers disagree.
- Tags: embedded, evasion, relationship
- Details:
  - Relevance: mismatched declared and observed types are common in disguised attachment delivery.
  - Meaning: at least one pair among extension/subtype/magic disagrees (`embedded.mismatch_axes`).
  - Chain usage: decode-stage indicator that strengthens action-linked attachment risk.
  - Metadata:
    - `embedded.relationship.filespec_present`
    - `embedded.relationship.binding`
    - `embedded.extension_family`
    - `embedded.declared_subtype`
    - `embedded.declared_family`
    - `embedded.magic_family`
    - `embedded.family_mismatch`
    - `embedded.mismatch_axes`
    - `chain.stage=decode`, `chain.capability=embedded_payload`, `chain.trigger=embedded_file`

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

## packetised_payload_obfuscation

- ID: `packetised_payload_obfuscation`
- Label: Packetised payload obfuscation
- Description: Stream exhibits packet-like high-entropy blocks with index/length traits consistent with staged payload reconstruction.
- Tags: decoder, evasion, staging
- Details:
  - Relevance: packetised staging can hide executable payloads until runtime reassembly.
  - Meaning: stream data appears segmented into indexed high-entropy blocks with length-field structure.
  - Chain usage: high severity requires launch-path or execution-sink corroboration; trigger-only paths are retained at medium severity.
  - Metadata:
    - `packet.block_count` (int): number of packet-like blocks detected.
    - `packet.estimated_index_fields` (int): inferred count of index/length fields per block.
    - `packet.reconstruction_feasibility` (`low`, `medium`, `high`): estimated ease of payload reassembly.
    - `packet.stride_bytes` (int): inferred packet stride length.
    - `packet.monotonic_index_ratio` (float): ratio of blocks with monotonic index progression.
    - `packet.length_field_ratio` (float): ratio of blocks with plausible length fields.
    - `packet.index_gap_ratio` (float): ratio of index discontinuities between adjacent blocks.
    - `packet.unique_index_ratio` (float): unique index cardinality ratio over block count.
    - `packet.index_width_bytes` (int): inferred index field width.
    - `packet.length_width_bytes` (int): inferred length field width.
    - `packet.endianness` (`big`, `little`): inferred packet-field byte order.
    - `packet.correlation.execution_bridge` (bool-like string): true when launch/script execution bridge is present.
    - `packet.correlation.launch_path` (bool-like string): launch action path present.
    - `packet.correlation.execution_sink` (bool-like string): JavaScript execution sink path present.
    - `packet.correlation.trigger_path` (bool-like string): action-trigger path present.
    - `packet.correlation.bridge_sources` (string list): correlated bridge source families.

## eof_offset_unusual

- ID: `eof_offset_unusual`
- Label: EOF marker far from file end
- Description: Detected eof marker far from file end.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Exploitation: ObjStm can pack arbitrary objects (JavaScript, annotations, embedded files, other streams) into a single compressed stream to hide malicious payloads or confuse outsiders.
  - Triage advice: rerun with `--deep` to decode the ObjStm so each embedded object surfaces as its own node and any actionable payloads (JS/actions/images) emit their own findings.
  - Metadata: `objstm.preview` lists the first few embedded object IDs with their classified types so you can gauge payload locations without rerunning immediately.
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

## pdfjs_font_injection

- ID: `pdfjs_font_injection`
- Label: PDF.js font injection risk
- Description: Font-related structures include payload-like values associated with browser PDF.js injection paths.
- Tags: font, pdfjs, evasion
- Details:
  - Relevance: browser-based PDF rendering attack surface.
  - Meaning: detector emits `pdfjs.subsignal` for one of:
    - `fontmatrix_non_numeric`
    - `fontbbox_non_numeric`
    - `encoding_string_values`
    - `encoding_scriptlike_names`
    - `cmap_script_tokens`
    - `uncommon_subtype_combo`
  - Chain usage: renderer-targeted exploitation signal; prioritise when combined with JavaScript/action findings.
  - Metadata:
    - `pdfjs.affected_versions`: currently `<4.2.67`
    - `font.subtype`: font subtype when present.
    - `renderer.profile=pdfjs`
    - `renderer.precondition=pdfjs_font_parse_path_reachable`
    - `chain.stage=render`, `chain.capability=font_renderer_injection`, `chain.trigger=pdfjs`
    - `reader_impacts`: includes browser-oriented impact notes.

## pdfjs_annotation_injection

- ID: `pdfjs_annotation_injection`
- Label: PDF.js annotation injection indicator
- Description: Annotation appearance/content fields contain script-like payload tokens.
- Tags: annotation, pdfjs, injection
- Details:
  - Relevance: browser annotation rendering can expose script injection surfaces.
  - Meaning: `/AP` or annotation content fields include executable-style token patterns.
  - Chain usage: browser-render path indicator; correlate with action and JavaScript findings.
  - Metadata:
    - `annot.subtype`
    - `annot.trigger_context` (`annotation_render_only`, `annotation_action`, `mixed`)
    - `annot.action_trigger_count`
    - `injection.sources` (for example `/AP,/Contents,/RC`)
    - optional `injection.normalised=true` and `injection.decode_layers`
    - `chain.stage=render`, `chain.capability=annotation_injection`, `chain.trigger=annotation_render`

## pdfjs_form_injection

- ID: `pdfjs_form_injection`
- Label: PDF.js form injection indicator
- Description: Form value/appearance fields contain script-like payload tokens.
- Tags: forms, pdfjs, injection
- Details:
  - Relevance: interactive forms can carry payload material into rendered contexts.
  - Meaning: `/V`, `/DV`, or `/AP` form fields include injection-like script tokens.
  - Chain usage: form-stage injection indicator; prioritise with external action or JS findings.
  - Metadata:
    - `injection.sources`: contributing form keys (`/V`, `/DV`, `/AP`).
    - `injection.normalised`: `true` when encoded content required decode/normalisation before detection.
    - `injection.decode_layers`: number of decode rounds applied (bounded).
  - Confidence note: confidence is boosted when multi-layer decode is required to surface script tokens.

## form_html_injection

- ID: `form_html_injection`
- Label: HTML injection in form field value
- Description: Form field value contains HTML tags, event handlers, or context-breaking sequences that could enable XSS if rendered in web context.
- Tags: forms, html, xss, injection, browser
- Details:
  - Relevance: form field values containing HTML injection patterns can execute scripts when the PDF is rendered in browser-based viewers (PDF.js) or when form data is exported to web contexts.
  - Meaning: `/V`, `/DV`, or `/AP` form entries contain HTML-context indicators such as tags, event-handler attributes, context-breaking sequences, or protocol handlers.
  - Chain usage: XSS injection indicator; prioritise when PDF is processed by web-based viewers or form data extraction pipelines.
  - Patterns detected: HTML tags (`<script>`, `<img>`, `<iframe>`, `<svg>`, `<details>`), event handlers (`onclick=`, `onerror=`, `ontoggle=`), context-breaking (`">`, `</`), protocol handlers (`javascript:`, `data:text/html`).
  - Metadata:
    - `injection.sources`: contributing form keys (`/V`, `/DV`, `/AP`).
    - `injection.normalised`: `true` when encoded content required decode/normalisation before detection.
    - `injection.decode_layers`: number of decode rounds applied (bounded).
  - Reader impacts: PDF.js and browser-based renderers may interpret HTML in form values, enabling XSS attacks.
  - Remediation: review form field `/V` and `/DV` entries for HTML tag injection; apply context-appropriate output encoding when displaying form values in web interfaces.

## scattered_payload_assembly

- ID: `scattered_payload_assembly`
- Label: Scattered payload assembly indicator
- Description: Form payload fragments are benign in isolation but assemble into an injection-capable payload.
- Tags: forms, obfuscation, fragmentation, injection
- Details:
  - Relevance: modern malicious PDFs can distribute payload fragments across multiple objects to evade single-object token checks.
  - Meaning: `/V`, `/DV`, or `/AP` fragments from form-linked objects reconstruct into a payload with JavaScript or HTML injection indicators.
  - Chain usage: decode-stage indicator for distributed payload staging; prioritise when co-occurring with action and renderer findings.
  - Metadata:
    - `scatter.fragment_count`: number of fragments used in assembly.
    - `scatter.object_ids`: contributing object references.
    - `injection.sources`: contributing source keys (for example `/V`, `/Contents`, `/Title`).
    - `injection.signal.js` / `injection.signal.html`: assembled payload signal classification.
    - `injection.normalised` and `injection.decode_layers`: present when normalisation was required.
  - Remediation: resolve indirect references and inspect reconstructed values before relying on per-object benign classifications.

## form_field_oversized_value

- ID: `form_field_oversized_value`
- Label: Oversized form field value
- Description: Form field value size exceeds expected interactive form bounds.
- Tags: forms, anomaly
- Details:
  - Relevance: unusually large field values can hide staged payloads, encoded content, or fragmented exploit material.
  - Meaning: `/V` or `/DV` resolved payload length exceeded threshold (4 KB), including indirect references and array-fragment reconstruction.
  - Chain usage: input-stage anomaly signal that can raise confidence when paired with injection or decode-stage findings.
  - Metadata:
    - `field.name`
    - `field.source` (`/V` or `/DV`)
    - `field.value_len`
    - `field.oversized_threshold`
    - `payload.ref_chain`
    - `chain.stage=input`, `chain.capability=oversized_form_value`, `chain.trigger=acroform`
  - Remediation: inspect oversized field payloads for encoded script, staged data, and distributed fragments.

## obfuscated_name_encoding

- ID: `obfuscated_name_encoding`
- Label: Obfuscated PDF name encoding
- Description: Security-relevant PDF names use `#xx` hex encoding, which may indicate obfuscation.
- Tags: obfuscation, parser, metadata
- Details:
  - Relevance: action and script names can be hidden with PDF name hex encoding to evade simple token matching.
  - Meaning: at least one security-relevant name token (action/filter/script/form context) contained raw `#xx` encoding.
  - Chain usage: decode-stage context signal; use as a confidence booster when paired with action or injection findings.
  - Metadata:
    - `obfuscation.name_count`: number of distinct encoded security-relevant names.
    - `obfuscation.names`: decoded names that matched.
    - `chain.stage=decode`, `chain.capability=name_obfuscation`.
  - Remediation: inspect raw and decoded name tokens in flagged objects before classifying as benign.

## pdf_string_hex_encoded

- ID: `pdf_string_hex_encoded`
- Label: Hex-encoded PDF string in security context
- Description: Security-relevant string values use PDF hex-literal string syntax.
- Tags: obfuscation, parser, metadata
- Details:
  - Relevance: hex-literal strings can conceal action/form payload text from naive literal-string scans.
  - Meaning: security-relevant keys (for example `/JS`, `/URI`, `/F`, `/V`, `/DV`, `/Contents`, `/T`) carried `PdfStr::Hex` values.
  - Chain usage: decode-stage context signal used to raise confidence for associated action/injection findings.
  - Metadata:
    - `obfuscation.hex_string_count`
    - `obfuscation.hex_string_keys`
    - `obfuscation.hex_string_samples`
    - `chain.stage=decode`, `chain.capability=string_hex_obfuscation`
  - Remediation: review decoded string values and correlate with action targets, form payloads, and execution-capable findings.

## cross_stream_payload_assembly

- ID: `cross_stream_payload_assembly`
- Label: Cross-stream payload assembly indicator
- Description: JavaScript assembly behaviour aligns with payload fragments reconstructed from form, annotation, or metadata objects.
- Tags: javascript, forms, obfuscation, correlation
- Details:
  - Relevance: exploit chains can split payload material between PDF object values and JavaScript runtime reconstruction logic.
  - Meaning: JavaScript assembly patterns (for example `fromCharCode`, split/join, concat) correlate with reconstructed payloads assembled from form field values, annotation content, or document metadata string fragments.
  - Chain usage: decode-stage bridge indicator linking JavaScript execution context to distributed payload staging across form, annotation, and metadata surfaces.
  - Metadata:
    - `js.object.ref`: object containing JavaScript assembly logic.
    - `scatter.object_ids`: contributing fragmented source objects.
    - `injection.sources`: contributing source keys (for example `/V`, `/Contents`, `/Title`).
    - `cross_stream.source_types`: contributing source domains (`form`, `annotation`, `metadata`).
    - optional `js.payload.fromcharcode_*` fields when static reconstruction metadata is available.
    - `chain.stage=decode`, `chain.capability=cross_stream_assembly`, `chain.trigger=pdfjs`.
  - Remediation: triage as a correlated chain and inspect both JavaScript reconstruction code and referenced form/object fragment sources.

## pdfjs_eval_path_risk

- ID: `pdfjs_eval_path_risk`
- Label: PDF.js eval-path risk indicator
- Description: Document contains font structures commonly associated with PDF.js eval-render paths.
- Tags: font, pdfjs, info
- Details:
  - Relevance: complex font rendering paths can increase browser-side attack exposure.
  - Meaning: font subtype/encoding structure suggests higher-sensitivity render pathways.
  - Chain usage: informational context signal for triage and environment-specific risk assessment.
  - Metadata:
    - `pdfjs.eval_path_object_count`
    - `font.subtypes`
    - `renderer.profile=pdfjs`
    - `renderer.precondition=pdfjs_font_eval_path_reachable`
    - `chain.stage=render`, `chain.capability=font_eval_path`, `chain.trigger=pdfjs`

## font_js_exploitation_bridge

- ID: `font_js_exploitation_bridge`
- Label: Correlated font and JavaScript exploitation indicators
- Description: Suspicious font structures co-occur with executable JavaScript indicators in the same PDF.
- Tags: font, javascript, correlation
- Details:
  - Relevance: combined font and JS signals strongly suggest staged renderer exploitation attempts.
  - Meaning: bridge correlation requires both suspicious font indicators and JavaScript execution-capable indicators.
  - Chain usage: prioritisation signal for analyst triage; confidence and severity are adjusted by co-location and high-risk JS semantics.
  - Metadata:
    - `bridge.font_indicators`
    - `bridge.js_indicators`
    - `bridge.confidence_adjusted`
    - `bridge.co_location` (`shared_object` or `document_level`)
    - `bridge.shared_object_count`
    - optional `bridge.shared_objects`
    - `bridge.js_high_risk`
    - `renderer.profile=pdfjs`
    - `renderer.precondition=pdfjs_font_eval_and_js_execution_paths_reachable`
    - `chain.stage=render`, `chain.capability=font_js_renderer_bridge`, `chain.trigger=pdfjs`

## gotor_present

- ID: `gotor_present`
- Label: GoToR action present
- Description: Action dictionary with /S /GoToR.
- Tags: action, external
- Details:
  - Relevance: executable action surface.
  - Meaning: viewer can perform external or privileged actions.
  - Chain usage: treated as an action node that can be linked to triggers and payloads.

## hidden_layer_action

- ID: `hidden_layer_action`
- Label: Hidden-layer action risk
- Description: Optional content groups (`OCG`/`OCProperties`) co-occur with action execution surfaces, indicating potential hidden-layer action paths.
- Tags: composite, action, hidden-layer
- Details:
  - Relevance: hidden optional-content structures can conceal actionable behaviour from casual inspection.
  - Meaning: correlates `ocg_present` with action findings; confidence is stronger when object-level co-location is present.
  - Chain usage: high-priority action-stage context signal for stealth execution paths.
  - Metadata:
    - `context.hidden_layer=true`
    - `context.ocg_signal_count`

## action_remote_target_suspicious

- ID: `action_remote_target_suspicious`
- Label: Suspicious remote action target
- Description: Action target uses high-risk remote target patterns or obfuscated target encoding.
- Tags: action, external, obfuscation
- Details:
  - Relevance: remote action targets can drive external fetch/open paths and exfiltration behaviour.
  - Meaning: flags suspicious `/F` or `/URI` targets for actions such as `/GoToR`, `/GoToE`, `/SubmitForm`, `/Launch`, and `/URI`.
  - Chain usage: action-stage risk enhancer used to connect action nodes to egress or payload-delivery paths.
  - Metadata:
    - `action.remote.indicators`: matched indicators (`unc_path`, `data_uri`, `javascript_scheme`, `file_scheme`, `obfuscated_target`)
    - `action.remote.target_preview`: normalised target preview
    - `action.remote.scheme`: parsed scheme token (or leading path token for UNC-style paths)
    - `action.param.source`: source key containing the target (`/F` or `/URI`)
    - `egress.channel`: normalised outbound channel (`remote_goto`, `uri_action`, `submit_form`, `launch_target`)
    - `egress.target_kind`: target classification (`unc_path`, `data_uri`, `script_uri`, `file_uri`, `remote_target`)
    - `egress.user_interaction_required`: heuristic interaction requirement (`true`, `false`, `unknown`)
    - `chain.stage=egress`, `chain.capability=remote_action_target`, `chain.trigger=action`

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
- Description: Decoded ICC profile fails concrete validation checks (for example declared-size bounds, `acsp` signature, tag-table bounds/overlap, or `/N` component mismatch).
- Tags: color
- Details:
  - Relevance: color profile parsing risk.
  - Meaning: malformed or contradictory ICC metadata can trigger parser/decoder differentials and unsafe code paths.
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

## image.colour_space_invalid

- ID: `image.colour_space_invalid`
- Label: Invalid colour space
- Severity: Medium
- Confidence: Strong
- Description: Image colour space is malformed, unresolved, or violates the PDF specification.
- Tags: image, colour-space, malformed
- Details:
  - Relevance: malformed colour space arrays may indicate evasion, crafted exploits, or corrupted PDFs.
  - Meaning: the /ColorSpace entry could not be resolved to a known type.
  - Metadata: `image.colour_space_issue` describes the specific problem (missing elements, unresolved reference, invalid /N, depth exceeded).

## image.bpc_anomalous

- ID: `image.bpc_anomalous`
- Label: Anomalous bits per component
- Severity: Low
- Confidence: Strong
- Description: Image BitsPerComponent value is not a standard value (1, 2, 4, 8, or 16).
- Tags: image, malformed
- Details:
  - Relevance: non-standard BPC values violate the PDF specification and may target decoder edge cases.
  - Metadata: `image.bits_per_component` contains the declared value.

## image.pixel_buffer_overflow

- ID: `image.pixel_buffer_overflow`
- Label: Image pixel buffer overflow
- Severity: Medium
- Confidence: Certain
- Description: Image dimensions and colour depth would produce a pixel buffer exceeding safe limits.
- Tags: image, resource-exhaustion
- Details:
  - Relevance: potential denial of service via memory exhaustion or integer overflow in decoders.
  - Metadata: `image.calculated_buffer_bytes`, `image.channels`, `image.bpc`.

## image.pixel_data_size_mismatch

- ID: `image.pixel_data_size_mismatch`
- Label: Image stream size mismatch
- Severity: Medium
- Confidence: Probable
- Description: Decoded stream length does not match the expected pixel data size for the declared dimensions.
- Tags: image, data-hiding
- Details:
  - Relevance: may indicate hidden data appended to image streams, truncated content, or inconsistent metadata.
  - Metadata: `image.expected_bytes`, `image.actual_bytes`.

## image.indexed_palette_short

- ID: `image.indexed_palette_short`
- Label: Indexed palette too short
- Severity: Low
- Confidence: Strong
- Description: Indexed colour space palette has fewer bytes than required by the declared hival.
- Tags: image, colour-space, malformed
- Details:
  - Relevance: short palettes may cause out-of-bounds reads in vulnerable decoders.
  - Metadata: `image.palette_expected_bytes`, `image.palette_actual_bytes`, `image.hival`.

## image.decode_array_invalid

- ID: `image.decode_array_invalid`
- Label: Invalid decode array
- Severity: Low
- Confidence: Strong
- Description: Image /Decode array has incorrect length for the colour space.
- Tags: image, malformed
- Details:
  - Relevance: invalid /Decode arrays may cause index-out-of-bounds or numeric instability in decoders.
  - Metadata: `image.decode_array_length`, `image.decode_array_expected_length`.

## image.metadata_oversized

- ID: `image.metadata_oversized`
- Label: Oversized image metadata
- Severity: Medium
- Confidence: Strong
- Description: Embedded image metadata segment exceeds safe size limits.
- Tags: image, metadata, resource-exhaustion
- Details:
  - Relevance: oversized metadata segments can trigger parser stress and conceal payloads.
  - Metadata: `image.metadata.kind`, `image.metadata.bytes`.

## image.metadata_malformed

- ID: `image.metadata_malformed`
- Label: Malformed image metadata
- Severity: Medium
- Confidence: Probable
- Description: Embedded image metadata structure is malformed or truncated.
- Tags: image, metadata, malformed
- Details:
  - Relevance: malformed metadata can target parser edge-cases in viewers and tooling.
  - Metadata: `image.metadata.issue`.

## image.metadata_suspicious_density

- ID: `image.metadata_suspicious_density`
- Label: Suspicious metadata density
- Severity: Low
- Confidence: Probable
- Description: Image metadata occupies an unusually large share of the image payload.
- Tags: image, metadata, evasion
- Details:
  - Relevance: abnormally dense metadata can indicate covert channels or padding-based obfuscation.
  - Metadata: `image.metadata.total_bytes`, `image.metadata.ratio_percent`.

## image.metadata_scriptable_content

- ID: `image.metadata_scriptable_content`
- Label: Scriptable metadata content
- Severity: Medium
- Confidence: Tentative
- Description: Embedded image metadata contains script-like markers.
- Tags: image, metadata, active-content
- Details:
  - Relevance: script-like markers in metadata can indicate active-content experiments or exploit scaffolding.
  - Metadata: `image.metadata.scriptable`.

## incremental_update_chain

- ID: `incremental_update_chain`
- Label: Incremental update chain present
- Description: Detected incremental update chain present.
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: file structure may be malformed or intentionally confusing.
  - Chain usage: used as evasion context that can hide payloads or actions.
  - Metadata:
    - `graph.evasion_kind=incremental_overlay`
    - `graph.depth`
    - `graph.conflict_count`
    - `chain.stage=decode`, `chain.capability=graph_incremental_overlay`, `chain.trigger=xref`

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

## js_heap_grooming

- ID: `js_heap_grooming`
- Label: Heap grooming pattern detected
- Description: JavaScript shows repeated heap allocation and view-shaping patterns consistent with grooming.
- Tags: exploit, javascript, memory
- Details:
  - Relevance: modern memory exploitation preparation.
  - Meaning: repeated `ArrayBuffer`/typed-array shaping patterns may prepare deterministic heap layout.
  - Chain usage: used as pre-exploitation staging context.

## js_lfh_priming

- ID: `js_lfh_priming`
- Label: LFH priming pattern detected
- Description: JavaScript appears to prime allocation buckets through repeated allocation/free cycles.
- Tags: exploit, javascript, memory
- Details:
  - Relevance: low-fragmentation heap preparation in modern exploit chains.
  - Meaning: repeated same-size allocation cycles are followed by targeted placement allocations.
  - Chain usage: used as exploitation-preparation context.

## js_rop_chain_construction

- ID: `js_rop_chain_construction`
- Label: ROP chain construction pattern detected
- Description: JavaScript uses address arithmetic and sequential write patterns consistent with ROP chain staging.
- Tags: exploit, javascript, memory
- Details:
  - Relevance: strong exploitation signal.
  - Meaning: gadget-style address maths and sequential memory writes indicate control-flow hijack preparation.
  - Chain usage: used as direct exploitation-stage indicator.

## js_info_leak_primitive

- ID: `js_info_leak_primitive`
- Label: Info-leak primitive pattern detected
- Description: JavaScript exhibits ArrayBuffer/TypedArray patterns consistent with out-of-bounds memory disclosure primitives.
- Tags: exploit, javascript, memory
- Details:
  - Relevance: memory disclosure often precedes reliable code execution.
  - Meaning: length/byteLength mismatch and indexed read patterns suggest leak primitive construction.
  - Chain usage: used as exploitation precondition context.

## js_aaencode_encoding

- ID: `js_aaencode_encoding`
- Label: AAEncode encoding detected
- Description: JavaScript appears obfuscated with AAEncode fullwidth/emoticon-style encoding.
- Tags: evasion, javascript, obfuscation
- Details:
  - Relevance: concealment of executable intent.
  - Meaning: AAEncode-style payloads hide readable logic behind non-standard character encodings.
  - Chain usage: used as a staged obfuscation layer before runtime materialisation.

## js_jjencode_encoding

- ID: `js_jjencode_encoding`
- Label: JJEncode encoding detected
- Description: JavaScript appears obfuscated with JJEncode symbol-heavy encoding.
- Tags: evasion, javascript, obfuscation
- Details:
  - Relevance: concealment of executable intent.
  - Meaning: JJEncode-style symbol density indicates deliberate anti-analysis obfuscation.
  - Chain usage: used as a staged obfuscation layer prior to decode/execute phases.

## js_jsfuck_encoding

- ID: `js_jsfuck_encoding`
- Label: JSFuck encoding detected
- Description: JavaScript appears obfuscated with JSFuck character-restricted encoding.
- Tags: evasion, javascript, obfuscation
- Details:
  - Relevance: concealment of executable intent.
  - Meaning: JSFuck payloads encode logic with restricted punctuation, impairing direct static review.
  - Chain usage: used as a pre-execution obfuscation stage that often pairs with dynamic eval sinks.

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
  - Metadata:
    - `js.source`: source container class (`action`, `open_action`, `aa_event`, `annotation`, `name_tree`, `catalog_js`, `uri`, `data_uri`, `xfa`, `embedded_file`)
    - `js.container_path`: normalised container path (for example `/Catalog/OpenAction/JS`, `/Catalog/Names/JavaScript/Names[]`, `/Annot/A/JS`)
    - `js.object_ref_chain`: resolved object lineage for the selected payload candidate

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

## js_runtime_dependency_loader_abuse

- ID: `js_runtime_dependency_loader_abuse`
- Label: Runtime dependency loader abuse
- Description: JavaScript dynamically loaded runtime modules and invoked execution or write sinks.
- Tags: javascript, runtime, supply-chain
- Details:
  - Relevance: dynamic module loading in Node-like environments.
  - Meaning: runtime dependency resolution is used to reach sensitive APIs (for example process execution or filesystem writes).
  - Chain usage: used as staging/execution capability expansion before payload actions.

## js_runtime_credential_harvest

- ID: `js_runtime_credential_harvest`
- Label: Credential-harvest form emulation
- Description: JavaScript combined field/form APIs with outbound submission behaviour, consistent with credential harvesting.
- Tags: javascript, phishing, runtime
- Details:
  - Relevance: interactive lure and exfiltration behaviour.
  - Meaning: script-driven forms or fields are paired with submission/network sinks.
  - Chain usage: used as social-engineering and data-capture stage.

## js_runtime_heap_manipulation

- ID: `js_runtime_heap_manipulation`
- Label: Runtime heap manipulation primitives
- Description: JavaScript exercised heap-related primitives during sandbox execution.
- Tags: javascript, memory, runtime
- Details:
  - Relevance: runtime heap shaping can support staged decode, exploitation, or obfuscated dispatch.
  - Meaning: allocation, view creation, and byte-level access primitives were observed (for example `ArrayBuffer`, typed arrays, `DataView`).
  - Chain usage: used as exploitation-preparation context and correlated with decode/execution findings.
  - Metadata highlights:
    - `js.runtime.heap.allocation_count`
    - `js.runtime.heap.view_count`
    - `js.runtime.heap.access_count`
    - `js.runtime.heap.allocations`
    - `js.runtime.heap.views`
    - `js.runtime.heap.accesses`
    - `js.runtime.truncation.heap_accesses_dropped`

## js_runtime_wasm_loader_staging

- ID: `js_runtime_wasm_loader_staging`
- Label: WASM loader staging observed
- Description: JavaScript invoked WebAssembly loader APIs in a sequence consistent with staged execution.
- Tags: javascript, runtime, wasm
- Details:
  - Relevance: staged or evasive runtime execution.
  - Meaning: WebAssembly can be used as an intermediate decode/dispatch layer.
  - Chain usage: used as payload staging before dynamic execution.

## js_runtime_service_worker_persistence

- ID: `js_runtime_service_worker_persistence`
- Label: Service worker persistence abuse
- Description: JavaScript used service worker lifecycle and cache APIs in a persistence-oriented sequence.
- Tags: javascript, persistence, runtime
- Details:
  - Relevance: browser persistence and cache-backed staging.
  - Meaning: service worker registration is combined with lifecycle/cache operations to maintain foothold or staged content.
  - Chain usage: used as persistence and payload-resume stage.
  - Metadata highlights:
    - `js.runtime.service_worker.registration_calls`
    - `js.runtime.service_worker.update_calls`
    - `js.runtime.service_worker.event_handlers_registered`
    - `js.runtime.service_worker.lifecycle_events_executed`
    - `js.runtime.service_worker.cache_calls`
    - `js.runtime.service_worker.indexeddb_calls`

## js_runtime_webcrypto_key_staging

- ID: `js_runtime_webcrypto_key_staging`
- Label: WebCrypto key staging and exfiltration
- Description: JavaScript handled WebCrypto key material and then attempted outbound transmission.
- Tags: crypto, javascript, runtime
- Details:
  - Relevance: cryptographic material access and transfer.
  - Meaning: key generation/import/export is coupled with network-capable sinks.
  - Chain usage: used as credential/key capture and exfiltration stage.

## js_runtime_storage_payload_staging

- ID: `js_runtime_storage_payload_staging`
- Label: Storage-backed payload staging
- Description: JavaScript staged payload content in browser storage before decode or execution.
- Tags: javascript, runtime, staging
- Details:
  - Relevance: local persistence and delayed execution.
  - Meaning: browser storage APIs are used as intermediate payload buffers.
  - Chain usage: used as staging and delayed activation stage.

## js_runtime_dynamic_module_evasion

- ID: `js_runtime_dynamic_module_evasion`
- Label: Dynamic module graph evasion
- Description: JavaScript performed dynamic module loading and graph traversal with execution sinks.
- Tags: javascript, module-loading, runtime
- Details:
  - Relevance: runtime capability expansion and evasion.
  - Meaning: module resolution is used to assemble execution paths at runtime.
  - Chain usage: used as loader/expansion stage before payload dispatch.

## js_runtime_realtime_channel_abuse

- ID: `js_runtime_realtime_channel_abuse`
- Label: Covert realtime channel abuse
- Description: JavaScript prepared encoded data and sent it through realtime communication channels.
- Tags: javascript, network, runtime
- Details:
  - Relevance: low-latency command-and-control or exfiltration.
  - Meaning: WebSocket/WebRTC-like channels are used to move staged content.
  - Chain usage: used as outbound communication stage.
  - Metadata highlights:
    - `js.runtime.realtime.session_count`
    - `js.runtime.realtime.unique_targets`
    - `js.runtime.realtime.send_count`
    - `js.runtime.realtime.avg_payload_len`
    - `js.runtime.realtime.channel_types`

## js_runtime_clipboard_session_hijack

- ID: `js_runtime_clipboard_session_hijack`
- Label: Clipboard/session hijack behaviour
- Description: JavaScript accessed clipboard/session artefacts and attempted outbound transfer.
- Tags: javascript, runtime, session
- Details:
  - Relevance: data theft and user-session abuse.
  - Meaning: clipboard or session sources are paired with exfiltration sinks.
  - Chain usage: used as collection and theft stage.

## js_runtime_dom_policy_bypass

- ID: `js_runtime_dom_policy_bypass`
- Label: DOM sink policy bypass attempt
- Description: JavaScript routed obfuscated input into sensitive DOM or script sink surfaces.
- Tags: javascript, runtime, xss
- Details:
  - Relevance: script injection and policy bypass.
  - Meaning: sink APIs are reached through obfuscated or dynamic construction paths.
  - Chain usage: used as execution and injection stage.

## js_runtime_wasm_memory_unpacker

- ID: `js_runtime_wasm_memory_unpacker`
- Label: WASM memory unpacker pipeline
- Description: JavaScript combined WebAssembly memory operations with unpacking and dynamic execution.
- Tags: javascript, runtime, wasm
- Details:
  - Relevance: staged unpacking and evasive execution.
  - Meaning: WASM memory surfaces are combined with decode and dynamic execution sinks.
  - Chain usage: used as packed payload decode and dispatch stage.

## js_runtime_extension_api_abuse

- ID: `js_runtime_extension_api_abuse`
- Label: Extension API abuse probe
- Description: JavaScript probed extension runtime APIs, indicating privilege and environment reconnaissance.
- Tags: javascript, runtime, reconnaissance
- Details:
  - Relevance: privilege and environment capability checks.
  - Meaning: extension runtime/storage surfaces are enumerated prior to higher-risk actions.
  - Chain usage: used as reconnaissance and environment validation stage.

## js_runtime_modern_fingerprint_evasion

- ID: `js_runtime_modern_fingerprint_evasion`
- Label: Modern fingerprinting evasion
- Description: JavaScript performed modern fingerprint probes with timing or gating behaviour.
- Tags: evasion, javascript, runtime
- Details:
  - Relevance: anti-analysis and environment filtering.
  - Meaning: modern browser fingerprint APIs are used to gate payload execution.
  - Chain usage: used as anti-analysis and conditional execution stage.

## js_runtime_chunked_data_exfil

- ID: `js_runtime_chunked_data_exfil`
- Label: Chunked data exfiltration pipeline
- Description: JavaScript staged data in chunks and transmitted it across repeated outbound sends.
- Tags: exfiltration, javascript, runtime
- Details:
  - Relevance: staged data theft and covert transfer.
  - Meaning: data is buffered/encoded and exfiltrated in repeated transmissions.
  - Chain usage: used as chunked exfiltration stage.
  - Metadata highlights:
    - `taint_edges` (behaviour metadata key)
    - exfil scoring/feature fields (`query_entropy`, `target_repetition`, `exfil_score`)

## js_runtime_interaction_coercion

- ID: `js_runtime_interaction_coercion`
- Label: Interaction coercion loop
- Description: JavaScript repeatedly invoked dialog primitives with loop or gating cues consistent with coercive lures.
- Tags: javascript, runtime, social-engineering
- Details:
  - Relevance: user-pressure and lure behaviour.
  - Meaning: repeated alert/confirm/prompt patterns are used to force user action.
  - Chain usage: used as social-engineering and execution-enable stage.

## js_runtime_lotl_api_chain_execution

- ID: `js_runtime_lotl_api_chain_execution`
- Label: Living-off-the-land API chain execution
- Description: JavaScript chained benign host APIs from environment and staging surfaces into execution behaviour.
- Tags: javascript, lotl, runtime
- Details:
  - Relevance: low-noise abuse of legitimate APIs.
  - Meaning: environment + file staging + execution chain occurs without direct downloader API dependence.
  - Chain usage: used as stealthy staging-to-execution path.

## js_runtime_api_sequence_malicious

- ID: `js_runtime_api_sequence_malicious`
- Label: Suspicious API call sequence
- Description: JavaScript executed a suspicious source/transform/sink API sequence consistent with staged malicious intent.
- Tags: behavioural, javascript, runtime
- Details:
  - Relevance: resilient detection against syntactic rewrites.
  - Meaning: source acquisition APIs are chained with transformation calls and sensitive sinks.
  - Chain usage: used as a sequence-level intent signal for rewritten malware.

## js_runtime_source_sink_complexity

- ID: `js_runtime_source_sink_complexity`
- Label: Complex source-to-sink data flow
- Description: JavaScript routed data from acquisition sources to sensitive sinks with a multi-step transformation chain.
- Tags: behavioural, javascript, runtime
- Details:
  - Relevance: obfuscation-resilient flow analysis.
  - Meaning: multi-step transforms between source and sink increase suspicion even when individual calls look benign.
  - Chain usage: used to prioritise staged source-to-sink flows.

## js_runtime_entropy_at_sink

- ID: `js_runtime_entropy_at_sink`
- Label: High-entropy payload at execution sink
- Description: JavaScript passed high-entropy runtime strings into execution sinks, consistent with obfuscated payload staging.
- Tags: behavioural, javascript, runtime
- Details:
  - Relevance: detects encoded/packed payload material reaching execution.
  - Meaning: high-entropy sink arguments indicate likely hidden executable content.
  - Chain usage: used as execution-stage obfuscation signal.

## js_runtime_dynamic_string_materialisation

- ID: `js_runtime_dynamic_string_materialisation`
- Label: Dynamic string materialisation into execution sink
- Description: JavaScript dynamically materialised executable strings before invoking execution sinks.
- Tags: behavioural, javascript, runtime
- Details:
  - Relevance: runtime reconstruction of payload content.
  - Meaning: decoded or constructed strings are staged then executed.
  - Chain usage: used as runtime payload build-and-exec signal.

## js_runtime_path_morphism

- ID: `js_runtime_path_morphism`
- Label: Runtime path morphism detected
- Description: Runtime execution paths diverged across profiles with AST delta activity, consistent with self-modifying or profile-gated behaviour.
- Tags: behavioural, javascript, runtime
- Details:
  - Relevance: catches profile-dependent and self-modifying runtime behaviour missed by single-path execution.
  - Meaning: call/property/phase signatures and delta summaries differ materially across executed runtime profiles.
  - Chain usage: high-priority follow-up signal for gated payload activation and evasive profile-specific execution.
  - Metadata highlights:
    - `js.runtime.path_morphism.executed_profiles`
    - `js.runtime.path_morphism.distinct_signatures`
    - `js.runtime.path_morphism.delta_profiles`
    - `js.runtime.path_morphism.added_calls`
    - `js.runtime.path_morphism.added_identifiers`
    - `js.runtime.path_morphism.added_string_literals`
    - `js.runtime.path_morphism.trigger_call_count`
    - `js.runtime.path_morphism.phase_set_size`
    - `js.runtime.path_morphism.score`
    - `js.runtime.profile_mode.deception_hardened_count`
    - `js.runtime.interaction_pack_order`
    - `js.runtime.interaction_pack.open_profiles`
    - `js.runtime.interaction_pack.idle_profiles`
    - `js.runtime.interaction_pack.click_profiles`
    - `js.runtime.interaction_pack.form_profiles`
    - `js.runtime.capability_matrix.distinct_signatures`
    - `js.runtime.unresolved_identifier_error_total`
    - `js.runtime.unresolved_callable_error_total`
    - `js.runtime.unresolved_callee_hint_total`

## js_runtime_error_recovery_patterns

- ID: `js_runtime_error_recovery_patterns`
- Label: Runtime error recovery patterning
- Description: JavaScript repeatedly triggered errors and pivoted to fallback execution paths, consistent with runtime adaptation or anti-analysis behaviour.
- Tags: behavioural, javascript, runtime
- Details:
  - Relevance: anti-analysis and resilient execution behaviour.
  - Meaning: repeated error/recovery loops indicate adaptive control flow rather than simple script failure.
  - Chain usage: used as robustness/evasion context when correlating runtime intent.

## js_runtime_dormant_or_gated_execution

- ID: `js_runtime_dormant_or_gated_execution`
- Label: Dormant or gated execution behaviour
- Description: JavaScript payload appears dormant under current emulation and may require specific runtime gates, interaction, or environment triggers to activate.
- Tags: behavioural, javascript, runtime
- Details:
  - Relevance: identifies likely delayed or environment-gated payload activation.
  - Meaning: large or complex script content produced little/no runtime activity in current profile set.
  - Chain usage: used as a follow-up triage signal to prioritise deeper environment/profile replay.

## js_semantic_source_to_sink_flow

- ID: `js_semantic_source_to_sink_flow`
- Label: Semantic source-to-sink flow detected
- Description: AST semantic call graph indicates a source-to-sink flow with transformation depth, resilient to syntactic rewrites.
- Tags: ast, javascript, semantic
- Details:
  - Relevance: semantics-first detection for rewritten malware.
  - Meaning: call graph analysis links source calls to sinks through transformation steps.
  - Chain usage: used as static semantic corroboration for behavioural findings.

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

## js_dead_code_injection

- ID: `js_dead_code_injection`
- Label: Dead code injection obfuscation
- Description: JavaScript contains unreachable branches or post-terminator code consistent with anti-analysis dead-code injection.
- Tags: evasion, javascript, obfuscation
- Details:
  - Relevance: anti-analysis and analyst time-wasting technique.
  - Meaning: deliberately unreachable logic is mixed with live code to obscure payload intent.
  - Chain usage: used as a structural obfuscation layer prior to execution stages.

## js_array_rotation_decode

- ID: `js_array_rotation_decode`
- Label: Array rotation decode pattern
- Description: JavaScript contains string-array rotation decode patterns common in obfuscator-style loaders.
- Tags: evasion, javascript, obfuscation
- Details:
  - Relevance: common string decryption and payload materialisation primitive.
  - Meaning: push/shift rotation with indexed lookup suggests staged deobfuscation.
  - Chain usage: used as an intermediate decode stage before dynamic eval or sink invocation.

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

## linearization_integrity

- ID: `linearization_integrity`
- Label: Linearization integrity anomaly
- Description: Linearization dictionary integrity checks failed (size, hint offsets, xref relation, or object ordering).
- Tags: evasion, structure
- Details:
  - Relevance: parser differential/evasion risk.
  - Meaning: linearisation metadata is inconsistent with file layout and may yield reader-specific object loading.
  - Chain usage: used as structural parser-divergence context.

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

## null_ref_chain_termination

- ID: `null_ref_chain_termination`
- Label: Null/missing reference chain termination
- Description: Security-relevant indirect reference chain terminates at `null`, `0 0 R`, or a missing object.
- Tags: structure, evasion, parser
- Details:
  - Relevance: deep broken reference chains can trigger parser-state confusion and hide malicious intent in action/form contexts.
  - Meaning: chain depth is at least three indirect references and ends in a null/missing terminal object in keys such as `/OpenAction`, `/A`, `/AA`, `/V`, `/DV`, `/AP`, or `/Contents`.
  - Chain usage: decode-stage structural risk signal; combine with action/injection findings to prioritise likely exploit paths.
  - Metadata:
    - `context.owner`
    - `context.key`
    - `termination.kind` (`missing_object`, `null_literal`, `null_object_ref`)
    - `termination.target`
    - `ref.depth`
    - `ref.chain`
    - `chain.stage=decode`, `chain.capability=null_ref_chain`, `chain.trigger=parser`

## open_action_present

- ID: `open_action_present`
- Label: Document OpenAction present
- Description: OpenAction triggers when the PDF opens.
- Tags: action
- Details:
  - Relevance: automatic execution trigger.
  - Meaning: OpenAction runs on document open.
  - Chain usage: treated as the trigger node that links to actions or payloads.
  - Metadata:
    - `action.trigger_context=open_action`
    - `action.trigger_event_normalised=/OpenAction`
    - `action.trigger_type=automatic`
    - `chain.stage=execute`, `chain.capability=action_trigger_chain`, `chain.trigger=open_action`

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

## passive_external_resource_fetch

- ID: `passive_external_resource_fetch`
- Label: Passive external resource fetch surface
- Description: External fetch targets were found in render-related objects and may trigger outbound requests during preview, indexing, or open-time processing.
- Tags: action, passive, network
- Details:
  - Relevance: preview/no-click network exposure in enterprise pipelines.
  - Meaning: document objects reference external locations (`http`, `ftp`, `file`, `smb`, `unc`) in rendering or action contexts.
  - Chain usage: used as passive delivery-stage context, especially when combined with automatic triggers.
  - Metadata highlights:
    - `passive.external_target_count`
    - `passive.external_protocols`
    - `passive.protocol_breakdown`
    - `passive.protocol_risk_class`
    - `passive.source_contexts`
    - `passive.source_context_breakdown`
    - `passive.trigger_mode`
    - `passive.indexer_trigger_likelihood`
    - `passive.preview_indexer_context_count`

## passive_credential_leak_risk

- ID: `passive_credential_leak_risk`
- Label: Passive credential leak risk
- Description: UNC/SMB-style external targets were detected in render-time contexts and may leak credentials through implicit authentication attempts.
- Tags: credential, network, passive
- Details:
  - Relevance: NTLM/Kerberos leak pathways via document rendering or preview.
  - Meaning: one or more external targets used UNC/SMB addressing in contexts likely to be resolved by host tooling.
  - Chain usage: used as high-priority exfiltration-risk signal when triaging passive document workflows.
  - Metadata highlights:
    - `passive.credential_leak_risk`
    - `passive.ntlm_hash_leak_likelihood`
    - `passive.credential_leak_hit_count`
    - `passive.ntlm_target_count`
    - `passive.ntlm_hosts`
    - `passive.ntlm_shares`
    - `passive.external_targets_sample`

## passive_render_pipeline_risk_composite

- ID: `passive_render_pipeline_risk_composite`
- Label: Passive render pipeline exploitation chain
- Description: Automatic trigger pathways, preview-prone contexts, and external fetch targets co-occur, consistent with passive render-pipeline exploitation techniques.
- Tags: chain, passive, render
- Details:
  - Relevance: no-click exploitation and data leak risk in preview/index infrastructure.
  - Meaning: automatic action triggers overlap with render-prone objects and external fetch references.
  - Chain usage: treated as a composite high-risk chain requiring immediate isolation and investigation.
  - Metadata highlights:
    - `passive.composite_rule`
    - `passive.preview_prone_surface`
    - `passive.external_protocols`

## resource.external_reference_obfuscated

- ID: `resource.external_reference_obfuscated`
- Label: Obfuscated external reference target
- Severity: Medium
- Confidence: Probable
- Description: External targets include encoding or normalisation anomalies that indicate obfuscation.
- Tags: network, passive, evasion
- Details:
  - Relevance: obfuscated targets can bypass simple allowlists and triage heuristics.
  - Metadata highlights:
    - `resource.obfuscated_target_count`
    - `passive.external_targets_sample`
    - `passive.external_targets_normalised`

## resource.external_reference_high_risk_scheme

- ID: `resource.external_reference_high_risk_scheme`
- Label: High-risk external reference scheme
- Severity: High
- Confidence: Strong
- Description: External references use high-risk schemes (UNC/SMB/file/data) in renderable contexts.
- Tags: network, passive, credential
- Details:
  - Relevance: high-risk schemes can trigger credential leakage or unsafe host interactions.
  - Metadata highlights:
    - `resource.high_risk_scheme_count`
    - `passive.protocol_risk_class`
    - `passive.ntlm_target_count`

## resource.hidden_render_path

- ID: `resource.hidden_render_path`
- Label: Hidden resource render path
- Severity: Medium
- Confidence: Probable
- Description: Image/font objects are reachable through indirect resource paths without clear direct page ancestry.
- Tags: structure, render, evasion
- Details:
  - Relevance: nested resource indirection can conceal suspicious payload activation paths.
  - Metadata highlights:
    - `resource.hidden_render_path_count`
    - `passive.source_context_breakdown`

## resource.provenance_xref_conflict

- ID: `resource.provenance_xref_conflict`
- Label: Resource provenance with xref conflict
- Severity: High
- Confidence: Probable
- Description: Resource revision overrides co-occur with xref conflict signals.
- Tags: structure, xref, provenance
- Details:
  - Relevance: combined provenance and xref anomalies increase parser differential risk.
  - Metadata highlights:
    - `resource.object_id`
    - `resource.provenance`
    - `resource.object_shadowed_revisions`

## font.provenance_incremental_override

- ID: `font.provenance_incremental_override`
- Label: Font revision override
- Severity: Medium
- Confidence: Strong
- Description: Font object identifier appears across multiple revisions.
- Tags: font, structure, provenance
- Details:
  - Relevance: revision overrides can hide embedded font payload changes.
  - Metadata highlights:
    - `font.object_shadowed_revisions`
    - `font.object_provenance`

## font.structure_subtype_mismatch

- ID: `font.structure_subtype_mismatch`
- Label: Font subtype mismatch
- Severity: High
- Confidence: Probable
- Description: Font dictionary subtype and embedded stream key usage are inconsistent.
- Tags: font, structure, malformed

## font.structure_encoding_inconsistent

- ID: `font.structure_encoding_inconsistent`
- Label: Font encoding inconsistent
- Severity: Medium
- Confidence: Strong
- Description: Font dictionary contains inconsistent encoding declarations.
- Tags: font, structure, malformed

## font.structure_mapping_anomalous

- ID: `font.structure_mapping_anomalous`
- Label: Font mapping anomalous
- Severity: Medium
- Confidence: Probable
- Description: Font CID/GID mapping declarations are unusual and potentially evasive.
- Tags: font, structure, mapping

## font.orphaned_but_reachable

- ID: `font.orphaned_but_reachable`
- Label: Font orphaned but reachable
- Severity: Low
- Confidence: Tentative
- Description: Font appears reachable through indirect resource chains without direct page linkage.
- Tags: font, structure, render

## image.provenance_incremental_override

- ID: `image.provenance_incremental_override`
- Label: Image revision override
- Severity: Medium
- Confidence: Strong
- Description: Image object identifier appears across multiple revisions.
- Tags: image, structure, provenance

## image.structure_filter_chain_inconsistent

- ID: `image.structure_filter_chain_inconsistent`
- Label: Image filter chain inconsistent
- Severity: Medium
- Confidence: Strong
- Description: Image `/Filter` and `/DecodeParms` declarations are structurally inconsistent.
- Tags: image, filters, malformed

## image.structure_mask_inconsistent

- ID: `image.structure_mask_inconsistent`
- Label: Image mask inconsistent
- Severity: Medium
- Confidence: Probable
- Description: Image mask-related keys (`/ImageMask`, `/SMask`, `/ColorSpace`) contain contradictions.
- Tags: image, mask, malformed

## image.structure_geometry_improbable

- ID: `image.structure_geometry_improbable`
- Label: Image geometry improbable
- Severity: Low
- Confidence: Tentative
- Description: Image dimensions form extreme aspect ratios or implausible geometry.
- Tags: image, geometry, evasion

## image.orphaned_but_reachable

- ID: `image.orphaned_but_reachable`
- Label: Image orphaned but reachable
- Severity: Low
- Confidence: Tentative
- Description: Image appears reachable through indirect resource chains without direct page linkage.
- Tags: image, structure, render

## composite.font_structure_with_provenance_evasion

- ID: `composite.font_structure_with_provenance_evasion`
- Label: Font structure and provenance evasion composite
- Severity: High
- Confidence: Strong
- Description: Font structure anomalies coincide with provenance conflict signals.
- Tags: composite, font, provenance

## composite.image_structure_with_hidden_path

- ID: `composite.image_structure_with_hidden_path`
- Label: Image structure with hidden path composite
- Severity: High
- Confidence: Strong
- Description: Image structure anomalies coincide with hidden or orphaned render-path signals.
- Tags: composite, image, render

## composite.resource_external_with_trigger_surface

- ID: `composite.resource_external_with_trigger_surface`
- Label: External resource with trigger surface composite
- Severity: Medium to High (trigger-path dependent)
- Confidence: Probable to Strong (trigger-path dependent)
- Description: High-risk external resource references coincide with automatic or user-triggered action surfaces.
- Tags: composite, network, actions
- Details:
  - Relevance: external-reference risk depends on whether execution is automatic or user-triggered.
  - Meaning: correlates external reference indicators with trigger findings and classifies trigger-path initiation.
  - Metadata:
    - `composite.trigger_path` (`automatic_or_hidden` or `user_only`)
    - `composite.trigger_automatic_count`
    - `composite.trigger_user_count`
    - `composite.trigger_hidden_count`
    - `composite.trigger_unknown_count`

## composite.decode_amplification_chain

- ID: `composite.decode_amplification_chain`
- Label: Decode amplification chain
- Severity: High
- Confidence: Strong
- Description: Multiple decode-pressure signals co-occur across image/font/metadata structures.
- Tags: composite, decode, resource-exhaustion

## composite.resource_overrides_with_decoder_pressure

- ID: `composite.resource_overrides_with_decoder_pressure`
- Label: Resource overrides with decoder pressure
- Severity: High
- Confidence: Probable
- Description: Resource provenance override signals co-occur with decode-pressure indicators.
- Tags: composite, provenance, decode

## composite.injection_edge_bridge

- ID: `composite.injection_edge_bridge`
- Label: Injection edge bridge
- Severity: Medium to High (edge-dependent)
- Confidence: Probable to Strong (edge-dependent)
- Description: Deterministic bridge between related injection/action findings that forms an exploit path edge.
- Tags: composite, chain, injection, correlation
- Details:
  - Relevance: links otherwise separate findings into machine-readable exploit transitions.
  - Meaning: emitted when specific preconditions co-locate, such as:
    - `form_html_injection -> pdfjs_form_injection`
    - `*_injection -> submitform_present`
    - `*_injection -> action_remote_target_suspicious`
    - `pdfjs_annotation_injection -> annotation_action_chain`
    - `pdfjs_annotation_injection -> js_present(js.source=annotation*)`
    - `pdfjs_form_injection -> pdfjs_eval_path_risk`
    - `scattered_payload_assembly|cross_stream_payload_assembly -> *_injection`
    - `obfuscated_name_encoding -> action_*`
  - Metadata:
    - `edge.reason`: stable edge classifier (for example `scatter_to_injection`)
    - `edge.confidence`: edge confidence label
    - `edge.from`, `edge.to`: source and target finding kinds
    - `edge.shared_objects`: shared object identifiers
    - `edge.stage.from`, `edge.stage.to`: optional stage hints when available
    - `edge.initiation.from`, `edge.initiation.to`: optional initiation hints (`automatic`, `user`, `hidden`)
    - `edge.js.source.from`, `edge.js.source.to`: optional JS source classes propagated from linked findings
    - `edge.js.container_path.from`, `edge.js.container_path.to`: optional JS container paths propagated from linked findings
    - `exploit.preconditions`: concise exploit prerequisites
    - `exploit.blockers`: likely controls that block exploitation
    - `exploit.outcomes`: plausible exploit outcomes for the edge
    - `chain.confidence`: composed confidence from edge and source/target findings
    - `chain.severity`: guardrailed chain severity (execution+egress required for `High`)

## resource.declared_but_unused

- ID: `resource.declared_but_unused`
- Label: Declared resources unused
- Severity: Low
- Confidence: Probable
- Description: Page resources declare fonts/XObjects not referenced by content operators.
- Tags: resource, structure, evasion

## resource.hidden_invocation_pattern

- ID: `resource.hidden_invocation_pattern`
- Label: Hidden invocation pattern
- Severity: Medium
- Confidence: Probable
- Description: XObject invocations occur inside clipping context patterns consistent with concealed rendering.
- Tags: resource, render, evasion

## resource.operator_usage_anomalous

- ID: `resource.operator_usage_anomalous`
- Label: Anomalous operator usage
- Severity: Medium
- Confidence: Tentative
- Description: Resource invocation operator volume is unusually high.
- Tags: resource, parser-stress, evasion

## resource.inheritance_conflict_font

- ID: `resource.inheritance_conflict_font`
- Label: Font inheritance conflict
- Severity: Medium
- Confidence: Strong
- Description: Page-local font resources conflict with inherited page-tree resources.
- Tags: resource, inheritance, font

## resource.inheritance_conflict_xobject

- ID: `resource.inheritance_conflict_xobject`
- Label: XObject inheritance conflict
- Severity: Medium
- Confidence: Strong
- Description: Page-local XObject resources conflict with inherited page-tree resources.
- Tags: resource, inheritance, image

## resource.inheritance_override_suspicious

- ID: `resource.inheritance_override_suspicious`
- Label: Suspicious inheritance override
- Severity: Medium
- Confidence: Probable
- Description: Resource inheritance overrides are conflicting and potentially parser-differential.
- Tags: resource, inheritance, differential

## resource.override_outside_signature_scope

- ID: `resource.override_outside_signature_scope`
- Label: Resource override outside signature scope
- Severity: High
- Confidence: Strong
- Description: Object override appears after signature coverage boundary.
- Tags: signature, provenance, resource

## image.override_outside_signature_scope

- ID: `image.override_outside_signature_scope`
- Label: Image override outside signature scope
- Severity: High
- Confidence: Strong
- Description: Image resource override appears after signature coverage boundary.
- Tags: signature, image, provenance

## font.override_outside_signature_scope

- ID: `font.override_outside_signature_scope`
- Label: Font override outside signature scope
- Severity: High
- Confidence: Strong
- Description: Font resource override appears after signature coverage boundary.
- Tags: signature, font, provenance

## image.inline_structure_filter_chain_inconsistent

- ID: `image.inline_structure_filter_chain_inconsistent`
- Label: Inline image filter chain inconsistent
- Severity: Medium
- Confidence: Strong
- Description: Inline image filter and decode parms declarations are inconsistent.
- Tags: image, inline, malformed

## image.inline_decode_array_invalid

- ID: `image.inline_decode_array_invalid`
- Label: Inline image decode array invalid
- Severity: Low
- Confidence: Strong
- Description: Inline image `/Decode` entry has invalid non-paired value count.
- Tags: image, inline, malformed

## image.inline_mask_inconsistent

- ID: `image.inline_mask_inconsistent`
- Label: Inline image mask inconsistent
- Severity: Medium
- Confidence: Probable
- Description: Inline image mask semantics are contradictory.
- Tags: image, inline, mask

## font.type3_charproc_complexity_high

- ID: `font.type3_charproc_complexity_high`
- Label: Type 3 charproc complexity high
- Severity: Medium
- Confidence: Probable
- Description: Type 3 glyph programs have unusually high complexity.
- Tags: font, type3, complexity

## font.type3_charproc_resource_abuse

- ID: `font.type3_charproc_resource_abuse`
- Label: Type 3 charproc resource abuse
- Severity: High
- Confidence: Probable
- Description: Type 3 glyph programs invoke resource/state operators in suspicious ways.
- Tags: font, type3, resource

## font.type3_charproc_recursion_like_pattern

- ID: `font.type3_charproc_recursion_like_pattern`
- Label: Type 3 recursion-like pattern
- Severity: Medium
- Confidence: Tentative
- Description: Type 3 glyph programs show deep/unbalanced graphics state nesting.
- Tags: font, type3, recursion

## font.cmap_range_overlap

- ID: `font.cmap_range_overlap`
- Label: CMap range overlap
- Severity: Medium
- Confidence: Strong
- Description: ToUnicode CMap contains overlapping ranges.
- Tags: font, cmap, malformed

## font.cmap_cardinality_anomalous

- ID: `font.cmap_cardinality_anomalous`
- Label: CMap cardinality anomalous
- Severity: Medium
- Confidence: Probable
- Description: ToUnicode CMap range count is unusually large.
- Tags: font, cmap, evasion

## font.cmap_subtype_inconsistent

- ID: `font.cmap_subtype_inconsistent`
- Label: CMap subtype inconsistent
- Severity: Medium
- Confidence: Strong
- Description: Font subtype and ToUnicode CMap style are inconsistent.
- Tags: font, cmap, structure

### Calibration Notes: Image/Font Structural Follow-up (2026-02-17)

- Deterministic structural contradictions (for example inheritance conflicts, CMap overlaps, signature-scope overrides) are calibrated at `Strong` confidence.
- Heuristic/high-volume behavioural patterns (for example operator density and Type 3 complexity spikes) remain `Probable` or `Tentative` unless corroborated.
- Escalation rule: when provenance override signals co-occur with structural contradictions, emit correlated `High` severity composite findings (`composite.resource_overrides_with_decoder_pressure`, `composite.decode_amplification_chain`) for triage priority.

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
  - Relevance: viewer-dependent rich media runtimes can expose interactive execution paths.
  - Meaning: RichMedia annotations/dictionaries are present.
  - Chain usage: render-stage contextual signal; severity remains conservative without execute corroboration.
  - Metadata:
    - `viewer.feature=richmedia`
    - `viewer.support_required=true`
    - `viewer.support_matrix=viewer_dependent_richmedia_runtime`
    - `renderer.profile=richmedia_viewer`
    - `renderer.precondition=richmedia_runtime_enabled`
    - `richmedia.trigger_context` (`feature_present`, `action_linked`)
    - `chain.stage=render`, `chain.capability=richmedia_surface`, `chain.trigger=viewer_feature`

## richmedia_3d_structure_anomaly

- ID: `richmedia_3d_structure_anomaly`
- Label: 3D rich-media structure anomaly
- Description: U3D/PRC stream structure deviates from bounded sanity checks and may indicate malformed or exploit-oriented payload material.
- Tags: 3d, decoder, richmedia
- Details:
  - Relevance: malformed 3D payloads can trigger decoder edge cases and parser instability.
  - Meaning: stream-level checks found structural inconsistencies in U3D/PRC data.
  - Chain usage: used as 3D payload-stage risk indicator for renderer exploit triage.
  - Metadata:
    - `media_type` (`u3d` or `prc`)
    - `richmedia.3d.decode_success`
    - `richmedia.3d.structure_anomalies`
    - `richmedia.3d.filter_depth`
    - `richmedia.3d.decoded_expansion_ratio`
    - `richmedia.3d.encoded_stream_bytes`
    - `richmedia.3d.declared_stream_length` (when `/Length` is present)
    - `richmedia.3d.block_count_estimate` (U3D)
    - `richmedia.3d.block_table_consumed_bytes` (U3D)
    - `richmedia.3d.block_table_trailing_bytes` (U3D)
    - `stream.entropy`

## richmedia_3d_decoder_risk

- ID: `richmedia_3d_decoder_risk`
- Label: 3D rich-media decoder risk correlation
- Description: 3D structure anomalies co-occur with decoder-risk factors (high entropy, deep filter chain, or decode instability).
- Tags: 3d, correlation, decoder, richmedia
- Details:
  - Relevance: highlights high-risk 3D payloads likely to stress or exploit decoding paths.
  - Meaning: malformed structure appears alongside one or more decoder-risk multipliers.
  - Chain usage: escalation-level finding for immediate containment and replay.
  - Metadata:
    - `richmedia.3d.decoder_correlation`
    - `richmedia.3d.structure_anomalies`
    - `richmedia.3d.filter_depth`
    - `stream.entropy`

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

## shadow_hide_attack

- ID: `shadow_hide_attack`
- Label: Shadow hide attack indicators
- Description: Post-signature revision added overlay annotation/form appearances that can obscure signed content.
- Tags: evasion, signature, structure
- Details:
  - Relevance: signed-content integrity bypass.
  - Meaning: overlays added after signing can hide previously signed visual content.
  - Chain usage: used as post-signature tampering indicator.

## shadow_replace_attack

- ID: `shadow_replace_attack`
- Label: Shadow replace attack indicators
- Description: Post-signature revision changed page/content object semantics compared with the signed revision.
- Tags: evasion, signature, structure
- Details:
  - Relevance: signed-content integrity bypass.
  - Meaning: shadowed page/content objects differ across the signature boundary.
  - Chain usage: used as post-signature replacement indicator.

## shadow_hide_replace_attack

- ID: `shadow_hide_replace_attack`
- Label: Shadow hide-and-replace attack indicators
- Description: Post-signature revision combines overlay additions with content replacement.
- Tags: evasion, signature, structure
- Details:
  - Relevance: high-confidence signed-content tampering.
  - Meaning: both hide and replace patterns are present across the signature boundary.
  - Chain usage: used as critical shadow-attack composite indicator.

## certified_doc_manipulation

- ID: `certified_doc_manipulation`
- Label: Certified document manipulation indicators
- Description: Post-certification visual updates were detected and assessed against DocMDP permission constraints.
- Tags: crypto, evasion, signature, structure
- Details:
  - Relevance: certification-integrity bypass and trust abuse.
  - Meaning: annotation and/or signature-field overlays were added after certification, with severity/confidence adjusted by P1-P3 policy compliance.
  - Chain usage: used as certified tampering indicator with cross-revision diff context.

## revision_page_content_changed

- ID: `revision_page_content_changed`
- Label: Revision page content changed
- Description: Page/content objects changed across revisions, indicating likely visual content modification.
- Tags: evasion, revision, structure
- Details:
  - Relevance: post-revision visual tampering risk.
  - Meaning: /Page or content-related object semantics differ between revision boundaries.
  - Chain usage: used as revision-level visual mutation indicator.

## revision_annotations_changed

- ID: `revision_annotations_changed`
- Label: Revision annotations changed
- Description: Annotation objects were added or modified across revisions.
- Tags: evasion, revision, structure
- Details:
  - Relevance: overlay and interaction-surface mutation risk.
  - Meaning: annotation deltas were observed in incremental updates.
  - Chain usage: used as annotation-based evasion/tampering indicator.

## revision_catalog_changed

- ID: `revision_catalog_changed`
- Label: Revision catalog changed
- Description: Document catalog/root structures changed across revisions.
- Tags: evasion, revision, structure
- Details:
  - Relevance: behaviour-level document mutation.
  - Meaning: catalog-level semantics changed (e.g., action roots or document structure controls).
  - Chain usage: used as high-signal structural tampering indicator.

## revision_anomaly_scoring

- ID: `revision_anomaly_scoring`
- Label: Revision anomaly scoring
- Description: Revision-level anomaly scoring indicates unusual incremental-update mutation patterns.
- Tags: evasion, revision, scoring
- Details:
  - Relevance: prioritised triage for suspicious update sequences.
  - Meaning: one or more revisions exceed anomaly thresholds based on weighted structural/behavioural deltas.
  - Chain usage: used as aggregate revision-risk indicator.

## parse_disagreement

- ID: `parse_disagreement`
- Label: Parser disagreement detected
- Description: Carved objects disagree with parsed revisions.
- Tags: evasion, structure
- Details:
  - Relevance: parser disagreement can indicate hidden revisions or parsing tricks.
  - Meaning: carved object definitions differ from the primary parser view.
  - Chain usage: highlights stealthy payload delivery.

## parser_divergence_risk

- ID: `parser_divergence_risk`
- Label: Parser divergence risk
- Description: Multiple divergence indicators suggest the PDF may render differently across readers or parser strictness levels.
- Tags: evasion, parser, structure
- Details:
  - Relevance: reader-dependent rendering and detection bypass risk.
  - Meaning: combined indicators (filter divergence, content anomalies, xref/linearisation signals) exceed the divergence threshold.
  - Chain usage: aggregate parser-evasion indicator.

## renderer_behavior_divergence_known_path

- ID: `renderer_behavior_divergence_known_path`
- Label: Known renderer behaviour divergence path
- Description: Known reader-behaviour divergence paths were detected across action, script, or form surfaces.
- Tags: parser, renderer, divergence
- Details:
  - Relevance: highlights behaviour deltas across Acrobat, Pdfium, and Preview profiles.
  - Meaning: one or more known divergence paths (for example open-action JavaScript or interactive XFA pathways) were observed.
  - Chain usage: prioritisation signal for multi-renderer replay and policy hardening.
  - Metadata:
    - `renderer.known_paths` (csv): matched divergence catalogue path identifiers.
    - `renderer.catalogue_version` (string): renderer divergence catalogue revision.
    - `renderer.catalogue_entries` (csv): stable ordered catalogue entries matched for this file.
    - `renderer.profile_deltas` (string): per-profile severity/impact delta summary.
    - `renderer.executable_path_variance` (int): number of distinct divergence paths detected.
    - `renderer.risk_score` (int): aggregate divergence score.
    - `renderer.automatic_trigger` (bool-like string): whether automatic trigger context was present.
    - `renderer.catalogue.family.action_handling` (bool-like string): action-handling divergence family matched.
    - `renderer.catalogue.family.js_execution_policy` (bool-like string): JS policy divergence family matched.
    - `renderer.catalogue.family.attachment_open` (bool-like string): attachment/open divergence family matched.
    - `renderer.catalogue.family_count` (int): number of divergence families matched.

## renderer_behavior_exploitation_chain

- ID: `renderer_behavior_exploitation_chain`
- Label: Renderer behaviour exploitation chain
- Description: Automatic trigger paths and high-risk renderer surfaces co-occur with script/action capabilities, consistent with exploitation-chain setup.
- Tags: chain, renderer, divergence
- Details:
  - Relevance: elevated exploitation risk where trigger, execution, and high-risk surface signals overlap.
  - Meaning: renderer divergence is not isolated; it is part of a multi-signal exploitation chain.
  - Chain usage: high-priority escalation signal for containment and replay.
  - Metadata:
    - `renderer.known_paths`
    - `renderer.catalogue_version`
    - `renderer.catalogue_entries`
    - `renderer.profile_deltas`
    - `renderer.risk_score`
    - `renderer.executable_path_variance`
    - `renderer.catalogue.family_count`
    - `renderer.chain_components`

## duplicate_stream_filters

- ID: `duplicate_stream_filters`
- Label: Duplicate stream payload with divergent filters
- Description: Identical stream payload bytes are present under different filter chains.
- Tags: evasion, filters, parser
- Details:
  - Relevance: parser-dependent decode behaviour.
  - Meaning: the same payload is wrapped with conflicting filter declarations.
  - Chain usage: low-level parser divergence building block.

## content_stream_anomaly

- ID: `content_stream_anomaly`
- Label: Content stream syntax anomaly
- Description: Decoded content stream includes explicit unknown operator, operand arity, or operand type mismatch counts.
- Tags: content, evasion, parser
- Details:
  - Relevance: malformed content streams can render differently across readers.
  - Meaning: operator set or operand validation (arity/type) deviates from expected content syntax.
  - Chain usage: parser-divergence signal for triage and replay.

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
  - Relevance: media/rendition surfaces may fetch or activate external media depending on viewer behaviour.
  - Meaning: `/Sound`, `/Movie`, or `/Rendition` structures are present.
  - Chain usage: render-stage contextual signal; egress semantics are attached when external rendition targets are detected.
  - Metadata:
    - `viewer.feature=sound_movie_rendition`
    - `viewer.support_required=true`
    - `viewer.support_matrix=viewer_dependent_media_runtime`
    - `renderer.profile=media_viewer`
    - `renderer.precondition=media_runtime_enabled`
    - `media.rendition_present`
    - optional `media.external_target`, `egress.channel=media_rendition`, `egress.target_kind=remote`, `egress.user_interaction_required=true`
    - `chain.stage=render`, `chain.capability=media_surface`, `chain.trigger=viewer_feature`

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

## xfa_entity_resolution_risk

- ID: `xfa_entity_resolution_risk`
- Label: XFA XML entity-resolution risk
- Description: XFA payload includes XML DTD/entity or external-reference constructs that can increase backend ingest risk when parser hardening is not enforced.
- Tags: xfa, xml, xxe
- Details:
  - Relevance: backend parser hardening and XXE-adjacent risk.
  - Meaning: XFA contains DOCTYPE/entity declarations or external schema/include references that should be treated as risky for downstream XML ingestion.
  - Chain usage: used as ingest-risk context and enrichment for XFA abuse triage.
  - Metadata:
    - `xfa.dtd_present` (bool): whether DOCTYPE/DTD marker was observed.
    - `xfa.entity_keyword_count` (int): number of `<!ENTITY` declarations observed.
    - `xfa.xml_entity_count` (int): number of XML entity declarations observed.
    - `xfa.external_entity_refs` (int): number of external entity declarations (`SYSTEM`/`PUBLIC`).
    - `xfa.external_reference_tokens` (int): external schema/include reference markers observed (`xsi:schemaLocation`, `xi:include` hrefs).
    - `backend.ingest_risk` (string): derived ingest risk level (`low`, `medium`, `high`).

## xfa_backend_xxe_pattern

- ID: `xfa_backend_xxe_pattern`
- Label: XFA backend XXE pattern
- Description: XFA payload contains external XML entity declarations consistent with backend XXE-style ingestion risk patterns.
- Tags: xfa, xml, xxe, backend
- Details:
  - Relevance: potential backend-side data exposure or SSRF-like resolution behaviour where parser hardening is absent.
  - Meaning: external entity declarations are present and should be treated as high-risk on ingest paths.
  - Chain usage: high-priority correlation signal for XFA pipelines and backend processing workflows.
  - Metadata:
    - `xfa.dtd_present`
    - `xfa.entity_keyword_count`
    - `xfa.xml_entity_count`
    - `xfa.external_entity_refs`
    - `xfa.external_reference_tokens`
    - `backend.ingest_risk`

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
  - Metadata:
    - `stage.count` (int): number of stage indicators detected for the payload.
    - `stage.sources` (string): stage source families (for example `javascript,action-trigger`).
    - `stage.fetch_targets` (string): resolved fetch/action targets if known.
    - `stage.fetch_target_count` (int): number of unique resolved fetch/action targets.
    - `stage.execution_bridge` (bool-like string): whether an execution bridge was observed.
    - `stage.execution_bridge_source` (string): bridge evidence family (`action_trigger`, `action_target`, `embedded_file`, or `none`).
    - `stage.trigger_edges` (string): triggering graph edge types observed for the stage object.

## staged_remote_template_fetch_unresolved

- ID: `staged_remote_template_fetch_unresolved`
- Label: Staged remote template fetch (unresolved bridge)
- Description: JavaScript indicates remote template or form-fetch behaviour, but a concrete execution bridge is not yet resolved.
- Tags: chain, supply-chain, staging
- Details:
  - Relevance: catches likely staged delivery patterns before an explicit execution bridge is proven.
  - Meaning: template/fetch indicators appear in script content with insufficient downstream execution linkage.
  - Chain usage: triage-first signal for follow-up correlation with action and execution findings.
  - Metadata:
    - `stage.sources`
    - `stage.fetch_targets`
    - `stage.fetch_target_count`
    - `stage.count`
    - `stage.execution_bridge`
    - `stage.execution_bridge_source`
    - `stage.trigger_edges`
    - `stage.remote_template_indicators`

## supply_chain_update_vector

- ID: `supply_chain_update_vector`
- Label: Update mechanism references
- Description: JavaScript references update or installer logic.
- Tags: general
- Details:
  - Relevance: supply-chain style behavior.
  - Meaning: indicators suggest staged download/update/persistence logic.
  - Chain usage: used as multi-step delivery or persistence stages.

## uri_present (retired)

- ID: `uri_present`
- Status: Retired (no longer emitted)
- Replacement: use `uri_listing` for document-level URI presence and `uri_content_analysis` for per-URI suspicious analysis.
- Notes:
  - Kept for compatibility in historical reports and feature vectors.
  - New scans should not emit this finding kind.

## uri_listing

- ID: `uri_listing`
- Label: URI(s) present
- Severity: Info → Low → Medium → High (volume/domains thresholds)
- Description: Aggregated URI listing; records every discovered URI plus contextual flags for up to 50 entries while still escalating severity when URI volume/diversity grows.
- Tags: action, external, summary
- Details:
  - Relevance: documents with many URIs increase attack surface, but per-URI noise is captured centrally.
  - Meaning: the finding collects `uri.count_*`, `uri.schemes`, `uri.domains_sample`, `uri.max_severity`, `uri.max_confidence`, and `uri.risk_band_counts` plus `uri.list.*` metadata (preview/canonical/chain_depth/visibility/trigger/suspicious/severity/confidence) so downstream consumers can inspect URI risk without flooding the report. `uri.suspicious_count` highlights how many URIs matched the `UriContentDetector` heuristics.
  - Chain usage: acts as a summary node that can be joined with other findings (e.g., suspicious URIs, action chains) and remains low-noise even when hundreds of links are present.

## xref_phantom_entries

- ID: `xref_phantom_entries`
- Label: Xref phantom entries detected
- Description: Xref deviations indicate offsets or trailer references that do not resolve cleanly.
- Tags: evasion, structure, xref
- Details:
  - Relevance: malformed xref structures can be used to confuse parsers and hide malicious content.
  - Meaning: offsets or trailer lookups in the xref chain are inconsistent with parseable object structure.
  - Chain usage: structural evasion indicator; combine with other findings for escalation.

## empty_objstm_padding

- ID: `empty_objstm_padding`
- Label: Sparse ObjStm padding detected
- Description: One or more object streams declare many embedded objects but contain little or no expanded content.
- Tags: evasion, structure, objstm
- Details:
  - Relevance: sparse object streams can be used as structural padding to dilute suspicious content density.
  - Meaning: declared embedded-object counts are inconsistent with expanded object presence.
  - Chain usage: structural evasion indicator; correlate with other concealment findings.

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
  - Metadata:
    - `graph.evasion_kind=xref_conflict`
    - `graph.depth`
    - `graph.conflict_count`
    - `xref.integrity.level`
    - `chain.stage=decode`, `chain.capability=graph_xref_evasion`, `chain.trigger=xref`

## object_reference_cycle

- ID: `object_reference_cycle`
- Label: Object reference cycle
- Description: Circular object-reference chain detected in object graph traversal.
- Tags: evasion, structure, graph
- Details:
  - Relevance: cycle-heavy graphs can hide exploit paths and stress parser traversal.
  - Meaning: cycle classification and overlap with execute-capable objects are recorded.
  - Chain usage: decode-stage structural evasion signal; prioritise when execute overlap is non-zero.
  - Metadata:
    - `cycle.length`
    - `cycle.type`
    - `graph.evasion_kind` (`reference_cycle` or `cycle_near_execute`)
    - `graph.depth`
    - `graph.conflict_count`
    - `graph.execute_overlap_count`
    - `chain.stage=decode`, `chain.capability=graph_cycle`, `chain.trigger=object_graph`

## object_reference_depth_high

- ID: `object_reference_depth_high`
- Label: High object reference depth
- Description: Object reference depth exceeds safe traversal threshold.
- Tags: evasion, structure, graph
- Details:
  - Relevance: deep indirection can conceal exploit staging and increase parser cost.
  - Meaning: maximum observed reference depth is above threshold and may indicate deliberate indirection.
  - Chain usage: decode-stage structural evasion signal.
  - Metadata:
    - `reference.max_depth`
    - `graph.evasion_kind=deep_indirection`
    - `graph.depth`
    - `graph.conflict_count`
    - `graph.execute_surface_count`
    - `chain.stage=decode`, `chain.capability=graph_indirection`, `chain.trigger=object_graph`

## trailer_root_conflict

- ID: `trailer_root_conflict`
- Label: Conflicting trailer /Root references
- Description: Multiple xref sections declare different trailer /Root references.
- Tags: evasion, structure, trailer
- Details:
  - Relevance: conflicting root references can steer different parsers to different document states.
  - Meaning: incremental update chain has inconsistent catalogue root targets.
  - Chain usage: structural evasion indicator; useful when correlating revision tampering.

## null_object_density

- ID: `null_object_density`
- Label: High null object density
- Description: Object graph contains an unusually high density of null placeholder objects.
- Tags: evasion, structure
- Details:
  - Relevance: null-padding can dilute malicious signal density and hinder triage.
  - Meaning: a large fraction of objects are structural placeholders with no content.
  - Chain usage: low-confidence structural evasion signal that should be aggregated with other indicators.

## structural_decoy_objects

- ID: `structural_decoy_objects`
- Label: Unreachable decoy object cluster
- Description: A substantial set of non-null objects is unreachable from the catalog root.
- Tags: evasion, structure
- Details:
  - Relevance: unreachable object clusters may hide alternate payload paths or padded decoys.
  - Meaning: reachability walk from trailer `/Root` does not include a large object subset.
  - Chain usage: structural evasion indicator suited for composite scoring.

## structural_decoy_objects_scan_limited

- ID: `structural_decoy_objects_scan_limited`
- Label: Structural decoy scan limited
- Description: Decoy object reachability scan was skipped because object count exceeded the configured cap.
- Tags: diagnostic, performance, structure
- Details:
  - Relevance: large object graphs can exceed safe detector budgets.
  - Meaning: analysis is intentionally bounded to protect throughput and stability.
  - Chain usage: operational signal indicating partial structural coverage.

## structural_evasion_composite

- ID: `structural_evasion_composite`
- Label: Composite structural evasion pattern
- Description: Detected 3 or more structural evasion indicators in the same document.
- Tags: evasion, structure, composite
- Details:
  - Relevance: multiple weak structural indicators together substantially increase malicious-evasion likelihood.
  - Meaning: detector aggregates distinct structural signals (`evasion.composite_indicators`) using a threshold gate.
  - Chain usage: prioritisation finding for analyst triage and correlation workflows.

## launch_obfuscated_executable

- ID: `launch_obfuscated_executable`
- Label: Correlated obfuscated executable launch
- Description: Launch action targets an embedded executable with high entropy.
- Tags: action, embedded, correlation
- Details:
  - Relevance: automatic execution tied to obfuscated payloads is high risk.
  - Meaning: correlation of launch and embedded executable strengthens confidence.
  - Chain usage: delivery/execution stage.

## composite.embedded_relationship_action

- ID: `composite.embedded_relationship_action`
- Label: Embedded relationship action bridge
- Severity: High
- Confidence: Probable to Strong
- Description: Embedded artefact type mismatch is linked to an executable action surface.
- Tags: composite, embedded, action, relationship
- Details:
  - Relevance: links disguised embedded payload indicators with action execution surfaces.
  - Meaning: emitted when `embedded_type_mismatch` is linked to launch/remote action findings by object or embedded hash lineage.
  - Chain usage: bridge from attachment disguise to execution stage.
  - Metadata:
    - `composite.link_reason` (`object` or `hash`)
    - `embedded.mismatch_axes`
    - `exploit.preconditions`
    - `exploit.blockers`
    - `exploit.outcomes`

## composite.graph_evasion_with_execute

- ID: `composite.graph_evasion_with_execute`
- Label: Graph evasion with execute surface composite
- Severity: High
- Confidence: Probable
- Description: Structural graph-evasion indicators co-occur with executable surfaces.
- Tags: composite, graph, evasion, execute
- Details:
  - Relevance: exploit delivery often pairs graph-level evasion with action/JS execution surfaces.
  - Meaning: correlates structural graph findings (xref conflicts, cycles, shadowing, deep indirection) with execute-stage findings.
  - Chain usage: prioritisation composite for evasive execute-capable documents.
  - Metadata:
    - `graph.evasion_kinds`
    - `graph.evasion_count`
    - `execute.surface_count`
    - `exploit.preconditions`
    - `exploit.blockers`
    - `exploit.outcomes`

## composite.richmedia_execute_path

- ID: `composite.richmedia_execute_path`
- Label: Rich media execute-path bridge
- Severity: Medium to High
- Confidence: Probable
- Description: Rich media/3D surfaces co-locate with execute or egress findings.
- Tags: composite, richmedia, 3d, action, chain
- Details:
  - Relevance: viewer-dependent media features can form exploit paths when linked to execute/egress surfaces.
  - Meaning: emitted when richmedia findings share object lineage with action/JS execute findings.
  - Chain usage: bridge from render-stage richmedia surfaces into execute/egress stages.
  - Metadata:
    - `edge.from`
    - `edge.to`
    - `edge.shared_objects`
    - `exploit.preconditions`
    - `exploit.blockers`
    - `exploit.outcomes`

## action_chain_malicious

- ID: `action_chain_malicious`
- Label: Malicious automatic action chain
- Description: Complex action chain triggers automatically and executes JavaScript.
- Tags: action, chain, correlation
- Details:
  - Relevance: automatic chains are a hallmark of malware.
  - Meaning: combined evidence of chain depth, trigger, and JS increases signal.
  - Chain usage: multi-stage activation without user interaction.
  - Metadata:
    - `js.source_classes`: source containers represented in correlated JS findings.
    - `js.container_paths`: normalised container paths represented in correlated JS findings.
    - `js.object_ref_chains`: object lineage paths from correlated JS findings.

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
