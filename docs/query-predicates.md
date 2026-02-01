# Query predicate reference

This guide documents the `--where` predicate filters for `sis query`.

## Supported queries

Predicate filtering is supported for:
- `js`, `js.count`
- `embedded`, `embedded.count`
- `xfa`, `xfa.count`
- `xfa.scripts`, `xfa.scripts.count`
- `swf`, `swf.count`, `swf.actionscript`, `swf.actionscript.count`, `swf.extract`, `swf.extract.count`
- `media.3d`, `media.3d.count`, `media.audio`, `media.audio.count`
- `images`, `images.count`, `images.jbig2`, `images.jpx`, `images.ccitt`, `images.risky`, `images.malformed`
- `objects.list`, `objects.with`, `objects.count`
- `urls`, `urls.count`
- `events`, `events.document`, `events.page`, `events.field`, `events.count`
- `findings`, `findings.count`, `findings.kind`, `findings.high`, `findings.medium`, `findings.low`, `findings.info`, `findings.critical`
- `findings.composite`, `findings.composite.count`
- `correlations`, `correlations.count`
- finding shortcut queries (for example `embedded.executables`, `launch.external`, `streams.high-entropy`) and their `.count` variants
- `encryption`, `encryption.weak`, `encryption.weak.count`
- `streams.entropy`

## Feature vector highlights

While `features` is not a predicate-driven query, the exported vector (CSV/JSON/JSONL) includes the same counts you can probe via `--where` elsewhere. The final entries in that vector map to the Stage 8 additions: `xfa.present`, `xfa.*` (payload/script/submit/sensitive-field counts), `encryption.*` (encryption presence, key length, entropy stats, encrypted embedded files) and `filters.*` (unusual/invalid filter counts and depth). Use `docs/ml-features.md` for the canonical index mapping and to ensure your ML pipeline normalises these inputs consistently.

## Fields

Predicates can use these fields:
- `length`: size in bytes for the underlying payload or text field
- `entropy`: Shannon entropy (0-8 range) for the payload or text field
- `filter`: query-specific category (see mappings below)
- `type`: high-level category name for the record
- `subtype`: query-specific subtype (see mappings below)
- `name`: record name or filename when available
- `magic`: magic classifier label when available (for example `pe`, `zip`, `FWS`)
- `severity`: finding severity (findings queries only, alias for `filter`)
- `confidence`: finding confidence level (findings queries only)
- `surface`: finding attack surface (findings queries only)
- `kind`: finding kind (findings queries only, alias for `subtype`)
- `objects`: finding related object count (findings queries only)
- `evidence`: finding evidence span count (findings queries only)
- `width`: image width in pixels (image queries only)
- `height`: image height in pixels (image queries only)
- `pixels`: total pixel count (image queries only)
- `risky`: boolean flag for risky image formats (image queries only)
- `format`: alias for `subtype` (image queries only)

## Field mappings by query

### JavaScript (`js`, `js.count`)
- `length`: extracted JavaScript bytes (decoded or raw depending on flags)
- `entropy`: extracted JavaScript bytes
- `type`: `Stream` or `String`
- `filter`: stream `/Filter` name (if present)
- `subtype`: stream `/Subtype` name (if present)

### Embedded files (`embedded`, `embedded.count`)
- `length`: extracted embedded payload bytes
- `entropy`: extracted embedded payload bytes
- `type`: `Stream`
- `filter`: stream `/Filter` name (if present)
- `subtype`: stream `/Subtype` name (if present)
- `name`: embedded filename
- `magic`: magic classifier for payload bytes (for example `pe`, `zip`, `script`)

### XFA scripts (`xfa.scripts`, `xfa.scripts.count`)
- `length`: extracted script bytes
- `entropy`: extracted script bytes entropy
- `type`: `XfaScript`
- `filter`: `xfa`
- `subtype`: `script`
- `name`: generated script filename

### XFA forms (`xfa`, `xfa.count`)
- `length`: decoded XFA payload size
- `script_count`: number of `<script>`/`<execute>` occurrences found
- `type`: `XfaForm`
- `filter`: `xfa`
- `url`: submit target (per `xfa.submit` finding)
- `field`: sensitive field name (per `xfa.sensitive` finding)
- `has_doctype`: `true` when DOCTYPE guard triggered (matches `xfa.has_doctype`)
- `submit_urls`: JSON array of detected submit URLs
- `sensitive_fields`: JSON array of field names reported for the payload

### SWF queries (`swf`, `swf.count`, `swf.actionscript`, `swf.actionscript.count`, `swf.extract`, `swf.extract.count`)
- `length`: extracted SWF bytes (decoded or raw depending on flags)
- `entropy`: extracted SWF bytes entropy
- `type`: `SwfContent`
- `filter`: stream `/Filter` name (if present)
- `subtype`: `swf`
- `name`: generated SWF filename
- `magic`: SWF header tag (`FWS`, `CWS`, `ZWS`)
- `media_type`: always `swf`
- `size_bytes`: stream size before extraction limits
- `swf.version`: SWF header version (when parsing succeeds)
- `swf.decompressed_bytes`: bytes parsed during ActionScript analysis
- `swf.declared_length`: length from the SWF header (used to enforce the 10 MB limit)
- `swf.action_tag_count`: number of ActionScript tags scanned
- `swf.action_tags`: comma-separated list of ActionScript tag names

### Images (`images*`)
- `length`: image stream bytes (decoded or raw depending on flags)
- `entropy`: image stream bytes entropy
- `type`: `Image`
- `filter`: image stream `/Filter` list (if present)
- `subtype`: detected image format (`JBIG2`, `JPX`, `JPEG`, `PNG`, `CCITT`, `TIFF`, `Unknown`)
- `width`: `/Width` value when available
- `height`: `/Height` value when available
- `pixels`: `width * height` when available
- `risky`: `true` for `JBIG2`, `JPX`, `CCITT` formats
- `format`: alias for `subtype`

### Media queries (`media.3d`, `media.3d.count`, `media.audio`, `media.audio.count`)
- `type`: `Media3D` or `MediaAudio`
- `filter`: stream `/Filter` name (if present)
- `subtype`: media type label (`u3d`, `prc`, `mp3`, `mp4`, or `unknown`)
- `media_type`: format label (`u3d`, `prc`, `mp3`, `mp4`, `unknown`)
- `size_bytes`: stream payload length
- `name`: generated handle derived from the object identifier
- `object`: object reference string (included in `meta`)

### Objects (`objects.list`, `objects.with`, `objects.count`)
- `length`: stream length (decoded where possible; falls back to `/Length`)
- `entropy`: stream bytes entropy (0 when not available)
- `type`: object atom type (for example `Stream`, `Dict`, `Array`, `String`)
- `filter`: stream `/Filter` name (if present)
- `subtype`: dictionary or stream `/Subtype` name (if present)

### URLs (`urls`, `urls.count`)
- `length`: URL string length
- `entropy`: URL string bytes
- `type`: `Url`

### Events (`events*`)
- `length`: `action_details` string length
- `entropy`: `action_details` bytes
- `type`: `Event`
- `filter`: event level (`document`, `page`, `field`)
- `subtype`: `event_type`

### Findings (`findings*`)
- `length`: finding `description` length
- `entropy`: finding `description` bytes
- `type`: `Finding`
- `filter`: severity (`info`, `low`, `medium`, `high`, `critical`)
- `subtype`: finding `kind`
  - `severity`: severity (`info`, `low`, `medium`, `high`, `critical`)
  - `impact`: impact bucket (`critical`, `high`, `medium`, `low`, `none`)
  - `confidence`: confidence (`certain`, `strong`, `probable`, `tentative`, `weak`, `heuristic`)
  - `action_type`: action taxonomy (for example `Launch`, `JavaScript`, `GoTo`)
- `action_target`: where the action is headed (for example `uri:http://example.com`)
- `action_initiation`: how the action is triggered (`automatic`, `user`, `hidden`, `deep`)
- `reader.impact.<profile>`: severity bucket seen by each reader profile (`acrobat`, `pdfium`, `preview`)
- `reader.impact.summary`: comma-separated `<profile>:<severity>/<impact>` summary (for example `acrobat:critical/critical,pdfium:low/low`)
- `surface`: attack surface (for example `embedded_files`, `actions`, `streams_and_filters`)
- `kind`: finding kind (same as `subtype`)
- `objects`: number of related objects
- `meta.<key>`: detector metadata entries such as `meta.cve`, `meta.attack_surface`, `meta.launch.target_path`, or `meta.reader.impact.summary`. Use `meta.cve` to focus on CVE-driven heuristics and `meta.attack_surface` to group detections by the taxonomy referenced in `docs/threat-intel-tracker.md`.
- `evidence`: number of evidence spans

### Encryption queries
- `type`: `Finding`
- `subtype`: `encryption_present`, `encryption_key_short`, or `crypto_weak_algo`
- `kind`: alias for `subtype`
- `crypto.algorithm`: detected encryption algorithm (`RC4-40`, `AES-256`)
- `crypto.key_length`: key length in bits (extracted from `/Length`)
- `crypto.version`: `/V` value from the encryption dictionary
- `crypto.revision`: `/R` value from the encryption dictionary
- `crypto.issue`: description of the weakness (sourced from `crypto_weak_algo`)
- `filter`: severity of the finding
- `objects`: typically `["trailer"]` or `["signature"]`
- `evidence`: spans covering the trailer or signature dict

### Streams entropy (`streams.entropy`)
- `length`: decoded stream length (subject to decode limits)
- `entropy`: entropy computed on sliding windows (0-8 scale)
- `sample_size_bytes`: bytes consumed for entropy sampling (max 10 MB)
- `stream.magic_type`: classifier label (`zip`, `rar`, `unknown`, etc.)
- `stream.sample_timed_out`: `true` if the sampling hit the timeout budget
- `filter`: stream `/Filter` value (if present)
- `subtype`: `/Subtype` name (if present)
- `name`: generated handle such as `123 0 obj`
- `meta`: includes `stream.size_bytes`, `stream.sample_size_bytes`, `stream.magic_type`, and `stream.sample_timed_out`

## Examples

```bash
# Large JavaScript payloads with high entropy
sis query js file.pdf --where "length > 1024 AND entropy > 5.5"

# Events triggered at document level
sis query events file.pdf --where "filter == 'document'"

# High severity findings
sis query findings file.pdf --where "filter == 'high'"

# CVE-specific detections (e.g., limit to the FreeType gvar heuristic)
sis query findings file.pdf --where "meta.cve == 'CVE-2025-27363'"

# Streams using FlateDecode
sis query objects.with Stream file.pdf --where "filter == '/FlateDecode'"

# Large, risky images
sis query images file.pdf --where "risky == true AND pixels > 1000000"

# PNG images with high entropy
sis query images file.pdf --where "format == 'PNG' AND entropy > 7.5"

# Reader divergence example
sis query findings file.pdf --where "reader.impact.preview == 'low'"

# Filter chain findings with allowlist misses
sis query filters.unusual file.pdf --where "violation_type == 'allowlist_miss'"

# Filter order violations involving Crypt
sis query filters.invalid file.pdf --where "violation_type == 'crypt_not_outermost'"

# Filter chains flagged in strict mode
sis query filters.unusual file.pdf --where "violation_type == 'strict_mode'"

# Image filters chained with compression
sis query filters.unusual file.pdf --where "violation_type == 'image_with_compression'"

## Image predicate metadata

When querying `images`, `images.malformed` or other image shortcuts, the predicate context exposes the dynamic inspection metadata produced by the static and decode pipelines:

- `width`, `height`, `pixels`: reported dimensions and total pixels.
- `format`: detected format label (`JPEG`, `JBIG2`, `JPX`, `CCITT`, etc.).
- `image.decode`: decode outcome (`success`, `failed`, `skipped`).
- `image.decode_error`: decoder message when `image.decode == 'failed'`.
- `image.decode_skipped`: skip reason (`too_many_images`, `budget_exceeded`, `timeout`).
- `image.decode_too_large_reason`: whether `bytes` or `pixels` limits triggered `image.decode_too_large`.
- `image.decode_ms`: measured decode time in milliseconds.
- `image.filters`: comma-joined filter chain labels.

Use these fields to target specific decode behaviours:

```bash
sis query sample.pdf images --deep --where "image.decode == 'failed'"
sis query sample.pdf images.malformed --where "format == 'JBIG2'"
sis query sample.pdf images --where "image.decode_too_large_reason == 'pixels'"
```
```
