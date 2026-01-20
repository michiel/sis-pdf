# Query predicate reference

This guide documents the `--where` predicate filters for `sis query`.

## Supported queries

Predicate filtering is supported for:
- `js`, `js.count`
- `embedded`, `embedded.count`
- `xfa.scripts`, `xfa.scripts.count`
- `swf.extract`, `swf.extract.count`
- `images`, `images.count`, `images.jbig2`, `images.jpx`, `images.ccitt`, `images.risky`, `images.malformed`
- `objects.list`, `objects.with`, `objects.count`
- `urls`, `urls.count`
- `events`, `events.document`, `events.page`, `events.field`, `events.count`
- `findings`, `findings.count`, `findings.kind`, `findings.high`, `findings.medium`, `findings.low`, `findings.info`, `findings.critical`
- finding shortcut queries (for example `embedded.executables`, `launch.external`, `streams.high-entropy`) and their `.count` variants

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

### SWF extraction (`swf.extract`, `swf.extract.count`)
- `length`: extracted SWF bytes (decoded or raw depending on flags)
- `entropy`: extracted SWF bytes entropy
- `type`: `SwfStream`
- `filter`: stream `/Filter` name (if present)
- `subtype`: `swf`
- `name`: generated SWF filename
- `magic`: SWF header tag (`FWS`, `CWS`, `ZWS`)

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
- `confidence`: confidence (`heuristic`, `probable`, `strong`)
- `surface`: attack surface (for example `embedded_files`, `actions`, `streams_and_filters`)
- `kind`: finding kind (same as `subtype`)
- `objects`: number of related objects
- `evidence`: number of evidence spans

## Examples

```bash
# Large JavaScript payloads with high entropy
sis query js file.pdf --where "length > 1024 AND entropy > 5.5"

# Events triggered at document level
sis query events file.pdf --where "filter == 'document'"

# High severity findings
sis query findings file.pdf --where "filter == 'high'"

# Streams using FlateDecode
sis query objects.with Stream file.pdf --where "filter == '/FlateDecode'"

# Large, risky images
sis query images file.pdf --where "risky == true AND pixels > 1000000"

# PNG images with high entropy
sis query images file.pdf --where "format == 'PNG' AND entropy > 7.5"

# Filter chain findings with allowlist misses
sis query filters.unusual file.pdf --where "violation_type == 'allowlist_miss'"

# Filter order violations involving Crypt
sis query filters.invalid file.pdf --where "violation_type == 'crypt_not_outermost'"

# Filter chains flagged in strict mode
sis query filters.unusual file.pdf --where "violation_type == 'strict_mode'"

# Image filters chained with compression
sis query filters.unusual file.pdf --where "violation_type == 'image_with_compression'"
```
