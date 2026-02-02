# 20260202 Filter extension plan

## Context

`sis explain` currently surfaces a high‑severity finding whenever a stream decoder encounters a filter it does not explicitly support in `crates/sis-pdf-pdf/src/decode.rs`: `/FlateDecode`, `/ASCIIHexDecode`, `/ASCII85Decode`, `/RunLengthDecode`, and `/LZWDecode`. When the pipeline later hands off to dedicated detectors (e.g., image analysis for `/DCTDecode`), that higher‑severity finding becomes a false positive. We need to extend the “unsupported filter” handling so the other components remain responsible for their specialized filters, but without escalating them as errors during the generic decode pass.

## Goals

- Allow additional, intentionally deferred filters (JPEG/JPEG2000, JBIG2, CCITT) to complete the generic decode pass without emitting a hard failure that the content-first detection treats as High severity.
- Keep detection metadata honest by capturing when a filter was intentionally deferred and avoid raising `declared_filter_invalid` for those cases.
- Document the filter scope so maintainers can tell when to add new handlers to the generic decoder versus deferring to the image pipeline.

## Filters handled elsewhere (audit)

- `/DCTDecode`, `/DCT` — JPEG-specific image decoding happens inside `crates/image-analysis`.
- `/JPXDecode`, `/JPX` — JPEG2000 streams routed through the JPX decoder in `crates/image-analysis`.
- `/JBIG2Decode`, `/JBIG2` — JBIG2 image handling in `crates/image-analysis` and supported detectors.
- `/CCITTFaxDecode`, `/CCITTFax` — CCITT/fax bitmaps are analyzed via the image static/dynamic passes.

Keeping this list here makes it easier to extend the helper while also noting the assets already claiming ownership of those filters.

## Implementation status

- [x] Audit filters that already receive dedicated handling (see list above).
- [x] Introduce a filter classification helper and special error type so `decode_filter` can report “deferred” filters.
- [x] Propagate the new outcome into `DecodeOutcome` and reduce the reported severity for deferred cases.
- [x] Document the updated filter scope and add tests/fixtures covering the new behaviour.

## Next steps

No follow-up tasks remain for this plan unless we add new deferred filters.
## Testing

- `cargo test -p sis-pdf-pdf`
- `cargo test -p sis-pdf`
- Run any relevant detection/integration tests referencing `sis explain` (e.g., targeted fixture run) to ensure no false high severities.

## Risks

- If the classification grows unwieldy, there is a risk of accidentally downgrading genuinely unsupported filters.
- Need to keep plan in sync with future filter support added outside image analysis (e.g., any new decoder crate).
