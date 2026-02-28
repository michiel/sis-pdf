# Case Study: Decompression Bomb with Font-Noise Overlay

**Fixture**: `crates/sis-pdf-core/tests/fixtures/corpus_captured/decompression-bomb-font-flood-b509f6c9.pdf`  
**SHA256**: `b509f6c92dd4661b2872b9d18ffc07dced17306b4bdf74df19932bd0f8b110d0`  
**Classification**: Malicious | DenialOfService + ExploitPrimitive

## Threat Summary

This file combines high-ratio compressed streams (up to 1025.6x expansion) with parser stress and additional font/image anomaly noise. It is a strong denial-of-service style sample where decoder amplification is the primary risk and secondary structural anomalies increase analyst workload.

## File Structure

- Objects: 65
- Streams: multiple compressed payload streams
- Trailers: 1 (`secondary_parser.trailer_count=3`)
- ObjStm ratio: 0.0

## Detection Chain

Primary findings:
- `decompression_ratio_suspicious` x6 (Critical/Strong)
- `parser_resource_exhaustion` (High/Strong)
- `label_mismatch_stream_type` x7 (High/Strong)
- `font.cmap_range_overlap` x5 (Medium/Strong)
- `font_exploitation_cluster` (High/Probable)

Intent:
- `DenialOfService` score 28 (Strong)
- `ExploitPrimitive` score 19 (Strong)

Runtime profile:
- Total deep scan runtime: ~5.1 s
- `content_first_stage1`: ~5.0 s (dominant)

## Evasion Techniques

- Extreme decompression ratios to trigger CPU/memory amplification.
- Mixed font/image anomalies to dilute triage focus.
- Multiple high-severity structural findings that obscure the principal DoS path.

## Key Indicators

- `decompression_ratio_suspicious` with `decode.ratio` up to 1025.6
- `parser_resource_exhaustion`
- high count of `label_mismatch_stream_type`

## Regression Coverage

- `decompression_bomb_font_flood_fixture_stays_stable`

## Chain Assessment

Chain representation is improved but still incomplete for DoS narratives. Several top chains are `parser_resource_exhaustion` variants, while critical decompression findings remain mostly singleton. A dedicated decompression DoS chain should consistently join amplification findings with parser exhaustion and decoder-risk signals.
