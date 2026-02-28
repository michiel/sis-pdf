# Case Study: Decode Budget Exhaustion at Scale (545-page Structure Pressure)

**Fixture**: `crates/sis-pdf-core/tests/fixtures/corpus_captured/decode-budget-exhaustion-c2d0d7e2.pdf`  
**SHA256**: `c2d0d7e20939319d1500856a40a275e72eed9174b02353b55bcbff58aef8e75d`  
**Classification**: Malicious | DenialOfService

## Threat Summary

This sample drives decoder and traversal pressure through a very large object graph (545 objects/pages) and repeated stream anomalies. The scan remains stable (no crash), but deep analysis runtime is dominated by one detector pass. The dominant threat is resource exhaustion and analysis degradation rather than a single clear execution payload.

## File Structure

- Objects: 545
- Pages: 545
- Streams: 39
- Trailers: 1 (`secondary_parser.trailer_count=4`)
- ObjStm ratio: 0.0
- File size: ~12.6 MB

## Detection Chain

Primary findings:
- `parser_resource_exhaustion` (High/Strong)
- `object_reference_depth_high` (High/Strong)
- `content_stream_marked_evasion` x9 (Medium/Tentative)
- `label_mismatch_stream_type` x25 (Medium/Strong)
- `image.suspect_strip_dimensions` x20 (Medium/Probable)

Intent:
- `DenialOfService` (score 6, Strong)
- `ExploitPrimitive` (score 2, Heuristic)

Runtime profile:
- Total deep scan runtime: ~33.7 s
- `content_first_stage1`: ~33.0 s (dominant hotspot)
- `content_phishing`: ~0.7 s

## Evasion Techniques

- High-volume object/page fan-out to increase traversal and decode overhead.
- Mixed medium-confidence stream anomalies that generate analyst noise.
- Marker-style content-stream findings without strong action/payload links.

## Key Indicators

- `parser_resource_exhaustion`
- `object_reference_depth_high`
- repeated non-fatal `decode_budget_exceeded` telemetry warnings
- `content_first_stage1` runtime dominance (>97% in profile)

## Regression Coverage

- `decode_budget_exhaustion_fixture_stays_stable`

## Chain Assessment

Attack-path representation is weak for this sample: top chains are singletons (`parser_resource_exhaustion`, `parser_trailer_count_diff`, `object_reference_depth_high`) with zero edges. This is sufficient for surfacing DoS risk but not for end-to-end path narration. A dedicated DoS chain synthesiser should group budget/decoder/exhaustion signals into a single operational chain.
