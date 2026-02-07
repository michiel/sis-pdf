# `/FlateDecode` in sis

## Overview

`/FlateDecode` is the canonical lossless compression filter in PDF. It wraps raw payload bytes (text, images, object tables, annotations, etc.) with the DEFLATE stream prefix expected by `zlib`/`flate` implementations. While the filter is lightweight, it is also ubiquitous, which makes it a high-value detection surface: attackers use it for obfuscation, while legitimate PDFs use it everywhere from page content to linearization metadata.

This document explains:

* how `/FlateDecode` is declared in the PDF object model,
* what the `sis` pipeline does when it sees `/FlateDecode`,
* how the `/FlateDecode` detector heuristics work,
* the common failure modes our analysts should expect, and
* how to interpret those failures during triage.

## How `/FlateDecode` is declared

A stream dictionary declares `/FlateDecode` by inserting either a single `/FlateDecode` name or an array that includes `/FlateDecode` among other filters. A minimal example:

```
60 0 obj
<</Length 988 /Filter /FlateDecode>>
stream
...majority of bytes compressed with DEFLATE...
endstream
```

More advanced dictionaries carry decoding parameters (`/DecodeParms`), predictors, or multi-stage filter chains such as `/FlateDecode` followed by `/ASCII85Decode`. PDF processors unroll those filters from first-to-last to obtain the decoded bytes.

Streams that are “structural” (Object Streams `/Type /ObjStm`, XRef streams `/Type /XRef`, linearization metadata `/Linearized`, and `/Type /Metadata`) typically carry `/FlateDecode` even though their output is not human-readable text. They store tables, object entries, or metadata that remains meaningful only after parsing, and this is noisily binary to a naive ASCII detector.

## How sis handles `/FlateDecode`

1. **Decoding** – `sis` runs `decode_stream_with_meta` (see `crates/sis-pdf-pdf/src/decode.rs`). It:
   * extracts the raw bytes behind the stream span,
   * gathers filter names (`stream_filters`),
   * checks fast heuristics such as `looks_like_jpeg`/`looks_like_zlib` to identify obvious mismatches, and
   * attempts a full decode pipeline (`decode_stream`), which sequentially runs each filter, applies the `/DecodeParms`, and enforces length/budget caps.

2. **Recording metadata** – `DecodeMeta` captures:
   * what filters were declared,
   * whether any mismatch heuristic triggered,
   * whether the decode succeeded, failed, recovered, or was truncated,
   * any filters that were “recovered” (decoded even though the heuristic said they were invalid), and
   * the decoded data bytes. This metadata is attached to all blobs (`Blob::from_stream`) so findings referencing the stream can cite it.

3. **Detector integration** – The content-first detector (`crates/sis-pdf-detectors/src/content_first.rs`) looks at the decoded blob and uses `declared_filter_invalid_finding` to signal when:
   * a Flate stream failed to decode (`DecodeOutcome::Failed`),
   * the stream *appears* mismatched (`DecodeOutcome::SuspectMismatch`) based on fast heuristics, but decoding succeeded, or
   * the decoded bytes do not match the exported filter signature.

   Structural streams now bypass this finding via `stream_is_structural`, so ObjStm, XRef, Metadata, and linearization dictionaries no longer emit high-volume noise.

4. **Traceability** – The finding records `meta.decode.mismatch`, `meta.decode.outcome`, and `meta.stream.filters`, which investigators can correlate with `stream` query output (with `--decode`, `--raw`, or `--hexdump`) to inspect the bytes and the stream dictionary.

## Failure modes

### 1. **Missing/invalid DEFLATE header**

*Symptom*: `looks_like_zlib` rejects the stream (value does not match `0x78 0x{01|5E|9C|DA}`) before attempting a decode. This often happens when the stream is not actually DEFLATE or is prefixed with random bytes.

*Analyst view*: A high-severity `declared_filter_invalid` fire whose `metadata.decode.mismatch` shows `/FlateDecode:stream is not zlib-like`, but the stream may still decompress after we recover or misconfiguration. Use `stream <obj> <gen> --raw` to dump the raw bytes; try feeding them to a reference `zlib` tool to see if a shifted offset or extra header is present. If it does not decompress at all, treat it as a genuine obfuscation or corruption.

### 2. **Valid zlib header, but decode fails**

*Symptom*: `decode_stream` returns `DecodeOutcome::Failed`, and `declared_filter_invalid` reports “Declared filters failed to decode.” This points to truncated data, a filter chain that exceeds a limit, or a filter that `sis` cannot handle (e.g., unsupported custom filters).

*Analyst view*: The stream dictionary often shows multiple filters; look at `/DecodeParms`, `/Length`, and `/Filter` entries. Extra filters (such as `/LZWDecode`, `/Fl` with incorrect parameters, or `/Crypt`) may require deeper inspection. Use `sis query stream <obj> <gen> --decode` to see whether the pipeline decoded anything or whether we hit a budget. The finding’s `meta.decode.outcome` and `decode.mismatch` fields document the failure reason.

### 3. **Zlib-like heuristic fires, decode succeeds (recent tuning)**

*Symptom*: Historically, structural streams triggered a high-volume “stream is not zlib-like” mismatch even though the stream is valid because object streams are binary tables. After the recent decoding change, if we decode successfully, we drop the heuristic mismatch immediately, so `DecodeOutcome::SuspectMismatch` only fires when there are *additional* mismatches besides the initial zlib check.

*Analyst view*: This means legitimate ObjStm/XRef/Metadata streams now remain quiet unless another filter mismatch occurs. If you still see a `declared_filter_invalid` hit for a structural stream, the decoded bytes may truly violate the declared filter chain (e.g., corrupted indexes). Verify by dumping the stream with `--decode` and checking that the decoded output matches ASN.1/PS object tables expected for that stream type.

## Interpreting the finding

When `declared_filter_invalid` fires for `/FlateDecode`:

1. **Check the metadata** – `decode.outcome`, `decode.mismatch`, and `stream.filters` help distinguish between structural noise and real corruption.  
2. **Inspect the dictionary** – use `sis query stream <obj> <gen>` to see `/Filter`, `/Length`, `/DecodeParms`, `/Type`/`/Subtype`.  
3. **Dump the bytes** – `--raw` gives you the compressed bytes; `--decode` shows the decompressed output. For sensitive investigations, pipe the raw bytes into `zlib-flate -uncompress` or another trusted tool to compare results.
4. **Look for context** – is the stream part of an annotation, JavaScript payload, or object stream? Structural streams are now automatically ignored, but all other streams should correlate with actual content (images, fonts, JS).  
5. **Decide action** – if the stream decompresses cleanly and matches the declared filter (despite a malformed header), mark it as a false positive. If the decode fails or the stream contains unexpected binary, escalate as a potential obfuscation/corruption vector.

## Summary

`/FlateDecode` is a decoder and detector hotspot because it is both common and flexible. `sis` balances fast heuristics (the “zlib-like” check) with a full decode pipeline and structural whitelists to avoid noise. When you see a `declared_filter_invalid` finding, focus on the metadata, dictionary, and decoded bytes to decide whether the stream reflects a malicious payload, a malformed viewer artifact, or a harmless structural stream that should remain ignored. This document should be referenced whenever `/FlateDecode` is in question during an investigation to ensure consistent reasoning and triage decisions.
