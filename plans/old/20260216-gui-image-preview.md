# Image Pixel Reconstruction and Security Review

## Context

The Object Inspector can now preview JPEG image streams (implemented in the prior change). However, most PDF images use FlateDecode with raw pixel data -- these show "Stream contains binary data" with no preview. To support them we need colour space resolution and pixel reconstruction. Because this code operates on untrusted PDF data, we must also review the attack surface it introduces and ensure detection coverage.

## Dependency Graph

```
Stage 1 (colour space types + parsing)
    |
    v
Stage 2 (pixel reconstruction engine)
    |
    v
Stage 3 (GUI integration) --- Stage 4 (security review, read-only)
                                   |
                                   v
                              Stage 5 (new detector findings)
```

---

## Stage 1: Colour Space Model

**Goal**: Define the colour space representation and parsing in the `image-analysis` crate.

**New file**: `crates/image-analysis/src/colour_space.rs`

```rust
pub enum ResolvedColourSpace {
    DeviceGray,
    DeviceRGB,
    DeviceCMYK,
    Indexed { base: Box<ResolvedColourSpace>, hival: u8, palette: Vec<u8> },
    ICCBased { n: u8 },           // channel count from /N in ICC stream dict
    Calibrated { channels: u8 },  // CalGray(1), CalRGB(3), Lab(3)
    Unknown(String),
}
```

Methods: `channels() -> Option<u8>`, `supports_preview() -> bool`.

Parsing function:

```rust
pub fn resolve_colour_space(
    dict: &PdfDict<'_>,
    graph: &ObjectGraph<'_>,
) -> Option<ResolvedColourSpace>
```

Parsing rules:
- Name `/DeviceGray` | `/DeviceRGB` | `/DeviceCMYK` -> direct variant
- Name `/CalGray` -> `Calibrated { channels: 1 }`, `/CalRGB` -> `Calibrated { channels: 3 }`
- Array `[/ICCBased <ref>]` -> resolve ref, read `/N` from ICC stream dict, validate 1 <= n <= 4
- Array `[/Indexed <base> <hival> <palette>]` -> resolve base recursively (depth cap = 2), extract palette bytes from string or stream
- Anything else -> `Unknown(name_string)`

**Modify**: `crates/image-analysis/src/lib.rs` -- add `pub mod colour_space;`

**Tests** (in-module):
- `device_gray_from_name`, `device_rgb_from_name`, `device_cmyk_from_name`
- `icc_based_from_array` -- mock ObjectGraph with ICC stream having `/N 3`
- `indexed_with_device_rgb_base` -- `[/Indexed /DeviceRGB 255 <palette>]`
- `unknown_colour_space_returned`
- `recursive_depth_limited` -- nested Indexed base does not recurse beyond depth 2

**Reuse**: Test helper patterns from `crates/image-analysis/tests/dynamic_limits.rs` (pdf_name, pdf_obj_name, pdf_obj_int, make_image_entry, ObjectGraph construction).

---

## Stage 2: Pixel Reconstruction Engine

**Goal**: Convert decoded stream bytes + image dict metadata into RGBA pixels.

**New file**: `crates/image-analysis/src/pixel_buffer.rs`

```rust
pub const MAX_PREVIEW_BUFFER_BYTES: u64 = 64 * 1024 * 1024; // 64 MB (4096x4096 RGBA)

pub struct PixelBuffer {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,   // row-major, 4 bytes/pixel
}

pub enum PixelError {
    MissingKey(&'static str),
    UnsupportedColourSpace(String),
    BufferSizeExceeded { expected: u64, limit: u64 },
    InsufficientData { expected: usize, actual: usize },
    UnsupportedBitsPerComponent(u32),
    ArithmeticOverflow(String),
    PaletteTooShort { expected: usize, actual: usize },
    InvalidDecodeArray(String),
}

pub fn reconstruct_pixels(
    decoded: &[u8],
    dict: &PdfDict<'_>,
    graph: &ObjectGraph<'_>,
) -> Result<PixelBuffer, PixelError>
```

Implementation steps:
1. Extract Width, Height, BitsPerComponent from dict (using `crate::util::dict_u32`)
2. Resolve colour space via `resolve_colour_space(dict, graph)`
3. Checked arithmetic: `bits_per_row = width * channels * bpc`, `bytes_per_row = (bits_per_row + 7) / 8`, `total = bytes_per_row * height`
4. Validate total <= MAX_PREVIEW_BUFFER_BYTES and total <= decoded.len()
5. Unpack sub-byte samples for BPC 1, 2, 4 (rows padded to byte boundaries)
6. Apply `/Decode` array if present (remap sample ranges, validate length = 2 * channels)
7. Convert to RGBA:
   - DeviceGray / ICCBased(1) / Calibrated(1): `[v, v, v, 255]`
   - DeviceRGB / ICCBased(3) / Calibrated(3): `[r, g, b, 255]`
   - DeviceCMYK / ICCBased(4): `r = (1-c/255)*(1-k/255)*255` clamped, same for g, b
   - Indexed: palette lookup (bounds-checked against hival and palette length), then convert base
   - Unknown: return `UnsupportedColourSpace`

**Modify**: `crates/image-analysis/src/lib.rs` -- add `pub mod pixel_buffer;`
**Modify**: `crates/image-analysis/src/util.rs` -- add `dict_f64_array()` for /Decode extraction

**Tests** (in-module):
- `gray_8bpc_2x2` -- 4 gray bytes -> 16 RGBA bytes
- `rgb_8bpc_1x1` -- 3 bytes -> 4 RGBA bytes
- `cmyk_8bpc_1x1` -- CMYK conversion produces valid RGB
- `gray_1bpc_8x1` -- 8 pixels packed in 1 byte
- `gray_4bpc_2x1` -- 2 pixels in 1 byte
- `indexed_rgb_palette` -- palette lookup + base conversion
- `decode_array_remaps_values` -- /Decode [1 0] inverts grayscale
- `insufficient_data_error` -- stream too short
- `buffer_size_overflow_rejected` -- huge dimensions caught
- `zero_width_rejected`, `zero_height_rejected`

---

## Stage 3: GUI Preview Integration

**Goal**: Wire pixel reconstruction into the Object Inspector for non-JPEG image streams.

**Modify**: `crates/sis-pdf-gui/src/object_data.rs`

The `extract_one_object` signature needs `graph: &ObjectGraph<'_>` added as a parameter (currently takes only `bytes`, `entry`, `classifications`). Propagate through `extract_object_data`.

After the existing JPEG preview block, add fallback:

```rust
#[cfg(feature = "gui")]
if image_preview.is_none() && obj_type == "image" {
    if let Some(ref decoded_data) = stream_raw {
        image_preview = reconstruct_image_preview(decoded_data, &s.dict, graph);
    }
}
```

`reconstruct_image_preview` calls `image_analysis::pixel_buffer::reconstruct_pixels`, then thumbnails to 256px max using the existing `image` crate dependency.

**Files**:
- `crates/sis-pdf-gui/src/object_data.rs` -- add graph parameter, call reconstruction
- `crates/sis-pdf-gui/src/panels/objects.rs` -- no changes needed; existing preview renderer handles any `(u32, u32, Vec<u8>)`

**Verification**:
- `cargo check -p sis-pdf-gui --target wasm32-unknown-unknown`
- `cargo test -p sis-pdf-gui --no-default-features --lib`

---

## Stage 4: Security Review

**Goal**: Review the new code paths for attack susceptibility and document gaps in current detection.

This is a review stage -- no code changes. Produces the analysis that drives Stage 5.

### 4.1 Colour Space Resolution Attacks

| Vector | Risk | Mitigation | Gap? |
|--------|------|-----------|------|
| Circular Indexed base refs | Stack overflow | Depth cap = 2 | Verify cap tested |
| Missing elements in CS array | Index OOB | Pattern match requires all elements | Verify explicit length check |
| ICCBased with /N = 0 or > 4 | Invalid channels | Validate 1 <= n <= 4 | **New finding**: `image.colour_space_invalid` |
| Wrong types in CS array | Type confusion | Typed extraction per element | Needs test coverage |
| Indirect ref to wrong type | Unexpected atom | Type-check after resolve_ref | Verify |

### 4.2 Pixel Buffer Attacks

| Vector | Risk | Mitigation | Gap? |
|--------|------|-----------|------|
| W * H * channels * BPC overflow | Integer overflow | All checked_* arithmetic | **New finding**: `image.pixel_buffer_overflow` |
| W=0 or H=0 | Division by zero | Explicit zero check | Verify |
| BPC not in {1,2,4,8} | Wrong unpacking | Return UnsupportedBitsPerComponent | **New finding**: `image.bpc_anomalous` |
| Declared dims vs stream length mismatch | Over/underread | Check expected <= decoded.len() | **New finding**: `image.pixel_data_size_mismatch` |

### 4.3 Decode Array Attacks

| Vector | Risk | Mitigation | Gap? |
|--------|------|-----------|------|
| /Decode length != 2*channels | Index OOB | Validate length | **New finding**: `image.decode_array_invalid` |
| /Decode with NaN/Infinity | Numeric instability | Clamp to [0, 65535] | Verify |

### 4.4 Palette Attacks

| Vector | Risk | Mitigation | Gap? |
|--------|------|-----------|------|
| Palette shorter than (hival+1)*base_channels | OOB read | Check palette length | **New finding**: `image.indexed_palette_short` |
| Sample values > hival | OOB palette lookup | Clamp to hival | Verify |

### 4.5 CMYK Conversion

| Vector | Risk | Mitigation | Gap? |
|--------|------|-----------|------|
| All-255 CMYK values | Underflow | f64 intermediates, clamp [0, 255] | Verify |

---

## Stage 5: New Detector Findings

**Goal**: Implement findings for the gaps identified in Stage 4. All go into `crates/image-analysis/src/static_analysis.rs` (which already iterates over all image XObjects), except `image.pixel_data_size_mismatch` which belongs in `dynamic.rs`.

### 5.1 `image.colour_space_invalid`
- **Severity**: Medium, **Confidence**: Strong
- **Trigger**: CS array wrong element count, wrong types, circular refs, ICCBased with invalid /N
- **Metadata**: `image.colour_space_raw`, `image.colour_space_issue`
- **Implementation**: Call `resolve_colour_space` during static analysis; if it returns `Unknown` or errors, emit finding

### 5.2 `image.bpc_anomalous`
- **Severity**: Low, **Confidence**: Strong
- **Trigger**: BitsPerComponent not in {1, 2, 4, 8, 16} or missing when required by colour space
- **Metadata**: `image.bits_per_component`

### 5.3 `image.pixel_buffer_overflow`
- **Severity**: Medium, **Confidence**: Certain
- **Trigger**: W * H * channels * BPC overflows u64 or exceeds MAX_PREVIEW_BUFFER_BYTES
- **Metadata**: `image.width`, `image.height`, `image.channels`, `image.bpc`, `image.calculated_buffer_bytes`

### 5.4 `image.pixel_data_size_mismatch` (in `dynamic.rs`)
- **Severity**: Medium, **Confidence**: Probable
- **Trigger**: Decoded stream length != expected for declared W * H * channels * BPC
- **Metadata**: `image.expected_bytes`, `image.actual_bytes`
- Runs during dynamic analysis since it requires decoded data

### 5.5 `image.indexed_palette_short`
- **Severity**: Low, **Confidence**: Strong
- **Trigger**: Palette bytes < (hival + 1) * base_channels
- **Metadata**: `image.palette_expected_bytes`, `image.palette_actual_bytes`, `image.hival`

### 5.6 `image.decode_array_invalid`
- **Severity**: Low, **Confidence**: Strong
- **Trigger**: /Decode array length != 2 * channels, or contains non-numeric values
- **Metadata**: `image.decode_array_length`, `image.decode_array_expected_length`

**Files to modify**:
- `crates/image-analysis/src/static_analysis.rs` -- add 5.1-5.3, 5.5-5.6 checks in the existing image XObject loop
- `crates/image-analysis/src/dynamic.rs` -- add 5.4 check after successful decode
- `crates/sis-pdf-detectors/src/image_analysis.rs` -- add finding summary/severity for new kinds
- `docs/findings.md` -- document all new finding IDs

**Tests** (in `crates/image-analysis/tests/`):
- `static_colour_space_invalid` -- image with `[/ICCBased]` (missing ref)
- `static_bpc_anomalous` -- image with BPC=7
- `static_pixel_buffer_overflow` -- W=100000 H=100000
- `static_indexed_palette_short` -- Indexed with truncated palette
- `dynamic_pixel_data_size_mismatch` -- decoded stream shorter than expected

---

## Key Design Decisions

1. **Pixel reconstruction in `image-analysis` crate, not GUI**: Keeps logic testable without windowing deps
2. **No ICC profile application**: Use /N for channel count only. Accurate colour needs lcms2 (C library, violates Rust-native constraint). Preview is colour-approximate.
3. **Naive CMYK-to-RGB**: `(1-C/255)*(1-K/255)*255` -- acceptable for a security analysis tool
4. **BPC=16 not supported**: Rare in practice, doubles buffer size. Intentional limitation, documented.
5. **MAX_PREVIEW_BUFFER_BYTES = 64 MB**: 4096x4096 RGBA. Generous for real PDFs, prevents exhaustion.
6. **resolve_colour_space takes ObjectGraph not ScanContext**: image-analysis depends on sis-pdf-pdf but not sis-pdf-core

## Critical Files

- `crates/image-analysis/src/lib.rs` -- add colour_space, pixel_buffer modules
- `crates/image-analysis/src/colour_space.rs` -- new: colour space parsing
- `crates/image-analysis/src/pixel_buffer.rs` -- new: pixel reconstruction
- `crates/image-analysis/src/static_analysis.rs` -- add new validation findings
- `crates/image-analysis/src/dynamic.rs` -- add pixel_data_size_mismatch finding
- `crates/image-analysis/src/util.rs` -- extend with dict_f64_array helper
- `crates/image-analysis/tests/dynamic_limits.rs` -- test helper patterns to reuse
- `crates/sis-pdf-gui/src/object_data.rs` -- wire preview, add graph parameter
- `crates/sis-pdf-detectors/src/image_analysis.rs` -- add severity/summary for new finding kinds
- `docs/findings.md` -- document new findings

## Verification

Per stage:
1. `cargo test -p image-analysis` -- colour space parsing tests pass
2. `cargo test -p image-analysis` -- pixel reconstruction tests pass
3. `cargo check -p sis-pdf-gui --target wasm32-unknown-unknown` + `cargo test -p sis-pdf-gui --no-default-features --lib`
4. Security review document complete (this plan's Stage 4 section)
5. `cargo test -p image-analysis` -- new finding tests pass, `cargo test -p sis-pdf-detectors` -- integration tests pass
