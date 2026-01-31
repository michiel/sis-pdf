# Image Analysis Implementation Plan

## Goal

Introduce a dedicated image analysis pipeline to detect suspicious or malformed image content in PDFs, covering both static heuristics (default) and dynamic decoding (deep scan), with findings integrated into sis-pdf output, query interface, and feature extraction.

## Detailed Goals

- Detect risky image formats (JBIG2, JPEG2000, CCITT) and anomalous image parameters in a fast static pass.
- Decode selected image streams safely under deep scan to surface malformed image data.
- **Integrate with query interface** for interactive image exploration, extraction, and filtering.
- **Export image features** for ML pipelines via existing feature vector system.
- Correlate image findings with JS and object graph context when relevant (action + image present).
- Maintain deterministic, bounded runtime with strict limits on image size and decode time.
- Ensure findings are documented with severity/impact/confidence fields and surfaced in reports.

## Summary Review of Research

The research highlights a long history of image-based PDF exploits (JBIG2, JPEG2000, TIFF/CCITT, PNG/XFA) and modern examples (FORCEDENTRY). It emphasises that:
- Image decoders remain a critical attack surface across readers.
- Image streams can hide payloads or trigger memory corruption.
- Static heuristics can identify risky formats and anomalous parameters at low cost.
- Dynamic decoding can confirm malformed or exploit-like content but must be tightly bounded.

## Scope

- New `crates/image-analysis` crate with static and dynamic analysis modules.
- Static analysis runs by default; dynamic analysis runs when `ScanOptions.deep == true`.
- Findings surfaced via existing report/findings pipeline.
- **Query interface integration** for interactive image analysis and extraction.
- **Feature vector integration** for ML pipelines.
- Documentation updates for new findings and query types.

## Non-Goals

- Full image rendering or visual output.
- Emulating reader-specific bugs or running any image code in-process via unsafe FFI.
- Process-level sandboxing (deferred to post-1.0, see Future Enhancements).

## Design Overview

- **Static analysis**: identify image XObjects, inspect filters/dictionaries, sniff headers where safe, and emit low-cost findings with metadata.
- **Dynamic analysis**: decode select formats using memory-safe Rust crates with hard limits, record decode failures and anomalies.
- **Query integration**: expose image queries for interactive analysis (`images`, `images.jbig2`, `images --where "width > 10000"`).
- **Feature extraction**: add image-specific features to existing FeatureVector for ML.
- **Config**: default static on, dynamic gated by `--deep` with optional `--no-image-decode` opt-out.
- **Findings**: structured finding IDs following existing naming conventions; metadata includes filters, dimensions, decode outcome.

---

## Performance SLOs

To ensure image analysis doesn't degrade scan performance, the following Service Level Objectives (SLOs) are established:

### Static Analysis (Default Mode)

**Target overhead:**
- **Average:** <1ms per image
- **Worst-case:** <10ms per image
- **Batch impact:** <5% total scan time increase for PDFs with 10+ images

**Measurement:**
- Add tracing spans: `image_static_analysis`, `image_enumeration`, `image_heuristics`
- Emit timing in finding metadata: `image.analysis_ms`
- Report in `--profile` output

### Dynamic Analysis (Deep Mode)

**Resource limits:**
- **Per-image timeout:** 250ms (existing, configurable via `scan.image_decode_timeout_ms`)
- **Total per-PDF budget:** 5 seconds for all image decodes combined
- **Automatic skip:** If >50 images in single PDF, skip dynamic analysis with warning

**Max resource consumption:**
- **Max pixels:** 100 million per image (existing)
- **Max decode bytes:** 256 MB per image (existing)

**Measurement:**
- Emit `image.decode_ms` in finding metadata
- Track cumulative decode time per PDF
- Log warning when budget exceeded

### Instrumentation Requirements

**Tracing spans to add:**
```rust
// In image-analysis crate:
#[tracing::instrument(skip(ctx))]
fn analyze_static(ctx: &ScanContext) -> Vec<ImageFinding> { ... }

#[tracing::instrument(skip(data))]
fn decode_jbig2(data: &[u8], opts: &DecodeOpts) -> Result<DecodedImage> { ... }
```

**Profile output:**
```
Image Analysis:
  Static: 23 images analyzed in 12ms (avg 0.5ms/image)
  Dynamic: 3 JBIG2 images decoded in 487ms (avg 162ms/image)
  Skipped: 0 images (budget not exceeded)
```

---

## Timeout Enforcement Strategy

**Decision:** Use **cooperative timeout checking** with fallback to OS-level limits for batch mode.

### Implementation Approach

**Per-image cooperative timeout:**
```rust
// In dynamic.rs:
pub struct ImageDecodeOptions {
    pub max_decode_ms: u64,        // Default: 250ms
    pub max_pixels: u64,            // Default: 100 million
    pub checkpoint_interval: usize, // Check timeout every N operations (default: 1000)
}

// Decoder wrapper with cooperative checks:
fn decode_with_timeout<F>(
    decode_fn: F,
    data: &[u8],
    opts: &ImageDecodeOptions,
) -> Result<Vec<u8>>
where
    F: FnOnce(&[u8], &TimeoutChecker) -> Result<Vec<u8>>,
{
    let start = Instant::now();
    let checker = TimeoutChecker {
        start,
        max_ms: opts.max_decode_ms,
        checkpoint_interval: opts.checkpoint_interval,
        ops_count: AtomicUsize::new(0),
    };

    decode_fn(data, &checker)
}

pub struct TimeoutChecker {
    start: Instant,
    max_ms: u64,
    checkpoint_interval: usize,
    ops_count: AtomicUsize,
}

impl TimeoutChecker {
    pub fn check(&self) -> Result<()> {
        let ops = self.ops_count.fetch_add(1, Ordering::Relaxed);
        if ops % self.checkpoint_interval == 0 {
            if self.start.elapsed().as_millis() > self.max_ms as u128 {
                return Err(anyhow!("Image decode timeout exceeded"));
            }
        }
        Ok(())
    }
}
```

**Decoder integration pattern:**
```rust
// In JBIG2 decoder wrapper:
fn decode_jbig2_with_timeout(data: &[u8], checker: &TimeoutChecker) -> Result<Vec<u8>> {
    let segments = parse_jbig2_segments(data)?;
    let mut output = Vec::new();

    for segment in segments {
        checker.check()?; // Cooperative timeout check
        let decoded = decode_segment(&segment)?;
        output.extend(decoded);
    }

    Ok(output)
}
```

### Fallback for Non-Cooperative Decoders

If third-party decoders don't support cooperative checks:
- **Document as known limitation** in security section
- Rely on OS-level process timeouts in batch mode
- Consider wrapping in thread with `std::thread::spawn` + timeout for critical paths
- Log warning when using non-cooperative decoder

### Per-Format Pixel Limits

**Decision:** Use global max_pixels with format-specific scaling:
```rust
pub fn get_format_pixel_limit(format: ImageFormat) -> u64 {
    match format {
        ImageFormat::JBIG2 => 50_000_000,  // More restrictive (50M pixels)
        ImageFormat::JPX => 75_000_000,     // Moderate (75M pixels)
        ImageFormat::JPEG | ImageFormat::PNG => 100_000_000, // Standard (100M)
        _ => 100_000_000,
    }
}
```

---

## Query Interface Integration

**Priority:** Critical for forensic workflow integration.

The query interface (Phases 1-9 complete in IMPLEMENTATION_PLAN.md) provides interactive exploration, batch processing, and extraction. Image analysis must integrate fully.

### New Query Types

Add to `crates/sis-pdf/src/commands/query.rs`:

```rust
// In Query enum:
pub enum Query {
    // ... existing variants ...

    // Image queries
    Images,                     // List all images
    ImagesCount,               // Count images
    ImagesJbig2,              // Filter by JBIG2 format
    ImagesJbig2Count,         // Count JBIG2 images
    ImagesJpx,                // Filter by JPEG2000 format
    ImagesJpxCount,           // Count JPEG2000 images
    ImagesCcitt,              // Filter by CCITT format
    ImagesCcittCount,         // Count CCITT images
    ImagesRisky,              // Show risky formats (JBIG2/JPX/CCITT)
    ImagesRiskyCount,         // Count risky images
    ImagesMalformed,          // Show images that failed decode (deep mode)
    ImagesMalformedCount,     // Count malformed images
}
```

### Query String Syntax

Add to `parse_query()` in query.rs:

```rust
match input {
    // ... existing patterns ...

    // Image queries
    "images" => Ok(Query::Images),
    "images.count" => Ok(Query::ImagesCount),
    "images.jbig2" => Ok(Query::ImagesJbig2),
    "images.jbig2.count" => Ok(Query::ImagesJbig2Count),
    "images.jpx" => Ok(Query::ImagesJpx),
    "images.jpx.count" => Ok(Query::ImagesJpxCount),
    "images.ccitt" => Ok(Query::ImagesCcitt),
    "images.ccitt.count" => Ok(Query::ImagesCcittCount),
    "images.risky" => Ok(Query::ImagesRisky),
    "images.risky.count" => Ok(Query::ImagesRiskyCount),
    "images.malformed" => Ok(Query::ImagesMalformed),
    "images.malformed.count" => Ok(Query::ImagesMalformedCount),

    // ...
}
```

### Query Handlers

Implement in `execute_query_with_context()`:

```rust
Query::Images => {
    let images = extract_images(ctx, decode_mode, predicate)?;
    if let Some(extract_path) = extract_to {
        // Extract images to disk
        let written = write_image_files(ctx, extract_path, max_extract_bytes, decode_mode, predicate)?;
        Ok(QueryResult::List(written))
    } else {
        // Return preview list
        Ok(QueryResult::List(images))
    }
}

Query::ImagesCount => {
    let images = extract_images(ctx, decode_mode, predicate)?;
    Ok(QueryResult::Scalar(ScalarValue::Number(images.len() as i64)))
}

Query::ImagesJbig2 => {
    let jbig2_images = extract_images_by_format(ctx, ImageFormat::JBIG2, decode_mode, predicate)?;
    Ok(QueryResult::List(jbig2_images))
}

// ... similar for other image query types ...
```

### Image Extraction Support

Add to `crates/sis-pdf/src/commands/query.rs`:

```rust
/// Extract images from PDF with metadata
fn extract_images(
    ctx: &ScanContext,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    let mut images = Vec::new();

    for entry in &ctx.graph.objects {
        if let Some(dict) = entry_dict(entry) {
            // Check for /Type /XObject /Subtype /Image
            if is_image_xobject(dict) {
                let image_info = analyze_image_object(ctx, entry, decode_mode)?;

                // Apply predicate filtering
                let meta = PredicateContext {
                    length: image_info.data_length,
                    filter: image_info.filter.clone(),
                    type_name: "Image".to_string(),
                    subtype: Some(image_info.format.to_string()),
                    entropy: image_info.entropy,
                };

                if predicate.map(|pred| pred.evaluate(&meta)).unwrap_or(true) {
                    images.push(format!(
                        "Object {}_{}: {} ({}x{}, {}, {} bytes)",
                        entry.obj,
                        entry.gen,
                        image_info.format,
                        image_info.width,
                        image_info.height,
                        image_info.filter.as_deref().unwrap_or("none"),
                        image_info.data_length
                    ));
                }
            }
        }
    }

    Ok(images)
}

/// Write image files to disk (similar to write_js_files)
fn write_image_files(
    ctx: &ScanContext,
    extract_to: &Path,
    max_bytes: usize,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    use std::fs;

    fs::create_dir_all(extract_to)?;

    let mut written_files = Vec::new();
    let mut count = 0usize;

    for entry in &ctx.graph.objects {
        if let Some(dict) = entry_dict(entry) {
            if is_image_xobject(dict) {
                let image_info = analyze_image_object(ctx, entry, decode_mode)?;

                // Apply predicate filtering
                let meta = PredicateContext {
                    length: image_info.data_length,
                    filter: image_info.filter.clone(),
                    type_name: "Image".to_string(),
                    subtype: Some(image_info.format.to_string()),
                    entropy: image_info.entropy,
                };

                if predicate.map(|pred| pred.evaluate(&meta)).unwrap_or(true) {
                    let base_name = format!("image_{}_{}", entry.obj, entry.gen);
                    let extension = image_extension(&image_info.format);

                    let (filename, output_bytes, mode_label) = match decode_mode {
                        DecodeMode::Decode => (
                            format!("{base_name}.{extension}"),
                            image_info.data.clone(),
                            "decode",
                        ),
                        DecodeMode::Raw => (
                            format!("{base_name}.raw"),
                            image_info.raw_data.clone(),
                            "raw",
                        ),
                        DecodeMode::Hexdump => (
                            format!("{base_name}.hex"),
                            format_hexdump(&image_info.data).into_bytes(),
                            "hexdump",
                        ),
                    };

                    let filepath = extract_to.join(&filename);
                    let hash = sha256_hex(&image_info.data);

                    fs::write(&filepath, &output_bytes)?;

                    let info = format!(
                        "{}: {}x{} {}, {} bytes, sha256={}, object={}_{}",
                        filename,
                        image_info.width,
                        image_info.height,
                        image_info.format,
                        image_info.data.len(),
                        hash,
                        entry.obj,
                        entry.gen
                    );
                    written_files.push(info);
                    count += 1;
                }
            }
        }
    }

    eprintln!("Extracted {} image(s) to {}", count, extract_to.display());
    Ok(written_files)
}

fn image_extension(format: &ImageFormat) -> &'static str {
    match format {
        ImageFormat::JBIG2 => "jbig2",
        ImageFormat::JPX => "jp2",
        ImageFormat::JPEG => "jpg",
        ImageFormat::PNG => "png",
        ImageFormat::TIFF => "tif",
        ImageFormat::CCITT => "ccitt",
        ImageFormat::Unknown => "bin",
    }
}
```

### Predicate Support for Images

Images support all standard predicate fields (Phase 8):

**Predicate fields:**
- `length` - Image data byte length (decoded or raw depending on mode)
- `filter` - Compression filter name (`JBIG2Decode`, `JPXDecode`, etc.)
- `type` - Always "Image"
- `subtype` - Image format (`JBIG2`, `JPX`, `JPEG`, `PNG`, etc.)
- `entropy` - Shannon entropy of image data

**Additional image-specific predicate fields (add to PredicateField enum):**
- `width` - Image width in pixels
- `height` - Image height in pixels
- `pixels` - Total pixel count (width × height)
- `risky` - Boolean indicating risky format (JBIG2/JPX/CCITT)

### Usage Examples

**Basic image queries:**
```bash
# List all images
sis query malware.pdf images

# Count images
sis query malware.pdf images.count

# Find JBIG2 images
sis query malware.pdf images.jbig2

# Count risky images
sis query malware.pdf images.risky.count
```

**With predicates (Phase 8):**
```bash
# Find large images
sis query malware.pdf images --where "width > 10000 OR height > 10000"

# Find suspicious JBIG2 with extreme aspect ratios
sis query malware.pdf images.jbig2 --where "width == 1 OR height == 1"

# Find high-entropy images (possible steganography)
sis query malware.pdf images --where "entropy > 7.5 AND format == 'PNG'"

# Complex filter
sis query corpus.pdf images --where "risky AND pixels > 1000000"
```

**Image extraction:**
```bash
# Extract all images
sis query malware.pdf images --extract-to /tmp/images

# Extract only JBIG2 images
sis query malware.pdf images.jbig2 --extract-to /tmp/jbig2

# Extract risky images in raw format
sis query malware.pdf images.risky --extract-to /tmp/risky --raw

# Extract with filtering
sis query malware.pdf images --where "format == 'JBIG2' OR format == 'JPX'" \
  --extract-to /tmp/risky_images
```

**Batch mode:**
```bash
# Find all PDFs with JBIG2 images
sis query --path corpus --glob "*.pdf" images.jbig2.count --format jsonl | \
  jq -c 'select(.result > 0)'

# Extract all risky images from corpus
sis query --path corpus --glob "*.pdf" images.risky --extract-to /tmp/corpus_images

# Count malformed images across corpus (requires --deep)
sis query --path corpus --glob "*.pdf" --deep images.malformed.count
```

**REPL mode:**
```bash
sis query malware.pdf
sis> images
sis> images.jbig2
sis> images --where "width > 5000"
sis> :extract-to /tmp/out
sis> images.risky
```

**JSON output:**
```bash
# Get image details as JSON
sis query malware.pdf images --json

# Output:
{
  "query": "images",
  "file": "malware.pdf",
  "result": [
    "Object 52_0: JBIG2 (1x10000, JBIG2Decode, 4523 bytes)",
    "Object 63_0: JPEG (800x600, DCTDecode, 45231 bytes)"
  ]
}

# JSONL for streaming
sis query --path corpus --glob "*.pdf" images.count --format jsonl
{"path": "doc1.pdf", "result": 5}
{"path": "doc2.pdf", "result": 0}
{"path": "malware.pdf", "result": 12}
```

### Integration Checklist

- [x] Add Query enum variants for image queries
- [x] Implement `parse_query()` patterns for image query strings
- [x] Implement query handlers in `execute_query_with_context()`
- [x] Add `extract_images()` helper function
- [x] Add `write_image_files()` extraction function
- [x] Add image-specific predicate fields (width, height, pixels, risky)
- [x] Update REPL help text with image query examples
- [x] Add query tests for image queries
- [x] Document in `docs/query-interface.md`

---

## Feature Vector Integration

**Priority:** High for ML pipeline compatibility.

Image analysis findings must populate the existing feature vector system used for ML inference and training.

### Add ImageFeatures Struct

In `crates/sis-pdf-core/src/features.rs`:

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct ImageFeatures {
    pub image_count: usize,
    pub jbig2_count: usize,
    pub jpx_count: usize,
    pub jpeg_count: usize,
    pub png_count: usize,
    pub ccitt_count: usize,
    pub risky_image_count: usize,      // JBIG2 + JPX + CCITT
    pub malformed_image_count: usize,  // Failed decode in deep mode
    pub max_image_width: u32,
    pub max_image_height: u32,
    pub max_image_pixels: u64,
    pub total_image_pixels: u64,
    pub avg_image_entropy: f64,
    pub extreme_dimensions_count: usize, // 1xN or Nx1 patterns
    pub multi_filter_count: usize,       // Images with filter chains
    pub xfa_image_count: usize,         // Images embedded in XFA forms
}
```

### Update FeatureVector

```rust
pub struct FeatureVector {
    pub general: GeneralFeatures,
    pub structural: StructuralFeatures,
    pub behavioral: BehavioralFeatures,
    pub content: ContentFeatures,
    pub graph: GraphFeatures,
    pub images: ImageFeatures,  // NEW
}

impl FeatureVector {
    pub fn as_f32_vec(&self) -> Vec<f32> {
        vec![
            // ... existing features ...

            // Image features (16 new features)
            self.images.image_count as f32,
            self.images.jbig2_count as f32,
            self.images.jpx_count as f32,
            self.images.jpeg_count as f32,
            self.images.png_count as f32,
            self.images.ccitt_count as f32,
            self.images.risky_image_count as f32,
            self.images.malformed_image_count as f32,
            self.images.max_image_width as f32,
            self.images.max_image_height as f32,
            self.images.max_image_pixels as f32,
            self.images.total_image_pixels as f32,
            self.images.avg_image_entropy as f32,
            self.images.extreme_dimensions_count as f32,
            self.images.multi_filter_count as f32,
            self.images.xfa_image_count as f32,
        ]
    }
}

pub fn feature_names() -> Vec<&'static str> {
    vec![
        // ... existing feature names ...

        // Image features
        "images.image_count",
        "images.jbig2_count",
        "images.jpx_count",
        "images.jpeg_count",
        "images.png_count",
        "images.ccitt_count",
        "images.risky_image_count",
        "images.malformed_image_count",
        "images.max_image_width",
        "images.max_image_height",
        "images.max_image_pixels",
        "images.total_image_pixels",
        "images.avg_image_entropy",
        "images.extreme_dimensions_count",
        "images.multi_filter_count",
        "images.xfa_image_count",
    ]
}
```

### Feature Extraction Integration

In `sis_pdf_core::features::FeatureExtractor::extract()`:

```rust
impl FeatureExtractor {
    pub fn extract(ctx: &ScanContext) -> FeatureVector {
        // ... existing feature extraction ...

        // Image feature extraction
        let images = extract_image_features(ctx);

        FeatureVector {
            general,
            structural,
            behavioral,
            content,
            graph,
            images,
        }
    }
}

fn extract_image_features(ctx: &ScanContext) -> ImageFeatures {
    let mut features = ImageFeatures::default();
    let mut total_entropy = 0.0;
    let mut entropy_count = 0;

    for entry in &ctx.graph.objects {
        if let Some(dict) = entry_dict(entry) {
            if is_image_xobject(dict) {
                features.image_count += 1;

                // Classify by format
                let format = detect_image_format(dict);
                match format {
                    ImageFormat::JBIG2 => {
                        features.jbig2_count += 1;
                        features.risky_image_count += 1;
                    }
                    ImageFormat::JPX => {
                        features.jpx_count += 1;
                        features.risky_image_count += 1;
                    }
                    ImageFormat::JPEG => features.jpeg_count += 1,
                    ImageFormat::PNG => features.png_count += 1,
                    ImageFormat::CCITT => {
                        features.ccitt_count += 1;
                        features.risky_image_count += 1;
                    }
                    _ => {}
                }

                // Extract dimensions
                if let Some((width, height)) = get_image_dimensions(dict) {
                    features.max_image_width = features.max_image_width.max(width);
                    features.max_image_height = features.max_image_height.max(height);
                    let pixels = width as u64 * height as u64;
                    features.max_image_pixels = features.max_image_pixels.max(pixels);
                    features.total_image_pixels += pixels;

                    // Detect extreme dimensions (1xN or Nx1)
                    if width == 1 || height == 1 {
                        features.extreme_dimensions_count += 1;
                    }
                }

                // Check for filter chains
                if has_multi_filter(dict) {
                    features.multi_filter_count += 1;
                }

                // Calculate entropy (if data accessible)
                if let Some(data) = get_image_data(ctx, entry) {
                    total_entropy += entropy_score(&data);
                    entropy_count += 1;
                }
            }
        }
    }

    // Calculate average entropy
    if entropy_count > 0 {
        features.avg_image_entropy = total_entropy / entropy_count as f64;
    }

    // Detect XFA images (requires XFA parsing)
    features.xfa_image_count = count_xfa_images(ctx);

    // Malformed count requires deep analysis
    if ctx.options.deep {
        features.malformed_image_count = count_malformed_images(ctx);
    }

    features
}
```

### Feature Export Integration

Images features automatically flow through existing export:

```bash
# CSV export (now includes 16 image features)
sis query malware.pdf features > features.csv

# JSON export
sis query malware.pdf features.json

# Batch export
sis query --path corpus --glob "*.pdf" features --format jsonl > corpus_features.jsonl
```

**Total feature count:** 35 (existing) + 16 (images) = **51 features**

---

## Integration Details

### Pipeline Integration

Add image analysis call sites after object graph creation and before report assembly:

**In `crates/sis-pdf-core/src/runner.rs`:**

```rust
pub fn run_analysis(ctx: &mut ScanContext) -> Vec<Finding> {
    // ... existing detector calls ...

    // Image analysis (static - always runs)
    if ctx.options.image_static {
        let image_static_findings = image_analysis::analyze_static(ctx);
        findings.extend(image_static_findings);
    }

    // Image analysis (dynamic - deep mode only)
    if ctx.options.deep && ctx.options.image_dynamic {
        let image_dynamic_findings = image_analysis::analyze_dynamic(ctx);
        findings.extend(image_dynamic_findings);
    }

    // ... rest of analysis ...
}
```

### Result Mapping

Convert image analysis results into `Finding` entries:

**Attack Surface:**
- Add `AttackSurface::Images` to `crates/sis-pdf-core/src/model.rs`

**Finding metadata fields:**
```rust
// In Finding.meta:
"image.format" => "JBIG2" | "JPX" | "JPEG" | "PNG" | "CCITT" | "TIFF"
"image.filters" => "JBIG2Decode" | "JPXDecode" | "DCTDecode" | etc.
"image.width" => u32
"image.height" => u32
"image.pixels" => u64
"image.decode" => "success" | "failed" | "timeout" | "too_large" | "skipped"
"image.decode_ms" => u64
"image.decode_error" => string (if decode failed)
"image.entropy" => f64
```

**Object references:**
- `objects`: `vec!["{obj} {gen} obj"]` for image streams

**Positions:**
- Stream position previews where available

### Report Output

Extend report sections to include image findings:

**Text report section:**
```
Images:
  - JBIG2 detected (2 instances)
    └─ Object 52 0: 1x10000 pixels (suspicious dimensions)
       Filter: /JBIG2Decode
       SHA256: a1b2c3d4...
    └─ Object 67 0: 800x600 pixels
       Filter: /JBIG2Decode
       Decode: success (142ms)

  - JPEG2000 detected (1 instance)
    └─ Object 89 0: 1024x768 pixels
       Filter: /JPXDecode
       Decode: failed (malformed header)
```

### JSONL Finding Output

```json
{
  "kind": "jbig2_image_present",
  "severity": "Medium",
  "surface": "Images",
  "description": "JBIG2 image detected (risky format with exploit history)",
  "objects": ["52 0"],
  "meta": {
    "image.format": "JBIG2",
    "image.width": 1,
    "image.height": 10000,
    "image.pixels": 10000,
    "image.filters": "JBIG2Decode",
    "image.decode": "success",
    "image.decode_ms": 142,
    "image.entropy": 6.8
  },
  "positions": ["obj 52:0 /Type /XObject /Subtype /Image"]
}

{
  "kind": "image_extreme_dimensions",
  "severity": "High",
  "surface": "Images",
  "description": "Image with extreme aspect ratio (possible exploit trigger)",
  "objects": ["52 0"],
  "meta": {
    "image.format": "JBIG2",
    "image.width": 1,
    "image.height": 10000,
    "image.aspect_ratio": "1:10000"
  }
}

{
  "kind": "jpx_image_malformed",
  "severity": "High",
  "surface": "Images",
  "description": "JPEG2000 image failed decode (malformed structure)",
  "objects": ["89 0"],
  "meta": {
    "image.format": "JPX",
    "image.width": 1024,
    "image.height": 768,
    "image.filters": "JPXDecode",
    "image.decode": "failed",
    "image.decode_error": "Invalid box order in JP2 header"
  }
}
```

### SARIF Output

Image findings flow through existing SARIF output pipeline (no schema changes needed).

### Configuration

Add to `ScanOptions`:

```rust
pub struct ScanOptions {
    // ... existing fields ...

    pub image_static: bool,                  // Default: true
    pub image_dynamic: bool,                 // Default: true (when deep=true)
    pub image_decode_timeout_ms: u64,        // Default: 250ms
    pub image_max_pixels: u64,               // Default: 100 million
    pub image_max_decode_bytes: u64,         // Default: 256 MB
    pub image_total_budget_ms: u64,          // Default: 5000ms (5 seconds)
    pub image_skip_threshold: usize,         // Default: 50 images
}
```

Add to config file (`config.toml`):

```toml
[scan]
# ... existing scan options ...

# Image analysis options
image_static = true
image_dynamic = true  # Requires deep = true
image_decode_timeout_ms = 250
image_max_pixels = 100000000  # 100 million
image_max_decode_bytes = 268435456  # 256 MB
image_total_budget_ms = 5000  # 5 seconds total per PDF
image_skip_threshold = 50  # Skip dynamic if >50 images
```

Add CLI flags to `crates/sis-pdf/src/main.rs`:

```rust
#[arg(long, help = "Disable static image analysis")]
no_image_static: bool,

#[arg(long, help = "Disable dynamic image decoding (deep mode only)")]
no_image_decode: bool,
```

### Chain Scoring Integration

When image objects participate in action chains, boost risk scores:

**In `crates/sis-pdf-core/src/chain_score.rs` (or relevant module):**

```rust
fn calculate_chain_risk_score(chain: &ActionChain, ctx: &ScanContext) -> f32 {
    let mut score = base_risk_score(chain);

    // ... existing scoring logic ...

    // Boost for image involvement
    if chain_references_risky_image(chain, ctx) {
        score *= 1.5;
        add_chain_note(
            chain,
            "Chain references JBIG2/JPX image (exploit vector)"
        );
    }

    if chain_references_malformed_image(chain, ctx) {
        score *= 1.8;
        add_chain_note(
            chain,
            "Chain references malformed image (possible exploit trigger)"
        );
    }

    // JS + risky image combination
    if chain.involves_js && chain_references_risky_image(chain, ctx) {
        score *= 1.3;
        add_chain_note(
            chain,
            "JavaScript chain references risky image format"
        );
    }

    score
}

fn chain_references_risky_image(chain: &ActionChain, ctx: &ScanContext) -> bool {
    for edge in &chain.edges {
        if is_risky_image_object(ctx, edge.dst) {
            return true;
        }
    }
    false
}

fn is_risky_image_object(ctx: &ScanContext, obj_ref: (u32, u16)) -> bool {
    if let Some(entry) = ctx.graph.get_object(obj_ref.0, obj_ref.1) {
        if let Some(dict) = entry_dict(entry) {
            if is_image_xobject(dict) {
                let format = detect_image_format(dict);
                return matches!(
                    format,
                    ImageFormat::JBIG2 | ImageFormat::JPX | ImageFormat::CCITT
                );
            }
        }
    }
    false
}
```

**Chain metadata addition:**

Add to chain JSON output:

```json
{
  "chain_id": 5,
  "risk_score": 8.7,
  "score_factors": [
    "automatic_trigger",
    "involves_javascript",
    "references_risky_image",
    "malformed_image_in_chain"
  ],
  "notes": [
    "OpenAction triggers JavaScript",
    "JavaScript references JBIG2 image at object 52 0",
    "JBIG2 image has suspicious 1x10000 dimensions"
  ]
}
```

---

## Decoder Dependency Review

**Priority:** Critical for security and maintainability.

### Decoder Crate Audit

| Decoder | Crate | Version | Audit Status | Security Notes | Fallback Strategy |
|---------|-------|---------|--------------|----------------|-------------------|
| **JBIG2** | `jbig2dec` or custom | TBD | ⚠️ Unaudited | JBIG2 has exploit history (FORCEDENTRY) | Skip decode, emit `jbig2_image_present` finding |
| **JPEG2000** | `jpeg2000` or custom | TBD | ⚠️ Unaudited | JPX has known vulnerabilities (CVE-2018-4990) | Skip decode, emit `jpx_image_present` finding |
| **JPEG/DCT** | `jpeg-decoder` | 0.3.x | ✅ Widely used | Mature, well-tested | Built-in (required) |
| **PNG** | `png` | 0.17.x | ✅ Mature | Standard PNG decoder | Built-in (required) |
| **TIFF** | `tiff` | 0.9.x | ✅ Mature | Standard TIFF decoder | Built-in (required) |

### Dependency Pinning Strategy

**In `Cargo.toml`:**

```toml
[dependencies]
# Image decoders - exact version pinning for security
jpeg-decoder = "=0.3.1"  # No ^ or ~ for security-critical deps
png = "=0.17.13"
tiff = "=0.9.1"

[dependencies.image-analysis]
# Feature-gate risky decoders
default = ["jpeg", "png", "tiff"]
risky = ["jbig2", "jpx"]  # Opt-in for JBIG2/JPX
all = ["jpeg", "png", "tiff", "jbig2", "jpx"]
```

**In `crates/image-analysis/Cargo.toml`:**

```toml
[features]
default = ["jpeg", "png", "tiff"]
jpeg = ["jpeg-decoder"]
png = ["dep:png"]
tiff = ["dep:tiff"]
jbig2 = []  # TODO: Add JBIG2 decoder when available
jpx = []    # TODO: Add JPX decoder when available
risky = ["jbig2", "jpx"]

[dependencies]
jpeg-decoder = { version = "=0.3.1", optional = true }
png = { version = "=0.17.13", optional = true }
tiff = { version = "=0.9.1", optional = true }
```

### Security Audit Process

**CI Integration:**

```yaml
# .github/workflows/security-audit.yml
- name: Audit image decoder dependencies
  run: |
    cargo audit --deny warnings
    cargo audit --file crates/image-analysis/Cargo.lock

- name: Check for known vulnerabilities in image decoders
  run: |
    cargo deny check advisories
```

**Fuzzing Recommendation (see Testing section below):**

```bash
# Fuzz all decoders
cargo fuzz run jbig2_decode -- -max_total_time=300
cargo fuzz run jpx_decode -- -max_total_time=300
cargo fuzz run jpeg_decode -- -max_total_time=300
```

### Fallback Strategy

**If decoder unavailable at compile time:**

```rust
// In dynamic.rs:
#[cfg(feature = "jbig2")]
fn decode_jbig2(data: &[u8], opts: &DecodeOptions) -> Result<DecodedImage> {
    // ... actual decode implementation ...
}

#[cfg(not(feature = "jbig2"))]
fn decode_jbig2(data: &[u8], opts: &DecodeOptions) -> Result<DecodedImage> {
    Err(anyhow!("JBIG2 decoder not available (compile with --features jbig2)"))
}
```

**If decode fails at runtime:**

```rust
// Treat decode failure as finding, not error:
match decode_image(data, format, opts) {
    Ok(decoded) => {
        emit_finding(ImageFinding {
            kind: format!("{}_image_present", format.to_lowercase()),
            severity: Severity::Medium,
            // ... metadata ...
        });
    }
    Err(e) => {
        emit_finding(ImageFinding {
            kind: format!("{}_image_malformed", format.to_lowercase()),
            severity: Severity::High,
            meta: json!({
                "image.decode": "failed",
                "image.decode_error": e.to_string(),
            }),
        });
    }
}
```

### CLI Flags for Decoder Control

```bash
# Disable risky decoders
sis scan malware.pdf --deep --no-jbig2-decode --no-jpx-decode

# Enable all decoders (if compiled with risky feature)
sis scan malware.pdf --deep  # Default behavior with full features
```

---

## Implementation Steps

### Phase 1: MVP (Week 1)

**Goal:** Static analysis with finding integration and query support.

#### Step 1: Crate Scaffolding
- [x] Create `crates/image-analysis/` directory
- [x] Add `lib.rs` with public API
- [x] Add `static_analysis.rs` for static heuristics
- [x] Add `dynamic.rs` for dynamic decoding
- [x] Define core types:
  - `ImageStaticOptions`
  - `ImageStaticResult`
  - `ImageFinding` struct

**Files to create:**
- `crates/image-analysis/Cargo.toml`
- `crates/image-analysis/src/lib.rs`
- `crates/image-analysis/src/static_analysis.rs`
- `crates/image-analysis/src/dynamic.rs`
- `crates/image-analysis/src/util.rs`

#### Step 2: Static Image Enumeration

**XObject discovery:**
- [x] Enumerate all objects with `/Type /XObject` and `/Subtype /Image`
- [x] Extract stream dictionaries for filter/dimension analysis
- [x] Extract `/Filter`, `/Width`, `/Height`, `/BitsPerComponent`, `/ColorSpace`
- [x] Track object positions for evidence

**XFA image discovery (conditional):**
- [x] Locate XFA forms via catalog `/AcroForm /XFA`
- [x] Parse XFA XML for `<image>` tags with `href` or embedded base64
- [x] Extract referenced objects or decode inline image data
- [x] **Files to modify:** `crates/sis-pdf-pdf/src/xfa.rs` (add image extraction)

**Files to modify:**
- `crates/image-analysis/src/static_analysis.rs` (implement enumeration)
- `crates/sis-pdf-pdf/src/xfa.rs` (XFA integration)

#### Step 3: Static Heuristics
- [x] Flag presence of risky filters (`JBIG2Decode`, `JPXDecode`, `CCITTFaxDecode`)
- [x] Detect multi-filter chains and suspicious combinations
- [x] Flag anomalous dimensions:
  - Extreme size (>100 megapixels)
  - 1xN or Nx1 patterns (aspect ratio exploits)
  - Invalid ratios (0 width/height)
- [x] Sniff headers for JPEG/JP2/PNG when feasible (bounded reads, first 16 bytes)
- [x] Emit initial findings (Info/Low/Medium severity) with metadata

**Finding kinds to add:**
- `image.jbig2_present` (Low)
- `image.jpx_present` (Low)
- `image.ccitt_present` (Low)
- `image.extreme_dimensions` (Medium)
- `image.multiple_filters` (Low)
- `image.pixel_count_excessive` (Medium)

**Files to modify:**
- `crates/image-analysis/src/static_analysis.rs` (implement heuristics)

#### Step 5: Findings and Metadata

**Finding naming convention:** Follow existing codebase patterns (not `image.X`, but `X_image` or `image_X`)

**Finding IDs to add:**
- `jbig2_image_present` - JBIG2 image detected
- `jpx_image_present` - JPEG2000 image detected
- `ccitt_image_present` - CCITT Fax image detected
- `image_extreme_dimensions` - Image with suspicious dimensions
- `image_multi_filter` - Image with multiple compression filters
- `image.decode_failed` - Generic image decode failure
- `image.decode_skipped` - Decode skipped due to policy limits
- `image.decode_too_large` - Image exceeds configured decode limits
- `image.xfa_image_present` - XFA form contains embedded image

**Dynamic-only finding IDs (Phase 2):**
- `image.jbig2_malformed` - JBIG2 decode failed
- `image.jpx_malformed` - JPEG2000 decode failed
- `image.jpeg_malformed` - JPEG decode failed
- `image.ccitt_malformed` - CCITT decode failed
- `image.xfa_decode_failed` - XFA image decode failed

**Documentation:**
- [x] Add finding definitions to `docs/findings.md`
- [x] Define severity/impact/confidence for each
- [x] Add evidence expectations
- [x] Add remediation notes

**Files to modify:**
- `docs/findings.md`

#### Step 6: Integration

**Scan pipeline integration:**
- [x] Wire static analysis into detectors (image analysis detector)
- [x] Add `AttackSurface::Images` to `crates/sis-pdf-core/src/model.rs`
- [x] Ensure findings are added to report/JSON/SARIF output
- [x] Add configuration flags to `ScanOptions`
- [x] Add CLI flags: `--no-image-analysis`, `--no-image-dynamic`
- [x] Update CLI help text
- [x] Update `docs/configuration.md`
- [x] Update `docs/analysis.md`

**Query interface integration:**
- [x] Add Query enum variants to `crates/sis-pdf/src/commands/query.rs`
- [x] Implement query string parsing patterns
- [x] Implement query handlers in `execute_query_with_context()`
- [x] Add `extract_images()` helper
- [x] Add `write_image_files()` extraction function
- [x] Add image-specific predicate fields
- [x] Update REPL help text
- [x] Add query examples to `docs/query-interface.md`

**Feature vector integration:**
- [x] Add `ImageFeatures` struct to `crates/sis-pdf-core/src/features.rs`
- [x] Update `FeatureVector` to include `images` field
- [x] Update `as_f32_vec()` to include 16 image features
- [x] Update `feature_names()` with image feature names
- [x] Implement `extract_image_features()` in FeatureExtractor

**Files to modify:**
- `crates/sis-pdf-core/src/runner.rs`
- `crates/sis-pdf-core/src/model.rs`
- `crates/sis-pdf-core/src/scan.rs` (ScanOptions)
- `crates/sis-pdf/src/main.rs` (CLI flags)
- `crates/sis-pdf/src/commands/query.rs` (query integration)
- `crates/sis-pdf-core/src/features.rs` (feature vector)
- `docs/configuration.md`
- `docs/analysis.md`
- `docs/query-interface.md`

#### Step 7: Basic Testing
- [x] Add unit tests for static heuristics (synthetic image objects)
- [x] Add tests for image enumeration
- [x] Add tests for finding generation
- [x] Add query integration tests
- [x] Add feature extraction tests

**Files to create:**
- `crates/image-analysis/tests/static_tests.rs`
- `crates/sis-pdf/tests/query_images_tests.rs`
- `crates/sis-pdf-core/tests/image_features_tests.rs`

---

### Phase 2: Dynamic Analysis (Week 2)

**Goal:** Add image decoding with timeout/size limits and malformed detection.

#### Step 4: Dynamic Analysis Implementation

**Decoder integration:**
- [x] Add JPEG decoder (`jpeg-decoder` crate)
- [x] Add PNG decoder (`png` crate)
- [x] Add JBIG2 decoder (`hayro-jbig2` crate)
- [x] Add JPEG2000 decoder (`hayro-jpeg2000` crate)

**Hard limits implementation:**
- [x] Implement cooperative timeout checking (TimeoutChecker)
- [x] Implement max_pixels limit (100 million default)
- [x] Implement max_decode_bytes limit (256 MB default)
- [x] Implement total budget per PDF (5 seconds default)
- [x] Implement auto-skip threshold (50 images default)

**Findings emission:**
- [x] Emit findings for decode failures
- [x] Emit findings for malformed streams
- [x] Emit findings for resource limit violations
- [x] Record decode timing metadata

**Files to modify:**
- `crates/image-analysis/src/dynamic.rs` (full implementation)
- `crates/image-analysis/Cargo.toml` (add decoder dependencies)

#### Step 7 (continued): Extended Testing

**Dynamic analysis tests:**
- [x] Add tests for timeout enforcement
- [x] Add tests for size limit enforcement
- [x] Add tests for malformed image handling
- [x] Add tests for decode success cases

**Fixtures:**
- [ ] Add malformed JBIG2 fixture
- [ ] Add malformed JPEG2000 fixture
- [ ] Add valid image fixtures for each format

**Files to create:**
- `crates/image-analysis/tests/dynamic_tests.rs`
- `crates/sis-pdf-core/tests/fixtures/images/malformed_jbig2.pdf`
- `crates/sis-pdf-core/tests/fixtures/images/malformed_jpx.pdf`
- `crates/sis-pdf-core/tests/fixtures/images/valid_jpeg.pdf`

---

### Phase 3: Query Integration Polish (Week 3)

**Goal:** Full query interface integration with all features.

- [ ] Test all image query types end-to-end
- [ ] Test predicate filtering with images
- [ ] Test image extraction in various modes (decode/raw/hexdump)
- [ ] Test batch mode with image queries
- [ ] Test REPL mode with image queries
- [ ] Add comprehensive documentation
- [ ] Add usage examples to docs

**Files to modify:**
- `docs/query-interface.md` (comprehensive image query docs)
- `README.md` (add image analysis to feature list)

---

### Phase 4: Polish & Advanced Features (Week 4)

**Goal:** XFA support, performance optimization, CVE regression tests.

- [x] Implement full XFA image extraction (if not done in Phase 1)
- [ ] Run performance profiling with `--profile`
- [ ] Verify SLO compliance (static <1ms/image, dynamic within budget)
- [x] Generate CVE regression fixtures (synthetic)
- [x] Add CVE regression tests
- [ ] Add fuzzing infrastructure
- [ ] Add YARA integration (optional)
- [ ] Add differential analysis hooks (optional)

**CVE Fixture Generation:**
- [ ] Create `scripts/generate_image_fixtures.py`
- [x] Generate synthetic fixtures for CVE-2009-0658 (JBIG2)
- [x] Generate synthetic fixtures for CVE-2018-4990 (JPX)
- [x] Generate synthetic fixtures for CVE-2010-0188 (XFA/TIFF)
- [x] Generate synthetic fixtures for CVE-2021-30860 (JBIG2/FORCEDENTRY)

**Files to create:**
- `scripts/generate_image_fixtures.py`
- `crates/sis-pdf-core/tests/fixtures/images/cve-2009-0658-jbig2.pdf`
- `crates/sis-pdf-core/tests/fixtures/images/cve-2018-4990-jpx.pdf`
- `crates/sis-pdf-core/tests/fixtures/images/cve-2010-0188-xfa-tiff.pdf`
- `crates/sis-pdf-core/tests/fixtures/images/cve-2021-30860-jbig2.pdf`
- `crates/image-analysis/fuzz/fuzz_targets/*.rs`

---

## CVE Regression Fixtures Strategy

**Approach:** Generate synthetic fixtures that emulate structural traits of CVEs without actual exploits.

### Fixture Generation Script

Create `scripts/generate_image_fixtures.py`:

```python
#!/usr/bin/env python3
"""
Generate minimal PDF fixtures with image anomalies for testing.

These fixtures emulate structural traits of known CVEs without
containing actual exploits. They test detection heuristics and
decoder robustness.
"""

import struct
import zlib
from pathlib import Path

def generate_jbig2_extreme_dimensions():
    """CVE-2009-0658: JBIG2 with 1x10000 dimensions."""
    # Minimal PDF with JBIG2 image having extreme aspect ratio
    pdf = b"""%PDF-1.4
1 0 obj
<< /Type /XObject /Subtype /Image /Width 1 /Height 10000
   /BitsPerComponent 1 /ColorSpace /DeviceGray
   /Filter /JBIG2Decode /Length 100 >>
stream
""" + b"\x00" * 100 + b"""
endstream
endobj
xref
0 2
0000000000 65535 f
0000000009 00000 n
trailer
<< /Size 2 /Root 1 0 R >>
startxref
215
%%EOF
"""
    return pdf

def generate_jpx_malformed_header():
    """CVE-2018-4990: JPEG2000 with invalid box order."""
    # JPEG2000 with boxes out of order
    jpx_data = (
        b"\x00\x00\x00\x0C\x6A\x50\x20\x20\x0D\x0A\x87\x0A"  # JP2 signature (wrong)
        b"\x00\x00\x00\x14\x66\x74\x79\x70"  # ftyp box (should come first)
        # ... truncated for brevity
    )
    # Wrap in PDF
    compressed = zlib.compress(jpx_data)
    pdf = f"""%PDF-1.4
1 0 obj
<< /Type /XObject /Subtype /Image /Width 100 /Height 100
   /BitsPerComponent 8 /ColorSpace /DeviceRGB
   /Filter [/FlateDecode /JPXDecode] /Length {len(compressed)} >>
stream
""".encode() + compressed + b"""
endstream
endobj
xref
0 2
0000000000 65535 f
0000000009 00000 n
trailer
<< /Size 2 /Root 1 0 R >>
startxref
""" + str(200 + len(compressed)).encode() + b"""
%%EOF
"""
    return pdf

def generate_xfa_tiff():
    """CVE-2010-0188: XFA with TIFF-like data."""
    # XFA form with embedded TIFF data that fails strict parsing
    xfa_xml = """<?xml version="1.0"?>
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
  <template>
    <subform>
      <field>
        <image contentType="image/tiff">
          <!-- Malformed TIFF header (invalid byte order) -->
          <value>AAECAw==</value>
        </image>
      </field>
    </subform>
  </template>
</xdp:xdp>"""
    # Wrap in PDF with XFA
    # ... (full implementation in actual script)
    pass

def main():
    fixtures_dir = Path("crates/sis-pdf-core/tests/fixtures/images")
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    # Generate CVE fixtures
    fixtures = {
        "cve-2009-0658-jbig2.pdf": generate_jbig2_extreme_dimensions(),
        "cve-2018-4990-jpx.pdf": generate_jpx_malformed_header(),
        # "cve-2010-0188-xfa.pdf": generate_xfa_tiff(),  # TODO
        # "cve-2021-30860-jbig2.pdf": generate_jbig2_forcedentry(),  # TODO
    }

    for filename, data in fixtures.items():
        filepath = fixtures_dir / filename
        filepath.write_bytes(data)
        print(f"Generated: {filepath}")

if __name__ == "__main__":
    main()
```

**Usage:**
```bash
python3 scripts/generate_image_fixtures.py
```

### CVE Regression Tests

In `crates/image-analysis/tests/cve_regression_tests.rs`:

```rust
#[test]
fn cve_2009_0658_jbig2_extreme_dimensions() {
    let fixture = load_fixture("images/cve-2009-0658-jbig2.pdf");
    let ctx = build_scan_context(&fixture);
    let findings = image_analysis::analyze_static(&ctx);

    // Should detect JBIG2 presence
    assert!(findings.iter().any(|f| f.kind == "jbig2_image_present"));

    // Should detect extreme dimensions
    assert!(findings.iter().any(|f| f.kind == "image_extreme_dimensions"));

    // In deep mode, should attempt decode
    if ctx.options.deep {
        let dynamic_findings = image_analysis::analyze_dynamic(&ctx);
        // May emit jbig2_image_malformed depending on decoder behavior
    }
}

#[test]
fn cve_2018_4990_jpx_malformed_header() {
    let fixture = load_fixture("images/cve-2018-4990-jpx.pdf");
    let ctx = build_scan_context(&fixture);
    let findings = image_analysis::analyze_static(&ctx);

    assert!(findings.iter().any(|f| f.kind == "jpx_image_present"));

    if ctx.options.deep {
        let dynamic_findings = image_analysis::analyze_dynamic(&ctx);
        assert!(dynamic_findings.iter().any(|f| f.kind == "jpx_image_malformed"));
    }
}
```

---

## Testing Infrastructure

### Unit Tests

**Static analysis tests:**
```rust
// crates/image-analysis/tests/static_tests.rs

#[test]
fn detects_jbig2_filter() {
    let pdf = create_test_pdf_with_jbig2();
    let findings = analyze_static_from_bytes(&pdf);
    assert!(findings.iter().any(|f| f.kind == "jbig2_image_present"));
}

#[test]
fn detects_extreme_dimensions() {
    let pdf = create_pdf_with_dimensions(1, 10000);
    let findings = analyze_static_from_bytes(&pdf);
    assert!(findings.iter().any(|f| f.kind == "image_extreme_dimensions"));
}

#[test]
fn detects_multi_filter_chain() {
    let pdf = create_pdf_with_filters(&["FlateDecode", "JBIG2Decode"]);
    let findings = analyze_static_from_bytes(&pdf);
    assert!(findings.iter().any(|f| f.kind == "image_multi_filter"));
}
```

**Dynamic analysis tests:**
```rust
// crates/image-analysis/tests/dynamic_tests.rs

#[test]
fn timeout_enforcement() {
    let malformed_jbig2 = create_infinite_loop_jbig2();
    let opts = DecodeOptions {
        max_decode_ms: 100,
        ..Default::default()
    };

    let start = Instant::now();
    let result = decode_image(&malformed_jbig2, ImageFormat::JBIG2, &opts);
    let elapsed = start.elapsed().as_millis();

    assert!(result.is_err());
    assert!(elapsed < 200); // Should timeout ~100ms, not hang
}

#[test]
fn size_limit_enforcement() {
    let huge_image = create_jbig2_with_pixels(200_000_000); // 200M pixels
    let opts = DecodeOptions {
        max_pixels: 100_000_000,
        ..Default::default()
    };

    let result = decode_image(&huge_image, ImageFormat::JBIG2, &opts);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("pixel limit"));
}

#[test]
fn successful_decode_emits_metadata() {
    let valid_jpeg = include_bytes!("fixtures/valid_100x100.jpg");
    let opts = DecodeOptions::default();

    let result = decode_image(valid_jpeg, ImageFormat::JPEG, &opts).unwrap();
    assert_eq!(result.width, 100);
    assert_eq!(result.height, 100);
    assert!(result.decode_ms < 50); // Should be fast
}
```

### Fuzzing Infrastructure

**Add fuzzing targets:**

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Create fuzz directory
mkdir -p crates/image-analysis/fuzz/fuzz_targets
```

**Fuzz targets:**

```rust
// crates/image-analysis/fuzz/fuzz_targets/jbig2_decode.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use image_analysis::dynamic::{decode_image, ImageFormat, DecodeOptions};

fuzz_target!(|data: &[u8]| {
    let opts = DecodeOptions {
        max_decode_ms: 100,
        max_pixels: 10_000_000,
        max_decode_bytes: 10_000_000,
        ..Default::default()
    };

    // Should never panic, always return Ok or Err
    let _ = decode_image(data, ImageFormat::JBIG2, &opts);
});
```

```rust
// crates/image-analysis/fuzz/fuzz_targets/jpx_decode.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use image_analysis::dynamic::{decode_image, ImageFormat, DecodeOptions};

fuzz_target!(|data: &[u8]| {
    let opts = DecodeOptions::default();
    let _ = decode_image(data, ImageFormat::JPX, &opts);
});
```

**Run fuzzing:**

```bash
# Fuzz JBIG2 decoder for 5 minutes
cargo fuzz run jbig2_decode -- -max_total_time=300

# Fuzz JPX decoder
cargo fuzz run jpx_decode -- -max_total_time=300

# Fuzz with larger corpus
cargo fuzz run jbig2_decode corpus/jbig2/ -- -max_total_time=3600
```

**CI Integration:**

```yaml
# .github/workflows/fuzz.yml
name: Fuzzing

on:
  schedule:
    - cron: '0 2 * * *'  # Run nightly

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install Rust nightly
        run: rustup default nightly
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz
      - name: Fuzz JBIG2 decoder
        run: cargo fuzz run jbig2_decode -- -max_total_time=300
      - name: Fuzz JPX decoder
        run: cargo fuzz run jpx_decode -- -max_total_time=300
```

### Integration Tests

```rust
// crates/sis-pdf/tests/image_query_integration.rs

#[test]
fn query_images_lists_all_images() {
    let pdf = load_fixture("multi_image.pdf");
    let result = query(&pdf, "images").unwrap();

    match result {
        QueryResult::List(images) => {
            assert!(!images.is_empty());
            assert!(images[0].contains("Object"));
        }
        _ => panic!("Expected list result"),
    }
}

#[test]
fn query_images_jbig2_filters_format() {
    let pdf = load_fixture("mixed_images.pdf");
    let result = query(&pdf, "images.jbig2").unwrap();

    match result {
        QueryResult::List(images) => {
            for image in images {
                assert!(image.contains("JBIG2"));
            }
        }
        _ => panic!("Expected list result"),
    }
}

#[test]
fn query_images_with_predicate() {
    let pdf = load_fixture("multi_image.pdf");
    let predicate = parse_predicate("width > 1000").unwrap();
    let result = query_with_predicate(&pdf, "images", Some(&predicate)).unwrap();

    // Should only return large images
    match result {
        QueryResult::List(images) => {
            assert!(!images.is_empty());
            // Verify all results match predicate
        }
        _ => panic!("Expected list result"),
    }
}

#[test]
fn batch_mode_image_count() {
    let corpus = Path::new("tests/fixtures/images");
    run_batch_query(
        corpus,
        "*.pdf",
        "images.count",
        OutputFormat::Jsonl
    ).unwrap();

    // Verify JSONL output format
    // Verify counts are correct
}
```

---

## Nice-to-Have Features

### YARA Integration for Image Payloads

**Goal:** Run YARA rules on decoded image data to detect steganography, embedded shellcode, or known exploit patterns.

**Implementation:**

```rust
// In dynamic.rs, after successful decode:
fn analyze_image_with_yara(
    decoded: &DecodedImage,
    ctx: &ScanContext,
) -> Vec<ImageFinding> {
    let mut findings = Vec::new();

    if let Some(yara_scanner) = &ctx.yara_scanner {
        let scan_result = yara_scanner.scan_bytes(
            &decoded.data,
            &format!("image_payload_{}_{}", decoded.obj, decoded.gen)
        );

        if let Ok(matches) = scan_result {
            for yara_match in matches {
                findings.push(ImageFinding {
                    kind: "image_yara_match".to_string(),
                    severity: Severity::High,
                    description: format!(
                        "YARA rule '{}' matched in decoded image data",
                        yara_match.rule
                    ),
                    meta: json!({
                        "yara.rule": yara_match.rule,
                        "yara.namespace": yara_match.namespace,
                        "image.format": decoded.format.to_string(),
                    }),
                    objects: vec![format!("{} {}", decoded.obj, decoded.gen)],
                });
            }
        }
    }

    findings
}
```

**YARA rules for images:**

```yara
// rules/image_exploits.yar

rule JBIG2_Shellcode_Pattern {
    meta:
        description = "Detects potential shellcode in JBIG2 image data"
        severity = "high"
    strings:
        $shellcode1 = { 90 90 90 90 [4-8] 31 C0 50 68 }
        $shellcode2 = { EB ?? 5E 31 C0 88 46 ?? }
    condition:
        any of them
}

rule PNG_Steganography {
    meta:
        description = "PNG with high entropy in IDAT chunks (possible steganography)"
        severity = "medium"
    strings:
        $png_sig = { 89 50 4E 47 0D 0A 1A 0A }
        $idat = "IDAT"
    condition:
        $png_sig at 0 and #idat > 1
}
```

**Configuration:**

```toml
[scan.image_analysis]
yara_on_decoded = true  # Run YARA on decoded image data
yara_rules = "rules/image_exploits.yar"
```

**Use cases:**
- Detect steganography in PNG pixel data
- Find embedded shellcode in JBIG2 segments
- Identify known exploit patterns in JPX boxes

---

### Differential Image Analysis (Temporal Tracking)

**Goal:** Track image changes across PDF versions to detect evasion techniques.

**Integration with temporal analysis plan (plans/20260109-temporal-analysis.md):**

```rust
// In temporal analysis module:
pub struct ImageChangeAnalysis {
    pub images_added: Vec<ImageInfo>,
    pub images_removed: Vec<ImageInfo>,
    pub images_modified: Vec<ImageModification>,
}

pub struct ImageModification {
    pub obj_ref: (u32, u16),
    pub dimension_change: Option<(u32, u32, u32, u32)>, // old_w, old_h, new_w, new_h
    pub filter_change: Option<(String, String)>,        // old_filter, new_filter
    pub data_change: bool,                              // Content changed
}

fn analyze_image_changes(
    old_version: &ScanContext,
    new_version: &ScanContext,
) -> ImageChangeAnalysis {
    // Compare image objects between versions
    // Detect additions, removals, modifications
    // Flag suspicious changes:
    //   - Dimension changes (legitimate resize vs exploit trigger)
    //   - Filter swaps (compression change as evasion)
    //   - Format changes (JPEG -> JBIG2)
}
```

**Findings:**
- `image_added_in_version` - New image appeared in updated PDF
- `image_dimension_changed` - Image dimensions modified
- `image_filter_changed` - Compression filter changed
- `image_format_changed` - Format conversion (JPEG -> JBIG2)

**Defer to:** Temporal analysis implementation (not in scope for MVP).

---

### Process Isolation (Post-1.0)

**Goal:** Run image decoders in isolated processes for defense-in-depth.

**Risk:** Even memory-safe Rust decoders can have:
- Logic bugs causing excessive memory allocation (DoS)
- Infinite loops despite timeout checks
- Stack overflow in deep recursion

**Option A: WebAssembly Sandbox**

```rust
// Compile decoders to WASM, run in wasmtime
use wasmtime::*;

fn decode_in_wasm(data: &[u8], format: ImageFormat) -> Result<DecodedImage> {
    let engine = Engine::default();
    let module = Module::from_file(&engine, "decoders/jbig2_decoder.wasm")?;

    let mut store = Store::new(&engine, ());
    store.limiter(|_| ResourceLimiter {
        memory_size: 256 * 1024 * 1024, // 256 MB max
        ..Default::default()
    });

    let instance = Instance::new(&mut store, &module, &[])?;
    let decode_fn = instance.get_typed_func::<(u32, u32), u32>(&mut store, "decode")?;

    // Call WASM function with timeout
    let result = decode_fn.call(&mut store, (data.as_ptr() as u32, data.len() as u32))?;

    Ok(result)
}
```

**Pros:**
- Platform-independent
- Strong isolation
- Configurable resource limits enforced by runtime

**Cons:**
- Performance overhead (~2-3x slower)
- Requires async runtime
- Additional complexity

**Option B: Process-per-Decode**

```rust
use std::process::{Command, Stdio};
use std::time::Duration;

fn decode_in_subprocess(data: &[u8], format: ImageFormat) -> Result<DecodedImage> {
    let mut child = Command::new("sis-image-decoder")
        .arg(format.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    child.stdin.as_mut().unwrap().write_all(data)?;

    // OS-level timeout via waitpid
    let output = wait_timeout(&mut child, Duration::from_millis(250))?;

    if output.status.success() {
        parse_decoded_output(&output.stdout)
    } else {
        Err(anyhow!("Decoder subprocess failed"))
    }
}
```

**Pros:**
- OS-enforced limits (timeout, memory)
- Simple implementation

**Cons:**
- Process creation overhead (~10-20ms per image)
- Platform-specific (fork on Unix, CreateProcess on Windows)

**Decision:** Defer to post-1.0. Document as **known limitation** in security section:

> **Known Limitation:** Image decoders run in-process with cooperative timeout checking. While using memory-safe Rust decoders mitigates many risks, logic bugs could still cause resource exhaustion. For production deployment with untrusted PDFs, consider:
> - Running sis-pdf in a container with resource limits
> - Using batch mode with process-level timeouts
> - Monitoring memory usage and implementing OOM safeguards
>
> Future versions may add process-level sandboxing for defense-in-depth.

---

## Risks and Mitigations

### Risk: Performance Cost

**Mitigation:**
- Keep static analysis lightweight (<1ms per image)
- Dynamic analysis only in deep mode
- Enforce total budget per PDF (5 seconds)
- Auto-skip if >50 images detected

### Risk: Decoder Robustness

**Mitigation:**
- Prefer pure Rust decoders (memory safety)
- Guard with size/time limits
- Fuzz all decoders in CI
- Treat decode failures as findings (not errors)
- Feature-gate risky decoders (JBIG2/JPX)

### Risk: False Positives

**Mitigation:**
- Mark "present" findings as Info/Low severity
- Raise severity only on clear anomalies (extreme dimensions, malformed decode)
- Provide context in finding descriptions
- Allow users to configure severity thresholds

### Risk: Decoder Availability

**Mitigation:**
- Feature-gate JBIG2/JPX decoders
- Graceful fallback if decoder unavailable
- Emit warning, continue analysis
- Document decoder requirements

### Risk: XFA Parsing Complexity

**Mitigation:**
- Phase 1: XFA fallback (emit `xfa_images_not_analyzed`)
- Phase 4: Full XFA support if parser ready
- Don't block MVP on XFA support

---

## Status

### Phase 1: MVP (Target: Week 1)
- [x] Step 1: Crate scaffolding
- [x] Step 2: Static image enumeration (XObject + XFA fallback)
- [x] Step 3: Static heuristics
- [x] Step 5: Findings and metadata
- [x] Step 6: Integration (scan + query + features)
- [x] Step 7: Basic testing

### Phase 2: Dynamic Analysis (Target: Week 2)
- [x] Step 4: Dynamic analysis (JPEG/PNG/JBIG2/JPX)
- [ ] Step 7: Extended testing

### Phase 3: Query Polish (Target: Week 3)
- [ ] Query integration end-to-end testing
- [ ] Documentation and examples

### Phase 4: Advanced Features (Target: Week 4)
- [x] Full XFA support (if applicable)
- [ ] Performance profiling
- [x] CVE regression fixtures
- [ ] Fuzzing infrastructure
- [ ] YARA integration (nice-to-have)

---

## Success Criteria

- [ ] Static analysis runs by default with <1ms overhead per image
- [ ] Dynamic analysis runs in deep mode with resource limits enforced
- [x] Query interface supports all image query types
- [x] Image extraction works in all decode modes
- [x] Feature vector includes 16 image features
- [x] Findings flow through report/JSON/SARIF/JSONL output
- [x] Chain scoring includes image context
- [ ] All decoders fuzzed without panics
- [ ] Performance SLOs met (<5% overhead for static, <5s budget for dynamic)
- [x] Documentation complete (findings.md, query-interface.md, configuration.md)
- [x] CVE regression tests pass

---

## References

- **Query Interface:** `IMPLEMENTATION_PLAN.md` (Phases 1-9 complete)
- **Feature Extraction:** `crates/sis-pdf-core/src/features.rs`
- **Temporal Analysis:** `plans/20260109-temporal-analysis.md`
- **JBIG2 Research:** CVE-2009-0658, CVE-2021-30860 (FORCEDENTRY)
- **JPEG2000 Research:** CVE-2018-4990
- **XFA/TIFF Research:** CVE-2010-0188
