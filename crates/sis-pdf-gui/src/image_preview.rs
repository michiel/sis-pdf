use sis_pdf_pdf::blob_classify::{classify_blob, BlobKind};
use sis_pdf_pdf::decode::decode_stream;
use sis_pdf_pdf::graph::{ObjectGraph, ParseOptions};
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfStream};

#[cfg(not(target_arch = "wasm32"))]
type StageTimer = std::time::Instant;
#[cfg(target_arch = "wasm32")]
type StageTimer = f64;

fn stage_timer_start() -> StageTimer {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::Instant::now()
    }
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now()
    }
}

fn stage_timer_elapsed_ms(start: StageTimer) -> u64 {
    #[cfg(not(target_arch = "wasm32"))]
    {
        start.elapsed().as_millis() as u64
    }
    #[cfg(target_arch = "wasm32")]
    {
        let elapsed = js_sys::Date::now() - start;
        if elapsed.is_finite() && elapsed > 0.0 {
            elapsed as u64
        } else {
            0
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ImagePreviewStage {
    RawProbe,
    FullStreamDecode,
    PrefixDecode,
    ContainerDecode,
    PixelReconstruct,
    Thumbnail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ImagePreviewOutcome {
    Ready,
    SkippedBudget,
    Unsupported,
    DecodeFailed,
    ReconstructFailed,
    InvalidMetadata,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImagePreviewStatus {
    pub stage: ImagePreviewStage,
    pub outcome: ImagePreviewOutcome,
    pub detail: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub input_bytes: Option<usize>,
    #[serde(default)]
    pub output_bytes: Option<usize>,
    #[serde(default)]
    pub elapsed_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub struct PreviewLimits {
    pub max_stream_decode_bytes: usize,
    pub max_source_bytes: usize,
    pub max_preview_pixels: u64,
    pub max_preview_rgba_bytes: u64,
    pub max_preview_decode_bytes: u64,
}

impl Default for PreviewLimits {
    fn default() -> Self {
        Self {
            max_stream_decode_bytes: 8 * 1024 * 1024,
            max_source_bytes: 16 * 1024 * 1024,
            max_preview_pixels: 16_000_000,
            max_preview_rgba_bytes: 64 * 1024 * 1024,
            max_preview_decode_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PreviewBuildResult {
    pub preview: Option<(u32, u32, Vec<u8>)>,
    pub statuses: Vec<ImagePreviewStatus>,
    pub summary: String,
    pub source_used: Option<String>,
}

pub fn build_preview_for_object(
    bytes: &[u8],
    obj: u32,
    gen: u16,
    limits: PreviewLimits,
) -> Option<PreviewBuildResult> {
    let parse_opts = ParseOptions {
        recover_xref: true,
        deep: false,
        strict: false,
        max_objstm_bytes: limits.max_stream_decode_bytes,
        max_objects: 250_000,
        max_objstm_total_bytes: limits.max_stream_decode_bytes.saturating_mul(4),
        carve_stream_objects: false,
        max_carved_objects: 0,
        max_carved_bytes: 0,
    };
    let graph = sis_pdf_pdf::graph::parse_pdf(bytes, parse_opts).ok()?;
    let entry = graph.objects.iter().find(|entry| entry.obj == obj && entry.gen == gen)?;
    let PdfAtom::Stream(stream) = &entry.atom else {
        return None;
    };
    Some(build_preview_for_stream(bytes, stream, &graph, limits, None))
}

pub fn build_preview_for_stream(
    bytes: &[u8],
    stream: &PdfStream<'_>,
    graph: &ObjectGraph<'_>,
    limits: PreviewLimits,
    decoded_stream: Option<&[u8]>,
) -> PreviewBuildResult {
    let mut statuses = Vec::new();

    let start = stream.data_span.start as usize;
    let end = stream.data_span.end as usize;
    if !(start < end && end <= bytes.len()) {
        statuses.push(ImagePreviewStatus {
            stage: ImagePreviewStage::RawProbe,
            outcome: ImagePreviewOutcome::InvalidMetadata,
            detail: "Invalid stream span".to_string(),
            source: Some("stream".to_string()),
            input_bytes: None,
            output_bytes: None,
            elapsed_ms: None,
        });
        return PreviewBuildResult {
            preview: None,
            summary: "Preview unavailable (invalid stream span)".to_string(),
            statuses,
            source_used: None,
        };
    }
    let raw_bytes = &bytes[start..end];
    if raw_bytes.len() > limits.max_source_bytes {
        statuses.push(ImagePreviewStatus {
            stage: ImagePreviewStage::RawProbe,
            outcome: ImagePreviewOutcome::SkippedBudget,
            detail: format!(
                "Raw stream exceeds preview source budget ({} > {})",
                raw_bytes.len(),
                limits.max_source_bytes
            ),
            source: Some("raw".to_string()),
            input_bytes: Some(raw_bytes.len()),
            output_bytes: None,
            elapsed_ms: None,
        });
        return PreviewBuildResult {
            preview: None,
            summary: "Unavailable: raw stream exceeded preview source budget".to_string(),
            statuses,
            source_used: None,
        };
    }
    let raw_kind = classify_blob(raw_bytes);
    statuses.push(ImagePreviewStatus {
        stage: ImagePreviewStage::RawProbe,
        outcome: ImagePreviewOutcome::Ready,
        detail: format!("Raw probe blob kind: {}", raw_kind.as_str()),
        source: Some("raw".to_string()),
        input_bytes: Some(raw_bytes.len()),
        output_bytes: None,
        elapsed_ms: None,
    });

    let (raw_preview, raw_ready) = generate_image_preview(
        raw_bytes,
        raw_kind,
        &stream.dict,
        graph,
        &mut statuses,
        limits,
        "raw",
    );
    if raw_ready {
        return PreviewBuildResult {
            preview: raw_preview,
            summary: "Ready: decoded from raw stream bytes".to_string(),
            statuses,
            source_used: Some("raw".to_string()),
        };
    }

    if let Some(decoded) = decoded_stream {
        statuses.push(ImagePreviewStatus {
            stage: ImagePreviewStage::FullStreamDecode,
            outcome: ImagePreviewOutcome::Ready,
            detail: format!("Decoded stream reused ({} bytes)", decoded.len()),
            source: Some("reused-decoded".to_string()),
            input_bytes: Some(raw_bytes.len()),
            output_bytes: Some(decoded.len()),
            elapsed_ms: None,
        });
        let kind = classify_blob(decoded);
        let (preview, ready) = generate_image_preview(
            decoded,
            kind,
            &stream.dict,
            graph,
            &mut statuses,
            limits,
            "reused-decoded",
        );
        if ready {
            return PreviewBuildResult {
                preview,
                summary: "Ready: decoded from stream bytes".to_string(),
                statuses,
                source_used: Some("reused-decoded".to_string()),
            };
        }
    } else {
        let decode_start = stage_timer_start();
        match decode_stream(bytes, stream, limits.max_stream_decode_bytes) {
            Ok(decoded) => {
                statuses.push(ImagePreviewStatus {
                    stage: ImagePreviewStage::FullStreamDecode,
                    outcome: ImagePreviewOutcome::Ready,
                    detail: format!("Decoded {} bytes", decoded.data.len()),
                    source: Some("full-decode".to_string()),
                    input_bytes: Some(raw_bytes.len()),
                    output_bytes: Some(decoded.data.len()),
                    elapsed_ms: Some(stage_timer_elapsed_ms(decode_start)),
                });
                let kind = classify_blob(&decoded.data);
                let (preview, ready) = generate_image_preview(
                    &decoded.data,
                    kind,
                    &stream.dict,
                    graph,
                    &mut statuses,
                    limits,
                    "full-decode",
                );
                if ready {
                    return PreviewBuildResult {
                        preview,
                        summary: "Ready: decoded from stream bytes".to_string(),
                        statuses,
                        source_used: Some("full-decode".to_string()),
                    };
                }
            }
            Err(err) => {
                statuses.push(ImagePreviewStatus {
                    stage: ImagePreviewStage::FullStreamDecode,
                    outcome: ImagePreviewOutcome::DecodeFailed,
                    detail: format!("Stream decode failed: {err}"),
                    source: Some("full-decode".to_string()),
                    input_bytes: Some(raw_bytes.len()),
                    output_bytes: None,
                    elapsed_ms: Some(stage_timer_elapsed_ms(decode_start)),
                });
            }
        }
    }

    let prefix_start = stage_timer_start();
    if let Some(prefix_decoded) =
        decode_stream_with_non_deferred_prefix(bytes, stream, limits.max_stream_decode_bytes)
    {
        statuses.push(ImagePreviewStatus {
            stage: ImagePreviewStage::PrefixDecode,
            outcome: ImagePreviewOutcome::Ready,
            detail: format!("Decoded non-deferred prefix ({} bytes)", prefix_decoded.len()),
            source: Some("prefix-decoded".to_string()),
            input_bytes: Some(raw_bytes.len()),
            output_bytes: Some(prefix_decoded.len()),
            elapsed_ms: Some(stage_timer_elapsed_ms(prefix_start)),
        });
        let kind = classify_blob(&prefix_decoded);
        let (preview, ready) = generate_image_preview(
            &prefix_decoded,
            kind,
            &stream.dict,
            graph,
            &mut statuses,
            limits,
            "prefix-decoded",
        );
        if ready {
            return PreviewBuildResult {
                preview,
                summary: "Ready: decoded using non-deferred filter prefix".to_string(),
                statuses,
                source_used: Some("prefix-decoded".to_string()),
            };
        }
    } else {
        statuses.push(ImagePreviewStatus {
            stage: ImagePreviewStage::PrefixDecode,
            outcome: ImagePreviewOutcome::Unsupported,
            detail: "No usable non-deferred filter prefix".to_string(),
            source: Some("prefix-decoded".to_string()),
            input_bytes: Some(raw_bytes.len()),
            output_bytes: None,
            elapsed_ms: Some(stage_timer_elapsed_ms(prefix_start)),
        });
    }

    PreviewBuildResult {
        preview: None,
        summary: "Unavailable: decode and reconstruction paths failed".to_string(),
        statuses,
        source_used: None,
    }
}

#[cfg(feature = "gui")]
fn reconstruct_image_preview(
    decoded: &[u8],
    dict: &PdfDict<'_>,
    graph: &ObjectGraph<'_>,
) -> Option<(u32, u32, Vec<u8>)> {
    use image::GenericImageView;

    let pixel_buf = image_analysis::pixel_buffer::reconstruct_pixels(decoded, dict, graph).ok()?;
    let (w, h) = (pixel_buf.width, pixel_buf.height);
    if w == 0 || h == 0 {
        return None;
    }
    let max_dim = w.max(h);
    if max_dim <= 256 {
        return Some((w, h, pixel_buf.rgba));
    }
    let img = image::RgbaImage::from_raw(w, h, pixel_buf.rgba)?;
    let thumb = image::DynamicImage::ImageRgba8(img).thumbnail(256, 256);
    let (tw, th) = thumb.dimensions();
    Some((tw, th, thumb.to_rgba8().into_raw()))
}

#[cfg(feature = "gui")]
fn decode_jpeg_preview(data: &[u8], limits: PreviewLimits) -> Option<(u32, u32, Vec<u8>)> {
    use image::GenericImageView;
    use image::ImageDecoder;
    use std::io::Cursor;

    let decoder = image::codecs::jpeg::JpegDecoder::new(Cursor::new(data)).ok()?;
    let (w, h) = decoder.dimensions();
    if w == 0 || h == 0 {
        return None;
    }
    let pixel_count = (w as u64).checked_mul(h as u64)?;
    if pixel_count > limits.max_preview_pixels {
        return None;
    }
    let decode_bytes = decoder.total_bytes();
    if decode_bytes > limits.max_preview_decode_bytes {
        return None;
    }
    let color = decoder.color_type();
    let mut decoded = vec![0u8; usize::try_from(decode_bytes).ok()?];
    let decoder = image::codecs::jpeg::JpegDecoder::new(Cursor::new(data)).ok()?;
    decoder.read_image(&mut decoded).ok()?;

    let rgba = match color {
        image::ColorType::L8 => {
            let mut rgba = Vec::with_capacity(usize::try_from(pixel_count.checked_mul(4)?).ok()?);
            for &v in &decoded {
                rgba.extend_from_slice(&[v, v, v, 255]);
            }
            rgba
        }
        image::ColorType::Rgb8 => {
            let mut rgba = Vec::with_capacity(usize::try_from(pixel_count.checked_mul(4)?).ok()?);
            for chunk in decoded.chunks_exact(3) {
                rgba.extend_from_slice(&[chunk[0], chunk[1], chunk[2], 255]);
            }
            rgba
        }
        _ => return None,
    };
    if (rgba.len() as u64) > limits.max_preview_rgba_bytes {
        return None;
    }
    let img = image::RgbaImage::from_raw(w, h, rgba)?;
    let thumb = if w.max(h) > 256 {
        image::DynamicImage::ImageRgba8(img).thumbnail(256, 256)
    } else {
        image::DynamicImage::ImageRgba8(img)
    };
    let (tw, th) = thumb.dimensions();
    Some((tw, th, thumb.to_rgba8().into_raw()))
}

#[cfg(feature = "gui")]
fn decode_image_preview(data: &[u8], limits: PreviewLimits) -> Option<(u32, u32, Vec<u8>)> {
    use image::GenericImageView;

    let img = image::load_from_memory(data).ok()?;
    let (w, h) = img.dimensions();
    if w == 0 || h == 0 {
        return None;
    }
    let pixel_count = (w as u64).checked_mul(h as u64)?;
    if pixel_count > limits.max_preview_pixels {
        return None;
    }
    let thumb = if w.max(h) > 256 { img.thumbnail(256, 256) } else { img };
    let (tw, th) = thumb.dimensions();
    let rgba = thumb.to_rgba8().into_raw();
    if (rgba.len() as u64) > limits.max_preview_rgba_bytes {
        return None;
    }
    Some((tw, th, rgba))
}

fn decode_stream_with_non_deferred_prefix(
    bytes: &[u8],
    stream: &PdfStream<'_>,
    max_decode_bytes: usize,
) -> Option<Vec<u8>> {
    let filters = sis_pdf_pdf::decode::stream_filters(&stream.dict);
    if filters.is_empty() {
        return None;
    }
    let prefix_len = filters.iter().take_while(|f| !is_deferred_image_filter(f)).count();
    if prefix_len == 0 || prefix_len >= filters.len() {
        return None;
    }
    let mut prefix_dict = stream.dict.clone();
    truncate_filter_chain_for_prefix(&mut prefix_dict, prefix_len);
    let prefix_stream = PdfStream { dict: prefix_dict, data_span: stream.data_span };
    let decoded = decode_stream(bytes, &prefix_stream, max_decode_bytes).ok()?;
    Some(decoded.data)
}

fn is_deferred_image_filter(filter: &str) -> bool {
    matches!(
        filter,
        "/DCTDecode"
            | "/DCT"
            | "/JPXDecode"
            | "/JPX"
            | "/JBIG2Decode"
            | "/JBIG2"
            | "/CCITTFaxDecode"
            | "/CCITTFax"
    )
}

fn truncate_filter_chain_for_prefix(dict: &mut PdfDict<'_>, prefix_len: usize) {
    for (key, value) in dict.entries.iter_mut() {
        if key.decoded.eq_ignore_ascii_case(b"/Filter") {
            if let PdfAtom::Array(items) = &mut value.atom {
                items.truncate(prefix_len);
                if prefix_len == 1 {
                    if let Some(first) = items.first().cloned() {
                        value.atom = first.atom;
                    }
                }
            }
            continue;
        }
        if key.decoded.eq_ignore_ascii_case(b"/DecodeParms") {
            if let PdfAtom::Array(items) = &mut value.atom {
                items.truncate(prefix_len);
            }
        }
    }
}

fn generate_image_preview(
    decoded: &[u8],
    blob_kind: BlobKind,
    dict: &PdfDict<'_>,
    graph: &ObjectGraph<'_>,
    statuses: &mut Vec<ImagePreviewStatus>,
    limits: PreviewLimits,
    source_label: &str,
) -> (Option<(u32, u32, Vec<u8>)>, bool) {
    #[cfg(not(feature = "gui"))]
    {
        let _ = (decoded, blob_kind, dict, graph, limits);
        statuses.push(ImagePreviewStatus {
            stage: ImagePreviewStage::ContainerDecode,
            outcome: ImagePreviewOutcome::Unsupported,
            detail: "GUI image decode support disabled".to_string(),
            source: Some(source_label.to_string()),
            input_bytes: Some(decoded.len()),
            output_bytes: None,
            elapsed_ms: None,
        });
        return (None, false);
    }

    #[cfg(feature = "gui")]
    {
        match blob_kind {
            BlobKind::Jpeg => {
                let stage_start = stage_timer_start();
                let preview = decode_jpeg_preview(decoded, limits);
                if preview.is_some() {
                    let out_bytes = preview.as_ref().map(|(_, _, rgba)| rgba.len());
                    statuses.push(ImagePreviewStatus {
                        stage: ImagePreviewStage::ContainerDecode,
                        outcome: ImagePreviewOutcome::Ready,
                        detail: "JPEG container decode succeeded".to_string(),
                        source: Some(source_label.to_string()),
                        input_bytes: Some(decoded.len()),
                        output_bytes: out_bytes,
                        elapsed_ms: Some(stage_timer_elapsed_ms(stage_start)),
                    });
                    statuses.push(ImagePreviewStatus {
                        stage: ImagePreviewStage::Thumbnail,
                        outcome: ImagePreviewOutcome::Ready,
                        detail: "Thumbnail generated".to_string(),
                        source: Some(source_label.to_string()),
                        input_bytes: Some(decoded.len()),
                        output_bytes: out_bytes,
                        elapsed_ms: Some(stage_timer_elapsed_ms(stage_start)),
                    });
                    (preview, true)
                } else {
                    statuses.push(ImagePreviewStatus {
                        stage: ImagePreviewStage::ContainerDecode,
                        outcome: ImagePreviewOutcome::DecodeFailed,
                        detail: "JPEG container decode failed or exceeded limits".to_string(),
                        source: Some(source_label.to_string()),
                        input_bytes: Some(decoded.len()),
                        output_bytes: None,
                        elapsed_ms: Some(stage_timer_elapsed_ms(stage_start)),
                    });
                    (None, false)
                }
            }
            BlobKind::Png | BlobKind::Gif | BlobKind::Bmp | BlobKind::Tiff | BlobKind::Webp => {
                let stage_start = stage_timer_start();
                let preview = decode_image_preview(decoded, limits);
                if preview.is_some() {
                    let out_bytes = preview.as_ref().map(|(_, _, rgba)| rgba.len());
                    statuses.push(ImagePreviewStatus {
                        stage: ImagePreviewStage::ContainerDecode,
                        outcome: ImagePreviewOutcome::Ready,
                        detail: format!("{} container decode succeeded", blob_kind.as_str()),
                        source: Some(source_label.to_string()),
                        input_bytes: Some(decoded.len()),
                        output_bytes: out_bytes,
                        elapsed_ms: Some(stage_timer_elapsed_ms(stage_start)),
                    });
                    statuses.push(ImagePreviewStatus {
                        stage: ImagePreviewStage::Thumbnail,
                        outcome: ImagePreviewOutcome::Ready,
                        detail: "Thumbnail generated".to_string(),
                        source: Some(source_label.to_string()),
                        input_bytes: Some(decoded.len()),
                        output_bytes: out_bytes,
                        elapsed_ms: Some(stage_timer_elapsed_ms(stage_start)),
                    });
                    (preview, true)
                } else {
                    statuses.push(ImagePreviewStatus {
                        stage: ImagePreviewStage::ContainerDecode,
                        outcome: ImagePreviewOutcome::DecodeFailed,
                        detail: format!(
                            "{} container decode failed or exceeded limits",
                            blob_kind.as_str()
                        ),
                        source: Some(source_label.to_string()),
                        input_bytes: Some(decoded.len()),
                        output_bytes: None,
                        elapsed_ms: Some(stage_timer_elapsed_ms(stage_start)),
                    });
                    (None, false)
                }
            }
            _ => {
                let container_start = stage_timer_start();
                let generic = decode_image_preview(decoded, limits);
                if generic.is_some() {
                    let out_bytes = generic.as_ref().map(|(_, _, rgba)| rgba.len());
                    statuses.push(ImagePreviewStatus {
                        stage: ImagePreviewStage::ContainerDecode,
                        outcome: ImagePreviewOutcome::Ready,
                        detail: "Generic container decode succeeded".to_string(),
                        source: Some(source_label.to_string()),
                        input_bytes: Some(decoded.len()),
                        output_bytes: out_bytes,
                        elapsed_ms: Some(stage_timer_elapsed_ms(container_start)),
                    });
                    statuses.push(ImagePreviewStatus {
                        stage: ImagePreviewStage::Thumbnail,
                        outcome: ImagePreviewOutcome::Ready,
                        detail: "Thumbnail generated".to_string(),
                        source: Some(source_label.to_string()),
                        input_bytes: Some(decoded.len()),
                        output_bytes: out_bytes,
                        elapsed_ms: Some(stage_timer_elapsed_ms(container_start)),
                    });
                    return (generic, true);
                }
                statuses.push(ImagePreviewStatus {
                    stage: ImagePreviewStage::ContainerDecode,
                    outcome: ImagePreviewOutcome::Unsupported,
                    detail: format!("Unsupported container kind {}", blob_kind.as_str()),
                    source: Some(source_label.to_string()),
                    input_bytes: Some(decoded.len()),
                    output_bytes: None,
                    elapsed_ms: Some(stage_timer_elapsed_ms(container_start)),
                });
                let reconstruct_start = stage_timer_start();
                let reconstructed = reconstruct_image_preview(decoded, dict, graph);
                if reconstructed.is_some() {
                    let out_bytes = reconstructed.as_ref().map(|(_, _, rgba)| rgba.len());
                    statuses.push(ImagePreviewStatus {
                        stage: ImagePreviewStage::PixelReconstruct,
                        outcome: ImagePreviewOutcome::Ready,
                        detail: "Raw pixel reconstruction succeeded".to_string(),
                        source: Some(source_label.to_string()),
                        input_bytes: Some(decoded.len()),
                        output_bytes: out_bytes,
                        elapsed_ms: Some(stage_timer_elapsed_ms(reconstruct_start)),
                    });
                    statuses.push(ImagePreviewStatus {
                        stage: ImagePreviewStage::Thumbnail,
                        outcome: ImagePreviewOutcome::Ready,
                        detail: "Thumbnail generated".to_string(),
                        source: Some(source_label.to_string()),
                        input_bytes: Some(decoded.len()),
                        output_bytes: out_bytes,
                        elapsed_ms: Some(stage_timer_elapsed_ms(reconstruct_start)),
                    });
                    (reconstructed, true)
                } else {
                    statuses.push(ImagePreviewStatus {
                        stage: ImagePreviewStage::PixelReconstruct,
                        outcome: ImagePreviewOutcome::ReconstructFailed,
                        detail: "Raw pixel reconstruction failed".to_string(),
                        source: Some(source_label.to_string()),
                        input_bytes: Some(decoded.len()),
                        output_bytes: None,
                        elapsed_ms: Some(stage_timer_elapsed_ms(reconstruct_start)),
                    });
                    (None, false)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sis_pdf_pdf::object::{PdfName, PdfObj};
    use sis_pdf_pdf::span::Span;
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::time::Instant;

    fn empty_graph<'a>(bytes: &'a [u8]) -> ObjectGraph<'a> {
        ObjectGraph {
            bytes,
            objects: Vec::new(),
            index: HashMap::new(),
            trailers: Vec::new(),
            startxrefs: Vec::new(),
            xref_sections: Vec::new(),
            deviations: Vec::new(),
            telemetry_events: Vec::new(),
        }
    }

    fn span() -> Span {
        Span { start: 0, end: 0 }
    }

    fn name(decoded: &[u8]) -> PdfName<'static> {
        PdfName { span: span(), raw: Cow::Owned(decoded.to_vec()), decoded: decoded.to_vec() }
    }

    fn obj(atom: PdfAtom<'static>) -> PdfObj<'static> {
        PdfObj { span: span(), atom }
    }

    #[test]
    fn stage_outcomes_include_prefix_decode_when_full_decode_defers() {
        let encoded = b"414243>";
        let stream = PdfStream {
            dict: PdfDict {
                span: span(),
                entries: vec![(
                    name(b"/Filter"),
                    obj(PdfAtom::Array(vec![
                        obj(PdfAtom::Name(name(b"/ASCIIHexDecode"))),
                        obj(PdfAtom::Name(name(b"/DCTDecode"))),
                    ])),
                )],
            },
            data_span: Span { start: 0, end: encoded.len() as u64 },
        };
        let graph = empty_graph(encoded);
        let result =
            build_preview_for_stream(encoded, &stream, &graph, PreviewLimits::default(), None);
        assert!(result.preview.is_none());
        assert!(result.statuses.iter().any(|status| {
            status.stage == ImagePreviewStage::FullStreamDecode
                && status.outcome == ImagePreviewOutcome::DecodeFailed
        }));
        assert!(result.statuses.iter().any(|status| {
            status.stage == ImagePreviewStage::PrefixDecode
                && status.outcome == ImagePreviewOutcome::Ready
        }));
        assert!(result.statuses.iter().any(|status| {
            status.stage == ImagePreviewStage::RawProbe
                && status.source.as_deref() == Some("raw")
                && status.input_bytes == Some(encoded.len())
        }));
    }

    #[test]
    fn stage_outcomes_report_prefix_unsupported_for_deferred_only_chain() {
        let encoded = b"\xFF\xD8\xFF";
        let stream = PdfStream {
            dict: PdfDict {
                span: span(),
                entries: vec![(
                    name(b"/Filter"),
                    obj(PdfAtom::Array(vec![obj(PdfAtom::Name(name(b"/DCTDecode")))])),
                )],
            },
            data_span: Span { start: 0, end: encoded.len() as u64 },
        };
        let graph = empty_graph(encoded);
        let result =
            build_preview_for_stream(encoded, &stream, &graph, PreviewLimits::default(), None);
        assert!(result.statuses.iter().any(|status| {
            status.stage == ImagePreviewStage::PrefixDecode
                && status.outcome == ImagePreviewOutcome::Unsupported
        }));
    }

    #[test]
    fn stage_outcomes_report_invalid_stream_span() {
        let encoded = b"abc";
        let stream = PdfStream {
            dict: PdfDict { span: span(), entries: Vec::new() },
            data_span: Span { start: 2, end: 9 },
        };
        let graph = empty_graph(encoded);
        let result =
            build_preview_for_stream(encoded, &stream, &graph, PreviewLimits::default(), None);
        assert_eq!(result.summary, "Preview unavailable (invalid stream span)");
        assert_eq!(result.statuses.len(), 1);
        assert_eq!(result.statuses[0].stage, ImagePreviewStage::RawProbe);
        assert_eq!(result.statuses[0].outcome, ImagePreviewOutcome::InvalidMetadata);
    }

    #[test]
    fn preview_pipeline_budget_mixed_filters() {
        let encoded = b"414243>";
        let stream = PdfStream {
            dict: PdfDict {
                span: span(),
                entries: vec![(
                    name(b"/Filter"),
                    obj(PdfAtom::Array(vec![
                        obj(PdfAtom::Name(name(b"/ASCIIHexDecode"))),
                        obj(PdfAtom::Name(name(b"/DCTDecode"))),
                    ])),
                )],
            },
            data_span: Span { start: 0, end: encoded.len() as u64 },
        };
        let graph = empty_graph(encoded);
        let start = Instant::now();
        let result =
            build_preview_for_stream(encoded, &stream, &graph, PreviewLimits::default(), None);
        let elapsed = start.elapsed().as_millis() as u64;
        assert!(elapsed < 200, "mixed-filter preview pipeline should be fast, got {elapsed} ms");
        assert!(result.statuses.iter().any(|status| {
            status.stage == ImagePreviewStage::PrefixDecode
                && status.outcome == ImagePreviewOutcome::Ready
        }));
    }

    #[test]
    fn preview_pipeline_budget_large_source_bytes() {
        let encoded = vec![0u8; 128];
        let stream = PdfStream {
            dict: PdfDict { span: span(), entries: Vec::new() },
            data_span: Span { start: 0, end: encoded.len() as u64 },
        };
        let graph = empty_graph(&encoded);
        let limits = PreviewLimits { max_source_bytes: 64, ..PreviewLimits::default() };
        let result = build_preview_for_stream(&encoded, &stream, &graph, limits, None);
        assert!(result.preview.is_none());
        assert_eq!(result.summary, "Unavailable: raw stream exceeded preview source budget");
        assert!(result.statuses.iter().any(|status| {
            status.stage == ImagePreviewStage::RawProbe
                && status.outcome == ImagePreviewOutcome::SkippedBudget
        }));
    }

    #[test]
    fn preview_pipeline_budget_large_raw_pixels_fast_fail() {
        let encoded = vec![0u8; 4 * 1024 * 1024];
        let stream = PdfStream {
            dict: PdfDict { span: span(), entries: Vec::new() },
            data_span: Span { start: 0, end: encoded.len() as u64 },
        };
        let graph = empty_graph(&encoded);
        let limits = PreviewLimits { max_source_bytes: 128 * 1024, ..PreviewLimits::default() };
        let start = Instant::now();
        let result = build_preview_for_stream(&encoded, &stream, &graph, limits, None);
        let elapsed = start.elapsed().as_millis() as u64;
        assert!(
            elapsed < 50,
            "oversized raw payload should fail fast via source-byte budget, got {elapsed} ms"
        );
        assert!(result.preview.is_none());
        assert_eq!(result.summary, "Unavailable: raw stream exceeded preview source budget");
        let gate_status = result
            .statuses
            .iter()
            .find(|status| status.stage == ImagePreviewStage::RawProbe)
            .expect("raw probe budget status");
        assert_eq!(gate_status.outcome, ImagePreviewOutcome::SkippedBudget);
        assert_eq!(gate_status.source.as_deref(), Some("raw"));
        assert_eq!(gate_status.input_bytes, Some(encoded.len()));
    }
}
