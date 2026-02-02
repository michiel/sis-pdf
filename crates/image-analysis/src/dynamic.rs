use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use sis_pdf_pdf::decode::{decode_stream_with_meta, DecodeLimits};
use sis_pdf_pdf::object::{PdfAtom, PdfStream};
use sis_pdf_pdf::xfa::extract_xfa_image_payloads;
use sis_pdf_pdf::ObjectGraph;

use crate::timeout::TimeoutChecker;
use crate::util::dict_u32;
use crate::{ImageDynamicOptions, ImageDynamicResult, ImageFinding};

pub fn analyze_dynamic_images(
    graph: &ObjectGraph<'_>,
    opts: &ImageDynamicOptions,
) -> ImageDynamicResult {
    let image_count = graph
        .objects
        .iter()
        .filter(|entry| {
            if let PdfAtom::Stream(stream) = &entry.atom {
                is_image_stream(stream)
            } else {
                false
            }
        })
        .count();
    let mut findings = Vec::new();

    if opts.skip_threshold > 0 && image_count > opts.skip_threshold {
        if let Some(entry) = graph.objects.iter().find(|entry| {
            if let PdfAtom::Stream(stream) = &entry.atom {
                is_image_stream(stream)
            } else {
                false
            }
        }) {
            let mut meta = BTreeMap::new();
            meta.insert("image.decode_skipped".into(), "too_many_images".into());
            meta.insert("image.decode".into(), "skipped".into());
            meta.insert("image.count".into(), image_count.to_string());
            meta.insert(
                "image.skip_threshold".into(),
                opts.skip_threshold.to_string(),
            );
            findings.push(ImageFinding {
                kind: "image.decode_skipped".into(),
                obj: entry.obj,
                gen: entry.gen,
                meta,
            });
        }
        return ImageDynamicResult { findings };
    }

    let mut total_decode_ms = 0u64;
    let mut budget_exceeded = false;

    for entry in &graph.objects {
        let PdfAtom::Stream(stream) = &entry.atom else {
            continue;
        };
        if !is_image_stream(stream) {
            continue;
        }

        let (filters, filter_label) = stream_filters(stream);
        let mut meta = BTreeMap::new();
        meta.insert("image.filters".into(), filter_label);
        if let Some(width) = dict_u32(&stream.dict, b"/Width") {
            meta.insert("image.width".into(), width.to_string());
        }
        if let Some(height) = dict_u32(&stream.dict, b"/Height") {
            meta.insert("image.height".into(), height.to_string());
        }

        if opts.total_budget_ms > 0 && total_decode_ms >= opts.total_budget_ms {
            meta.insert("image.decode_skipped".into(), "budget_exceeded".into());
            meta.insert("image.decode".into(), "skipped".into());
            findings.push(ImageFinding {
                kind: "image.decode_skipped".into(),
                obj: entry.obj,
                gen: entry.gen,
                meta,
            });
            budget_exceeded = true;
            break;
        }

        let Some(data) = stream_data(graph, stream) else {
            continue;
        };

        if let Some(reason) = image_exceeds_limits(stream, data, opts) {
            meta.insert("image.decode_too_large".into(), "true".into());
            meta.insert("image.decode_too_large_reason".into(), reason.into());
            meta.insert("image.decode".into(), "too_large".into());
            findings.push(ImageFinding {
                kind: "image.decode_too_large".into(),
                obj: entry.obj,
                gen: entry.gen,
                meta: meta.clone(),
            });
            continue;
        }

        let timeout = if opts.timeout_ms > 0 {
            Some(TimeoutChecker::new(
                Duration::from_millis(opts.timeout_ms),
                1024,
            ))
        } else {
            None
        };
        let timeout_ref = timeout.as_ref();
        let start = Instant::now();
        let decode_result = decode_image_data(graph, data, stream, &filters, opts, timeout_ref);
        let elapsed = timeout_ref
            .map(|checker| checker.elapsed())
            .unwrap_or_else(|| start.elapsed());
        let mut elapsed_ms = elapsed.as_millis();
        if elapsed_ms == 0 {
            elapsed_ms = 1;
        }
        let elapsed_ms = elapsed_ms as u64;
        meta.insert("image.decode_ms".into(), elapsed_ms.to_string());
        if opts.total_budget_ms > 0 {
            total_decode_ms = total_decode_ms.saturating_add(elapsed_ms);
        }

        if opts.timeout_ms > 0 && elapsed_ms >= opts.timeout_ms {
            meta.insert("image.decode".into(), "timeout".into());
            meta.insert("image.decode_skipped".into(), "timeout".into());
            findings.push(ImageFinding {
                kind: "image.decode_skipped".into(),
                obj: entry.obj,
                gen: entry.gen,
                meta: meta.clone(),
            });
            if opts.total_budget_ms > 0 && total_decode_ms >= opts.total_budget_ms {
                budget_exceeded = true;
                break;
            }
            continue;
        }

        match decode_result {
            DecodeStatus::Ok => {
                meta.insert("image.decode".into(), "success".into());
            }
            DecodeStatus::Skipped(reason) => {
                meta.insert("image.decode".into(), "skipped".into());
                meta.insert("image.decode_skipped".into(), reason.clone());
                findings.push(ImageFinding {
                    kind: "image.decode_skipped".into(),
                    obj: entry.obj,
                    gen: entry.gen,
                    meta: meta.clone(),
                });
            }
            DecodeStatus::Failed(err) => {
                meta.insert("image.decode".into(), "failed".into());
                meta.insert("image.decode_error".into(), err.clone());
                findings.push(ImageFinding {
                    kind: decode_error_kind(&filters),
                    obj: entry.obj,
                    gen: entry.gen,
                    meta: meta.clone(),
                });
            }
        }
    }

    if !budget_exceeded {
        findings.extend(analyze_xfa_images(graph, opts));
    }

    ImageDynamicResult { findings }
}

fn is_image_stream(stream: &PdfStream<'_>) -> bool {
    let Some((_, subtype)) = stream.dict.get_first(b"/Subtype") else {
        return false;
    };
    matches!(
        &subtype.atom,
        PdfAtom::Name(name) if name.decoded == b"/Image" || name.decoded == b"Image"
    )
}

fn stream_filters(stream: &PdfStream<'_>) -> (Vec<String>, String) {
    let Some((_, filter)) = stream.dict.get_first(b"/Filter") else {
        return (Vec::new(), "-".into());
    };
    match &filter.atom {
        PdfAtom::Name(name) => {
            let label = String::from_utf8_lossy(&name.decoded)
                .trim()
                .trim_start_matches('/')
                .to_string();
            (vec![label.clone()], label)
        }
        PdfAtom::Array(arr) => {
            let mut out = Vec::new();
            for item in arr {
                if let PdfAtom::Name(name) = &item.atom {
                    let label = String::from_utf8_lossy(&name.decoded)
                        .trim()
                        .trim_start_matches('/')
                        .to_string();
                    out.push(label);
                }
            }
            let label = if out.is_empty() {
                "-".into()
            } else {
                out.join(",")
            };
            (out, label)
        }
        _ => (Vec::new(), "-".into()),
    }
}

fn stream_data<'a>(graph: &'a ObjectGraph<'a>, stream: &PdfStream<'_>) -> Option<&'a [u8]> {
    let span = stream.data_span;
    let start = span.start as usize;
    let end = span.end as usize;
    if start >= end || end > graph.bytes.len() {
        return None;
    }
    Some(&graph.bytes[start..end])
}

fn image_exceeds_limits(
    stream: &PdfStream<'_>,
    data: &[u8],
    opts: &ImageDynamicOptions,
) -> Option<&'static str> {
    if opts.max_decode_bytes > 0 && data.len() > opts.max_decode_bytes {
        return Some("bytes");
    }
    let width = dict_u32(&stream.dict, b"/Width");
    let height = dict_u32(&stream.dict, b"/Height");
    let Some(width) = width else { return None };
    let Some(height) = height else { return None };
    let pixels = width as u64 * height as u64;
    if opts.max_pixels > 0 && pixels > opts.max_pixels {
        Some("pixels")
    } else {
        None
    }
}

fn decode_error_kind(filters: &[String]) -> String {
    if filters.iter().any(|f| f == "JBIG2Decode") {
        return "image.jbig2_malformed".into();
    }
    if filters.iter().any(|f| f == "JPXDecode") {
        return "image.jpx_malformed".into();
    }
    if filters.iter().any(|f| f == "DCTDecode" || f == "DCT") {
        return "image.jpeg_malformed".into();
    }
    if filters.iter().any(|f| f == "CCITTFaxDecode") {
        return "image.ccitt_malformed".into();
    }
    "image.decode_failed".into()
}

enum DecodeStatus {
    Ok,
    Skipped(String),
    Failed(String),
}

fn check_timeout(timeout: Option<&TimeoutChecker>) -> Option<DecodeStatus> {
    if let Some(checker) = timeout {
        if checker.check().is_err() {
            return Some(DecodeStatus::Skipped("timeout".into()));
        }
    }
    None
}

fn decode_image_data(
    graph: &ObjectGraph<'_>,
    data: &[u8],
    stream: &PdfStream<'_>,
    filters: &[String],
    opts: &ImageDynamicOptions,
    timeout: Option<&TimeoutChecker>,
) -> DecodeStatus {
    if let Some(status) = check_timeout(timeout) {
        return status;
    }

    if filters.len() > 1 {
        return DecodeStatus::Skipped("filter_chain_unsupported".into());
    }

    if filters.iter().any(|f| f == "JBIG2Decode") {
        if let Some(status) = check_timeout(timeout) {
            return status;
        }
        let status = decode_jbig2(graph, stream, data, opts, timeout);
        if let Some(status) = check_timeout(timeout) {
            return status;
        }
        return status;
    }

    if filters.iter().any(|f| f == "JPXDecode") {
        if let Some(status) = check_timeout(timeout) {
            return status;
        }
        let status = decode_jpx(data, opts, timeout);
        if let Some(status) = check_timeout(timeout) {
            return status;
        }
        return status;
    }

    if filters.iter().any(|f| f == "DCTDecode" || f == "DCT") {
        if let Some(status) = check_timeout(timeout) {
            return status;
        }
        let status = decode_jpeg(data, timeout);
        if let Some(status) = check_timeout(timeout) {
            return status;
        }
        return status;
    }

    if filters.iter().any(|f| f == "CCITTFaxDecode") {
        return DecodeStatus::Skipped("ccitt_decode_not_implemented".into());
    }

    if filters.is_empty() {
        if let Some(status) = check_timeout(timeout) {
            return status;
        }
        let header = &data[..data.len().min(16)];
        if header.starts_with(b"\x89PNG\r\n\x1a\n") {
            let status = decode_png(data, timeout);
            if let Some(status) = check_timeout(timeout) {
                return status;
            }
            return status;
        }
        if header.starts_with(b"II*\x00") || header.starts_with(b"MM\x00*") {
            let status = decode_tiff(data, timeout);
            if let Some(status) = check_timeout(timeout) {
                return status;
            }
            return status;
        }
        if header.starts_with(b"\xFF\xD8") {
            let status = decode_jpeg(data, timeout);
            if let Some(status) = check_timeout(timeout) {
                return status;
            }
            return status;
        }
    }
    DecodeStatus::Skipped("unknown_format".into())
}

fn analyze_xfa_images(graph: &ObjectGraph<'_>, opts: &ImageDynamicOptions) -> Vec<ImageFinding> {
    let mut findings = Vec::new();
    for entry in &graph.objects {
        let dict = match &entry.atom {
            PdfAtom::Dict(dict) => dict,
            PdfAtom::Stream(stream) => &stream.dict,
            _ => continue,
        };
        let Some((_, xfa_obj)) = dict.get_first(b"/XFA") else {
            continue;
        };
        let payloads = super::static_analysis::xfa_payloads_from_obj(
            graph,
            xfa_obj,
            sis_pdf_pdf::decode::DecodeLimits {
                max_decoded_bytes: opts.max_decode_bytes,
                max_filter_chain_depth: 8,
            },
        );
        for payload in payloads {
            for image in extract_xfa_image_payloads(&payload) {
                let mut meta = BTreeMap::new();
                meta.insert("image.xfa".into(), "true".into());
                if let Some(content_type) = image.content_type {
                    meta.insert("image.content_type".into(), content_type);
                }
                let status = decode_xfa_image(&image.bytes);
                match status {
                    DecodeStatus::Ok => {}
                    DecodeStatus::Skipped(reason) => {
                        meta.insert("image.decode_skipped".into(), reason);
                        findings.push(ImageFinding {
                            kind: "image.decode_skipped".into(),
                            obj: entry.obj,
                            gen: entry.gen,
                            meta,
                        });
                    }
                    DecodeStatus::Failed(err) => {
                        meta.insert("image.decode_error".into(), err);
                        findings.push(ImageFinding {
                            kind: "image.xfa_decode_failed".into(),
                            obj: entry.obj,
                            gen: entry.gen,
                            meta,
                        });
                    }
                }
            }
        }
    }
    findings
}

fn decode_xfa_image(bytes: &[u8]) -> DecodeStatus {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return decode_png(bytes, None);
    }
    if bytes.starts_with(b"II*\x00") || bytes.starts_with(b"MM\x00*") {
        return decode_tiff(bytes, None);
    }
    if bytes.starts_with(b"\xFF\xD8") {
        return decode_jpeg(bytes, None);
    }
    DecodeStatus::Skipped("unknown_xfa_image".into())
}

#[cfg(feature = "jpeg")]
fn decode_jpeg(bytes: &[u8], timeout: Option<&TimeoutChecker>) -> DecodeStatus {
    if let Some(status) = check_timeout(timeout) {
        return status;
    }
    let mut decoder = jpeg_decoder::Decoder::new(bytes);
    let result = decoder.decode();
    if let Some(status) = check_timeout(timeout) {
        return status;
    }
    match result {
        Ok(_) => DecodeStatus::Ok,
        Err(err) => DecodeStatus::Failed(err.to_string()),
    }
}

#[cfg(not(feature = "jpeg"))]
fn decode_jpeg(_bytes: &[u8], _timeout: Option<&TimeoutChecker>) -> DecodeStatus {
    DecodeStatus::Skipped("jpeg_decoder_unavailable".into())
}

#[cfg(feature = "png")]
fn decode_png(bytes: &[u8], timeout: Option<&TimeoutChecker>) -> DecodeStatus {
    if let Some(status) = check_timeout(timeout) {
        return status;
    }
    let cursor = std::io::Cursor::new(bytes);
    let decoder = png::Decoder::new(cursor);
    match decoder.read_info() {
        Ok(mut reader) => match reader.output_buffer_size() {
            Some(size) => {
                let mut buf = vec![0; size];
                match reader.next_frame(&mut buf) {
                    Ok(_) => {
                        if let Some(status) = check_timeout(timeout) {
                            return status;
                        }
                        DecodeStatus::Ok
                    }
                    Err(err) => DecodeStatus::Failed(err.to_string()),
                }
            }
            None => DecodeStatus::Failed("png_buffer_size_unknown".into()),
        },
        Err(err) => DecodeStatus::Failed(err.to_string()),
    }
}

#[cfg(not(feature = "png"))]
fn decode_png(_bytes: &[u8], _timeout: Option<&TimeoutChecker>) -> DecodeStatus {
    DecodeStatus::Skipped("png_decoder_unavailable".into())
}

#[cfg(feature = "tiff")]
fn decode_tiff(bytes: &[u8], timeout: Option<&TimeoutChecker>) -> DecodeStatus {
    if let Some(status) = check_timeout(timeout) {
        return status;
    }
    let cursor = std::io::Cursor::new(bytes);
    let decoder = tiff::decoder::Decoder::new(cursor);
    match decoder {
        Ok(mut decoder) => match decoder.read_image() {
            Ok(_) => {
                if let Some(status) = check_timeout(timeout) {
                    return status;
                }
                DecodeStatus::Ok
            }
            Err(err) => DecodeStatus::Failed(err.to_string()),
        },
        Err(err) => DecodeStatus::Failed(err.to_string()),
    }
}

#[cfg(not(feature = "tiff"))]
fn decode_tiff(_bytes: &[u8], _timeout: Option<&TimeoutChecker>) -> DecodeStatus {
    DecodeStatus::Skipped("tiff_decoder_unavailable".into())
}

#[cfg(feature = "jbig2")]
fn decode_jbig2(
    graph: &ObjectGraph<'_>,
    stream: &PdfStream<'_>,
    bytes: &[u8],
    opts: &ImageDynamicOptions,
    timeout: Option<&TimeoutChecker>,
) -> DecodeStatus {
    if let Some(status) = check_timeout(timeout) {
        return status;
    }
    let globals = jbig2_globals_bytes(graph, stream, opts);
    let result = if let Some(globals) = globals.as_deref() {
        hayro_jbig2::decode_embedded(bytes, Some(globals))
    } else {
        hayro_jbig2::decode(bytes)
    };
    if let Some(status) = check_timeout(timeout) {
        return status;
    }
    match result {
        Ok(image) => {
            let pixels = image.width as u64 * image.height as u64;
            if pixels > opts.max_pixels {
                DecodeStatus::Failed("pixel_limit_exceeded".into())
            } else {
                DecodeStatus::Ok
            }
        }
        Err(err) => DecodeStatus::Failed(err.to_string()),
    }
}

#[cfg(not(feature = "jbig2"))]
fn decode_jbig2(
    _graph: &ObjectGraph<'_>,
    _stream: &PdfStream<'_>,
    _bytes: &[u8],
    _opts: &ImageDynamicOptions,
    _timeout: Option<&TimeoutChecker>,
) -> DecodeStatus {
    DecodeStatus::Skipped("jbig2_decoder_unavailable".into())
}

#[cfg(feature = "jpx")]
fn decode_jpx(
    bytes: &[u8],
    opts: &ImageDynamicOptions,
    timeout: Option<&TimeoutChecker>,
) -> DecodeStatus {
    if let Some(status) = check_timeout(timeout) {
        return status;
    }
    let settings = hayro_jpeg2000::DecodeSettings {
        resolve_palette_indices: true,
        strict: true,
        target_resolution: jpeg2000_target_resolution(opts),
    };
    let image = match hayro_jpeg2000::Image::new(bytes, &settings) {
        Ok(image) => image,
        Err(err) => return DecodeStatus::Failed(err.to_string()),
    };
    let pixels = image.width() as u64 * image.height() as u64;
    if pixels > opts.max_pixels {
        DecodeStatus::Failed("pixel_limit_exceeded".into())
    } else {
        if let Some(status) = check_timeout(timeout) {
            return status;
        }
        if let Err(err) = image.decode() {
            return DecodeStatus::Failed(err.to_string());
        }
        DecodeStatus::Ok
    }
}

fn jpeg2000_target_resolution(opts: &ImageDynamicOptions) -> Option<(u32, u32)> {
    if opts.max_pixels == 0 {
        return None;
    }
    let mut max_side = (opts.max_pixels as f64).sqrt();
    if max_side < 1.0 {
        max_side = 1.0;
    }
    if max_side > u32::MAX as f64 {
        max_side = u32::MAX as f64;
    }
    Some((max_side as u32, max_side as u32))
}

#[cfg(not(feature = "jpx"))]
fn decode_jpx(
    _bytes: &[u8],
    _opts: &ImageDynamicOptions,
    _timeout: Option<&TimeoutChecker>,
) -> DecodeStatus {
    DecodeStatus::Skipped("jpx_decoder_unavailable".into())
}

fn jbig2_globals_bytes(
    graph: &ObjectGraph<'_>,
    stream: &PdfStream<'_>,
    opts: &ImageDynamicOptions,
) -> Option<Vec<u8>> {
    let (_, parms_obj) = stream.dict.get_first(b"/DecodeParms")?;
    let globals_obj = match &parms_obj.atom {
        PdfAtom::Dict(dict) => dict.get_first(b"/JBIG2Globals").map(|(_, v)| v),
        PdfAtom::Array(items) => items.iter().find_map(|item| match &item.atom {
            PdfAtom::Dict(dict) => dict.get_first(b"/JBIG2Globals").map(|(_, v)| v),
            _ => None,
        }),
        _ => None,
    }?;
    match &globals_obj.atom {
        PdfAtom::Ref { .. } => {
            let entry = graph.resolve_ref(globals_obj)?;
            let PdfAtom::Stream(stream) = &entry.atom else {
                return None;
            };
            let result = decode_stream_with_meta(
                graph.bytes,
                stream,
                DecodeLimits {
                    max_decoded_bytes: opts.max_decode_bytes,
                    max_filter_chain_depth: 8,
                },
            );
            result.data
        }
        PdfAtom::Stream(stream) => {
            let result = decode_stream_with_meta(
                graph.bytes,
                stream,
                DecodeLimits {
                    max_decoded_bytes: opts.max_decode_bytes,
                    max_filter_chain_depth: 8,
                },
            );
            result.data
        }
        _ => None,
    }
}
