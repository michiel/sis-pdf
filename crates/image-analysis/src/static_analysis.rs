use std::collections::BTreeMap;

use sis_pdf_pdf::decode::{decode_stream_with_meta, DecodeLimits};
use sis_pdf_pdf::object::{PdfAtom, PdfStream};
use sis_pdf_pdf::xfa::extract_xfa_image_payloads;
use sis_pdf_pdf::ObjectGraph;

use crate::colour_space::{resolve_colour_space, ResolvedColourSpace};
use crate::pixel_buffer::MAX_PREVIEW_BUFFER_BYTES;
use crate::util::{dict_f64_array, dict_u32, string_bytes};
use crate::{ImageFinding, ImageStaticOptions, ImageStaticResult};

const DEFAULT_HEADER_BYTES: usize = 4096;
const ZERO_CLICK_PIXEL_THRESHOLD: u64 = 1_000_000;

pub fn analyze_static_images(
    graph: &ObjectGraph<'_>,
    opts: &ImageStaticOptions,
) -> ImageStaticResult {
    let max_header_bytes =
        if opts.max_header_bytes == 0 { DEFAULT_HEADER_BYTES } else { opts.max_header_bytes };
    let mut findings = Vec::new();
    for entry in &graph.objects {
        let PdfAtom::Stream(stream) = &entry.atom else {
            continue;
        };
        if !is_image_stream(stream) {
            continue;
        }
        let (filters, filter_label) = stream_filters(stream);
        let mut meta = BTreeMap::new();
        meta.insert("image.filters".into(), filter_label.clone());
        if let Some(width) = dict_u32(&stream.dict, b"/Width") {
            meta.insert("image.width".into(), width.to_string());
        }
        if let Some(height) = dict_u32(&stream.dict, b"/Height") {
            meta.insert("image.height".into(), height.to_string());
        }
        if let Some(bits) = dict_u32(&stream.dict, b"/BitsPerComponent") {
            meta.insert("image.bits_per_component".into(), bits.to_string());
        }
        let (width, height) = image_dimensions(stream);
        if let (Some(w), Some(h)) = (width, height) {
            let pixels = w as u64 * h as u64;
            meta.insert("image.pixel_count".into(), pixels.to_string());
            if opts.max_dimension > 0 && (w > opts.max_dimension || h > opts.max_dimension) {
                findings.push(ImageFinding {
                    kind: "image.extreme_dimensions".into(),
                    obj: entry.obj,
                    gen: entry.gen,
                    meta: meta.clone(),
                });
            }
            if opts.max_pixels > 0 && pixels > opts.max_pixels {
                findings.push(ImageFinding {
                    kind: "image.pixel_count_excessive".into(),
                    obj: entry.obj,
                    gen: entry.gen,
                    meta: meta.clone(),
                });
            }
            let exceed_dimension = opts.max_dimension > 0
                && (w == 1 || h == 1)
                && pixels > (opts.max_dimension as u64);
            let huge_pixels = pixels >= ZERO_CLICK_PIXEL_THRESHOLD;
            if exceed_dimension || huge_pixels {
                findings.push(ImageFinding {
                    kind: "image.suspect_strip_dimensions".into(),
                    obj: entry.obj,
                    gen: entry.gen,
                    meta: meta.clone(),
                });
                if filters.iter().any(|f| f == "JBIG2Decode") {
                    let long_dim = std::cmp::max(w, h);
                    let short_dim = std::cmp::min(w, h);
                    let mut zero_meta = meta.clone();
                    zero_meta.insert("cve".into(), "CVE-2021-30860".into());
                    zero_meta
                        .insert("attack_surface".into(), "Image codecs / zero-click JBIG2".into());
                    zero_meta
                        .insert("image.zero_click_long_dimension".into(), long_dim.to_string());
                    zero_meta
                        .insert("image.zero_click_short_dimension".into(), short_dim.to_string());
                    findings.push(ImageFinding {
                        kind: "image.zero_click_jbig2".into(),
                        obj: entry.obj,
                        gen: entry.gen,
                        meta: zero_meta,
                    });
                }
            }
        }
        if filters.iter().any(|f| f == "JBIG2Decode") {
            findings.push(ImageFinding {
                kind: "image.jbig2_present".into(),
                obj: entry.obj,
                gen: entry.gen,
                meta: meta.clone(),
            });
        }
        if filters.iter().any(|f| f == "JPXDecode") {
            findings.push(ImageFinding {
                kind: "image.jpx_present".into(),
                obj: entry.obj,
                gen: entry.gen,
                meta: meta.clone(),
            });
        }
        if filters.iter().any(|f| f == "CCITTFaxDecode") {
            findings.push(ImageFinding {
                kind: "image.ccitt_present".into(),
                obj: entry.obj,
                gen: entry.gen,
                meta: meta.clone(),
            });
        }
        if filters.len() > 1 {
            findings.push(ImageFinding {
                kind: "image.multiple_filters".into(),
                obj: entry.obj,
                gen: entry.gen,
                meta: meta.clone(),
            });
        }
        if filter_decode_parms_mismatch(stream, filters.len()) {
            let mut structure_meta = meta.clone();
            structure_meta
                .insert("image.structure_issue".into(), "filter_decodeparms_mismatch".into());
            findings.push(ImageFinding {
                kind: "image.structure_filter_chain_inconsistent".into(),
                obj: entry.obj,
                gen: entry.gen,
                meta: structure_meta,
            });
        }
        if let Some(data) = stream_data(graph, stream) {
            let header = &data[..data.len().min(max_header_bytes)];
            if header_starts_with(header, b"\x00\x00\x00\x0cjP  \r\n\x87\n") {
                meta.insert("image.header.jp2".into(), "true".into());
            }
            if header_starts_with(header, b"\xFF\xD8") {
                meta.insert("image.header.jpeg".into(), "true".into());
            }
            if header_starts_with(header, b"\x89PNG\r\n\x1a\n") {
                meta.insert("image.header.png".into(), "true".into());
            }
        }

        // --- Colour space validation ---
        let cs = resolve_colour_space(&stream.dict, graph);
        if let Some(ref cs_val) = cs {
            meta.insert("image.colour_space".into(), format!("{:?}", cs_val));
            if let ResolvedColourSpace::Unknown(ref reason) = cs_val {
                let mut cs_meta = meta.clone();
                cs_meta.insert("image.colour_space_issue".into(), reason.clone());
                findings.push(ImageFinding {
                    kind: "image.colour_space_invalid".into(),
                    obj: entry.obj,
                    gen: entry.gen,
                    meta: cs_meta,
                });
            }
        }

        // --- BitsPerComponent validation ---
        let bpc = dict_u32(&stream.dict, b"/BitsPerComponent");
        if let Some(bpc_val) = bpc {
            if !matches!(bpc_val, 1 | 2 | 4 | 8 | 16) {
                let mut bpc_meta = meta.clone();
                bpc_meta.insert("image.bits_per_component".into(), bpc_val.to_string());
                findings.push(ImageFinding {
                    kind: "image.bpc_anomalous".into(),
                    obj: entry.obj,
                    gen: entry.gen,
                    meta: bpc_meta,
                });
            }
        }

        // --- Pixel buffer overflow detection ---
        if let (Some(w), Some(h), Some(ref cs_val)) = (width, height, &cs) {
            if let Some(channels) = cs_val.channels() {
                let bpc_val = bpc.unwrap_or(8) as u64;
                let ch = if matches!(cs_val, ResolvedColourSpace::Indexed { .. }) {
                    1u64
                } else {
                    channels as u64
                };
                let bits = (w as u64)
                    .checked_mul(h as u64)
                    .and_then(|v| v.checked_mul(ch))
                    .and_then(|v| v.checked_mul(bpc_val));
                let buffer_bytes = bits.map(|b| (b + 7) / 8);
                if let Some(buf) = buffer_bytes {
                    if buf > MAX_PREVIEW_BUFFER_BYTES {
                        let mut overflow_meta = meta.clone();
                        overflow_meta
                            .insert("image.calculated_buffer_bytes".into(), buf.to_string());
                        overflow_meta.insert("image.channels".into(), ch.to_string());
                        overflow_meta.insert("image.bpc".into(), bpc_val.to_string());
                        findings.push(ImageFinding {
                            kind: "image.pixel_buffer_overflow".into(),
                            obj: entry.obj,
                            gen: entry.gen,
                            meta: overflow_meta,
                        });
                    }
                } else {
                    // Arithmetic overflow
                    let mut overflow_meta = meta.clone();
                    overflow_meta.insert("image.overflow".into(), "arithmetic".into());
                    findings.push(ImageFinding {
                        kind: "image.pixel_buffer_overflow".into(),
                        obj: entry.obj,
                        gen: entry.gen,
                        meta: overflow_meta,
                    });
                }
            }
        }

        // --- Indexed palette validation ---
        if let Some(ResolvedColourSpace::Indexed { ref base, hival, ref palette }) = cs {
            let base_channels = base.channels().unwrap_or(3) as usize;
            let expected_palette_bytes = (hival as usize + 1) * base_channels;
            if palette.len() < expected_palette_bytes {
                let mut pal_meta = meta.clone();
                pal_meta.insert(
                    "image.palette_expected_bytes".into(),
                    expected_palette_bytes.to_string(),
                );
                pal_meta.insert("image.palette_actual_bytes".into(), palette.len().to_string());
                pal_meta.insert("image.hival".into(), hival.to_string());
                findings.push(ImageFinding {
                    kind: "image.indexed_palette_short".into(),
                    obj: entry.obj,
                    gen: entry.gen,
                    meta: pal_meta,
                });
            }
        }

        // --- Decode array validation ---
        if let Some(ref cs_val) = cs {
            let source_channels = if matches!(cs_val, ResolvedColourSpace::Indexed { .. }) {
                1usize
            } else {
                cs_val.channels().unwrap_or(0) as usize
            };
            if source_channels > 0 {
                if let Some(parsed_decode) = dict_f64_array(&stream.dict, b"/Decode") {
                    let expected_len = source_channels * 2;
                    let mut da_meta = meta.clone();
                    match parsed_decode {
                        Ok(values) => {
                            if values.len() != expected_len {
                                da_meta.insert(
                                    "image.decode_array_length".into(),
                                    values.len().to_string(),
                                );
                                da_meta.insert(
                                    "image.decode_array_expected_length".into(),
                                    expected_len.to_string(),
                                );
                                da_meta.insert(
                                    "image.decode_array_issue".into(),
                                    "length_mismatch".into(),
                                );
                                findings.push(ImageFinding {
                                    kind: "image.decode_array_invalid".into(),
                                    obj: entry.obj,
                                    gen: entry.gen,
                                    meta: da_meta,
                                });
                            }
                        }
                        Err(issue) => {
                            da_meta.insert("image.decode_array_issue".into(), issue);
                            da_meta.insert(
                                "image.decode_array_expected_length".into(),
                                expected_len.to_string(),
                            );
                            findings.push(ImageFinding {
                                kind: "image.decode_array_invalid".into(),
                                obj: entry.obj,
                                gen: entry.gen,
                                meta: da_meta,
                            });
                        }
                    }
                }
            }
        }

        // --- Mask consistency validation ---
        if has_inconsistent_masks(stream) {
            let mut mask_meta = meta.clone();
            mask_meta.insert("image.structure_issue".into(), "mask_inconsistent".into());
            findings.push(ImageFinding {
                kind: "image.structure_mask_inconsistent".into(),
                obj: entry.obj,
                gen: entry.gen,
                meta: mask_meta,
            });
        }

        // --- Geometry plausibility validation ---
        if let (Some(w), Some(h)) = (width, height) {
            if is_improbable_geometry(w, h) {
                let mut geometry_meta = meta.clone();
                geometry_meta.insert("image.structure_issue".into(), "geometry_improbable".into());
                findings.push(ImageFinding {
                    kind: "image.structure_geometry_improbable".into(),
                    obj: entry.obj,
                    gen: entry.gen,
                    meta: geometry_meta,
                });
            }
        }
    }
    findings.extend(analyze_xfa_images(graph, opts, max_header_bytes));
    ImageStaticResult { findings }
}

fn is_image_stream(stream: &PdfStream<'_>) -> bool {
    let Some((_, subtype)) = stream.dict.get_first(b"/Subtype") else {
        return false;
    };
    matches!(&subtype.atom, PdfAtom::Name(name) if name.decoded == b"/Image" || name.decoded == b"Image")
}

fn image_dimensions(stream: &PdfStream<'_>) -> (Option<u32>, Option<u32>) {
    let width = dict_u32(&stream.dict, b"/Width");
    let height = dict_u32(&stream.dict, b"/Height");
    (width, height)
}

fn stream_filters(stream: &PdfStream<'_>) -> (Vec<String>, String) {
    let Some((_, filter)) = stream.dict.get_first(b"/Filter") else {
        return (Vec::new(), "-".into());
    };
    match &filter.atom {
        PdfAtom::Name(name) => {
            let label =
                String::from_utf8_lossy(&name.decoded).trim().trim_start_matches('/').to_string();
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
            let label = if out.is_empty() { "-".into() } else { out.join(",") };
            (out, label)
        }
        _ => (Vec::new(), "-".into()),
    }
}

fn header_starts_with(buf: &[u8], sig: &[u8]) -> bool {
    buf.len() >= sig.len() && &buf[..sig.len()] == sig
}

fn filter_decode_parms_mismatch(stream: &PdfStream<'_>, filter_count: usize) -> bool {
    if filter_count <= 1 {
        return false;
    }
    let Some((_, decode_parms_obj)) = stream.dict.get_first(b"/DecodeParms") else {
        return false;
    };
    match &decode_parms_obj.atom {
        PdfAtom::Array(items) => !items.is_empty() && items.len() != filter_count,
        PdfAtom::Dict(_) => true,
        _ => true,
    }
}

fn has_inconsistent_masks(stream: &PdfStream<'_>) -> bool {
    let image_mask = stream.dict.get_first(b"/ImageMask").and_then(|(_, obj)| match obj.atom {
        PdfAtom::Bool(value) => Some(value),
        _ => None,
    });
    let has_smask = stream.dict.get_first(b"/SMask").is_some();
    let has_color_space = stream.dict.get_first(b"/ColorSpace").is_some();

    (image_mask == Some(true) && has_smask) || (image_mask == Some(true) && has_color_space)
}

fn is_improbable_geometry(width: u32, height: u32) -> bool {
    let long = width.max(height) as u64;
    let short = width.min(height) as u64;
    if short == 0 {
        return true;
    }
    let ratio = long / short;
    ratio >= 10_000 || long >= 10_000_000
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

fn analyze_xfa_images(
    graph: &ObjectGraph<'_>,
    opts: &ImageStaticOptions,
    max_header_bytes: usize,
) -> Vec<ImageFinding> {
    let mut findings = Vec::new();
    let limits = DecodeLimits {
        max_decoded_bytes: opts.max_xfa_decode_bytes,
        max_filter_chain_depth: opts.max_filter_chain_depth,
    };
    for entry in &graph.objects {
        let dict = match &entry.atom {
            PdfAtom::Dict(dict) => dict,
            PdfAtom::Stream(stream) => &stream.dict,
            _ => continue,
        };
        let Some((_, xfa_obj)) = dict.get_first(b"/XFA") else {
            continue;
        };
        let payloads = xfa_payloads_from_obj(graph, xfa_obj, limits);
        for payload in payloads {
            let images = extract_xfa_image_payloads(&payload);
            for image in images {
                let mut meta = BTreeMap::new();
                meta.insert("image.xfa".into(), "true".into());
                if let Some(content_type) = image.content_type {
                    meta.insert("image.content_type".into(), content_type);
                }
                let header = &image.bytes[..image.bytes.len().min(max_header_bytes)];
                if header_starts_with(header, b"\xFF\xD8") {
                    meta.insert("image.header.jpeg".into(), "true".into());
                }
                if header_starts_with(header, b"\x89PNG\r\n\x1a\n") {
                    meta.insert("image.header.png".into(), "true".into());
                }
                if header_starts_with(header, b"II*\x00") || header_starts_with(header, b"MM\x00*")
                {
                    meta.insert("image.header.tiff".into(), "true".into());
                }
                findings.push(ImageFinding {
                    kind: "image.xfa_image_present".into(),
                    obj: entry.obj,
                    gen: entry.gen,
                    meta,
                });
            }
        }
    }
    findings
}

pub(crate) fn xfa_payloads_from_obj(
    graph: &ObjectGraph<'_>,
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
    limits: DecodeLimits,
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    match &obj.atom {
        PdfAtom::Array(items) => {
            let mut iter = items.iter().peekable();
            while let Some(item) = iter.next() {
                match &item.atom {
                    PdfAtom::Name(_) | PdfAtom::Str(_) => {
                        if let Some(next) = iter.next() {
                            out.extend(resolve_xfa_payload(graph, next, limits));
                        }
                    }
                    _ => {
                        out.extend(resolve_xfa_payload(graph, item, limits));
                    }
                }
            }
        }
        _ => {
            out.extend(resolve_xfa_payload(graph, obj, limits));
        }
    }
    out
}

fn resolve_xfa_payload(
    graph: &ObjectGraph<'_>,
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
    limits: DecodeLimits,
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    match &obj.atom {
        PdfAtom::Str(s) => out.push(string_bytes(s)),
        PdfAtom::Stream(stream) => {
            let result = decode_stream_with_meta(graph.bytes, stream, limits);
            if let Some(data) = result.data {
                out.push(data);
            }
        }
        PdfAtom::Ref { .. } => {
            if let Some(entry) = graph.resolve_ref(obj) {
                match &entry.atom {
                    PdfAtom::Stream(stream) => {
                        let result = decode_stream_with_meta(graph.bytes, stream, limits);
                        if let Some(data) = result.data {
                            out.push(data);
                        }
                    }
                    PdfAtom::Str(s) => out.push(string_bytes(s)),
                    _ => {}
                }
            }
        }
        _ => {}
    }
    out
}
