use std::collections::BTreeMap;

use sis_pdf_pdf::decode::{decode_stream_with_meta, DecodeLimits};
use sis_pdf_pdf::object::{PdfAtom, PdfStream};
use sis_pdf_pdf::xfa::extract_xfa_image_payloads;
use sis_pdf_pdf::ObjectGraph;

use crate::util::{dict_u32, string_bytes};
use crate::{ImageFinding, ImageStaticOptions, ImageStaticResult};

const DEFAULT_HEADER_BYTES: usize = 4096;
const ZERO_CLICK_PIXEL_THRESHOLD: u64 = 1_000_000;

pub fn analyze_static_images(
    graph: &ObjectGraph<'_>,
    opts: &ImageStaticOptions,
) -> ImageStaticResult {
    let max_header_bytes = if opts.max_header_bytes == 0 {
        DEFAULT_HEADER_BYTES
    } else {
        opts.max_header_bytes
    };
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
                    zero_meta.insert(
                        "attack_surface".into(),
                        "Image codecs / zero-click JBIG2".into(),
                    );
                    zero_meta.insert(
                        "image.zero_click_long_dimension".into(),
                        long_dim.to_string(),
                    );
                    zero_meta.insert(
                        "image.zero_click_short_dimension".into(),
                        short_dim.to_string(),
                    );
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

fn header_starts_with(buf: &[u8], sig: &[u8]) -> bool {
    buf.len() >= sig.len() && &buf[..sig.len()] == sig
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
