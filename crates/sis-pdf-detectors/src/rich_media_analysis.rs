use anyhow::Result;

use flate2::read::ZlibDecoder;
use lzma_rust2::LzmaReader;
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::evidence::EvidenceBuilder;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::stream_analysis::{analyse_stream, StreamLimits};
use sis_pdf_core::timeout::TimeoutChecker;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfStream};
use sis_pdf_pdf::swf::{parse_swf_header, SwfCompression};
use std::io::{Cursor, Read};
use std::time::Duration;

use crate::entry_dict;

pub struct RichMediaContentDetector;

impl Detector for RichMediaContentDetector {
    fn id(&self) -> &'static str {
        "rich_media_content"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::RichMedia3D
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Cheap
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let timeout = TimeoutChecker::new(Duration::from_millis(100));
        for entry in &ctx.graph.objects {
            if timeout.check().is_err() {
                break;
            }
            let PdfAtom::Stream(stream) = &entry.atom else {
                continue;
            };
            if let Some(dict) = entry_dict(entry) {
                if !is_rich_media_dict(dict) {
                    continue;
                }
            }
            let Some(raw) = stream_bytes(ctx.bytes, stream) else {
                continue;
            };
            if !swf_magic(raw) {
                continue;
            }
            let header = match parse_swf_header(raw) {
                Some(value) => value,
                None => continue,
            };
            let header_bytes = match raw.get(..SWF_HEADER_LEN) {
                Some(bytes) => bytes,
                None => continue,
            };
            let body_offset = swf_body_offset(header.compression);
            if body_offset >= raw.len() {
                continue;
            }
            let compressed_len = raw.len().saturating_sub(body_offset);
            if compressed_len == 0 {
                continue;
            }
            let mut decode_timeout =
                TimeoutChecker::new(Duration::from_millis(SWF_DECODE_TIMEOUT_MS));
            let Some(scan_result) = decompress_swf_body(
                raw,
                header.compression,
                &header,
                header_bytes,
                body_offset,
                &mut decode_timeout,
            ) else {
                continue;
            };
            if scan_result.decompressed_body_len > SWF_DECOMPRESSED_LIMIT {
                continue;
            }
            let ratio = scan_result.decompressed_body_len as f64 / compressed_len as f64;
            if ratio > SWF_DECOMPRESSION_RATIO_LIMIT {
                continue;
            }
            let mut meta = std::collections::HashMap::new();
            insert_stream_analysis_meta(&mut meta, raw);
            meta.insert(
                "swf.magic".into(),
                String::from_utf8_lossy(&raw[..3]).into(),
            );
            meta.insert("swf.size".into(), raw.len().to_string());
            meta.insert("media_type".into(), "swf".into());
            meta.insert(
                "swf.decompressed_bytes".into(),
                scan_result.decompressed_body_len.to_string(),
            );
            meta.insert("swf.decompression_ratio".into(), format!("{:.2}", ratio));
            meta.insert("swf.version".into(), header.version.to_string());
            meta.insert("swf.declared_length".into(), header.file_length.to_string());
            meta.insert(
                "swf.compression".into(),
                swf_compression_label(header.compression),
            );
            if let Some(rate) = header.frame_rate {
                meta.insert("swf.frame_rate".into(), format!("{:.2}", rate));
            }
            if let Some(count) = header.frame_count {
                meta.insert("swf.frame_count".into(), count.to_string());
            }
            let evidence = EvidenceBuilder::new()
                .file_offset(
                    stream.dict.span.start,
                    stream.dict.span.len() as u32,
                    "RichMedia dict",
                )
                .file_offset(
                    stream.data_span.start,
                    stream.data_span.len() as u32,
                    "RichMedia stream",
                )
                .build();
            let action_evidence = evidence.clone();
            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "swf_embedded".into(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                title: "SWF content embedded".into(),
                description: "Stream data matches SWF magic header.".into(),
                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                evidence,
                remediation: Some("Extract and inspect the SWF payload.".into()),
                meta: meta.clone(),
                yara: None,
                position: None,
                positions: Vec::new(),
            });
            if !scan_result.action_scan.action_tags.is_empty() {
                let mut action_meta = meta.clone();
                action_meta.insert(
                    "swf.action_tag_count".into(),
                    scan_result.action_scan.action_tags.len().to_string(),
                );
                action_meta.insert(
                    "swf.tags_scanned".into(),
                    scan_result.action_scan.tags_scanned.to_string(),
                );
                action_meta.insert(
                    "swf.action_tags".into(),
                    encode_list(&scan_result.action_scan.action_tags),
                );
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "swf_actionscript_detected".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    title: "SWF ActionScript tags detected".into(),
                    description:
                        "SWF stream contains ActionScript tags (DoAction/DoInitAction/DoABC)."
                            .into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: action_evidence,
                    remediation: Some("Review the ActionScript tags for malicious logic.".into()),
                    meta: action_meta,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                });
            }
        }
        Ok(findings)
    }
}

fn swf_magic(data: &[u8]) -> bool {
    matches!(data.get(0..3), Some(b"FWS") | Some(b"CWS") | Some(b"ZWS"))
}

fn swf_compression_label(compression: SwfCompression) -> String {
    match compression {
        SwfCompression::None => "none",
        SwfCompression::Zlib => "zlib",
        SwfCompression::Lzma => "lzma",
    }
    .to_string()
}

#[derive(Clone)]
struct SwfActionScan {
    action_tags: Vec<String>,
    tags_scanned: usize,
}

fn scan_swf_action_tags(data: &[u8], max_tags: usize) -> SwfActionScan {
    let mut scan = SwfActionScan {
        action_tags: Vec::new(),
        tags_scanned: 0,
    };
    if data.len() < 12 {
        return scan;
    }
    let nbits = data[8] >> 3;
    let rect_bits = 5u32 + 4u32 * nbits as u32;
    let rect_bytes = ((rect_bits + 7) / 8) as usize;
    let mut offset = 8 + rect_bytes + 4;
    if offset >= data.len() {
        return scan;
    }

    let mut tags_seen = 0usize;
    while offset + 2 <= data.len() && tags_seen < max_tags {
        let tag_header = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let tag_code = tag_header >> 6;
        let mut tag_len = (tag_header & 0x3F) as usize;
        offset += 2;
        if tag_len == 0x3F {
            if offset + 4 > data.len() {
                break;
            }
            tag_len = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            offset += 4;
        }
        if offset + tag_len > data.len() {
            break;
        }
        if let Some(name) = action_tag_name(tag_code) {
            scan.action_tags.push(name.to_string());
        }
        offset = offset.saturating_add(tag_len);
        tags_seen += 1;
        if tag_code == 0 {
            break;
        }
    }
    scan.tags_scanned = tags_seen;
    scan
}

struct SwfActionScanResult {
    action_scan: SwfActionScan,
    decompressed_body_len: usize,
}

const SWF_HEADER_LEN: usize = 8;
const SWF_LZMA_HEADER_EXTRA: usize = 9;
const SWF_DECODE_CHUNK: usize = 4096;
const SWF_DECODE_TIMEOUT_MS: u64 = 250;

fn swf_body_offset(compression: SwfCompression) -> usize {
    match compression {
        SwfCompression::None | SwfCompression::Zlib => SWF_HEADER_LEN,
        SwfCompression::Lzma => SWF_HEADER_LEN + SWF_LZMA_HEADER_EXTRA,
    }
}

fn decompress_swf_body(
    raw: &[u8],
    compression: SwfCompression,
    header: &sis_pdf_pdf::swf::SwfHeader,
    header_bytes: &[u8],
    body_offset: usize,
    timeout: &mut TimeoutChecker,
) -> Option<SwfActionScanResult> {
    match compression {
        SwfCompression::None => {
            let body = raw.get(body_offset..)?;
            let composed = build_swf_bytes(header_bytes, body);
            let scan = scan_swf_action_tags(&composed, SWF_ACTION_TAG_LIMIT);
            Some(SwfActionScanResult {
                action_scan: scan,
                decompressed_body_len: body.len(),
            })
        }
        SwfCompression::Zlib => {
            let body = raw.get(body_offset..)?;
            let cursor = Cursor::new(body);
            let mut decoder = ZlibDecoder::new(cursor);
            decompress_with_reader(&mut decoder, header_bytes, timeout)
        }
        SwfCompression::Lzma => {
            if raw.len() <= body_offset {
                return None;
            }
            let props = *raw.get(12)?;
            let dict_size = u32::from_le_bytes(raw.get(13..17)?.try_into().ok()?);
            let body = raw.get(body_offset..)?;
            let cursor = Cursor::new(body);
            let uncomp_size = header.file_length.saturating_sub(8) as u64;
            let mut reader =
                LzmaReader::new_with_props(cursor, uncomp_size, props, dict_size, None).ok()?;
            decompress_with_reader(&mut reader, header_bytes, timeout)
        }
    }
}

fn decompress_with_reader<R: Read>(
    reader: &mut R,
    header_bytes: &[u8],
    timeout: &mut TimeoutChecker,
) -> Option<SwfActionScanResult> {
    let mut partial_body = Vec::new();
    let mut scan = SwfActionScan {
        action_tags: Vec::new(),
        tags_scanned: 0,
    };
    let mut buf = [0u8; SWF_DECODE_CHUNK];
    loop {
        if timeout.check().is_err() {
            return None;
        }
        let n = reader.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        partial_body.extend_from_slice(&buf[..n]);
        let composed = build_swf_bytes(header_bytes, &partial_body);
        scan = scan_swf_action_tags(&composed, SWF_ACTION_TAG_LIMIT);
        if scan.tags_scanned >= SWF_ACTION_TAG_LIMIT {
            break;
        }
        if partial_body.len() >= SWF_DECOMPRESSED_LIMIT {
            break;
        }
    }
    if partial_body.is_empty() {
        let composed = build_swf_bytes(header_bytes, &partial_body);
        scan = scan_swf_action_tags(&composed, SWF_ACTION_TAG_LIMIT);
    }
    Some(SwfActionScanResult {
        action_scan: scan,
        decompressed_body_len: partial_body.len(),
    })
}

fn build_swf_bytes(header: &[u8], body: &[u8]) -> Vec<u8> {
    let mut composed = Vec::with_capacity(header.len() + body.len());
    composed.extend_from_slice(header);
    composed.extend_from_slice(body);
    composed
}

fn stream_bytes<'a>(bytes: &'a [u8], stream: &PdfStream<'_>) -> Option<&'a [u8]> {
    let start = stream.data_span.start as usize;
    let end = stream.data_span.end as usize;
    if start >= end || end > bytes.len() {
        return None;
    }
    Some(&bytes[start..end])
}

fn action_tag_name(code: u16) -> Option<&'static str> {
    match code {
        12 => Some("DoAction"),
        59 => Some("DoInitAction"),
        72 => Some("DoABC2"),
        82 => Some("DoABC"),
        _ => None,
    }
}

fn encode_list(values: &[String]) -> String {
    let escaped: Vec<String> = values
        .iter()
        .map(|value| {
            format!(
                "\"{}\"",
                value
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\n', " ")
                    .replace('\r', " ")
            )
        })
        .collect();
    format!("[{}]", escaped.join(","))
}

fn insert_stream_analysis_meta(meta: &mut std::collections::HashMap<String, String>, data: &[u8]) {
    let analysis = analyse_stream(data, &StreamLimits::default());
    meta.insert("stream.magic_type".into(), analysis.magic_type);
    meta.insert("stream.entropy".into(), format!("{:.2}", analysis.entropy));
    meta.insert("stream.blake3".into(), analysis.blake3);
    meta.insert("size_bytes".into(), analysis.size_bytes.to_string());
}

fn is_rich_media_dict(dict: &PdfDict<'_>) -> bool {
    dict.has_name(b"/Type", b"/RichMedia")
        || dict.has_name(b"/Subtype", b"/RichMedia")
        || dict.has_name(b"/Subtype", b"/Flash")
        || dict.get_first(b"/RichMedia").is_some()
}

const SWF_ACTION_TAG_LIMIT: usize = 10;
const SWF_DECOMPRESSED_LIMIT: usize = 10 * 1024 * 1024;
const SWF_DECOMPRESSION_RATIO_LIMIT: f64 = 10.0;
