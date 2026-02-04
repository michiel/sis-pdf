use std::convert::TryInto;
use std::io::{Cursor, Read};

use crate::timeout::TimeoutChecker;
use flate2::read::ZlibDecoder;
use lzma_rust2::LzmaReader;
use sis_pdf_pdf::swf::{parse_swf_header, SwfCompression, SwfHeader};

#[derive(Clone, Default)]
pub struct SwfActionScan {
    pub action_tags: Vec<String>,
    pub tags_scanned: usize,
}

pub struct SwfAnalysis {
    pub header: SwfHeader,
    pub action_scan: SwfActionScan,
    pub decompressed_body_len: usize,
    pub compressed_len: usize,
}

pub const SWF_ACTION_TAG_LIMIT: usize = 10;
#[cfg(not(test))]
pub const SWF_DECOMPRESSED_LIMIT: usize = 10 * 1024 * 1024;
#[cfg(test)]
pub const SWF_DECOMPRESSED_LIMIT: usize = 1024;
pub const SWF_DECOMPRESSION_RATIO_LIMIT: f64 = 10.0;
pub const SWF_HEADER_LEN: usize = 8;
pub const SWF_LZMA_HEADER_EXTRA: usize = 9;
pub const SWF_DECODE_CHUNK: usize = 4096;
pub const SWF_DECODE_TIMEOUT_MS: u64 = 250;

pub fn swf_magic(data: &[u8]) -> bool {
    matches!(data.get(0..3), Some(b"FWS") | Some(b"CWS") | Some(b"ZWS"))
}

pub fn swf_magic_label(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"FWS") {
        Some("FWS")
    } else if data.starts_with(b"CWS") {
        Some("CWS")
    } else if data.starts_with(b"ZWS") {
        Some("ZWS")
    } else {
        None
    }
}

pub fn swf_body_offset(compression: SwfCompression) -> usize {
    match compression {
        SwfCompression::None | SwfCompression::Zlib => SWF_HEADER_LEN,
        SwfCompression::Lzma => SWF_HEADER_LEN + SWF_LZMA_HEADER_EXTRA,
    }
}

pub fn swf_compression_label(compression: SwfCompression) -> &'static str {
    match compression {
        SwfCompression::None => "none",
        SwfCompression::Zlib => "zlib",
        SwfCompression::Lzma => "lzma",
    }
}

pub fn detect_3d_format(data: &[u8]) -> Option<&'static str> {
    if data.len() >= 4 && data[..4] == [0x00, 0x00, 0x00, 0x24] {
        return Some("u3d");
    }
    if data.starts_with(b"PRC") {
        return Some("prc");
    }
    None
}

pub fn detect_media_format(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"ID3") {
        return Some("mp3");
    }
    if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xFB {
        return Some("mp3");
    }
    if data.len() >= 12 && &data[4..8] == b"ftyp" {
        return Some("mp4");
    }
    None
}

pub fn scan_swf_action_tags(data: &[u8], max_tags: usize) -> SwfActionScan {
    let mut scan = SwfActionScan::default();
    if data.len() < 12 {
        return scan;
    }
    let nbits = data[8] >> 3;
    let rect_bits = 5u32 + 4u32 * nbits as u32;
    let rect_bytes = ((rect_bits + 7) / 8) as usize;
    let mut offset = SWF_HEADER_LEN + rect_bytes;
    if offset + 4 >= data.len() {
        return scan;
    }
    offset += 4; // frame rate + frame count

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

fn action_tag_name(code: u16) -> Option<&'static str> {
    match code {
        12 => Some("DoAction"),
        59 => Some("DoInitAction"),
        72 => Some("DoABC2"),
        82 => Some("DoABC"),
        _ => None,
    }
}

pub fn analyze_swf(raw: &[u8], timeout: &mut TimeoutChecker) -> Option<SwfAnalysis> {
    let header = parse_swf_header(raw)?;
    if !swf_magic(raw) {
        return None;
    }
    let header_bytes = raw.get(..SWF_HEADER_LEN)?;
    let declared_length = header.file_length as usize;
    if declared_length > SWF_HEADER_LEN + SWF_DECOMPRESSED_LIMIT {
        return None;
    }
    let body_offset = swf_body_offset(header.compression);
    if body_offset >= raw.len() {
        return None;
    }
    let compressed_len = raw.len().saturating_sub(body_offset);
    if compressed_len == 0 {
        return None;
    }
    let scan_result = decompress_swf_body(
        raw,
        header.compression,
        &header,
        header_bytes,
        body_offset,
        timeout,
    )?;
    Some(SwfAnalysis {
        header,
        action_scan: scan_result.action_scan,
        decompressed_body_len: scan_result.decompressed_body_len,
        compressed_len,
    })
}

fn decompress_swf_body(
    raw: &[u8],
    compression: SwfCompression,
    header: &SwfHeader,
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
            let props = *raw.get(SWF_HEADER_LEN)?;
            let dict_size = u32::from_le_bytes(
                raw.get(SWF_HEADER_LEN + 1..SWF_HEADER_LEN + 5)?
                    .try_into()
                    .ok()?,
            );
            let body = raw.get(body_offset..)?;
            let cursor = Cursor::new(body);
            let uncomp_size = header.file_length.saturating_sub(SWF_HEADER_LEN as u32) as u64;
            let mut reader =
                LzmaReader::new_with_props(cursor, uncomp_size, props, dict_size, None).ok()?;
            decompress_with_reader(&mut reader, header_bytes, timeout)
        }
    }
}

struct SwfActionScanResult {
    action_scan: SwfActionScan,
    decompressed_body_len: usize,
}

fn decompress_with_reader<R: Read>(
    reader: &mut R,
    header_bytes: &[u8],
    timeout: &mut TimeoutChecker,
) -> Option<SwfActionScanResult> {
    let mut partial_body = Vec::new();
    let mut scan = SwfActionScan::default();
    let mut buf = [0u8; SWF_DECODE_CHUNK];
    loop {
        if timeout.check().is_err() {
            return None;
        }
        let n = reader.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        let remaining = SWF_DECOMPRESSED_LIMIT.saturating_sub(partial_body.len());
        if remaining == 0 {
            break;
        }
        let to_take = remaining.min(n);
        partial_body.extend_from_slice(&buf[..to_take]);
        let composed = build_swf_bytes(header_bytes, &partial_body);
        scan = scan_swf_action_tags(&composed, SWF_ACTION_TAG_LIMIT);
        if scan.tags_scanned >= SWF_ACTION_TAG_LIMIT {
            break;
        }
        if partial_body.len() >= SWF_DECOMPRESSED_LIMIT {
            break;
        }
        if to_take < n {
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

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;
    use std::time::Duration;

    fn make_minimal_swf_body() -> Vec<u8> {
        // RECT for frame size: nbits=1, 0 for all coords
        let nbits = 1u8;
        let rect_header = nbits << 3;
        vec![
            rect_header, // RECT + other bits (simplified)
            0,
            0,
            0, // fill to align
        ]
    }

    fn build_fws(raw_body: &[u8], version: u8, _compression: SwfCompression) -> Vec<u8> {
        let file_length = (SWF_HEADER_LEN + raw_body.len()) as u32;
        let mut header = Vec::with_capacity(SWF_HEADER_LEN);
        header.extend_from_slice(b"FWS");
        header.push(version);
        header.extend_from_slice(&file_length.to_le_bytes());
        header.extend_from_slice(raw_body);
        header
    }

    #[test]
    fn analyze_swf_uncompressed() {
        let mut body = vec![0x00, 0x00, 0x00, 0x00, 0x00];
        body.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]); // DoAction tag
        let raw = build_fws(&body, 6, SwfCompression::None);
        let mut timeout = TimeoutChecker::new(Duration::from_millis(SWF_DECODE_TIMEOUT_MS));
        let analysis = analyze_swf(&raw, &mut timeout).expect("should parse FWS");
        assert_eq!(analysis.decompressed_body_len, body.len());
    }

    #[test]
    fn detect_media_format_mp3() {
        assert_eq!(detect_media_format(b"ID3"), Some("mp3"));
        assert_eq!(detect_media_format(&[0xFF, 0xFB, 0x00]), Some("mp3"));
    }

    #[test]
    fn detect_media_format_mp4() {
        let mut header = vec![0u8; 12];
        header[4..8].copy_from_slice(b"ftyp");
        assert_eq!(detect_media_format(&header), Some("mp4"));
    }

    #[test]
    fn detect_3d_format_values() {
        assert_eq!(detect_3d_format(&[0x00, 0x00, 0x00, 0x24]), Some("u3d"));
        assert_eq!(detect_3d_format(b"PRC"), Some("prc"));
    }

    #[test]
    fn analyze_swf_compressed() {
        let mut body = make_minimal_swf_body();
        body.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&body).unwrap();
        let compressed = encoder.finish().unwrap();
        let file_length = (SWF_HEADER_LEN + compressed.len()) as u32;
        let mut raw = Vec::new();
        raw.extend_from_slice(b"CWS");
        raw.push(6);
        raw.extend_from_slice(&file_length.to_le_bytes());
        raw.extend_from_slice(&compressed);
        let mut timeout = TimeoutChecker::new(Duration::from_millis(SWF_DECODE_TIMEOUT_MS));
        let analysis = analyze_swf(&raw, &mut timeout).expect("should parse CWS");
        assert!(analysis.decompressed_body_len >= body.len());
    }

    #[test]
    fn scan_swf_action_tags_detects_actionscript() {
        let mut body = vec![0x00, 0x00, 0x00, 0x00, 0x00];
        body.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]); // DoAction tag header (length=0)
        body.extend_from_slice(&[0x00, 0x00]); // TagEnd

        let raw = build_fws(&body, 9, SwfCompression::None);
        let scan = scan_swf_action_tags(&raw, SWF_ACTION_TAG_LIMIT);
        assert!(scan.action_tags.contains(&"DoAction".to_string()));
        assert!(scan.tags_scanned > 0);
    }

    #[test]
    fn swf_decompression_limit_enforced() {
        let mut body = vec![0x41; SWF_DECOMPRESSED_LIMIT + 512];
        body.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]); // DoAction tag
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&body).unwrap();
        let compressed = encoder.finish().unwrap();
        let file_length = (SWF_HEADER_LEN + compressed.len()) as u32;
        let mut raw = Vec::new();
        raw.extend_from_slice(b"CWS");
        raw.push(6);
        raw.extend_from_slice(&file_length.to_le_bytes());
        raw.extend_from_slice(&compressed);

        let mut timeout = TimeoutChecker::new(Duration::from_millis(SWF_DECODE_TIMEOUT_MS));
        let analysis = analyze_swf(&raw, &mut timeout).expect("should parse CWS");
        assert_eq!(analysis.decompressed_body_len, SWF_DECOMPRESSED_LIMIT);
    }

    #[test]
    fn swf_size_limit_blocks_large_headers() {
        let body = vec![0x00; SWF_DECOMPRESSED_LIMIT + 128];
        let raw = build_fws(&body, 10, SwfCompression::None);
        let mut timeout = TimeoutChecker::new(Duration::from_millis(SWF_DECODE_TIMEOUT_MS));
        assert!(analyze_swf(&raw, &mut timeout).is_none());
    }
}
