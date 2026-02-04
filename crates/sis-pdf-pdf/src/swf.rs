#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwfCompression {
    None,
    Zlib,
    Lzma,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SwfHeader {
    pub signature: [u8; 3],
    pub version: u8,
    pub file_length: u32,
    pub compression: SwfCompression,
    pub frame_size_bytes: usize,
    pub frame_rate: Option<f32>,
    pub frame_count: Option<u16>,
}

pub fn parse_swf_header(bytes: &[u8]) -> Option<SwfHeader> {
    if bytes.len() < 8 {
        return None;
    }
    let signature = [bytes[0], bytes[1], bytes[2]];
    let compression = match &signature {
        b"FWS" => SwfCompression::None,
        b"CWS" => SwfCompression::Zlib,
        b"ZWS" => SwfCompression::Lzma,
        _ => return None,
    };
    let version = bytes[3];
    let file_length = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if compression != SwfCompression::None {
        return Some(SwfHeader {
            signature,
            version,
            file_length,
            compression,
            frame_size_bytes: 0,
            frame_rate: None,
            frame_count: None,
        });
    }
    let rect_bytes = rect_byte_len(bytes.get(8..)?)?;
    let offset = 8 + rect_bytes;
    let (frame_rate, frame_count) = if offset + 4 <= bytes.len() {
        let rate_raw = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let rate = rate_raw as f32 / 256.0;
        let count = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]);
        (Some(rate), Some(count))
    } else {
        (None, None)
    };
    Some(SwfHeader {
        signature,
        version,
        file_length,
        compression,
        frame_size_bytes: rect_bytes,
        frame_rate,
        frame_count,
    })
}

fn rect_byte_len(data: &[u8]) -> Option<usize> {
    let first = *data.first()?;
    let nbits = first >> 3;
    let rect_bits = 5u32 + 4u32 * nbits as u32;
    Some(rect_bits.div_ceil(8) as usize)
}
