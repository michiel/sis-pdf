use sis_pdf_pdf::swf::{parse_swf_header, SwfCompression};

fn build_fws(tags: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"FWS");
    out.push(9);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&[0x08, 0x00]); // RECT: nbits=1, all zeros
    out.extend_from_slice(&[0x00, 0x18]); // 24.0 fps (fixed 8.8)
    out.extend_from_slice(&[0x01, 0x00]); // frame count
    out.extend_from_slice(tags);
    let len = out.len() as u32;
    out[4..8].copy_from_slice(&len.to_le_bytes());
    out
}

#[test]
fn parses_uncompressed_swf_header() {
    let bytes = build_fws(&[0x00, 0x00]);
    let header = parse_swf_header(&bytes).expect("header");
    assert_eq!(header.version, 9);
    assert_eq!(header.file_length, bytes.len() as u32);
    assert_eq!(header.compression, SwfCompression::None);
    assert_eq!(header.frame_size_bytes, 2);
    let rate = header.frame_rate.expect("frame rate");
    assert!((rate - 24.0).abs() < 0.01);
    assert_eq!(header.frame_count, Some(1));
}

#[test]
fn parses_compressed_swf_header_metadata() {
    let bytes = b"CWS\x09\x08\x00\x00\x00";
    let header = parse_swf_header(bytes).expect("header");
    assert_eq!(header.version, 9);
    assert_eq!(header.file_length, 8);
    assert_eq!(header.compression, SwfCompression::Zlib);
    assert_eq!(header.frame_rate, None);
    assert_eq!(header.frame_count, None);
}
