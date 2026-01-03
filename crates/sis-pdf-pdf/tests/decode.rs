use sis_pdf_pdf::decode::decode_ascii_hex;

#[test]
fn ascii_hex_decode() {
    let out = decode_ascii_hex(b"61 62 2e>");
    assert_eq!(out, b"ab.");
}
