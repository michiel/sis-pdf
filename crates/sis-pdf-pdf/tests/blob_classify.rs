use sis_pdf_pdf::blob_classify::{classify_blob, BlobKind};

#[test]
fn detects_archive_signatures() {
    assert_eq!(classify_blob(b"\x1F\x8B\x08\x00"), BlobKind::Gzip);
    assert_eq!(classify_blob(b"BZh91AY"), BlobKind::Bzip2);
    assert_eq!(classify_blob(b"\xFD7zXZ\x00\x00"), BlobKind::Xz);
    assert_eq!(classify_blob(b"\x28\xB5\x2F\xFD\x00"), BlobKind::Zstd);
    assert_eq!(classify_blob(b"Rar!\x1A\x07\x00"), BlobKind::Rar);
    assert_eq!(classify_blob(b"7z\xBC\xAF\x27\x1C\x00"), BlobKind::SevenZ);
}

#[test]
fn detects_zip_and_ooxml() {
    assert_eq!(classify_blob(b"PK\x03\x04"), BlobKind::Zip);
    let mut ooxml = b"PK\x03\x04".to_vec();
    ooxml.extend_from_slice(b"[Content_Types].xml");
    assert_eq!(classify_blob(&ooxml), BlobKind::Ooxml);
}

#[test]
fn detects_media_signatures() {
    assert_eq!(classify_blob(b"\x00\x00\x00\x18ftypmp42"), BlobKind::Mp4);
    assert_eq!(classify_blob(b"RIFF\x24\x00\x00\x00AVI "), BlobKind::Avi);
    assert_eq!(classify_blob(b"RIFF\x24\x00\x00\x00WAVE"), BlobKind::Wav);
    assert_eq!(classify_blob(b"ID3\x03\x00\x00"), BlobKind::Mp3);
    assert_eq!(
        classify_blob(b"\x1A\x45\xDF\xA3\x93\x42\x82\x88"),
        BlobKind::Mkv
    );
}

#[test]
fn detects_font_signatures() {
    assert_eq!(
        classify_blob(b"\x00\x01\x00\x00\x00\x10"),
        BlobKind::FontTrueType
    );
    assert_eq!(classify_blob(b"OTTO\x00\x01"), BlobKind::FontOpenType);
    assert_eq!(classify_blob(b"%!PS-AdobeFont-1.0"), BlobKind::FontType1);
    assert_eq!(classify_blob(b"wOFF\x00\x01"), BlobKind::FontWoff);
    assert_eq!(classify_blob(b"wOF2\x00\x01"), BlobKind::FontWoff2);
}

#[test]
fn detects_additional_image_signatures() {
    assert_eq!(classify_blob(b"RIFF\x24\x00\x00\x00WEBP"), BlobKind::Webp);
    assert_eq!(
        classify_blob(b"\x00\x00\x00\x0CjP  \x0D\x0A\x87\x0A"),
        BlobKind::Jp2
    );
}

#[test]
fn validates_known_formats() {
    let jpeg = b"\xFF\xD8test\xFF\xD9";
    let png = b"\x89PNG\r\n\x1A\n\x00\x00\x00\rIHDR";
    let zip = b"PK\x03\x04testPK\x01\x02";
    let swf = b"FWS\x09\x08\x00\x00\x00";

    assert!(sis_pdf_pdf::blob_classify::validate_blob_kind(jpeg, BlobKind::Jpeg).valid);
    assert!(sis_pdf_pdf::blob_classify::validate_blob_kind(png, BlobKind::Png).valid);
    assert!(sis_pdf_pdf::blob_classify::validate_blob_kind(zip, BlobKind::Zip).valid);
    assert!(sis_pdf_pdf::blob_classify::validate_blob_kind(swf, BlobKind::Swf).valid);
}

#[test]
fn detects_invalid_zip_entry_lengths() {
    let mut zip = b"PK\x03\x04".to_vec();
    zip.extend_from_slice(&[0u8; 14]);
    zip.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // compressed size 16
    zip.extend_from_slice(&[0u8; 8]);
    zip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // name len, extra len
    zip.extend_from_slice(b"PK\x01\x02");
    let result = sis_pdf_pdf::blob_classify::validate_blob_kind(&zip, BlobKind::Zip);
    assert!(!result.valid);
}

#[test]
fn detects_png_chunk_overflow() {
    let mut png = b"\x89PNG\r\n\x1A\n".to_vec();
    png.extend_from_slice(&[0x00, 0x00, 0x10, 0x00]); // length 4096
    png.extend_from_slice(b"IHDR");
    png.extend_from_slice(&[0u8; 8]);
    let result = sis_pdf_pdf::blob_classify::validate_blob_kind(&png, BlobKind::Png);
    assert!(!result.valid);
}

#[test]
fn detects_swf_length_mismatch() {
    let mut swf = b"FWS".to_vec();
    swf.extend_from_slice(&[0x09, 0xFF, 0x00, 0x00, 0x00]); // declared length 255
    let result = sis_pdf_pdf::blob_classify::validate_blob_kind(&swf, BlobKind::Swf);
    assert!(!result.valid);
}

#[test]
fn detects_zip_central_directory_offset_out_of_bounds() {
    let mut zip = b"PK\x03\x04".to_vec();
    zip.extend_from_slice(b"test");
    zip.extend_from_slice(b"PK\x01\x02");
    zip.extend_from_slice(b"PK\x05\x06");
    zip.extend_from_slice(&[0u8; 12]);
    zip.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0x7F]); // offset beyond buffer
    zip.extend_from_slice(&[0u8; 2]);
    let result = sis_pdf_pdf::blob_classify::validate_blob_kind(&zip, BlobKind::Zip);
    assert!(!result.valid);
}

#[test]
fn detects_mp4_size_mismatch() {
    let mp4 = b"\x00\x00\x00\x40ftypisom";
    let result = sis_pdf_pdf::blob_classify::validate_blob_kind(mp4, BlobKind::Mp4);
    assert!(!result.valid);
}

#[test]
fn detects_webp_size_mismatch() {
    let webp = b"RIFF\xFF\xFF\xFF\x7FWEBP";
    let result = sis_pdf_pdf::blob_classify::validate_blob_kind(webp, BlobKind::Webp);
    assert!(!result.valid);
}

#[test]
fn detects_zip_eocd_comment_overflow() {
    let mut zip = b"PK\x03\x04".to_vec();
    zip.extend_from_slice(b"test");
    zip.extend_from_slice(b"PK\x01\x02");
    zip.extend_from_slice(b"PK\x05\x06");
    zip.extend_from_slice(&[0u8; 12]);
    zip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // central directory offset
    zip.extend_from_slice(&[0xFF, 0x7F]); // comment length overflow
    let result = sis_pdf_pdf::blob_classify::validate_blob_kind(&zip, BlobKind::Zip);
    assert!(!result.valid);
}

#[test]
fn detects_mp4_box_overflow() {
    let mut mp4 = b"\x00\x00\x00\x18ftypisom".to_vec();
    mp4.extend_from_slice(b"\x00\x00\x00\x04moov");
    let result = sis_pdf_pdf::blob_classify::validate_blob_kind(&mp4, BlobKind::Mp4);
    assert!(!result.valid);
}
