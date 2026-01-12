#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobKind {
    Pdf,
    Zip,
    Ooxml,
    Ole2,
    Pe,
    Elf,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    Rar,
    SevenZ,
    Swf,
    Jpeg,
    Png,
    Gif,
    Bmp,
    Tiff,
    Webp,
    Jp2,
    FontTrueType,
    FontOpenType,
    FontType1,
    FontWoff,
    FontWoff2,
    Mp4,
    Avi,
    Wav,
    Mp3,
    Mkv,
    Xml,
    Html,
    Unknown,
}

impl BlobKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            BlobKind::Pdf => "pdf",
            BlobKind::Zip => "zip",
            BlobKind::Ooxml => "ooxml",
            BlobKind::Ole2 => "ole2",
            BlobKind::Pe => "pe",
            BlobKind::Elf => "elf",
            BlobKind::Gzip => "gzip",
            BlobKind::Bzip2 => "bzip2",
            BlobKind::Xz => "xz",
            BlobKind::Zstd => "zstd",
            BlobKind::Rar => "rar",
            BlobKind::SevenZ => "7z",
            BlobKind::Swf => "swf",
            BlobKind::Jpeg => "jpeg",
            BlobKind::Png => "png",
            BlobKind::Gif => "gif",
            BlobKind::Bmp => "bmp",
            BlobKind::Tiff => "tiff",
            BlobKind::Webp => "webp",
            BlobKind::Jp2 => "jp2",
            BlobKind::FontTrueType => "ttf",
            BlobKind::FontOpenType => "otf",
            BlobKind::FontType1 => "type1",
            BlobKind::FontWoff => "woff",
            BlobKind::FontWoff2 => "woff2",
            BlobKind::Mp4 => "mp4",
            BlobKind::Avi => "avi",
            BlobKind::Wav => "wav",
            BlobKind::Mp3 => "mp3",
            BlobKind::Mkv => "mkv",
            BlobKind::Xml => "xml",
            BlobKind::Html => "html",
            BlobKind::Unknown => "unknown",
        }
    }

    pub fn is_image(&self) -> bool {
        matches!(
            self,
            BlobKind::Jpeg
                | BlobKind::Png
                | BlobKind::Gif
                | BlobKind::Bmp
                | BlobKind::Tiff
                | BlobKind::Webp
                | BlobKind::Jp2
        )
    }

    pub fn is_container_or_executable(&self) -> bool {
        matches!(
            self,
            BlobKind::Pe
                | BlobKind::Elf
                | BlobKind::Zip
                | BlobKind::Ooxml
                | BlobKind::Ole2
                | BlobKind::Gzip
                | BlobKind::Bzip2
                | BlobKind::Xz
                | BlobKind::Zstd
                | BlobKind::Rar
                | BlobKind::SevenZ
        )
    }
}

pub fn classify_blob(bytes: &[u8]) -> BlobKind {
    let data = strip_leading_whitespace(bytes);

    if data.starts_with(b"%PDF-") {
        return BlobKind::Pdf;
    }
    if data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A {
        return BlobKind::Pe;
    }
    if data.starts_with(b"\x7FELF") {
        return BlobKind::Elf;
    }
    if data.starts_with(b"\x1F\x8B") {
        return BlobKind::Gzip;
    }
    if data.starts_with(b"BZh") {
        return BlobKind::Bzip2;
    }
    if data.starts_with(b"\xFD7zXZ\x00") {
        return BlobKind::Xz;
    }
    if data.starts_with(b"\x28\xB5\x2F\xFD") {
        return BlobKind::Zstd;
    }
    if data.starts_with(b"Rar!\x1A\x07\x00") || data.starts_with(b"Rar!\x1A\x07\x01\x00") {
        return BlobKind::Rar;
    }
    if data.starts_with(b"7z\xBC\xAF\x27\x1C") {
        return BlobKind::SevenZ;
    }
    if looks_like_zip(data) {
        if has_ooxml_marker(data) {
            return BlobKind::Ooxml;
        }
        return BlobKind::Zip;
    }
    if data.starts_with(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") {
        return BlobKind::Ole2;
    }
    if data.starts_with(b"wOFF") {
        return BlobKind::FontWoff;
    }
    if data.starts_with(b"wOF2") {
        return BlobKind::FontWoff2;
    }
    if data.starts_with(b"OTTO") {
        return BlobKind::FontOpenType;
    }
    if data.starts_with(b"\x00\x01\x00\x00") {
        return BlobKind::FontTrueType;
    }
    if data.starts_with(b"%!PS-AdobeFont") {
        return BlobKind::FontType1;
    }
    if looks_like_swf(data) {
        return BlobKind::Swf;
    }
    if looks_like_jpeg(data) {
        return BlobKind::Jpeg;
    }
    if data.starts_with(b"\x89PNG\r\n\x1A\n") {
        return BlobKind::Png;
    }
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return BlobKind::Gif;
    }
    if data.starts_with(b"BM") {
        return BlobKind::Bmp;
    }
    if data.starts_with(b"II*\0") || data.starts_with(b"MM\0*") {
        return BlobKind::Tiff;
    }
    if looks_like_webp(data) {
        return BlobKind::Webp;
    }
    if looks_like_jp2(data) {
        return BlobKind::Jp2;
    }
    if looks_like_mp4(data) {
        return BlobKind::Mp4;
    }
    if looks_like_riff(data, b"AVI ") {
        return BlobKind::Avi;
    }
    if looks_like_riff(data, b"WAVE") {
        return BlobKind::Wav;
    }
    if data.starts_with(b"ID3") {
        return BlobKind::Mp3;
    }
    if data.starts_with(b"\x1A\x45\xDF\xA3") {
        return BlobKind::Mkv;
    }
    if looks_like_xml(data) {
        return BlobKind::Xml;
    }
    if looks_like_html(data) {
        return BlobKind::Html;
    }

    BlobKind::Unknown
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub reason: Option<String>,
}

impl ValidationResult {
    fn ok() -> Self {
        Self {
            valid: true,
            reason: None,
        }
    }

    fn fail(reason: &str) -> Self {
        Self {
            valid: false,
            reason: Some(reason.to_string()),
        }
    }
}

pub fn validate_blob_kind(bytes: &[u8], kind: BlobKind) -> ValidationResult {
    match kind {
        BlobKind::Jpeg => validate_jpeg(bytes),
        BlobKind::Png => validate_png(bytes),
        BlobKind::Zip | BlobKind::Ooxml => validate_zip(bytes),
        BlobKind::Swf => validate_swf(bytes),
        BlobKind::Mp4 => validate_mp4(bytes),
        BlobKind::Webp => validate_webp(bytes),
        _ => ValidationResult::ok(),
    }
}

fn validate_jpeg(bytes: &[u8]) -> ValidationResult {
    if !looks_like_jpeg(bytes) {
        return ValidationResult::fail("missing JPEG SOI");
    }
    let mut soi_idx = None;
    let mut eoi_idx = None;
    for (idx, window) in bytes.windows(2).enumerate() {
        if window == [0xFF, 0xD8] && soi_idx.is_none() {
            soi_idx = Some(idx);
        }
        if window == [0xFF, 0xD9] {
            eoi_idx = Some(idx);
        }
    }
    if let (Some(soi), Some(eoi)) = (soi_idx, eoi_idx) {
        if eoi > soi {
            return ValidationResult::ok();
        }
    }
    if bytes.windows(2).any(|w| w == [0xFF, 0xD9]) {
        return ValidationResult::ok();
    }
    ValidationResult::fail("missing JPEG EOI marker")
}

fn validate_png(bytes: &[u8]) -> ValidationResult {
    if bytes.len() < 16 || !bytes.starts_with(b"\x89PNG\r\n\x1A\n") {
        return ValidationResult::fail("invalid PNG signature");
    }
    let chunk_type = &bytes[12..16];
    if chunk_type == b"IHDR" {
        if let Some(reason) = png_crc_optional_check(bytes) {
            return ValidationResult::fail(&reason);
        }
        ValidationResult::ok()
    } else {
        ValidationResult::fail("missing IHDR chunk")
    }
}

fn validate_zip(bytes: &[u8]) -> ValidationResult {
    if !looks_like_zip(bytes) {
        return ValidationResult::fail("missing ZIP signature");
    }
    if bytes.windows(4).any(|w| w == b"PK\x01\x02") {
        if let Some(reason) = zip_entry_length_check(bytes) {
            return ValidationResult::fail(&reason);
        }
        if let Some(reason) = zip_central_directory_offset_check(bytes) {
            return ValidationResult::fail(&reason);
        }
        return ValidationResult::ok();
    }
    ValidationResult::fail("missing ZIP central directory")
}

fn validate_swf(bytes: &[u8]) -> ValidationResult {
    if !looks_like_swf(bytes) || bytes.len() < 8 {
        return ValidationResult::fail("invalid SWF header");
    }
    let declared = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    if declared == 0 {
        return ValidationResult::fail("invalid SWF length");
    }
    if declared > bytes.len() {
        return ValidationResult::fail("SWF length exceeds available bytes");
    }
    ValidationResult::ok()
}

fn png_crc_optional_check(bytes: &[u8]) -> Option<String> {
    let mut offset = 8usize;
    while offset + 12 <= bytes.len() {
        let length = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        let chunk_end = offset + 12 + length;
        if chunk_end > bytes.len() {
            return Some("PNG chunk length exceeds buffer".to_string());
        }
        let ctype = &bytes[offset + 4..offset + 8];
        if ctype == b"IEND" {
            break;
        }
        offset = chunk_end;
    }
    None
}

fn zip_entry_length_check(bytes: &[u8]) -> Option<String> {
    let mut offset = 0usize;
    let max_scan = bytes.len().min(512 * 1024);
    while offset + 30 <= max_scan {
        if bytes[offset..offset + 4] == *b"PK\x03\x04" {
            let name_len = u16::from_le_bytes([bytes[offset + 26], bytes[offset + 27]]) as usize;
            let extra_len = u16::from_le_bytes([bytes[offset + 28], bytes[offset + 29]]) as usize;
            let data_start = offset + 30 + name_len + extra_len;
            if data_start > bytes.len() {
                return Some("ZIP entry header exceeds buffer".to_string());
            }
            let comp_size = u32::from_le_bytes([
                bytes[offset + 18],
                bytes[offset + 19],
                bytes[offset + 20],
                bytes[offset + 21],
            ]) as usize;
            let data_end = data_start.saturating_add(comp_size);
            if data_end > bytes.len() {
                return Some("ZIP entry size exceeds buffer".to_string());
            }
            offset = data_end;
        } else {
            offset += 1;
        }
    }
    None
}

fn zip_central_directory_offset_check(bytes: &[u8]) -> Option<String> {
    let eocd = find_eocd(bytes)?;
    if eocd + 22 > bytes.len() {
        return Some("ZIP EOCD truncated".to_string());
    }
    let comment_len = u16::from_le_bytes([bytes[eocd + 20], bytes[eocd + 21]]) as usize;
    let comment_end = eocd + 22 + comment_len;
    if comment_end > bytes.len() {
        return Some("ZIP EOCD comment length exceeds buffer".to_string());
    }
    let offset = u32::from_le_bytes([
        bytes[eocd + 16],
        bytes[eocd + 17],
        bytes[eocd + 18],
        bytes[eocd + 19],
    ]) as usize;
    if offset + 4 > bytes.len() {
        return Some("ZIP central directory offset out of bounds".to_string());
    }
    if &bytes[offset..offset + 4] != b"PK\x01\x02" {
        return Some("ZIP central directory signature missing at offset".to_string());
    }
    None
}

fn find_eocd(bytes: &[u8]) -> Option<usize> {
    let sig = b"PK\x05\x06";
    let max_scan = bytes.len().min(65_558);
    let start = bytes.len().saturating_sub(max_scan);
    for idx in (start..bytes.len().saturating_sub(3)).rev() {
        if &bytes[idx..idx + 4] == sig {
            return Some(idx);
        }
    }
    None
}

fn strip_leading_whitespace(bytes: &[u8]) -> &[u8] {
    let mut idx = 0usize;
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }
    &bytes[idx..]
}

fn looks_like_zip(data: &[u8]) -> bool {
    data.starts_with(b"PK\x03\x04")
        || data.starts_with(b"PK\x05\x06")
        || data.starts_with(b"PK\x07\x08")
}

fn has_ooxml_marker(data: &[u8]) -> bool {
    let needle = b"[Content_Types].xml";
    find_subsequence(data, needle)
}

fn looks_like_swf(data: &[u8]) -> bool {
    data.starts_with(b"FWS") || data.starts_with(b"CWS") || data.starts_with(b"ZWS")
}

fn looks_like_jpeg(data: &[u8]) -> bool {
    data.len() > 2 && data[0] == 0xFF && data[1] == 0xD8
}

fn looks_like_webp(data: &[u8]) -> bool {
    data.len() >= 12 && data.starts_with(b"RIFF") && data[8..12] == *b"WEBP"
}

fn looks_like_jp2(data: &[u8]) -> bool {
    data.len() >= 12
        && data[0..4] == [0x00, 0x00, 0x00, 0x0C]
        && data[4..8] == *b"jP  "
        && data[8..12] == [0x0D, 0x0A, 0x87, 0x0A]
}

fn looks_like_mp4(data: &[u8]) -> bool {
    data.len() >= 8 && data[4..8] == *b"ftyp"
}

fn looks_like_riff(data: &[u8], kind: &[u8; 4]) -> bool {
    data.len() >= 12 && data.starts_with(b"RIFF") && data[8..12] == *kind
}

fn looks_like_xml(data: &[u8]) -> bool {
    let lower = lower_ascii_prefix(data, 128);
    lower.starts_with(b"<?xml") || lower.starts_with(b"<x:xmpmeta")
}

fn looks_like_html(data: &[u8]) -> bool {
    let lower = lower_ascii_prefix(data, 128);
    lower.starts_with(b"<html") || lower.starts_with(b"<script")
}

fn lower_ascii_prefix(data: &[u8], max_len: usize) -> Vec<u8> {
    data.iter()
        .take(max_len)
        .map(|b| b.to_ascii_lowercase())
        .collect()
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
fn validate_mp4(bytes: &[u8]) -> ValidationResult {
    if !looks_like_mp4(bytes) {
        return ValidationResult::fail("missing ftyp box");
    }
    if bytes.len() < 8 {
        return ValidationResult::fail("truncated ftyp box");
    }
    let size = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if size < 8 {
        return ValidationResult::fail("invalid ftyp size");
    }
    if size > bytes.len() {
        return ValidationResult::fail("ftyp size exceeds buffer");
    }
    if let Some(reason) = mp4_box_walk(bytes, size) {
        return ValidationResult::fail(&reason);
    }
    ValidationResult::ok()
}

fn validate_webp(bytes: &[u8]) -> ValidationResult {
    if !looks_like_webp(bytes) {
        return ValidationResult::fail("invalid WebP signature");
    }
    if bytes.len() < 12 {
        return ValidationResult::fail("truncated WebP header");
    }
    let size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    let total = size.saturating_add(8);
    if total > bytes.len() {
        return ValidationResult::fail("WebP length exceeds buffer");
    }
    ValidationResult::ok()
}

fn mp4_box_walk(bytes: &[u8], start: usize) -> Option<String> {
    let mut offset = start;
    let max_scan = bytes.len().min(start + 256 * 1024);
    let mut boxes_seen = 0usize;
    while offset + 8 <= max_scan && boxes_seen < 16 {
        let size = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        if size < 8 {
            return Some("MP4 box size too small".to_string());
        }
        if offset + size > bytes.len() {
            return Some("MP4 box size exceeds buffer".to_string());
        }
        offset += size;
        boxes_seen += 1;
    }
    None
}
