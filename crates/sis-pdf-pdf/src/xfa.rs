use base64::engine::general_purpose::STANDARD;
use base64::Engine;

#[derive(Debug, Clone)]
pub struct XfaPayload {
    pub bytes: Vec<u8>,
    pub content_type: Option<String>,
    pub source: String,
}

pub fn extract_xfa_script_payloads(bytes: &[u8]) -> Vec<Vec<u8>> {
    let max_scan_bytes = 512 * 1024;
    let slice = if bytes.len() > max_scan_bytes { &bytes[..max_scan_bytes] } else { bytes };
    let lower: Vec<u8> = slice.iter().map(|b| b.to_ascii_lowercase()).collect();
    let mut out = Vec::new();
    for (start_tag, end_tag) in [
        (b"<script".as_slice(), b"</script>".as_slice()),
        (b"<xfa:script".as_slice(), b"</xfa:script>".as_slice()),
    ] {
        let mut idx = 0usize;
        while let Some(pos) = find_subslice(&lower[idx..], start_tag) {
            let tag_start = idx + pos;
            let tag_end = match lower[tag_start..].iter().position(|b| *b == b'>') {
                Some(end) => tag_start + end + 1,
                None => break,
            };
            if !xfa_script_tag_is_javascript(&lower[tag_start..tag_end]) {
                idx = tag_end;
                continue;
            }
            let Some(end_pos) = find_subslice(&lower[tag_end..], end_tag) else {
                break;
            };
            let content_end = tag_end + end_pos;
            let content = &slice[tag_end..content_end];
            let stripped = strip_cdata(content);
            let trimmed = trim_ascii_whitespace(stripped);
            if !trimmed.is_empty() {
                out.push(trimmed.to_vec());
            }
            idx = content_end + end_tag.len();
        }
    }
    out
}

pub fn extract_xfa_image_payloads(bytes: &[u8]) -> Vec<XfaPayload> {
    let max_scan_bytes = 512 * 1024;
    let slice = if bytes.len() > max_scan_bytes { &bytes[..max_scan_bytes] } else { bytes };
    let lower: Vec<u8> = slice.iter().map(|b| b.to_ascii_lowercase()).collect();
    let mut out = Vec::new();
    for (start_tag, end_tag) in [
        (b"<image".as_slice(), b"</image>".as_slice()),
        (b"<xfa:image".as_slice(), b"</xfa:image>".as_slice()),
    ] {
        let mut idx = 0usize;
        while let Some(pos) = find_subslice(&lower[idx..], start_tag) {
            let tag_start = idx + pos;
            let tag_end = match lower[tag_start..].iter().position(|b| *b == b'>') {
                Some(end) => tag_start + end + 1,
                None => break,
            };
            let tag = &lower[tag_start..tag_end];
            if let Some(payload) = extract_data_uri_from_tag(tag, &slice[tag_start..tag_end]) {
                out.push(payload);
            }
            let Some(end_pos) = find_subslice(&lower[tag_end..], end_tag) else {
                idx = tag_end;
                continue;
            };
            let content_end = tag_end + end_pos;
            let content = &slice[tag_end..content_end];
            if let Some(payload) = decode_base64_content(content) {
                out.push(payload);
            }
            idx = content_end + end_tag.len();
        }
    }
    out
}

fn xfa_script_tag_is_javascript(tag: &[u8]) -> bool {
    let lower = String::from_utf8_lossy(tag).to_ascii_lowercase();
    let attrs = ["contenttype", "type", "language"];
    let mut found_attr = false;
    for attr in attrs {
        if let Some(value) = extract_attr_value(&lower, attr) {
            found_attr = true;
            if value.contains("javascript") || value.contains("ecmascript") {
                return true;
            }
        }
    }
    if found_attr {
        return false;
    }
    true
}

fn extract_data_uri_from_tag(tag_lower: &[u8], tag_raw: &[u8]) -> Option<XfaPayload> {
    let tag = String::from_utf8_lossy(tag_lower).to_string();
    let value =
        extract_attr_value(&tag, "href").or_else(|| extract_attr_value(&tag, "xlink:href"))?;
    if !value.starts_with("data:") {
        return None;
    }
    let parts: Vec<&str> = value.splitn(2, ',').collect();
    if parts.len() != 2 {
        return None;
    }
    let meta = parts[0];
    let data = parts[1];
    let content_type =
        meta.strip_prefix("data:").and_then(|v| v.split(';').next()).map(|v| v.to_string());
    let decoded = STANDARD.decode(data.as_bytes()).ok()?;
    Some(XfaPayload {
        bytes: decoded,
        content_type,
        source: String::from_utf8_lossy(tag_raw).to_string(),
    })
}

fn decode_base64_content(content: &[u8]) -> Option<XfaPayload> {
    let stripped = strip_cdata(content);
    let trimmed = trim_ascii_whitespace(stripped);
    if trimmed.is_empty() {
        return None;
    }
    let decoded = STANDARD.decode(trimmed).ok()?;
    Some(XfaPayload { bytes: decoded, content_type: None, source: "xfa:image-body".into() })
}

fn extract_attr_value(tag: &str, attr: &str) -> Option<String> {
    let needle = format!("{}=", attr);
    let pos = tag.find(&needle)?;
    let rest = &tag[pos + needle.len()..];
    let rest = rest.trim_start();
    let quote = rest.chars().next()?;
    let rest = rest.trim_start_matches(quote);
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

fn strip_cdata(bytes: &[u8]) -> &[u8] {
    let lower: Vec<u8> = bytes.iter().map(|b| b.to_ascii_lowercase()).collect();
    let start = b"<![cdata[";
    let end = b"]]>";
    let Some(start_pos) = find_subslice(&lower, start) else {
        return bytes;
    };
    let after_start = start_pos + start.len();
    let Some(end_pos) = find_subslice(&lower[after_start..], end) else {
        return bytes;
    };
    let content_end = after_start + end_pos;
    &bytes[after_start..content_end]
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let mut start = 0usize;
    let mut end = bytes.len();
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &bytes[start..end]
}
