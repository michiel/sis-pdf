use sis_pdf_pdf::object::{PdfAtom, PdfObj, PdfStr};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NormalisedExternalTarget {
    pub original: String,
    pub normalised: String,
    pub protocol: Option<String>,
    pub credential_leak_risk: bool,
    pub high_risk_scheme: bool,
    pub obfuscated: bool,
    pub ntlm_host: Option<String>,
    pub ntlm_share: Option<String>,
}

pub fn extract_text_target(obj: &PdfObj<'_>) -> Option<String> {
    match &obj.atom {
        PdfAtom::Str(text) => Some(String::from_utf8_lossy(&string_bytes(text)).to_string()),
        PdfAtom::Name(name) => Some(String::from_utf8_lossy(&name.decoded).to_string()),
        _ => None,
    }
}

pub fn normalise_external_target(raw: &str) -> Option<NormalisedExternalTarget> {
    let original = raw.trim().to_string();
    if original.is_empty() {
        return None;
    }
    let percent_decoded = percent_decode_ascii(&original);
    let mut normalised = collapse_whitespace(&percent_decoded).trim().to_string();
    if normalised.starts_with("SMB://") {
        normalised = format!("smb://{}", &normalised[6..]);
    }
    if normalised.starts_with("//") {
        normalised = format!("\\\\{}", normalised.trim_start_matches('/'));
    }
    if normalised.starts_with(r"\\") {
        normalised = normalised.replace('/', r"\");
    }
    let protocol = classify_protocol(&normalised).map(ToString::to_string);
    let (ntlm_host, ntlm_share) = extract_ntlm_target_details(&normalised, protocol.as_deref());
    let credential_leak_risk = matches!(protocol.as_deref(), Some("unc" | "smb"));
    let high_risk_scheme = matches!(protocol.as_deref(), Some("unc" | "smb" | "file" | "data"));
    let obfuscated = is_obfuscated(raw, &normalised);
    Some(NormalisedExternalTarget {
        original,
        normalised,
        protocol,
        credential_leak_risk,
        high_risk_scheme,
        obfuscated,
        ntlm_host,
        ntlm_share,
    })
}

pub fn classify_protocol(raw: &str) -> Option<&'static str> {
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("\\\\") {
        return Some("unc");
    }
    if lower.starts_with("smb://") {
        return Some("smb");
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Some("http");
    }
    if lower.starts_with("ftp://") {
        return Some("ftp");
    }
    if lower.starts_with("file://") {
        return Some("file");
    }
    if lower.starts_with("data:") {
        return Some("data");
    }
    None
}

pub fn extract_ntlm_target_details(
    target: &str,
    protocol: Option<&str>,
) -> (Option<String>, Option<String>) {
    if protocol == Some("unc") {
        let trimmed = target.trim().trim_start_matches('\\');
        let mut parts = trimmed.split('\\').filter(|part| !part.is_empty());
        let host = parts.next().map(|value| value.to_string());
        let share = parts.next().map(|value| value.to_string());
        return (host, share);
    }
    if protocol == Some("smb") {
        let trimmed = target.trim();
        let without_scheme =
            trimmed.strip_prefix("smb://").or_else(|| trimmed.strip_prefix("SMB://"));
        if let Some(rest) = without_scheme {
            let mut parts = rest.split('/').filter(|part| !part.is_empty());
            let host = parts.next().map(|value| value.to_string());
            let share = parts.next().map(|value| value.to_string());
            return (host, share);
        }
    }
    (None, None)
}

fn string_bytes(value: &PdfStr<'_>) -> Vec<u8> {
    match value {
        PdfStr::Literal { decoded, .. } => decoded.clone(),
        PdfStr::Hex { decoded, .. } => decoded.clone(),
    }
}

fn is_obfuscated(raw: &str, normalised: &str) -> bool {
    raw != normalised
        || raw.contains('%')
        || raw.contains('\n')
        || raw.contains('\r')
        || raw.contains('\t')
}

fn percent_decode_ascii(input: &str) -> String {
    let mut out = String::new();
    let bytes = input.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h1 = bytes[i + 1];
            let h2 = bytes[i + 2];
            if let (Some(a), Some(b)) = (hex_val(h1), hex_val(h2)) {
                let value = (a << 4) | b;
                out.push(value as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn collapse_whitespace(input: &str) -> String {
    let mut out = String::new();
    let mut last_ws = false;
    for ch in input.chars() {
        if ch.is_ascii_whitespace() {
            if !last_ws {
                out.push(' ');
            }
            last_ws = true;
        } else {
            out.push(ch);
            last_ws = false;
        }
    }
    out
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(10 + (byte - b'a')),
        b'A'..=b'F' => Some(10 + (byte - b'A')),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_protocol, normalise_external_target};

    #[test]
    fn normaliser_decodes_and_flags_obfuscation() {
        let result = normalise_external_target("  smb://host/%73hare  ").expect("target");
        assert_eq!(result.protocol.as_deref(), Some("smb"));
        assert!(result.obfuscated);
        assert_eq!(result.ntlm_host.as_deref(), Some("host"));
    }

    #[test]
    fn protocol_classification_handles_unc() {
        assert_eq!(classify_protocol("\\\\host\\share\\file"), Some("unc"));
    }
}
