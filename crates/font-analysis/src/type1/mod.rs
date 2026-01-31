mod charstring;
mod eexec;
mod findings;

pub use findings::analyze_type1;

/// Checks if font data represents a Type 1 font by examining headers and markers
pub fn is_type1_font(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    // Check for PostScript Type 1 markers in first 1KB
    let search_len = data.len().min(1024);
    let search_data = &data[0..search_len];

    // Look for Type 1 font signatures
    has_ps_adobe_font_marker(search_data)
        || has_font_type_1_marker(search_data)
        || has_notdef_marker(search_data)
        || has_pfb_header(data)
}

/// Check for %!PS-AdobeFont marker
fn has_ps_adobe_font_marker(data: &[u8]) -> bool {
    let markers: &[&[u8]] = &[
        b"%!PS-AdobeFont",
        b"%!FontType1",
        b"%!PS-Adobe-3.0 Resource-Font",
    ];

    for marker in markers {
        if data.len() >= marker.len() {
            for i in 0..=data.len().saturating_sub(marker.len()) {
                if &data[i..i + marker.len()] == *marker {
                    return true;
                }
            }
        }
    }
    false
}

/// Check for FontType 1 marker
fn has_font_type_1_marker(data: &[u8]) -> bool {
    // Look for "/FontType 1" in the data
    let marker = b"/FontType 1";
    if data.len() >= marker.len() {
        for i in 0..=data.len().saturating_sub(marker.len()) {
            if &data[i..i + marker.len()] == marker {
                return true;
            }
        }
    }
    false
}

/// Check for .notdef marker (common in Type 1 fonts)
fn has_notdef_marker(data: &[u8]) -> bool {
    let marker = b"/.notdef";
    if data.len() >= marker.len() {
        for i in 0..=data.len().saturating_sub(marker.len()) {
            if &data[i..i + marker.len()] == marker {
                return true;
            }
        }
    }
    false
}

/// Check for PFB (Printer Font Binary) header
fn has_pfb_header(data: &[u8]) -> bool {
    // PFB files start with 0x80 0x01
    data.len() >= 2 && data[0] == 0x80 && (data[1] == 0x01 || data[1] == 0x02)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ps_adobe_font_marker() {
        let data = b"%!PS-AdobeFont-1.0: Helvetica";
        assert!(is_type1_font(data));
    }

    #[test]
    fn test_font_type_1_marker() {
        let data = b"/FontType 1 def";
        assert!(is_type1_font(data));
    }

    #[test]
    fn test_notdef_marker() {
        let data = b"/.notdef 0 def";
        assert!(is_type1_font(data));
    }

    #[test]
    fn test_pfb_header() {
        let data = b"\x80\x01\x00\x00\x00\x00";
        assert!(is_type1_font(data));
    }

    #[test]
    fn test_not_type1() {
        let data = b"\x00\x01\x00\x00"; // TrueType/OpenType header
        assert!(!is_type1_font(data));
    }

    #[test]
    fn test_empty_data() {
        let data = b"";
        assert!(!is_type1_font(data));
    }
}
