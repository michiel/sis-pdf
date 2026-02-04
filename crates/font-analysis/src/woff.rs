/// WOFF/WOFF2 decompression and conversion to SFNT format
///
/// This module handles WOFF and WOFF2 compressed fonts, decompressing them
/// and converting to standard SFNT format for analysis.
#[cfg(feature = "dynamic")]
use std::collections::HashMap;
#[cfg(feature = "dynamic")]
use tracing::{debug, instrument, warn};

use crate::model::FontFinding;
#[cfg(feature = "dynamic")]
use crate::model::{Confidence, Severity};

/// Detect if data is a WOFF font
pub fn is_woff(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == b"wOFF"
}

/// Detect if data is a WOFF2 font
pub fn is_woff2(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == b"wOF2"
}

/// Decompress WOFF/WOFF2 font to SFNT format
#[cfg(feature = "dynamic")]
#[instrument(skip(data), fields(data_len = data.len(), is_woff = is_woff(data), is_woff2 = is_woff2(data)))]
pub fn decompress_woff(data: &[u8]) -> Result<Vec<u8>, String> {
    if is_woff2(data) {
        debug!("Decompressing WOFF2 font");
        decompress_woff2(data)
    } else if is_woff(data) {
        debug!("Decompressing WOFF font");
        decompress_woff1(data)
    } else {
        Err("Not a WOFF/WOFF2 font".to_string())
    }
}

#[cfg(not(feature = "dynamic"))]
pub fn decompress_woff(_data: &[u8]) -> Result<Vec<u8>, String> {
    Err("WOFF support requires dynamic feature".to_string())
}

/// Decompress WOFF (version 1) to SFNT
#[cfg(feature = "dynamic")]
fn decompress_woff1(data: &[u8]) -> Result<Vec<u8>, String> {
    use allsorts::binary::read::ReadScope;
    use allsorts::subset::whole_font;
    use allsorts::tag;
    use allsorts::woff::WoffFont;

    let scope = ReadScope::new(data);
    let woff =
        scope.read::<WoffFont<'_>>().map_err(|e| format!("Failed to parse WOFF file: {:?}", e))?;

    let tags: Vec<u32> = woff.table_directory.iter().map(|entry| entry.tag).collect();
    if !tags.contains(&tag::HEAD) || !tags.contains(&tag::MAXP) {
        debug!("WOFF font missing required tables; skipping SFNT conversion");
        return Ok(data.to_vec());
    }

    whole_font(&woff, &tags).map_err(|e| format!("Failed to build SFNT from WOFF: {:?}", e))
}

/// Decompress WOFF2 to SFNT
#[cfg(feature = "dynamic")]
fn decompress_woff2(data: &[u8]) -> Result<Vec<u8>, String> {
    use allsorts::binary::read::ReadScope;
    use allsorts::subset::whole_font;
    use allsorts::tag;
    use allsorts::woff2::Woff2Font;

    let scope = ReadScope::new(data);
    let woff = scope
        .read::<Woff2Font<'_>>()
        .map_err(|e| format!("Failed to parse WOFF2 file: {:?}", e))?;
    let tags: Vec<u32> = woff.table_directory.iter().map(|entry| entry.tag).collect();
    if !tags.contains(&tag::HEAD) || !tags.contains(&tag::MAXP) {
        debug!("WOFF2 font missing required tables; skipping SFNT conversion");
        return Ok(data.to_vec());
    }
    let provider =
        woff.table_provider(0).map_err(|e| format!("Failed to load WOFF2 tables: {:?}", e))?;
    whole_font(&provider, &tags).map_err(|e| format!("Failed to build SFNT from WOFF2: {:?}", e))
}

/// Validate WOFF decompression for security issues
#[cfg(feature = "dynamic")]
#[instrument(skip(data), fields(data_len = data.len()))]
pub fn validate_woff_decompression(data: &[u8]) -> Vec<FontFinding> {
    let mut findings = Vec::new();

    // Check for integer overflow in decompression
    // WOFF header contains original length field
    if is_woff(data) && data.len() >= 16 {
        let original_length = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;

        // Suspicious if claimed decompressed size is > 100MB
        if original_length > 100 * 1024 * 1024 {
            warn!(original_length = original_length, "Suspiciously large WOFF original length");

            let mut meta = HashMap::new();
            meta.insert("format".to_string(), "WOFF".to_string());
            meta.insert("original_length".to_string(), original_length.to_string());
            meta.insert("max_safe_size".to_string(), "104857600".to_string());

            findings.push(FontFinding {
                kind: "font.woff_decompression_anomaly".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                title: "Suspicious WOFF decompression size".to_string(),
                description: format!(
                    "WOFF file claims decompressed size of {} bytes (>100MB), potential DoS",
                    original_length
                ),
                meta,
            });
        }

        // Check for decompression bomb (claimed size >> compressed size)
        let compression_ratio = original_length as f64 / data.len() as f64;
        if compression_ratio > 1000.0 {
            warn!(compression_ratio = compression_ratio, "Suspicious WOFF compression ratio");

            let mut meta = HashMap::new();
            meta.insert("format".to_string(), "WOFF".to_string());
            meta.insert("compression_ratio".to_string(), compression_ratio.to_string());
            meta.insert("compressed_size".to_string(), data.len().to_string());
            meta.insert("claimed_size".to_string(), original_length.to_string());

            findings.push(FontFinding {
                kind: "font.woff_decompression_anomaly".to_string(),
                severity: Severity::High,
                confidence: Confidence::Probable,
                title: "WOFF decompression bomb detected".to_string(),
                description: format!(
                    "WOFF compression ratio of {:.1}x is suspicious (decompression bomb)",
                    compression_ratio
                ),
                meta,
            });
        }
    }

    // Similar checks for WOFF2
    if is_woff2(data) && data.len() >= 48 {
        let total_sfnt_size = u32::from_be_bytes([data[12], data[13], data[14], data[15]]) as usize;

        if total_sfnt_size > 100 * 1024 * 1024 {
            warn!(total_sfnt_size = total_sfnt_size, "Suspiciously large WOFF2 original length");

            let mut meta = HashMap::new();
            meta.insert("format".to_string(), "WOFF2".to_string());
            meta.insert("total_sfnt_size".to_string(), total_sfnt_size.to_string());
            meta.insert("max_safe_size".to_string(), "104857600".to_string());

            findings.push(FontFinding {
                kind: "font.woff_decompression_anomaly".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                title: "Suspicious WOFF2 decompression size".to_string(),
                description: format!(
                    "WOFF2 file claims decompressed size of {} bytes (>100MB), potential DoS",
                    total_sfnt_size
                ),
                meta,
            });
        }

        let compression_ratio = total_sfnt_size as f64 / data.len() as f64;
        if compression_ratio > 1000.0 {
            warn!(compression_ratio = compression_ratio, "Suspicious WOFF2 compression ratio");

            let mut meta = HashMap::new();
            meta.insert("format".to_string(), "WOFF2".to_string());
            meta.insert("compression_ratio".to_string(), compression_ratio.to_string());

            findings.push(FontFinding {
                kind: "font.woff_decompression_anomaly".to_string(),
                severity: Severity::High,
                confidence: Confidence::Probable,
                title: "WOFF2 decompression bomb detected".to_string(),
                description: format!(
                    "WOFF2 compression ratio of {:.1}x is suspicious (decompression bomb)",
                    compression_ratio
                ),
                meta,
            });
        }
    }

    findings
}

#[cfg(not(feature = "dynamic"))]
pub fn validate_woff_decompression(_data: &[u8]) -> Vec<FontFinding> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_woff() {
        let woff_data = b"wOFF\x00\x00\x00\x00";
        assert!(is_woff(woff_data));

        let not_woff = b"OTTO\x00\x00\x00\x00";
        assert!(!is_woff(not_woff));
    }

    #[test]
    fn test_is_woff2() {
        let woff2_data = b"wOF2\x00\x00\x00\x00";
        assert!(is_woff2(woff2_data));

        let not_woff2 = b"wOFF\x00\x00\x00\x00";
        assert!(!is_woff2(not_woff2));
    }

    #[test]
    #[cfg(feature = "dynamic")]
    fn test_validate_woff_decompression_bomb() {
        // Create WOFF header with suspicious decompression ratio
        let mut woff_data = vec![0u8; 16];
        woff_data[0..4].copy_from_slice(b"wOFF");
        // Original length = 100MB
        woff_data[8..12].copy_from_slice(&100_000_000u32.to_be_bytes());

        let findings = validate_woff_decompression(&woff_data);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.kind == "font.woff_decompression_anomaly"));
    }
}
