/// Type 1 font finding generation

use std::collections::HashMap;

use crate::model::{Confidence, FontFinding, Severity};

use super::charstring::{analyze_charstring, CharstringAnalysis};
use super::eexec::decrypt_eexec_auto;

/// Analyze Type 1 font and generate findings
pub fn analyze_type1(data: &[u8]) -> Vec<FontFinding> {
    let mut findings = Vec::new();

    // Try to decrypt eexec section if present
    let decrypted_data = if has_eexec_section(data) {
        extract_and_decrypt_eexec(data)
    } else {
        data.to_vec()
    };

    // Analyze charstrings
    let analysis = analyze_charstring(&decrypted_data);

    // Generate findings based on analysis
    generate_findings_from_analysis(&analysis, &mut findings);

    findings
}

/// Check if data contains an eexec section
fn has_eexec_section(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    text.contains("eexec")
}

/// Extract and decrypt eexec section from Type 1 font
fn extract_and_decrypt_eexec(data: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(data);

    // Find eexec marker
    if let Some(eexec_start) = text.find("eexec") {
        // Skip whitespace after eexec
        let mut start = eexec_start + 5;
        while start < data.len() && data[start].is_ascii_whitespace() {
            start += 1;
        }

        // Find end marker (usually "cleartomark" or "0" followed by zeros)
        let end = find_eexec_end(&data[start..])
            .map(|offset| start + offset)
            .unwrap_or(data.len());

        // Decrypt the section
        let encrypted = &data[start..end];
        let mut decrypted = decrypt_eexec_auto(encrypted);

        // Skip the first 4 random bytes (standard in Type 1)
        if decrypted.len() > 4 {
            decrypted.drain(0..4);
        }

        return decrypted;
    }

    data.to_vec()
}

/// Find the end of an eexec section
fn find_eexec_end(data: &[u8]) -> Option<usize> {
    let text = String::from_utf8_lossy(data);

    // Look for cleartomark or 512 zeros (standard end markers)
    if let Some(pos) = text.find("cleartomark") {
        return Some(pos);
    }

    // Look for pattern of zeros (at least 64 consecutive zeros)
    let mut zero_count = 0;
    for (i, &byte) in data.iter().enumerate() {
        if byte == b'0' || byte == 0 {
            zero_count += 1;
            if zero_count >= 64 {
                return Some(i - 64);
            }
        } else if !byte.is_ascii_whitespace() {
            zero_count = 0;
        }
    }

    None
}

/// Generate findings from charstring analysis
fn generate_findings_from_analysis(analysis: &CharstringAnalysis, findings: &mut Vec<FontFinding>) {
    // Check for dangerous operators
    if !analysis.dangerous_ops.is_empty() {
        let mut meta = HashMap::new();
        meta.insert("operator_count".to_string(), analysis.dangerous_ops.len().to_string());

        let operators: Vec<String> = analysis
            .dangerous_ops
            .iter()
            .map(|op| format!("{}@{}", op.operator, op.context))
            .collect();
        meta.insert("operators".to_string(), operators.join(", "));

        findings.push(FontFinding {
            kind: "font.type1_dangerous_operator".to_string(),
            severity: Severity::High,
            confidence: Confidence::Probable,
            title: "Type 1 font with dangerous operators".to_string(),
            description: format!(
                "Font contains {} dangerous Type 1 operators that could be exploited.",
                analysis.dangerous_ops.len()
            ),
            meta,
        });
    }

    // Check for excessive stack depth
    if analysis.max_stack_depth > 100 {
        let mut meta = HashMap::new();
        meta.insert("max_stack_depth".to_string(), analysis.max_stack_depth.to_string());

        findings.push(FontFinding {
            kind: "font.type1_excessive_stack".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            title: "Type 1 font with excessive stack usage".to_string(),
            description: format!(
                "Font charstrings use excessive stack depth ({}), which may indicate an exploit attempt.",
                analysis.max_stack_depth
            ),
            meta,
        });
    }

    // Check for large charstring programs
    if analysis.total_operators > 10_000 {
        let mut meta = HashMap::new();
        meta.insert("total_operators".to_string(), analysis.total_operators.to_string());

        findings.push(FontFinding {
            kind: "font.type1_large_charstring".to_string(),
            severity: Severity::Low,
            confidence: Confidence::Heuristic,
            title: "Type 1 font with large charstring program".to_string(),
            description: format!(
                "Font contains {} charstring operators, which is unusually large.",
                analysis.total_operators
            ),
            meta,
        });
    }

    // Check for BLEND exploit pattern
    if analysis.has_blend_pattern {
        let mut meta = HashMap::new();
        meta.insert("exploit_type".to_string(), "BLEND_2015".to_string());

        findings.push(FontFinding {
            kind: "font.type1_blend_exploit".to_string(),
            severity: Severity::High,
            confidence: Confidence::Strong,
            title: "Type 1 BLEND exploit pattern detected".to_string(),
            description: "Font contains the signature pattern of the 2015 BLEND exploit (CVE-2015-XXXX).".to_string(),
            meta,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_eexec_section() {
        let data = b"currentfile eexec 1234567890";
        assert!(has_eexec_section(data));

        let data = b"no encryption here";
        assert!(!has_eexec_section(data));
    }

    #[test]
    fn test_analyze_type1_benign() {
        let data = b"/.notdef { 0 0 rmoveto 100 100 rlineto closepath endchar } ND";
        let findings = analyze_type1(data);

        // Should not generate findings for benign font
        assert!(findings.is_empty() || findings.iter().all(|f| f.severity != Severity::High));
    }

    #[test]
    fn test_analyze_type1_with_dangerous_ops() {
        let data = b"/.notdef { callothersubr return callothersubr return callothersubr return callothersubr return } ND";
        let findings = analyze_type1(data);

        // Should generate findings for dangerous operators
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.kind == "font.type1_dangerous_operator"));
    }

    #[test]
    fn test_analyze_type1_blend_pattern() {
        // Simulate BLEND exploit pattern
        let data = b"/.test { callothersubr return callothersubr return callothersubr return callothersubr return } ND";
        let findings = analyze_type1(data);

        // Should detect BLEND pattern
        assert!(findings.iter().any(|f| f.kind == "font.type1_blend_exploit"));
    }
}
