mod parser;
mod variable_fonts;

pub use parser::{parse_font, FontContext};

use crate::model::FontFinding;

#[cfg(feature = "dynamic")]
pub fn analyse(data: &[u8]) -> Result<(), String> {
    // Try parsing with skrifa first (original behavior)
    use skrifa::FontRef;
    FontRef::new(data)
        .map(|_| ())
        .map_err(|err| err.to_string())?;

    // Also try ttf-parser for more detailed analysis
    let _context = parser::parse_font(data)?;

    Ok(())
}

#[cfg(not(feature = "dynamic"))]
pub fn analyse(_data: &[u8]) -> Result<(), String> {
    Err("dynamic analysis not compiled".into())
}

#[cfg(feature = "dynamic")]
pub fn available() -> bool {
    true
}

#[cfg(not(feature = "dynamic"))]
pub fn available() -> bool {
    false
}

/// Perform comprehensive dynamic analysis and return findings
#[cfg(feature = "dynamic")]
pub fn analyze_with_findings(data: &[u8]) -> Vec<FontFinding> {
    let mut findings = Vec::new();

    // Parse font and extract context
    let context = match parser::parse_font(data) {
        Ok(ctx) => ctx,
        Err(err) => {
            let mut meta = HashMap::new();
            meta.insert("parse_error".to_string(), err);
            findings.push(FontFinding {
                kind: "font.dynamic_parse_failure".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                title: "Font parsing failed".to_string(),
                description: "Dynamic font parsing encountered an error".to_string(),
                meta,
            });
            return findings;
        }
    };

    // Check for CVE-specific issues
    variable_fonts::check_cve_2025_27163(&context, &mut findings);
    variable_fonts::check_cve_2025_27164(&context, &mut findings);

    findings
}

#[cfg(not(feature = "dynamic"))]
pub fn analyze_with_findings(_data: &[u8]) -> Vec<FontFinding> {
    Vec::new()
}
