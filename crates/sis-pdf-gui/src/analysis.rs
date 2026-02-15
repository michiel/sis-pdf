use sis_pdf_core::report::Report;
use sis_pdf_core::runner::run_scan_with_detectors;
use sis_pdf_core::scan::{
    CorrelationOptions, FontAnalysisOptions, ImageAnalysisOptions, ProfileFormat, ScanOptions,
};

/// Browser security profile: non-configurable hard caps for WASM analysis.
const MAX_FILE_SIZE: usize = 50 * 1024 * 1024; // 50 MB
const MAX_OBJECTS: usize = 250_000;
const MAX_DECODE_BYTES: usize = 64 * 1024 * 1024; // 64 MB
const MAX_TOTAL_DECODED_BYTES: usize = 256 * 1024 * 1024; // 256 MB
const MAX_RECURSION_DEPTH: usize = 50;

/// Result of browser-side PDF analysis.
#[derive(Debug)]
pub struct AnalysisResult {
    pub report: Report,
    pub file_name: String,
    pub file_size: usize,
}

/// Error returned when analysis cannot proceed.
#[derive(Debug)]
pub enum AnalysisError {
    FileTooLarge { size: usize, limit: usize },
    ParseFailed(String),
    ScanFailed(String),
}

impl std::fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileTooLarge { size, limit } => {
                write!(f, "File size {} bytes exceeds {} byte limit", size, limit)
            }
            Self::ParseFailed(msg) => write!(f, "PDF parse failed: {}", msg),
            Self::ScanFailed(msg) => write!(f, "Scan failed: {}", msg),
        }
    }
}

/// Run the analysis pipeline on raw PDF bytes with hardened browser caps.
pub fn analyze(bytes: &[u8], file_name: &str) -> Result<AnalysisResult, AnalysisError> {
    if bytes.len() > MAX_FILE_SIZE {
        return Err(AnalysisError::FileTooLarge { size: bytes.len(), limit: MAX_FILE_SIZE });
    }

    let options = ScanOptions {
        deep: false,
        max_decode_bytes: MAX_DECODE_BYTES,
        max_total_decoded_bytes: MAX_TOTAL_DECODED_BYTES,
        recover_xref: true,
        parallel: false,
        batch_parallel: false,
        diff_parser: false,
        max_objects: MAX_OBJECTS,
        max_recursion_depth: MAX_RECURSION_DEPTH,
        fast: false,
        focus_trigger: None,
        focus_depth: 0,
        yara_scope: None,
        strict: false,
        strict_summary: false,
        ir: false,
        ml_config: None,
        font_analysis: FontAnalysisOptions::default(),
        image_analysis: ImageAnalysisOptions::default(),
        filter_allowlist: None,
        filter_allowlist_strict: false,
        profile: false,
        profile_format: ProfileFormat::Text,
        group_chains: true,
        correlation: CorrelationOptions::default(),
    };

    let detectors = sis_pdf_detectors::default_detectors();

    let report = run_scan_with_detectors(bytes, options, &detectors)
        .map_err(|e| AnalysisError::ScanFailed(e.to_string()))?;

    Ok(AnalysisResult { report, file_name: file_name.to_string(), file_size: bytes.len() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_file() {
        let big = vec![0u8; MAX_FILE_SIZE + 1];
        let result = analyze(&big, "too_big.pdf");
        assert!(result.is_err());
        match result.unwrap_err() {
            AnalysisError::FileTooLarge { size, limit } => {
                assert_eq!(size, MAX_FILE_SIZE + 1);
                assert_eq!(limit, MAX_FILE_SIZE);
            }
            other => panic!("Expected FileTooLarge, got: {:?}", other),
        }
    }

    #[test]
    fn analyzes_minimal_pdf() {
        let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n58\n%%EOF";
        let result = analyze(pdf, "minimal.pdf");
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.file_name, "minimal.pdf");
        assert_eq!(result.file_size, pdf.len());
    }
}
