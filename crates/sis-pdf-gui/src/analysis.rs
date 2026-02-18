use sis_pdf_core::report::Report;
use sis_pdf_core::runner::run_scan_with_detectors;
use sis_pdf_core::scan::{
    CorrelationOptions, FontAnalysisOptions, ImageAnalysisOptions, ProfileFormat, ScanOptions,
};
use sis_pdf_pdf::graph::ParseOptions;

use crate::object_data::{self, ObjectData, ObjectExtractOptions};

/// Browser security profile: non-configurable hard caps for WASM analysis.
const MAX_FILE_SIZE: usize = 50 * 1024 * 1024; // 50 MB
const MAX_OBJECTS: usize = 250_000;
const MAX_DECODE_BYTES: usize = 64 * 1024 * 1024; // 64 MB
const MAX_TOTAL_DECODED_BYTES: usize = 256 * 1024 * 1024; // 256 MB
const MAX_RECURSION_DEPTH: usize = 50;

/// Result of browser-side PDF analysis.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AnalysisResult {
    pub report: Report,
    pub object_data: ObjectData,
    pub bytes: Vec<u8>,
    pub file_name: String,
    pub file_size: usize,
    pub pdf_version: Option<String>,
    pub page_count: usize,
}

/// Serializable analysis payload used by WASM worker orchestration.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct WorkerAnalysisResult {
    pub report: Report,
    pub object_data: ObjectData,
    pub file_name: String,
    pub file_size: usize,
    pub pdf_version: Option<String>,
    pub page_count: usize,
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

    let options = gui_scan_options();

    let detectors = sis_pdf_detectors::default_detectors();

    let report = run_scan_with_detectors(bytes, options, &detectors)
        .map_err(|e| AnalysisError::ScanFailed(e.to_string()))?;

    // Re-parse to extract owned object data for the Object Inspector.
    // The ObjectGraph borrows bytes and cannot be stored, so we extract
    // an owned summary here. This second parse is fast (~50ms typical).
    let object_data = extract_object_data(bytes);
    let pdf_version = extract_pdf_version(bytes);
    let page_count = count_pages(&object_data);

    Ok(AnalysisResult {
        report,
        object_data,
        bytes: bytes.to_vec(),
        file_name: file_name.to_string(),
        file_size: bytes.len(),
        pdf_version,
        page_count,
    })
}

pub fn analyze_for_worker(
    bytes: &[u8],
    file_name: &str,
) -> Result<WorkerAnalysisResult, AnalysisError> {
    if bytes.len() > MAX_FILE_SIZE {
        return Err(AnalysisError::FileTooLarge { size: bytes.len(), limit: MAX_FILE_SIZE });
    }
    let options = gui_scan_options();
    let detectors = sis_pdf_detectors::default_detectors();
    let report = run_scan_with_detectors(bytes, options, &detectors)
        .map_err(|e| AnalysisError::ScanFailed(e.to_string()))?;
    let object_data = extract_object_data_compact(bytes);
    let pdf_version = extract_pdf_version(bytes);
    let page_count = count_pages(&object_data);
    Ok(WorkerAnalysisResult {
        report,
        object_data,
        file_name: file_name.to_string(),
        file_size: bytes.len(),
        pdf_version,
        page_count,
    })
}

pub fn worker_result_into_analysis(worker: WorkerAnalysisResult, bytes: Vec<u8>) -> AnalysisResult {
    let mut object_data = worker.object_data;
    object_data.rebuild_index();
    AnalysisResult {
        report: worker.report,
        object_data,
        bytes,
        file_name: worker.file_name,
        file_size: worker.file_size,
        pdf_version: worker.pdf_version,
        page_count: worker.page_count,
    }
}

fn gui_scan_options() -> ScanOptions {
    ScanOptions {
        deep: true,
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
        font_analysis: FontAnalysisOptions {
            dynamic_enabled: true,
            ..FontAnalysisOptions::default()
        },
        image_analysis: ImageAnalysisOptions {
            dynamic_enabled: true,
            ..ImageAnalysisOptions::default()
        },
        filter_allowlist: None,
        filter_allowlist_strict: false,
        profile: false,
        profile_format: ProfileFormat::Text,
        group_chains: true,
        correlation: CorrelationOptions::default(),
    }
}

fn extract_object_data(bytes: &[u8]) -> ObjectData {
    extract_object_data_with_options(bytes, ObjectExtractOptions::FULL)
}

fn extract_object_data_compact(bytes: &[u8]) -> ObjectData {
    extract_object_data_with_options(bytes, ObjectExtractOptions::WORKER_COMPACT)
}

fn extract_object_data_with_options(bytes: &[u8], options: ObjectExtractOptions) -> ObjectData {
    let parse_opts = ParseOptions {
        recover_xref: true,
        deep: false,
        strict: false,
        max_objstm_bytes: MAX_DECODE_BYTES,
        max_objects: MAX_OBJECTS,
        max_objstm_total_bytes: MAX_TOTAL_DECODED_BYTES,
        carve_stream_objects: false,
        max_carved_objects: 0,
        max_carved_bytes: 0,
    };
    let graph = match sis_pdf_pdf::graph::parse_pdf(bytes, parse_opts) {
        Ok(g) => g,
        Err(_) => return ObjectData::default(),
    };
    let classifications = graph.classify_objects();
    object_data::extract_object_data_with_options(bytes, &graph, &classifications, options)
}

/// Extract the PDF version from the `%PDF-X.Y` header.
fn extract_pdf_version(bytes: &[u8]) -> Option<String> {
    let prefix = b"%PDF-";
    if bytes.len() < prefix.len() + 3 {
        return None;
    }
    if &bytes[..prefix.len()] != prefix {
        return None;
    }
    let rest = &bytes[prefix.len()..];
    let end = rest
        .iter()
        .position(|&b| b == b'\n' || b == b'\r' || b == b' ')
        .unwrap_or(rest.len())
        .min(10);
    let version = std::str::from_utf8(&rest[..end]).ok()?;
    Some(version.to_string())
}

/// Count objects classified as pages.
fn count_pages(object_data: &ObjectData) -> usize {
    object_data.objects.iter().filter(|o| o.obj_type == "page").count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_data::{extract_object_data_with_options, ObjectExtractOptions};

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

    #[test]
    fn gui_defaults_enable_dynamic_analysis_paths() {
        let options = gui_scan_options();
        assert!(options.deep, "GUI should default to deep analysis");
        assert!(
            options.font_analysis.dynamic_enabled,
            "GUI should enable dynamic font analysis by default"
        );
        assert!(
            options.image_analysis.dynamic_enabled,
            "GUI should enable dynamic image analysis by default"
        );
    }

    #[test]
    fn gui_build_has_js_sandbox_support() {
        assert!(
            sis_pdf_detectors::sandbox_available(),
            "GUI detector build should include js-sandbox support"
        );
    }

    #[test]
    fn worker_result_json_roundtrip_rebuilds_object_index() {
        let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n58\n%%EOF";
        let worker = analyze_for_worker(pdf, "minimal.pdf").expect("analysis should succeed");
        let encoded = serde_json::to_string(&worker).expect("worker result should serialise");
        let decoded: WorkerAnalysisResult =
            serde_json::from_str(&encoded).expect("worker result should deserialise");
        let analysis = worker_result_into_analysis(decoded, pdf.to_vec());
        assert!(
            analysis.object_data.index.contains_key(&(1, 0)),
            "deserialised worker result should rebuild object lookup index"
        );
    }

    #[test]
    fn worker_result_uses_compact_object_payload() {
        let pdf = b"%PDF-1.4\n1 0 obj\n<< /Length 5 >>\nstream\nhello\nendstream\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n62\n%%EOF";
        let worker = analyze_for_worker(pdf, "stream.pdf").expect("analysis should succeed");
        let stream_obj = worker
            .object_data
            .objects
            .iter()
            .find(|obj| obj.has_stream)
            .expect("expected stream object");
        assert!(stream_obj.stream_raw.is_none(), "worker payload should omit decoded stream bytes");
        assert!(
            stream_obj.image_preview.is_none(),
            "worker payload should omit image preview pixels"
        );
    }

    #[test]
    fn compact_object_payload_stays_within_budget_for_stream_heavy_pdf() {
        let pdf = build_stream_heavy_pdf(120, 2048);
        let parse_opts = ParseOptions {
            recover_xref: true,
            deep: false,
            strict: false,
            max_objstm_bytes: MAX_DECODE_BYTES,
            max_objects: MAX_OBJECTS,
            max_objstm_total_bytes: MAX_TOTAL_DECODED_BYTES,
            carve_stream_objects: false,
            max_carved_objects: 0,
            max_carved_bytes: 0,
        };
        let graph = sis_pdf_pdf::graph::parse_pdf(&pdf, parse_opts).expect("parse heavy test PDF");
        let classifications = graph.classify_objects();
        let full = extract_object_data_with_options(
            &pdf,
            &graph,
            &classifications,
            ObjectExtractOptions::FULL,
        );
        let compact = extract_object_data_with_options(
            &pdf,
            &graph,
            &classifications,
            ObjectExtractOptions::WORKER_COMPACT,
        );
        let full_bytes = serde_json::to_vec(&full).expect("serialise full payload").len();
        let compact_bytes = serde_json::to_vec(&compact).expect("serialise compact payload").len();

        assert!(
            compact_bytes < full_bytes / 3,
            "compact payload should be materially smaller (compact={} full={})",
            compact_bytes,
            full_bytes
        );
        assert!(
            compact_bytes <= 1_000_000,
            "compact payload should stay within budget (got {} bytes)",
            compact_bytes
        );
    }

    fn build_stream_heavy_pdf(stream_count: usize, stream_len: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut offsets: Vec<usize> = vec![0]; // xref object 0

        bytes.extend_from_slice(b"%PDF-1.4\n");

        // Root catalog object.
        offsets.push(bytes.len());
        bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog >>\nendobj\n");

        // Stream objects.
        let payload = vec![b'A'; stream_len];
        for obj_num in 2..=(stream_count + 1) {
            offsets.push(bytes.len());
            let header = format!("{} 0 obj\n<< /Length {} >>\nstream\n", obj_num, stream_len);
            bytes.extend_from_slice(header.as_bytes());
            bytes.extend_from_slice(&payload);
            bytes.extend_from_slice(b"\nendstream\nendobj\n");
        }

        let xref_offset = bytes.len();
        let xref_header = format!("xref\n0 {}\n", offsets.len());
        bytes.extend_from_slice(xref_header.as_bytes());
        bytes.extend_from_slice(b"0000000000 65535 f \n");
        for offset in offsets.iter().skip(1) {
            let line = format!("{:010} 00000 n \n", offset);
            bytes.extend_from_slice(line.as_bytes());
        }
        let trailer = format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF",
            offsets.len(),
            xref_offset
        );
        bytes.extend_from_slice(trailer.as_bytes());
        bytes
    }
}
