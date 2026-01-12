use anyhow::{anyhow, Result};
use serde::Serialize;
use serde_json;
use std::fs;
use std::path::Path;

use sis_pdf_core::scan::ScanContext;
use sis_pdf_core::model::Severity;

/// Query types supported by the interface
#[derive(Debug, Clone)]
pub enum Query {
    // Metadata queries
    Pages,
    Objects,
    ObjectsCount,
    Creator,
    Producer,
    Title,
    Created,
    Modified,
    Version,
    Encrypted,
    Filesize,

    // Structure queries
    Trailer,
    Catalog,

    // Content queries
    JavaScript,
    JavaScriptCount,
    Urls,
    UrlsCount,
    Embedded,
    EmbeddedCount,

    // Finding queries
    Findings,
    FindingsCount,
    FindingsBySeverity(Severity),
    FindingsByKind(String),

    // Object queries
    ShowObject(u32, u16),

    // Advanced queries
    Chains,
    Cycles,
}

/// Query result that can be serialized to JSON or formatted as text
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum QueryResult {
    Scalar(ScalarValue),
    List(Vec<String>),
    Structure(serde_json::Value),
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ScalarValue {
    String(String),
    Number(i64),
    Boolean(bool),
}

/// Parse a query string into a Query enum
pub fn parse_query(input: &str) -> Result<Query> {
    let input = input.trim();

    match input {
        // Metadata
        "pages" => Ok(Query::Pages),
        "objects" => Ok(Query::ObjectsCount),
        "objects.count" => Ok(Query::ObjectsCount),
        "creator" => Ok(Query::Creator),
        "producer" => Ok(Query::Producer),
        "title" => Ok(Query::Title),
        "created" => Ok(Query::Created),
        "modified" => Ok(Query::Modified),
        "version" => Ok(Query::Version),
        "encrypted" => Ok(Query::Encrypted),
        "filesize" => Ok(Query::Filesize),

        // Structure
        "trailer" => Ok(Query::Trailer),
        "catalog" => Ok(Query::Catalog),

        // Content
        "js" | "javascript" => Ok(Query::JavaScript),
        "js.count" => Ok(Query::JavaScriptCount),
        "urls" | "uris" => Ok(Query::Urls),
        "urls.count" => Ok(Query::UrlsCount),
        "embedded" => Ok(Query::Embedded),
        "embedded.count" => Ok(Query::EmbeddedCount),

        // Findings
        "findings" => Ok(Query::Findings),
        "findings.count" => Ok(Query::FindingsCount),
        "findings.high" => Ok(Query::FindingsBySeverity(Severity::High)),
        "findings.medium" => Ok(Query::FindingsBySeverity(Severity::Medium)),
        "findings.low" => Ok(Query::FindingsBySeverity(Severity::Low)),
        "findings.info" => Ok(Query::FindingsBySeverity(Severity::Info)),
        "findings.critical" => Ok(Query::FindingsBySeverity(Severity::Critical)),

        // Advanced
        "chains" => Ok(Query::Chains),
        "cycles" => Ok(Query::Cycles),

        _ => {
            // Try to parse object queries
            if let Some(rest) = input.strip_prefix("object ").or(input.strip_prefix("obj ")) {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() == 1 {
                    let obj = parts[0].parse::<u32>()
                        .map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    return Ok(Query::ShowObject(obj, 0));
                } else if parts.len() == 2 {
                    let obj = parts[0].parse::<u32>()
                        .map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    let gen = parts[1].parse::<u16>()
                        .map_err(|_| anyhow!("Invalid generation number: {}", parts[1]))?;
                    return Ok(Query::ShowObject(obj, gen));
                }
            }

            // Try to parse findings.kind query
            if let Some(kind) = input.strip_prefix("findings.kind ") {
                return Ok(Query::FindingsByKind(kind.to_string()));
            }

            Err(anyhow!("Unknown query: {}", input))
        }
    }
}

/// Build a scan context (public version for REPL caching)
pub fn build_scan_context_public<'a>(
    bytes: &'a [u8],
    options: &ScanOptions,
) -> Result<sis_pdf_core::scan::ScanContext<'a>> {
    build_scan_context(bytes, options)
}

/// Execute a query using a pre-built context (for REPL mode)
pub fn execute_query_with_context(
    query: &Query,
    ctx: &ScanContext,
) -> Result<QueryResult> {
    match query {
        Query::Pages => {
            let count = count_pages(ctx)?;
            Ok(QueryResult::Scalar(ScalarValue::Number(count as i64)))
        }
        Query::ObjectsCount => {
            let count = ctx.graph.objects.len();
            Ok(QueryResult::Scalar(ScalarValue::Number(count as i64)))
        }
        Query::Creator => {
            let creator = get_metadata_field(ctx, "Creator")?;
            Ok(QueryResult::Scalar(ScalarValue::String(creator)))
        }
        Query::Producer => {
            let producer = get_metadata_field(ctx, "Producer")?;
            Ok(QueryResult::Scalar(ScalarValue::String(producer)))
        }
        Query::Title => {
            let title = get_metadata_field(ctx, "Title")?;
            Ok(QueryResult::Scalar(ScalarValue::String(title)))
        }
        Query::Version => {
            let version = get_pdf_version(ctx.bytes)?;
            Ok(QueryResult::Scalar(ScalarValue::String(version)))
        }
        Query::Encrypted => {
            let encrypted = is_encrypted(ctx)?;
            Ok(QueryResult::Scalar(ScalarValue::Boolean(encrypted)))
        }
        Query::Filesize => {
            Ok(QueryResult::Scalar(ScalarValue::Number(ctx.bytes.len() as i64)))
        }
        Query::FindingsCount => {
            let findings = run_detectors(ctx)?;
            Ok(QueryResult::Scalar(ScalarValue::Number(findings.len() as i64)))
        }
        Query::FindingsBySeverity(severity) => {
            let findings = run_detectors(ctx)?;
            let filtered: Vec<String> = findings
                .iter()
                .filter(|f| &f.severity == severity)
                .map(|f| format!("{}: {}", f.kind, f.title))
                .collect();
            Ok(QueryResult::List(filtered))
        }
        Query::FindingsByKind(kind) => {
            let findings = run_detectors(ctx)?;
            let filtered: Vec<String> = findings
                .iter()
                .filter(|f| f.kind == *kind)
                .map(|f| format!("{}: {}", f.kind, f.title))
                .collect();
            Ok(QueryResult::List(filtered))
        }
        Query::Findings => {
            let findings = run_detectors(ctx)?;
            let result: Vec<String> = findings
                .iter()
                .map(|f| format!("{}: {}", f.kind, f.title))
                .collect();
            Ok(QueryResult::List(result))
        }
        Query::JavaScript => {
            let js_code = extract_javascript(ctx)?;
            Ok(QueryResult::List(js_code))
        }
        Query::JavaScriptCount => {
            let js_code = extract_javascript(ctx)?;
            Ok(QueryResult::Scalar(ScalarValue::Number(js_code.len() as i64)))
        }
        Query::Urls => {
            let urls = extract_urls(ctx)?;
            Ok(QueryResult::List(urls))
        }
        Query::UrlsCount => {
            let urls = extract_urls(ctx)?;
            Ok(QueryResult::Scalar(ScalarValue::Number(urls.len() as i64)))
        }
        Query::Embedded => {
            let embedded = extract_embedded_files(ctx)?;
            Ok(QueryResult::List(embedded))
        }
        Query::EmbeddedCount => {
            let embedded = extract_embedded_files(ctx)?;
            Ok(QueryResult::Scalar(ScalarValue::Number(embedded.len() as i64)))
        }
        Query::Created => {
            let created = get_metadata_field(ctx, "CreationDate")?;
            Ok(QueryResult::Scalar(ScalarValue::String(created)))
        }
        Query::Modified => {
            let modified = get_metadata_field(ctx, "ModDate")?;
            Ok(QueryResult::Scalar(ScalarValue::String(modified)))
        }
        _ => Err(anyhow!("Query not yet implemented: {:?}", query)),
    }
}

/// Execute a query against a PDF file
pub fn execute_query(
    query: &Query,
    pdf_path: &Path,
    scan_options: &ScanOptions,
) -> Result<QueryResult> {
    // Read PDF file
    let bytes = fs::read(pdf_path)?;

    // Parse PDF and build context
    let ctx = build_scan_context(&bytes, scan_options)?;

    // Delegate to execute_query_with_context
    execute_query_with_context(query, &ctx)
}

/// Scan options for query execution
pub struct ScanOptions {
    pub deep: bool,
    pub max_decode_bytes: usize,
    pub max_total_decoded_bytes: usize,
    pub no_recover: bool,
    pub max_objects: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            deep: false,
            max_decode_bytes: 32 * 1024 * 1024,
            max_total_decoded_bytes: 256 * 1024 * 1024,
            no_recover: false,
            max_objects: 500_000,
        }
    }
}

// Helper functions (stubs for now, will be implemented)

fn build_scan_context<'a>(
    bytes: &'a [u8],
    options: &ScanOptions,
) -> Result<sis_pdf_core::scan::ScanContext<'a>> {
    let scan_options = sis_pdf_core::scan::ScanOptions {
        recover_xref: !options.no_recover,
        deep: options.deep,
        max_decode_bytes: options.max_decode_bytes,
        max_total_decoded_bytes: options.max_total_decoded_bytes,
        strict: false,
        strict_summary: false,
        diff_parser: false,
        fast: false,
        focus_trigger: None,
        yara_scope: None,
        focus_depth: 5,
        ir: false,
        max_objects: options.max_objects,
        max_recursion_depth: 64,
        parallel: false,
        batch_parallel: false,
        ml_config: None,
        font_analysis: sis_pdf_core::scan::FontAnalysisOptions::default(),
    };

    // Parse PDF
    let graph = sis_pdf_pdf::parse_pdf(
        bytes,
        sis_pdf_pdf::ParseOptions {
            recover_xref: scan_options.recover_xref,
            deep: scan_options.deep,
            strict: scan_options.strict,
            max_objstm_bytes: scan_options.max_decode_bytes,
            max_objects: scan_options.max_objects,
            max_objstm_total_bytes: scan_options.max_total_decoded_bytes,
            carve_stream_objects: false,
            max_carved_objects: 0,
            max_carved_bytes: 0,
        },
    )?;

    Ok(sis_pdf_core::scan::ScanContext::new(
        bytes,
        graph,
        scan_options,
    ))
}

fn count_pages(ctx: &ScanContext) -> Result<usize> {
    // Fallback: count Page objects
    let mut page_count = 0;
    for obj in &ctx.graph.objects {
        if let sis_pdf_pdf::object::PdfAtom::Dict(dict) = &obj.atom {
            for (key, value) in &dict.entries {
                let key_bytes = &key.decoded;
                if key_bytes.as_slice() == b"/Type" || key_bytes.as_slice() == b"Type" {
                    if let sis_pdf_pdf::object::PdfAtom::Name(name) = &value.atom {
                        let name_bytes = &name.decoded;
                        if name_bytes.as_slice() == b"/Page" || name_bytes.as_slice() == b"Page" {
                            page_count += 1;
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(page_count)
}

fn get_metadata_field(ctx: &ScanContext, field: &str) -> Result<String> {
    // Look for /Info dictionary in the trailer
    if let Some(trailer) = ctx.graph.trailers.first() {
        // Find /Info entry
        for (key, value) in &trailer.entries {
            let key_bytes = &key.decoded;
            if key_bytes.as_slice() == b"/Info" || key_bytes.as_slice() == b"Info" {
                // Resolve the reference
                if let sis_pdf_pdf::object::PdfAtom::Ref { obj, gen } = &value.atom {
                    if let Some(info_obj) = ctx.graph.get_object(*obj, *gen) {
                        if let sis_pdf_pdf::object::PdfAtom::Dict(dict) = &info_obj.atom {
                            let field_bytes = format!("/{}", field).into_bytes();
                            let field_bytes_alt = field.as_bytes().to_vec();

                            for (k, v) in &dict.entries {
                                let k_bytes = &k.decoded;
                                if k_bytes.as_slice() == field_bytes.as_slice() || k_bytes.as_slice() == field_bytes_alt.as_slice() {
                                    if let sis_pdf_pdf::object::PdfAtom::Str(s) = &v.atom {
                                        let decoded = match s {
                                            sis_pdf_pdf::object::PdfStr::Literal { decoded, .. } => decoded,
                                            sis_pdf_pdf::object::PdfStr::Hex { decoded, .. } => decoded,
                                        };
                                        return Ok(decode_pdf_text_string(decoded));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(String::new())
}

/// Decode a PDF text string, handling UTF-16BE with BOM or PDFDocEncoding
fn decode_pdf_text_string(bytes: &[u8]) -> String {
    // Check for UTF-16BE BOM (0xFE 0xFF)
    if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        // UTF-16BE encoding
        let utf16_bytes = &bytes[2..];
        if utf16_bytes.len() % 2 != 0 {
            // Invalid UTF-16 (odd number of bytes after BOM)
            return String::from_utf8_lossy(bytes).to_string();
        }

        // Convert byte pairs to u16 values (big-endian)
        let utf16_chars: Vec<u16> = utf16_bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect();

        // Decode UTF-16 to String
        String::from_utf16(&utf16_chars).unwrap_or_else(|_| String::from_utf8_lossy(bytes).to_string())
    } else {
        // PDFDocEncoding or plain ASCII/Latin-1
        String::from_utf8_lossy(bytes).to_string()
    }
}

fn get_pdf_version(bytes: &[u8]) -> Result<String> {
    // Look for %PDF-X.Y header
    if bytes.len() < 8 {
        return Ok("unknown".to_string());
    }

    if &bytes[0..5] == b"%PDF-" {
        if let Ok(header) = std::str::from_utf8(&bytes[0..8]) {
            return Ok(header[5..].to_string());
        }
    }

    Ok("unknown".to_string())
}

fn is_encrypted(ctx: &ScanContext) -> Result<bool> {
    // Look for /Encrypt entry in trailer
    if let Some(trailer) = ctx.graph.trailers.first() {
        for (key, _value) in &trailer.entries {
            let key_bytes = &key.decoded;
            if key_bytes.as_slice() == b"/Encrypt" || key_bytes.as_slice() == b"Encrypt" {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn run_detectors(ctx: &ScanContext) -> Result<Vec<sis_pdf_core::model::Finding>> {
    let detectors = sis_pdf_detectors::default_detectors();
    let mut findings = Vec::new();

    for detector in detectors {
        match detector.run(ctx) {
            Ok(mut det_findings) => findings.append(&mut det_findings),
            Err(e) => {
                // Log error but continue with other detectors
                eprintln!("Detector {} failed: {}", detector.id(), e);
            }
        }
    }

    Ok(findings)
}

/// Format query result as human-readable text
pub fn format_result(result: &QueryResult, compact: bool) -> String {
    match result {
        QueryResult::Scalar(ScalarValue::String(s)) => s.clone(),
        QueryResult::Scalar(ScalarValue::Number(n)) => n.to_string(),
        QueryResult::Scalar(ScalarValue::Boolean(b)) => {
            if compact {
                if *b { "true" } else { "false" }.to_string()
            } else {
                if *b { "yes" } else { "no" }.to_string()
            }
        }
        QueryResult::List(items) => {
            if compact {
                items.len().to_string()
            } else {
                items.join("\n")
            }
        }
        QueryResult::Structure(v) => {
            serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".to_string())
        }
    }
}

/// Format query result as JSON
pub fn format_json(query: &str, file: &str, result: &QueryResult) -> Result<String> {
    let output = serde_json::json!({
        "query": query,
        "file": file,
        "result": result,
    });

    Ok(serde_json::to_string_pretty(&output)?)
}

/// Extract JavaScript code from PDF
fn extract_javascript(ctx: &ScanContext) -> Result<Vec<String>> {
    use sis_pdf_pdf::object::{PdfAtom, PdfStr};

    let mut js_code = Vec::new();

    for entry in &ctx.graph.objects {
        // Check for /JS entry in dictionary or stream
        if let Some(dict) = entry_dict(entry) {
            if let Some((_, obj)) = dict.get_first(b"/JS") {
                if let Some(code) = extract_obj_text(&ctx.graph, ctx.bytes, obj) {
                    js_code.push(format!("Object {}_{}: {}", entry.obj, entry.gen, preview_text(&code, 200)));
                }
            }
        }
    }

    Ok(js_code)
}

/// Extract URLs from PDF
fn extract_urls(ctx: &ScanContext) -> Result<Vec<String>> {
    use sis_pdf_pdf::object::PdfAtom;

    let mut urls = Vec::new();

    for entry in &ctx.graph.objects {
        if let Some(dict) = entry_dict(entry) {
            // Check for /URI entry (Action dictionaries)
            if let Some((_, obj)) = dict.get_first(b"/URI") {
                if let Some(uri) = extract_obj_text(&ctx.graph, ctx.bytes, obj) {
                    urls.push(uri);
                }
            }

            // Check for /URL entry (some PDFs use this)
            if let Some((_, obj)) = dict.get_first(b"/URL") {
                if let Some(url) = extract_obj_text(&ctx.graph, ctx.bytes, obj) {
                    urls.push(url);
                }
            }
        }
    }

    // Deduplicate
    urls.sort();
    urls.dedup();

    Ok(urls)
}

/// Extract embedded files information from PDF
fn extract_embedded_files(ctx: &ScanContext) -> Result<Vec<String>> {
    use sis_pdf_pdf::object::PdfAtom;

    let mut embedded = Vec::new();

    for entry in &ctx.graph.objects {
        if let PdfAtom::Stream(st) = &entry.atom {
            if st.dict.has_name(b"/Type", b"/EmbeddedFile") {
                let name = embedded_filename(&st.dict)
                    .unwrap_or_else(|| format!("embedded_{}_{}.bin", entry.obj, entry.gen));

                // Get file size if possible
                let size = st.dict.get_first(b"/Length")
                    .and_then(|(_, obj)| {
                        if let PdfAtom::Int(n) = &obj.atom {
                            Some(*n as usize)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);

                embedded.push(format!("{} ({}_{}, {} bytes)", name, entry.obj, entry.gen, size));
            }
        }
    }

    Ok(embedded)
}

// Helper functions

fn entry_dict<'a>(
    entry: &'a sis_pdf_pdf::graph::ObjEntry<'a>,
) -> Option<&'a sis_pdf_pdf::object::PdfDict<'a>> {
    use sis_pdf_pdf::object::PdfAtom;
    match &entry.atom {
        PdfAtom::Dict(d) => Some(d),
        PdfAtom::Stream(st) => Some(&st.dict),
        _ => None,
    }
}

fn extract_obj_text(
    graph: &sis_pdf_pdf::ObjectGraph<'_>,
    bytes: &[u8],
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
) -> Option<String> {
    use sis_pdf_pdf::object::PdfAtom;

    match &obj.atom {
        PdfAtom::Str(s) => {
            let text_bytes = string_bytes(s);
            Some(decode_pdf_text_string(&text_bytes))
        }
        PdfAtom::Stream(st) => {
            sis_pdf_pdf::decode::decode_stream(bytes, st, 32 * 1024 * 1024)
                .ok()
                .map(|d| String::from_utf8_lossy(&d.data).to_string())
        }
        PdfAtom::Ref { .. } => {
            let entry = graph.resolve_ref(obj)?;
            match &entry.atom {
                PdfAtom::Str(s) => {
                    let text_bytes = string_bytes(s);
                    Some(decode_pdf_text_string(&text_bytes))
                }
                PdfAtom::Stream(st) => {
                    sis_pdf_pdf::decode::decode_stream(bytes, st, 32 * 1024 * 1024)
                        .ok()
                        .map(|d| String::from_utf8_lossy(&d.data).to_string())
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn string_bytes(s: &sis_pdf_pdf::object::PdfStr<'_>) -> Vec<u8> {
    use sis_pdf_pdf::object::PdfStr;
    match s {
        PdfStr::Literal { decoded, .. } => decoded.clone(),
        PdfStr::Hex { decoded, .. } => decoded.clone(),
    }
}

fn embedded_filename(dict: &sis_pdf_pdf::object::PdfDict<'_>) -> Option<String> {
    use sis_pdf_pdf::object::PdfAtom;

    // Try /F (file name)
    if let Some((_, obj)) = dict.get_first(b"/F") {
        if let PdfAtom::Str(s) = &obj.atom {
            let text_bytes = string_bytes(s);
            return Some(decode_pdf_text_string(&text_bytes));
        }
    }

    // Try /UF (unicode file name)
    if let Some((_, obj)) = dict.get_first(b"/UF") {
        if let PdfAtom::Str(s) = &obj.atom {
            let text_bytes = string_bytes(s);
            return Some(decode_pdf_text_string(&text_bytes));
        }
    }

    None
}

fn preview_text(text: &str, max_len: usize) -> String {
    let trimmed = text.trim();
    if trimmed.len() <= max_len {
        trimmed.to_string()
    } else {
        format!("{}...", &trimmed[..max_len])
    }
}
