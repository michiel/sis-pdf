use anyhow::{anyhow, Result};
use serde::Serialize;
use serde_json::{self, json};
use std::fs;
use std::path::Path;

use sis_pdf_core::model::Severity;
use sis_pdf_core::scan::ScanContext;

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

    // Event trigger queries
    Events,
    EventsCount,
    EventsDocument,
    EventsPage,
    EventsField,

    // Object queries
    ShowObject(u32, u16),
    ObjectsList,
    ObjectsWithType(String),

    // Advanced queries
    Chains,
    ChainsJs,
    Cycles,
    CyclesPage,
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
        "objects.list" => Ok(Query::ObjectsList),
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

        // Events
        "events" => Ok(Query::Events),
        "events.count" => Ok(Query::EventsCount),
        "events.document" => Ok(Query::EventsDocument),
        "events.page" => Ok(Query::EventsPage),
        "events.field" => Ok(Query::EventsField),

        // Advanced
        "chains" => Ok(Query::Chains),
        "chains.js" => Ok(Query::ChainsJs),
        "cycles" => Ok(Query::Cycles),
        "cycles.page" => Ok(Query::CyclesPage),

        _ => {
            // Try to parse object queries
            if let Some(rest) = input.strip_prefix("object ").or(input.strip_prefix("obj ")) {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() == 1 {
                    let obj = parts[0]
                        .parse::<u32>()
                        .map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    return Ok(Query::ShowObject(obj, 0));
                } else if parts.len() == 2 {
                    let obj = parts[0]
                        .parse::<u32>()
                        .map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    let gen = parts[1]
                        .parse::<u16>()
                        .map_err(|_| anyhow!("Invalid generation number: {}", parts[1]))?;
                    return Ok(Query::ShowObject(obj, gen));
                }
            }

            // Try to parse findings.kind query
            if let Some(kind) = input.strip_prefix("findings.kind ") {
                return Ok(Query::FindingsByKind(kind.to_string()));
            }

            // Try to parse objects.with query
            if let Some(obj_type) = input.strip_prefix("objects.with ") {
                return Ok(Query::ObjectsWithType(obj_type.to_string()));
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
pub fn execute_query_with_context(query: &Query, ctx: &ScanContext) -> Result<QueryResult> {
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
        Query::Filesize => Ok(QueryResult::Scalar(ScalarValue::Number(
            ctx.bytes.len() as i64
        ))),
        Query::FindingsCount => {
            let findings = run_detectors(ctx)?;
            Ok(QueryResult::Scalar(ScalarValue::Number(
                findings.len() as i64
            )))
        }
        Query::FindingsBySeverity(severity) => {
            let findings = run_detectors(ctx)?;
            let filtered: Vec<String> = findings
                .iter()
                .filter(|f| &f.severity == severity)
                .map(|f| format!("{} {:?} {} {:?} {}: {}", f.id, f.severity, impact_from_severity(&f.severity), f.confidence, f.kind, f.title))
                .collect();
            Ok(QueryResult::List(filtered))
        }
        Query::FindingsByKind(kind) => {
            let findings = run_detectors(ctx)?;
            let filtered: Vec<String> = findings
                .iter()
                .filter(|f| f.kind == *kind)
                .map(|f| format!("{} {:?} {} {:?} {}: {}", f.id, f.severity, impact_from_severity(&f.severity), f.confidence, f.kind, f.title))
                .collect();
            Ok(QueryResult::List(filtered))
        }
        Query::Findings => {
            let findings = run_detectors(ctx)?;
            let result: Vec<String> = findings
                .iter()
                .map(|f| format!("{} {:?} {} {:?} {}: {}", f.id, f.severity, impact_from_severity(&f.severity), f.confidence, f.kind, f.title))
                .collect();
            Ok(QueryResult::List(result))
        }
        Query::JavaScript => {
            let js_code = extract_javascript(ctx)?;
            Ok(QueryResult::List(js_code))
        }
        Query::JavaScriptCount => {
            let js_code = extract_javascript(ctx)?;
            Ok(QueryResult::Scalar(ScalarValue::Number(
                js_code.len() as i64
            )))
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
            Ok(QueryResult::Scalar(ScalarValue::Number(
                embedded.len() as i64
            )))
        }
        Query::Created => {
            let created = get_metadata_field(ctx, "CreationDate")?;
            Ok(QueryResult::Scalar(ScalarValue::String(created)))
        }
        Query::Modified => {
            let modified = get_metadata_field(ctx, "ModDate")?;
            Ok(QueryResult::Scalar(ScalarValue::String(modified)))
        }
        Query::ShowObject(obj, gen) => {
            let obj_str = show_object(ctx, *obj, *gen)?;
            Ok(QueryResult::Scalar(ScalarValue::String(obj_str)))
        }
        Query::ObjectsList => {
            let objects = list_objects(ctx)?;
            Ok(QueryResult::List(objects))
        }
        Query::ObjectsWithType(obj_type) => {
            let objects = list_objects_with_type(ctx, obj_type)?;
            Ok(QueryResult::List(objects))
        }
        Query::Trailer => {
            let trailer_str = show_trailer(ctx)?;
            Ok(QueryResult::Scalar(ScalarValue::String(trailer_str)))
        }
        Query::Catalog => {
            let catalog_str = show_catalog(ctx)?;
            Ok(QueryResult::Scalar(ScalarValue::String(catalog_str)))
        }
        Query::Chains => {
            let chains = list_action_chains(ctx)?;
            Ok(QueryResult::Structure(chains))
        }
        Query::ChainsJs => {
            let chains = list_js_chains(ctx)?;
            Ok(QueryResult::Structure(chains))
        }
        Query::Cycles => {
            let cycles = list_cycles(ctx)?;
            Ok(QueryResult::Structure(cycles))
        }
        Query::CyclesPage => {
            let cycles = list_page_cycles(ctx)?;
            Ok(QueryResult::Structure(cycles))
        }
        Query::Events => {
            let events = extract_event_triggers(ctx, None)?;
            Ok(QueryResult::Structure(events))
        }
        Query::EventsCount => {
            let events_json = extract_event_triggers(ctx, None)?;
            let count = events_json.as_array().map(|arr| arr.len()).unwrap_or(0);
            Ok(QueryResult::Scalar(ScalarValue::Number(count as i64)))
        }
        Query::EventsDocument => {
            let events = extract_event_triggers(ctx, Some("document"))?;
            Ok(QueryResult::Structure(events))
        }
        Query::EventsPage => {
            let events = extract_event_triggers(ctx, Some("page"))?;
            Ok(QueryResult::Structure(events))
        }
        Query::EventsField => {
            let events = extract_event_triggers(ctx, Some("field"))?;
            Ok(QueryResult::Structure(events))
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
                                if k_bytes.as_slice() == field_bytes.as_slice()
                                    || k_bytes.as_slice() == field_bytes_alt.as_slice()
                                {
                                    if let sis_pdf_pdf::object::PdfAtom::Str(s) = &v.atom {
                                        let decoded = match s {
                                            sis_pdf_pdf::object::PdfStr::Literal {
                                                decoded,
                                                ..
                                            } => decoded,
                                            sis_pdf_pdf::object::PdfStr::Hex {
                                                decoded, ..
                                            } => decoded,
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
        String::from_utf16(&utf16_chars)
            .unwrap_or_else(|_| String::from_utf8_lossy(bytes).to_string())
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

fn impact_from_severity(severity: &Severity) -> &'static str {
    match severity {
        Severity::Info => "None",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
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
    let mut js_code = Vec::new();

    for entry in &ctx.graph.objects {
        // Check for /JS entry in dictionary or stream
        if let Some(dict) = entry_dict(entry) {
            if let Some((_, obj)) = dict.get_first(b"/JS") {
                if let Some(code) = extract_obj_text(&ctx.graph, ctx.bytes, obj) {
                    js_code.push(format!(
                        "Object {}_{}: {}",
                        entry.obj,
                        entry.gen,
                        preview_text(&code, 200)
                    ));
                }
            }
        }
    }

    Ok(js_code)
}

/// Extract URLs from PDF
fn extract_urls(ctx: &ScanContext) -> Result<Vec<String>> {
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
                let size = st
                    .dict
                    .get_first(b"/Length")
                    .and_then(|(_, obj)| {
                        if let PdfAtom::Int(n) = &obj.atom {
                            Some(*n as usize)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);

                embedded.push(format!(
                    "{} ({}_{}, {} bytes)",
                    name, entry.obj, entry.gen, size
                ));
            }
        }
    }

    Ok(embedded)
}

/// Extract event triggers from PDF
fn extract_event_triggers(ctx: &ScanContext, filter_level: Option<&str>) -> Result<serde_json::Value> {
    use sis_pdf_pdf::object::PdfAtom;

    let mut events = Vec::new();

    // 1. Document-level events (from Catalog and document actions)
    // Find catalog from trailer /Root entry
    if let Some(trailer) = ctx.graph.trailers.first() {
        for (key, value) in &trailer.entries {
            let key_bytes = &key.decoded;
            if key_bytes == b"/Root" {
                if let PdfAtom::Ref { obj, gen } = &value.atom {
                    if let Some(catalog_entry) = ctx.graph.get_object(*obj, *gen) {
                        if let Some(dict) = entry_dict(catalog_entry) {
                            // OpenAction (automatic execution on document open)
                            if let Some((_, action_obj)) = dict.get_first(b"/OpenAction") {
                                if filter_level.is_none() || filter_level == Some("document") {
                                    let action_details = extract_action_details(&ctx.graph, ctx.bytes, action_obj);
                                    events.push(json!({
                                        "level": "document",
                                        "event_type": "OpenAction",
                                        "location": format!("obj {}:{} (Catalog)", obj, gen),
                                        "trigger_config": "Triggered on document open",
                                        "action_details": action_details
                                    }));
                                }
                            }

                            // Additional actions (AA dictionary)
                            if let Some((_, aa_obj)) = dict.get_first(b"/AA") {
                                if filter_level.is_none() || filter_level == Some("document") {
                                    extract_aa_events(&ctx.graph, ctx.bytes, aa_obj, "document", &format!("obj {}:{} (Catalog)", obj, gen), &mut events);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Page-level events
    for entry in &ctx.graph.objects {
        if let Some(dict) = entry_dict(entry) {
            // Check if this is a Page object
            if dict.has_name(b"/Type", b"/Page") {
                if filter_level.is_none() || filter_level == Some("page") {
                    // Check for Page AA (Additional Actions)
                    if let Some((_, aa_obj)) = dict.get_first(b"/AA") {
                        extract_aa_events(&ctx.graph, ctx.bytes, aa_obj, "page", &format!("obj {}:{}", entry.obj, entry.gen), &mut events);
                    }
                }
            }
        }
    }

    // 3. Field-level events (form fields / annotations)
    for entry in &ctx.graph.objects {
        if let Some(dict) = entry_dict(entry) {
            // Check for widget annotations (form fields)
            if dict.has_name(b"/Subtype", b"/Widget") || dict.get_first(b"/FT").is_some() {
                if filter_level.is_none() || filter_level == Some("field") {
                    let field_name = dict.get_first(b"/T")
                        .and_then(|(_, obj)| extract_obj_text(&ctx.graph, ctx.bytes, obj))
                        .unwrap_or_else(|| "unnamed".to_string());

                    // Check for field actions
                    if let Some((_, action_obj)) = dict.get_first(b"/A") {
                        let action_details = extract_action_details(&ctx.graph, ctx.bytes, action_obj);
                        events.push(json!({
                            "level": "field",
                            "event_type": "Action",
                            "location": format!("obj {}:{} (field: {})", entry.obj, entry.gen, field_name),
                            "trigger_config": "Triggered on field activation",
                            "action_details": action_details
                        }));
                    }

                    // Check for Additional Actions (AA)
                    if let Some((_, aa_obj)) = dict.get_first(b"/AA") {
                        extract_aa_events(&ctx.graph, ctx.bytes, aa_obj, "field", &format!("obj {}:{} (field: {})", entry.obj, entry.gen, field_name), &mut events);
                    }
                }
            }
        }
    }

    Ok(json!(events))
}

/// Extract additional actions from an AA dictionary
fn extract_aa_events(
    graph: &sis_pdf_pdf::ObjectGraph<'_>,
    bytes: &[u8],
    aa_obj: &sis_pdf_pdf::object::PdfObj<'_>,
    level: &str,
    location: &str,
    events: &mut Vec<serde_json::Value>,
) {
    use sis_pdf_pdf::object::PdfAtom;

    if let PdfAtom::Dict(ref aa_dict) = aa_obj.atom {
        let event_types = vec![
            (b"/O" as &[u8], if level == "page" { "Page/Open" } else { "OnFocus" }),
            (b"/C", if level == "page" { "Page/Close" } else { "OnBlur" }),
            (b"/WC", "Doc/WillClose"),
            (b"/WS", "Doc/WillSave"),
            (b"/DS", "Doc/DidSave"),
            (b"/WP", "Doc/WillPrint"),
            (b"/DP", "Doc/DidPrint"),
            (b"/K", "Keystroke"),
            (b"/F", "Format"),
            (b"/V", "Validate"),
            (b"/C", "Calculate"),
            (b"/D", "MouseDown"),
            (b"/U", "MouseUp"),
            (b"/E", "MouseEnter"),
            (b"/X", "MouseExit"),
            (b"/Fo", "OnFocus"),
            (b"/Bl", "OnBlur"),
        ];

        for (key, event_name) in event_types {
            if let Some((_, action_obj)) = aa_dict.get_first(key) {
                let action_details = extract_action_details(graph, bytes, action_obj);
                let trigger_desc = match event_name {
                    "Page/Open" => "Triggered when page is opened/viewed",
                    "Page/Close" => "Triggered when page is closed",
                    "Doc/WillClose" => "Triggered before document close",
                    "Doc/WillSave" => "Triggered before document save",
                    "Doc/DidSave" => "Triggered after document save",
                    "Doc/WillPrint" => "Triggered before printing",
                    "Doc/DidPrint" => "Triggered after printing",
                    "Keystroke" => "Triggered on each keystroke in field",
                    "Format" => "Triggered when field is formatted",
                    "Validate" => "Triggered on field validation",
                    "Calculate" => "Triggered when field value is calculated",
                    "MouseDown" => "Triggered on mouse button press",
                    "MouseUp" => "Triggered on mouse button release",
                    "MouseEnter" => "Triggered when mouse enters field",
                    "MouseExit" => "Triggered when mouse exits field",
                    "OnFocus" => "Triggered when field receives focus",
                    "OnBlur" => "Triggered when field loses focus",
                    _ => "Triggered by event",
                };

                events.push(json!({
                    "level": level,
                    "event_type": event_name,
                    "location": location,
                    "trigger_config": trigger_desc,
                    "action_details": action_details
                }));
            }
        }
    }
}

/// Extract action details from an action object
fn extract_action_details(
    graph: &sis_pdf_pdf::ObjectGraph<'_>,
    bytes: &[u8],
    action_obj: &sis_pdf_pdf::object::PdfObj<'_>,
) -> String {
    use sis_pdf_pdf::object::PdfAtom;

    if let Some(dict) = match &action_obj.atom {
        PdfAtom::Dict(d) => Some(d),
        PdfAtom::Stream(st) => Some(&st.dict),
        _ => None,
    } {
        // Check action type
        if let Some((_, s_obj)) = dict.get_first(b"/S") {
            if let Some(action_type) = extract_obj_text(graph, bytes, s_obj) {
                match action_type.as_str() {
                    "/JavaScript" => {
                        if let Some((_, js_obj)) = dict.get_first(b"/JS") {
                            if let Some(js_code) = extract_obj_text(graph, bytes, js_obj) {
                                return format!("JavaScript: {}", preview_text(&js_code, 100));
                            }
                        }
                        return "JavaScript: <code unavailable>".to_string();
                    }
                    "/URI" => {
                        if let Some((_, uri_obj)) = dict.get_first(b"/URI") {
                            if let Some(uri) = extract_obj_text(graph, bytes, uri_obj) {
                                return format!("URI: {}", uri);
                            }
                        }
                        return "URI: <unavailable>".to_string();
                    }
                    "/SubmitForm" => {
                        if let Some((_, f_obj)) = dict.get_first(b"/F") {
                            if let Some(url) = extract_obj_text(graph, bytes, f_obj) {
                                return format!("Submit form to: {}", url);
                            }
                        }
                        return "Submit form".to_string();
                    }
                    "/Launch" => {
                        return "Launch external application".to_string();
                    }
                    "/GoTo" => {
                        return "Navigate to destination".to_string();
                    }
                    "/GoToR" => {
                        return "Navigate to remote destination".to_string();
                    }
                    "/Named" => {
                        if let Some((_, n_obj)) = dict.get_first(b"/N") {
                            if let Some(name) = extract_obj_text(graph, bytes, n_obj) {
                                return format!("Named action: {}", name);
                            }
                        }
                        return "Named action".to_string();
                    }
                    _ => return format!("Action type: {}", action_type),
                }
            }
        }
    }

    "Action details unavailable".to_string()
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
        PdfAtom::Stream(st) => sis_pdf_pdf::decode::decode_stream(bytes, st, 32 * 1024 * 1024)
            .ok()
            .map(|d| String::from_utf8_lossy(&d.data).to_string()),
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

/// Show a specific PDF object
fn show_object(ctx: &ScanContext, obj: u32, gen: u16) -> Result<String> {
    // Find the object in the graph
    if let Some(entry) = ctx.graph.get_object(obj, gen) {
        let mut output = String::new();
        output.push_str(&format!("Object {} {} obj\n", obj, gen));
        output.push_str(&format_pdf_atom(&entry.atom, 0));
        output.push_str("\nendobj");
        Ok(output)
    } else {
        Err(anyhow!("Object {} {} not found", obj, gen))
    }
}

/// Format a PDF atom for display
fn format_pdf_atom(atom: &sis_pdf_pdf::object::PdfAtom, indent: usize) -> String {
    use sis_pdf_pdf::object::PdfAtom;

    let indent_str = "  ".repeat(indent);

    match atom {
        PdfAtom::Null => format!("{}null", indent_str),
        PdfAtom::Bool(b) => format!("{}{}", indent_str, b),
        PdfAtom::Int(n) => format!("{}{}", indent_str, n),
        PdfAtom::Real(f) => format!("{}{}", indent_str, f),
        PdfAtom::Name(name) => {
            format!("{}/{}", indent_str, String::from_utf8_lossy(&name.decoded))
        }
        PdfAtom::Str(s) => {
            let bytes = match s {
                sis_pdf_pdf::object::PdfStr::Literal { decoded, .. } => decoded,
                sis_pdf_pdf::object::PdfStr::Hex { decoded, .. } => decoded,
            };
            format!("{}({})", indent_str, String::from_utf8_lossy(bytes))
        }
        PdfAtom::Array(arr) => {
            let mut output = format!("{}[\n", indent_str);
            for item in arr.iter() {
                output.push_str(&format_pdf_atom(&item.atom, indent + 1));
                output.push('\n');
            }
            output.push_str(&format!("{}]", indent_str));
            output
        }
        PdfAtom::Dict(dict) => {
            let mut output = format!("{}<<\n", indent_str);
            for (key, value) in &dict.entries {
                let key_str = String::from_utf8_lossy(&key.decoded);
                output.push_str(&format!("{}  {}", indent_str, key_str));
                output.push_str(" ");
                output.push_str(&format_pdf_atom(&value.atom, 0).trim());
                output.push('\n');
            }
            output.push_str(&format!("{}", indent_str));
            output.push_str(">>");
            output
        }
        PdfAtom::Stream(stream) => {
            let mut output = format_pdf_atom(&PdfAtom::Dict(stream.dict.clone()), indent);
            output.push_str("\nstream\n");
            output.push_str("<stream data>");
            output.push_str("\nendstream");
            output
        }
        PdfAtom::Ref { obj, gen } => format!("{}{} {} R", indent_str, obj, gen),
    }
}

/// List all object IDs
fn list_objects(ctx: &ScanContext) -> Result<Vec<String>> {
    let objects: Vec<String> = ctx
        .graph
        .objects
        .iter()
        .map(|entry| format!("{} {}", entry.obj, entry.gen))
        .collect();
    Ok(objects)
}

/// List objects with a specific type
fn list_objects_with_type(ctx: &ScanContext, obj_type: &str) -> Result<Vec<String>> {
    use sis_pdf_pdf::object::PdfAtom;

    let mut objects = Vec::new();
    let search_type = if obj_type.starts_with('/') {
        obj_type.to_string()
    } else {
        format!("/{}", obj_type)
    };

    for entry in &ctx.graph.objects {
        if let Some(dict) = entry_dict(entry) {
            // Look for /Type entry
            if let Some((_, type_obj)) = dict.get_first(b"/Type") {
                if let PdfAtom::Name(name) = &type_obj.atom {
                    let type_name = String::from_utf8_lossy(&name.decoded);
                    if type_name == search_type || type_name == &search_type[1..] {
                        objects.push(format!("{} {} ({})", entry.obj, entry.gen, type_name));
                    }
                }
            }
        }
    }

    Ok(objects)
}

/// Show the PDF trailer
fn show_trailer(ctx: &ScanContext) -> Result<String> {
    if let Some(trailer) = ctx.graph.trailers.first() {
        let mut output = String::from("<<\n");
        for (key, value) in &trailer.entries {
            let key_str = String::from_utf8_lossy(&key.decoded);
            output.push_str(&format!("  {} ", key_str));
            output.push_str(&format_pdf_atom(&value.atom, 0).trim());
            output.push('\n');
        }
        output.push_str(">>");
        Ok(output)
    } else {
        Err(anyhow!("No trailer found"))
    }
}

/// Show the PDF catalog
fn show_catalog(ctx: &ScanContext) -> Result<String> {
    use sis_pdf_pdf::object::PdfAtom;

    // Find catalog from trailer /Root entry
    if let Some(trailer) = ctx.graph.trailers.first() {
        for (key, value) in &trailer.entries {
            let key_bytes = &key.decoded;
            if key_bytes.as_slice() == b"/Root" || key_bytes.as_slice() == b"Root" {
                if let PdfAtom::Ref { obj, gen } = &value.atom {
                    if let Some(catalog_entry) = ctx.graph.get_object(*obj, *gen) {
                        let mut output = format!("Catalog (Object {} {})\n", obj, gen);
                        output.push_str(&format_pdf_atom(&catalog_entry.atom, 0));
                        return Ok(output);
                    }
                }
            }
        }
    }

    Err(anyhow!("Catalog not found"))
}

/// List all action chains
fn list_action_chains(ctx: &ScanContext) -> Result<serde_json::Value> {
    let classifications = ctx.classifications();
    let typed_graph = sis_pdf_pdf::typed_graph::TypedGraph::build(&ctx.graph, classifications);
    let path_finder = sis_pdf_pdf::path_finder::PathFinder::new(&typed_graph);

    let chains = path_finder.find_all_action_chains();
    Ok(build_chain_query_result(
        "chains",
        chains.iter().enumerate(),
    ))
}

/// List JavaScript-containing action chains
fn list_js_chains(ctx: &ScanContext) -> Result<serde_json::Value> {
    let classifications = ctx.classifications();
    let typed_graph = sis_pdf_pdf::typed_graph::TypedGraph::build(&ctx.graph, classifications);
    let path_finder = sis_pdf_pdf::path_finder::PathFinder::new(&typed_graph);

    let chains = path_finder.find_all_action_chains();
    let js_chains = chains
        .iter()
        .enumerate()
        .filter(|(_, chain)| chain.involves_js);

    Ok(build_chain_query_result("chains.js", js_chains))
}

/// List all reference cycles
fn list_cycles(ctx: &ScanContext) -> Result<serde_json::Value> {
    use std::collections::HashSet;

    let mut cycles = Vec::new();
    let mut visited = HashSet::new();
    let mut path = Vec::new();
    let mut path_set = HashSet::new();

    for entry in &ctx.graph.objects {
        if !visited.contains(&(entry.obj, entry.gen)) {
            find_cycles_dfs(
                &ctx.graph,
                entry.obj,
                entry.gen,
                &mut visited,
                &mut path,
                &mut path_set,
                &mut cycles,
            );
        }
    }

    Ok(build_cycles_result("cycles", &cycles))
}

/// List page tree cycles (only /Kids and /Parent edges)
fn list_page_cycles(ctx: &ScanContext) -> Result<serde_json::Value> {
    use sis_pdf_pdf::object::PdfAtom;
    use sis_pdf_pdf::typed_graph::TypedGraph;
    use std::collections::HashSet;

    let classifications = ctx.classifications();
    let typed_graph = TypedGraph::build(&ctx.graph, classifications);

    let page_nodes: Vec<(u32, u16)> = ctx
        .graph
        .objects
        .iter()
        .filter_map(|entry| {
            if let Some(dict) = entry_dict(entry) {
                if let Some((_, type_obj)) = dict.get_first(b"/Type") {
                    if let PdfAtom::Name(name) = &type_obj.atom {
                        let type_name = String::from_utf8_lossy(&name.decoded);
                        if type_name == "/Page"
                            || type_name == "Page"
                            || type_name == "/Pages"
                            || type_name == "Pages"
                        {
                            return Some((entry.obj, entry.gen));
                        }
                    }
                }
            }
            None
        })
        .collect();

    let mut cycles = Vec::new();
    let mut seen = HashSet::new();
    let mut path = Vec::new();
    let mut path_set = HashSet::new();

    for node in page_nodes {
        dfs_page_cycles(
            node,
            &typed_graph,
            &mut path,
            &mut path_set,
            &mut cycles,
            &mut seen,
        );
        path.clear();
        path_set.clear();
    }

    Ok(build_cycles_result("cycles.page", &cycles))
}

fn dfs_page_cycles(
    current: (u32, u16),
    graph: &sis_pdf_pdf::typed_graph::TypedGraph<'_>,
    path: &mut Vec<(u32, u16)>,
    path_set: &mut std::collections::HashSet<(u32, u16)>,
    cycles: &mut Vec<Vec<(u32, u16)>>,
    seen_cycles: &mut std::collections::HashSet<String>,
) {
    use sis_pdf_pdf::typed_graph::EdgeType;

    path.push(current);
    path_set.insert(current);

    for edge in graph.outgoing_edges(current.0, current.1) {
        if !matches!(edge.edge_type, EdgeType::PagesKids | EdgeType::PageParent) {
            continue;
        }

        let next = edge.dst;
        if let Some(pos) = path.iter().position(|&node| node == next) {
            record_page_cycle(cycles, seen_cycles, path[pos..].to_vec());
        } else {
            dfs_page_cycles(next, graph, path, path_set, cycles, seen_cycles);
        }
    }

    path_set.remove(&current);
    path.pop();
}

fn record_page_cycle(
    cycles: &mut Vec<Vec<(u32, u16)>>,
    seen_cycles: &mut std::collections::HashSet<String>,
    cycle: Vec<(u32, u16)>,
) {
    if cycle.is_empty() {
        return;
    }

    let normalized = normalize_cycle(&cycle);
    let key = cycle_key(&normalized);
    if seen_cycles.insert(key) {
        cycles.push(normalized);
    }
}

fn normalize_cycle(cycle: &[(u32, u16)]) -> Vec<(u32, u16)> {
    if cycle.is_empty() {
        return Vec::new();
    }

    fn rotation(cycle: &[(u32, u16)], start: usize) -> Vec<(u32, u16)> {
        let mut rotated = Vec::with_capacity(cycle.len());
        rotated.extend_from_slice(&cycle[start..]);
        rotated.extend_from_slice(&cycle[..start]);
        rotated
    }

    let mut best = rotation(cycle, 0);
    for start in 1..cycle.len() {
        let candidate = rotation(cycle, start);
        if candidate < best {
            best = candidate;
        }
    }

    let reversed_cycle: Vec<_> = cycle.iter().rev().copied().collect();
    for start in 0..reversed_cycle.len() {
        let candidate = rotation(&reversed_cycle, start);
        if candidate < best {
            best = candidate;
        }
    }

    best
}

fn cycle_key(cycle: &[(u32, u16)]) -> String {
    cycle
        .iter()
        .map(|(obj, gen)| format!("{obj}:{gen}"))
        .collect::<Vec<_>>()
        .join("->")
}

/// Helper function for DFS cycle detection
fn find_cycles_dfs(
    graph: &sis_pdf_pdf::ObjectGraph,
    obj: u32,
    gen: u16,
    visited: &mut std::collections::HashSet<(u32, u16)>,
    path: &mut Vec<(u32, u16)>,
    path_set: &mut std::collections::HashSet<(u32, u16)>,
    cycles: &mut Vec<Vec<(u32, u16)>>,
) {
    let current = (obj, gen);

    if path_set.contains(&current) {
        // Found a cycle - extract it
        if let Some(cycle_start) = path.iter().position(|&x| x == current) {
            let cycle = path[cycle_start..].to_vec();
            cycles.push(cycle);
        }
        return;
    }

    if visited.contains(&current) {
        return;
    }

    visited.insert(current);
    path.push(current);
    path_set.insert(current);

    // Find references in this object
    if let Some(entry) = graph.get_object(obj, gen) {
        collect_refs(&entry.atom, graph, visited, path, path_set, cycles);
    }

    path.pop();
    path_set.remove(&current);
}

/// Collect references from a PDF atom
fn collect_refs(
    atom: &sis_pdf_pdf::object::PdfAtom,
    graph: &sis_pdf_pdf::ObjectGraph,
    visited: &mut std::collections::HashSet<(u32, u16)>,
    path: &mut Vec<(u32, u16)>,
    path_set: &mut std::collections::HashSet<(u32, u16)>,
    cycles: &mut Vec<Vec<(u32, u16)>>,
) {
    use sis_pdf_pdf::object::PdfAtom;

    match atom {
        PdfAtom::Ref { obj, gen } => {
            find_cycles_dfs(graph, *obj, *gen, visited, path, path_set, cycles);
        }
        PdfAtom::Array(arr) => {
            for item in arr.iter() {
                collect_refs(&item.atom, graph, visited, path, path_set, cycles);
            }
        }
        PdfAtom::Dict(dict) => {
            for (_, value) in &dict.entries {
                collect_refs(&value.atom, graph, visited, path, path_set, cycles);
            }
        }
        PdfAtom::Stream(stream) => {
            for (_, value) in &stream.dict.entries {
                collect_refs(&value.atom, graph, visited, path, path_set, cycles);
            }
        }
        _ => {}
    }
}

fn build_chain_query_result<'a, I>(label: &str, chains: I) -> serde_json::Value
where
    I: Iterator<Item = (usize, &'a sis_pdf_pdf::path_finder::ActionChain<'a>)>,
{
    let chain_values: Vec<_> = chains
        .map(|(idx, chain)| chain_to_json(idx, chain))
        .collect();

    json!({
        "type": label,
        "count": chain_values.len(),
        "chains": chain_values,
    })
}

fn chain_to_json(
    idx: usize,
    chain: &sis_pdf_pdf::path_finder::ActionChain<'_>,
) -> serde_json::Value {
    let edges: Vec<_> = chain.edges.iter().map(|edge| edge_to_json(*edge)).collect();
    let payload = chain.payload.map(|(obj, gen)| ref_to_json((obj, gen)));

    json!({
        "id": idx,
        "trigger": chain.trigger.as_str(),
        "length": chain.length(),
        "automatic": chain.automatic,
        "involves_js": chain.involves_js,
        "involves_external": chain.involves_external,
        "risk_score": chain.risk_score(),
        "payload": payload,
        "edges": edges,
    })
}

fn edge_to_json(edge: &sis_pdf_pdf::typed_graph::TypedEdge) -> serde_json::Value {
    json!({
        "src": ref_to_json(edge.src),
        "dst": ref_to_json(edge.dst),
        "type": edge.edge_type.as_str(),
        "suspicious": edge.suspicious,
        "weight": edge.weight,
    })
}

fn ref_to_json(obj: (u32, u16)) -> serde_json::Value {
    json!({
        "obj": obj.0,
        "gen": obj.1,
    })
}

fn build_cycles_result(label: &str, cycles: &[Vec<(u32, u16)>]) -> serde_json::Value {
    let cycle_values: Vec<_> = cycles
        .iter()
        .enumerate()
        .map(|(idx, cycle)| cycle_to_json(idx, cycle))
        .collect();

    json!({
        "type": label,
        "count": cycle_values.len(),
        "cycles": cycle_values,
    })
}

fn cycle_to_json(idx: usize, cycle: &[(u32, u16)]) -> serde_json::Value {
    let path: Vec<_> = cycle
        .iter()
        .map(|&(obj, gen)| ref_to_json((obj, gen)))
        .collect();
    json!({
        "id": idx,
        "length": cycle.len(),
        "path": path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sis_pdf_pdf::path_finder::TriggerType;
    use sis_pdf_pdf::typed_graph::{EdgeType, TypedEdge};

    fn with_fixture_context<F>(fixture: &str, test: F)
    where
        F: FnOnce(&ScanContext),
    {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root is two levels above crate manifest");
        let fixture_path = workspace_root
            .join("crates/sis-pdf-core/tests/fixtures")
            .join(fixture);
        let bytes = std::fs::read(&fixture_path).expect("fixture read");
        let options = ScanOptions::default();
        let ctx = build_scan_context(&bytes, &options).expect("build context");
        test(&ctx);
    }

    #[test]
    fn advanced_query_json_outputs_are_structured() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let chains = list_action_chains(ctx).expect("chains");
            assert_eq!(chains["type"], json!("chains"));
            assert!(chains["chains"].is_array());

            let js_chains = list_js_chains(ctx).expect("js chains");
            assert_eq!(js_chains["type"], json!("chains.js"));

            let cycles = list_cycles(ctx).expect("cycles");
            assert_eq!(cycles["type"], json!("cycles"));

            let page_cycles = list_page_cycles(ctx).expect("page cycles");
            assert_eq!(page_cycles["type"], json!("cycles.page"));
        });
    }

    #[test]
    fn chain_to_json_includes_payload_and_edges() {
        let edges = vec![
            TypedEdge::new((1, 0), (2, 0), EdgeType::OpenAction),
            TypedEdge::new((2, 0), (3, 0), EdgeType::JavaScriptPayload),
        ];

        let chain = sis_pdf_pdf::path_finder::ActionChain {
            trigger: TriggerType::OpenAction,
            edges: vec![&edges[0], &edges[1]],
            payload: Some((3, 0)),
            automatic: true,
            involves_js: true,
            involves_external: false,
        };

        let json_value = chain_to_json(5, &chain);
        assert_eq!(json_value["id"], json!(5));
        assert_eq!(json_value["trigger"], json!("open_action"));
        assert!(json_value["payload"].is_object());
        assert_eq!(json_value["payload"]["obj"], json!(3));

        let edge_array = json_value["edges"].as_array().unwrap();
        assert_eq!(edge_array.len(), 2);
        assert_eq!(edge_array[1]["type"], json!("javascript_payload"));
        assert_eq!(edge_array[1]["suspicious"], json!(true));
    }

    #[test]
    fn cycle_to_json_builds_path_details() {
        let cycle = vec![(1, 0), (2, 0), (3, 0), (1, 0)];
        let json_value = cycle_to_json(2, &cycle);
        assert_eq!(json_value["id"], json!(2));
        assert_eq!(json_value["length"], json!(4));

        let path = json_value["path"].as_array().unwrap();
        assert_eq!(path.len(), 4);
        assert_eq!(path[0]["obj"], json!(1));
    }
}
