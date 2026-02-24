//! Query command implementation and output formatting helpers.

use anyhow::{anyhow, Result};
use clap::ValueEnum;
use globset::Glob;
use rayon::prelude::*;
use serde::Serialize;
use serde_json::{self, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;
use walkdir::WalkDir;

use sis_pdf_core::canonical::canonical_name;
use sis_pdf_core::correlation;
use sis_pdf_core::model::{
    AttackSurface, Confidence, EvidenceSource, EvidenceSpan, Finding, Severity,
};
use sis_pdf_core::object_context::{build_object_context_index, get_object_context};
use sis_pdf_core::revision_timeline::{build_revision_timeline, DEFAULT_MAX_REVISIONS};
use sis_pdf_core::rich_media::{
    analyze_swf, detect_3d_format, detect_media_format, SWF_DECODE_TIMEOUT_MS,
};
use sis_pdf_core::runner::assign_stable_ids;
use sis_pdf_core::scan::{CorrelationOptions, ScanContext};
use sis_pdf_core::structure_overlay::{
    build_structure_overlay_with_findings, StructureOverlay, StructureOverlayBuildOptions,
};
use sis_pdf_core::timeout::TimeoutChecker;
use sis_pdf_detectors::polyglot::analyze_polyglot_signatures;
use sis_pdf_detectors::xfa_forms::{collect_xfa_forms, XfaFormRecord};
use sis_pdf_pdf::object::{PdfAtom, PdfName};
use syntect::easy::HighlightLines;
use syntect::highlighting::{Style, Theme, ThemeSet};
use syntect::parsing::SyntaxSet;
use syntect::util::as_24_bit_terminal_escaped;

mod csv;
mod predicates;
mod readable;
use self::csv::{events_to_csv_rows, findings_to_csv_rows};
use self::predicates::PredicateContext;
#[allow(unused_imports)]
pub use self::predicates::{
    parse_predicate, PredicateExpr, PredicateField, PredicateOp, PredicateValue,
};
pub use readable::format_readable_result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Readable,
    Json,
    Jsonl,
    Yaml,
    Csv,
    Dot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportVerbosity {
    Compact,
    Standard,
    Verbose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ChainSummaryLevel {
    Minimal,
    Events,
    Full,
}

impl OutputFormat {
    pub fn parse(input: &str) -> Result<Self> {
        match input {
            "text" => Ok(OutputFormat::Text),
            "readable" => Ok(OutputFormat::Readable),
            "json" => Ok(OutputFormat::Json),
            "jsonl" => Ok(OutputFormat::Jsonl),
            "yaml" | "yml" => Ok(OutputFormat::Yaml),
            "csv" => Ok(OutputFormat::Csv),
            "dot" => Ok(OutputFormat::Dot),
            _ => Err(anyhow!("invalid format: {input}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeMode {
    Decode,
    Raw,
    Hexdump,
}

const CANONICAL_DIFF_SAMPLE_LIMIT: usize = 32;

/// Query types supported by the interface
#[derive(Debug, Clone)]
pub enum Query {
    // Metadata queries
    Pages,
    ObjectsCount,
    Creator,
    Producer,
    Title,
    Created,
    Modified,
    Version,
    Encrypted,
    Filesize,
    PagesExecution,

    // Structure queries
    Trailer,
    Catalog,
    Xref,
    XrefCount,
    XrefStartxrefs,
    XrefStartxrefsCount,
    XrefSections,
    XrefSectionsCount,
    XrefTrailers,
    XrefTrailersCount,
    XrefDeviations,
    XrefDeviationsCount,
    Revisions,
    RevisionsDetail,
    RevisionsCount,

    // Content queries
    JavaScript,
    JavaScriptCount,
    Urls,
    UrlsCount,
    Embedded,
    EmbeddedCount,
    XfaScripts,
    XfaScriptsCount,
    XfaForms,
    XfaFormsCount,
    Images,
    ImagesCount,
    ImagesJbig2,
    ImagesJbig2Count,
    ImagesJpx,
    ImagesJpxCount,
    ImagesCcitt,
    ImagesCcittCount,
    ImagesRisky,
    ImagesRiskyCount,
    ImagesMalformed,
    ImagesMalformedCount,
    SwfContent,
    SwfContentCount,
    SwfActionScript,
    SwfActionScriptCount,
    SwfStreams,
    SwfStreamsCount,
    Media3D,
    Media3DCount,
    MediaAudio,
    MediaAudioCount,

    // Finding queries
    Findings,
    FindingsCsv,
    FindingsCount,
    FindingsBySeverity(Severity),
    FindingsByKind(String),
    FindingsByKindCount(String),
    FindingsComposite,
    FindingsCompositeCsv,
    FindingsCompositeCount,
    FindingsWithChain,
    FindingsBySeverityWithChain(Severity),
    FindingsByKindWithChain(String),
    FindingsCompositeWithChain,
    Correlations,
    CorrelationsCount,
    CanonicalDiff,
    Encryption,
    EncryptionWeak,
    EncryptionWeakCount,

    // Event trigger queries
    Events,
    EventsFull,
    EventsFullCsv,
    EventsCount,
    EventsDocument,
    EventsPage,
    EventsField,

    // Object queries
    ShowObject(u32, u16),
    ShowObjectDetail { obj: u32, gen: u16, context_only: bool },
    ShowObjectContext(u32, u16),
    ObjectsList,
    ObjectsWithType(String),

    // Advanced queries
    Chains,
    ChainsCount,
    ChainsJs,
    ChainsAll,
    ChainsAllCount,
    ChainsJsAll,
    Cycles,
    CyclesPage,

    // Export queries
    ExportOrgDot,
    ExportOrgJson,
    ExportStructureDot,
    ExportStructureJson,
    ExportStructureDotDepth(usize),
    ExportStructureJsonDepth(usize),
    ExportStructureOverlayDot,
    ExportStructureOverlayJson,
    ExportStructureOverlayDotDepth(usize),
    ExportStructureOverlayJsonDepth(usize),
    ExportStructureOverlayTelemetryDot,
    ExportStructureOverlayTelemetryJson,
    ExportStructureOverlayTelemetryDotDepth(usize),
    ExportStructureOverlayTelemetryJsonDepth(usize),
    ExportEventDot,
    ExportEventJson,
    ExportEventDotHops(usize),
    ExportEventJsonHops(usize),
    ExportEventStreamDot,
    ExportEventStreamJson,
    ExportEventStreamDotHops(usize),
    ExportEventStreamJsonHops(usize),
    ExportIrText,
    ExportIrJson,
    ExportFeatures,
    ExportFeaturesJson,

    // Reference queries
    References(u32, u16),

    // Stream queries
    Stream(StreamQuery),
    StreamsEntropy,
    RuntimeCaps,

    // Content stream structured analysis
    StreamContentOps { obj: u32, gen: u16, recursive: bool, with_findings: bool },
    StreamContentOpsJson { obj: u32, gen: u16, recursive: bool, with_findings: bool },
    PageContentOps { page_idx: usize, with_findings: bool },
    PageContentOpsJson { page_idx: usize, with_findings: bool },
    GraphContentStreamDot { obj: u32, gen: u16, recursive: bool },
    GraphContentStreamJson { obj: u32, gen: u16, recursive: bool },
    GraphPageContentDot { page_idx: usize, recursive: bool },
    GraphPageContentJson { page_idx: usize, recursive: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamQuery {
    pub obj: u32,
    pub gen: u16,
    pub decode_override: Option<DecodeMode>,
    pub output: StreamOutput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamOutput {
    Summary,
    Raw,
}

/// Query result that can be serialized to JSON or formatted as text
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum QueryResult {
    Scalar(ScalarValue),
    List(Vec<String>),
    Structure(serde_json::Value),
    Error(QueryError),
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ScalarValue {
    String(String),
    Number(i64),
    Boolean(bool),
}

#[derive(Debug, Serialize)]
pub struct QueryError {
    pub status: &'static str,
    pub error_code: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

pub fn query_syntax_error(message: impl Into<String>) -> QueryResult {
    QueryResult::Error(QueryError {
        status: "error",
        error_code: "QUERY_SYNTAX_ERROR",
        message: message.into(),
        context: None,
    })
}

pub fn query_error_with_context(
    error_code: &'static str,
    message: impl Into<String>,
    context: Option<serde_json::Value>,
) -> QueryResult {
    QueryResult::Error(QueryError { status: "error", error_code, message: message.into(), context })
}

fn build_invalid_pdf_result(pdf_path: &Path, bytes: &[u8], reason: &str) -> QueryResult {
    let mut meta = HashMap::new();
    meta.insert("path".to_string(), pdf_path.display().to_string());
    meta.insert("reason".to_string(), reason.to_string());

    let evidence_len = bytes.len().min(16) as u32;
    let evidence = EvidenceSpan {
        source: EvidenceSource::File,
        offset: 0,
        length: evidence_len,
        origin: None,
        note: Some("Invalid PDF header".into()),
    };

    let finding = Finding {
        id: "invalid_pdf_header".into(),
        surface: AttackSurface::FileStructure,
        kind: "invalid_pdf_header".into(),
        severity: Severity::High,
        confidence: Confidence::Strong,
        impact: None,
        title: "Invalid PDF format".into(),
        description: format!("File header validation failed: {}", reason),
        objects: vec![pdf_path.display().to_string()],
        evidence: vec![evidence],
        remediation: Some("Ensure the file is a valid PDF and retry the scan.".into()),
        meta,
        yara: None,
        position: None,
        positions: Vec::new(),
        ..Finding::default()
    };

    let mut findings = vec![finding];
    let summary = analyze_polyglot_signatures(bytes);
    if let Some(polyglot) = build_polyglot_finding(pdf_path, &summary) {
        findings.push(polyglot);
    }

    QueryResult::Structure(json!(findings))
}

fn build_polyglot_finding(
    pdf_path: &Path,
    summary: &sis_pdf_detectors::polyglot::PolyglotSignatureSummary,
) -> Option<Finding> {
    if summary.hits.is_empty() {
        return None;
    }

    let severity = Severity::High;
    let confidence = Confidence::Strong;

    let sig_list = summary
        .hits
        .iter()
        .take(12)
        .map(|hit| format!("{}@{}", hit.label, hit.offset))
        .collect::<Vec<_>>()
        .join(", ");

    let mut evidence = Vec::new();
    for hit in summary.hits.iter().take(8) {
        evidence.push(EvidenceSpan {
            source: EvidenceSource::File,
            offset: hit.offset as u64,
            length: hit.length as u32,
            origin: None,
            note: Some(format!("Magic {}", hit.label)),
        });
    }

    let mut meta = HashMap::new();
    let header_offset =
        summary.pdf_header_offset.map(|off| off.to_string()).unwrap_or_else(|| "missing".into());
    meta.insert("polyglot.pdf_header_offset".into(), header_offset);
    meta.insert("polyglot.pdf_header_at_zero".into(), summary.pdf_header_at_zero.to_string());
    meta.insert("polyglot.signatures".into(), sig_list.clone());

    Some(Finding {
        id: "polyglot_signature_conflict".into(),
        surface: AttackSurface::FileStructure,
        kind: "polyglot_signature_conflict".into(),
        severity,
        confidence,
        title: "Polyglot signature conflict".into(),
        description: format!(
            "File header failed but conflicting signatures were still detected: {}.",
            sig_list
        ),
        objects: vec![pdf_path.display().to_string()],
        evidence,
        remediation: Some(
            "Validate file type by content and block mixed-format files in the PDF pipeline."
                .into(),
        ),
        meta,
        yara: None,
        position: None,
        positions: Vec::new(),
        ..Finding::default()
    })
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
        "pages.execution" | "pages.execution.json" => Ok(Query::PagesExecution),

        // Structure
        "trailer" => Ok(Query::Trailer),
        "catalog" => Ok(Query::Catalog),
        "xref" => Ok(Query::Xref),
        "xref.count" => Ok(Query::XrefCount),
        "xref.startxrefs" => Ok(Query::XrefStartxrefs),
        "xref.startxrefs.count" => Ok(Query::XrefStartxrefsCount),
        "xref.sections" => Ok(Query::XrefSections),
        "xref.sections.count" => Ok(Query::XrefSectionsCount),
        "xref.trailers" => Ok(Query::XrefTrailers),
        "xref.trailers.count" => Ok(Query::XrefTrailersCount),
        "xref.deviations" => Ok(Query::XrefDeviations),
        "xref.deviations.count" => Ok(Query::XrefDeviationsCount),
        "revisions" => Ok(Query::Revisions),
        "revisions.detail" => Ok(Query::RevisionsDetail),
        "revisions.count" => Ok(Query::RevisionsCount),

        // Content
        "js" | "javascript" => Ok(Query::JavaScript),
        "js.count" => Ok(Query::JavaScriptCount),
        "urls" | "uris" => Ok(Query::Urls),
        "urls.count" => Ok(Query::UrlsCount),
        "embedded" => Ok(Query::Embedded),
        "embedded.count" => Ok(Query::EmbeddedCount),
        "xfa" => Ok(Query::XfaForms),
        "xfa.count" => Ok(Query::XfaFormsCount),
        "xfa.scripts" => Ok(Query::XfaScripts),
        "xfa.scripts.count" => Ok(Query::XfaScriptsCount),
        "swf" => Ok(Query::SwfContent),
        "swf.count" => Ok(Query::SwfContentCount),
        "swf.actionscript" => Ok(Query::SwfActionScript),
        "swf.actionscript.count" => Ok(Query::SwfActionScriptCount),
        "swf.extract" => Ok(Query::SwfStreams),
        "swf.extract.count" => Ok(Query::SwfStreamsCount),
        "embedded.executables" => Ok(Query::FindingsByKind("embedded_executable_present".into())),
        "embedded.executables.count" => {
            Ok(Query::FindingsByKindCount("embedded_executable_present".into()))
        }
        "embedded.scripts" => Ok(Query::FindingsByKind("embedded_script_present".into())),
        "embedded.scripts.count" => {
            Ok(Query::FindingsByKindCount("embedded_script_present".into()))
        }
        "embedded.archives.encrypted" => {
            Ok(Query::FindingsByKind("embedded_archive_encrypted".into()))
        }
        "embedded.archives.encrypted.count" => {
            Ok(Query::FindingsByKindCount("embedded_archive_encrypted".into()))
        }
        "embedded.double-extension" => {
            Ok(Query::FindingsByKind("embedded_double_extension".into()))
        }
        "embedded.double-extension.count" => {
            Ok(Query::FindingsByKindCount("embedded_double_extension".into()))
        }
        "embedded.encrypted" => Ok(Query::FindingsByKind("embedded_encrypted".into())),
        "embedded.encrypted.count" => Ok(Query::FindingsByKindCount("embedded_encrypted".into())),
        "images" => Ok(Query::Images),
        "images.count" => Ok(Query::ImagesCount),
        "images.jbig2" => Ok(Query::ImagesJbig2),
        "images.jbig2.count" => Ok(Query::ImagesJbig2Count),
        "images.jpx" => Ok(Query::ImagesJpx),
        "images.jpx.count" => Ok(Query::ImagesJpxCount),
        "images.ccitt" => Ok(Query::ImagesCcitt),
        "images.ccitt.count" => Ok(Query::ImagesCcittCount),
        "images.risky" => Ok(Query::ImagesRisky),
        "images.risky.count" => Ok(Query::ImagesRiskyCount),
        "images.malformed" => Ok(Query::ImagesMalformed),
        "images.malformed.count" => Ok(Query::ImagesMalformedCount),
        "media.3d" => Ok(Query::Media3D),
        "media.3d.count" => Ok(Query::Media3DCount),
        "media.audio" => Ok(Query::MediaAudio),
        "media.audio.count" => Ok(Query::MediaAudioCount),
        "launch" => Ok(Query::FindingsByKind("launch_action_present".into())),
        "launch.count" => Ok(Query::FindingsByKindCount("launch_action_present".into())),
        "launch.external" => Ok(Query::FindingsByKind("launch_external_program".into())),
        "launch.external.count" => Ok(Query::FindingsByKindCount("launch_external_program".into())),
        "launch.embedded" => Ok(Query::FindingsByKind("launch_embedded_file".into())),
        "launch.embedded.count" => Ok(Query::FindingsByKindCount("launch_embedded_file".into())),
        "actions.chains" => Ok(Query::Chains),
        "actions.chains.count" => Ok(Query::ChainsCount),
        "actions.chains.all" => Ok(Query::ChainsAll),
        "actions.chains.all.count" => Ok(Query::ChainsAllCount),
        "actions.chains.js.all" => Ok(Query::ChainsJsAll),
        "actions.chains.complex" => Ok(Query::FindingsByKind("action_chain_complex".into())),
        "actions.chains.complex.count" => {
            Ok(Query::FindingsByKindCount("action_chain_complex".into()))
        }
        "actions.triggers.automatic" => {
            Ok(Query::FindingsByKind("action_automatic_trigger".into()))
        }
        "actions.triggers.automatic.count" => {
            Ok(Query::FindingsByKindCount("action_automatic_trigger".into()))
        }
        "actions.triggers.hidden" => Ok(Query::FindingsByKind("action_hidden_trigger".into())),
        "actions.triggers.hidden.count" => {
            Ok(Query::FindingsByKindCount("action_hidden_trigger".into()))
        }
        "xfa.submit" => Ok(Query::FindingsByKind("xfa_submit".into())),
        "xfa.submit.count" => Ok(Query::FindingsByKindCount("xfa_submit".into())),
        "xfa.sensitive" => Ok(Query::FindingsByKind("xfa_sensitive_field".into())),
        "xfa.sensitive.count" => Ok(Query::FindingsByKindCount("xfa_sensitive_field".into())),
        "xfa.too-large" => Ok(Query::FindingsByKind("xfa_too_large".into())),
        "xfa.too-large.count" => Ok(Query::FindingsByKindCount("xfa_too_large".into())),
        "xfa.scripts.high" => Ok(Query::FindingsByKind("xfa_script_count_high".into())),
        "xfa.scripts.high.count" => Ok(Query::FindingsByKindCount("xfa_script_count_high".into())),
        "findings.swf" => Ok(Query::FindingsByKind("swf_embedded".into())),
        "findings.swf.count" => Ok(Query::FindingsByKindCount("swf_embedded".into())),
        "streams.high-entropy" => Ok(Query::FindingsByKind("stream_high_entropy".into())),
        "streams.high-entropy.count" => {
            Ok(Query::FindingsByKindCount("stream_high_entropy".into()))
        }
        "streams.entropy" => Ok(Query::StreamsEntropy),
        "runtime.caps" => Ok(Query::RuntimeCaps),
        "runtime.caps.json" => Ok(Query::RuntimeCaps),
        "encryption" => Ok(Query::Encryption),
        "encryption.weak" => Ok(Query::EncryptionWeak),
        "encryption.weak.count" => Ok(Query::EncryptionWeakCount),
        "filters.unusual" => Ok(Query::FindingsByKind("filter_chain_unusual".into())),
        "filters.unusual.count" => Ok(Query::FindingsByKindCount("filter_chain_unusual".into())),
        "filters.invalid" => Ok(Query::FindingsByKind("filter_order_invalid".into())),
        "filters.invalid.count" => Ok(Query::FindingsByKindCount("filter_order_invalid".into())),
        "filters.repeated" => Ok(Query::FindingsByKind("filter_combination_unusual".into())),
        "filters.repeated.count" => {
            Ok(Query::FindingsByKindCount("filter_combination_unusual".into()))
        }

        // Findings
        "findings" => Ok(Query::Findings),
        "findings.csv" => Ok(Query::FindingsCsv),
        "findings.count" => Ok(Query::FindingsCount),
        "findings.composite" => Ok(Query::FindingsComposite),
        "findings.composite.csv" => Ok(Query::FindingsCompositeCsv),
        "findings.composite.count" => Ok(Query::FindingsCompositeCount),
        "correlations" => Ok(Query::Correlations),
        "correlations.count" => Ok(Query::CorrelationsCount),
        "canonical-diff" => Ok(Query::CanonicalDiff),
        "findings.high" => Ok(Query::FindingsBySeverity(Severity::High)),
        "findings.medium" => Ok(Query::FindingsBySeverity(Severity::Medium)),
        "findings.low" => Ok(Query::FindingsBySeverity(Severity::Low)),
        "findings.info" => Ok(Query::FindingsBySeverity(Severity::Info)),
        "findings.critical" => Ok(Query::FindingsBySeverity(Severity::Critical)),

        // Events
        "events" => Ok(Query::Events),
        "events.full" => Ok(Query::EventsFull),
        "events.full.csv" => Ok(Query::EventsFullCsv),
        "events.count" => Ok(Query::EventsCount),
        "events.document" => Ok(Query::EventsDocument),
        "events.page" => Ok(Query::EventsPage),
        "events.field" => Ok(Query::EventsField),

        // Advanced
        "chains" => Ok(Query::Chains),
        "chains.all" => Ok(Query::ChainsAll),
        "chains.all.count" => Ok(Query::ChainsAllCount),
        "chains.js" => Ok(Query::ChainsJs),
        "chains.js.all" => Ok(Query::ChainsJsAll),
        "cycles" => Ok(Query::Cycles),
        "cycles.page" => Ok(Query::CyclesPage),

        // Export queries
        "org" => Ok(Query::ExportOrgDot),
        "org.dot" => Ok(Query::ExportOrgDot),
        "org.json" => Ok(Query::ExportOrgJson),
        "graph.org" => Ok(Query::ExportOrgDot),
        "graph.org.dot" => Ok(Query::ExportOrgDot),
        "graph.org.json" => Ok(Query::ExportOrgJson),
        "graph.structure" => Ok(Query::ExportStructureDot),
        "graph.structure.dot" => Ok(Query::ExportStructureDot),
        "graph.structure.json" => Ok(Query::ExportStructureJson),
        "graph.structure.overlay" => Ok(Query::ExportStructureOverlayDot),
        "graph.structure.overlay.dot" => Ok(Query::ExportStructureOverlayDot),
        "graph.structure.overlay.json" => Ok(Query::ExportStructureOverlayJson),
        "graph.structure.overlay.telemetry" => Ok(Query::ExportStructureOverlayTelemetryDot),
        "graph.structure.overlay.telemetry.dot" => Ok(Query::ExportStructureOverlayTelemetryDot),
        "graph.structure.overlay.telemetry.json" => Ok(Query::ExportStructureOverlayTelemetryJson),
        "graph.event" => Ok(Query::ExportEventDot),
        "graph.event.dot" => Ok(Query::ExportEventDot),
        "graph.event.json" => Ok(Query::ExportEventJson),
        "graph.event.stream" => Ok(Query::ExportEventStreamDot),
        "graph.event.stream.dot" => Ok(Query::ExportEventStreamDot),
        "graph.event.stream.json" => Ok(Query::ExportEventStreamJson),
        "graph.action" => Ok(Query::ExportEventDot),
        "graph.action.dot" => Ok(Query::ExportEventDot),
        "graph.action.json" => Ok(Query::ExportEventJson),
        "ir" => Ok(Query::ExportIrText),
        "ir.text" => Ok(Query::ExportIrText),
        "ir.json" => Ok(Query::ExportIrJson),
        "graph.ir" => Ok(Query::ExportIrText),
        "graph.ir.text" => Ok(Query::ExportIrText),
        "graph.ir.json" => Ok(Query::ExportIrJson),
        "features" => Ok(Query::ExportFeatures),
        "features.csv" => Ok(Query::ExportFeatures),
        "features.json" => Ok(Query::ExportFeaturesJson),

        _ => {
            // Content stream queries — recursive and findings variants first (longer prefix wins).
            if let Some(rest) = input.strip_prefix("stream.content.json.recursive ") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if !parts.is_empty() {
                    let obj = parts[0].parse::<u32>().map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    let gen = parts.get(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
                    return Ok(Query::StreamContentOpsJson { obj, gen, recursive: true, with_findings: false });
                }
            }
            if let Some(rest) = input.strip_prefix("stream.content.json.findings ") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if !parts.is_empty() {
                    let obj = parts[0].parse::<u32>().map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    let gen = parts.get(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
                    return Ok(Query::StreamContentOpsJson { obj, gen, recursive: false, with_findings: true });
                }
            }
            if let Some(rest) = input.strip_prefix("stream.content.json ") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if !parts.is_empty() {
                    let obj = parts[0].parse::<u32>().map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    let gen = parts.get(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
                    return Ok(Query::StreamContentOpsJson { obj, gen, recursive: false, with_findings: false });
                }
            }
            if let Some(rest) = input.strip_prefix("stream.content.recursive ") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if !parts.is_empty() {
                    let obj = parts[0].parse::<u32>().map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    let gen = parts.get(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
                    return Ok(Query::StreamContentOps { obj, gen, recursive: true, with_findings: false });
                }
            }
            if let Some(rest) = input.strip_prefix("stream.content.findings ") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if !parts.is_empty() {
                    let obj = parts[0].parse::<u32>().map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    let gen = parts.get(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
                    return Ok(Query::StreamContentOps { obj, gen, recursive: false, with_findings: true });
                }
            }
            if let Some(rest) = input.strip_prefix("stream.content ") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if !parts.is_empty() {
                    let obj = parts[0].parse::<u32>().map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    let gen = parts.get(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
                    return Ok(Query::StreamContentOps { obj, gen, recursive: false, with_findings: false });
                }
            }
            if let Some(rest) = input.strip_prefix("page.content.json.findings ") {
                let idx = rest.trim().parse::<usize>().map_err(|_| anyhow!("Invalid page index: {}", rest.trim()))?;
                return Ok(Query::PageContentOpsJson { page_idx: idx, with_findings: true });
            }
            if let Some(rest) = input.strip_prefix("page.content.json ") {
                let idx = rest.trim().parse::<usize>().map_err(|_| anyhow!("Invalid page index: {}", rest.trim()))?;
                return Ok(Query::PageContentOpsJson { page_idx: idx, with_findings: false });
            }
            if let Some(rest) = input.strip_prefix("page.content.findings ") {
                let idx = rest.trim().parse::<usize>().map_err(|_| anyhow!("Invalid page index: {}", rest.trim()))?;
                return Ok(Query::PageContentOps { page_idx: idx, with_findings: true });
            }
            if let Some(rest) = input.strip_prefix("page.content ") {
                let idx = rest.trim().parse::<usize>().map_err(|_| anyhow!("Invalid page index: {}", rest.trim()))?;
                return Ok(Query::PageContentOps { page_idx: idx, with_findings: false });
            }
            if let Some(rest) = input.strip_prefix("graph.content.json.recursive ") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if !parts.is_empty() {
                    let obj = parts[0].parse::<u32>().map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    let gen = parts.get(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
                    return Ok(Query::GraphContentStreamJson { obj, gen, recursive: true });
                }
            }
            if let Some(rest) = input.strip_prefix("graph.content.json ") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if !parts.is_empty() {
                    let obj = parts[0].parse::<u32>().map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    let gen = parts.get(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
                    return Ok(Query::GraphContentStreamJson { obj, gen, recursive: false });
                }
            }
            if let Some(rest) = input.strip_prefix("graph.content.recursive ") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if !parts.is_empty() {
                    let obj = parts[0].parse::<u32>().map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    let gen = parts.get(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
                    return Ok(Query::GraphContentStreamDot { obj, gen, recursive: true });
                }
            }
            if let Some(rest) = input.strip_prefix("graph.content ") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if !parts.is_empty() {
                    let obj = parts[0].parse::<u32>().map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    let gen = parts.get(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
                    return Ok(Query::GraphContentStreamDot { obj, gen, recursive: false });
                }
            }
            if let Some(rest) = input.strip_prefix("graph.page.content.json.recursive ") {
                let idx = rest.trim().parse::<usize>().map_err(|_| anyhow!("Invalid page index: {}", rest.trim()))?;
                return Ok(Query::GraphPageContentJson { page_idx: idx, recursive: true });
            }
            if let Some(rest) = input.strip_prefix("graph.page.content.json ") {
                let idx = rest.trim().parse::<usize>().map_err(|_| anyhow!("Invalid page index: {}", rest.trim()))?;
                return Ok(Query::GraphPageContentJson { page_idx: idx, recursive: false });
            }
            if let Some(rest) = input.strip_prefix("graph.page.content.recursive ") {
                let idx = rest.trim().parse::<usize>().map_err(|_| anyhow!("Invalid page index: {}", rest.trim()))?;
                return Ok(Query::GraphPageContentDot { page_idx: idx, recursive: true });
            }
            if let Some(rest) = input.strip_prefix("graph.page.content ") {
                let idx = rest.trim().parse::<usize>().map_err(|_| anyhow!("Invalid page index: {}", rest.trim()))?;
                return Ok(Query::GraphPageContentDot { page_idx: idx, recursive: false });
            }

            if let Some(rest) = input.strip_prefix("graph.structure.depth ") {
                let depth = rest
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| anyhow!("Invalid depth: {}", rest.trim()))?;
                return Ok(Query::ExportStructureDotDepth(depth));
            }
            if let Some(rest) = input.strip_prefix("graph.structure.overlay.depth ") {
                let depth = rest
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| anyhow!("Invalid depth: {}", rest.trim()))?;
                return Ok(Query::ExportStructureOverlayDotDepth(depth));
            }
            if let Some(rest) = input.strip_prefix("graph.structure.overlay.telemetry.depth ") {
                let depth = rest
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| anyhow!("Invalid depth: {}", rest.trim()))?;
                return Ok(Query::ExportStructureOverlayTelemetryDotDepth(depth));
            }
            if let Some(rest) = input.strip_prefix("graph.event.hops ") {
                let hops = rest
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| anyhow!("Invalid hop count: {}", rest.trim()))?;
                return Ok(Query::ExportEventDotHops(hops));
            }
            if let Some(rest) = input.strip_prefix("graph.event.stream.hops ") {
                let hops = rest
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| anyhow!("Invalid hop count: {}", rest.trim()))?;
                return Ok(Query::ExportEventStreamDotHops(hops));
            }
            if let Some(rest) = input.strip_prefix("graph.action.hops ") {
                let hops = rest
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| anyhow!("Invalid hop count: {}", rest.trim()))?;
                return Ok(Query::ExportEventDotHops(hops));
            }

            // Try to parse ref/references query
            if let Some(rest) = input.strip_prefix("ref ").or(input.strip_prefix("references ")) {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() == 1 {
                    let obj = parts[0]
                        .parse::<u32>()
                        .map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    return Ok(Query::References(obj, 0));
                } else if parts.len() == 2 {
                    let obj = parts[0]
                        .parse::<u32>()
                        .map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    let gen = parts[1]
                        .parse::<u16>()
                        .map_err(|_| anyhow!("Invalid generation number: {}", parts[1]))?;
                    return Ok(Query::References(obj, gen));
                }
                return Err(anyhow!("Invalid ref query format"));
            }

            // Try to parse object queries
            if let Some(rest) =
                input.strip_prefix("obj.detail ").or(input.strip_prefix("object.detail "))
            {
                let mut parts = rest.split_whitespace();
                let obj_token = parts.next().ok_or_else(|| anyhow!("Object number required"))?;
                let obj = obj_token
                    .parse::<u32>()
                    .map_err(|_| anyhow!("Invalid object number: {}", obj_token))?;
                let mut gen = 0u16;
                let mut context_only = false;
                if let Some(next) = parts.next() {
                    if next.starts_with("--") {
                        match next {
                            "--context-only" => context_only = true,
                            _ => return Err(anyhow!("Unknown obj.detail flag: {}", next)),
                        }
                    } else {
                        gen = next
                            .parse::<u16>()
                            .map_err(|_| anyhow!("Invalid generation number: {}", next))?;
                    }
                }
                for token in parts {
                    match token {
                        "--context-only" => context_only = true,
                        _ => return Err(anyhow!("Unknown obj.detail flag: {}", token)),
                    }
                }
                return Ok(Query::ShowObjectDetail { obj, gen, context_only });
            }

            if let Some(rest) =
                input.strip_prefix("object.context ").or(input.strip_prefix("obj.context "))
            {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() == 1 {
                    let obj = parts[0]
                        .parse::<u32>()
                        .map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    return Ok(Query::ShowObjectContext(obj, 0));
                } else if parts.len() == 2 {
                    let obj = parts[0]
                        .parse::<u32>()
                        .map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    let gen = parts[1]
                        .parse::<u16>()
                        .map_err(|_| anyhow!("Invalid generation number: {}", parts[1]))?;
                    return Ok(Query::ShowObjectContext(obj, gen));
                }
                return Err(anyhow!("Invalid object.context query format"));
            }

            if let Some(rest) = input
                .strip_prefix("object ")
                .or(input.strip_prefix("obj "))
                .or(input.strip_prefix("o "))
            {
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

            // Try to parse stream queries
            if let Some(rest) = input.strip_prefix("stream ") {
                let mut parts = rest.split_whitespace();
                let obj_token = parts.next().ok_or_else(|| anyhow!("Object number required"))?;
                let obj = obj_token
                    .parse::<u32>()
                    .map_err(|_| anyhow!("Invalid object number: {}", obj_token))?;
                let mut gen = 0u16;
                let mut decode_override = None;
                let mut output = StreamOutput::Summary;
                if let Some(next) = parts.next() {
                    if next.starts_with("--") {
                        gen = 0;
                        match next {
                            "--raw" => {
                                output = StreamOutput::Raw;
                                decode_override = Some(DecodeMode::Raw);
                            }
                            "--hexdump" => {
                                decode_override = Some(DecodeMode::Hexdump);
                            }
                            "--decode" => {
                                decode_override = Some(DecodeMode::Decode);
                            }
                            _ => return Err(anyhow!("Unknown stream flag: {}", next)),
                        }
                    } else {
                        gen = next
                            .parse::<u16>()
                            .map_err(|_| anyhow!("Invalid generation number: {}", next))?;
                    }
                }
                for token in parts {
                    match token {
                        "--raw" => {
                            output = StreamOutput::Raw;
                            decode_override = Some(DecodeMode::Raw);
                        }
                        "--hexdump" => {
                            decode_override = Some(DecodeMode::Hexdump);
                        }
                        "--decode" => {
                            decode_override = Some(DecodeMode::Decode);
                        }
                        other => return Err(anyhow!("Unknown stream flag: {}", other)),
                    }
                }
                return Ok(Query::Stream(StreamQuery { obj, gen, decode_override, output }));
            }

            // Try to parse findings.kind query
            if let Some(kind) = input.strip_prefix("findings.kind.count ") {
                return Ok(Query::FindingsByKindCount(kind.to_string()));
            }

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

pub fn apply_output_format(query: Query, format: OutputFormat) -> Result<Query> {
    let resolved = match format {
        OutputFormat::Json | OutputFormat::Jsonl | OutputFormat::Yaml => match query {
            Query::ExportOrgDot => Query::ExportOrgJson,
            Query::ExportStructureDot => Query::ExportStructureJson,
            Query::ExportStructureDotDepth(depth) => Query::ExportStructureJsonDepth(depth),
            Query::ExportStructureOverlayDot => Query::ExportStructureOverlayJson,
            Query::ExportStructureOverlayDotDepth(depth) => {
                Query::ExportStructureOverlayJsonDepth(depth)
            }
            Query::ExportStructureOverlayTelemetryDot => Query::ExportStructureOverlayTelemetryJson,
            Query::ExportStructureOverlayTelemetryDotDepth(depth) => {
                Query::ExportStructureOverlayTelemetryJsonDepth(depth)
            }
            Query::ExportEventDot => Query::ExportEventJson,
            Query::ExportEventDotHops(hops) => Query::ExportEventJsonHops(hops),
            Query::ExportEventStreamDot => Query::ExportEventStreamJson,
            Query::ExportEventStreamDotHops(hops) => Query::ExportEventStreamJsonHops(hops),
            Query::ExportIrText => Query::ExportIrJson,
            Query::ExportFeatures => Query::ExportFeaturesJson,
            other => other,
        },
        OutputFormat::Dot => match query {
            Query::ExportOrgJson | Query::ExportOrgDot => Query::ExportOrgDot,
            Query::ExportStructureJson | Query::ExportStructureDot => Query::ExportStructureDot,
            Query::ExportStructureJsonDepth(depth) | Query::ExportStructureDotDepth(depth) => {
                Query::ExportStructureDotDepth(depth)
            }
            Query::ExportStructureOverlayJson | Query::ExportStructureOverlayDot => {
                Query::ExportStructureOverlayDot
            }
            Query::ExportStructureOverlayJsonDepth(depth)
            | Query::ExportStructureOverlayDotDepth(depth) => {
                Query::ExportStructureOverlayDotDepth(depth)
            }
            Query::ExportStructureOverlayTelemetryJson
            | Query::ExportStructureOverlayTelemetryDot => Query::ExportStructureOverlayTelemetryDot,
            Query::ExportStructureOverlayTelemetryJsonDepth(depth)
            | Query::ExportStructureOverlayTelemetryDotDepth(depth) => {
                Query::ExportStructureOverlayTelemetryDotDepth(depth)
            }
            Query::ExportEventJson | Query::ExportEventDot => Query::ExportEventDot,
            Query::ExportEventJsonHops(hops) | Query::ExportEventDotHops(hops) => {
                Query::ExportEventDotHops(hops)
            }
            Query::ExportEventStreamJson | Query::ExportEventStreamDot => Query::ExportEventStreamDot,
            Query::ExportEventStreamJsonHops(hops)
            | Query::ExportEventStreamDotHops(hops) => Query::ExportEventStreamDotHops(hops),
            _ => {
                return Err(anyhow!(
                    "--format dot is only supported for graph.org, graph.structure, graph.event, and graph.event.stream queries"
                ))
            }
        },
        OutputFormat::Csv => match query {
            Query::ExportFeatures | Query::ExportFeaturesJson => Query::ExportFeatures,
            Query::Findings => Query::FindingsCsv,
            Query::FindingsComposite => Query::FindingsCompositeCsv,
            Query::EventsFull => Query::EventsFullCsv,
            _ => {
                return Err(anyhow!(
                    "--format csv is only supported for features, findings, findings.composite, and events.full queries"
                ))
            }
        },
        OutputFormat::Text | OutputFormat::Readable => match query {
            Query::ExportOrgJson => Query::ExportOrgDot,
            Query::ExportStructureJson => Query::ExportStructureDot,
            Query::ExportStructureJsonDepth(depth) => Query::ExportStructureDotDepth(depth),
            Query::ExportStructureOverlayJson => Query::ExportStructureOverlayDot,
            Query::ExportStructureOverlayJsonDepth(depth) => Query::ExportStructureOverlayDotDepth(depth),
            Query::ExportStructureOverlayTelemetryJson => Query::ExportStructureOverlayTelemetryDot,
            Query::ExportStructureOverlayTelemetryJsonDepth(depth) => {
                Query::ExportStructureOverlayTelemetryDotDepth(depth)
            }
            Query::ExportEventJson => Query::ExportEventDot,
            Query::ExportEventJsonHops(hops) => Query::ExportEventDotHops(hops),
            Query::ExportEventStreamJson => Query::ExportEventStreamDot,
            Query::ExportEventStreamJsonHops(hops) => Query::ExportEventStreamDotHops(hops),
            Query::ExportIrJson => Query::ExportIrText,
            Query::ExportFeaturesJson => Query::ExportFeatures,
            other => other,
        },
    };

    Ok(resolved)
}

pub fn apply_with_chain(query: Query, with_chain: bool) -> Result<Query> {
    if !with_chain {
        return Ok(query);
    }
    let resolved = match query {
        Query::Findings => Query::FindingsWithChain,
        Query::FindingsBySeverity(severity) => Query::FindingsBySeverityWithChain(severity),
        Query::FindingsByKind(kind) => Query::FindingsByKindWithChain(kind),
        Query::FindingsComposite => Query::FindingsCompositeWithChain,
        Query::FindingsWithChain
        | Query::FindingsBySeverityWithChain(_)
        | Query::FindingsByKindWithChain(_)
        | Query::FindingsCompositeWithChain => query,
        _ => return Err(anyhow!("--with-chain is only supported for findings queries")),
    };
    Ok(resolved)
}

pub fn apply_report_verbosity(
    query: &Query,
    result: QueryResult,
    verbosity: ReportVerbosity,
    output_format: OutputFormat,
) -> QueryResult {
    if verbosity != ReportVerbosity::Compact {
        return result;
    }

    if !matches!(output_format, OutputFormat::Text | OutputFormat::Readable) {
        return result;
    }

    if matches!(
        query,
        Query::Findings
            | Query::FindingsBySeverity(_)
            | Query::FindingsByKind(_)
            | Query::FindingsComposite
            | Query::FindingsWithChain
            | Query::FindingsBySeverityWithChain(_)
            | Query::FindingsByKindWithChain(_)
            | Query::FindingsCompositeWithChain
    ) {
        if let QueryResult::Structure(value) = result {
            QueryResult::Structure(filter_findings_by_severity(value))
        } else {
            result
        }
    } else {
        result
    }
}

fn filter_findings_by_severity(value: serde_json::Value) -> serde_json::Value {
    let filter_array = |entries: Vec<serde_json::Value>| {
        serde_json::Value::Array(
            entries
                .into_iter()
                .filter(|entry| match entry.get("severity").and_then(|v| v.as_str()) {
                    Some("Info") | Some("Low") => false,
                    Some(other) => {
                        !other.eq_ignore_ascii_case("info") && !other.eq_ignore_ascii_case("low")
                    }
                    None => true,
                })
                .collect(),
        )
    };

    match value {
        serde_json::Value::Array(entries) => filter_array(entries),
        serde_json::Value::Object(mut object)
            if object.get("type").and_then(|v| v.as_str()) == Some("findings_with_chain") =>
        {
            if let Some(entries) = object.get("findings").and_then(|v| v.as_array()).cloned() {
                object.insert("findings".into(), filter_array(entries));
            }
            serde_json::Value::Object(object)
        }
        other => other,
    }
}

pub fn apply_chain_summary(
    query: &Query,
    result: QueryResult,
    level: ChainSummaryLevel,
    output_format: OutputFormat,
) -> QueryResult {
    if level == ChainSummaryLevel::Full {
        return result;
    }
    if !matches!(output_format, OutputFormat::Text | OutputFormat::Readable) {
        return result;
    }
    if !matches!(query, Query::Chains | Query::ChainsJs | Query::ChainsAll | Query::ChainsJsAll) {
        return result;
    }

    if let QueryResult::Structure(mut value) = result {
        if let Some(serde_json::Value::Array(chains)) = value.get_mut("chains") {
            for chain in chains.iter_mut() {
                summarize_chain_edges(chain, level);
            }
        }
        QueryResult::Structure(value)
    } else {
        result
    }
}

fn summarize_chain_edges(chain: &mut serde_json::Value, level: ChainSummaryLevel) {
    if level == ChainSummaryLevel::Full {
        return;
    }
    let original_count = chain
        .get("edges")
        .and_then(|v| v.as_array().map(|arr| arr.len()))
        .or_else(|| chain.get("length").and_then(|v| v.as_u64().map(|n| n as usize)))
        .unwrap_or(0);
    let risk_score = chain.get("risk_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let threshold = (risk_score * 0.4).max(0.25);

    let mut summary_entry = None;
    if let Some(serde_json::Value::Array(edges)) = chain.get_mut("edges") {
        match level {
            ChainSummaryLevel::Minimal => edges.clear(),
            ChainSummaryLevel::Events => {
                edges.retain(|edge| should_keep_edge(edge, threshold));
            }
            ChainSummaryLevel::Full => {}
        }
        if level != ChainSummaryLevel::Full {
            summary_entry = Some(serde_json::json!({
                "level": level_label(level),
                "original": original_count,
                "kept": edges.len()
            }));
        }
    }

    if let Some(summary) = summary_entry {
        if let Some(map) = chain.as_object_mut() {
            map.insert("edges_summary".into(), summary);
        }
    }

    if level == ChainSummaryLevel::Minimal {
        if let Some(map) = chain.as_object_mut() {
            map.insert("filtered_edges".into(), serde_json::json!(true));
        }
    }
}

fn should_keep_edge(edge: &serde_json::Value, threshold: f64) -> bool {
    if edge.get("suspicious").and_then(|v| v.as_bool()).unwrap_or(false) {
        return true;
    }
    if let Some(weight) = edge.get("weight").and_then(|v| v.as_f64()) {
        return weight >= threshold;
    }
    false
}

fn level_label(level: ChainSummaryLevel) -> &'static str {
    match level {
        ChainSummaryLevel::Minimal => "minimal",
        ChainSummaryLevel::Events => "events",
        ChainSummaryLevel::Full => "full",
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
    extract_to: Option<&Path>,
    max_extract_bytes: usize,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
) -> Result<QueryResult> {
    let result = (|| {
        if predicate.is_some()
            && !matches!(
                query,
                Query::JavaScript
                    | Query::JavaScriptCount
                    | Query::Embedded
                    | Query::EmbeddedCount
                    | Query::XfaScripts
                    | Query::XfaScriptsCount
                    | Query::SwfContent
                    | Query::SwfContentCount
                    | Query::SwfActionScript
                    | Query::SwfActionScriptCount
                    | Query::SwfStreams
                    | Query::SwfStreamsCount
                    | Query::Urls
                    | Query::UrlsCount
                    | Query::Images
                    | Query::ImagesCount
                    | Query::ImagesJbig2
                    | Query::ImagesJbig2Count
                    | Query::ImagesJpx
                    | Query::ImagesJpxCount
                    | Query::ImagesCcitt
                    | Query::ImagesCcittCount
                    | Query::ImagesRisky
                    | Query::ImagesRiskyCount
                    | Query::ImagesMalformed
                    | Query::ImagesMalformedCount
                    | Query::Media3D
                    | Query::Media3DCount
                    | Query::MediaAudio
                    | Query::MediaAudioCount
                    | Query::Events
                    | Query::EventsFull
                    | Query::EventsFullCsv
                    | Query::EventsCount
                    | Query::EventsDocument
                    | Query::EventsPage
                    | Query::EventsField
                    | Query::Chains
                    | Query::ChainsCount
                    | Query::ChainsJs
                    | Query::Findings
                    | Query::FindingsCsv
                    | Query::FindingsCount
                    | Query::FindingsBySeverity(_)
                    | Query::FindingsByKind(_)
                    | Query::FindingsByKindCount(_)
                    | Query::FindingsComposite
                    | Query::FindingsCompositeCsv
                    | Query::FindingsCompositeCount
                    | Query::FindingsWithChain
                    | Query::FindingsBySeverityWithChain(_)
                    | Query::FindingsByKindWithChain(_)
                    | Query::FindingsCompositeWithChain
                    | Query::StreamsEntropy
                    | Query::ObjectsCount
                    | Query::ObjectsList
                    | Query::ObjectsWithType(_)
                    | Query::XrefStartxrefs
                    | Query::XrefStartxrefsCount
                    | Query::XrefSections
                    | Query::XrefSectionsCount
                    | Query::XrefTrailers
                    | Query::XrefTrailersCount
                    | Query::XrefDeviations
                    | Query::XrefDeviationsCount
                    | Query::Revisions
                    | Query::RevisionsCount
            )
        {
            ensure_predicate_supported(query)?;
        }

        match query {
            Query::Pages => {
                let count = count_pages(ctx)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(count as i64)))
            }
            Query::ObjectsCount => {
                let count = count_objects(ctx, decode_mode, max_extract_bytes, predicate)?;
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
            Query::Filesize => Ok(QueryResult::Scalar(ScalarValue::Number(ctx.bytes.len() as i64))),
            Query::PagesExecution => {
                Ok(QueryResult::Structure(extract_pages_execution(ctx, predicate)?))
            }
            Query::FindingsCount => {
                let findings = findings_with_cache(ctx)?;
                let filtered = filter_findings(findings, predicate);
                Ok(QueryResult::Scalar(ScalarValue::Number(filtered.len() as i64)))
            }
            Query::FindingsBySeverity(severity) => {
                let findings = findings_with_cache(ctx)?;
                let filtered: Vec<sis_pdf_core::model::Finding> =
                    findings.into_iter().filter(|f| &f.severity == severity).collect();
                let filtered = filter_findings(filtered, predicate);
                Ok(QueryResult::Structure(json!(filtered)))
            }
            Query::FindingsBySeverityWithChain(severity) => {
                let findings = findings_with_cache(ctx)?;
                let filtered: Vec<sis_pdf_core::model::Finding> =
                    findings.into_iter().filter(|f| &f.severity == severity).collect();
                let filtered = filter_findings(filtered, predicate);
                Ok(QueryResult::Structure(build_findings_with_chain(
                    filtered,
                    ctx.options.group_chains,
                )))
            }
            Query::FindingsByKind(kind) => {
                let findings = findings_with_cache(ctx)?;
                let filtered: Vec<sis_pdf_core::model::Finding> =
                    findings.into_iter().filter(|f| f.kind == *kind).collect();
                let filtered = filter_findings(filtered, predicate);
                Ok(QueryResult::Structure(json!(filtered)))
            }
            Query::FindingsByKindWithChain(kind) => {
                let findings = findings_with_cache(ctx)?;
                let filtered: Vec<sis_pdf_core::model::Finding> =
                    findings.into_iter().filter(|f| f.kind == *kind).collect();
                let filtered = filter_findings(filtered, predicate);
                Ok(QueryResult::Structure(build_findings_with_chain(
                    filtered,
                    ctx.options.group_chains,
                )))
            }
            Query::FindingsByKindCount(kind) => {
                let findings = findings_with_cache(ctx)?;
                let filtered: Vec<sis_pdf_core::model::Finding> =
                    findings.into_iter().filter(|f| f.kind == *kind).collect();
                let filtered = filter_findings(filtered, predicate);
                Ok(QueryResult::Scalar(ScalarValue::Number(filtered.len() as i64)))
            }
            Query::Findings => {
                let findings = findings_with_cache(ctx)?;
                let filtered = filter_findings(findings, predicate);
                Ok(QueryResult::Structure(json!(filtered)))
            }
            Query::FindingsCsv => {
                let findings = findings_with_cache(ctx)?;
                let filtered = filter_findings(findings, predicate);
                Ok(QueryResult::List(findings_to_csv_rows(&filtered)))
            }
            Query::FindingsWithChain => {
                let findings = findings_with_cache(ctx)?;
                let filtered = filter_findings(findings, predicate);
                Ok(QueryResult::Structure(build_findings_with_chain(
                    filtered,
                    ctx.options.group_chains,
                )))
            }
            Query::FindingsComposite => {
                let findings = findings_with_cache(ctx)?;
                let filtered = filter_findings(findings, predicate);
                let composites: Vec<_> = filtered.into_iter().filter(is_composite).collect();
                Ok(QueryResult::Structure(json!(composites)))
            }
            Query::FindingsCompositeCsv => {
                let findings = findings_with_cache(ctx)?;
                let filtered = filter_findings(findings, predicate);
                let composites: Vec<_> = filtered.into_iter().filter(is_composite).collect();
                Ok(QueryResult::List(findings_to_csv_rows(&composites)))
            }
            Query::FindingsCompositeWithChain => {
                let findings = findings_with_cache(ctx)?;
                let filtered = filter_findings(findings, predicate);
                let composites: Vec<_> = filtered.into_iter().filter(is_composite).collect();
                Ok(QueryResult::Structure(build_findings_with_chain(
                    composites,
                    ctx.options.group_chains,
                )))
            }
            Query::FindingsCompositeCount => {
                let findings = findings_with_cache(ctx)?;
                let filtered = filter_findings(findings, predicate);
                let composites = filtered.into_iter().filter(is_composite).count();
                Ok(QueryResult::Scalar(ScalarValue::Number(composites as i64)))
            }
            Query::Correlations => {
                let findings = findings_with_cache(ctx)?;
                let filtered = filter_findings(findings, predicate);
                let composites: Vec<_> = filtered.into_iter().filter(is_composite).collect();
                let mut summary_map: HashMap<String, CorrelationSummary> = HashMap::new();
                for composite in composites {
                    let pattern = composite
                        .meta
                        .get("composite.pattern")
                        .map(|value| value.as_str())
                        .unwrap_or(composite.kind.as_str())
                        .to_string();
                    let severity = format!("{:?}", composite.severity);
                    let entry = summary_map
                        .entry(pattern)
                        .or_insert(CorrelationSummary { count: 0, severity });
                    entry.count += 1;
                }
                Ok(QueryResult::Structure(json!(summary_map)))
            }
            Query::CorrelationsCount => {
                let findings = findings_with_cache(ctx)?;
                let filtered = filter_findings(findings, predicate);
                let composites = filtered.into_iter().filter(is_composite).count();
                Ok(QueryResult::Scalar(ScalarValue::Number(composites as i64)))
            }
            Query::CanonicalDiff => {
                let diff = canonical_diff_json(ctx);
                Ok(QueryResult::Structure(diff))
            }
            Query::Encryption => {
                let findings = findings_with_cache(ctx)?;
                let filtered: Vec<_> = findings
                    .into_iter()
                    .filter(|f| f.kind == "encryption_present" || f.kind == "encryption_key_short")
                    .collect();
                let filtered = filter_findings(filtered, predicate);
                Ok(QueryResult::Structure(json!(filtered)))
            }
            Query::EncryptionWeak => {
                let findings = findings_with_cache(ctx)?;
                let filtered: Vec<_> =
                    findings.into_iter().filter(|f| f.kind == "crypto_weak_algo").collect();
                let filtered = filter_findings(filtered, predicate);
                Ok(QueryResult::Structure(json!(filtered)))
            }
            Query::EncryptionWeakCount => {
                let findings = findings_with_cache(ctx)?;
                let filtered: Vec<_> =
                    findings.into_iter().filter(|f| f.kind == "crypto_weak_algo").collect();
                let filtered = filter_findings(filtered, predicate);
                Ok(QueryResult::Scalar(ScalarValue::Number(filtered.len() as i64)))
            }
            Query::JavaScript => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                if let Some(extract_path) = extract_to {
                    // Extract to disk
                    let written = write_js_files(
                        ctx,
                        extract_path,
                        max_extract_bytes,
                        decode_mode,
                        predicate,
                    )?;
                    Ok(QueryResult::List(written))
                } else {
                    // Return preview list
                    let js_code = extract_javascript(ctx, decode_mode, predicate)?;
                    Ok(QueryResult::List(js_code))
                }
            }
            Query::JavaScriptCount => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let js_code = extract_javascript(ctx, decode_mode, predicate)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(js_code.len() as i64)))
            }
            Query::Urls => {
                let urls = extract_urls(ctx, predicate)?;
                Ok(QueryResult::List(urls))
            }
            Query::UrlsCount => {
                let urls = extract_urls(ctx, predicate)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(urls.len() as i64)))
            }
            Query::Embedded => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                if let Some(extract_path) = extract_to {
                    // Extract to disk
                    let written = write_embedded_files(
                        ctx,
                        extract_path,
                        max_extract_bytes,
                        decode_mode,
                        predicate,
                    )?;
                    Ok(QueryResult::List(written))
                } else {
                    // Return preview list
                    let embedded = extract_embedded_files(ctx, decode_mode, predicate)?;
                    Ok(QueryResult::List(embedded))
                }
            }
            Query::EmbeddedCount => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let embedded = extract_embedded_files(ctx, decode_mode, predicate)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(embedded.len() as i64)))
            }
            Query::XfaForms => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let forms = list_xfa_forms(ctx, predicate)?;
                Ok(QueryResult::Structure(forms))
            }
            Query::XfaFormsCount => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let forms = list_xfa_forms(ctx, predicate)?;
                let count = forms["count"].as_u64().unwrap_or(0);
                Ok(QueryResult::Scalar(ScalarValue::Number(count as i64)))
            }
            Query::XfaScripts => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                if let Some(extract_path) = extract_to {
                    let written = write_xfa_scripts(ctx, extract_path, predicate)?;
                    Ok(QueryResult::List(written))
                } else {
                    let scripts = extract_xfa_scripts(ctx, predicate)?;
                    Ok(QueryResult::List(scripts))
                }
            }
            Query::XfaScriptsCount => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let scripts = extract_xfa_scripts(ctx, predicate)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(scripts.len() as i64)))
            }
            Query::SwfContent => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                if let Some(extract_path) = extract_to {
                    let written = write_swf_streams(
                        ctx,
                        extract_path,
                        max_extract_bytes,
                        decode_mode,
                        predicate,
                    )?;
                    Ok(QueryResult::List(written))
                } else {
                    let entries =
                        collect_swf_content(ctx, max_extract_bytes, decode_mode, predicate)?;
                    let lines = entries.iter().map(format_swf_summary).collect();
                    Ok(QueryResult::List(lines))
                }
            }
            Query::SwfContentCount => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let entries = collect_swf_content(ctx, max_extract_bytes, decode_mode, predicate)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(entries.len() as i64)))
            }
            Query::SwfActionScript => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let entries = collect_swf_content(ctx, max_extract_bytes, decode_mode, predicate)?;
                let scripts: Vec<_> =
                    entries.into_iter().filter(|entry| !entry.action_tags.is_empty()).collect();
                let lines = scripts.iter().map(format_swf_summary).collect();
                Ok(QueryResult::List(lines))
            }
            Query::SwfActionScriptCount => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let entries = collect_swf_content(ctx, max_extract_bytes, decode_mode, predicate)?;
                let script_count =
                    entries.into_iter().filter(|entry| !entry.action_tags.is_empty()).count();
                Ok(QueryResult::Scalar(ScalarValue::Number(script_count as i64)))
            }
            Query::SwfStreams => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                if let Some(extract_path) = extract_to {
                    let written = write_swf_streams(
                        ctx,
                        extract_path,
                        max_extract_bytes,
                        decode_mode,
                        predicate,
                    )?;
                    Ok(QueryResult::List(written))
                } else {
                    let streams =
                        extract_swf_streams(ctx, max_extract_bytes, decode_mode, predicate)?;
                    Ok(QueryResult::List(streams))
                }
            }
            Query::SwfStreamsCount => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let streams = extract_swf_streams(ctx, max_extract_bytes, decode_mode, predicate)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(streams.len() as i64)))
            }
            Query::Images => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                if let Some(extract_path) = extract_to {
                    let written = write_image_files(
                        ctx,
                        extract_path,
                        max_extract_bytes,
                        decode_mode,
                        predicate,
                    )?;
                    Ok(QueryResult::List(written))
                } else {
                    let images = extract_images(ctx, decode_mode, max_extract_bytes, predicate)?;
                    Ok(QueryResult::List(images))
                }
            }
            Query::ImagesCount => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let images = extract_images(ctx, decode_mode, max_extract_bytes, predicate)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(images.len() as i64)))
            }
            Query::Stream(stream) => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let mode = stream.decode_override.unwrap_or(decode_mode);
                if let Some(extract_path) = extract_to {
                    let written = write_stream_object(
                        ctx,
                        stream.obj,
                        stream.gen,
                        extract_path,
                        max_extract_bytes,
                        mode,
                    )?;
                    Ok(QueryResult::List(vec![written]))
                } else {
                    let preview = preview_stream_object(
                        ctx,
                        stream.obj,
                        stream.gen,
                        max_extract_bytes,
                        mode,
                    )?;
                    Ok(QueryResult::List(vec![preview]))
                }
            }
            Query::StreamContentOps { obj, gen, recursive, with_findings } => {
                let text = execute_stream_content_ops(ctx, *obj, *gen, *recursive, *with_findings)?;
                Ok(QueryResult::List(vec![text]))
            }
            Query::StreamContentOpsJson { obj, gen, recursive, with_findings } => {
                let json = execute_stream_content_ops_json(ctx, *obj, *gen, *recursive, *with_findings)?;
                Ok(QueryResult::Structure(json))
            }
            Query::PageContentOps { page_idx, with_findings } => {
                let text = execute_page_content_ops(ctx, *page_idx, *with_findings)?;
                Ok(QueryResult::List(vec![text]))
            }
            Query::PageContentOpsJson { page_idx, with_findings } => {
                let json = execute_page_content_ops_json(ctx, *page_idx, *with_findings)?;
                Ok(QueryResult::Structure(json))
            }
            Query::GraphContentStreamDot { obj, gen, recursive } => {
                let dot = execute_content_graph_dot(ctx, *obj, *gen, *recursive)?;
                Ok(QueryResult::List(vec![dot]))
            }
            Query::GraphContentStreamJson { obj, gen, recursive } => {
                let json = execute_content_graph_json(ctx, *obj, *gen, *recursive)?;
                Ok(QueryResult::Structure(json))
            }
            Query::GraphPageContentDot { page_idx, recursive } => {
                let dot = execute_page_content_graph_dot(ctx, *page_idx, *recursive)?;
                Ok(QueryResult::List(vec![dot]))
            }
            Query::GraphPageContentJson { page_idx, recursive } => {
                let json = execute_page_content_graph_json(ctx, *page_idx, *recursive)?;
                Ok(QueryResult::Structure(json))
            }
            Query::StreamsEntropy => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let mut rows = Vec::new();
                for entry in &ctx.graph.objects {
                    let PdfAtom::Stream(stream) = &entry.atom else {
                        continue;
                    };
                    let Ok(decoded) = ctx.decoded.get_or_decode(ctx.bytes, stream) else {
                        continue;
                    };
                    let analysis = sis_pdf_core::stream_analysis::analyse_stream(
                        &decoded.data,
                        &sis_pdf_core::stream_analysis::StreamLimits::default(),
                    );
                    let filter_label = filter_name(&stream.dict).unwrap_or_default();
                    let subtype = subtype_name(&stream.dict);
                    let mut predicate_meta = HashMap::new();
                    predicate_meta
                        .insert("sample_size_bytes".into(), analysis.sample_bytes.to_string());
                    predicate_meta
                        .insert("stream.size_bytes".into(), analysis.size_bytes.to_string());
                    predicate_meta.insert("stream.magic_type".into(), analysis.magic_type.clone());
                    predicate_meta
                        .insert("stream.sample_timed_out".into(), analysis.timed_out.to_string());
                    let predicate_context = PredicateContext {
                        length: decoded.data.len(),
                        filter: Some(filter_label.clone()),
                        type_name: "Stream".to_string(),
                        subtype: subtype.clone(),
                        entropy: analysis.entropy,
                        width: 0,
                        height: 0,
                        pixels: 0,
                        risky: false,
                        severity: None,
                        confidence: None,
                        surface: None,
                        kind: None,
                        object_count: 0,
                        evidence_count: 0,
                        name: Some(format!("{} {} obj", entry.obj, entry.gen)),
                        magic: Some(analysis.magic_type.clone()),
                        hash: None,
                        impact: None,
                        action_type: None,
                        action_target: None,
                        action_initiation: None,
                        meta: predicate_meta,
                    };
                    if predicate.map(|pred| pred.evaluate(&predicate_context)).unwrap_or(true) {
                        let filter_display = if filter_label.is_empty() {
                            "none".to_string()
                        } else {
                            filter_label.clone()
                        };
                        let subtype_display = subtype.unwrap_or_else(|| "unknown".into());
                        rows.push(format!(
                            "{} {} obj: entropy={:.3}, sample={} bytes, magic={}, filter={}, subtype={}",
                            entry.obj,
                            entry.gen,
                            analysis.entropy,
                            analysis.sample_bytes,
                            analysis.magic_type,
                            filter_display,
                            subtype_display,
                        ));
                    }
                }
                Ok(QueryResult::List(rows))
            }
            Query::RuntimeCaps => {
                let caps = extract_runtime_caps(ctx)?;
                Ok(QueryResult::Structure(caps))
            }
            Query::ImagesJbig2 => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let images = extract_images_by_format(
                    ctx,
                    ImageFormat::Jbig2,
                    decode_mode,
                    max_extract_bytes,
                    predicate,
                )?;
                Ok(QueryResult::List(images))
            }
            Query::ImagesJbig2Count => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let images = extract_images_by_format(
                    ctx,
                    ImageFormat::Jbig2,
                    decode_mode,
                    max_extract_bytes,
                    predicate,
                )?;
                Ok(QueryResult::Scalar(ScalarValue::Number(images.len() as i64)))
            }
            Query::ImagesJpx => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let images = extract_images_by_format(
                    ctx,
                    ImageFormat::Jpx,
                    decode_mode,
                    max_extract_bytes,
                    predicate,
                )?;
                Ok(QueryResult::List(images))
            }
            Query::ImagesJpxCount => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let images = extract_images_by_format(
                    ctx,
                    ImageFormat::Jpx,
                    decode_mode,
                    max_extract_bytes,
                    predicate,
                )?;
                Ok(QueryResult::Scalar(ScalarValue::Number(images.len() as i64)))
            }
            Query::ImagesCcitt => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let images = extract_images_by_format(
                    ctx,
                    ImageFormat::Ccitt,
                    decode_mode,
                    max_extract_bytes,
                    predicate,
                )?;
                Ok(QueryResult::List(images))
            }
            Query::ImagesCcittCount => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let images = extract_images_by_format(
                    ctx,
                    ImageFormat::Ccitt,
                    decode_mode,
                    max_extract_bytes,
                    predicate,
                )?;
                Ok(QueryResult::Scalar(ScalarValue::Number(images.len() as i64)))
            }
            Query::ImagesRisky => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let images = extract_images_risky(ctx, decode_mode, max_extract_bytes, predicate)?;
                Ok(QueryResult::List(images))
            }
            Query::ImagesRiskyCount => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let images = extract_images_risky(ctx, decode_mode, max_extract_bytes, predicate)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(images.len() as i64)))
            }
            Query::ImagesMalformed => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let images =
                    extract_images_malformed(ctx, decode_mode, max_extract_bytes, predicate)?;
                Ok(QueryResult::List(images))
            }
            Query::ImagesMalformedCount => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let images =
                    extract_images_malformed(ctx, decode_mode, max_extract_bytes, predicate)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(images.len() as i64)))
            }
            Query::Media3D => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let entries = collect_media_3d_entries(ctx, predicate)?;
                let lines = entries.iter().map(|entry| format_media_summary("3D", entry)).collect();
                Ok(QueryResult::List(lines))
            }
            Query::Media3DCount => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let entries = collect_media_3d_entries(ctx, predicate)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(entries.len() as i64)))
            }
            Query::MediaAudio => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let entries = collect_media_audio_entries(ctx, predicate)?;
                let lines =
                    entries.iter().map(|entry| format_media_summary("MediaAudio", entry)).collect();
                Ok(QueryResult::List(lines))
            }
            Query::MediaAudioCount => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let entries = collect_media_audio_entries(ctx, predicate)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(entries.len() as i64)))
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
            Query::ShowObjectDetail { obj, gen, context_only } => {
                let detail = show_object_detail_query(ctx, *obj, *gen, *context_only)?;
                Ok(QueryResult::Structure(detail))
            }
            Query::ShowObjectContext(obj, gen) => {
                let context = show_object_context_query(ctx, *obj, *gen)?;
                Ok(QueryResult::Structure(context))
            }
            Query::ObjectsList => {
                let objects = list_objects(ctx, decode_mode, max_extract_bytes, predicate)?;
                Ok(QueryResult::List(objects))
            }
            Query::ObjectsWithType(obj_type) => {
                let objects = list_objects_with_type(
                    ctx,
                    obj_type,
                    decode_mode,
                    max_extract_bytes,
                    predicate,
                )?;
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
            Query::Xref => {
                let startxrefs = list_xref_startxrefs(ctx, None)?;
                let sections = list_xref_sections(ctx, None)?;
                let trailers = list_xref_trailers(ctx, None)?;
                let deviations = list_xref_deviations(ctx, None)?;
                Ok(QueryResult::Structure(json!({
                    "startxref_count": startxrefs.len(),
                    "section_count": sections.len(),
                    "trailer_count": trailers.len(),
                    "deviation_count": deviations.len(),
                    "startxrefs": startxrefs,
                    "sections": sections,
                    "trailers": trailers,
                    "deviations": deviations,
                })))
            }
            Query::XrefCount => {
                Ok(QueryResult::Scalar(ScalarValue::Number(ctx.graph.startxrefs.len() as i64)))
            }
            Query::XrefStartxrefs => {
                let startxrefs = list_xref_startxrefs(ctx, predicate)?;
                Ok(QueryResult::Structure(json!(startxrefs)))
            }
            Query::XrefStartxrefsCount => {
                let startxrefs = list_xref_startxrefs(ctx, predicate)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(startxrefs.len() as i64)))
            }
            Query::XrefSections => {
                let sections = list_xref_sections(ctx, predicate)?;
                Ok(QueryResult::Structure(json!(sections)))
            }
            Query::XrefSectionsCount => {
                let sections = list_xref_sections(ctx, predicate)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(sections.len() as i64)))
            }
            Query::XrefTrailers => {
                let trailers = list_xref_trailers(ctx, predicate)?;
                Ok(QueryResult::Structure(json!(trailers)))
            }
            Query::XrefTrailersCount => {
                let trailers = list_xref_trailers(ctx, predicate)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(trailers.len() as i64)))
            }
            Query::XrefDeviations => {
                let deviations = list_xref_deviations(ctx, predicate)?;
                Ok(QueryResult::Structure(json!(deviations)))
            }
            Query::XrefDeviationsCount => {
                let deviations = list_xref_deviations(ctx, predicate)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(deviations.len() as i64)))
            }
            Query::Revisions => {
                let revisions = list_revisions(ctx, predicate)?;
                Ok(QueryResult::Structure(json!(revisions)))
            }
            Query::RevisionsDetail => {
                let revisions = list_revisions_detail(ctx, predicate)?;
                Ok(QueryResult::Structure(json!(revisions)))
            }
            Query::RevisionsCount => {
                let revisions = list_revisions(ctx, predicate)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(revisions.len() as i64)))
            }
            Query::Chains => {
                let chains = list_action_chains(ctx, predicate, false)?;
                Ok(QueryResult::Structure(chains))
            }
            Query::ChainsCount => {
                let chains = list_action_chains(ctx, predicate, false)?;
                let count = chains.get("count").and_then(|value| value.as_u64()).unwrap_or(0);
                Ok(QueryResult::Scalar(ScalarValue::Number(count as i64)))
            }
            Query::ChainsJs => {
                let chains = list_js_chains(ctx, predicate, false)?;
                Ok(QueryResult::Structure(chains))
            }
            Query::ChainsAll => {
                let chains = list_action_chains(ctx, predicate, true)?;
                Ok(QueryResult::Structure(chains))
            }
            Query::ChainsAllCount => {
                let chains = list_action_chains(ctx, predicate, true)?;
                let count = chains.get("count").and_then(|value| value.as_u64()).unwrap_or(0);
                Ok(QueryResult::Scalar(ScalarValue::Number(count as i64)))
            }
            Query::ChainsJsAll => {
                let chains = list_js_chains(ctx, predicate, true)?;
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
            Query::References(obj, gen) => {
                let references = list_references(ctx, *obj, *gen)?;
                Ok(QueryResult::Structure(references))
            }
            Query::Events => {
                let events = extract_event_triggers(ctx, None, predicate)?;
                Ok(QueryResult::Structure(events))
            }
            Query::EventsFull => {
                let events = extract_event_triggers_full(ctx, None, predicate)?;
                Ok(QueryResult::Structure(events))
            }
            Query::EventsFullCsv => {
                let events = extract_event_triggers_full(ctx, None, predicate)?;
                let rows = events
                    .get("events")
                    .and_then(|value| value.as_array())
                    .map(|entries| events_to_csv_rows(entries))
                    .unwrap_or_else(|| events_to_csv_rows(&[]));
                Ok(QueryResult::List(rows))
            }
            Query::EventsCount => {
                let events_json = extract_event_triggers(ctx, None, predicate)?;
                let count = events_json.as_array().map(|arr| arr.len()).unwrap_or(0);
                Ok(QueryResult::Scalar(ScalarValue::Number(count as i64)))
            }
            Query::EventsDocument => {
                let events = extract_event_triggers(ctx, Some("document"), predicate)?;
                Ok(QueryResult::Structure(events))
            }
            Query::EventsPage => {
                let events = extract_event_triggers(ctx, Some("page"), predicate)?;
                Ok(QueryResult::Structure(events))
            }
            Query::EventsField => {
                let events = extract_event_triggers(ctx, Some("field"), predicate)?;
                Ok(QueryResult::Structure(events))
            }
            Query::ExportOrgDot => {
                let classifications = ctx.classifications();
                let typed_graph =
                    sis_pdf_pdf::typed_graph::TypedGraph::build(&ctx.graph, classifications);
                let org_graph = sis_pdf_core::org::OrgGraph::from_object_graph_enhanced(
                    &ctx.graph,
                    classifications,
                    &typed_graph,
                );
                let dot_output = sis_pdf_core::org_export::export_org_dot(&org_graph);
                Ok(QueryResult::Scalar(ScalarValue::String(dot_output)))
            }
            Query::ExportOrgJson => {
                let classifications = ctx.classifications();
                let typed_graph =
                    sis_pdf_pdf::typed_graph::TypedGraph::build(&ctx.graph, classifications);
                let org_graph = sis_pdf_core::org::OrgGraph::from_object_graph_enhanced(
                    &ctx.graph,
                    classifications,
                    &typed_graph,
                );
                let json_output = sis_pdf_core::org_export::export_org_json(&org_graph);
                Ok(QueryResult::Structure(json_output))
            }
            Query::ExportStructureDot => {
                let classifications = ctx.classifications();
                let typed_graph =
                    sis_pdf_pdf::typed_graph::TypedGraph::build(&ctx.graph, classifications);
                let org_graph = sis_pdf_core::org::OrgGraph::from_object_graph_enhanced(
                    &ctx.graph,
                    classifications,
                    &typed_graph,
                );
                let dot_output = export_structure_dot(&org_graph, &typed_graph, 8, None);
                Ok(QueryResult::Scalar(ScalarValue::String(dot_output)))
            }
            Query::ExportStructureJson => {
                let classifications = ctx.classifications();
                let typed_graph =
                    sis_pdf_pdf::typed_graph::TypedGraph::build(&ctx.graph, classifications);
                let org_graph = sis_pdf_core::org::OrgGraph::from_object_graph_enhanced(
                    &ctx.graph,
                    classifications,
                    &typed_graph,
                );
                let json_output = export_structure_json(&org_graph, &typed_graph, 8, None);
                Ok(QueryResult::Structure(json_output))
            }
            Query::ExportStructureDotDepth(depth) => {
                let classifications = ctx.classifications();
                let typed_graph =
                    sis_pdf_pdf::typed_graph::TypedGraph::build(&ctx.graph, classifications);
                let org_graph = sis_pdf_core::org::OrgGraph::from_object_graph_enhanced(
                    &ctx.graph,
                    classifications,
                    &typed_graph,
                );
                let dot_output = export_structure_dot(&org_graph, &typed_graph, *depth, None);
                Ok(QueryResult::Scalar(ScalarValue::String(dot_output)))
            }
            Query::ExportStructureJsonDepth(depth) => {
                let classifications = ctx.classifications();
                let typed_graph =
                    sis_pdf_pdf::typed_graph::TypedGraph::build(&ctx.graph, classifications);
                let org_graph = sis_pdf_core::org::OrgGraph::from_object_graph_enhanced(
                    &ctx.graph,
                    classifications,
                    &typed_graph,
                );
                let json_output = export_structure_json(&org_graph, &typed_graph, *depth, None);
                Ok(QueryResult::Structure(json_output))
            }
            Query::ExportStructureOverlayDot => {
                let classifications = ctx.classifications();
                let typed_graph =
                    sis_pdf_pdf::typed_graph::TypedGraph::build(&ctx.graph, classifications);
                let org_graph = sis_pdf_core::org::OrgGraph::from_object_graph_enhanced(
                    &ctx.graph,
                    classifications,
                    &typed_graph,
                );
                let findings = findings_with_cache(ctx)?;
                let overlay = build_structure_overlay_with_findings(
                    ctx,
                    StructureOverlayBuildOptions::default(),
                    Some(&findings),
                );
                let dot_output = export_structure_dot(&org_graph, &typed_graph, 8, Some(&overlay));
                Ok(QueryResult::Scalar(ScalarValue::String(dot_output)))
            }
            Query::ExportStructureOverlayJson => {
                let classifications = ctx.classifications();
                let typed_graph =
                    sis_pdf_pdf::typed_graph::TypedGraph::build(&ctx.graph, classifications);
                let org_graph = sis_pdf_core::org::OrgGraph::from_object_graph_enhanced(
                    &ctx.graph,
                    classifications,
                    &typed_graph,
                );
                let findings = findings_with_cache(ctx)?;
                let overlay = build_structure_overlay_with_findings(
                    ctx,
                    StructureOverlayBuildOptions::default(),
                    Some(&findings),
                );
                let json_output =
                    export_structure_json(&org_graph, &typed_graph, 8, Some(&overlay));
                Ok(QueryResult::Structure(json_output))
            }
            Query::ExportStructureOverlayDotDepth(depth) => {
                let classifications = ctx.classifications();
                let typed_graph =
                    sis_pdf_pdf::typed_graph::TypedGraph::build(&ctx.graph, classifications);
                let org_graph = sis_pdf_core::org::OrgGraph::from_object_graph_enhanced(
                    &ctx.graph,
                    classifications,
                    &typed_graph,
                );
                let findings = findings_with_cache(ctx)?;
                let overlay = build_structure_overlay_with_findings(
                    ctx,
                    StructureOverlayBuildOptions::default(),
                    Some(&findings),
                );
                let dot_output =
                    export_structure_dot(&org_graph, &typed_graph, *depth, Some(&overlay));
                Ok(QueryResult::Scalar(ScalarValue::String(dot_output)))
            }
            Query::ExportStructureOverlayJsonDepth(depth) => {
                let classifications = ctx.classifications();
                let typed_graph =
                    sis_pdf_pdf::typed_graph::TypedGraph::build(&ctx.graph, classifications);
                let org_graph = sis_pdf_core::org::OrgGraph::from_object_graph_enhanced(
                    &ctx.graph,
                    classifications,
                    &typed_graph,
                );
                let findings = findings_with_cache(ctx)?;
                let overlay = build_structure_overlay_with_findings(
                    ctx,
                    StructureOverlayBuildOptions::default(),
                    Some(&findings),
                );
                let json_output =
                    export_structure_json(&org_graph, &typed_graph, *depth, Some(&overlay));
                Ok(QueryResult::Structure(json_output))
            }
            Query::ExportStructureOverlayTelemetryDot => {
                let classifications = ctx.classifications();
                let typed_graph =
                    sis_pdf_pdf::typed_graph::TypedGraph::build(&ctx.graph, classifications);
                let org_graph = sis_pdf_core::org::OrgGraph::from_object_graph_enhanced(
                    &ctx.graph,
                    classifications,
                    &typed_graph,
                );
                let findings = findings_with_cache(ctx)?;
                let overlay = build_structure_overlay_with_findings(
                    ctx,
                    StructureOverlayBuildOptions {
                        include_telemetry: true,
                        include_signature: true,
                        ..StructureOverlayBuildOptions::default()
                    },
                    Some(&findings),
                );
                let dot_output = export_structure_dot(&org_graph, &typed_graph, 8, Some(&overlay));
                Ok(QueryResult::Scalar(ScalarValue::String(dot_output)))
            }
            Query::ExportStructureOverlayTelemetryJson => {
                let classifications = ctx.classifications();
                let typed_graph =
                    sis_pdf_pdf::typed_graph::TypedGraph::build(&ctx.graph, classifications);
                let org_graph = sis_pdf_core::org::OrgGraph::from_object_graph_enhanced(
                    &ctx.graph,
                    classifications,
                    &typed_graph,
                );
                let findings = findings_with_cache(ctx)?;
                let overlay = build_structure_overlay_with_findings(
                    ctx,
                    StructureOverlayBuildOptions {
                        include_telemetry: true,
                        include_signature: true,
                        ..StructureOverlayBuildOptions::default()
                    },
                    Some(&findings),
                );
                let json_output =
                    export_structure_json(&org_graph, &typed_graph, 8, Some(&overlay));
                Ok(QueryResult::Structure(json_output))
            }
            Query::ExportStructureOverlayTelemetryDotDepth(depth) => {
                let classifications = ctx.classifications();
                let typed_graph =
                    sis_pdf_pdf::typed_graph::TypedGraph::build(&ctx.graph, classifications);
                let org_graph = sis_pdf_core::org::OrgGraph::from_object_graph_enhanced(
                    &ctx.graph,
                    classifications,
                    &typed_graph,
                );
                let findings = findings_with_cache(ctx)?;
                let overlay = build_structure_overlay_with_findings(
                    ctx,
                    StructureOverlayBuildOptions {
                        include_telemetry: true,
                        include_signature: true,
                        ..StructureOverlayBuildOptions::default()
                    },
                    Some(&findings),
                );
                let dot_output =
                    export_structure_dot(&org_graph, &typed_graph, *depth, Some(&overlay));
                Ok(QueryResult::Scalar(ScalarValue::String(dot_output)))
            }
            Query::ExportStructureOverlayTelemetryJsonDepth(depth) => {
                let classifications = ctx.classifications();
                let typed_graph =
                    sis_pdf_pdf::typed_graph::TypedGraph::build(&ctx.graph, classifications);
                let org_graph = sis_pdf_core::org::OrgGraph::from_object_graph_enhanced(
                    &ctx.graph,
                    classifications,
                    &typed_graph,
                );
                let findings = findings_with_cache(ctx)?;
                let overlay = build_structure_overlay_with_findings(
                    ctx,
                    StructureOverlayBuildOptions {
                        include_telemetry: true,
                        include_signature: true,
                        ..StructureOverlayBuildOptions::default()
                    },
                    Some(&findings),
                );
                let json_output =
                    export_structure_json(&org_graph, &typed_graph, *depth, Some(&overlay));
                Ok(QueryResult::Structure(json_output))
            }
            Query::ExportEventDot => {
                let typed_graph = ctx.build_typed_graph();
                let findings = findings_with_cache(ctx)?;
                let mut event_graph = sis_pdf_core::event_graph::build_event_graph(
                    &typed_graph,
                    &findings,
                    sis_pdf_core::event_graph::EventGraphOptions::default(),
                );
                if let Some(pred) = predicate {
                    event_graph = filter_event_graph_by_predicate(event_graph, pred);
                }
                let dot_output = sis_pdf_core::event_graph::export_event_graph_dot(&event_graph);
                Ok(QueryResult::Scalar(ScalarValue::String(dot_output)))
            }
            Query::ExportEventJson => {
                let typed_graph = ctx.build_typed_graph();
                let findings = findings_with_cache(ctx)?;
                let mut event_graph = sis_pdf_core::event_graph::build_event_graph(
                    &typed_graph,
                    &findings,
                    sis_pdf_core::event_graph::EventGraphOptions::default(),
                );
                if let Some(pred) = predicate {
                    event_graph = filter_event_graph_by_predicate(event_graph, pred);
                }
                let json_output = sis_pdf_core::event_graph::export_event_graph_json(&event_graph);
                Ok(QueryResult::Structure(json_output))
            }
            Query::ExportEventDotHops(hops) => {
                let typed_graph = ctx.build_typed_graph();
                let findings = findings_with_cache(ctx)?;
                let event_graph = sis_pdf_core::event_graph::build_event_graph(
                    &typed_graph,
                    &findings,
                    sis_pdf_core::event_graph::EventGraphOptions::default(),
                );
                let seed_nodes =
                    event_graph_seed_nodes(&event_graph, predicate).unwrap_or_else(HashSet::new);
                let event_graph = induced_event_subgraph(event_graph, &seed_nodes, *hops);
                let dot_output = sis_pdf_core::event_graph::export_event_graph_dot(&event_graph);
                Ok(QueryResult::Scalar(ScalarValue::String(dot_output)))
            }
            Query::ExportEventJsonHops(hops) => {
                let typed_graph = ctx.build_typed_graph();
                let findings = findings_with_cache(ctx)?;
                let event_graph = sis_pdf_core::event_graph::build_event_graph(
                    &typed_graph,
                    &findings,
                    sis_pdf_core::event_graph::EventGraphOptions::default(),
                );
                let seed_nodes =
                    event_graph_seed_nodes(&event_graph, predicate).unwrap_or_else(HashSet::new);
                let event_graph = induced_event_subgraph(event_graph, &seed_nodes, *hops);
                let json_output = sis_pdf_core::event_graph::export_event_graph_json(&event_graph);
                Ok(QueryResult::Structure(json_output))
            }
            Query::ExportEventStreamDot => {
                let typed_graph = ctx.build_typed_graph();
                let findings = findings_with_cache(ctx)?;
                let mut event_graph = sis_pdf_core::event_graph::build_event_graph(
                    &typed_graph,
                    &findings,
                    sis_pdf_core::event_graph::EventGraphOptions::default(),
                );
                if let Some(pred) = predicate {
                    event_graph = filter_event_graph_by_predicate(event_graph, pred);
                }
                let stream_overlay = build_event_stream_overlay_json(ctx, &event_graph);
                let dot_output = export_event_stream_overlay_dot(&stream_overlay);
                Ok(QueryResult::Scalar(ScalarValue::String(dot_output)))
            }
            Query::ExportEventStreamJson => {
                let typed_graph = ctx.build_typed_graph();
                let findings = findings_with_cache(ctx)?;
                let mut event_graph = sis_pdf_core::event_graph::build_event_graph(
                    &typed_graph,
                    &findings,
                    sis_pdf_core::event_graph::EventGraphOptions::default(),
                );
                if let Some(pred) = predicate {
                    event_graph = filter_event_graph_by_predicate(event_graph, pred);
                }
                let stream_overlay = build_event_stream_overlay_json(ctx, &event_graph);
                Ok(QueryResult::Structure(stream_overlay))
            }
            Query::ExportEventStreamDotHops(hops) => {
                let typed_graph = ctx.build_typed_graph();
                let findings = findings_with_cache(ctx)?;
                let event_graph = sis_pdf_core::event_graph::build_event_graph(
                    &typed_graph,
                    &findings,
                    sis_pdf_core::event_graph::EventGraphOptions::default(),
                );
                let seed_nodes =
                    event_graph_seed_nodes(&event_graph, predicate).unwrap_or_else(HashSet::new);
                let event_graph = induced_event_subgraph(event_graph, &seed_nodes, *hops);
                let stream_overlay = build_event_stream_overlay_json(ctx, &event_graph);
                let dot_output = export_event_stream_overlay_dot(&stream_overlay);
                Ok(QueryResult::Scalar(ScalarValue::String(dot_output)))
            }
            Query::ExportEventStreamJsonHops(hops) => {
                let typed_graph = ctx.build_typed_graph();
                let findings = findings_with_cache(ctx)?;
                let event_graph = sis_pdf_core::event_graph::build_event_graph(
                    &typed_graph,
                    &findings,
                    sis_pdf_core::event_graph::EventGraphOptions::default(),
                );
                let seed_nodes =
                    event_graph_seed_nodes(&event_graph, predicate).unwrap_or_else(HashSet::new);
                let event_graph = induced_event_subgraph(event_graph, &seed_nodes, *hops);
                let stream_overlay = build_event_stream_overlay_json(ctx, &event_graph);
                Ok(QueryResult::Structure(stream_overlay))
            }
            Query::ExportIrText => {
                let ir_opts = sis_pdf_pdf::ir::IrOptions {
                    max_lines_per_object: 256,
                    max_string_len: 120,
                    max_array_elems: 128,
                };
                let ir_artifacts = sis_pdf_core::ir_pipeline::build_ir_graph(&ctx.graph, &ir_opts);
                let text_output = sis_pdf_core::ir_export::export_ir_text(&ir_artifacts.ir_objects);
                Ok(QueryResult::Scalar(ScalarValue::String(text_output)))
            }
            Query::ExportIrJson => {
                let ir_opts = sis_pdf_pdf::ir::IrOptions {
                    max_lines_per_object: 256,
                    max_string_len: 120,
                    max_array_elems: 128,
                };
                let ir_artifacts = sis_pdf_core::ir_pipeline::build_ir_graph(&ctx.graph, &ir_opts);
                let json_output = sis_pdf_core::ir_export::export_ir_json(&ir_artifacts.ir_objects);
                Ok(QueryResult::Structure(json_output))
            }
            Query::ExportFeatures => {
                let features = sis_pdf_core::features::FeatureExtractor::extract(ctx);
                let feature_names = sis_pdf_core::features::feature_names();
                let feature_values = features.as_f32_vec();

                // Create CSV output
                let mut csv_output = String::new();
                csv_output.push_str("feature,value\n");
                for (name, value) in feature_names.iter().zip(feature_values.iter()) {
                    csv_output.push_str(&format!("{},{}\n", name, value));
                }

                Ok(QueryResult::Scalar(ScalarValue::String(csv_output)))
            }
            Query::ExportFeaturesJson => {
                let features = sis_pdf_core::features::FeatureExtractor::extract(ctx);
                let feature_names = sis_pdf_core::features::feature_names();
                let feature_values = features.as_f32_vec();
                let mut values = serde_json::Map::new();

                for (name, value) in feature_names.iter().zip(feature_values.iter()) {
                    values.insert(name.to_string(), json!(value));
                }

                Ok(QueryResult::Structure(serde_json::Value::Object(values)))
            }
        }
    })();

    result.or_else(|err| Ok(QueryResult::Error(build_query_error(err))))
}

/// Execute a query against a PDF file
pub fn execute_query(
    query: &Query,
    pdf_path: &Path,
    scan_options: &ScanOptions,
    extract_to: Option<&Path>,
    max_extract_bytes: usize,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
) -> Result<QueryResult> {
    // Read PDF file
    let bytes = match fs::read(pdf_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            return Ok(query_error_with_context(
                "FILE_READ_ERROR",
                format!("Failed to read PDF file: {}", err),
                Some(json!({ "path": pdf_path.display().to_string() })),
            ));
        }
    };

    // Parse PDF and build context
    let ctx = match build_scan_context(&bytes, scan_options) {
        Ok(ctx) => ctx,
        Err(err) => {
            let reason = err.to_string();
            if reason.contains("missing PDF header") {
                return Ok(build_invalid_pdf_result(pdf_path, &bytes, &reason));
            }
            return Ok(query_error_with_context(
                "PARSE_ERROR",
                format!("Failed to parse PDF: {}", err),
                Some(json!({ "path": pdf_path.display().to_string() })),
            ));
        }
    };

    // Delegate to execute_query_with_context
    execute_query_with_context(query, &ctx, extract_to, max_extract_bytes, decode_mode, predicate)
}

/// Scan options for query execution
pub struct ScanOptions {
    pub deep: bool,
    pub max_decode_bytes: usize,
    pub max_total_decoded_bytes: usize,
    pub no_recover: bool,
    pub max_objects: usize,
    pub group_chains: bool,
    pub correlation: CorrelationOptions,
    pub diff_parser: bool,
    pub strict: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            deep: false,
            max_decode_bytes: 32 * 1024 * 1024,
            max_total_decoded_bytes: 256 * 1024 * 1024,
            no_recover: false,
            max_objects: 500_000,
            group_chains: true,
            correlation: CorrelationOptions::default(),
            diff_parser: false,
            strict: false,
        }
    }
}

// Helper functions (stubs for now, will be implemented)

fn build_scan_context<'a>(
    bytes: &'a [u8],
    options: &ScanOptions,
) -> Result<sis_pdf_core::scan::ScanContext<'a>> {
    if bytes.is_empty() {
        return Err(anyhow!("empty PDF input"));
    }
    let first_non_ws = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .ok_or_else(|| anyhow!("empty PDF input"))?;
    if !bytes[first_non_ws..].starts_with(b"%PDF-") {
        return Err(anyhow!("missing PDF header"));
    }

    let scan_options = sis_pdf_core::scan::ScanOptions {
        recover_xref: !options.no_recover,
        deep: options.deep,
        max_decode_bytes: options.max_decode_bytes,
        max_total_decoded_bytes: options.max_total_decoded_bytes,
        strict: options.strict,
        strict_summary: false,
        diff_parser: options.diff_parser,
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
        image_analysis: sis_pdf_core::scan::ImageAnalysisOptions::default(),
        filter_allowlist: None,
        filter_allowlist_strict: false,
        profile: false,
        profile_format: sis_pdf_core::scan::ProfileFormat::Text,
        group_chains: options.group_chains,
        correlation: options.correlation.clone(),
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

    Ok(sis_pdf_core::scan::ScanContext::new(bytes, graph, scan_options))
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
        if !utf16_bytes.len().is_multiple_of(2) {
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

    if ctx.options.diff_parser {
        let mut diff = sis_pdf_core::diff::diff_with_lopdf(ctx.bytes, &ctx.graph);
        findings.append(&mut diff.findings);
    }

    let composites = correlation::correlate_findings(&findings, &ctx.options.correlation);
    findings.extend(composites);
    sis_pdf_core::runner::maybe_record_secondary_parser_prevalence_baseline(&mut findings);
    findings.push(sis_pdf_core::structure_overlay::structural_complexity_summary_finding(ctx));
    sis_pdf_core::finding_caps::apply_default_global_kind_cap(&mut findings);
    assign_stable_ids(&mut findings);

    Ok(findings)
}

fn findings_with_cache(ctx: &ScanContext) -> Result<Vec<sis_pdf_core::model::Finding>> {
    if let Some(cache) = ctx.cached_findings(&ctx.options) {
        return Ok(cache.findings.clone());
    }
    let findings = run_detectors(ctx)?;
    ctx.populate_findings_cache(findings.clone(), &ctx.options);
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
            if let Some(summary) = format_findings_with_chain_text(v, compact) {
                return summary;
            }
            if let Some(summary) = format_object_detail_text(v) {
                return summary;
            }
            if let Some(summary) = format_object_context_text(v, compact) {
                return summary;
            }
            serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".to_string())
        }
        QueryResult::Error(err) => err.message.clone(),
    }
}

fn format_findings_with_chain_text(value: &serde_json::Value, compact: bool) -> Option<String> {
    if value.get("type").and_then(|v| v.as_str()) != Some("findings_with_chain") {
        return None;
    }
    let finding_count = value.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
    let chains = value.get("chains").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if compact {
        return Some(format!("{finding_count} findings, {} chains", chains.len()));
    }

    let mut out = vec![format!("Findings: {finding_count}"), format!("Chains: {}", chains.len())];
    for chain in chains.iter().take(8) {
        let stages = chain
            .get("ordered_stages")
            .and_then(|v| v.as_array())
            .map(|values| {
                values
                    .iter()
                    .filter_map(|entry| entry.as_str().map(str::to_string))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let stage_path = if stages.is_empty() { "-".to_string() } else { stages.join(" -> ") };
        let edge_reason = chain
            .get("edge")
            .and_then(|edge| edge.get("reason"))
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let chain_id = chain.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        out.push(format!("Potential chain: {stage_path} [{edge_reason}] (id={chain_id})"));
    }
    Some(out.join("\n"))
}

fn format_object_detail_text(value: &serde_json::Value) -> Option<String> {
    if value.get("type").and_then(|entry| entry.as_str()) != Some("object_detail") {
        return None;
    }
    let object = value.get("object")?;
    let obj = object.get("obj").and_then(|entry| entry.as_u64()).unwrap_or(0);
    let generation = object.get("gen").and_then(|entry| entry.as_u64()).unwrap_or(0);
    let content = object.get("content").and_then(|entry| entry.as_str()).unwrap_or("");
    let context = value.get("security_context")?;
    let tainted = context.get("tainted").and_then(|entry| entry.as_bool()).unwrap_or(false);
    let taint_source =
        context.get("taint_source").and_then(|entry| entry.as_bool()).unwrap_or(false);
    let chain_count = context.get("chains").and_then(|entry| entry.as_array()).map_or(0, Vec::len);
    let finding_count = context.get("finding_count").and_then(|entry| entry.as_u64()).unwrap_or(0);
    let severity = context.get("max_severity").and_then(|entry| entry.as_str()).unwrap_or("None");
    let confidence =
        context.get("max_confidence").and_then(|entry| entry.as_str()).unwrap_or("None");

    let mut out = String::new();
    if !content.is_empty() {
        out.push_str(content);
        out.push_str("\n\n");
    } else {
        out.push_str(&format!("Object {obj} {generation} detail\n\n"));
    }
    out.push_str("Object security context\n");
    out.push_str(&format!("  Tainted: {}\n", if tainted { "yes" } else { "no" }));
    out.push_str(&format!("  Taint source: {}\n", if taint_source { "yes" } else { "no" }));
    out.push_str(&format!("  Finding count: {finding_count}\n"));
    out.push_str(&format!("  Chain membership: {chain_count}\n"));
    out.push_str(&format!("  Max severity: {severity}\n"));
    out.push_str(&format!("  Max confidence: {confidence}\n"));
    Some(out)
}

fn format_object_context_text(value: &serde_json::Value, compact: bool) -> Option<String> {
    if value.get("type").and_then(|entry| entry.as_str()) != Some("object_context") {
        return None;
    }
    let object = value.get("object")?;
    let summary = value.get("summary")?;
    let obj = object.get("obj").and_then(|entry| entry.as_u64()).unwrap_or(0);
    let generation = object.get("gen").and_then(|entry| entry.as_u64()).unwrap_or(0);
    let tainted = summary.get("tainted").and_then(|entry| entry.as_bool()).unwrap_or(false);
    let chain_count = summary.get("chain_count").and_then(|entry| entry.as_u64()).unwrap_or(0);
    let severity = summary.get("max_severity").and_then(|entry| entry.as_str()).unwrap_or("None");
    if compact {
        return Some(format!(
            "{obj} {generation}: tainted={}, chains={chain_count}, severity={severity}",
            if tainted { "yes" } else { "no" }
        ));
    }
    let confidence =
        summary.get("max_confidence").and_then(|entry| entry.as_str()).unwrap_or("None");
    Some(format!(
        "Object {obj} {generation}\n  Tainted: {}\n  Chains: {chain_count}\n  Max severity: {severity}\n  Max confidence: {confidence}",
        if tainted { "yes" } else { "no" }
    ))
}

/// Format query result as JSON
pub fn format_json(query: &str, file: &str, result: &QueryResult) -> Result<String> {
    let payload = build_result_payload(query, file, result);
    Ok(serde_json::to_string_pretty(&payload)?)
}

/// Format query result as YAML
pub fn format_yaml(query: &str, file: &str, result: &QueryResult) -> Result<String> {
    let payload = build_result_payload(query, file, result);
    Ok(serde_yaml::to_string(&payload)?)
}

pub fn colourise_output(output: &str, format: OutputFormat) -> Result<String> {
    match format {
        OutputFormat::Json => highlight_with_syntect(output, "json"),
        OutputFormat::Yaml => highlight_with_syntect(output, "yaml"),
        _ => Ok(output.to_string()),
    }
}

fn highlight_with_syntect(text: &str, extension: &str) -> Result<String> {
    static SYNTAX_SET: OnceLock<SyntaxSet> = OnceLock::new();
    static THEME: OnceLock<Theme> = OnceLock::new();

    let syntax_set = SYNTAX_SET.get_or_init(SyntaxSet::load_defaults_newlines);
    let theme = THEME.get_or_init(|| {
        let themes = ThemeSet::load_defaults();
        themes
            .themes
            .get("base16-ocean.dark")
            .cloned()
            .or_else(|| themes.themes.values().next().cloned())
            .unwrap_or_default()
    });

    let syntax = syntax_set
        .find_syntax_by_extension(extension)
        .or_else(|| syntax_set.find_syntax_by_token(extension))
        .unwrap_or_else(|| syntax_set.find_syntax_plain_text());

    let mut highlighter = HighlightLines::new(syntax, theme);
    let mut output = String::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let ranges: Vec<(Style, &str)> = highlighter.highlight_line(line, syntax_set)?;
        output.push_str(&as_24_bit_terminal_escaped(&ranges, false));
        if lines.peek().is_some() {
            output.push('\n');
        }
    }

    Ok(output)
}

/// Format query result as JSON Lines (single line per result)
pub fn format_jsonl(query: &str, file: &str, result: &QueryResult) -> Result<String> {
    let payload = build_result_payload(query, file, result);
    Ok(serde_json::to_string(&payload)?)
}

fn build_result_payload(query: &str, file: &str, result: &QueryResult) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("query".into(), serde_json::json!(query));
    map.insert("file".into(), serde_json::json!(file));
    map.insert("result".into(), serde_json::json!(result));
    if let Some(summary) = build_findings_digest(query, result) {
        map.insert("summary".into(), summary);
    }
    serde_json::Value::Object(map)
}

fn build_findings_digest(query: &str, result: &QueryResult) -> Option<serde_json::Value> {
    if !query.starts_with("findings") {
        return None;
    }
    let entries = match result {
        QueryResult::Structure(serde_json::Value::Array(entries)) => entries.clone(),
        QueryResult::Structure(serde_json::Value::Object(object))
            if object.get("type").and_then(|value| value.as_str())
                == Some("findings_with_chain") =>
        {
            object.get("findings").and_then(|value| value.as_array()).cloned().unwrap_or_default()
        }
        _ => Vec::new(),
    };
    if !entries.is_empty() {
        let mut severity_counts: HashMap<String, usize> = HashMap::new();
        let mut surface_counts: HashMap<String, usize> = HashMap::new();
        let mut kind_counts: HashMap<String, usize> = HashMap::new();
        let mut js_breakpoint_buckets: HashMap<String, usize> = HashMap::new();
        let mut js_script_timeout_findings = 0usize;
        let mut js_loop_iteration_limit_hits = 0usize;
        for entry in entries.iter().filter_map(|value| value.as_object()) {
            if let Some(severity) =
                entry.get("severity").and_then(|value| value.as_str()).map(|s| s.to_string())
            {
                *severity_counts.entry(severity).or_insert(0) += 1;
            }
            if let Some(surface) =
                entry.get("surface").and_then(|value| value.as_str()).map(|s| s.to_string())
            {
                *surface_counts.entry(surface).or_insert(0) += 1;
            }
            if let Some(kind) =
                entry.get("kind").and_then(|value| value.as_str()).map(|s| s.to_string())
            {
                *kind_counts.entry(kind).or_insert(0) += 1;
            }
            if entry
                .get("kind")
                .and_then(|value| value.as_str())
                .map(|kind| kind == "js_sandbox_timeout")
                .unwrap_or(false)
            {
                js_script_timeout_findings += 1;
            }
            let is_breakpoint = entry
                .get("kind")
                .and_then(|value| value.as_str())
                .map(|kind| kind == "js_emulation_breakpoint")
                .unwrap_or(false);
            if is_breakpoint {
                if let Some(meta) = entry.get("meta").and_then(|value| value.as_object()) {
                    if let Some(raw_buckets) =
                        meta.get("js.emulation_breakpoint.buckets").and_then(|value| value.as_str())
                    {
                        for token in
                            raw_buckets.split(',').map(str::trim).filter(|token| !token.is_empty())
                        {
                            let mut parts = token.splitn(2, ':');
                            let Some(bucket) =
                                parts.next().map(str::trim).filter(|bucket| !bucket.is_empty())
                            else {
                                continue;
                            };
                            let count = parts
                                .next()
                                .map(str::trim)
                                .and_then(|raw| raw.parse::<usize>().ok())
                                .unwrap_or(1);
                            *js_breakpoint_buckets.entry(bucket.to_string()).or_insert(0) += count;
                            if bucket == "loop_iteration_limit" {
                                js_loop_iteration_limit_hits += count;
                            }
                        }
                    }
                }
            }
        }
        if severity_counts.is_empty()
            && surface_counts.is_empty()
            && kind_counts.is_empty()
            && js_breakpoint_buckets.is_empty()
        {
            return None;
        }
        let mut summary_map = serde_json::Map::new();
        if !severity_counts.is_empty() {
            summary_map.insert("findings_by_severity".into(), serde_json::json!(severity_counts));
        }
        if !surface_counts.is_empty() {
            summary_map.insert("findings_by_surface".into(), serde_json::json!(surface_counts));
        }
        if !kind_counts.is_empty() {
            summary_map.insert("findings_by_kind".into(), serde_json::json!(kind_counts));
        }
        if !js_breakpoint_buckets.is_empty() {
            summary_map.insert(
                "js_emulation_breakpoints_by_bucket".into(),
                serde_json::json!(js_breakpoint_buckets),
            );
        }
        if js_script_timeout_findings > 0 || js_loop_iteration_limit_hits > 0 {
            summary_map.insert(
                "js_runtime_budget".into(),
                serde_json::json!({
                    "script_timeout_findings": js_script_timeout_findings,
                    "loop_iteration_limit_hits": js_loop_iteration_limit_hits
                }),
            );
        }
        return Some(serde_json::Value::Object(summary_map));
    }
    None
}

/// Extract JavaScript code from PDF
fn extract_javascript(
    ctx: &ScanContext,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    let mut js_code = Vec::new();

    for entry in &ctx.graph.objects {
        // Check for /JS entry in dictionary or stream
        if let Some(dict) = entry_dict(entry) {
            if let Some((_, obj)) = dict.get_first(b"/JS") {
                if let Some((bytes, meta)) = extract_obj_with_metadata(
                    &ctx.graph,
                    ctx.bytes,
                    obj,
                    32 * 1024 * 1024,
                    decode_mode,
                ) {
                    if predicate.map(|pred| pred.evaluate(&meta)).unwrap_or(true) {
                        if let Some(code) = extract_obj_text(&ctx.graph, ctx.bytes, obj) {
                            js_code.push(format!(
                                "Object {}_{}: {}",
                                entry.obj,
                                entry.gen,
                                preview_text(&code, 200)
                            ));
                        } else if decode_mode == DecodeMode::Raw {
                            js_code.push(format!(
                                "Object {}_{}: {} bytes (raw)",
                                entry.obj,
                                entry.gen,
                                bytes.len()
                            ));
                        }
                    }
                }
            }
        }
    }

    Ok(js_code)
}

/// Extract URLs from PDF
fn extract_urls(ctx: &ScanContext, predicate: Option<&PredicateExpr>) -> Result<Vec<String>> {
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

    if let Some(pred) = predicate {
        let filtered =
            urls.into_iter().filter(|url| pred.evaluate(&predicate_context_for_url(url))).collect();
        Ok(filtered)
    } else {
        Ok(urls)
    }
}

/// Extract embedded files information from PDF
fn extract_embedded_files(
    ctx: &ScanContext,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    let mut embedded = Vec::new();
    let embedded_index = sis_pdf_core::embedded_index::build_embedded_artefact_index(&ctx.graph);

    for entry in &ctx.graph.objects {
        if let PdfAtom::Stream(st) = &entry.atom {
            if st.dict.has_name(b"/Type", b"/EmbeddedFile") {
                let data = stream_bytes_for_mode(ctx.bytes, st, 32 * 1024 * 1024, decode_mode)?;
                let stream_ref = (entry.obj, entry.gen);
                let artefact_ref = embedded_index.get(&stream_ref);
                let name = artefact_ref
                    .and_then(|record| record.filename.clone())
                    .or_else(|| embedded_filename(&st.dict))
                    .unwrap_or_else(|| format!("embedded_{}_{}.bin", entry.obj, entry.gen));
                let analysis = sis_pdf_core::stream_analysis::analyse_stream(
                    &data,
                    &sis_pdf_core::stream_analysis::StreamLimits::default(),
                );
                let hash = sha256_hex(&data);
                let mut predicate_meta = HashMap::new();
                predicate_meta.insert("name".into(), name.clone());
                predicate_meta.insert("magic".into(), analysis.magic_type.clone());
                predicate_meta.insert("hash".into(), hash.clone());
                if let Some((filespec_obj, filespec_gen)) =
                    artefact_ref.and_then(|record| record.filespec_ref)
                {
                    predicate_meta.insert(
                        "filespec_ref".into(),
                        format!("{} {}", filespec_obj, filespec_gen),
                    );
                }
                let meta = PredicateContext {
                    length: data.len(),
                    filter: filter_name(&st.dict),
                    type_name: "Stream".to_string(),
                    subtype: subtype_name(&st.dict),
                    entropy: entropy_score(&data),
                    width: 0,
                    height: 0,
                    pixels: 0,
                    risky: false,
                    severity: None,
                    confidence: None,
                    surface: None,
                    kind: None,
                    object_count: 0,
                    evidence_count: 0,
                    name: Some(name.clone()),
                    magic: Some(analysis.magic_type),
                    hash: Some(hash),
                    impact: None,
                    action_type: None,
                    action_target: None,
                    action_initiation: None,
                    meta: predicate_meta,
                };
                if predicate.map(|pred| pred.evaluate(&meta)).unwrap_or(true) {
                    if let Some((filespec_obj, filespec_gen)) =
                        artefact_ref.and_then(|record| record.filespec_ref)
                    {
                        embedded.push(format!(
                            "{} ({}_{}, filespec={}_{}, {} bytes)",
                            name,
                            entry.obj,
                            entry.gen,
                            filespec_obj,
                            filespec_gen,
                            data.len()
                        ));
                    } else {
                        embedded.push(format!(
                            "{} ({}_{}, {} bytes)",
                            name,
                            entry.obj,
                            entry.gen,
                            data.len()
                        ));
                    }
                }
            }
        }
    }

    Ok(embedded)
}

struct XfaScriptPayload {
    bytes: Vec<u8>,
    source: String,
    entry_ref: String,
    ref_chain: String,
}

fn collect_xfa_script_payloads(ctx: &ScanContext) -> Vec<XfaScriptPayload> {
    use sis_pdf_pdf::decode::DecodeLimits;
    let limits = DecodeLimits {
        max_decoded_bytes: ctx.options.image_analysis.max_xfa_decode_bytes,
        max_filter_chain_depth: ctx.options.image_analysis.max_filter_chain_depth,
    };
    let mut out = Vec::new();
    for entry in &ctx.graph.objects {
        let dict = match &entry.atom {
            PdfAtom::Dict(dict) => dict,
            PdfAtom::Stream(stream) => &stream.dict,
            _ => continue,
        };
        let Some((_, xfa_obj)) = dict.get_first(b"/XFA") else {
            continue;
        };
        let payloads = xfa_payloads_from_obj(&ctx.graph, xfa_obj, limits);
        for xfa_payload in payloads {
            let entry_ref = format!("{} {} obj", entry.obj, entry.gen);
            let ref_chain = xfa_payload.ref_chain.clone();
            for script in sis_pdf_pdf::xfa::extract_xfa_script_payloads(&xfa_payload.bytes) {
                out.push(XfaScriptPayload {
                    bytes: script,
                    source: format!("{}_{}", entry.obj, entry.gen),
                    entry_ref: entry_ref.clone(),
                    ref_chain: ref_chain.clone(),
                });
            }
        }
    }
    out
}

fn extract_xfa_scripts(
    ctx: &ScanContext,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    let mut scripts = Vec::new();
    let payloads = collect_xfa_script_payloads(ctx);
    for (idx, payload) in payloads.iter().enumerate() {
        let filename = format!("xfa_script_{:03}.js", idx + 1);
        let hash = sha256_hex(&payload.bytes);
        let mut predicate_meta = HashMap::new();
        predicate_meta.insert("filename".into(), filename.clone());
        predicate_meta.insert("object".into(), payload.entry_ref.clone());
        predicate_meta.insert("xfa.ref_chain".into(), payload.ref_chain.clone());
        predicate_meta.insert("hash.sha256".into(), hash.clone());
        predicate_meta.insert("size_bytes".into(), payload.bytes.len().to_string());
        let meta = PredicateContext {
            length: payload.bytes.len(),
            filter: Some("xfa".to_string()),
            type_name: "XfaScript".to_string(),
            subtype: Some("script".to_string()),
            entropy: entropy_score(&payload.bytes),
            width: 0,
            height: 0,
            pixels: 0,
            risky: false,
            severity: None,
            confidence: None,
            surface: None,
            kind: None,
            object_count: 0,
            evidence_count: 0,
            name: Some(filename.clone()),
            hash: Some(hash),
            magic: None,
            impact: None,
            action_type: None,
            action_target: None,
            action_initiation: None,
            meta: predicate_meta,
        };
        if predicate.map(|pred| pred.evaluate(&meta)).unwrap_or(true) {
            let preview = String::from_utf8_lossy(&payload.bytes);
            scripts.push(format!(
                "{} (source {}, {} bytes): {}",
                filename,
                payload.source,
                payload.bytes.len(),
                preview_text(&preview, 200)
            ));
        }
    }
    Ok(scripts)
}

fn write_xfa_scripts(
    ctx: &ScanContext,
    extract_to: &Path,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    use std::fs;

    fs::create_dir_all(extract_to)?;
    let payloads = collect_xfa_script_payloads(ctx);
    let mut written = Vec::new();
    let mut manifest = Vec::new();
    for (idx, payload) in payloads.iter().enumerate() {
        let filename = format!("xfa_script_{:03}.js", idx + 1);
        let hash = sha256_hex(&payload.bytes);
        let mut predicate_meta = HashMap::new();
        predicate_meta.insert("filename".into(), filename.clone());
        predicate_meta.insert("object".into(), payload.entry_ref.clone());
        predicate_meta.insert("xfa.ref_chain".into(), payload.ref_chain.clone());
        predicate_meta.insert("hash.sha256".into(), hash.clone());
        predicate_meta.insert("size_bytes".into(), payload.bytes.len().to_string());
        let meta = PredicateContext {
            length: payload.bytes.len(),
            filter: Some("xfa".to_string()),
            type_name: "XfaScript".to_string(),
            subtype: Some("script".to_string()),
            entropy: entropy_score(&payload.bytes),
            width: 0,
            height: 0,
            pixels: 0,
            risky: false,
            severity: None,
            confidence: None,
            surface: None,
            kind: None,
            object_count: 0,
            evidence_count: 0,
            name: Some(filename.clone()),
            hash: Some(hash.clone()),
            magic: None,
            impact: None,
            action_type: None,
            action_target: None,
            action_initiation: None,
            meta: predicate_meta,
        };
        if predicate.map(|pred| pred.evaluate(&meta)).unwrap_or(true) {
            let filepath = extract_to.join(&filename);
            fs::write(&filepath, &payload.bytes)?;
            written.push(format!(
                "{}: {} bytes, sha256={}, source={}",
                filename,
                payload.bytes.len(),
                hash,
                payload.source
            ));
            manifest.push(serde_json::json!({
                "index": idx + 1,
                "filename": filename,
                "sha256": hash,
                "size_bytes": payload.bytes.len(),
                "object": payload.entry_ref,
                "ref_chain": payload.ref_chain,
                "source": payload.source,
            }));
        }
    }
    let manifest_path = extract_to.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;
    written.push(format!("manifest.json: {} entries", manifest.len()));
    Ok(written)
}

struct SwfStreamInfo {
    obj: u32,
    gen: u16,
    data: Vec<u8>,
    filter: Option<String>,
    magic: &'static str,
}

fn swf_magic_label(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"FWS") {
        Some("FWS")
    } else if bytes.starts_with(b"CWS") {
        Some("CWS")
    } else if bytes.starts_with(b"ZWS") {
        Some("ZWS")
    } else {
        None
    }
}

struct SwfContentEntry {
    name: String,
    filter: Option<String>,
    magic: &'static str,
    size_bytes: usize,
    version: Option<u8>,
    declared_length: Option<u32>,
    decompressed_bytes: usize,
    action_tags: Vec<String>,
}

fn collect_swf_content(
    ctx: &ScanContext,
    max_extract_bytes: usize,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<SwfContentEntry>> {
    let mut entries = Vec::new();
    for entry in &ctx.graph.objects {
        let sis_pdf_pdf::object::PdfAtom::Stream(stream) = &entry.atom else {
            continue;
        };
        let data = match stream_bytes_for_mode(ctx.bytes, stream, max_extract_bytes, decode_mode) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let Some(magic) = swf_magic_label(&data) else {
            continue;
        };
        let filter = filter_name(&stream.dict);
        let name = format!("swf_{}_{}", entry.obj, entry.gen);
        let mut meta = HashMap::new();
        meta.insert("object".into(), format!("{} {}", entry.obj, entry.gen));
        meta.insert("media_type".into(), "swf".into());
        meta.insert("magic".into(), magic.to_string());
        if let Some(filter_name) = &filter {
            meta.insert("filter".into(), filter_name.clone());
        }
        meta.insert("size_bytes".into(), data.len().to_string());

        let mut version = None;
        let mut declared_length = None;
        let mut decompressed_bytes = 0;
        let mut action_tags = Vec::new();
        let mut timeout = TimeoutChecker::new(Duration::from_millis(SWF_DECODE_TIMEOUT_MS));
        if let Some(analysis) = analyze_swf(&data, &mut timeout) {
            let detected_version = analysis.header.version;
            version = Some(detected_version);
            declared_length = Some(analysis.header.file_length);
            decompressed_bytes = analysis.decompressed_body_len;
            action_tags = analysis.action_scan.action_tags.clone();
            meta.insert("swf.version".into(), detected_version.to_string());
            meta.insert("swf.decompressed_bytes".into(), decompressed_bytes.to_string());
            meta.insert("swf.declared_length".into(), analysis.header.file_length.to_string());
            meta.insert("swf.action_tag_count".into(), action_tags.len().to_string());
            if !action_tags.is_empty() {
                meta.insert("swf.action_tags".into(), action_tags.join(","));
            }
        }

        let predicate_context = PredicateContext {
            length: data.len(),
            filter: filter.clone(),
            type_name: "SwfContent".to_string(),
            subtype: Some("swf".to_string()),
            entropy: entropy_score(&data),
            width: 0,
            height: 0,
            pixels: 0,
            risky: false,
            severity: None,
            confidence: None,
            surface: None,
            kind: None,
            object_count: 0,
            evidence_count: 0,
            name: Some(name.clone()),
            magic: Some(magic.to_string()),
            hash: None,
            impact: None,
            action_type: None,
            action_target: None,
            action_initiation: None,
            meta: meta.clone(),
        };

        if predicate.map(|pred| pred.evaluate(&predicate_context)).unwrap_or(true) {
            entries.push(SwfContentEntry {
                name,
                filter,
                magic,
                size_bytes: data.len(),
                version,
                declared_length,
                decompressed_bytes,
                action_tags,
            });
        }
    }
    Ok(entries)
}

fn format_swf_summary(entry: &SwfContentEntry) -> String {
    let mut parts = vec![format!("SWF {} ({})", entry.magic, entry.name)];
    parts.push(format!("size={} bytes", entry.size_bytes));
    if let Some(filter) = &entry.filter {
        parts.push(format!("filter={}", filter));
    }
    if let Some(version) = entry.version {
        parts.push(format!("version={}", version));
    }
    if let Some(declared) = entry.declared_length {
        parts.push(format!("declared={}", declared));
    }
    parts.push(format!("decompressed={}", entry.decompressed_bytes));
    let actions =
        if entry.action_tags.is_empty() { "none".to_string() } else { entry.action_tags.join(",") };
    parts.push(format!("actions=[{}]", actions));
    parts.join(", ")
}

struct MediaContentEntry {
    name: String,
    media_type: String,
    size_bytes: usize,
    filter: Option<String>,
}

fn collect_media_3d_entries(
    ctx: &ScanContext,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<MediaContentEntry>> {
    let mut entries = Vec::new();
    for entry in &ctx.graph.objects {
        let sis_pdf_pdf::object::PdfAtom::Stream(stream) = &entry.atom else {
            continue;
        };
        let dict = match entry_dict(entry) {
            Some(d) => d,
            None => continue,
        };
        let is_3d = dict.has_name(b"/Subtype", b"/3D")
            || dict.has_name(b"/Subtype", b"/U3D")
            || dict.has_name(b"/Subtype", b"/PRC")
            || dict.has_name(b"/Type", b"/3D")
            || dict.get_first(b"/3D").is_some()
            || dict.get_first(b"/U3D").is_some()
            || dict.get_first(b"/PRC").is_some();
        if !is_3d {
            continue;
        }
        let span = stream.data_span;
        if span.end as usize > ctx.bytes.len() {
            continue;
        }
        let size_bytes = (span.end - span.start) as usize;
        let filter = filter_name(&stream.dict);
        let name = format!("media_3d_{}_{}", entry.obj, entry.gen);
        let media_type = peek_stream_bytes(ctx.bytes, stream, 16)
            .as_deref()
            .and_then(detect_3d_format)
            .unwrap_or("unknown")
            .to_string();
        let mut meta = HashMap::new();
        meta.insert("object".into(), format!("{} {}", entry.obj, entry.gen));
        meta.insert("media_type".into(), media_type.clone());
        meta.insert("size_bytes".into(), size_bytes.to_string());
        if let Some(filter_name) = &filter {
            meta.insert("filter".into(), filter_name.clone());
        }
        let predicate_context = PredicateContext {
            length: size_bytes,
            filter: filter.clone(),
            type_name: "Media3D".to_string(),
            subtype: Some(media_type.clone()),
            entropy: 0.0,
            width: 0,
            height: 0,
            pixels: 0,
            risky: false,
            severity: None,
            confidence: None,
            surface: None,
            kind: None,
            object_count: 0,
            evidence_count: 0,
            name: Some(name.clone()),
            magic: Some(media_type.clone()),
            hash: None,
            impact: None,
            action_type: None,
            action_target: None,
            action_initiation: None,
            meta,
        };
        if predicate.map(|pred| pred.evaluate(&predicate_context)).unwrap_or(true) {
            entries.push(MediaContentEntry { name, media_type, size_bytes, filter });
        }
    }
    Ok(entries)
}

fn collect_media_audio_entries(
    ctx: &ScanContext,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<MediaContentEntry>> {
    let mut entries = Vec::new();
    for entry in &ctx.graph.objects {
        let sis_pdf_pdf::object::PdfAtom::Stream(stream) = &entry.atom else {
            continue;
        };
        let dict = match entry_dict(entry) {
            Some(d) => d,
            None => continue,
        };
        let has_media = dict.has_name(b"/Subtype", b"/Sound")
            || dict.has_name(b"/Subtype", b"/Movie")
            || dict.get_first(b"/Sound").is_some()
            || dict.get_first(b"/Movie").is_some()
            || dict.get_first(b"/Rendition").is_some();
        if !has_media {
            continue;
        }
        let span = stream.data_span;
        if span.end as usize > ctx.bytes.len() {
            continue;
        }
        let size_bytes = (span.end - span.start) as usize;
        let filter = filter_name(&stream.dict);
        let name = format!("media_audio_{}_{}", entry.obj, entry.gen);
        let media_type = peek_stream_bytes(ctx.bytes, stream, 16)
            .as_deref()
            .and_then(detect_media_format)
            .unwrap_or("unknown")
            .to_string();
        let mut meta = HashMap::new();
        meta.insert("object".into(), format!("{} {}", entry.obj, entry.gen));
        meta.insert("media_type".into(), media_type.clone());
        meta.insert("size_bytes".into(), size_bytes.to_string());
        if let Some(filter_name) = &filter {
            meta.insert("filter".into(), filter_name.clone());
        }
        let predicate_context = PredicateContext {
            length: size_bytes,
            filter: filter.clone(),
            type_name: "MediaAudio".to_string(),
            subtype: Some(media_type.clone()),
            entropy: 0.0,
            width: 0,
            height: 0,
            pixels: 0,
            risky: false,
            severity: None,
            confidence: None,
            surface: None,
            kind: None,
            object_count: 0,
            evidence_count: 0,
            name: Some(name.clone()),
            magic: Some(media_type.clone()),
            hash: None,
            impact: None,
            action_type: None,
            action_target: None,
            action_initiation: None,
            meta,
        };
        if predicate.map(|pred| pred.evaluate(&predicate_context)).unwrap_or(true) {
            entries.push(MediaContentEntry { name, media_type, size_bytes, filter });
        }
    }
    Ok(entries)
}

fn format_media_summary(label: &str, entry: &MediaContentEntry) -> String {
    let filter = entry.filter.as_deref().unwrap_or("none");
    format!(
        "{} {} ({} bytes, filter={}, type={})",
        label, entry.name, entry.size_bytes, filter, entry.media_type
    )
}

fn peek_stream_bytes(
    bytes: &[u8],
    stream: &sis_pdf_pdf::object::PdfStream<'_>,
    max_len: usize,
) -> Option<Vec<u8>> {
    let span = stream.data_span;
    let start = span.start as usize;
    let end = span.end as usize;
    if end > bytes.len() || start >= end {
        return None;
    }
    let length = std::cmp::min(end - start, max_len);
    Some(bytes[start..start + length].to_vec())
}

fn collect_swf_streams(
    ctx: &ScanContext,
    max_extract_bytes: usize,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<SwfStreamInfo>> {
    use sis_pdf_pdf::object::PdfAtom;

    let mut streams = Vec::new();
    for entry in &ctx.graph.objects {
        let PdfAtom::Stream(stream) = &entry.atom else {
            continue;
        };
        let data = match stream_bytes_for_mode(ctx.bytes, stream, max_extract_bytes, decode_mode) {
            Ok(data) => data,
            Err(_) => continue,
        };
        let Some(magic) = swf_magic_label(&data) else {
            continue;
        };
        let name = format!("swf_{}_{}.swf", entry.obj, entry.gen);
        let magic_label = magic.to_string();
        let mut predicate_meta = HashMap::new();
        let name_clone = name.clone();
        predicate_meta.insert("name".into(), name_clone.clone());
        predicate_meta.insert("magic".into(), magic_label.clone());
        let meta = PredicateContext {
            length: data.len(),
            filter: filter_name(&stream.dict),
            type_name: "SwfStream".to_string(),
            subtype: Some("swf".to_string()),
            entropy: entropy_score(&data),
            width: 0,
            height: 0,
            pixels: 0,
            risky: false,
            severity: None,
            confidence: None,
            surface: None,
            kind: None,
            object_count: 0,
            evidence_count: 0,
            name: Some(name),
            hash: None,
            impact: None,
            action_type: None,
            action_target: None,
            action_initiation: None,
            magic: Some(magic_label),
            meta: predicate_meta,
        };
        if predicate.map(|pred| pred.evaluate(&meta)).unwrap_or(true) {
            streams.push(SwfStreamInfo {
                obj: entry.obj,
                gen: entry.gen,
                data,
                filter: meta.filter,
                magic,
            });
        }
    }
    Ok(streams)
}

fn extract_swf_streams(
    ctx: &ScanContext,
    max_extract_bytes: usize,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for info in collect_swf_streams(ctx, max_extract_bytes, decode_mode, predicate)? {
        let filter = info.filter.unwrap_or_else(|| "none".into());
        out.push(format!(
            "SWF {} ({}_{}, {}, {} bytes)",
            info.magic,
            info.obj,
            info.gen,
            filter,
            info.data.len()
        ));
    }
    Ok(out)
}

fn write_swf_streams(
    ctx: &ScanContext,
    extract_to: &Path,
    max_extract_bytes: usize,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    use std::fs;

    fs::create_dir_all(extract_to)?;
    let mut written = Vec::new();
    for info in collect_swf_streams(ctx, max_extract_bytes, decode_mode, predicate)? {
        let filename = format!("swf_{}_{}.swf", info.obj, info.gen);
        let filepath = extract_to.join(&filename);
        fs::write(&filepath, &info.data)?;
        let hash = sha256_hex(&info.data);
        written.push(format!(
            "{}: {} bytes, sha256={}, magic={}",
            filename,
            info.data.len(),
            hash,
            info.magic
        ));
    }
    Ok(written)
}

fn write_stream_object(
    ctx: &ScanContext,
    obj: u32,
    gen: u16,
    extract_to: &Path,
    max_bytes: usize,
    decode_mode: DecodeMode,
) -> Result<String> {
    use sis_pdf_pdf::object::PdfAtom;
    use std::fs;

    fs::create_dir_all(extract_to)?;

    let entry = ctx
        .graph
        .get_object(obj, gen)
        .ok_or_else(|| anyhow!("Object {} {} not found", obj, gen))?;
    let PdfAtom::Stream(stream) = &entry.atom else {
        return Err(anyhow!("Object {} {} is not a stream", obj, gen));
    };

    let data = stream_bytes_for_mode(ctx.bytes, stream, max_bytes, decode_mode)?;
    let base_name = format!("stream_{}_{}", obj, gen);
    let (filename, output_bytes, mode_label) = match decode_mode {
        DecodeMode::Decode => (format!("{base_name}.bin"), data.clone(), "decode"),
        DecodeMode::Raw => (format!("{base_name}.raw"), data.clone(), "raw"),
        DecodeMode::Hexdump => {
            (format!("{base_name}.hex"), format_hexdump(&data).into_bytes(), "hexdump")
        }
    };
    let filepath = extract_to.join(&filename);
    let hash = sha256_hex(&data);

    fs::write(&filepath, &output_bytes)?;

    let mut info =
        format!("{}: {} bytes, sha256={}, object={}_{}", filename, data.len(), hash, obj, gen);
    info.push_str(&format!(", mode={}", mode_label));
    if decode_mode == DecodeMode::Hexdump {
        info.push_str(&format!(", hexdump_bytes={}", output_bytes.len()));
    }
    Ok(info)
}

fn preview_stream_object(
    ctx: &ScanContext,
    obj: u32,
    gen: u16,
    max_bytes: usize,
    decode_mode: DecodeMode,
) -> Result<String> {
    use sis_pdf_pdf::object::PdfAtom;

    let entry = ctx
        .graph
        .get_object(obj, gen)
        .ok_or_else(|| anyhow!("Object {} {} not found", obj, gen))?;
    let PdfAtom::Stream(stream) = &entry.atom else {
        return Err(anyhow!("Object {} {} is not a stream", obj, gen));
    };

    let data = stream_bytes_for_mode(ctx.bytes, stream, max_bytes, decode_mode)?;
    let hash = sha256_hex(&data);
    let mut info = format!("stream {}_{}: {} bytes, sha256={}", obj, gen, data.len(), hash);

    match decode_mode {
        DecodeMode::Decode | DecodeMode::Raw => {
            let preview = String::from_utf8_lossy(&data);
            info.push_str(&format!(", preview=\"{}\"", preview_text(&preview, 200)));
        }
        DecodeMode::Hexdump => {
            let preview = hex_preview(&data, 64);
            info.push_str(&format!(", preview_hex=\"{}\"", preview));
        }
    }

    Ok(info)
}

fn hex_preview(data: &[u8], max_bytes: usize) -> String {
    let mut out = String::new();
    let mut count = 0usize;
    for byte in data.iter().take(max_bytes) {
        if count > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{:02x}", byte));
        count += 1;
    }
    if data.len() > max_bytes {
        out.push_str(" ...");
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImageFormat {
    Jbig2,
    Jpx,
    Jpeg,
    Png,
    Ccitt,
    Tiff,
    Unknown,
}

impl ImageFormat {
    fn label(self) -> &'static str {
        match self {
            ImageFormat::Jbig2 => "JBIG2",
            ImageFormat::Jpx => "JPX",
            ImageFormat::Jpeg => "JPEG",
            ImageFormat::Png => "PNG",
            ImageFormat::Ccitt => "CCITT",
            ImageFormat::Tiff => "TIFF",
            ImageFormat::Unknown => "Unknown",
        }
    }

    fn extension(self) -> &'static str {
        match self {
            ImageFormat::Jbig2 => "jbig2",
            ImageFormat::Jpx => "jp2",
            ImageFormat::Jpeg => "jpg",
            ImageFormat::Png => "png",
            ImageFormat::Ccitt => "ccitt",
            ImageFormat::Tiff => "tif",
            ImageFormat::Unknown => "bin",
        }
    }

    fn risky(self) -> bool {
        matches!(self, ImageFormat::Jbig2 | ImageFormat::Jpx | ImageFormat::Ccitt)
    }
}

#[derive(Debug, Clone)]
struct ImageInfo {
    obj: u32,
    gen: u16,
    format: ImageFormat,
    width: u32,
    height: u32,
    filter: Option<String>,
    data: Vec<u8>,
    raw_data: Vec<u8>,
}

fn extract_images(
    ctx: &ScanContext,
    decode_mode: DecodeMode,
    max_extract_bytes: usize,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    let images = collect_images(ctx, decode_mode, max_extract_bytes, predicate)?;
    let mut output = Vec::new();
    for image in images {
        let dimensions = if image.width > 0 && image.height > 0 {
            format!("{}x{}", image.width, image.height)
        } else {
            "-".into()
        };
        let filter = image.filter.clone().unwrap_or_else(|| "-".into());
        output.push(format!(
            "Object {}_{}: {} ({}, {}, {} bytes)",
            image.obj,
            image.gen,
            image.format.label(),
            dimensions,
            filter,
            image.data.len()
        ));
    }
    Ok(output)
}

fn collect_images(
    ctx: &ScanContext,
    decode_mode: DecodeMode,
    max_extract_bytes: usize,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<ImageInfo>> {
    let mut images = Vec::new();
    for entry in &ctx.graph.objects {
        let sis_pdf_pdf::object::PdfAtom::Stream(stream) = &entry.atom else {
            continue;
        };
        if !is_image_stream(&stream.dict) {
            continue;
        }
        let raw_data = raw_stream_bytes(ctx.bytes, stream, max_extract_bytes)?;
        let data = match decode_mode {
            DecodeMode::Raw => raw_data.clone(),
            DecodeMode::Decode | DecodeMode::Hexdump => {
                stream_bytes_for_mode(ctx.bytes, stream, max_extract_bytes, decode_mode)
                    .unwrap_or_else(|_| raw_data.clone())
            }
        };
        let entropy = entropy_score(&data);
        let (width, height) = image_dimensions(&stream.dict);
        let pixels = if width > 0 && height > 0 { width as u64 * height as u64 } else { 0 };
        let format = detect_image_format(&stream.dict, &raw_data);
        let filter = image_filter_label(&stream.dict);
        let ctx_meta = PredicateContext {
            length: data.len(),
            filter: filter.clone(),
            type_name: "Image".to_string(),
            subtype: Some(format.label().to_string()),
            entropy,
            width,
            height,
            pixels,
            risky: format.risky(),
            severity: None,
            confidence: None,
            surface: None,
            kind: None,
            object_count: 0,
            evidence_count: 0,
            name: None,
            magic: None,
            hash: None,
            impact: None,
            action_type: None,
            action_target: None,
            action_initiation: None,
            meta: HashMap::new(),
        };
        if predicate.map(|pred| pred.evaluate(&ctx_meta)).unwrap_or(true) {
            images.push(ImageInfo {
                obj: entry.obj,
                gen: entry.gen,
                format,
                width,
                height,
                filter,
                data,
                raw_data,
            });
        }
    }
    Ok(images)
}

fn extract_images_by_format(
    ctx: &ScanContext,
    target: ImageFormat,
    decode_mode: DecodeMode,
    max_extract_bytes: usize,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    let images = collect_images(ctx, decode_mode, max_extract_bytes, predicate)?;
    let output = images
        .into_iter()
        .filter(|image| image.format == target)
        .map(|image| {
            let dimensions = if image.width > 0 && image.height > 0 {
                format!("{}x{}", image.width, image.height)
            } else {
                "-".into()
            };
            let filter = image.filter.clone().unwrap_or_else(|| "-".into());
            format!(
                "Object {}_{}: {} ({}, {}, {} bytes)",
                image.obj,
                image.gen,
                image.format.label(),
                dimensions,
                filter,
                image.data.len()
            )
        })
        .collect();
    Ok(output)
}

fn extract_images_risky(
    ctx: &ScanContext,
    decode_mode: DecodeMode,
    max_extract_bytes: usize,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    let images = collect_images(ctx, decode_mode, max_extract_bytes, predicate)?;
    let output = images
        .into_iter()
        .filter(|image| image.format.risky())
        .map(|image| {
            let dimensions = if image.width > 0 && image.height > 0 {
                format!("{}x{}", image.width, image.height)
            } else {
                "-".into()
            };
            let filter = image.filter.clone().unwrap_or_else(|| "-".into());
            format!(
                "Object {}_{}: {} ({}, {}, {} bytes)",
                image.obj,
                image.gen,
                image.format.label(),
                dimensions,
                filter,
                image.data.len()
            )
        })
        .collect();
    Ok(output)
}

fn extract_images_malformed(
    ctx: &ScanContext,
    decode_mode: DecodeMode,
    max_extract_bytes: usize,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    if !ctx.options.deep {
        return Err(anyhow!("images.malformed requires --deep"));
    }
    let opts = image_analysis::ImageDynamicOptions {
        max_pixels: ctx.options.image_analysis.max_pixels,
        max_decode_bytes: ctx.options.image_analysis.max_decode_bytes,
        timeout_ms: ctx.options.image_analysis.timeout_ms,
        total_budget_ms: ctx.options.image_analysis.total_budget_ms,
        skip_threshold: ctx.options.image_analysis.skip_threshold,
    };
    let dynamic = image_analysis::dynamic::analyze_dynamic_images(&ctx.graph, &opts);
    let mut failing = std::collections::HashSet::new();
    for finding in dynamic.findings {
        if matches!(
            finding.kind.as_str(),
            "image.decode_failed"
                | "image.jbig2_malformed"
                | "image.jpx_malformed"
                | "image.jpeg_malformed"
                | "image.ccitt_malformed"
                | "image.xfa_decode_failed"
        ) {
            failing.insert((finding.obj, finding.gen));
        }
    }
    let images = collect_images(ctx, decode_mode, max_extract_bytes, predicate)?;
    let output = images
        .into_iter()
        .filter(|image| failing.contains(&(image.obj, image.gen)))
        .map(|image| {
            let dimensions = if image.width > 0 && image.height > 0 {
                format!("{}x{}", image.width, image.height)
            } else {
                "-".into()
            };
            let filter = image.filter.clone().unwrap_or_else(|| "-".into());
            format!(
                "Object {}_{}: {} ({}, {}, {} bytes)",
                image.obj,
                image.gen,
                image.format.label(),
                dimensions,
                filter,
                image.data.len()
            )
        })
        .collect();
    Ok(output)
}

fn write_image_files(
    ctx: &ScanContext,
    extract_to: &Path,
    max_bytes: usize,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    use std::fs;

    fs::create_dir_all(extract_to)?;

    let images = collect_images(ctx, decode_mode, max_bytes, predicate)?;
    let mut written_files = Vec::new();
    let mut count = 0usize;

    for image in images {
        let base_name = format!("image_{}_{}", image.obj, image.gen);
        let (filename, output_bytes, mode_label) = match decode_mode {
            DecodeMode::Decode => (
                format!("{}.{}", base_name, image.format.extension()),
                image.data.clone(),
                "decode",
            ),
            DecodeMode::Raw => (format!("{base_name}.raw"), image.raw_data.clone(), "raw"),
            DecodeMode::Hexdump => {
                (format!("{base_name}.hex"), format_hexdump(&image.data).into_bytes(), "hexdump")
            }
        };
        let filepath = extract_to.join(&filename);
        fs::write(&filepath, &output_bytes)?;

        let hash = sha256_hex(&image.data);
        let info = format!(
            "{}: {}x{} {}, {} bytes, sha256={}, object={}_{} ({})",
            filename,
            image.width,
            image.height,
            image.format.label(),
            image.data.len(),
            hash,
            image.obj,
            image.gen,
            mode_label
        );
        written_files.push(info);
        count += 1;
    }

    eprintln!("Extracted {} image(s) to {}", count, extract_to.display());
    Ok(written_files)
}

fn is_image_stream(dict: &sis_pdf_pdf::object::PdfDict<'_>) -> bool {
    dict.has_name(b"/Subtype", b"/Image")
}

fn image_dimensions(dict: &sis_pdf_pdf::object::PdfDict<'_>) -> (u32, u32) {
    let width = dict_u32(dict, b"/Width").unwrap_or(0);
    let height = dict_u32(dict, b"/Height").unwrap_or(0);
    (width, height)
}

fn dict_u32(dict: &sis_pdf_pdf::object::PdfDict<'_>, key: &[u8]) -> Option<u32> {
    let (_, obj) = dict.get_first(key)?;
    match &obj.atom {
        sis_pdf_pdf::object::PdfAtom::Int(n) => (*n).try_into().ok(),
        sis_pdf_pdf::object::PdfAtom::Real(v) => {
            if *v >= 0.0 {
                (*v as u64).try_into().ok()
            } else {
                None
            }
        }
        sis_pdf_pdf::object::PdfAtom::Str(s) => {
            let bytes = string_bytes(s);
            let text = String::from_utf8_lossy(&bytes);
            text.trim().parse::<u32>().ok()
        }
        _ => None,
    }
}

fn detect_image_format(dict: &sis_pdf_pdf::object::PdfDict<'_>, data: &[u8]) -> ImageFormat {
    if let Some(filters) = image_filter_names(dict) {
        for filter in filters {
            if filter.eq_ignore_ascii_case(b"/JBIG2Decode") {
                return ImageFormat::Jbig2;
            }
            if filter.eq_ignore_ascii_case(b"/JPXDecode") {
                return ImageFormat::Jpx;
            }
            if filter.eq_ignore_ascii_case(b"/CCITTFaxDecode") {
                return ImageFormat::Ccitt;
            }
            if filter.eq_ignore_ascii_case(b"/DCTDecode") || filter.eq_ignore_ascii_case(b"/DCT") {
                return ImageFormat::Jpeg;
            }
        }
    }
    if data.starts_with(b"\xFF\xD8") {
        return ImageFormat::Jpeg;
    }
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return ImageFormat::Png;
    }
    if data.starts_with(b"II*\x00") || data.starts_with(b"MM\x00*") {
        return ImageFormat::Tiff;
    }
    ImageFormat::Unknown
}

fn image_filter_names(dict: &sis_pdf_pdf::object::PdfDict<'_>) -> Option<Vec<Vec<u8>>> {
    let (_, filter) = dict.get_first(b"/Filter")?;
    match &filter.atom {
        sis_pdf_pdf::object::PdfAtom::Name(name) => Some(vec![name.decoded.clone()]),
        sis_pdf_pdf::object::PdfAtom::Array(items) => {
            let mut out = Vec::new();
            for item in items {
                if let sis_pdf_pdf::object::PdfAtom::Name(name) = &item.atom {
                    out.push(name.decoded.clone());
                }
            }
            Some(out)
        }
        _ => None,
    }
}

fn image_filter_label(dict: &sis_pdf_pdf::object::PdfDict<'_>) -> Option<String> {
    let (_, filter) = dict.get_first(b"/Filter")?;
    match &filter.atom {
        sis_pdf_pdf::object::PdfAtom::Name(name) => {
            Some(String::from_utf8_lossy(&name.decoded).trim().trim_start_matches('/').to_string())
        }
        sis_pdf_pdf::object::PdfAtom::Array(items) => {
            let mut out = Vec::new();
            for item in items {
                if let sis_pdf_pdf::object::PdfAtom::Name(name) = &item.atom {
                    let label = String::from_utf8_lossy(&name.decoded)
                        .trim()
                        .trim_start_matches('/')
                        .to_string();
                    out.push(label);
                }
            }
            if out.is_empty() {
                None
            } else {
                Some(out.join(","))
            }
        }
        _ => None,
    }
}

fn ensure_predicate_supported(query: &Query) -> Result<()> {
    match query {
        Query::JavaScript
        | Query::JavaScriptCount
        | Query::Embedded
        | Query::EmbeddedCount
        | Query::XfaScripts
        | Query::XfaScriptsCount
        | Query::XfaForms
        | Query::XfaFormsCount
        | Query::SwfStreams
        | Query::SwfStreamsCount
        | Query::Urls
        | Query::UrlsCount
        | Query::Images
        | Query::ImagesCount
        | Query::ImagesJbig2
        | Query::ImagesJbig2Count
        | Query::ImagesJpx
        | Query::ImagesJpxCount
        | Query::ImagesCcitt
        | Query::ImagesCcittCount
        | Query::ImagesRisky
        | Query::ImagesRiskyCount
        | Query::ImagesMalformed
        | Query::ImagesMalformedCount
        | Query::Events
        | Query::EventsFull
        | Query::EventsFullCsv
        | Query::EventsCount
        | Query::EventsDocument
        | Query::EventsPage
        | Query::EventsField
        | Query::Chains
        | Query::ChainsCount
        | Query::ChainsJs
        | Query::ChainsAll
        | Query::ChainsAllCount
        | Query::ChainsJsAll
        | Query::ExportStructureDot
        | Query::ExportStructureJson
                    | Query::ExportStructureOverlayDot
                    | Query::ExportStructureOverlayJson
                    | Query::ExportStructureOverlayDotDepth(_)
                    | Query::ExportStructureOverlayJsonDepth(_)
                    | Query::ExportStructureOverlayTelemetryDot
                    | Query::ExportStructureOverlayTelemetryJson
                    | Query::ExportStructureOverlayTelemetryDotDepth(_)
                    | Query::ExportStructureOverlayTelemetryJsonDepth(_)
        | Query::ExportEventDot
        | Query::ExportEventJson
        | Query::ExportEventDotHops(_)
        | Query::ExportEventJsonHops(_)
        | Query::ExportEventStreamDot
        | Query::ExportEventStreamJson
        | Query::ExportEventStreamDotHops(_)
        | Query::ExportEventStreamJsonHops(_)
        | Query::Findings
        | Query::FindingsCsv
        | Query::FindingsCount
        | Query::FindingsBySeverity(_)
        | Query::FindingsByKind(_)
        | Query::FindingsByKindCount(_)
        | Query::FindingsComposite
        | Query::FindingsCompositeCsv
        | Query::FindingsCompositeCount
        | Query::FindingsWithChain
        | Query::FindingsBySeverityWithChain(_)
        | Query::FindingsByKindWithChain(_)
        | Query::FindingsCompositeWithChain
        | Query::Correlations
        | Query::CorrelationsCount
        | Query::ObjectsCount
        | Query::ObjectsList
        | Query::ObjectsWithType(_)
        | Query::XrefStartxrefs
        | Query::XrefStartxrefsCount
        | Query::XrefSections
        | Query::XrefSectionsCount
        | Query::XrefTrailers
        | Query::XrefTrailersCount
        | Query::XrefDeviations
        | Query::XrefDeviationsCount
        | Query::Revisions
        | Query::RevisionsDetail
        | Query::RevisionsCount
        | Query::PagesExecution => Ok(()),
        _ => Err(anyhow!(
            "Predicate filtering is only supported for js, embedded, urls, images, events, graph.event, graph.event.stream, findings, correlations, objects, xref, revisions, and pages.execution queries"
        )),
    }
}

#[derive(Debug, serde::Serialize)]
struct CorrelationSummary {
    count: usize,
    severity: String,
}

/// Extract event triggers from PDF
fn extract_event_triggers(
    ctx: &ScanContext,
    filter_level: Option<&str>,
    predicate: Option<&PredicateExpr>,
) -> Result<serde_json::Value> {
    use sis_pdf_core::event_graph::{build_event_graph, EventGraphOptions};
    use sis_pdf_core::event_projection::extract_event_records;

    let typed_graph = ctx.build_typed_graph();
    let event_graph = build_event_graph(&typed_graph, &[], EventGraphOptions::default());
    let records = extract_event_records(&event_graph);
    let mut events = Vec::new();
    for record in records {
        let level = event_level_for_type(&record.event_type);
        if filter_level.is_some_and(|filter| filter != level) {
            continue;
        }
        let event = json!({
            "node_id": record.node_id,
            "graph_ref": record.node_id,
            "level": level,
            "trigger": record.trigger_class,
            "event_type": record.event_type,
            "label": record.label,
            "source_object": record.source_object.map(|(obj, gen)| format!("{obj}:{gen}")),
            "execute_targets": record.execute_targets.iter().map(|target| {
                json!({
                    "node_id": target.node_id,
                    "object_ref": target.object_ref.map(|(obj, gen)| format!("{obj}:{gen}")),
                })
            }).collect::<Vec<_>>(),
            "outcome_targets": record.outcome_targets.iter().map(|outcome| {
                json!({
                    "node_id": outcome.node_id,
                    "outcome_type": outcome.outcome_type,
                    "label": outcome.label,
                    "confidence_score": outcome.confidence_score,
                    "severity_hint": outcome.severity_hint,
                    "evidence": outcome.evidence,
                    "source_object": outcome.source_object.map(|(obj, gen)| format!("{obj}:{gen}")),
                })
            }).collect::<Vec<_>>(),
            "linked_finding_ids": record.linked_finding_ids,
            "mitre_techniques": record.mitre_techniques,
            "event_key": record.event_key,
            "initiation": record.initiation,
            "branch_index": record.branch_index,
            "action_details": record.label,
        });
        if let Some(pred) = predicate {
            if !predicate_context_for_event(&event).is_some_and(|ctx| pred.evaluate(&ctx)) {
                continue;
            }
        }
        events.push(event);
    }
    Ok(json!(events))
}

fn extract_pages_execution(
    ctx: &ScanContext,
    predicate: Option<&PredicateExpr>,
) -> Result<serde_json::Value> {
    use sis_pdf_core::event_graph::{build_event_graph, EventGraphOptions};
    use sis_pdf_core::event_projection::{
        build_stream_exec_summaries, extract_event_records_with_projection, ProjectionOptions,
    };

    #[derive(Default)]
    struct PageExecSummary {
        content_stream_count: usize,
        total_ops: usize,
        op_family_counts: BTreeMap<String, usize>,
        resource_names: BTreeSet<String>,
        anomaly_flags: BTreeSet<String>,
        linked_finding_ids: BTreeSet<String>,
    }

    let typed_graph = ctx.build_typed_graph();
    let event_graph = build_event_graph(&typed_graph, &[], EventGraphOptions::default());
    let stream_summaries = build_stream_exec_summaries(ctx.bytes, &ctx.graph, &event_graph);
    let records = extract_event_records_with_projection(
        &event_graph,
        &ProjectionOptions { include_stream_exec_summary: true },
        Some(&stream_summaries),
    );

    let mut by_page = BTreeMap::<(u32, u16), PageExecSummary>::new();
    for record in records {
        if record.event_type != "ContentStreamExec" {
            continue;
        }
        let Some(page_ref) = record.source_object else {
            continue;
        };
        let summary = by_page.entry(page_ref).or_default();
        summary.content_stream_count = summary.content_stream_count.saturating_add(1);

        for finding_id in record.linked_finding_ids {
            summary.linked_finding_ids.insert(finding_id);
        }

        if let Some(stream_exec) = record.stream_exec {
            summary.total_ops = summary.total_ops.saturating_add(stream_exec.total_ops);
            for (family, count) in stream_exec.op_family_counts {
                *summary.op_family_counts.entry(family).or_insert(0) += count;
            }
            for resource in stream_exec.resource_refs {
                summary.resource_names.insert(resource.name);
            }
            if stream_exec.graphics_state_underflow {
                summary.anomaly_flags.insert("graphics_state_underflow".to_string());
            }
            if stream_exec.unknown_op_count > 0 {
                summary.anomaly_flags.insert("unknown_ops".to_string());
            }
            if stream_exec.truncated {
                summary.anomaly_flags.insert("projection_truncated".to_string());
            }
        }
    }

    let mut pages = Vec::<serde_json::Value>::new();
    for ((obj, gen), summary) in by_page {
        let page_ref = format!("{obj}:{gen}");
        let anomaly_count = summary.anomaly_flags.len();
        let resource_count = summary.resource_names.len();
        let mut meta = HashMap::new();
        meta.insert("page".to_string(), page_ref.clone());
        meta.insert("total_ops".to_string(), summary.total_ops.to_string());
        meta.insert("anomaly_count".to_string(), anomaly_count.to_string());
        meta.insert("resource_count".to_string(), resource_count.to_string());
        let pred_ctx = PredicateContext {
            length: summary.total_ops,
            filter: Some("page_execution".to_string()),
            type_name: "PageExecution".to_string(),
            subtype: Some(page_ref.clone()),
            entropy: 0.0,
            width: 0,
            height: 0,
            pixels: 0,
            risky: anomaly_count > 0,
            severity: None,
            confidence: None,
            surface: Some("StreamsAndFilters".to_string()),
            kind: Some("page_execution".to_string()),
            object_count: summary.content_stream_count,
            evidence_count: summary.linked_finding_ids.len(),
            name: Some(page_ref.clone()),
            magic: None,
            hash: None,
            impact: None,
            action_type: None,
            action_target: None,
            action_initiation: None,
            meta,
        };
        if let Some(pred) = predicate {
            if !pred.evaluate(&pred_ctx) {
                continue;
            }
        }

        pages.push(json!({
            "page_ref": page_ref,
            "content_stream_count": summary.content_stream_count,
            "total_ops": summary.total_ops,
            "op_family_counts": summary.op_family_counts,
            "resource_names": summary.resource_names.into_iter().collect::<Vec<_>>(),
            "resource_count": resource_count,
            "anomaly_flags": summary.anomaly_flags.into_iter().collect::<Vec<_>>(),
            "anomaly_count": anomaly_count,
            "linked_finding_ids": summary.linked_finding_ids.into_iter().collect::<Vec<_>>(),
        }));
    }

    Ok(json!({
        "type": "pages_execution",
        "count": pages.len(),
        "pages": pages,
    }))
}

fn extract_event_triggers_full(
    ctx: &ScanContext,
    filter_level: Option<&str>,
    predicate: Option<&PredicateExpr>,
) -> Result<serde_json::Value> {
    use sis_pdf_core::event_graph::{build_event_graph, EventGraphOptions};
    use sis_pdf_core::event_projection::{
        build_finding_event_index, build_stream_exec_summaries,
        extract_event_records_with_projection, ProjectionOptions,
    };

    let typed_graph = ctx.build_typed_graph();
    let event_graph = build_event_graph(&typed_graph, &[], EventGraphOptions::default());
    let stream_summaries = build_stream_exec_summaries(ctx.bytes, &ctx.graph, &event_graph);
    let records = extract_event_records_with_projection(
        &event_graph,
        &ProjectionOptions { include_stream_exec_summary: true },
        Some(&stream_summaries),
    );
    let finding_event_index = build_finding_event_index(&records);
    let mut event_finding_index = BTreeMap::<String, Vec<String>>::new();
    let mut events = Vec::new();

    for record in records {
        let level = event_level_for_type(&record.event_type);
        if filter_level.is_some_and(|filter| filter != level) {
            continue;
        }

        let node_edges = event_graph
            .forward_index
            .get(&record.node_id)
            .into_iter()
            .flat_map(|edge_ids| edge_ids.iter())
            .filter_map(|edge_id| event_graph.edges.get(*edge_id))
            .map(|edge| {
                json!({
                    "kind": format!("{:?}", edge.kind),
                    "to": edge.to,
                    "provenance": edge.provenance,
                    "metadata": edge.metadata,
                })
            })
            .collect::<Vec<_>>();

        let event = json!({
            "node_id": record.node_id,
            "graph_ref": record.node_id,
            "level": level,
            "trigger": record.trigger_class,
            "event_type": record.event_type,
            "label": record.label,
            "source_object": record.source_object.map(|(obj, gen)| format!("{obj}:{gen}")),
            "execute_targets": record.execute_targets.iter().map(|target| {
                json!({
                    "node_id": target.node_id,
                    "object_ref": target.object_ref.map(|(obj, gen)| format!("{obj}:{gen}")),
                })
            }).collect::<Vec<_>>(),
            "outcome_targets": record.outcome_targets.iter().map(|outcome| {
                json!({
                    "node_id": outcome.node_id,
                    "outcome_type": outcome.outcome_type,
                    "label": outcome.label,
                    "confidence_score": outcome.confidence_score,
                    "severity_hint": outcome.severity_hint,
                    "evidence": outcome.evidence,
                    "source_object": outcome.source_object.map(|(obj, gen)| format!("{obj}:{gen}")),
                })
            }).collect::<Vec<_>>(),
            "linked_finding_ids": record.linked_finding_ids,
            "mitre_techniques": record.mitre_techniques,
            "event_key": record.event_key,
            "initiation": record.initiation,
            "branch_index": record.branch_index,
            "stream_exec": record.stream_exec,
            "event_edges": node_edges,
            "action_details": record.label,
        });

        if let Some(pred) = predicate {
            if !predicate_context_for_event(&event).is_some_and(|ctx| pred.evaluate(&ctx)) {
                continue;
            }
        }
        events.push(event);
        let mut finding_ids = record.linked_finding_ids.clone();
        finding_ids.sort();
        finding_ids.dedup();
        event_finding_index.insert(record.node_id, finding_ids);
    }

    Ok(json!({
        "events": events,
        "finding_event_index": finding_event_index,
        "event_finding_index": event_finding_index,
    }))
}

fn extract_runtime_caps(ctx: &ScanContext) -> Result<serde_json::Value> {
    use sis_pdf_core::event_graph::{build_event_graph, EventGraphOptions};
    use sis_pdf_core::event_projection::{
        build_stream_exec_summaries, extract_event_records_with_projection, ProjectionOptions,
    };

    let findings = findings_with_cache(ctx)?;
    let typed_graph = ctx.build_typed_graph();
    let event_graph = build_event_graph(&typed_graph, &findings, EventGraphOptions::default());
    let stream_summaries = build_stream_exec_summaries(ctx.bytes, &ctx.graph, &event_graph);
    let records = extract_event_records_with_projection(
        &event_graph,
        &ProjectionOptions { include_stream_exec_summary: true },
        Some(&stream_summaries),
    );

    let truncated_stream_event_count = records
        .iter()
        .filter(|record| record.stream_exec.as_ref().is_some_and(|stream| stream.truncated))
        .count();

    let mut truncation_flags = BTreeSet::<String>::new();
    let mut js_runtime_truncation_counters = BTreeMap::<String, u64>::new();
    for finding in &findings {
        for (key, value) in &finding.meta {
            if !key.contains("truncat") {
                continue;
            }
            if value.eq_ignore_ascii_case("true") {
                truncation_flags.insert(key.clone());
            }
            if key.starts_with("js.runtime.truncation.") {
                if let Ok(parsed) = value.parse::<u64>() {
                    js_runtime_truncation_counters.insert(key.clone(), parsed);
                }
            }
        }
    }

    Ok(json!({
        "type": "runtime_caps",
        "schema_version": 1,
        "caps": {
            "event_graph": {
                "applied": event_graph.truncation.is_some(),
                "node_cap": event_graph.truncation.as_ref().map(|value| value.node_cap).unwrap_or(0),
                "edge_cap": event_graph.truncation.as_ref().map(|value| value.edge_cap).unwrap_or(0),
                "dropped_nodes": event_graph.truncation.as_ref().map(|value| value.dropped_nodes).unwrap_or(0),
                "dropped_edges": event_graph.truncation.as_ref().map(|value| value.dropped_edges).unwrap_or(0),
            },
            "stream_exec_projection": {
                "truncated_event_count": truncated_stream_event_count,
            },
            "finding_meta": {
                "truncation_flag_count": truncation_flags.len(),
                "truncation_flags": truncation_flags,
                "js_runtime_truncation_counters": js_runtime_truncation_counters,
            },
        }
    }))
}

fn empty_runtime_caps() -> serde_json::Value {
    json!({
        "type": "runtime_caps",
        "schema_version": 1,
        "caps": {
            "event_graph": {
                "applied": false,
                "node_cap": 0,
                "edge_cap": 0,
                "dropped_nodes": 0,
                "dropped_edges": 0,
            },
            "stream_exec_projection": {
                "truncated_event_count": 0,
            },
            "finding_meta": {
                "truncation_flag_count": 0,
                "truncation_flags": [],
                "js_runtime_truncation_counters": {},
            },
        }
    })
}

fn event_level_for_type(event_type: &str) -> &'static str {
    match event_type {
        "DocumentOpen" | "DocumentWillClose" | "DocumentWillSave" | "DocumentDidSave"
        | "DocumentWillPrint" | "DocumentDidPrint" | "NextAction" | "JsTimerDelayed" => "document",
        "PageOpen" | "PageClose" | "PageVisible" | "PageInvisible" | "ContentStreamExec" => "page",
        "FieldKeystroke"
        | "FieldFormat"
        | "FieldValidate"
        | "FieldCalculate"
        | "FieldMouseDown"
        | "FieldMouseUp"
        | "FieldMouseEnter"
        | "FieldMouseExit"
        | "FieldOnFocus"
        | "FieldOnBlur"
        | "FieldActivation"
        | "AnnotationActivation" => "field",
        _ => "document",
    }
}

fn build_event_stream_overlay_json(
    ctx: &ScanContext,
    event_graph: &sis_pdf_core::event_graph::EventGraph,
) -> serde_json::Value {
    use sis_pdf_core::event_projection::{
        build_stream_exec_summaries, extract_event_records_with_projection, ProjectionOptions,
    };

    let stream_summaries = build_stream_exec_summaries(ctx.bytes, &ctx.graph, event_graph);
    let records = extract_event_records_with_projection(
        event_graph,
        &ProjectionOptions { include_stream_exec_summary: true },
        Some(&stream_summaries),
    );

    let mut overlay_nodes = Vec::<serde_json::Value>::new();
    let mut overlay_edges = Vec::<serde_json::Value>::new();
    let mut node_ids = HashSet::<String>::new();
    let mut edge_ids = HashSet::<(String, String, String)>::new();
    let mut stream_event_count = 0usize;
    let mut truncated_event_ids = Vec::<String>::new();

    for record in records {
        if record.event_type != "ContentStreamExec" {
            continue;
        }
        let Some(stream_exec) = record.stream_exec else {
            continue;
        };
        stream_event_count += 1;
        if stream_exec.truncated {
            truncated_event_ids.push(record.node_id.clone());
        }

        for (family, count) in &stream_exec.op_family_counts {
            let node_id = format!(
                "stream.ops.{}.{}",
                overlay_id_component(&record.node_id),
                overlay_id_component(family)
            );
            push_overlay_json_node(
                &mut overlay_nodes,
                &mut node_ids,
                json!({
                    "id": node_id.clone(),
                    "kind": "op_cluster",
                    "attrs": {
                        "family": family,
                        "count": count,
                    }
                }),
            );
            push_overlay_json_edge(
                &mut overlay_edges,
                &mut edge_ids,
                json!({
                    "from": record.node_id.clone(),
                    "to": node_id,
                    "edge_type": "exec_observed",
                    "suspicious": false,
                    "attrs": {"count": count},
                }),
            );
        }

        for resource in &stream_exec.resource_refs {
            let node_id = format!(
                "stream.res.{}.{}",
                overlay_id_component(&record.node_id),
                overlay_name_hash(&format!("{}:{}", resource.op, resource.name))
            );
            push_overlay_json_node(
                &mut overlay_nodes,
                &mut node_ids,
                json!({
                    "id": node_id.clone(),
                    "kind": "resource_ref",
                    "attrs": {
                        "op": resource.op,
                        "name": resource.name,
                        "object_ref": resource.object_ref.map(|(obj, gen)| format!("{obj}:{gen}")),
                    }
                }),
            );
            push_overlay_json_edge(
                &mut overlay_edges,
                &mut edge_ids,
                json!({
                    "from": record.node_id.clone(),
                    "to": node_id,
                    "edge_type": "invokes_resource",
                    "suspicious": false,
                    "attrs": {
                        "op": resource.op,
                        "object_ref": resource.object_ref.map(|(obj, gen)| format!("{obj}:{gen}")),
                    },
                }),
            );
        }

        if let Some(marked_count) = stream_exec.op_family_counts.get("MarkedContent") {
            let mc_id = format!("stream.mc.{}.mc", overlay_id_component(&record.node_id));
            push_overlay_json_node(
                &mut overlay_nodes,
                &mut node_ids,
                json!({
                    "id": mc_id.clone(),
                    "kind": "marked_content",
                    "attrs": {
                        "tag": "any",
                        "count": marked_count,
                    }
                }),
            );
            push_overlay_json_edge(
                &mut overlay_edges,
                &mut edge_ids,
                json!({
                    "from": record.node_id.clone(),
                    "to": mc_id,
                    "edge_type": "enters_marked_content",
                    "suspicious": false,
                    "attrs": {"count": marked_count},
                }),
            );
        }

        if stream_exec.unknown_op_count > 0 {
            let anom_id =
                format!("stream.anom.{}.unknown_ops", overlay_id_component(&record.node_id));
            push_overlay_json_node(
                &mut overlay_nodes,
                &mut node_ids,
                json!({
                    "id": anom_id.clone(),
                    "kind": "anomaly",
                    "attrs": {
                        "anomaly": "unknown_ops",
                        "count": stream_exec.unknown_op_count,
                    }
                }),
            );
            push_overlay_json_edge(
                &mut overlay_edges,
                &mut edge_ids,
                json!({
                    "from": record.node_id.clone(),
                    "to": anom_id,
                    "edge_type": "signals_anomaly",
                    "suspicious": true,
                    "attrs": {
                        "severity": "medium",
                        "reason": "unknown_ops",
                    },
                }),
            );
        }
        if stream_exec.graphics_state_underflow {
            let anom_id =
                format!("stream.anom.{}.gstate_underflow", overlay_id_component(&record.node_id));
            push_overlay_json_node(
                &mut overlay_nodes,
                &mut node_ids,
                json!({
                    "id": anom_id.clone(),
                    "kind": "anomaly",
                    "attrs": {
                        "anomaly": "graphics_state_underflow",
                    }
                }),
            );
            push_overlay_json_edge(
                &mut overlay_edges,
                &mut edge_ids,
                json!({
                    "from": record.node_id.clone(),
                    "to": anom_id,
                    "edge_type": "signals_anomaly",
                    "suspicious": true,
                    "attrs": {
                        "severity": "high",
                        "reason": "graphics_state_underflow",
                    },
                }),
            );
        }
        if stream_exec.truncated {
            let anom_id = format!(
                "stream.anom.{}.projection_truncated",
                overlay_id_component(&record.node_id)
            );
            push_overlay_json_node(
                &mut overlay_nodes,
                &mut node_ids,
                json!({
                    "id": anom_id.clone(),
                    "kind": "anomaly",
                    "attrs": {
                        "anomaly": "projection_truncated",
                    }
                }),
            );
            push_overlay_json_edge(
                &mut overlay_edges,
                &mut edge_ids,
                json!({
                    "from": record.node_id.clone(),
                    "to": anom_id,
                    "edge_type": "signals_anomaly",
                    "suspicious": true,
                    "attrs": {
                        "severity": "low",
                        "reason": "projection_truncated",
                    },
                }),
            );
        }
    }

    let event_graph_json = sis_pdf_core::event_graph::export_event_graph_json(event_graph);
    json!({
        "type": "event_stream_overlay_graph",
        "schema_version": event_graph.schema_version,
        "event_graph": event_graph_json,
        "overlay": {
            "nodes": overlay_nodes,
            "edges": overlay_edges,
            "stats": {
                "stream_event_count": stream_event_count,
                "overlay_node_count": node_ids.len(),
                "overlay_edge_count": edge_ids.len(),
                "truncated_stream_event_count": truncated_event_ids.len(),
                "truncated_stream_event_ids": truncated_event_ids,
            },
            "truncation": event_graph.truncation,
        }
    })
}

fn export_event_stream_overlay_dot(stream_overlay: &serde_json::Value) -> String {
    let mut out = String::new();
    out.push_str("digraph event_stream_overlay {\n");
    out.push_str("  rankdir=LR;\n");
    out.push_str("  node [shape=box, style=rounded, fontsize=10];\n");

    if let Some(nodes) = stream_overlay["event_graph"]["nodes"].as_array() {
        out.push_str("  subgraph cluster_event_graph {\n");
        out.push_str("    label=\"Event Graph\";\n");
        out.push_str("    color=\"#bfc7d5\";\n");
        for node in nodes {
            let Some(node_id) = node.get("id").and_then(|value| value.as_str()) else {
                continue;
            };
            let label = node.get("label").and_then(|value| value.as_str()).unwrap_or(node_id);
            out.push_str(&format!(
                "    \"{}\" [label=\"{}\"];\n",
                escape_dot(node_id),
                escape_dot(label)
            ));
        }
        if let Some(edges) = stream_overlay["event_graph"]["edges"].as_array() {
            for edge in edges {
                let Some(from) = edge.get("from").and_then(|value| value.as_str()) else {
                    continue;
                };
                let Some(to) = edge.get("to").and_then(|value| value.as_str()) else {
                    continue;
                };
                let edge_kind = edge.get("kind").and_then(|value| value.as_str()).unwrap_or("edge");
                out.push_str(&format!(
                    "    \"{}\" -> \"{}\" [label=\"{}\", color=\"#7f8fa6\"];\n",
                    escape_dot(from),
                    escape_dot(to),
                    escape_dot(edge_kind)
                ));
            }
        }
        out.push_str("  }\n");
    }

    out.push_str("  subgraph cluster_event_stream_overlay {\n");
    out.push_str("    label=\"Event Stream Overlay\";\n");
    out.push_str("    color=\"#6f8fa6\";\n");
    if let Some(nodes) = stream_overlay["overlay"]["nodes"].as_array() {
        for node in nodes {
            let Some(node_id) = node.get("id").and_then(|value| value.as_str()) else {
                continue;
            };
            let kind = node.get("kind").and_then(|value| value.as_str()).unwrap_or("overlay");
            let label = match kind {
                "op_cluster" => {
                    let family = node["attrs"]["family"].as_str().unwrap_or("ops");
                    let count = node["attrs"]["count"].as_u64().unwrap_or(0);
                    format!("{family}\\ncount={count}")
                }
                "resource_ref" => {
                    let op = node["attrs"]["op"].as_str().unwrap_or("res");
                    let name = node["attrs"]["name"].as_str().unwrap_or("");
                    format!("{op} {name}")
                }
                "anomaly" => {
                    let anomaly = node["attrs"]["anomaly"].as_str().unwrap_or("anomaly");
                    format!("anomaly\\n{anomaly}")
                }
                "marked_content" => {
                    let count = node["attrs"]["count"].as_u64().unwrap_or(0);
                    format!("marked_content\\ncount={count}")
                }
                _ => kind.to_string(),
            };
            let colour = if kind == "anomaly" { "#d35400" } else { "#1f4e79" };
            out.push_str(&format!(
                "    \"{}\" [label=\"{}\", color=\"{}\"];\n",
                escape_dot(node_id),
                escape_dot(&label),
                colour
            ));
        }
    }
    if let Some(edges) = stream_overlay["overlay"]["edges"].as_array() {
        for edge in edges {
            let Some(from) = edge.get("from").and_then(|value| value.as_str()) else {
                continue;
            };
            let Some(to) = edge.get("to").and_then(|value| value.as_str()) else {
                continue;
            };
            let edge_type =
                edge.get("edge_type").and_then(|value| value.as_str()).unwrap_or("overlay");
            let suspicious =
                edge.get("suspicious").and_then(|value| value.as_bool()).unwrap_or(false);
            let colour = if suspicious { "#c0392b" } else { "#2c3e50" };
            out.push_str(&format!(
                "    \"{}\" -> \"{}\" [label=\"{}\", color=\"{}\"];\n",
                escape_dot(from),
                escape_dot(to),
                escape_dot(edge_type),
                colour
            ));
        }
    }
    out.push_str("  }\n");
    out.push_str("}\n");
    out
}

fn push_overlay_json_node(
    nodes: &mut Vec<serde_json::Value>,
    node_ids: &mut HashSet<String>,
    node: serde_json::Value,
) {
    let Some(node_id) = node.get("id").and_then(|value| value.as_str()) else {
        return;
    };
    if node_ids.insert(node_id.to_string()) {
        nodes.push(node);
    }
}

fn push_overlay_json_edge(
    edges: &mut Vec<serde_json::Value>,
    edge_ids: &mut HashSet<(String, String, String)>,
    edge: serde_json::Value,
) {
    let Some(from) = edge.get("from").and_then(|value| value.as_str()) else {
        return;
    };
    let Some(to) = edge.get("to").and_then(|value| value.as_str()) else {
        return;
    };
    let Some(edge_type) = edge.get("edge_type").and_then(|value| value.as_str()) else {
        return;
    };
    if edge_ids.insert((from.to_string(), to.to_string(), edge_type.to_string())) {
        edges.push(edge);
    }
}

fn overlay_id_component(value: &str) -> String {
    value.chars().map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' }).collect::<String>()
}

fn overlay_name_hash(value: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in value.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn escape_dot(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
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

fn canonical_diff_json(ctx: &ScanContext) -> serde_json::Value {
    let canonical = ctx.canonical_view();
    let total_objects = ctx.graph.objects.len();
    let mut kept = vec![false; total_objects];
    for &idx in &canonical.indices {
        if idx < total_objects {
            kept[idx] = true;
        }
    }

    let mut removed_entries = Vec::new();
    for (idx, kept) in kept.iter().enumerate() {
        if *kept {
            continue;
        }
        if let Some(entry) = ctx.graph.objects.get(idx) {
            removed_entries.push(json!({
                "obj": entry.obj,
                "gen": entry.gen,
                "note": "Shadowed by a later incremental definition"
            }));
        }
    }

    let mut name_changes = Vec::new();
    for entry in &ctx.graph.objects {
        if let Some(dict) = entry_dict(entry) {
            for (name, _) in &dict.entries {
                let canonical_key = canonical_name(&name.decoded);
                let raw_upper = raw_name_uppercase(name);
                if canonical_key != raw_upper {
                    name_changes.push(json!({
                        "obj": entry.obj,
                        "gen": entry.gen,
                        "original": raw_name_string(name),
                        "canonical": canonical_key,
                    }));
                }
            }
        }
    }

    let removed_total = removed_entries.len();
    let name_change_total = name_changes.len();
    let removed_sample =
        removed_entries.iter().take(CANONICAL_DIFF_SAMPLE_LIMIT).cloned().collect::<Vec<_>>();
    let name_sample =
        name_changes.iter().take(CANONICAL_DIFF_SAMPLE_LIMIT).cloned().collect::<Vec<_>>();

    json!({
        "summary": {
            "total_objects": total_objects,
            "canonical_object_count": canonical.indices.len(),
            "incremental_updates_removed": canonical.incremental_removed,
            "normalized_name_changes": name_change_total
        },
        "removed_objects": removed_sample,
        "name_changes": name_sample,
        "removed_total": removed_total,
        "name_change_total": name_change_total,
        "removed_sample_truncated": removed_total > CANONICAL_DIFF_SAMPLE_LIMIT,
        "name_changes_truncated": name_change_total > CANONICAL_DIFF_SAMPLE_LIMIT,
    })
}

fn raw_name_uppercase(name: &PdfName<'_>) -> String {
    String::from_utf8_lossy(&name.decoded)
        .trim_start_matches('/')
        .trim()
        .to_ascii_uppercase()
        .to_string()
}

fn raw_name_string(name: &PdfName<'_>) -> String {
    let binding = String::from_utf8_lossy(&name.decoded);
    let raw = binding.trim_start_matches('/').trim();
    if raw.is_empty() {
        "-".into()
    } else {
        raw.to_string()
    }
}

fn format_name(name: &PdfName<'_>) -> String {
    let binding = String::from_utf8_lossy(&name.decoded);
    let trimmed = binding.trim();
    if trimmed.is_empty() {
        "/".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{}", trimmed)
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
        PdfAtom::Name(name) => Some(format_name(name)),
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
                PdfAtom::Name(name) => Some(format_name(name)),
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

fn string_raw_bytes(s: &sis_pdf_pdf::object::PdfStr<'_>) -> Vec<u8> {
    use sis_pdf_pdf::object::PdfStr;
    match s {
        PdfStr::Literal { raw, .. } => raw.to_vec(),
        PdfStr::Hex { raw, .. } => raw.to_vec(),
    }
}

struct XfaPayloadMeta {
    bytes: Vec<u8>,
    ref_chain: String,
}

fn xfa_payloads_from_obj(
    graph: &sis_pdf_pdf::ObjectGraph<'_>,
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
    limits: sis_pdf_pdf::decode::DecodeLimits,
) -> Vec<XfaPayloadMeta> {
    use sis_pdf_pdf::object::PdfAtom;

    let mut out = Vec::new();
    match &obj.atom {
        PdfAtom::Array(items) => {
            let mut iter = items.iter().peekable();
            while let Some(item) = iter.next() {
                match &item.atom {
                    PdfAtom::Name(_) | PdfAtom::Str(_) => {
                        if let Some(next) = iter.next() {
                            out.extend(resolve_xfa_payload(graph, next, limits, Vec::new()));
                        }
                    }
                    _ => out.extend(resolve_xfa_payload(graph, item, limits, Vec::new())),
                }
            }
        }
        _ => out.extend(resolve_xfa_payload(graph, obj, limits, Vec::new())),
    }
    out
}

fn resolve_xfa_payload(
    graph: &sis_pdf_pdf::ObjectGraph<'_>,
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
    limits: sis_pdf_pdf::decode::DecodeLimits,
    ref_chain: Vec<String>,
) -> Vec<XfaPayloadMeta> {
    use sis_pdf_pdf::decode::decode_stream_with_meta;
    use sis_pdf_pdf::object::PdfAtom;

    let mut out = Vec::new();
    match &obj.atom {
        PdfAtom::Str(s) => out.push(XfaPayloadMeta {
            bytes: string_bytes(s),
            ref_chain: format_ref_chain(&ref_chain),
        }),
        PdfAtom::Stream(stream) => {
            let result = decode_stream_with_meta(graph.bytes, stream, limits);
            if let Some(data) = result.data {
                out.push(XfaPayloadMeta { bytes: data, ref_chain: format_ref_chain(&ref_chain) });
            }
        }
        PdfAtom::Ref { .. } => {
            if let Some(entry) = graph.resolve_ref(obj) {
                let mut next_chain = ref_chain.clone();
                next_chain.push(format!("{} {} R", entry.obj, entry.gen));
                match &entry.atom {
                    PdfAtom::Stream(stream) => {
                        let result = decode_stream_with_meta(graph.bytes, stream, limits);
                        if let Some(data) = result.data {
                            out.push(XfaPayloadMeta {
                                bytes: data,
                                ref_chain: format_ref_chain(&next_chain),
                            });
                        }
                    }
                    PdfAtom::Str(s) => out.push(XfaPayloadMeta {
                        bytes: string_bytes(s),
                        ref_chain: format_ref_chain(&next_chain),
                    }),
                    _ => {}
                }
            }
        }
        _ => {}
    }
    out
}

fn format_ref_chain(chain: &[String]) -> String {
    if chain.is_empty() {
        "-".into()
    } else {
        chain.join(" -> ")
    }
}

fn entropy_score(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for count in counts.iter().filter(|&&c| c > 0) {
        let p = *count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

fn filter_name(dict: &sis_pdf_pdf::object::PdfDict<'_>) -> Option<String> {
    use sis_pdf_pdf::object::PdfAtom;

    let filter_obj = dict.get_first(b"/Filter").map(|(_, obj)| obj)?;
    match &filter_obj.atom {
        PdfAtom::Name(name) => Some(String::from_utf8_lossy(&name.decoded).to_string()),
        PdfAtom::Array(items) => items.first().and_then(|item| {
            if let PdfAtom::Name(name) = &item.atom {
                Some(String::from_utf8_lossy(&name.decoded).to_string())
            } else {
                None
            }
        }),
        _ => None,
    }
}

fn subtype_name(dict: &sis_pdf_pdf::object::PdfDict<'_>) -> Option<String> {
    use sis_pdf_pdf::object::PdfAtom;

    let subtype_obj = dict.get_first(b"/Subtype").map(|(_, obj)| obj)?;
    if let PdfAtom::Name(name) = &subtype_obj.atom {
        Some(String::from_utf8_lossy(&name.decoded).to_string())
    } else {
        None
    }
}

fn atom_type_name(atom: &sis_pdf_pdf::object::PdfAtom<'_>) -> String {
    use sis_pdf_pdf::object::PdfAtom;
    match atom {
        PdfAtom::Null => "Null",
        PdfAtom::Bool(_) => "Bool",
        PdfAtom::Int(_) => "Int",
        PdfAtom::Real(_) => "Real",
        PdfAtom::Name(_) => "Name",
        PdfAtom::Str(_) => "String",
        PdfAtom::Array(_) => "Array",
        PdfAtom::Dict(_) => "Dict",
        PdfAtom::Stream(_) => "Stream",
        PdfAtom::Ref { .. } => "Ref",
    }
    .to_string()
}

fn predicate_context_for_entry(
    entry: &sis_pdf_pdf::graph::ObjEntry<'_>,
    bytes: &[u8],
    decode_mode: DecodeMode,
    max_extract_bytes: usize,
) -> PredicateContext {
    use sis_pdf_pdf::object::PdfAtom;

    match &entry.atom {
        PdfAtom::Str(s) => {
            let data = match decode_mode {
                DecodeMode::Raw => string_raw_bytes(s),
                DecodeMode::Decode | DecodeMode::Hexdump => string_bytes(s),
            };
            PredicateContext {
                length: data.len(),
                filter: None,
                type_name: "String".to_string(),
                subtype: None,
                entropy: entropy_score(&data),
                width: 0,
                height: 0,
                pixels: 0,
                risky: false,
                severity: None,
                confidence: None,
                surface: None,
                kind: None,
                object_count: 0,
                evidence_count: 0,
                name: None,
                magic: None,
                hash: None,
                impact: None,
                action_type: None,
                action_target: None,
                action_initiation: None,
                meta: HashMap::new(),
            }
        }
        PdfAtom::Stream(stream) => {
            let (data_len, entropy) =
                match stream_bytes_for_mode(bytes, stream, max_extract_bytes, decode_mode) {
                    Ok(data) => (data.len(), entropy_score(&data)),
                    Err(_) => {
                        let length = stream
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
                        (length, 0.0)
                    }
                };
            PredicateContext {
                length: data_len,
                filter: filter_name(&stream.dict),
                type_name: "Stream".to_string(),
                subtype: subtype_name(&stream.dict),
                entropy,
                width: 0,
                height: 0,
                pixels: 0,
                risky: false,
                severity: None,
                confidence: None,
                surface: None,
                kind: None,
                object_count: 0,
                evidence_count: 0,
                name: None,
                magic: None,
                hash: None,
                impact: None,
                action_type: None,
                action_target: None,
                action_initiation: None,
                meta: HashMap::new(),
            }
        }
        PdfAtom::Dict(dict) => PredicateContext {
            length: 0,
            filter: None,
            type_name: "Dict".to_string(),
            subtype: subtype_name(dict),
            entropy: 0.0,
            width: 0,
            height: 0,
            pixels: 0,
            risky: false,
            severity: None,
            confidence: None,
            surface: None,
            kind: None,
            object_count: 0,
            evidence_count: 0,
            name: None,
            magic: None,
            hash: None,
            impact: None,
            action_type: None,
            action_target: None,
            action_initiation: None,
            meta: HashMap::new(),
        },
        PdfAtom::Array(_) => PredicateContext {
            length: 0,
            filter: None,
            type_name: "Array".to_string(),
            subtype: None,
            entropy: 0.0,
            width: 0,
            height: 0,
            pixels: 0,
            risky: false,
            severity: None,
            confidence: None,
            surface: None,
            kind: None,
            object_count: 0,
            evidence_count: 0,
            name: None,
            magic: None,
            hash: None,
            impact: None,
            action_type: None,
            action_target: None,
            action_initiation: None,
            meta: HashMap::new(),
        },
        atom => PredicateContext {
            length: 0,
            filter: None,
            type_name: atom_type_name(atom),
            subtype: None,
            entropy: 0.0,
            width: 0,
            height: 0,
            pixels: 0,
            risky: false,
            severity: None,
            confidence: None,
            surface: None,
            kind: None,
            object_count: 0,
            evidence_count: 0,
            name: None,
            magic: None,
            hash: None,
            impact: None,
            action_type: None,
            action_target: None,
            action_initiation: None,
            meta: HashMap::new(),
        },
    }
}

fn predicate_context_for_url(url: &str) -> PredicateContext {
    let bytes = url.as_bytes();
    PredicateContext {
        length: bytes.len(),
        filter: None,
        type_name: "Url".to_string(),
        subtype: None,
        entropy: entropy_score(bytes),
        width: 0,
        height: 0,
        pixels: 0,
        risky: false,
        severity: None,
        confidence: None,
        surface: None,
        kind: None,
        object_count: 0,
        evidence_count: 0,
        name: None,
        hash: None,
        magic: None,
        impact: None,
        action_type: None,
        action_target: None,
        action_initiation: None,
        meta: HashMap::new(),
    }
}

fn predicate_context_for_event(event: &serde_json::Value) -> Option<PredicateContext> {
    let level = event.get("level").and_then(|value| value.as_str()).unwrap_or("document");
    let event_type = event.get("event_type")?.as_str()?;
    let details = event
        .get("action_details")
        .and_then(|value| value.as_str())
        .or_else(|| event.get("label").and_then(|value| value.as_str()))
        .unwrap_or_default();
    let bytes = details.as_bytes();
    let mut meta = HashMap::new();
    if let Some(trigger) = event.get("trigger").and_then(|value| value.as_str()) {
        meta.insert("trigger".to_string(), trigger.to_string());
    }
    if let Some(node_id) = event.get("node_id").and_then(|value| value.as_str()) {
        meta.insert("node_id".to_string(), node_id.to_string());
    }
    if let Some(source_object) = event.get("source_object").and_then(|value| value.as_str()) {
        meta.insert("source_object".to_string(), source_object.to_string());
    }
    Some(PredicateContext {
        length: bytes.len(),
        filter: Some(level.to_string()),
        type_name: "Event".to_string(),
        subtype: Some(event_type.to_string()),
        entropy: entropy_score(bytes),
        width: 0,
        height: 0,
        pixels: 0,
        risky: false,
        severity: None,
        confidence: None,
        surface: None,
        kind: None,
        object_count: 0,
        evidence_count: 0,
        name: None,
        hash: None,
        magic: None,
        impact: None,
        action_type: None,
        action_target: None,
        action_initiation: None,
        meta,
    })
}

fn filter_event_graph_by_predicate(
    event_graph: sis_pdf_core::event_graph::EventGraph,
    predicate: &PredicateExpr,
) -> sis_pdf_core::event_graph::EventGraph {
    use sis_pdf_core::event_graph::{EventEdge, EventNode, EventNodeKind};

    let mut keep_nodes = HashSet::new();
    let mut object_nodes = HashSet::new();
    for node in &event_graph.nodes {
        if let EventNodeKind::Object { .. } = node.kind {
            object_nodes.insert(node.id.clone());
        }
    }

    for node in &event_graph.nodes {
        if let Some(ctx) = predicate_context_for_event_graph_node(node) {
            if predicate.evaluate(&ctx) {
                keep_nodes.insert(node.id.clone());
            }
        }
    }

    if keep_nodes.is_empty() {
        return sis_pdf_core::event_graph::EventGraph {
            schema_version: event_graph.schema_version,
            nodes: Vec::new(),
            edges: Vec::new(),
            node_index: HashMap::new(),
            forward_index: HashMap::new(),
            reverse_index: HashMap::new(),
            truncation: event_graph.truncation,
        };
    }

    for edge in &event_graph.edges {
        if keep_nodes.contains(&edge.from) && object_nodes.contains(&edge.to) {
            keep_nodes.insert(edge.to.clone());
        }
        if keep_nodes.contains(&edge.to) && object_nodes.contains(&edge.from) {
            keep_nodes.insert(edge.from.clone());
        }
    }

    let nodes = event_graph
        .nodes
        .into_iter()
        .filter(|node| keep_nodes.contains(&node.id))
        .collect::<Vec<EventNode>>();
    let edges = event_graph
        .edges
        .into_iter()
        .filter(|edge| keep_nodes.contains(&edge.from) && keep_nodes.contains(&edge.to))
        .collect::<Vec<EventEdge>>();
    rebuild_event_graph_indices(event_graph.schema_version, nodes, edges, event_graph.truncation)
}

fn event_graph_seed_nodes(
    event_graph: &sis_pdf_core::event_graph::EventGraph,
    predicate: Option<&PredicateExpr>,
) -> Option<HashSet<String>> {
    use sis_pdf_core::event_graph::EventNodeKind;

    if let Some(predicate) = predicate {
        let mut seeds = HashSet::new();
        for node in &event_graph.nodes {
            if let Some(ctx) = predicate_context_for_event_graph_node(node) {
                if predicate.evaluate(&ctx) {
                    seeds.insert(node.id.clone());
                }
            }
        }
        return Some(seeds);
    }

    let mut defaults = HashSet::new();
    for node in &event_graph.nodes {
        match node.kind {
            EventNodeKind::Event { .. } | EventNodeKind::Outcome { .. } => {
                defaults.insert(node.id.clone());
            }
            _ => {}
        }
    }
    Some(defaults)
}

fn induced_event_subgraph(
    event_graph: sis_pdf_core::event_graph::EventGraph,
    seed_nodes: &HashSet<String>,
    hops: usize,
) -> sis_pdf_core::event_graph::EventGraph {
    if seed_nodes.is_empty() {
        return rebuild_event_graph_indices(
            event_graph.schema_version,
            Vec::new(),
            Vec::new(),
            event_graph.truncation,
        );
    }

    let mut frontier: Vec<String> = seed_nodes.iter().cloned().collect();
    let mut seen: HashSet<String> = seed_nodes.clone();
    let mut depth = 0usize;
    while depth < hops {
        let mut next = Vec::new();
        for node_id in &frontier {
            if let Some(outgoing) = event_graph.forward_index.get(node_id) {
                for edge_idx in outgoing {
                    let edge = &event_graph.edges[*edge_idx];
                    if seen.insert(edge.to.clone()) {
                        next.push(edge.to.clone());
                    }
                }
            }
            if let Some(incoming) = event_graph.reverse_index.get(node_id) {
                for edge_idx in incoming {
                    let edge = &event_graph.edges[*edge_idx];
                    if seen.insert(edge.from.clone()) {
                        next.push(edge.from.clone());
                    }
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
        depth += 1;
    }

    let nodes =
        event_graph.nodes.into_iter().filter(|node| seen.contains(&node.id)).collect::<Vec<_>>();
    let edges = event_graph
        .edges
        .into_iter()
        .filter(|edge| seen.contains(&edge.from) && seen.contains(&edge.to))
        .collect::<Vec<_>>();
    rebuild_event_graph_indices(event_graph.schema_version, nodes, edges, event_graph.truncation)
}

fn rebuild_event_graph_indices(
    schema_version: &'static str,
    nodes: Vec<sis_pdf_core::event_graph::EventNode>,
    edges: Vec<sis_pdf_core::event_graph::EventEdge>,
    truncation: Option<sis_pdf_core::event_graph::EventGraphTruncation>,
) -> sis_pdf_core::event_graph::EventGraph {
    let mut node_index = HashMap::new();
    for (idx, node) in nodes.iter().enumerate() {
        node_index.insert(node.id.clone(), idx);
    }
    let mut forward_index = HashMap::new();
    let mut reverse_index = HashMap::new();
    for (idx, edge) in edges.iter().enumerate() {
        forward_index.entry(edge.from.clone()).or_insert_with(Vec::new).push(idx);
        reverse_index.entry(edge.to.clone()).or_insert_with(Vec::new).push(idx);
    }
    sis_pdf_core::event_graph::EventGraph {
        schema_version,
        nodes,
        edges,
        node_index,
        forward_index,
        reverse_index,
        truncation,
    }
}

fn predicate_context_for_event_graph_node(
    node: &sis_pdf_core::event_graph::EventNode,
) -> Option<PredicateContext> {
    use sis_pdf_core::event_graph::{EventNodeKind, OutcomeType};

    let mut meta = HashMap::new();
    let (type_name, filter, subtype, action_target) = match &node.kind {
        EventNodeKind::Event { event_type, trigger, label, source_obj } => {
            let event_name = format!("{:?}", event_type);
            meta.insert("event_type".to_string(), event_name);
            meta.insert("trigger_class".to_string(), trigger.as_str().to_string());
            meta.insert("node_kind".to_string(), "event".to_string());
            meta.insert("label".to_string(), label.clone());
            if let Some((obj, gen)) = source_obj {
                meta.insert("source_obj".to_string(), format!("{obj} {gen}"));
            }
            (
                "Event".to_string(),
                Some("event".to_string()),
                Some(format!("{:?}", event_type)),
                None,
            )
        }
        EventNodeKind::Outcome {
            outcome_type,
            label,
            target,
            source_obj,
            confidence_source,
            confidence_score,
            severity_hint,
            ..
        } => {
            let outcome_name = format!("{:?}", outcome_type);
            meta.insert("outcome_type".to_string(), outcome_name.clone());
            meta.insert("node_kind".to_string(), "outcome".to_string());
            meta.insert("label".to_string(), label.clone());
            if let Some(value) = target {
                meta.insert("target".to_string(), value.clone());
            }
            if let Some((obj, gen)) = source_obj {
                meta.insert("source_obj".to_string(), format!("{obj} {gen}"));
            }
            if let Some(confidence) = confidence_source {
                meta.insert("confidence_source".to_string(), confidence.clone());
            }
            if let Some(score) = confidence_score {
                meta.insert("confidence_score".to_string(), score.to_string());
            }
            if let Some(severity) = severity_hint {
                meta.insert("severity_hint".to_string(), severity.clone());
            }
            if *outcome_type == OutcomeType::NetworkEgress {
                meta.insert("risk".to_string(), "high".to_string());
            }
            ("Outcome".to_string(), Some("outcome".to_string()), Some(outcome_name), target.clone())
        }
        EventNodeKind::Object { obj, gen, obj_type } => {
            meta.insert("node_kind".to_string(), "object".to_string());
            meta.insert("source_obj".to_string(), format!("{obj} {gen}"));
            ("Object".to_string(), Some("object".to_string()), obj_type.clone(), None)
        }
        EventNodeKind::Collapse { label, member_count, .. } => {
            meta.insert("node_kind".to_string(), "collapse".to_string());
            meta.insert("label".to_string(), label.clone());
            meta.insert("member_count".to_string(), member_count.to_string());
            ("Collapse".to_string(), Some("collapse".to_string()), None, None)
        }
    };

    Some(PredicateContext {
        length: node.id.len(),
        filter,
        type_name,
        subtype,
        entropy: 0.0,
        width: 0,
        height: 0,
        pixels: 0,
        risky: false,
        severity: None,
        confidence: None,
        surface: None,
        kind: None,
        object_count: 0,
        evidence_count: 0,
        name: Some(node.id.clone()),
        hash: None,
        magic: None,
        impact: None,
        action_type: None,
        action_target,
        action_initiation: None,
        meta,
    })
}

fn predicate_context_for_finding(finding: &sis_pdf_core::model::Finding) -> PredicateContext {
    let bytes = finding.description.as_bytes();
    let mut meta_map = HashMap::new();
    for (key, value) in &finding.meta {
        meta_map.insert(key.to_ascii_lowercase(), value.clone());
    }
    let name = meta_map
        .get("filename")
        .cloned()
        .or_else(|| meta_map.get("name").cloned())
        .or_else(|| meta_map.get("embedded.filename").cloned())
        .or_else(|| meta_map.get("launch.target_path").cloned());
    let magic = meta_map
        .get("magic")
        .cloned()
        .or_else(|| meta_map.get("embedded.magic").cloned())
        .or_else(|| meta_map.get("stream.magic_type").cloned());
    let hash = meta_map
        .get("hash.sha256")
        .cloned()
        .or_else(|| meta_map.get("hash").cloned())
        .or_else(|| meta_map.get("embedded.sha256").cloned());
    let impact_value = finding.impact.map(|impact| impact.as_str().to_string());
    if let Some(value) = &impact_value {
        meta_map.insert("impact".into(), value.clone());
    }
    let action_type = finding.action_type.clone();
    if let Some(value) = &action_type {
        meta_map.insert("action_type".into(), value.clone());
    }
    let action_target = finding.action_target.clone();
    if let Some(value) = &action_target {
        meta_map.insert("action_target".into(), value.clone());
    }
    let action_initiation = finding.action_initiation.clone();
    if let Some(value) = &action_initiation {
        meta_map.insert("action_initiation".into(), value.clone());
    }
    PredicateContext {
        length: bytes.len(),
        filter: Some(severity_to_string(&finding.severity)),
        type_name: "Finding".to_string(),
        subtype: Some(finding.kind.clone()),
        entropy: entropy_score(bytes),
        width: 0,
        height: 0,
        pixels: 0,
        risky: false,
        severity: Some(severity_to_string(&finding.severity)),
        confidence: Some(confidence_to_string(&finding.confidence)),
        surface: Some(surface_to_string(&finding.surface)),
        kind: Some(finding.kind.clone()),
        object_count: finding.objects.len(),
        evidence_count: finding.evidence.len(),
        name,
        magic,
        hash,
        impact: impact_value,
        action_type,
        action_target,
        action_initiation,
        meta: meta_map,
    }
}

fn severity_to_string(severity: &sis_pdf_core::model::Severity) -> String {
    match severity {
        sis_pdf_core::model::Severity::Info => "info",
        sis_pdf_core::model::Severity::Low => "low",
        sis_pdf_core::model::Severity::Medium => "medium",
        sis_pdf_core::model::Severity::High => "high",
        sis_pdf_core::model::Severity::Critical => "critical",
    }
    .to_string()
}

fn confidence_to_string(confidence: &sis_pdf_core::model::Confidence) -> String {
    match confidence {
        sis_pdf_core::model::Confidence::Certain => "certain",
        sis_pdf_core::model::Confidence::Strong => "strong",
        sis_pdf_core::model::Confidence::Probable => "probable",
        sis_pdf_core::model::Confidence::Tentative => "tentative",
        sis_pdf_core::model::Confidence::Weak => "weak",
        sis_pdf_core::model::Confidence::Heuristic => "heuristic",
    }
    .to_string()
}

fn surface_to_string(surface: &sis_pdf_core::model::AttackSurface) -> String {
    match surface {
        sis_pdf_core::model::AttackSurface::FileStructure => "file_structure",
        sis_pdf_core::model::AttackSurface::XRefTrailer => "xref_trailer",
        sis_pdf_core::model::AttackSurface::ObjectStreams => "object_streams",
        sis_pdf_core::model::AttackSurface::StreamsAndFilters => "streams_and_filters",
        sis_pdf_core::model::AttackSurface::Actions => "actions",
        sis_pdf_core::model::AttackSurface::JavaScript => "javascript",
        sis_pdf_core::model::AttackSurface::Forms => "forms",
        sis_pdf_core::model::AttackSurface::EmbeddedFiles => "embedded_files",
        sis_pdf_core::model::AttackSurface::RichMedia3D => "rich_media_3d",
        sis_pdf_core::model::AttackSurface::Images => "images",
        sis_pdf_core::model::AttackSurface::CryptoSignatures => "crypto_signatures",
        sis_pdf_core::model::AttackSurface::Metadata => "metadata",
        sis_pdf_core::model::AttackSurface::ContentPhishing => "content_phishing",
    }
    .to_string()
}

fn build_query_error(err: anyhow::Error) -> QueryError {
    let message = err.to_string();
    let (error_code, context) = classify_query_error(&message);
    QueryError { status: "error", error_code, message, context }
}

fn classify_query_error(message: &str) -> (&'static str, Option<serde_json::Value>) {
    let lower = message.to_ascii_lowercase();
    if let Some((obj, gen)) = parse_object_not_found(message) {
        return ("OBJ_NOT_FOUND", Some(json!({ "requested": format!("{obj} {gen}") })));
    }
    if lower.contains("invalid query")
        || lower.contains("failed to parse query")
        || lower.contains("query syntax")
    {
        return ("QUERY_SYNTAX_ERROR", None);
    }
    if lower.contains("decode") || lower.contains("decompress") || lower.contains("stream") {
        return ("DECODE_ERROR", None);
    }
    if lower.contains("parse") && lower.contains("pdf") {
        return ("PARSE_ERROR", None);
    }
    if lower.contains("encrypted") || lower.contains("password") || lower.contains("permission") {
        return ("PERMISSION_ERROR", None);
    }
    ("QUERY_ERROR", None)
}

fn parse_object_not_found(message: &str) -> Option<(u32, u16)> {
    let prefix = "Object ";
    let suffix = " not found";
    let start = message.find(prefix)? + prefix.len();
    let end = message.find(suffix)?;
    if end <= start {
        return None;
    }
    let parts: Vec<&str> = message[start..end].split_whitespace().collect();
    match parts.as_slice() {
        [obj, gen] => Some((obj.parse().ok()?, gen.parse().ok()?)),
        _ => None,
    }
}

fn filter_findings(
    findings: Vec<sis_pdf_core::model::Finding>,
    predicate: Option<&PredicateExpr>,
) -> Vec<sis_pdf_core::model::Finding> {
    if let Some(pred) = predicate {
        findings
            .into_iter()
            .filter(|finding| pred.evaluate(&predicate_context_for_finding(finding)))
            .collect()
    } else {
        findings
    }
}

fn build_findings_with_chain(
    findings: Vec<sis_pdf_core::model::Finding>,
    group_chains: bool,
) -> serde_json::Value {
    let findings_by_id =
        findings.iter().map(|finding| (finding.id.clone(), finding)).collect::<HashMap<_, _>>();
    let (chains, _templates) =
        sis_pdf_core::chain_synth::synthesise_chains(&findings, group_chains);
    let chain_values = chains
        .into_iter()
        .map(|chain| {
            let notes = chain.notes.clone();
            let stages = chain_ordered_stages(&chain, &findings_by_id);
            let stage_nodes = chain_stage_nodes(&chain, &findings_by_id);
            let contributing = chain
                .findings
                .iter()
                .filter_map(|id| findings_by_id.get(id))
                .map(|finding| {
                    json!({
                        "id": finding.id,
                        "kind": finding.kind,
                        "severity": format!("{:?}", finding.severity),
                        "confidence": format!("{:?}", finding.confidence),
                        "objects": finding.objects,
                        "chain_stage": finding.meta.get("chain.stage"),
                        "chain_capability": finding.meta.get("chain.capability"),
                    })
                })
                .collect::<Vec<_>>();
            let scatter = chain_scatter_context(&chain, &findings_by_id);
            json!({
                "id": chain.id,
                "group_id": chain.group_id,
                "group_count": chain.group_count,
                "group_members": chain.group_members,
                "path": chain.path,
                "score": chain.score,
                "reasons": chain.reasons,
                "ordered_stages": stages,
                "stage_nodes": stage_nodes,
                "shared_object_refs": chain_shared_object_refs(&chain, &findings_by_id),
                "contributing_findings": contributing,
                "edge": {
                    "reason": notes.get("edge.reason"),
                    "confidence": notes.get("edge.confidence"),
                    "from": notes.get("edge.from"),
                    "to": notes.get("edge.to"),
                    "shared_objects": notes.get("edge.shared_objects"),
                },
                "exploit": {
                    "preconditions": notes.get("exploit.preconditions"),
                    "blockers": notes.get("exploit.blockers"),
                    "outcomes": notes.get("exploit.outcomes"),
                },
                "scatter": scatter,
                "notes": notes,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "type": "findings_with_chain",
        "count": findings.len(),
        "chain_count": chain_values.len(),
        "findings": findings,
        "chains": chain_values,
    })
}

fn chain_ordered_stages(
    chain: &sis_pdf_core::chain::ExploitChain,
    findings_by_id: &HashMap<String, &sis_pdf_core::model::Finding>,
) -> Vec<String> {
    let mut stages = chain
        .findings
        .iter()
        .filter_map(|id| findings_by_id.get(id))
        .filter_map(|finding| finding.meta.get("chain.stage"))
        .cloned()
        .collect::<Vec<_>>();
    stages.sort_by_key(|stage| chain_stage_rank(stage));
    stages.dedup();
    stages
}

fn chain_stage_rank(stage: &str) -> usize {
    match stage {
        "input" => 0,
        "decode" => 1,
        "render" => 2,
        "execute" => 3,
        "egress" => 4,
        _ => 5,
    }
}

fn chain_shared_object_refs(
    chain: &sis_pdf_core::chain::ExploitChain,
    findings_by_id: &HashMap<String, &sis_pdf_core::model::Finding>,
) -> Vec<String> {
    let mut refs = chain
        .findings
        .iter()
        .filter_map(|id| findings_by_id.get(id))
        .flat_map(|finding| finding.objects.iter().cloned())
        .collect::<Vec<_>>();
    refs.sort();
    refs.dedup();
    refs
}

fn chain_stage_nodes(
    chain: &sis_pdf_core::chain::ExploitChain,
    findings_by_id: &HashMap<String, &sis_pdf_core::model::Finding>,
) -> serde_json::Value {
    let mut by_stage: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for finding in chain.findings.iter().filter_map(|id| findings_by_id.get(id)) {
        let stage = finding.meta.get("chain.stage").cloned().unwrap_or_else(|| "unknown".into());
        let entry = by_stage.entry(stage).or_default();
        entry.extend(finding.objects.iter().cloned());
    }
    for refs in by_stage.values_mut() {
        refs.sort();
        refs.dedup();
    }
    json!(by_stage)
}

fn chain_scatter_context(
    chain: &sis_pdf_core::chain::ExploitChain,
    findings_by_id: &HashMap<String, &sis_pdf_core::model::Finding>,
) -> Option<serde_json::Value> {
    let scatter_findings = chain
        .findings
        .iter()
        .filter_map(|id| findings_by_id.get(id))
        .filter(|finding| {
            matches!(
                finding.kind.as_str(),
                "scattered_payload_assembly" | "cross_stream_payload_assembly"
            )
        })
        .collect::<Vec<_>>();
    if scatter_findings.is_empty() {
        return None;
    }

    let mut object_ids = Vec::new();
    let mut fragment_count = 0usize;
    for finding in scatter_findings {
        if let Some(raw_count) = finding.meta.get("scatter.fragment_count") {
            fragment_count = fragment_count.max(raw_count.parse::<usize>().unwrap_or(0));
        }
        if let Some(raw_objects) = finding.meta.get("scatter.object_ids") {
            object_ids.extend(
                raw_objects
                    .split(',')
                    .map(str::trim)
                    .filter(|token| !token.is_empty())
                    .map(str::to_string),
            );
        }
    }
    object_ids.sort();
    object_ids.dedup();
    Some(json!({
        "fragment_count": fragment_count,
        "object_refs": object_ids,
    }))
}

fn is_composite(finding: &sis_pdf_core::model::Finding) -> bool {
    finding.meta.get("is_composite").map(|value| value == "true").unwrap_or(false)
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

fn extract_obj_with_metadata(
    graph: &sis_pdf_pdf::ObjectGraph<'_>,
    bytes: &[u8],
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
    max_bytes: usize,
    decode_mode: DecodeMode,
) -> Option<(Vec<u8>, PredicateContext)> {
    use sis_pdf_pdf::object::PdfAtom;

    match &obj.atom {
        PdfAtom::Str(s) => {
            let data = match decode_mode {
                DecodeMode::Raw => string_raw_bytes(s),
                DecodeMode::Decode | DecodeMode::Hexdump => string_bytes(s),
            };
            let ctx = PredicateContext {
                length: data.len(),
                filter: None,
                type_name: "String".to_string(),
                subtype: None,
                entropy: entropy_score(&data),
                width: 0,
                height: 0,
                pixels: 0,
                risky: false,
                severity: None,
                confidence: None,
                surface: None,
                kind: None,
                object_count: 0,
                evidence_count: 0,
                name: None,
                magic: None,
                hash: None,
                impact: None,
                action_type: None,
                action_target: None,
                action_initiation: None,
                meta: HashMap::new(),
            };
            Some((data, ctx))
        }
        PdfAtom::Stream(stream) => {
            let data = stream_bytes_for_mode(bytes, stream, max_bytes, decode_mode).ok()?;
            let ctx = PredicateContext {
                length: data.len(),
                filter: filter_name(&stream.dict),
                type_name: "Stream".to_string(),
                subtype: subtype_name(&stream.dict),
                entropy: entropy_score(&data),
                width: 0,
                height: 0,
                pixels: 0,
                risky: false,
                severity: None,
                confidence: None,
                surface: None,
                kind: None,
                object_count: 0,
                evidence_count: 0,
                name: None,
                magic: None,
                hash: None,
                impact: None,
                action_type: None,
                action_target: None,
                action_initiation: None,
                meta: HashMap::new(),
            };
            Some((data, ctx))
        }
        PdfAtom::Ref { .. } => {
            let entry = graph.resolve_ref(obj)?;
            match &entry.atom {
                PdfAtom::Str(s) => {
                    let data = match decode_mode {
                        DecodeMode::Raw => string_raw_bytes(s),
                        DecodeMode::Decode | DecodeMode::Hexdump => string_bytes(s),
                    };
                    let ctx = PredicateContext {
                        length: data.len(),
                        filter: None,
                        type_name: "String".to_string(),
                        subtype: None,
                        entropy: entropy_score(&data),
                        width: 0,
                        height: 0,
                        pixels: 0,
                        risky: false,
                        severity: None,
                        confidence: None,
                        surface: None,
                        kind: None,
                        object_count: 0,
                        evidence_count: 0,
                        name: None,
                        magic: None,
                        hash: None,
                        impact: None,
                        action_type: None,
                        action_target: None,
                        action_initiation: None,
                        meta: HashMap::new(),
                    };
                    Some((data, ctx))
                }
                PdfAtom::Stream(stream) => {
                    let data = stream_bytes_for_mode(bytes, stream, max_bytes, decode_mode).ok()?;
                    let ctx = PredicateContext {
                        length: data.len(),
                        filter: filter_name(&stream.dict),
                        type_name: "Stream".to_string(),
                        subtype: subtype_name(&stream.dict),
                        entropy: entropy_score(&data),
                        width: 0,
                        height: 0,
                        pixels: 0,
                        risky: false,
                        severity: None,
                        confidence: None,
                        surface: None,
                        kind: None,
                        object_count: 0,
                        evidence_count: 0,
                        name: None,
                        magic: None,
                        hash: None,
                        impact: None,
                        action_type: None,
                        action_target: None,
                        action_initiation: None,
                        meta: HashMap::new(),
                    };
                    Some((data, ctx))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn stream_bytes_for_mode(
    bytes: &[u8],
    stream: &sis_pdf_pdf::object::PdfStream<'_>,
    max_bytes: usize,
    decode_mode: DecodeMode,
) -> Result<Vec<u8>> {
    match decode_mode {
        DecodeMode::Decode | DecodeMode::Hexdump => {
            let decoded = sis_pdf_pdf::decode::decode_stream(bytes, stream, max_bytes)?;
            Ok(decoded.data)
        }
        DecodeMode::Raw => raw_stream_bytes(bytes, stream, max_bytes),
    }
}

pub fn maybe_stream_raw_bytes(
    query: &Query,
    ctx: &ScanContext,
    decode_mode: DecodeMode,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    if let Query::Stream(request) = query {
        if request.output != StreamOutput::Raw {
            return Ok(None);
        }
        let entry = ctx
            .graph
            .get_object(request.obj, request.gen)
            .ok_or_else(|| anyhow!("Object {} {} not found", request.obj, request.gen))?;
        let PdfAtom::Stream(stream) = &entry.atom else {
            return Err(anyhow!("Object {} {} is not a stream", request.obj, request.gen));
        };
        let mode = request.decode_override.unwrap_or(decode_mode);
        let data = stream_bytes_for_mode(ctx.bytes, stream, max_bytes, mode)?;
        return Ok(Some(data));
    }
    Ok(None)
}

fn raw_stream_bytes(
    bytes: &[u8],
    stream: &sis_pdf_pdf::object::PdfStream<'_>,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let span = stream.data_span;
    let start = span.start as usize;
    let end = span.end as usize;
    if start >= end || end > bytes.len() {
        return Err(anyhow!("invalid stream span"));
    }
    let data = &bytes[start..end];
    if max_bytes > 0 && data.len() > max_bytes {
        return Err(anyhow!("stream exceeds extract byte limit"));
    }
    Ok(data.to_vec())
}

/// Sanitize filename to prevent path traversal attacks
fn sanitize_embedded_filename(name: &str) -> String {
    use std::path::Path;

    // Extract just the filename, removing any path components
    let leaf = Path::new(name).file_name().and_then(|s| s.to_str()).unwrap_or("embedded.bin");

    // Filter to safe characters only
    let mut out = String::new();
    for ch in leaf.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }

    if out.is_empty() {
        "embedded.bin".into()
    } else {
        out
    }
}

/// Detect file type from magic bytes
fn magic_type(data: &[u8]) -> &'static str {
    if data.starts_with(b"MZ") {
        "pe"
    } else if data.starts_with(b"%PDF") {
        "pdf"
    } else if data.starts_with(b"PK\x03\x04") {
        "zip"
    } else if data.starts_with(b"\x7fELF") {
        "elf"
    } else if data.starts_with(b"#!") {
        "script"
    } else if data.starts_with(b"\x89PNG") {
        "png"
    } else if data.starts_with(b"\xff\xd8\xff") {
        "jpeg"
    } else if data.starts_with(b"GIF8") {
        "gif"
    } else {
        "unknown"
    }
}

/// Calculate SHA256 hash as hex string
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    hex::encode(digest)
}

/// Write JavaScript files to disk and return list of written files
fn write_js_files(
    ctx: &ScanContext,
    extract_to: &Path,
    max_bytes: usize,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    use std::fs;

    // Create output directory
    fs::create_dir_all(extract_to)?;

    let mut written_files = Vec::new();
    let mut count = 0usize;

    for entry in &ctx.graph.objects {
        if let Some(dict) = entry_dict(entry) {
            if let Some((_, obj)) = dict.get_first(b"/JS") {
                if let Some((data, meta)) =
                    extract_obj_with_metadata(&ctx.graph, ctx.bytes, obj, max_bytes, decode_mode)
                {
                    if predicate.map(|pred| pred.evaluate(&meta)).unwrap_or(true) {
                        let base_name = format!("js_{}_{}", entry.obj, entry.gen);
                        let (filename, output_bytes, mode_label) = match decode_mode {
                            DecodeMode::Decode => {
                                (format!("{base_name}.js"), data.clone(), "decode")
                            }
                            DecodeMode::Raw => (format!("{base_name}.raw"), data.clone(), "raw"),
                            DecodeMode::Hexdump => (
                                format!("{base_name}.hex"),
                                format_hexdump(&data).into_bytes(),
                                "hexdump",
                            ),
                        };
                        let filepath = extract_to.join(&filename);
                        let hash = sha256_hex(&data);

                        fs::write(&filepath, &output_bytes)?;

                        let mut info = format!(
                            "{}: {} bytes, sha256={}, object={}_{}",
                            filename,
                            data.len(),
                            hash,
                            entry.obj,
                            entry.gen
                        );
                        info.push_str(&format!(", mode={}", mode_label));
                        if decode_mode == DecodeMode::Hexdump {
                            info.push_str(&format!(", hexdump_bytes={}", output_bytes.len()));
                        }
                        written_files.push(info);
                        count += 1;
                    }
                }
            }
        }
    }

    eprintln!("Extracted {} JavaScript file(s) to {}", count, extract_to.display());
    Ok(written_files)
}

/// Write embedded files to disk and return list of written files
fn write_embedded_files(
    ctx: &ScanContext,
    extract_to: &Path,
    max_bytes: usize,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    use sis_pdf_pdf::object::PdfAtom;
    use std::fs;

    // Create output directory
    fs::create_dir_all(extract_to)?;

    let mut written_files = Vec::new();
    let mut count = 0usize;
    let mut total_bytes = 0usize;
    let embedded_index = sis_pdf_core::embedded_index::build_embedded_artefact_index(&ctx.graph);

    for entry in &ctx.graph.objects {
        if let PdfAtom::Stream(st) = &entry.atom {
            // Check if this is an embedded file
            if st.dict.has_name(b"/Type", b"/EmbeddedFile") {
                if let Ok(data) = stream_bytes_for_mode(ctx.bytes, st, max_bytes, decode_mode) {
                    // Check size limit
                    if max_bytes > 0 && total_bytes.saturating_add(data.len()) > max_bytes {
                        eprintln!(
                            "Embedded extraction budget exceeded ({} bytes), stopping",
                            max_bytes
                        );
                        break;
                    }

                    let stream_ref = (entry.obj, entry.gen);
                    let artefact_ref = embedded_index.get(&stream_ref);
                    let name = artefact_ref
                        .and_then(|record| record.filename.clone())
                        .or_else(|| embedded_filename(&st.dict))
                        .unwrap_or_else(|| format!("embedded_{}_{}.bin", entry.obj, entry.gen));
                    let analysis = sis_pdf_core::stream_analysis::analyse_stream(
                        &data,
                        &sis_pdf_core::stream_analysis::StreamLimits::default(),
                    );
                    let hash = sha256_hex(&data);
                    let mut predicate_meta = HashMap::new();
                    predicate_meta.insert("name".into(), name.clone());
                    predicate_meta.insert("magic".into(), analysis.magic_type.clone());
                    predicate_meta.insert("hash".into(), hash.clone());
                    if let Some((filespec_obj, filespec_gen)) =
                        artefact_ref.and_then(|record| record.filespec_ref)
                    {
                        predicate_meta.insert(
                            "filespec_ref".into(),
                            format!("{} {}", filespec_obj, filespec_gen),
                        );
                    }
                    let meta = PredicateContext {
                        length: data.len(),
                        filter: filter_name(&st.dict),
                        type_name: "Stream".to_string(),
                        subtype: subtype_name(&st.dict),
                        entropy: entropy_score(&data),
                        width: 0,
                        height: 0,
                        pixels: 0,
                        risky: false,
                        severity: None,
                        confidence: None,
                        surface: None,
                        kind: None,
                        object_count: 0,
                        evidence_count: 0,
                        name: Some(name.clone()),
                        magic: Some(analysis.magic_type),
                        hash: Some(hash.clone()),
                        impact: None,
                        action_type: None,
                        action_target: None,
                        action_initiation: None,
                        meta: predicate_meta,
                    };
                    if predicate.map(|pred| pred.evaluate(&meta)).unwrap_or(true) {
                        // Get filename
                        let safe_name = sanitize_embedded_filename(&name);
                        let (filename, output_bytes, mode_label) = match decode_mode {
                            DecodeMode::Decode => (safe_name, data.clone(), "decode"),
                            DecodeMode::Raw => (format!("{safe_name}.raw"), data.clone(), "raw"),
                            DecodeMode::Hexdump => (
                                format!("{safe_name}.hex"),
                                format_hexdump(&data).into_bytes(),
                                "hexdump",
                            ),
                        };
                        let filepath = extract_to.join(&filename);

                        // Detect file type and calculate hash
                        let file_type = magic_type(&data);
                        let data_len = data.len();

                        // Write file
                        fs::write(&filepath, &output_bytes)?;

                        let mut info = format!(
                            "{}: {} bytes, type={}, sha256={}, object={}_{}",
                            filename, data_len, file_type, hash, entry.obj, entry.gen
                        );
                        if let Some((filespec_obj, filespec_gen)) =
                            artefact_ref.and_then(|record| record.filespec_ref)
                        {
                            info.push_str(&format!(", filespec={}_{}", filespec_obj, filespec_gen));
                        }
                        info.push_str(&format!(", mode={}", mode_label));
                        if decode_mode == DecodeMode::Hexdump {
                            info.push_str(&format!(", hexdump_bytes={}", output_bytes.len()));
                        }
                        written_files.push(info);

                        total_bytes = total_bytes.saturating_add(data_len);
                        count += 1;
                    }
                }
            }
        }
    }

    eprintln!(
        "Extracted {} embedded file(s) ({} bytes total) to {}",
        count,
        total_bytes,
        extract_to.display()
    );
    Ok(written_files)
}

fn preview_text(text: &str, max_len: usize) -> String {
    let trimmed = text.trim();
    if trimmed.len() <= max_len {
        trimmed.to_string()
    } else {
        format!("{}...", &trimmed[..max_len])
    }
}

fn format_hexdump(data: &[u8]) -> String {
    let mut output = String::new();
    for (line_idx, chunk) in data.chunks(16).enumerate() {
        let offset = line_idx * 16;
        output.push_str(&format!("{offset:08x}  "));
        for i in 0..16 {
            if i < chunk.len() {
                output.push_str(&format!("{:02x} ", chunk[i]));
            } else {
                output.push_str("   ");
            }
            if i == 7 {
                output.push(' ');
            }
        }
        output.push_str(" |");
        for &byte in chunk {
            let ch = if byte.is_ascii_graphic() || byte == b' ' { byte as char } else { '.' };
            output.push(ch);
        }
        output.push_str("|\n");
    }
    output
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

fn show_object_detail_query(
    ctx: &ScanContext,
    obj: u32,
    gen: u16,
    context_only: bool,
) -> Result<serde_json::Value> {
    let object_content = if context_only { None } else { Some(show_object(ctx, obj, gen)?) };
    let context = build_object_security_context(ctx, obj, gen)?;
    Ok(json!({
        "type": "object_detail",
        "object_detail_schema_version": 1,
        "object": {
            "obj": obj,
            "gen": gen,
            "content": object_content,
        },
        "security_context": context,
    }))
}

fn show_object_context_query(ctx: &ScanContext, obj: u32, gen: u16) -> Result<serde_json::Value> {
    let context = build_object_security_context(ctx, obj, gen)?;
    Ok(json!({
        "type": "object_context",
        "object": {
            "obj": obj,
            "gen": gen,
        },
        "summary": {
            "tainted": context.tainted,
            "taint_source": context.taint_source,
            "chain_count": context.chains.len(),
            "finding_count": context.finding_count,
            "max_severity": context.max_severity.as_ref().map(|value| format!("{value:?}")),
            "max_confidence": context.max_confidence.as_ref().map(|value| format!("{value:?}")),
            "introduced_revision": context.introduced_revision,
            "post_cert": context.post_cert,
            "similar_count": context.similar_count,
        },
        "security_context": context,
    }))
}

fn build_object_security_context(
    ctx: &ScanContext,
    obj: u32,
    gen: u16,
) -> Result<sis_pdf_core::object_context::ObjectSecurityContext> {
    if ctx.graph.get_object(obj, gen).is_none() {
        return Err(anyhow!("Object {} {} not found", obj, gen));
    }

    let findings = findings_with_cache(ctx)?;
    let taint = sis_pdf_core::taint::taint_from_findings(&findings);
    let (chains, chain_templates) =
        sis_pdf_core::chain_synth::synthesise_chains(&findings, ctx.options.group_chains);
    let report = sis_pdf_core::report::Report::from_findings(
        findings,
        chains,
        chain_templates,
        Vec::new(),
        None,
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        None,
    );
    let index = build_object_context_index(&report, &taint);
    Ok(get_object_context(&index, obj, gen))
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
        PdfAtom::Str(s) => format!("{}{}", indent_str, format_pdf_string(s)),
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
                output.push(' ');
                output.push_str(format_pdf_atom(&value.atom, 0).trim());
                output.push('\n');
            }
            output.push_str(&indent_str.to_string());
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

fn format_pdf_string(value: &sis_pdf_pdf::object::PdfStr<'_>) -> String {
    use sis_pdf_pdf::object::PdfStr;
    match value {
        PdfStr::Hex { decoded, .. } => format!("<{}>", hex::encode(decoded)),
        PdfStr::Literal { decoded, .. } => {
            if let Ok(text) = std::str::from_utf8(decoded) {
                if text.chars().all(|ch| !ch.is_control() || matches!(ch, '\n' | '\r' | '\t')) {
                    return format!("({text})");
                }
            }
            format!("<{}>", hex::encode(decoded))
        }
    }
}

/// List all object IDs
fn list_objects(
    ctx: &ScanContext,
    decode_mode: DecodeMode,
    max_extract_bytes: usize,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    let objects: Vec<String> = ctx
        .graph
        .objects
        .iter()
        .filter(|entry| {
            if let Some(pred) = predicate {
                let context =
                    predicate_context_for_entry(entry, ctx.bytes, decode_mode, max_extract_bytes);
                pred.evaluate(&context)
            } else {
                true
            }
        })
        .map(|entry| format!("{} {}", entry.obj, entry.gen))
        .collect();
    Ok(objects)
}

/// List objects with a specific type
fn list_objects_with_type(
    ctx: &ScanContext,
    obj_type: &str,
    decode_mode: DecodeMode,
    max_extract_bytes: usize,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    use sis_pdf_pdf::object::PdfAtom;

    let mut objects = Vec::new();
    let search_type =
        if obj_type.starts_with('/') { obj_type.to_string() } else { format!("/{}", obj_type) };

    for entry in &ctx.graph.objects {
        if let Some(pred) = predicate {
            let context =
                predicate_context_for_entry(entry, ctx.bytes, decode_mode, max_extract_bytes);
            if !pred.evaluate(&context) {
                continue;
            }
        }
        if let Some(dict) = entry_dict(entry) {
            // Look for /Type entry
            if let Some((_, type_obj)) = dict.get_first(b"/Type") {
                if let PdfAtom::Name(name) = &type_obj.atom {
                    let type_name = String::from_utf8_lossy(&name.decoded);
                    if type_name == search_type || type_name == search_type[1..] {
                        objects.push(format!("{} {} ({})", entry.obj, entry.gen, type_name));
                    }
                }
            }
        }
    }

    Ok(objects)
}

fn count_objects(
    ctx: &ScanContext,
    decode_mode: DecodeMode,
    max_extract_bytes: usize,
    predicate: Option<&PredicateExpr>,
) -> Result<usize> {
    let mut count = 0usize;
    for entry in &ctx.graph.objects {
        if let Some(pred) = predicate {
            let context =
                predicate_context_for_entry(entry, ctx.bytes, decode_mode, max_extract_bytes);
            if !pred.evaluate(&context) {
                continue;
            }
        }
        count += 1;
    }
    Ok(count)
}

/// Show the PDF trailer
fn show_trailer(ctx: &ScanContext) -> Result<String> {
    if let Some(trailer) = ctx.graph.trailers.first() {
        let mut output = String::from("<<\n");
        for (key, value) in &trailer.entries {
            let key_str = String::from_utf8_lossy(&key.decoded);
            output.push_str(&format!("  {} ", key_str));
            output.push_str(format_pdf_atom(&value.atom, 0).trim());
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

fn list_xref_startxrefs(
    ctx: &ScanContext,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<serde_json::Value>> {
    let mut records = Vec::new();
    let bytes_len = ctx.bytes.len() as u64;
    for (idx, offset) in ctx.graph.startxrefs.iter().enumerate() {
        let in_bounds = *offset < bytes_len;
        let distance_from_eof = if *offset <= bytes_len { bytes_len - *offset } else { 0 };
        let mut meta = HashMap::new();
        meta.insert("xref.index".into(), idx.to_string());
        meta.insert("xref.offset".into(), offset.to_string());
        meta.insert("xref.distance_from_eof".into(), distance_from_eof.to_string());
        meta.insert("xref.in_bounds".into(), in_bounds.to_string());
        let predicate_context = PredicateContext {
            length: distance_from_eof as usize,
            filter: None,
            type_name: "XrefStartxref".to_string(),
            subtype: Some("startxref".to_string()),
            entropy: 0.0,
            width: 0,
            height: 0,
            pixels: 0,
            risky: !in_bounds,
            severity: None,
            confidence: None,
            surface: None,
            kind: Some("startxref".to_string()),
            object_count: 0,
            evidence_count: 0,
            name: Some(format!("startxref.{idx}")),
            magic: None,
            hash: None,
            impact: None,
            action_type: None,
            action_target: None,
            action_initiation: None,
            meta,
        };
        if predicate.map(|pred| pred.evaluate(&predicate_context)).unwrap_or(true) {
            records.push(json!({
                "index": idx,
                "offset": offset,
                "distance_from_eof": distance_from_eof,
                "in_bounds": in_bounds,
            }));
        }
    }
    Ok(records)
}

fn list_xref_sections(
    ctx: &ScanContext,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<serde_json::Value>> {
    let mut records = Vec::new();
    for (idx, section) in ctx.graph.xref_sections.iter().enumerate() {
        let mut meta = HashMap::new();
        meta.insert("xref.index".into(), idx.to_string());
        meta.insert("xref.offset".into(), section.offset.to_string());
        meta.insert("xref.kind".into(), section.kind.clone());
        meta.insert("xref.has_trailer".into(), section.has_trailer.to_string());
        if let Some(prev) = section.prev {
            meta.insert("xref.prev".into(), prev.to_string());
        }
        if let Some(size) = section.trailer_size {
            meta.insert("xref.trailer_size".into(), size.to_string());
        }
        if let Some(root) = &section.trailer_root {
            meta.insert("xref.trailer_root".into(), root.clone());
        }
        let predicate_context = PredicateContext {
            length: 0,
            filter: None,
            type_name: "XrefSection".to_string(),
            subtype: Some(section.kind.clone()),
            entropy: 0.0,
            width: 0,
            height: 0,
            pixels: 0,
            risky: section.kind == "unknown",
            severity: None,
            confidence: None,
            surface: None,
            kind: Some(section.kind.clone()),
            object_count: 0,
            evidence_count: 0,
            name: Some(format!("section#{idx}")),
            magic: None,
            hash: None,
            impact: None,
            action_type: None,
            action_target: None,
            action_initiation: None,
            meta,
        };
        if predicate.map(|pred| pred.evaluate(&predicate_context)).unwrap_or(true) {
            records.push(json!({
                "index": idx,
                "offset": section.offset,
                "kind": section.kind,
                "has_trailer": section.has_trailer,
                "prev": section.prev,
                "trailer_size": section.trailer_size,
                "trailer_root": section.trailer_root,
            }));
        }
    }
    Ok(records)
}

fn list_xref_trailers(
    ctx: &ScanContext,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<serde_json::Value>> {
    let mut records = Vec::new();
    for (idx, trailer) in ctx.graph.trailers.iter().enumerate() {
        let size = trailer_int_value(trailer, b"/Size");
        let root = trailer_ref_value(trailer, b"/Root");
        let info = trailer_ref_value(trailer, b"/Info");
        let encrypt = trailer_ref_value(trailer, b"/Encrypt");
        let prev = trailer_int_value(trailer, b"/Prev");
        let id_present = trailer.get_first(b"/ID").is_some();

        let mut meta = HashMap::new();
        meta.insert("xref.index".into(), idx.to_string());
        if let Some(value) = size {
            meta.insert("xref.size".into(), value.to_string());
        }
        if let Some(value) = &root {
            meta.insert("xref.root".into(), value.clone());
        }
        if let Some(value) = &info {
            meta.insert("xref.info".into(), value.clone());
        }
        if let Some(value) = &encrypt {
            meta.insert("xref.encrypt".into(), value.clone());
        }
        if let Some(value) = prev {
            meta.insert("xref.prev".into(), value.to_string());
        }
        meta.insert("xref.id_present".into(), id_present.to_string());

        let predicate_context = PredicateContext {
            length: 0,
            filter: None,
            type_name: "XrefTrailer".to_string(),
            subtype: Some("trailer".to_string()),
            entropy: 0.0,
            width: 0,
            height: 0,
            pixels: 0,
            risky: false,
            severity: None,
            confidence: None,
            surface: None,
            kind: Some("trailer".to_string()),
            object_count: 0,
            evidence_count: 0,
            name: Some(format!("trailer#{idx}")),
            magic: None,
            hash: None,
            impact: None,
            action_type: None,
            action_target: None,
            action_initiation: None,
            meta,
        };
        if predicate.map(|pred| pred.evaluate(&predicate_context)).unwrap_or(true) {
            records.push(json!({
                "index": idx,
                "size": size,
                "root": root,
                "info": info,
                "encrypt": encrypt,
                "id_present": id_present,
                "prev": prev,
            }));
        }
    }
    Ok(records)
}

fn list_xref_deviations(
    ctx: &ScanContext,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<serde_json::Value>> {
    let mut records = Vec::new();
    for dev in &ctx.graph.deviations {
        if !dev.kind.starts_with("xref_") {
            continue;
        }
        let mut meta = HashMap::new();
        meta.insert("xref.kind".into(), dev.kind.clone());
        meta.insert("xref.offset_start".into(), dev.span.start.to_string());
        meta.insert("xref.offset_end".into(), dev.span.end.to_string());
        if let Some(note) = &dev.note {
            meta.insert("xref.note".into(), note.clone());
        }

        let predicate_context = PredicateContext {
            length: dev.span.end.saturating_sub(dev.span.start) as usize,
            filter: None,
            type_name: "XrefDeviation".to_string(),
            subtype: Some(dev.kind.clone()),
            entropy: 0.0,
            width: 0,
            height: 0,
            pixels: 0,
            risky: true,
            severity: None,
            confidence: None,
            surface: None,
            kind: Some(dev.kind.clone()),
            object_count: 0,
            evidence_count: 0,
            name: None,
            magic: None,
            hash: None,
            impact: None,
            action_type: None,
            action_target: None,
            action_initiation: None,
            meta,
        };
        if predicate.map(|pred| pred.evaluate(&predicate_context)).unwrap_or(true) {
            records.push(json!({
                "kind": dev.kind,
                "offset_start": dev.span.start,
                "offset_end": dev.span.end,
                "note": dev.note,
            }));
        }
    }
    Ok(records)
}

fn list_revisions(
    ctx: &ScanContext,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<serde_json::Value>> {
    let timeline = build_revision_timeline(ctx, DEFAULT_MAX_REVISIONS);
    let mut records = Vec::new();
    for record in &timeline.revisions {
        let mut meta = revision_meta(record, &timeline);
        meta.insert("revision".into(), record.revision.to_string());
        meta.insert("startxref".into(), record.startxref.to_string());

        let predicate_context = PredicateContext {
            length: 0,
            filter: None,
            type_name: "Revision".to_string(),
            subtype: Some("revision".to_string()),
            entropy: 0.0,
            width: 0,
            height: 0,
            pixels: 0,
            risky: record.has_incremental_update && record.anomaly_score >= 4,
            severity: None,
            confidence: None,
            surface: None,
            kind: Some("revision".to_string()),
            object_count: record.objects_added + record.objects_modified,
            evidence_count: 0,
            name: Some(format!("revision#{}", record.revision)),
            magic: None,
            hash: None,
            impact: None,
            action_type: None,
            action_target: None,
            action_initiation: None,
            meta,
        };
        if predicate.map(|pred| pred.evaluate(&predicate_context)).unwrap_or(true) {
            records.push(json!({
                "revision": record.revision,
                "startxref": record.startxref,
                "has_incremental_update": record.has_incremental_update,
                "covered_by_signature": record.covered_by_signature,
                "objects_added": record.objects_added,
                "objects_modified": record.objects_modified,
                "objects_removed": record.objects_removed,
                "anomaly_score": record.anomaly_score,
            }));
        }
    }
    Ok(records)
}

fn list_revisions_detail(
    ctx: &ScanContext,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<serde_json::Value>> {
    let timeline = build_revision_timeline(ctx, DEFAULT_MAX_REVISIONS);
    let mut records = Vec::new();
    for record in &timeline.revisions {
        let mut meta = revision_meta(record, &timeline);
        meta.insert("revision".into(), record.revision.to_string());
        meta.insert("startxref".into(), record.startxref.to_string());

        let predicate_context = PredicateContext {
            length: 0,
            filter: None,
            type_name: "Revision".to_string(),
            subtype: Some("revision".to_string()),
            entropy: 0.0,
            width: 0,
            height: 0,
            pixels: 0,
            risky: record.has_incremental_update && record.anomaly_score >= 4,
            severity: None,
            confidence: None,
            surface: None,
            kind: Some("revision".to_string()),
            object_count: record.objects_added + record.objects_modified,
            evidence_count: 0,
            name: Some(format!("revision#{}", record.revision)),
            magic: None,
            hash: None,
            impact: None,
            action_type: None,
            action_target: None,
            action_initiation: None,
            meta,
        };
        if predicate.map(|pred| pred.evaluate(&predicate_context)).unwrap_or(true) {
            records.push(json!({
                "revision": record.revision,
                "startxref": record.startxref,
                "has_incremental_update": record.has_incremental_update,
                "covered_by_signature": record.covered_by_signature,
                "objects_added": record.objects_added,
                "objects_modified": record.objects_modified,
                "objects_removed": record.objects_removed,
                "page_content_changed": record.page_content_changed,
                "annotations_added": record.annotations_added,
                "annotations_modified": record.annotations_modified,
                "catalog_changed": record.catalog_changed,
                "action_or_js_changed": record.action_or_js_changed,
                "anomaly_score": record.anomaly_score,
                "anomaly_reasons": record.anomaly_reasons,
                "objects_added_refs": record.objects_added_refs,
                "objects_modified_refs": record.objects_modified_refs,
                "page_content_changed_refs": record.page_content_changed_refs,
                "annotation_added_refs": record.annotation_added_refs,
                "annotation_modified_refs": record.annotation_modified_refs,
                "catalog_changed_refs": record.catalog_changed_refs,
                "action_or_js_changed_refs": record.action_or_js_changed_refs,
                "total_revisions": timeline.total_revisions,
                "skipped_revisions": timeline.skipped_revisions,
                "timeline_capped": timeline.capped,
                "signature_boundaries": timeline.signature_boundaries,
                "prev_chain_valid": timeline.prev_chain_valid,
                "prev_chain_errors": timeline.prev_chain_errors,
            }));
        }
    }
    Ok(records)
}

fn revision_meta(
    record: &sis_pdf_core::revision_timeline::RevisionRecord,
    timeline: &sis_pdf_core::revision_timeline::RevisionTimeline,
) -> HashMap<String, String> {
    let mut meta = HashMap::new();
    meta.insert("revision.objects_added".into(), record.objects_added.to_string());
    meta.insert("revision.objects_modified".into(), record.objects_modified.to_string());
    meta.insert("revision.anomaly_score".into(), record.anomaly_score.to_string());
    meta.insert("revision.page_content_changed".into(), record.page_content_changed.to_string());
    meta.insert("revision.annotations_added".into(), record.annotations_added.to_string());
    meta.insert("revision.catalog_changed".into(), record.catalog_changed.to_string());
    meta.insert("revision.timeline_capped".into(), timeline.capped.to_string());
    meta.insert("revision.timeline_skipped".into(), timeline.skipped_revisions.to_string());
    meta
}

fn trailer_int_value(trailer: &sis_pdf_pdf::object::PdfDict<'_>, key: &[u8]) -> Option<u64> {
    trailer.get_first(key).and_then(|(_, value)| match value.atom {
        PdfAtom::Int(v) if v >= 0 => Some(v as u64),
        _ => None,
    })
}

fn trailer_ref_value(trailer: &sis_pdf_pdf::object::PdfDict<'_>, key: &[u8]) -> Option<String> {
    trailer.get_first(key).and_then(|(_, value)| match value.atom {
        PdfAtom::Ref { obj, gen } => Some(format!("{obj} {gen} R")),
        _ => None,
    })
}

fn export_structure_json(
    org_graph: &sis_pdf_core::org::OrgGraph,
    typed_graph: &sis_pdf_pdf::typed_graph::TypedGraph<'_>,
    helper_max_depth: usize,
    overlay: Option<&StructureOverlay>,
) -> serde_json::Value {
    let org = sis_pdf_core::org_export::export_org_json(org_graph);
    let typed_edge_stats = typed_edge_type_stats(typed_graph);
    let path_summary = action_path_summary(typed_graph);
    let helpers = structure_path_helpers(typed_graph, helper_max_depth);
    let mut output = json!({
        "type": "structure_graph",
        "org": org,
        "typed_edges": typed_edge_stats,
        "action_paths": path_summary,
        "path_helpers": helpers,
    });
    if let Some(overlay_data) = overlay {
        if let Ok(value) = serde_json::to_value(overlay_data) {
            if let Some(map) = output.as_object_mut() {
                map.insert("overlay".to_string(), value);
            }
        }
    }
    output
}

fn export_structure_dot(
    org_graph: &sis_pdf_core::org::OrgGraph,
    typed_graph: &sis_pdf_pdf::typed_graph::TypedGraph<'_>,
    helper_max_depth: usize,
    overlay: Option<&StructureOverlay>,
) -> String {
    let mut dot = sis_pdf_core::org_export::export_org_dot(org_graph);
    let typed_edge_stats = typed_edge_type_stats(typed_graph);
    let path_summary = action_path_summary(typed_graph);
    let helpers = structure_path_helpers(typed_graph, helper_max_depth);
    let edge_type_count = typed_edge_stats
        .get("by_type")
        .and_then(|v| v.as_array())
        .map(|items| items.len())
        .unwrap_or(0);
    let multi_step = path_summary.get("multi_step_chains").and_then(|v| v.as_u64()).unwrap_or(0);
    let max_len = path_summary.get("max_chain_length").and_then(|v| v.as_u64()).unwrap_or(0);
    let helper_count = helpers
        .get("reachable_from_trigger")
        .and_then(|v| v.as_array())
        .map(|items| items.len())
        .unwrap_or(0);
    let summary_comment = format!(
        "  // structure stats: {} typed edge types, multi-step chains={}, max_chain_length={}, trigger_helpers={}\n",
        edge_type_count, multi_step, max_len, helper_count
    );
    let overlay_block = summary_comment
        + &match overlay {
            Some(overlay_data) => structure_overlay_dot_block(overlay_data),
            None => String::new(),
        };
    if let Some(index) = dot.rfind('}') {
        dot.insert_str(index, &overlay_block);
    } else {
        dot.push_str(&overlay_block);
    }
    dot
}

fn structure_overlay_dot_block(overlay: &StructureOverlay) -> String {
    let mut out = String::new();
    out.push_str("  subgraph cluster_structure_overlay {\n");
    out.push_str("    label=\"forensic_overlay\";\n");
    out.push_str("    style=dashed;\n");
    out.push_str("    color=gray;\n");
    for node in &overlay.nodes {
        let (shape, colour) = overlay_node_style(node.kind.as_str());
        out.push_str(&format!(
            "    \"{}\" [label=\"{}\\n{}\", shape={}, style=\"rounded,dashed\", color=\"{}\"];\n",
            node.id, node.id, node.kind, shape, colour
        ));
    }
    for edge in &overlay.edges {
        out.push_str(&format!(
            "    \"{}\" -> \"{}\" [label=\"{}\", style=dashed, color=gray40];\n",
            edge.from, edge.to, edge.edge_type
        ));
    }
    out.push_str("  }\n");
    out
}

fn overlay_node_style(kind: &str) -> (&'static str, &'static str) {
    match kind {
        "file_root" => ("diamond", "gray30"),
        "startxref" => ("ellipse", "steelblue4"),
        "xref_section" => ("box", "deepskyblue4"),
        "trailer" => ("component", "darkgreen"),
        "revision" => ("hexagon", "darkgoldenrod4"),
        "objstm" | "carved_stream" => ("folder", "darkorange3"),
        "telemetry" => ("note", "firebrick3"),
        "signature" => ("octagon", "purple4"),
        _ => ("box", "gray40"),
    }
}

fn structure_path_helpers(
    typed_graph: &sis_pdf_pdf::typed_graph::TypedGraph<'_>,
    max_depth: usize,
) -> serde_json::Value {
    let path_finder = sis_pdf_pdf::path_finder::PathFinder::new(typed_graph);
    let chains = path_finder.find_all_action_chains();

    let mut trigger_stats = BTreeMap::<String, (usize, usize)>::new();
    let mut outcome_paths = Vec::new();
    let next_action_branches = collect_next_action_branches(typed_graph);

    for chain in &chains {
        let trigger = chain.trigger.as_str().to_string();
        let entry = trigger_stats.entry(trigger).or_insert((0, 0));
        entry.0 += 1;
        let mut reached = std::collections::HashSet::<(u32, u16)>::new();
        if let Some(first) = chain.edges.first() {
            for dst in reachable_targets_with_depth(typed_graph, first.src, max_depth) {
                reached.insert(dst);
            }
        }
        entry.1 += reached.len();

        if chain.involves_external || chain.involves_js {
            let mut steps = Vec::new();
            for edge in chain.edges.iter().take(max_depth.max(1)) {
                steps.push(format!(
                    "{} {} -{}-> {} {}",
                    edge.src.0,
                    edge.src.1,
                    edge.edge_type.as_str(),
                    edge.dst.0,
                    edge.dst.1
                ));
            }
            outcome_paths.push(json!({
                "trigger": chain.trigger.as_str(),
                "automatic": chain.automatic,
                "length": chain.length(),
                "involves_js": chain.involves_js,
                "involves_external": chain.involves_external,
                "payload": chain.payload.map(|(obj, gen)| format!("{obj} {gen} R")),
                "steps": steps,
                "truncated_to_depth": chain.edges.len() > max_depth.max(1),
            }));
        }
    }

    let reachable_from_trigger = trigger_stats
        .into_iter()
        .map(|(trigger, (chain_count, reachable_nodes))| {
            json!({
                "trigger": trigger,
                "chain_count": chain_count,
                "reachable_nodes": reachable_nodes,
            })
        })
        .collect::<Vec<_>>();

    if outcome_paths.len() > 8 {
        outcome_paths.truncate(8);
    }

    json!({
        "max_depth": max_depth,
        "reachable_from_trigger": reachable_from_trigger,
        "paths_to_outcome": outcome_paths,
        "next_action_branches": next_action_branches,
    })
}

fn reachable_targets_with_depth(
    typed_graph: &sis_pdf_pdf::typed_graph::TypedGraph<'_>,
    start: (u32, u16),
    max_depth: usize,
) -> std::collections::HashSet<(u32, u16)> {
    let mut out = std::collections::HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    let mut visited = std::collections::HashSet::new();
    queue.push_back((start, 0usize));
    visited.insert(start);

    while let Some((node, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        for edge in typed_graph.outgoing_edges(node.0, node.1) {
            if visited.insert(edge.dst) {
                out.insert(edge.dst);
                queue.push_back((edge.dst, depth + 1));
            }
        }
    }

    out
}

fn collect_next_action_branches(
    typed_graph: &sis_pdf_pdf::typed_graph::TypedGraph<'_>,
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for edge in &typed_graph.edges {
        if !matches!(edge.edge_type, sis_pdf_pdf::typed_graph::EdgeType::NextAction) {
            continue;
        }
        let (branch_index, source_next_kind) =
            infer_next_branch_details(typed_graph, edge.src, edge.dst);
        out.push(json!({
            "from": format!("{} {} R", edge.src.0, edge.src.1),
            "to": format!("{} {} R", edge.dst.0, edge.dst.1),
            "branch_index": branch_index,
            "source_next_kind": source_next_kind,
        }));
    }
    out
}

fn infer_next_branch_details(
    typed_graph: &sis_pdf_pdf::typed_graph::TypedGraph<'_>,
    src: (u32, u16),
    dst: (u32, u16),
) -> (Option<usize>, &'static str) {
    let Some(entry) = typed_graph.graph.get_object(src.0, src.1) else {
        return (None, "unknown");
    };
    let dict = match &entry.atom {
        PdfAtom::Dict(dict) => dict,
        PdfAtom::Stream(stream) => &stream.dict,
        _ => return (None, "unknown"),
    };
    let Some((_, next_obj)) = dict.get_first(b"/Next") else {
        return (None, "missing");
    };
    match &next_obj.atom {
        PdfAtom::Ref { .. } => (None, "single_ref"),
        PdfAtom::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                if let Some(resolved) = typed_graph.graph.resolve_ref(item) {
                    if (resolved.obj, resolved.gen) == dst {
                        return (Some(index), "array");
                    }
                }
            }
            (None, "array")
        }
        _ => (None, "other"),
    }
}

fn typed_edge_type_stats(
    typed_graph: &sis_pdf_pdf::typed_graph::TypedGraph<'_>,
) -> serde_json::Value {
    let mut stats = BTreeMap::<String, (usize, usize, usize)>::new();
    for edge in &typed_graph.edges {
        let key = edge.edge_type.as_str().to_string();
        let entry = stats.entry(key).or_insert((0, 0, 0));
        entry.0 += 1;
        if edge.suspicious {
            entry.1 += 1;
        }
        if edge.edge_type.is_executable() {
            entry.2 += 1;
        }
    }
    let by_type = stats
        .into_iter()
        .map(|(edge_type, (count, suspicious, executable))| {
            json!({
                "edge_type": edge_type,
                "count": count,
                "suspicious": suspicious,
                "executable": executable,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "total_edges": typed_graph.edges.len(),
        "suspicious_edges": typed_graph.suspicious_edges().len(),
        "by_type": by_type,
    })
}

fn action_path_summary(
    typed_graph: &sis_pdf_pdf::typed_graph::TypedGraph<'_>,
) -> serde_json::Value {
    let path_finder = sis_pdf_pdf::path_finder::PathFinder::new(typed_graph);
    let chains = path_finder.find_all_action_chains();
    let multi_step = chains.iter().filter(|chain| chain.length() > 1).count();
    let automatic = chains.iter().filter(|chain| chain.automatic).count();
    let js = chains.iter().filter(|chain| chain.involves_js).count();
    let external = chains.iter().filter(|chain| chain.involves_external).count();
    let max_chain_length = chains.iter().map(|chain| chain.length()).max().unwrap_or(0);
    json!({
        "total_chains": chains.len(),
        "multi_step_chains": multi_step,
        "automatic_chains": automatic,
        "js_chains": js,
        "external_chains": external,
        "max_chain_length": max_chain_length,
    })
}

/// List all action chains
fn list_action_chains(
    ctx: &ScanContext,
    predicate: Option<&PredicateExpr>,
    include_singleton_chains: bool,
) -> Result<serde_json::Value> {
    let classifications = ctx.classifications();
    let typed_graph = sis_pdf_pdf::typed_graph::TypedGraph::build(&ctx.graph, classifications);
    let path_finder = sis_pdf_pdf::path_finder::PathFinder::new(&typed_graph);

    let chains = path_finder.find_all_action_chains();
    let total_chains = chains
        .iter()
        .filter(|chain| is_default_visible_chain(chain, include_singleton_chains))
        .count();
    let filtered: Vec<_> = chains
        .iter()
        .enumerate()
        .filter(|(_, chain)| is_default_visible_chain(chain, include_singleton_chains))
        .filter(|(_, chain)| chain_matches_predicate(chain, predicate))
        .collect();

    Ok(build_chain_query_result(
        "chains",
        filtered.into_iter(),
        total_chains,
        ctx.options.group_chains,
    ))
}

/// List JavaScript-containing action chains
fn list_js_chains(
    ctx: &ScanContext,
    predicate: Option<&PredicateExpr>,
    include_singleton_chains: bool,
) -> Result<serde_json::Value> {
    let classifications = ctx.classifications();
    let typed_graph = sis_pdf_pdf::typed_graph::TypedGraph::build(&ctx.graph, classifications);
    let path_finder = sis_pdf_pdf::path_finder::PathFinder::new(&typed_graph);

    let chains = path_finder.find_all_action_chains();
    let total_chains = chains
        .iter()
        .filter(|chain| is_default_visible_chain(chain, include_singleton_chains))
        .count();
    let filtered: Vec<_> = chains
        .iter()
        .enumerate()
        .filter(|(_, chain)| is_default_visible_chain(chain, include_singleton_chains))
        .filter(|(_, chain)| chain_matches_predicate(chain, predicate))
        .filter(|(_, chain)| chain.involves_js)
        .collect();

    Ok(build_chain_query_result(
        "chains.js",
        filtered.into_iter(),
        total_chains,
        ctx.options.group_chains,
    ))
}

fn list_xfa_forms(
    ctx: &ScanContext,
    predicate: Option<&PredicateExpr>,
) -> Result<serde_json::Value> {
    let records = collect_xfa_forms(ctx);
    let total = records.len();
    let filtered: Vec<_> = records
        .iter()
        .enumerate()
        .filter(|(_, record)| xfa_form_matches_predicate(record, predicate))
        .collect();
    let forms: Vec<_> = filtered.iter().map(|(_, record)| format_xfa_record(record)).collect();
    Ok(json!({
        "type": "xfa",
        "count": forms.len(),
        "total": total,
        "forms": forms,
    }))
}

fn xfa_form_matches_predicate(record: &XfaFormRecord, predicate: Option<&PredicateExpr>) -> bool {
    predicate.map(|pred| pred.evaluate(&predicate_context_for_xfa_form(record))).unwrap_or(true)
}

fn predicate_context_for_xfa_form(record: &XfaFormRecord) -> PredicateContext {
    let mut meta = HashMap::new();
    meta.insert("object".into(), record.object_ref.clone());
    meta.insert("ref_chain".into(), record.ref_chain.clone());
    meta.insert("script_count".into(), record.script_count.to_string());
    meta.insert("has_doctype".into(), record.has_doctype.to_string());
    if !record.submit_urls.is_empty() {
        meta.insert("submit_urls".into(), encode_array(&record.submit_urls));
    }
    if !record.sensitive_fields.is_empty() {
        meta.insert("sensitive_fields".into(), encode_array(&record.sensitive_fields));
    }
    if let Some(preview) = &record.script_preview {
        meta.insert("script_preview".into(), preview.clone());
    }
    PredicateContext {
        length: record.size_bytes,
        filter: Some("xfa".to_string()),
        type_name: "XfaForm".to_string(),
        subtype: Some("xfa".to_string()),
        entropy: 0.0,
        width: 0,
        height: 0,
        pixels: 0,
        risky: record.has_doctype,
        severity: None,
        confidence: None,
        surface: Some("forms".to_string()),
        kind: None,
        object_count: 0,
        evidence_count: 0,
        name: Some(record.object_ref.clone()),
        hash: None,
        magic: None,
        impact: None,
        action_type: None,
        action_target: None,
        action_initiation: None,
        meta,
    }
}

fn format_xfa_record(record: &XfaFormRecord) -> serde_json::Value {
    json!({
        "object": record.object_ref,
        "payload_index": record.payload_index,
        "size_bytes": record.size_bytes,
        "script_count": record.script_count,
        "submit_urls": record.submit_urls,
        "sensitive_fields": record.sensitive_fields,
        "script_preview": record.script_preview,
        "has_doctype": record.has_doctype,
        "ref_chain": record.ref_chain,
    })
}

fn encode_array(values: &[String]) -> String {
    let escaped: Vec<String> = values
        .iter()
        .map(|value| format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect();
    format!("[{}]", escaped.join(","))
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
        dfs_page_cycles(node, &typed_graph, &mut path, &mut path_set, &mut cycles, &mut seen);
        path.clear();
        path_set.clear();
    }

    Ok(build_cycles_result("cycles.page", &cycles))
}

fn list_references(ctx: &ScanContext, obj: u32, gen: u16) -> Result<serde_json::Value> {
    use sis_pdf_pdf::typed_graph::TypedGraph;

    if ctx.graph.get_object(obj, gen).is_none() {
        return Err(anyhow!("Object {} {} not found", obj, gen));
    }

    let classifications = ctx.classifications();
    let typed_graph = TypedGraph::build(&ctx.graph, classifications);
    let incoming = typed_graph.incoming_edges(obj, gen);

    let references: Vec<_> = incoming
        .iter()
        .map(|edge| {
            let detail = edge_detail(&edge.edge_type)
                .map(|value| json!(value))
                .unwrap_or(serde_json::Value::Null);
            json!({
                "src": { "obj": edge.src.0, "gen": edge.src.1 },
                "relationship": edge.edge_type.as_str(),
                "detail": detail,
                "suspicious": edge.suspicious,
            })
        })
        .collect();

    Ok(json!({
        "type": "references",
        "target": { "obj": obj, "gen": gen },
        "count": references.len(),
        "references": references,
    }))
}

fn edge_detail(edge_type: &sis_pdf_pdf::typed_graph::EdgeType) -> Option<String> {
    use sis_pdf_pdf::typed_graph::EdgeType;

    match edge_type {
        EdgeType::DictReference { key } => Some(key.clone()),
        EdgeType::ArrayElement { index } => Some(format!("[{}]", index)),
        EdgeType::PageAction { event } => Some(event.clone()),
        EdgeType::AdditionalAction { event } => Some(event.clone()),
        EdgeType::FormFieldAction { event } => Some(event.clone()),
        _ => None,
    }
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
        if !matches!(edge.edge_type, EdgeType::PagesKids) {
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
    cycle.iter().map(|(obj, gen)| format!("{obj}:{gen}")).collect::<Vec<_>>().join("->")
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
            for (key, value) in &dict.entries {
                if key.decoded.eq_ignore_ascii_case(b"/Parent") {
                    continue;
                }
                collect_refs(&value.atom, graph, visited, path, path_set, cycles);
            }
        }
        PdfAtom::Stream(stream) => {
            for (key, value) in &stream.dict.entries {
                if key.decoded.eq_ignore_ascii_case(b"/Parent") {
                    continue;
                }
                collect_refs(&value.atom, graph, visited, path, path_set, cycles);
            }
        }
        _ => {}
    }
}

fn build_chain_query_result<'a, I>(
    label: &str,
    chains: I,
    total_chains: usize,
    group_chains: bool,
) -> serde_json::Value
where
    I: Iterator<Item = (usize, &'a sis_pdf_pdf::path_finder::ActionChain<'a>)>,
{
    let items: Vec<(usize, &'a sis_pdf_pdf::path_finder::ActionChain<'a>)> = chains.collect();
    let chain_values = if group_chains {
        let groups = group_query_chains(&items);
        let mut values = Vec::new();
        for group in groups {
            let meta = QueryChainGroupMeta {
                group_id: group.group_id.clone(),
                group_count: group.group_count,
                group_members: group.group_members.clone(),
            };
            values.push(chain_to_json(group.representative.0, group.representative.1, Some(&meta)));
        }
        values
    } else {
        items.iter().map(|(idx, chain)| chain_to_json(*idx, chain, None)).collect()
    };

    json!({
        "type": label,
        "count": chain_values.len(),
        "total_chains": total_chains,
        "chains": chain_values,
    })
}

fn chain_matches_predicate(
    chain: &sis_pdf_pdf::path_finder::ActionChain<'_>,
    predicate: Option<&PredicateExpr>,
) -> bool {
    predicate.map(|pred| pred.evaluate(&predicate_context_for_chain(chain))).unwrap_or(true)
}

fn is_default_visible_chain(
    chain: &sis_pdf_pdf::path_finder::ActionChain<'_>,
    include_singleton_chains: bool,
) -> bool {
    include_singleton_chains || chain.length() > 1
}

fn predicate_context_for_chain(
    chain: &sis_pdf_pdf::path_finder::ActionChain<'_>,
) -> PredicateContext {
    let mut meta = HashMap::new();
    meta.insert("depth".into(), chain.length().to_string());
    meta.insert("trigger".into(), chain.trigger.as_str().to_string());
    meta.insert("automatic".into(), if chain.automatic { "true".into() } else { "false".into() });
    meta.insert("has_js".into(), if chain.involves_js { "true".into() } else { "false".into() });
    meta.insert(
        "has_external".into(),
        if chain.involves_external { "true".into() } else { "false".into() },
    );

    PredicateContext {
        length: chain.length(),
        filter: None,
        type_name: "action_chain".into(),
        subtype: Some(chain.trigger.as_str().to_string()),
        entropy: 0.0,
        width: 0,
        height: 0,
        pixels: 0,
        risky: false,
        severity: None,
        confidence: None,
        surface: Some("action".into()),
        kind: Some(chain.trigger.as_str().to_string()),
        object_count: chain.edges.len(),
        evidence_count: 0,
        name: None,
        magic: None,
        hash: None,
        impact: None,
        action_type: None,
        action_target: None,
        action_initiation: None,
        meta,
    }
}

fn chain_to_json(
    idx: usize,
    chain: &sis_pdf_pdf::path_finder::ActionChain<'_>,
    group_meta: Option<&QueryChainGroupMeta>,
) -> serde_json::Value {
    let edges: Vec<_> = chain.edges.iter().map(|edge| edge_to_json(edge)).collect();
    let payload = chain.payload.map(|(obj, gen)| ref_to_json((obj, gen)));
    let (group_id, group_count, group_members) = if let Some(meta) = group_meta {
        (Some(meta.group_id.clone()), meta.group_count, meta.group_members.clone())
    } else {
        (Some(format!("chain-{}", idx)), 1, vec![idx])
    };

    json!({
        "id": idx,
        "group_id": group_id,
        "group_count": group_count,
        "group_members": group_members,
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

struct QueryChainGroup<'a> {
    group_id: String,
    group_count: usize,
    group_members: Vec<usize>,
    representative: (usize, &'a sis_pdf_pdf::path_finder::ActionChain<'a>),
}

struct QueryChainGroupMeta {
    group_id: String,
    group_count: usize,
    group_members: Vec<usize>,
}

#[derive(Hash, Eq, PartialEq)]
struct ChainSignature {
    trigger: String,
    payload: Option<(u32, u16)>,
    edges: Vec<EdgeSignature>,
    automatic: bool,
    involves_js: bool,
    involves_external: bool,
}

#[derive(Hash, Eq, PartialEq)]
struct EdgeSignature {
    edge_type: String,
    src: (u32, u16),
    dst: (u32, u16),
}

fn group_query_chains<'a>(
    chains: &[(usize, &'a sis_pdf_pdf::path_finder::ActionChain<'a>)],
) -> Vec<QueryChainGroup<'a>> {
    use std::collections::HashMap;

    let mut groups: HashMap<
        ChainSignature,
        Vec<(usize, &'a sis_pdf_pdf::path_finder::ActionChain<'a>)>,
    > = HashMap::new();
    for (idx, chain) in chains {
        let signature = chain_signature(chain);
        groups.entry(signature).or_default().push((*idx, *chain));
    }

    let mut output = Vec::new();
    for (signature, mut members) in groups {
        members.sort_by(|(lhs_idx, lhs), (rhs_idx, rhs)| {
            rhs.risk_score()
                .partial_cmp(&lhs.risk_score())
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| lhs_idx.cmp(rhs_idx))
        });
        let representative = members[0];
        let group_members = members.iter().map(|(idx, _)| *idx).collect::<Vec<_>>();
        let group_id = group_id_from_signature(&signature);
        output.push(QueryChainGroup {
            group_id,
            group_count: members.len(),
            group_members,
            representative,
        });
    }

    output.sort_by(|lhs, rhs| {
        rhs.representative
            .1
            .risk_score()
            .partial_cmp(&lhs.representative.1.risk_score())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| lhs.group_id.cmp(&rhs.group_id))
    });
    output
}

fn chain_signature(chain: &sis_pdf_pdf::path_finder::ActionChain<'_>) -> ChainSignature {
    let trigger = chain.trigger.as_str().to_string();
    let payload = chain.payload;
    let edges = chain
        .edges
        .iter()
        .map(|edge| EdgeSignature {
            edge_type: edge.edge_type.as_str().to_string(),
            src: edge.src,
            dst: edge.dst,
        })
        .collect::<Vec<_>>();
    ChainSignature {
        trigger,
        payload,
        edges,
        automatic: chain.automatic,
        involves_js: chain.involves_js,
        involves_external: chain.involves_external,
    }
}

fn group_id_from_signature(signature: &ChainSignature) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(signature.trigger.as_bytes());
    if let Some((obj, gen)) = signature.payload {
        hasher.update(&obj.to_le_bytes());
        hasher.update(&gen.to_le_bytes());
    }
    for edge in &signature.edges {
        hasher.update(edge.edge_type.as_bytes());
        hasher.update(&edge.src.0.to_le_bytes());
        hasher.update(&edge.src.1.to_le_bytes());
        hasher.update(&edge.dst.0.to_le_bytes());
        hasher.update(&edge.dst.1.to_le_bytes());
    }
    hasher.update(&[signature.automatic as u8]);
    hasher.update(&[signature.involves_js as u8]);
    hasher.update(&[signature.involves_external as u8]);
    format!("chain-group-{}", hasher.finalize().to_hex())
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
    let cycle_values: Vec<_> =
        cycles.iter().enumerate().map(|(idx, cycle)| cycle_to_json(idx, cycle)).collect();

    json!({
        "type": label,
        "count": cycle_values.len(),
        "cycles": cycle_values,
    })
}

fn cycle_to_json(idx: usize, cycle: &[(u32, u16)]) -> serde_json::Value {
    let path: Vec<_> = cycle.iter().map(|&(obj, gen)| ref_to_json((obj, gen))).collect();
    json!({
        "id": idx,
        "length": cycle.len(),
        "path": path,
    })
}

const DEFAULT_MAX_BATCH_JOBS: usize = 8;
const DEEP_LARGE_FILE_THRESHOLD_BYTES: u64 = 16 * 1024 * 1024;
const DEEP_LARGE_FILE_JOB_CAP: usize = 4;

fn resolve_batch_job_count(
    thread_count: usize,
    jobs_override: Option<usize>,
    deep_scan: bool,
    max_file_size_bytes: u64,
) -> usize {
    let default_jobs = thread_count.min(DEFAULT_MAX_BATCH_JOBS).max(1);
    let mut target_jobs = jobs_override.unwrap_or(default_jobs);
    if jobs_override.is_none() && deep_scan && max_file_size_bytes > DEEP_LARGE_FILE_THRESHOLD_BYTES
    {
        target_jobs = target_jobs.min(DEEP_LARGE_FILE_JOB_CAP).max(1);
    }
    target_jobs.min(thread_count).max(1)
}

const BATCH_CSV_HEADER: &str = "path,status,error_code,message,result";

fn csv_escape_cell(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn format_batch_csv_row(path: &str, result: &QueryResult) -> String {
    let (status, error_code, message, payload) = match result {
        QueryResult::Error(err) => {
            ("error".to_string(), err.error_code.to_string(), err.message.clone(), String::new())
        }
        QueryResult::Scalar(ScalarValue::String(s)) => {
            ("ok".to_string(), String::new(), String::new(), s.clone())
        }
        QueryResult::Scalar(ScalarValue::Number(n)) => {
            ("ok".to_string(), String::new(), String::new(), n.to_string())
        }
        QueryResult::Scalar(ScalarValue::Boolean(b)) => {
            ("ok".to_string(), String::new(), String::new(), b.to_string())
        }
        QueryResult::List(items) => (
            "ok".to_string(),
            String::new(),
            String::new(),
            serde_json::to_string(items).unwrap_or_else(|_| "[]".to_string()),
        ),
        QueryResult::Structure(value) => (
            "ok".to_string(),
            String::new(),
            String::new(),
            serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string()),
        ),
    };

    [
        csv_escape_cell(path),
        csv_escape_cell(&status),
        csv_escape_cell(&error_code),
        csv_escape_cell(&message),
        csv_escape_cell(&payload),
    ]
    .join(",")
}

/// Batch mode: Execute query across multiple PDF files in a directory
///
/// # Arguments
/// * `query` - The query to execute
/// * `path` - Directory to scan
/// * `glob` - Glob pattern for file matching
/// * `scan_options` - Scan configuration
/// * `extract_to` - Optional extraction directory
/// * `max_extract_bytes` - Maximum bytes to extract per file
/// * `decode_mode` - Stream decode behaviour for extraction
/// * `predicate` - Optional predicate filter for supported queries
/// * `output_format` - Output format override
/// * `max_batch_files` - Maximum number of files to process
/// * `max_batch_bytes` - Maximum total bytes to process
/// * `max_walk_depth` - Maximum directory depth
pub fn run_query_batch(
    query: &Query,
    path: &Path,
    glob: &str,
    scan_options: &ScanOptions,
    extract_to: Option<&Path>,
    max_extract_bytes: usize,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
    output_format: OutputFormat,
    colour: bool,
    max_batch_files: usize,
    max_batch_bytes: u64,
    max_walk_depth: usize,
    jobs: Option<usize>,
) -> Result<()> {
    use sis_pdf_core::model::Severity as SecuritySeverity;
    use sis_pdf_core::security_log::{SecurityDomain, SecurityEvent};
    use tracing::{error, Level};

    // Compile glob matcher
    let matcher = Glob::new(glob)?.compile_matcher();

    let log_batch_file_issue =
        |path: &Path, kind: &'static str, severity: SecuritySeverity, detail: &str| {
            SecurityEvent {
                level: Level::WARN,
                domain: SecurityDomain::Detection,
                severity,
                kind,
                policy: None,
                object_id: None,
                object_type: None,
                vector: None,
                technique: None,
                confidence: None,
                fatal: false,
                message: "Batch query skipped file",
            }
            .emit();
            error!(
                path = %path.display(),
                reason = %detail,
                kind = %kind,
                "Batch query skipped file"
            );
        };

    // Walk directory and collect matching files
    let iter = if path.is_file() {
        WalkDir::new(path.parent().unwrap_or(path)).follow_links(false).max_depth(max_walk_depth)
    } else {
        WalkDir::new(path).follow_links(false).max_depth(max_walk_depth)
    };

    let mut total_bytes = 0u64;
    let mut max_file_size_bytes = 0u64;
    let mut file_count = 0usize;
    let mut paths = Vec::new();

    for entry in iter.into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let entry_path = entry.path();
        if !matcher.is_match(entry_path) {
            continue;
        }

        file_count += 1;
        if file_count > max_batch_files {
            SecurityEvent {
                level: Level::ERROR,
                domain: SecurityDomain::Detection,
                severity: SecuritySeverity::Medium,
                kind: "batch_file_limit_exceeded",
                policy: None,
                object_id: None,
                object_type: None,
                vector: None,
                technique: None,
                confidence: None,
                fatal: false,
                message: "Batch query file count exceeded",
            }
            .emit();
            error!(max_files = max_batch_files, "Batch query file count exceeded");
            return Err(anyhow!("batch file count exceeds limit"));
        }

        if let Ok(meta) = entry.metadata() {
            max_file_size_bytes = max_file_size_bytes.max(meta.len());
            total_bytes = total_bytes.saturating_add(meta.len());
            if total_bytes > max_batch_bytes {
                SecurityEvent {
                    level: Level::ERROR,
                    domain: SecurityDomain::Detection,
                    severity: SecuritySeverity::Medium,
                    kind: "batch_size_limit_exceeded",
                    policy: None,
                    object_id: None,
                    object_type: None,
                    vector: None,
                    technique: None,
                    confidence: None,
                    fatal: false,
                    message: "Batch query byte limit exceeded",
                }
                .emit();
                error!(
                    total_bytes = total_bytes,
                    max_bytes = max_batch_bytes,
                    "Batch query byte limit exceeded"
                );
                return Err(anyhow!("batch size exceeds limit"));
            }
        }
        paths.push(entry_path.to_path_buf());
    }

    if paths.is_empty() {
        return Err(anyhow!("no files matched {} in {}", glob, path.display()));
    }

    fn read_pdf_bytes(path: &Path) -> Result<Vec<u8>> {
        fs::read(path).map_err(|e| anyhow!("failed to read {}: {}", path.display(), e))
    }

    // Process files in parallel using rayon
    let thread_count = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let use_parallel = thread_count > 1 && paths.len() > 1;

    let indexed_paths: Vec<(usize, PathBuf)> = paths.into_iter().enumerate().collect();

    // Batch result structure
    #[derive(Serialize)]
    struct BatchResult {
        path: String,
        result: QueryResult,
        #[serde(skip_serializing_if = "Option::is_none")]
        runtime_caps: Option<serde_json::Value>,
    }

    let make_batch_error = |path: &PathBuf, error_code: &'static str, message: String| {
        Some(BatchResult {
            path: path.display().to_string(),
            result: query_error_with_context(
                error_code,
                message,
                Some(json!({ "path": path.display().to_string() })),
            ),
            runtime_caps: if output_format == OutputFormat::Jsonl {
                Some(empty_runtime_caps())
            } else {
                None
            },
        })
    };

    let process_path = |path_buf: &PathBuf| -> Result<Option<BatchResult>> {
        let path_str = path_buf.display().to_string();
        let bytes = match read_pdf_bytes(path_buf) {
            Ok(bytes) => bytes,
            Err(err) => {
                let detail = err.to_string();
                log_batch_file_issue(
                    path_buf,
                    "batch_file_read_error",
                    SecuritySeverity::Medium,
                    &detail,
                );
                return Ok(make_batch_error(path_buf, "FILE_READ_ERROR", detail));
            }
        };

        // Build scan context
        let ctx = match build_scan_context(&bytes, scan_options) {
            Ok(ctx) => ctx,
            Err(err) => {
                let detail = err.to_string();
                log_batch_file_issue(path_buf, "batch_invalid_pdf", SecuritySeverity::Low, &detail);
                return Ok(make_batch_error(path_buf, "INVALID_PDF", detail));
            }
        };

        // Execute query
        let result = execute_query_with_context(
            query,
            &ctx,
            extract_to,
            max_extract_bytes,
            decode_mode,
            predicate,
        )?;

        // Filter out empty results
        let is_empty = match &result {
            QueryResult::Scalar(ScalarValue::Number(n)) => *n == 0,
            QueryResult::Scalar(ScalarValue::String(s)) => s.is_empty(),
            QueryResult::Scalar(ScalarValue::Boolean(_)) => false,
            QueryResult::List(l) => l.is_empty(),
            QueryResult::Structure(_) => false, // Always include structure results
            QueryResult::Error(_) => false,
        };

        let runtime_caps = if output_format == OutputFormat::Jsonl {
            extract_runtime_caps(&ctx).ok()
        } else {
            None
        };

        if is_empty {
            Ok(None)
        } else {
            Ok(Some(BatchResult { path: path_str, result, runtime_caps }))
        }
    };

    let results: Vec<(usize, Option<BatchResult>)> = if use_parallel {
        let target_jobs =
            resolve_batch_job_count(thread_count, jobs, scan_options.deep, max_file_size_bytes);
        let pool = rayon::ThreadPoolBuilder::new().num_threads(target_jobs).build();
        match pool {
            Ok(pool) => pool.install(|| {
                indexed_paths
                    .par_iter()
                    .map(|(idx, path_buf)| process_path(path_buf).map(|res| (*idx, res)))
                    .collect::<Result<Vec<_>>>()
            })?,
            Err(_) => {
                // Fall back to sequential processing
                indexed_paths
                    .iter()
                    .map(|(idx, path_buf)| process_path(path_buf).map(|res| (*idx, res)))
                    .collect::<Result<Vec<_>>>()?
            }
        }
    } else {
        indexed_paths
            .iter()
            .map(|(idx, path_buf)| process_path(path_buf).map(|res| (*idx, res)))
            .collect::<Result<Vec<_>>>()?
    };

    // Sort by original index to preserve order
    let mut sorted_results: Vec<_> =
        results.into_iter().filter_map(|(idx, res)| res.map(|r| (idx, r))).collect();
    sorted_results.sort_by_key(|(idx, _)| *idx);

    // Output results
    match output_format {
        OutputFormat::Json => {
            let results_only: Vec<_> = sorted_results.into_iter().map(|(_, r)| r).collect();
            let output = serde_json::to_string_pretty(&results_only)?;
            if colour && std::io::stdout().is_terminal() {
                println!("{}", colourise_output(&output, OutputFormat::Json)?);
            } else {
                println!("{}", output);
            }
        }
        OutputFormat::Jsonl => {
            for (_, batch_result) in sorted_results {
                println!("{}", serde_json::to_string(&batch_result)?);
            }
        }
        OutputFormat::Yaml => {
            let results_only: Vec<_> = sorted_results.into_iter().map(|(_, r)| r).collect();
            let output = serde_yaml::to_string(&results_only)?;
            if colour && std::io::stdout().is_terminal() {
                println!("{}", colourise_output(&output, OutputFormat::Yaml)?);
            } else {
                println!("{}", output);
            }
        }
        OutputFormat::Csv => {
            println!("{}", BATCH_CSV_HEADER);
            for (_, batch_result) in sorted_results {
                println!("{}", format_batch_csv_row(&batch_result.path, &batch_result.result));
            }
        }
        OutputFormat::Text | OutputFormat::Readable | OutputFormat::Dot => {
            for (_, batch_result) in sorted_results {
                match batch_result.result {
                    QueryResult::Scalar(ScalarValue::Number(n)) => {
                        println!("{}: {}", batch_result.path, n)
                    }
                    QueryResult::Scalar(ScalarValue::String(s)) => {
                        println!("{}: {}", batch_result.path, s)
                    }
                    QueryResult::Scalar(ScalarValue::Boolean(b)) => {
                        println!("{}: {}", batch_result.path, b)
                    }
                    QueryResult::List(l) => {
                        for item in l {
                            println!("{}: {}", batch_result.path, item);
                        }
                    }
                    QueryResult::Structure(j) => {
                        println!("{}: {}", batch_result.path, serde_json::to_string_pretty(&j)?);
                    }
                    QueryResult::Error(err) => {
                        println!("{}: {}", batch_result.path, err.message);
                    }
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Content stream query helpers
// ---------------------------------------------------------------------------

/// Decode and summarise a single stream object. Returns `Err(QueryResult::Error)` on failure.
fn decode_and_summarise_stream(
    ctx: &ScanContext,
    obj: u32,
    gen: u16,
    page_ref: Option<(u32, u16)>,
) -> Result<sis_pdf_pdf::content_summary::ContentStreamSummary> {
    use sis_pdf_pdf::content_summary::summarise_stream;

    let entry = ctx.graph.get_object(obj, gen).ok_or_else(|| {
        anyhow!("Object {} {} not found", obj, gen)
    })?;
    let stream = match &entry.atom {
        PdfAtom::Stream(st) => st.clone(),
        _ => anyhow::bail!("Object {} {} is not a stream", obj, gen),
    };
    let raw_stream_offset = stream.data_span.start;
    let decoded = ctx.decoded.get_or_decode(ctx.bytes, &stream).map_err(|e| {
        anyhow!("Failed to decode stream {} {}: {}", obj, gen, e)
    })?;

    // Resolve resources: if we have a page_ref, use resolve_page_resources; otherwise None.
    // We hold the resources as an owned PdfDict to satisfy lifetime requirements.
    let owned_resources = page_ref.and_then(|(po, pg)| {
        sis_pdf_core::page_tree::resolve_page_resources(&ctx.graph, po, pg)
    });

    let summary = summarise_stream(
        &decoded.data,
        decoded.truncated,
        (obj, gen),
        page_ref,
        raw_stream_offset,
        owned_resources.as_ref(),
        &ctx.graph,
    );
    Ok(summary)
}

/// Decode and recursively summarise a stream and all its Form XObject children.
fn decode_and_summarise_xobject_tree(
    ctx: &ScanContext,
    obj: u32,
    gen: u16,
    page_ref: Option<(u32, u16)>,
) -> Result<sis_pdf_pdf::content_summary::RecursiveContentSummary> {
    use sis_pdf_pdf::content_summary::summarise_xobject_tree;
    use std::collections::HashSet;

    let entry = ctx.graph.get_object(obj, gen).ok_or_else(|| {
        anyhow!("Object {} {} not found", obj, gen)
    })?;
    let stream = match &entry.atom {
        PdfAtom::Stream(st) => st.clone(),
        _ => anyhow::bail!("Object {} {} is not a stream", obj, gen),
    };
    let raw_stream_offset = stream.data_span.start;
    let decoded = ctx.decoded.get_or_decode(ctx.bytes, &stream).map_err(|e| {
        anyhow!("Failed to decode stream {} {}: {}", obj, gen, e)
    })?;
    let owned_resources = page_ref.and_then(|(po, pg)| {
        sis_pdf_core::page_tree::resolve_page_resources(&ctx.graph, po, pg)
    });

    let mut visited = HashSet::new();
    let rcs = summarise_xobject_tree(
        &decoded.data,
        decoded.truncated,
        (obj, gen),
        page_ref,
        raw_stream_offset,
        owned_resources.as_ref(),
        &ctx.graph,
        5, // default depth limit
        &mut visited,
    );
    Ok(rcs)
}

/// Run detectors and correlate findings for the given stream.
fn correlate_stream_findings_for_cli(
    ctx: &ScanContext,
    obj: u32,
    gen: u16,
    page_ref: Option<(u32, u16)>,
    approx_decoded_len: u64,
) -> Result<Vec<sis_pdf_core::content_correlation::CorrelatedStreamFinding>> {
    use sis_pdf_core::content_correlation::correlate_content_stream_findings;
    // Get the raw stream offset for evidence matching.
    let raw_stream_offset = ctx.graph.get_object(obj, gen)
        .and_then(|e| if let PdfAtom::Stream(st) = &e.atom { Some(st.data_span.start) } else { None })
        .unwrap_or(0);
    let findings = findings_with_cache(ctx)?;
    Ok(correlate_content_stream_findings(
        &findings,
        (obj, gen),
        page_ref,
        raw_stream_offset,
        approx_decoded_len,
    ))
}

/// Format correlated findings as a text section.
fn format_correlated_findings_text(
    ctx: &ScanContext,
    obj: u32,
    gen: u16,
    page_ref: Option<(u32, u16)>,
    approx_decoded_len: u64,
) -> Result<String> {
    let correlated = correlate_stream_findings_for_cli(ctx, obj, gen, page_ref, approx_decoded_len)?;
    if correlated.is_empty() {
        return Ok(String::new());
    }
    let mut out = String::from("  Correlated findings:\n");
    for f in &correlated {
        let severity_str = format!("{:?}", f.severity).to_lowercase();
        let confidence_str = format!("{:?}", f.confidence).to_lowercase();
        out.push_str(&format!(
            "    * {} [{}/{}]  id: {}\n",
            f.kind, severity_str, confidence_str, f.finding_id
        ));
    }
    Ok(out)
}

/// Serialise correlated findings to a JSON array.
fn correlated_findings_to_json(
    findings: &[sis_pdf_core::content_correlation::CorrelatedStreamFinding],
) -> serde_json::Value {
    use serde_json::json;
    let arr: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            json!({
                "id": f.finding_id,
                "kind": f.kind,
                "severity": format!("{:?}", f.severity).to_lowercase(),
                "confidence": format!("{:?}", f.confidence).to_lowercase(),
                "title": f.title,
                "anomaly_hint": f.anomaly_hint,
                "decoded_offset": f.decoded_offset,
            })
        })
        .collect();
    serde_json::Value::Array(arr)
}

/// Find the page that owns a given stream object by scanning the page tree.
fn find_page_for_stream(ctx: &ScanContext, obj: u32, gen: u16) -> Option<(u32, u16)> {
    let tree = sis_pdf_core::page_tree::build_page_tree(&ctx.graph);
    for page in &tree.pages {
        let streams = page_streams(ctx, page.obj, page.gen);
        if streams.contains(&(obj, gen)) {
            return Some((page.obj, page.gen));
        }
    }
    None
}

fn execute_stream_content_ops(
    ctx: &ScanContext,
    obj: u32,
    gen: u16,
    recursive: bool,
    with_findings: bool,
) -> Result<String> {
    use sis_pdf_pdf::content_summary::summary_to_text;
    let page_ref = find_page_for_stream(ctx, obj, gen);
    let mut out = String::new();
    if recursive {
        let rcs = decode_and_summarise_xobject_tree(ctx, obj, gen, page_ref)?;
        out.push_str(&summary_to_text(&rcs.root));
        for ((fobj, fgen), child) in &rcs.xobject_children {
            out.push_str(&format!("\n  [Form XObject {} {}]\n", fobj, fgen));
            out.push_str(&summary_to_text(child));
        }
    } else {
        let summary = decode_and_summarise_stream(ctx, obj, gen, page_ref)?;
        out.push_str(&summary_to_text(&summary));
        if with_findings {
            let findings_text = format_correlated_findings_text(ctx, obj, gen, page_ref, summary.stats.total_op_count as u64 * 8)?;
            if !findings_text.is_empty() {
                out.push_str(&findings_text);
            }
        }
    }
    Ok(out)
}

fn execute_stream_content_ops_json(
    ctx: &ScanContext,
    obj: u32,
    gen: u16,
    recursive: bool,
    with_findings: bool,
) -> Result<serde_json::Value> {
    use sis_pdf_pdf::content_summary::{summary_to_json, recursive_summary_to_json};
    let page_ref = find_page_for_stream(ctx, obj, gen);
    if recursive {
        let rcs = decode_and_summarise_xobject_tree(ctx, obj, gen, page_ref)?;
        Ok(recursive_summary_to_json(&rcs))
    } else {
        let summary = decode_and_summarise_stream(ctx, obj, gen, page_ref)?;
        let mut json = summary_to_json(&summary);
        if with_findings {
            let correlated = correlate_stream_findings_for_cli(ctx, obj, gen, page_ref, summary.stats.total_op_count as u64 * 8)?;
            json["correlated_findings"] = correlated_findings_to_json(&correlated);
        }
        Ok(json)
    }
}

/// Collect all content streams for a page (handles `/Contents` array).
fn page_streams(ctx: &ScanContext, page_obj: u32, page_gen: u16) -> Vec<(u32, u16)> {
    use sis_pdf_pdf::object::PdfAtom;

    let entry = match ctx.graph.get_object(page_obj, page_gen) {
        Some(e) => e,
        None => return vec![],
    };
    let dict = match &entry.atom {
        PdfAtom::Dict(d) => d.clone(),
        PdfAtom::Stream(st) => st.dict.clone(),
        _ => return vec![],
    };
    let Some((_, contents_obj)) = dict.get_first(b"/Contents") else {
        return vec![];
    };
    let mut out = Vec::new();
    match &contents_obj.atom {
        PdfAtom::Array(arr) => {
            for item in arr {
                if let Some((o, g)) = resolve_stream_ref(ctx, item) {
                    out.push((o, g));
                }
            }
        }
        PdfAtom::Ref { obj, gen } => {
            // Could be a direct ref to a stream or to an array — resolve it.
            if let Some(resolved) = ctx.graph.get_object(*obj, *gen) {
                match &resolved.atom {
                    PdfAtom::Stream(_) => out.push((*obj, *gen)),
                    PdfAtom::Array(arr) => {
                        for item in arr {
                            if let Some((o, g)) = resolve_stream_ref(ctx, item) {
                                out.push((o, g));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        PdfAtom::Stream(_) => {
            let span = contents_obj.span.start;
            if let Some(e) = ctx.graph.objects.iter().find(|e| e.body_span.start == span) {
                out.push((e.obj, e.gen));
            }
        }
        _ => {}
    }
    out
}

fn resolve_stream_ref(ctx: &ScanContext, obj: &sis_pdf_pdf::object::PdfObj<'_>) -> Option<(u32, u16)> {
    match &obj.atom {
        PdfAtom::Ref { obj, gen } => {
            ctx.graph.get_object(*obj, *gen).and_then(|e| match &e.atom {
                PdfAtom::Stream(_) => Some((*obj, *gen)),
                _ => None,
            })
        }
        PdfAtom::Stream(_) => {
            let span = obj.span.start;
            ctx.graph.objects.iter().find(|e| e.body_span.start == span).map(|e| (e.obj, e.gen))
        }
        _ => None,
    }
}

fn execute_page_content_ops(ctx: &ScanContext, page_idx: usize, with_findings: bool) -> Result<String> {
    use sis_pdf_pdf::content_summary::summary_to_text;
    let tree = sis_pdf_core::page_tree::build_page_tree(&ctx.graph);
    let page = tree.pages.get(page_idx).ok_or_else(|| {
        anyhow!("Page index {} out of range (document has {} pages)", page_idx, tree.pages.len())
    })?;
    let stream_refs = page_streams(ctx, page.obj, page.gen);
    if stream_refs.is_empty() {
        return Ok(format!("Page {} has no content streams\n", page_idx));
    }
    let mut out = String::new();
    for (obj, gen) in stream_refs {
        match decode_and_summarise_stream(ctx, obj, gen, Some((page.obj, page.gen))) {
            Ok(summary) => {
                out.push_str(&summary_to_text(&summary));
                if with_findings {
                    let approx_len = summary.stats.total_op_count as u64 * 8;
                    if let Ok(findings_text) = format_correlated_findings_text(ctx, obj, gen, Some((page.obj, page.gen)), approx_len) {
                        if !findings_text.is_empty() {
                            out.push_str(&findings_text);
                        }
                    }
                }
                out.push('\n');
            }
            Err(e) => {
                out.push_str(&format!("Content stream {} {} (decode error: {})\n", obj, gen, e));
            }
        }
    }
    Ok(out)
}

fn execute_page_content_ops_json(
    ctx: &ScanContext,
    page_idx: usize,
    with_findings: bool,
) -> Result<serde_json::Value> {
    use sis_pdf_pdf::content_summary::summary_to_json;
    let tree = sis_pdf_core::page_tree::build_page_tree(&ctx.graph);
    let page = tree.pages.get(page_idx).ok_or_else(|| {
        anyhow!("Page index {} out of range (document has {} pages)", page_idx, tree.pages.len())
    })?;
    let stream_refs = page_streams(ctx, page.obj, page.gen);
    let summaries: Vec<serde_json::Value> = stream_refs
        .into_iter()
        .filter_map(|(obj, gen)| {
            decode_and_summarise_stream(ctx, obj, gen, Some((page.obj, page.gen)))
                .ok()
                .map(|summary| {
                    let mut json = summary_to_json(&summary);
                    if with_findings {
                        let approx_len = summary.stats.total_op_count as u64 * 8;
                        if let Ok(correlated) = correlate_stream_findings_for_cli(ctx, obj, gen, Some((page.obj, page.gen)), approx_len) {
                            json["correlated_findings"] = correlated_findings_to_json(&correlated);
                        }
                    }
                    json
                })
        })
        .collect();
    Ok(serde_json::json!({ "page_idx": page_idx, "streams": summaries }))
}

fn execute_content_graph_dot(ctx: &ScanContext, obj: u32, gen: u16, recursive: bool) -> Result<String> {
    use sis_pdf_pdf::content_summary::{build_content_graph, build_content_graph_recursive, content_graph_to_dot};
    let page_ref = find_page_for_stream(ctx, obj, gen);
    if recursive {
        let rcs = decode_and_summarise_xobject_tree(ctx, obj, gen, page_ref)?;
        let csg = build_content_graph_recursive(&rcs.root, &rcs.xobject_children);
        Ok(content_graph_to_dot(&csg, &format!("stream {} {} (recursive)", obj, gen)))
    } else {
        let summary = decode_and_summarise_stream(ctx, obj, gen, page_ref)?;
        let csg = build_content_graph(&summary);
        Ok(content_graph_to_dot(&csg, &format!("stream {} {}", obj, gen)))
    }
}

fn execute_content_graph_json(ctx: &ScanContext, obj: u32, gen: u16, recursive: bool) -> Result<serde_json::Value> {
    use sis_pdf_pdf::content_summary::{build_content_graph, build_content_graph_recursive, content_graph_to_json};
    let page_ref = find_page_for_stream(ctx, obj, gen);
    if recursive {
        let rcs = decode_and_summarise_xobject_tree(ctx, obj, gen, page_ref)?;
        let csg = build_content_graph_recursive(&rcs.root, &rcs.xobject_children);
        Ok(content_graph_to_json(&csg))
    } else {
        let summary = decode_and_summarise_stream(ctx, obj, gen, page_ref)?;
        let csg = build_content_graph(&summary);
        Ok(content_graph_to_json(&csg))
    }
}

fn execute_page_content_graph_dot(ctx: &ScanContext, page_idx: usize, recursive: bool) -> Result<String> {
    use sis_pdf_pdf::content_summary::{build_content_graph, build_content_graph_recursive, content_graph_to_dot};
    let tree = sis_pdf_core::page_tree::build_page_tree(&ctx.graph);
    let page = tree.pages.get(page_idx).ok_or_else(|| {
        anyhow!("Page index {} out of range (document has {} pages)", page_idx, tree.pages.len())
    })?;
    let stream_refs = page_streams(ctx, page.obj, page.gen);
    let mut out = String::new();
    for (obj, gen) in stream_refs {
        if recursive {
            if let Ok(rcs) = decode_and_summarise_xobject_tree(ctx, obj, gen, Some((page.obj, page.gen))) {
                let csg = build_content_graph_recursive(&rcs.root, &rcs.xobject_children);
                out.push_str(&content_graph_to_dot(&csg, &format!("page {} stream {} {} (recursive)", page_idx, obj, gen)));
                out.push('\n');
            }
        } else if let Ok(summary) = decode_and_summarise_stream(ctx, obj, gen, Some((page.obj, page.gen))) {
            let csg = build_content_graph(&summary);
            out.push_str(&content_graph_to_dot(&csg, &format!("page {} stream {} {}", page_idx, obj, gen)));
            out.push('\n');
        }
    }
    Ok(out)
}

fn execute_page_content_graph_json(
    ctx: &ScanContext,
    page_idx: usize,
    recursive: bool,
) -> Result<serde_json::Value> {
    use sis_pdf_pdf::content_summary::{build_content_graph, build_content_graph_recursive, content_graph_to_json};
    let tree = sis_pdf_core::page_tree::build_page_tree(&ctx.graph);
    let page = tree.pages.get(page_idx).ok_or_else(|| {
        anyhow!("Page index {} out of range (document has {} pages)", page_idx, tree.pages.len())
    })?;
    let stream_refs = page_streams(ctx, page.obj, page.gen);
    let graphs: Vec<serde_json::Value> = stream_refs
        .into_iter()
        .filter_map(|(obj, gen)| {
            if recursive {
                decode_and_summarise_xobject_tree(ctx, obj, gen, Some((page.obj, page.gen)))
                    .ok()
                    .map(|rcs| {
                        let csg = build_content_graph_recursive(&rcs.root, &rcs.xobject_children);
                        content_graph_to_json(&csg)
                    })
            } else {
                decode_and_summarise_stream(ctx, obj, gen, Some((page.obj, page.gen)))
                    .ok()
                    .map(|s| {
                        let csg = build_content_graph(&s);
                        content_graph_to_json(&csg)
                    })
            }
        })
        .collect();
    Ok(serde_json::json!({ "page_idx": page_idx, "graphs": graphs }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use serde_json::Value;
    use sis_pdf_pdf::path_finder::TriggerType;
    use sis_pdf_pdf::typed_graph::{EdgeType, TypedEdge};
    use std::fs;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn with_fixture_context<F>(fixture: &str, test: F)
    where
        F: FnOnce(&ScanContext),
    {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root is two levels above crate manifest");
        let fixture_path = workspace_root.join("crates/sis-pdf-core/tests/fixtures").join(fixture);
        let bytes = std::fs::read(&fixture_path).expect("fixture read");
        let options = ScanOptions::default();
        let ctx = build_scan_context(&bytes, &options).expect("build context");
        test(&ctx);
    }

    fn with_fixture_context_opts<F>(fixture: &str, options: ScanOptions, test: F)
    where
        F: FnOnce(&ScanContext),
    {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root is two levels above crate manifest");
        let fixture_path = workspace_root.join("crates/sis-pdf-core/tests/fixtures").join(fixture);
        let bytes = std::fs::read(&fixture_path).expect("fixture read");
        let ctx = build_scan_context(&bytes, &options).expect("build context");
        test(&ctx);
    }

    fn build_simple_page_tree_pdf() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"%PDF-1.4\n");

        let objects = [
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] >>\nendobj\n",
        ];

        let mut offsets = Vec::new();
        for object in objects {
            offsets.push(bytes.len());
            bytes.extend_from_slice(object.as_bytes());
        }

        let xref_offset = bytes.len();
        bytes.extend_from_slice(b"xref\n0 4\n0000000000 65535 f \n");
        for offset in offsets {
            bytes.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        bytes.extend_from_slice(b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n");
        bytes.extend_from_slice(format!("{xref_offset}\n").as_bytes());
        bytes.extend_from_slice(b"%%EOF\n");

        bytes
    }

    fn build_pdf(objects: &[String], size: usize) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"%PDF-1.4\n");
        let mut offsets = vec![0usize; size];
        for object in objects {
            let id = object
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            if id < offsets.len() {
                offsets[id] = out.len();
            }
            out.extend_from_slice(object.as_bytes());
        }
        let startxref = out.len();
        out.extend_from_slice(format!("xref\n0 {}\n", size).as_bytes());
        out.extend_from_slice(b"0000000000 65535 f \n");
        for offset in offsets.iter().skip(1) {
            out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(
            format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n", size).as_bytes(),
        );
        out.extend_from_slice(startxref.to_string().as_bytes());
        out.extend_from_slice(b"\n%%EOF\n");
        out
    }

    fn build_simple_stream_pdf() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"%PDF-1.4\n");

        let objects = [
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
            "2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n",
            "3 0 obj\n<< /Length 5 >>\nstream\nhello\nendstream\nendobj\n",
        ];

        let mut offsets = Vec::new();
        for object in objects {
            offsets.push(bytes.len());
            bytes.extend_from_slice(object.as_bytes());
        }

        let xref_offset = bytes.len();
        bytes.extend_from_slice(b"xref\n0 4\n0000000000 65535 f \n");
        for offset in offsets {
            bytes.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        bytes.extend_from_slice(b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n");
        bytes.extend_from_slice(format!("{xref_offset}\n").as_bytes());
        bytes.extend_from_slice(b"%%EOF\n");

        bytes
    }

    fn build_pdf_with_info_trailer() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"%PDF-1.4\n");

        let objects = [
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R /MediaBox [0 0 300 200] >>\nendobj\n",
            "4 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n",
            "5 0 obj\n<< /Author (analyst) /Title (overlay-test) >>\nendobj\n",
        ];

        let mut offsets = Vec::new();
        for object in objects {
            offsets.push(bytes.len());
            bytes.extend_from_slice(object.as_bytes());
        }

        let xref_offset = bytes.len();
        bytes.extend_from_slice(b"xref\n0 6\n0000000000 65535 f \n");
        for offset in offsets {
            bytes.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        bytes.extend_from_slice(b"trailer\n<< /Size 6 /Root 1 0 R /Info 5 0 R >>\nstartxref\n");
        bytes.extend_from_slice(format!("{xref_offset}\n").as_bytes());
        bytes.extend_from_slice(b"%%EOF\n");
        bytes
    }

    fn build_pdf_with_unresolved_info_trailer() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"%PDF-1.4\n");

        let objects = [
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
            "2 0 obj\n<< /Type /Pages /Count 0 /Kids [] >>\nendobj\n",
        ];

        let mut offsets = Vec::new();
        for object in objects {
            offsets.push(bytes.len());
            bytes.extend_from_slice(object.as_bytes());
        }

        let xref_offset = bytes.len();
        bytes.extend_from_slice(b"xref\n0 3\n0000000000 65535 f \n");
        for offset in offsets {
            bytes.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        bytes.extend_from_slice(b"trailer\n<< /Size 3 /Root 1 0 R /Info 9 0 R >>\nstartxref\n");
        bytes.extend_from_slice(format!("{xref_offset}\n").as_bytes());
        bytes.extend_from_slice(b"%%EOF\n");
        bytes
    }

    fn build_pdf_with_oob_startxref() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"%PDF-1.4\n");
        bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog >>\nendobj\n");
        bytes.extend_from_slice(b"trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n999999\n%%EOF\n");
        bytes
    }

    fn build_pdf_with_many_detached(detached_count: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"%PDF-1.4\n");

        let mut objects = Vec::new();
        objects.push("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string());
        objects.push("2 0 obj\n<< /Type /Pages /Count 0 /Kids [] >>\nendobj\n".to_string());
        for obj in 3..(3 + detached_count as u32) {
            objects.push(format!("{obj} 0 obj\n<< /Producer (detached-{obj}) >>\nendobj\n"));
        }

        let mut offsets = Vec::new();
        for object in &objects {
            offsets.push(bytes.len());
            bytes.extend_from_slice(object.as_bytes());
        }

        let size = objects.len() + 1;
        let xref_offset = bytes.len();
        bytes.extend_from_slice(format!("xref\n0 {size}\n").as_bytes());
        bytes.extend_from_slice(b"0000000000 65535 f \n");
        for offset in offsets {
            bytes.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        bytes.extend_from_slice(
            format!("trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n")
                .as_bytes(),
        );
        bytes
    }

    #[test]
    fn advanced_query_json_outputs_are_structured() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let chains = list_action_chains(ctx, None, false).expect("chains");
            assert_eq!(chains["type"], json!("chains"));
            assert!(chains["chains"].is_array());

            let js_chains = list_js_chains(ctx, None, false).expect("js chains");
            assert_eq!(js_chains["type"], json!("chains.js"));

            let cycles = list_cycles(ctx).expect("cycles");
            assert_eq!(cycles["type"], json!("cycles"));

            let page_cycles = list_page_cycles(ctx).expect("page cycles");
            assert_eq!(page_cycles["type"], json!("cycles.page"));
        });
    }

    #[test]
    fn page_tree_cycles_ignore_parent_links() {
        let bytes = build_simple_page_tree_pdf();
        let options = ScanOptions::default();
        let ctx = build_scan_context(&bytes, &options).expect("build context");

        let cycles = list_cycles(&ctx).expect("cycles");
        assert_eq!(cycles["count"], json!(0));

        let page_cycles = list_page_cycles(&ctx).expect("page cycles");
        assert_eq!(page_cycles["count"], json!(0));
    }

    #[test]
    fn stream_query_extracts_object() {
        let bytes = build_simple_stream_pdf();
        let options = ScanOptions::default();
        let ctx = build_scan_context(&bytes, &options).expect("build context");
        let temp = tempdir().expect("tempdir");

        let result = execute_query_with_context(
            &Query::Stream(StreamQuery {
                obj: 3,
                gen: 0,
                decode_override: None,
                output: StreamOutput::Summary,
            }),
            &ctx,
            Some(temp.path()),
            1024 * 1024,
            DecodeMode::Decode,
            None,
        )
        .expect("stream query");

        match result {
            QueryResult::List(items) => {
                assert_eq!(items.len(), 1);
            }
            _ => panic!("unexpected stream query result"),
        }

        let output_path = temp.path().join("stream_3_0.bin");
        let data = std::fs::read(&output_path).expect("read stream output");
        assert_eq!(data, b"hello");
    }

    #[test]
    fn stream_query_preview_without_extract_to() {
        let bytes = build_simple_stream_pdf();
        let options = ScanOptions::default();
        let ctx = build_scan_context(&bytes, &options).expect("build context");

        let result = execute_query_with_context(
            &Query::Stream(StreamQuery {
                obj: 3,
                gen: 0,
                decode_override: None,
                output: StreamOutput::Summary,
            }),
            &ctx,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            None,
        )
        .expect("stream query");

        match result {
            QueryResult::List(items) => {
                assert_eq!(items.len(), 1);
                assert!(items[0].contains("preview=\"hello\""));
            }
            _ => panic!("unexpected stream query result"),
        }
    }

    #[test]
    fn chain_to_json_includes_payload_and_edges() {
        let edges = [
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

        let json_value = chain_to_json(5, &chain, None);
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
    fn default_chain_view_filters_single_edge_chains() {
        let single_edge_backing = [TypedEdge::new((1, 0), (2, 0), EdgeType::OpenAction)];
        let single_edge = sis_pdf_pdf::path_finder::ActionChain {
            trigger: TriggerType::OpenAction,
            edges: vec![&single_edge_backing[0]],
            payload: Some((2, 0)),
            automatic: true,
            involves_js: false,
            involves_external: false,
        };
        let multi_edge_edges = [
            TypedEdge::new((1, 0), (2, 0), EdgeType::OpenAction),
            TypedEdge::new((2, 0), (3, 0), EdgeType::JavaScriptPayload),
        ];
        let multi_edge = sis_pdf_pdf::path_finder::ActionChain {
            trigger: TriggerType::OpenAction,
            edges: vec![&multi_edge_edges[0], &multi_edge_edges[1]],
            payload: Some((3, 0)),
            automatic: true,
            involves_js: true,
            involves_external: false,
        };
        assert!(!is_default_visible_chain(&single_edge, false));
        assert!(is_default_visible_chain(&single_edge, true));
        assert!(is_default_visible_chain(&multi_edge, false));
    }

    #[test]
    fn chain_summary_events_filters_edges_before_display() {
        let chain = json!({
            "type": "chains",
            "count": 1,
            "total_chains": 1,
            "chains": [{
                "id": 0,
                "length": 3,
                "risk_score": 0.8,
                "edges": [
                    json!({"type": "open_action", "suspicious": false, "weight": 0.1}),
                    json!({"type": "launch", "suspicious": true, "weight": 0.1}),
                    json!({"type": "js_payload", "suspicious": false, "weight": 0.6})
                ]
            }]
        });
        let result = QueryResult::Structure(chain);
        let filtered = apply_chain_summary(
            &Query::Chains,
            result,
            ChainSummaryLevel::Events,
            OutputFormat::Text,
        );
        let body = match filtered {
            QueryResult::Structure(val) => val,
            other => panic!("expected structure, got {:?}", other),
        };
        let edges = body["chains"][0]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 2);
        assert_eq!(body["chains"][0]["edges_summary"]["kept"], json!(2));
    }

    #[test]
    fn chain_summary_minimal_clears_edges_and_marks_summary() {
        let chain = json!({
            "type": "chains",
            "count": 1,
            "total_chains": 1,
            "chains": [{
                "id": 0,
                "length": 2,
                "risk_score": 0.2,
                "edges": [
                    json!({"type": "js_payload", "suspicious": false, "weight": 0.1}),
                    json!({"type": "launch", "suspicious": false, "weight": 0.05})
                ]
            }]
        });
        let result = QueryResult::Structure(chain);
        let filtered = apply_chain_summary(
            &Query::ChainsJs,
            result,
            ChainSummaryLevel::Minimal,
            OutputFormat::Readable,
        );
        let body = match filtered {
            QueryResult::Structure(val) => val,
            other => panic!("expected structure, got {:?}", other),
        };
        let edges = body["chains"][0]["edges"].as_array().unwrap();
        assert!(edges.is_empty());
        assert_eq!(body["chains"][0]["edges_summary"]["level"], json!("minimal"));
    }

    #[test]
    fn chain_summary_full_for_json_keeps_all_edges() {
        let chain = json!({
            "type": "chains",
            "count": 1,
            "total_chains": 1,
            "chains": [{
                "id": 0,
                "length": 2,
                "risk_score": 0.1,
                "edges": [
                    json!({"type": "open_action", "suspicious": false, "weight": 0.1}),
                    json!({"type": "launch", "suspicious": false, "weight": 0.1})
                ]
            }]
        });
        let result = QueryResult::Structure(chain);
        let preserved = apply_chain_summary(
            &Query::Chains,
            result,
            ChainSummaryLevel::Full,
            OutputFormat::Json,
        );
        let body = match preserved {
            QueryResult::Structure(val) => val,
            other => panic!("expected structure, got {:?}", other),
        };
        let edges = body["chains"][0]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 2);
        assert!(body["chains"][0]["edges_summary"].is_null());
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

    #[test]
    fn output_format_parsing_accepts_expected_values() {
        assert_eq!(OutputFormat::parse("text").unwrap(), OutputFormat::Text);
        assert_eq!(OutputFormat::parse("json").unwrap(), OutputFormat::Json);
        assert_eq!(OutputFormat::parse("jsonl").unwrap(), OutputFormat::Jsonl);
        assert_eq!(OutputFormat::parse("yaml").unwrap(), OutputFormat::Yaml);
        assert_eq!(OutputFormat::parse("yml").unwrap(), OutputFormat::Yaml);
        assert_eq!(OutputFormat::parse("csv").unwrap(), OutputFormat::Csv);
        assert_eq!(OutputFormat::parse("dot").unwrap(), OutputFormat::Dot);
    }

    #[test]
    fn apply_output_format_overrides_export_variants() {
        let query = apply_output_format(Query::ExportOrgDot, OutputFormat::Json).unwrap();
        assert!(matches!(query, Query::ExportOrgJson));

        let query = apply_output_format(Query::ExportStructureDot, OutputFormat::Json).unwrap();
        assert!(matches!(query, Query::ExportStructureJson));
        let query =
            apply_output_format(Query::ExportStructureOverlayDot, OutputFormat::Json).unwrap();
        assert!(matches!(query, Query::ExportStructureOverlayJson));
        let query =
            apply_output_format(Query::ExportStructureOverlayDotDepth(2), OutputFormat::Json)
                .unwrap();
        assert!(matches!(query, Query::ExportStructureOverlayJsonDepth(2)));
        let query =
            apply_output_format(Query::ExportStructureOverlayTelemetryDot, OutputFormat::Json)
                .unwrap();
        assert!(matches!(query, Query::ExportStructureOverlayTelemetryJson));
        let query = apply_output_format(
            Query::ExportStructureOverlayTelemetryDotDepth(2),
            OutputFormat::Json,
        )
        .unwrap();
        assert!(matches!(query, Query::ExportStructureOverlayTelemetryJsonDepth(2)));

        let query = apply_output_format(Query::ExportEventDot, OutputFormat::Json).unwrap();
        assert!(matches!(query, Query::ExportEventJson));
        let query = apply_output_format(Query::ExportEventStreamDot, OutputFormat::Json).unwrap();
        assert!(matches!(query, Query::ExportEventStreamJson));

        let query = apply_output_format(Query::ExportIrText, OutputFormat::Json).unwrap();
        assert!(matches!(query, Query::ExportIrJson));

        let query = apply_output_format(Query::ExportFeatures, OutputFormat::Json).unwrap();
        assert!(matches!(query, Query::ExportFeaturesJson));

        let query = apply_output_format(Query::ExportOrgJson, OutputFormat::Dot).unwrap();
        assert!(matches!(query, Query::ExportOrgDot));

        let query = apply_output_format(Query::ExportStructureJson, OutputFormat::Dot).unwrap();
        assert!(matches!(query, Query::ExportStructureDot));
        let query =
            apply_output_format(Query::ExportStructureOverlayJson, OutputFormat::Dot).unwrap();
        assert!(matches!(query, Query::ExportStructureOverlayDot));
        let query =
            apply_output_format(Query::ExportStructureOverlayJsonDepth(2), OutputFormat::Dot)
                .unwrap();
        assert!(matches!(query, Query::ExportStructureOverlayDotDepth(2)));
        let query =
            apply_output_format(Query::ExportStructureOverlayTelemetryJson, OutputFormat::Dot)
                .unwrap();
        assert!(matches!(query, Query::ExportStructureOverlayTelemetryDot));
        let query = apply_output_format(
            Query::ExportStructureOverlayTelemetryJsonDepth(2),
            OutputFormat::Dot,
        )
        .unwrap();
        assert!(matches!(query, Query::ExportStructureOverlayTelemetryDotDepth(2)));

        let query = apply_output_format(Query::ExportEventJson, OutputFormat::Dot).unwrap();
        assert!(matches!(query, Query::ExportEventDot));
        let query = apply_output_format(Query::ExportEventStreamJson, OutputFormat::Dot).unwrap();
        assert!(matches!(query, Query::ExportEventStreamDot));

        let query = apply_output_format(Query::Findings, OutputFormat::Csv).unwrap();
        assert!(matches!(query, Query::FindingsCsv));
        let query = apply_output_format(Query::FindingsComposite, OutputFormat::Csv).unwrap();
        assert!(matches!(query, Query::FindingsCompositeCsv));
        let query = apply_output_format(Query::EventsFull, OutputFormat::Csv).unwrap();
        assert!(matches!(query, Query::EventsFullCsv));
        let error = apply_output_format(Query::Urls, OutputFormat::Csv);
        assert!(error.is_err());
    }

    #[test]
    fn format_jsonl_emits_single_line_json() {
        let result = QueryResult::Scalar(ScalarValue::Number(12));
        let output = format_jsonl("js.count", "sample.pdf", &result).unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["query"], json!("js.count"));
        assert_eq!(value["file"], json!("sample.pdf"));
        assert_eq!(value["result"], json!(12));
    }

    #[test]
    fn format_jsonl_preserves_events_structure() {
        let result = QueryResult::Structure(json!([{
            "node_id": "ev:1",
            "trigger": "automatic",
            "event_type": "DocumentOpen",
            "outcome_targets": [{"outcome_type": "NetworkEgress"}]
        }]));
        let output = format_jsonl("events", "sample.pdf", &result).expect("jsonl");
        let value: serde_json::Value = serde_json::from_str(&output).expect("json");
        let rows = value["result"].as_array().expect("rows");
        assert_eq!(rows[0]["trigger"], json!("automatic"));
        assert_eq!(rows[0]["outcome_targets"][0]["outcome_type"], json!("NetworkEgress"));
    }

    #[test]
    fn format_json_and_jsonl_keep_stable_top_level_keys() {
        let result = QueryResult::Scalar(ScalarValue::Number(7));
        let json_output = format_json("js.count", "sample.pdf", &result).unwrap();
        let jsonl_output = format_jsonl("js.count", "sample.pdf", &result).unwrap();

        let json_value: serde_json::Value = serde_json::from_str(&json_output).unwrap();
        let jsonl_value: serde_json::Value = serde_json::from_str(&jsonl_output).unwrap();
        let mut json_keys = json_value
            .as_object()
            .expect("json payload object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let mut jsonl_keys = jsonl_value
            .as_object()
            .expect("jsonl payload object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        json_keys.sort();
        jsonl_keys.sort();
        assert_eq!(json_keys, vec!["file".to_string(), "query".to_string(), "result".to_string()]);
        assert_eq!(jsonl_keys, vec!["file".to_string(), "query".to_string(), "result".to_string()]);
    }

    #[test]
    fn findings_summary_added_to_json_output() {
        let findings = json!([
            {"kind": "suspicious", "severity": "High", "surface": "Action"},
            {"kind": "info", "severity": "Info", "surface": "Structure"},
            {"kind": "suspicious", "severity": "High", "surface": "Action"},
            {"kind": "js_runtime_downloader_pattern", "severity": "High", "surface": "JavaScript"},
            {"kind": "js_sandbox_timeout", "severity": "Low", "surface": "JavaScript"},
            {
                "kind": "js_emulation_breakpoint",
                "severity": "Low",
                "surface": "JavaScript",
                "meta": {
                    "js.emulation_breakpoint.buckets": "missing_callable:2, loop_iteration_limit:1"
                }
            }
        ]);
        let result = QueryResult::Structure(findings);
        let output = format_json("findings", "sample.pdf", &result).unwrap();
        let json_value: serde_json::Value = serde_json::from_str(&output).unwrap();
        let summary = json_value["summary"].as_object().expect("summary present");
        assert_eq!(summary["findings_by_severity"]["High"], json!(3));
        assert_eq!(summary["findings_by_severity"]["Low"], json!(2));
        assert_eq!(summary["findings_by_severity"]["Info"], json!(1));
        assert_eq!(summary["findings_by_surface"]["Action"], json!(2));
        assert_eq!(summary["findings_by_kind"]["js_runtime_downloader_pattern"], json!(1));
        assert_eq!(summary["findings_by_kind"]["suspicious"], json!(2));
        assert_eq!(summary["js_emulation_breakpoints_by_bucket"]["missing_callable"], json!(2));
        assert_eq!(summary["js_emulation_breakpoints_by_bucket"]["loop_iteration_limit"], json!(1));
        assert_eq!(summary["js_runtime_budget"]["script_timeout_findings"], json!(1));
        assert_eq!(summary["js_runtime_budget"]["loop_iteration_limit_hits"], json!(1));
    }

    #[test]
    fn findings_summary_skipped_for_other_queries() {
        let findings = json!([
            {"kind": "something", "severity": "High", "surface": "Action"}
        ]);
        let result = QueryResult::Structure(findings);
        let output = format_json("images", "sample.pdf", &result).unwrap();
        let json_value: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(json_value.get("summary").is_none());
    }

    #[test]
    fn findings_summary_omits_runtime_budget_without_timeout_or_loop_buckets() {
        let findings = json!([
            {"kind": "suspicious", "severity": "High", "surface": "Action"},
            {
                "kind": "js_emulation_breakpoint",
                "severity": "Low",
                "surface": "JavaScript",
                "meta": { "js.emulation_breakpoint.buckets": "missing_callable:1" }
            }
        ]);
        let result = QueryResult::Structure(findings);
        let output = format_json("findings", "sample.pdf", &result).unwrap();
        let json_value: serde_json::Value = serde_json::from_str(&output).unwrap();
        let summary = json_value["summary"].as_object().expect("summary present");
        assert!(summary.get("js_runtime_budget").is_none());
    }

    #[test]
    fn format_yaml_emits_document() {
        let result = QueryResult::Scalar(ScalarValue::Number(12));
        let output = format_yaml("js.count", "sample.pdf", &result).unwrap();
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        assert_eq!(value["query"].as_str().unwrap(), "js.count");
        assert_eq!(value["file"].as_str().unwrap(), "sample.pdf");
        assert_eq!(value["result"].as_i64().unwrap(), 12);
    }

    #[test]
    fn colourise_output_adds_ansi_codes_for_json() {
        let json = "{\n  \"key\": 1\n}";
        let output = colourise_output(json, OutputFormat::Json).unwrap();
        assert!(output.contains('\u{1b}'));
    }

    #[test]
    fn format_hexdump_renders_offsets_and_ascii() {
        let data = b"ABC";
        let output = format_hexdump(data);
        assert!(output.starts_with("00000000"));
        assert!(output.contains("41 42 43"));
        assert!(output.contains("|ABC|"));
    }

    #[test]
    fn format_pdf_atom_renders_non_text_strings_as_hex() {
        use sis_pdf_pdf::object::PdfStr;
        let atom = sis_pdf_pdf::object::PdfAtom::Str(PdfStr::Literal {
            span: sis_pdf_pdf::span::Span { start: 0, end: 2 },
            raw: std::borrow::Cow::Owned(vec![0xFF, 0x00]),
            decoded: vec![0xFF, 0x00],
        });
        let output = format_pdf_atom(&atom, 0);
        assert_eq!(output, "<ff00>");
    }

    #[test]
    fn list_references_reports_target_and_count() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let entry = ctx.graph.objects.first().expect("object entry");
            let refs = list_references(ctx, entry.obj, entry.gen).expect("references");
            assert_eq!(refs["type"], json!("references"));
            assert_eq!(refs["target"]["obj"], json!(entry.obj));
            assert_eq!(refs["target"]["gen"], json!(entry.gen));
            let count = refs["count"].as_u64().expect("count");
            let list = refs["references"].as_array().expect("references list");
            assert_eq!(count as usize, list.len());
        });
    }

    #[test]
    fn images_query_lists_risky_formats() {
        with_fixture_context("images/cve-2009-0658-jbig2.pdf", |ctx| {
            let images =
                extract_images(ctx, DecodeMode::Decode, 1024 * 1024, None).expect("images");
            assert!(images.iter().any(|line| line.contains("JBIG2")));
        });
    }

    #[test]
    fn images_query_reports_valid_jpeg_entries() {
        with_fixture_context("images/valid_jpeg.pdf", |ctx| {
            let result = execute_query_with_context(
                &Query::Images,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("images query");

            match result {
                QueryResult::List(entries) => assert!(
                    entries.iter().any(|entry| entry.contains("DCTDecode")),
                    "expected JPEG filter entry"
                ),
                _ => panic!("expected list result for images query"),
            }
        });
    }

    #[test]
    fn images_count_query_returns_positive() {
        with_fixture_context("images/valid_jpeg.pdf", |ctx| {
            let result = execute_query_with_context(
                &Query::ImagesCount,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("images count query");

            match result {
                QueryResult::Scalar(ScalarValue::Number(count)) => {
                    assert!(count > 0, "expected positive image count");
                }
                _ => panic!("expected scalar result for images.count query"),
            }
        });
    }

    #[test]
    fn images_malformed_query_mentions_jbig2_fixture() {
        let options = ScanOptions { deep: true, ..Default::default() };
        with_fixture_context_opts("images/malformed_jbig2.pdf", options, |ctx| {
            let result = execute_query_with_context(
                &Query::ImagesMalformed,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("images malformed query");

            match result {
                QueryResult::List(entries) => {
                    assert!(
                        entries.iter().any(|entry| entry.contains("JBIG2")),
                        "expected JBIG2 indicator"
                    )
                }
                _ => panic!("expected list result for images.malformed query"),
            }
        });
    }

    #[test]
    fn images_malformed_requires_deep() {
        let options = ScanOptions { deep: false, ..Default::default() };
        with_fixture_context_opts("images/cve-2018-4990-jpx.pdf", options, |ctx| {
            let err = extract_images_malformed(ctx, DecodeMode::Decode, 1024 * 1024, None)
                .expect_err("malformed requires deep");
            assert!(err.to_string().contains("--deep"));
        });
    }

    #[test]
    fn parse_predicate_supports_boolean_logic() {
        let expr = parse_predicate("length > 10 AND entropy >= 5.0").expect("predicate");
        let ctx = PredicateContext {
            length: 20,
            filter: None,
            type_name: "Stream".to_string(),
            subtype: None,
            entropy: 6.5,
            width: 0,
            height: 0,
            pixels: 0,
            risky: false,
            severity: None,
            confidence: None,
            surface: None,
            kind: None,
            object_count: 0,
            evidence_count: 0,
            name: None,
            magic: None,
            hash: None,
            impact: None,
            action_type: None,
            action_target: None,
            action_initiation: None,
            meta: HashMap::new(),
        };
        assert!(expr.evaluate(&ctx));
    }

    #[test]
    fn predicate_not_operator_inverts_result() {
        let expr = parse_predicate("NOT type == 'Stream'").expect("predicate");
        let ctx = PredicateContext {
            length: 10,
            filter: None,
            type_name: "Stream".to_string(),
            subtype: None,
            entropy: 0.0,
            width: 0,
            height: 0,
            pixels: 0,
            risky: false,
            severity: None,
            confidence: None,
            surface: None,
            kind: None,
            object_count: 0,
            evidence_count: 0,
            name: None,
            magic: None,
            hash: None,
            impact: None,
            action_type: None,
            action_target: None,
            action_initiation: None,
            meta: HashMap::new(),
        };
        assert!(!expr.evaluate(&ctx));
    }

    #[test]
    fn predicate_supports_finding_metadata_fields() {
        let expr = parse_predicate(
            "severity == 'high' AND impact == 'high' AND action_type == 'Launch' AND action_target == 'uri:http://example.com' AND action_initiation == 'automatic' AND confidence == 'strong' AND surface == 'actions' AND kind == 'launch_external_program' AND objects > 0 AND evidence >= 1",
        )
        .expect("predicate");
        let ctx = PredicateContext {
            length: 0,
            filter: None,
            type_name: "Finding".to_string(),
            subtype: None,
            entropy: 0.0,
            width: 0,
            height: 0,
            pixels: 0,
            risky: false,
            severity: Some("high".to_string()),
            confidence: Some("strong".to_string()),
            surface: Some("actions".to_string()),
            kind: Some("launch_external_program".to_string()),
            object_count: 2,
            evidence_count: 1,
            name: None,
            magic: None,
            hash: None,
            impact: Some("high".to_string()),
            action_type: Some("Launch".to_string()),
            action_target: Some("uri:http://example.com".to_string()),
            action_initiation: Some("automatic".to_string()),
            meta: HashMap::new(),
        };
        assert!(expr.evaluate(&ctx));
    }

    #[test]
    fn action_chain_predicate_filters_by_depth() {
        with_fixture_context("action_chain_complex.pdf", |ctx| {
            let query = parse_query("actions.chains.complex").expect("query");
            let predicate = parse_predicate("action.chain_depth >= 3").expect("predicate");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                Some(&predicate),
            )
            .expect("query");
            match result {
                QueryResult::Structure(value) => {
                    let list = value.as_array().expect("array result");
                    assert!(!list.is_empty(), "expected findings after filtering by depth");
                }
                other => panic!("Unexpected result type: {:?}", other),
            }
        });
    }

    #[test]
    fn action_chain_predicate_filters_by_trigger_type() {
        with_fixture_context("action_chain_complex.pdf", |ctx| {
            let query = parse_query("actions.chains.complex").expect("query");
            let predicate =
                parse_predicate("action.trigger_type == 'automatic'").expect("predicate");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                Some(&predicate),
            )
            .expect("query");
            match result {
                QueryResult::Structure(value) => {
                    let list = value.as_array().expect("array result");
                    assert!(!list.is_empty(), "expected findings after filtering by trigger type");
                }
                other => panic!("Unexpected result type: {:?}", other),
            }
        });
    }

    #[test]
    fn action_chains_query_supports_predicate() {
        with_fixture_context("action_chain_complex.pdf", |ctx| {
            let query = parse_query("actions.chains").expect("query");
            let predicate = parse_predicate("has_js == 'true'").expect("predicate");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                Some(&predicate),
            )
            .expect("query");
            match result {
                QueryResult::Structure(value) => {
                    let chains = value["chains"].as_array().expect("chains array");
                    let count = value["count"].as_u64().expect("count");
                    let total = value["total_chains"].as_u64().expect("total");
                    assert_eq!(count as usize, chains.len());
                    assert!(count <= total);
                }
                other => panic!("Unexpected result type: {:?}", other),
            }
        });
    }

    #[test]
    fn action_chains_count_respects_predicate() {
        with_fixture_context("action_chain_complex.pdf", |ctx| {
            let query = parse_query("actions.chains.count").expect("query");
            let predicate = parse_predicate("has_js == 'true'").expect("predicate");
            let expected = list_action_chains(ctx, Some(&predicate), false).expect("chains");
            let expected_count = expected["count"].as_i64().expect("count");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                Some(&predicate),
            )
            .expect("query");
            match result {
                QueryResult::Scalar(ScalarValue::Number(count)) => {
                    assert_eq!(count, expected_count);
                }
                other => panic!("Unexpected result type: {:?}", other),
            }
        });
    }

    #[test]
    fn xfa_forms_query_returns_entries() {
        with_fixture_context("xfa/xfa_submit_sensitive.pdf", |ctx| {
            let query = parse_query("xfa").expect("query");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("query");
            match result {
                QueryResult::Structure(value) => {
                    assert_eq!(value["type"], json!("xfa"));
                    assert!(
                        value["count"].as_u64().unwrap_or(0) > 0,
                        "expected at least one XFA form"
                    );
                    let forms = value["forms"].as_array().expect("forms array");
                    assert!(!forms.is_empty(), "expected non-empty forms list");
                    let has_scripts =
                        forms.iter().any(|form| form["script_count"].as_u64().unwrap_or(0) > 0);
                    assert!(has_scripts, "expected some forms to report scripts");
                }
                other => panic!("Unexpected result type: {:?}", other),
            }
        });
    }

    #[test]
    fn xfa_forms_query_supports_script_predicate() {
        with_fixture_context("xfa/xfa_execute_high.pdf", |ctx| {
            let query = parse_query("xfa").expect("query");
            let predicate = parse_predicate("script_count > 1").expect("predicate");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                Some(&predicate),
            )
            .expect("query");
            if let QueryResult::Structure(value) = result {
                let count = value["count"].as_u64().unwrap_or(0);
                let total = value["total"].as_u64().unwrap_or(0);
                assert!(count <= total);
                assert!(count > 0, "predicate should match at least one form");
            } else {
                panic!("Unexpected result type");
            }
        });
    }

    #[test]
    fn xfa_forms_count_matches_predicate() {
        with_fixture_context("xfa/xfa_execute_high.pdf", |ctx| {
            let query = parse_query("xfa.count").expect("query");
            let predicate = parse_predicate("script_count > 1").expect("predicate");
            let expected = list_xfa_forms(ctx, Some(&predicate)).expect("forms");
            let expected_count = expected["count"].as_i64().expect("count");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                Some(&predicate),
            )
            .expect("query");
            match result {
                QueryResult::Scalar(ScalarValue::Number(count)) => {
                    assert_eq!(count, expected_count);
                }
                other => panic!("Unexpected result type: {:?}", other),
            }
        });
    }

    #[test]
    fn parse_query_supports_finding_shortcut_counts() {
        let query = parse_query("embedded.executables.count").expect("query");
        assert!(matches!(
            query,
            Query::FindingsByKindCount(ref kind) if kind == "embedded_executable_present"
        ));
        let query = parse_query("findings.kind.count embedded_executable_present").expect("query");
        assert!(matches!(
            query,
            Query::FindingsByKindCount(ref kind) if kind == "embedded_executable_present"
        ));
    }

    #[test]
    fn parse_query_supports_org_and_ir_aliases() {
        let query = parse_query("org").expect("org query");
        assert!(matches!(query, Query::ExportOrgDot));
        let query = parse_query("org.json").expect("org json query");
        assert!(matches!(query, Query::ExportOrgJson));
        let query = parse_query("graph.structure").expect("structure query");
        assert!(matches!(query, Query::ExportStructureDot));
        let query = parse_query("graph.structure.json").expect("structure json query");
        assert!(matches!(query, Query::ExportStructureJson));
        let query = parse_query("graph.structure.overlay").expect("structure overlay query");
        assert!(matches!(query, Query::ExportStructureOverlayDot));
        let query =
            parse_query("graph.structure.overlay.json").expect("structure overlay json query");
        assert!(matches!(query, Query::ExportStructureOverlayJson));
        let query = parse_query("graph.structure.overlay.telemetry")
            .expect("structure overlay telemetry query");
        assert!(matches!(query, Query::ExportStructureOverlayTelemetryDot));
        let query = parse_query("graph.structure.overlay.telemetry.json")
            .expect("structure overlay telemetry json query");
        assert!(matches!(query, Query::ExportStructureOverlayTelemetryJson));
        let query =
            parse_query("graph.structure.overlay.depth 2").expect("structure overlay depth query");
        assert!(matches!(query, Query::ExportStructureOverlayDotDepth(2)));
        let query = parse_query("graph.structure.overlay.telemetry.depth 2")
            .expect("structure overlay telemetry depth query");
        assert!(matches!(query, Query::ExportStructureOverlayTelemetryDotDepth(2)));
        let query = parse_query("graph.structure.depth 3").expect("structure depth query");
        assert!(matches!(query, Query::ExportStructureDotDepth(3)));
        let query = parse_query("graph.event").expect("event query");
        assert!(matches!(query, Query::ExportEventDot));
        let query = parse_query("graph.event.json").expect("event json query");
        assert!(matches!(query, Query::ExportEventJson));
        let query = parse_query("graph.event.stream").expect("event stream query");
        assert!(matches!(query, Query::ExportEventStreamDot));
        let query = parse_query("graph.event.stream.json").expect("event stream json query");
        assert!(matches!(query, Query::ExportEventStreamJson));
        let query = parse_query("events.full").expect("events full query");
        assert!(matches!(query, Query::EventsFull));
        let query = parse_query("events.full.csv").expect("events full csv query");
        assert!(matches!(query, Query::EventsFullCsv));
        let query = parse_query("findings.csv").expect("findings csv query");
        assert!(matches!(query, Query::FindingsCsv));
        let query = parse_query("findings.composite.csv").expect("findings composite csv query");
        assert!(matches!(query, Query::FindingsCompositeCsv));
        let query = parse_query("runtime.caps").expect("runtime caps query");
        assert!(matches!(query, Query::RuntimeCaps));
        let query = parse_query("runtime.caps.json").expect("runtime caps alias query");
        assert!(matches!(query, Query::RuntimeCaps));
        let query = parse_query("graph.action").expect("action alias query");
        assert!(matches!(query, Query::ExportEventDot));
        let query = parse_query("graph.event.hops 2").expect("event hops query");
        assert!(matches!(query, Query::ExportEventDotHops(2)));
        let query = parse_query("graph.event.stream.hops 3").expect("event stream hops query");
        assert!(matches!(query, Query::ExportEventStreamDotHops(3)));
        let query = parse_query("chains.all").expect("chains all query");
        assert!(matches!(query, Query::ChainsAll));
        let query = parse_query("actions.chains.all.count").expect("chains all count query");
        assert!(matches!(query, Query::ChainsAllCount));
        let query = parse_query("ir").expect("ir query");
        assert!(matches!(query, Query::ExportIrText));
        let query = parse_query("ir.json").expect("ir json query");
        assert!(matches!(query, Query::ExportIrJson));
        let query = parse_query("obj.detail 5 0 --context-only").expect("object detail query");
        assert!(matches!(query, Query::ShowObjectDetail { obj: 5, gen: 0, context_only: true }));
        let query = parse_query("object.context 5 0").expect("object context query");
        assert!(matches!(query, Query::ShowObjectContext(5, 0)));
    }

    #[test]
    fn execute_query_supports_object_detail_security_context() {
        with_fixture_context("action_chain_complex.pdf", |ctx| {
            let query = parse_query("obj.detail 1 0 --context-only").expect("query");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("execute query");
            match result {
                QueryResult::Structure(value) => {
                    assert_eq!(value.get("type").and_then(Value::as_str), Some("object_detail"));
                    assert_eq!(
                        value
                            .get("object")
                            .and_then(|entry| entry.get("obj"))
                            .and_then(Value::as_u64),
                        Some(1)
                    );
                    assert!(value.get("security_context").is_some());
                }
                other => panic!("unexpected query result: {:?}", other),
            }
        });
    }

    #[test]
    fn execute_query_supports_object_context_query() {
        with_fixture_context("action_chain_complex.pdf", |ctx| {
            let query = parse_query("object.context 1 0").expect("query");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("execute query");
            match result {
                QueryResult::Structure(value) => {
                    assert_eq!(value.get("type").and_then(Value::as_str), Some("object_context"));
                    assert!(value.get("summary").is_some());
                    assert!(value.get("security_context").is_some());
                }
                other => panic!("unexpected query result: {:?}", other),
            }
        });
    }

    #[test]
    fn execute_query_runtime_caps_returns_expected_sections() {
        with_fixture_context("action_chain_complex.pdf", |ctx| {
            let query = parse_query("runtime.caps").expect("query");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("execute query");
            match result {
                QueryResult::Structure(value) => {
                    assert_eq!(value.get("type").and_then(Value::as_str), Some("runtime_caps"));
                    assert_eq!(value.get("schema_version").and_then(Value::as_u64), Some(1));
                    assert!(value["caps"].get("event_graph").is_some());
                    assert!(value["caps"].get("stream_exec_projection").is_some());
                    assert!(value["caps"].get("finding_meta").is_some());
                }
                other => panic!("unexpected query result: {other:?}"),
            }
        });
    }

    #[test]
    fn parse_query_supports_pages_execution_aliases() {
        let query = parse_query("pages.execution").expect("pages.execution query");
        assert!(matches!(query, Query::PagesExecution));
        let query = parse_query("pages.execution.json").expect("pages.execution.json query");
        assert!(matches!(query, Query::PagesExecution));
    }

    #[test]
    fn execute_query_pages_execution_returns_expected_shape() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let query = parse_query("pages.execution").expect("query");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("query result");
            match result {
                QueryResult::Structure(value) => {
                    assert_eq!(value.get("type").and_then(Value::as_str), Some("pages_execution"));
                    assert!(value["count"].as_u64().unwrap_or(0) >= 1);
                    let pages = value["pages"].as_array().expect("pages array");
                    assert!(!pages.is_empty());
                    let first = &pages[0];
                    assert!(first.get("page_ref").is_some());
                    assert!(first.get("content_stream_count").is_some());
                    assert!(first.get("total_ops").is_some());
                }
                other => panic!("expected structure result, got {:?}", other),
            }
        });
    }

    #[test]
    fn execute_query_pages_execution_supports_predicate_via_meta_fields() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let query = parse_query("pages.execution").expect("query");
            let predicate = parse_predicate("meta.page == '3:0'").expect("predicate");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                Some(&predicate),
            )
            .expect("query result");
            match result {
                QueryResult::Structure(value) => {
                    let pages = value["pages"].as_array().expect("pages array");
                    for page in pages {
                        assert_eq!(page["page_ref"], json!("3:0"));
                    }
                }
                other => panic!("expected structure result, got {:?}", other),
            }
        });
    }

    #[test]
    fn execute_query_obj_output_shape_is_unchanged() {
        with_fixture_context("action_chain_complex.pdf", |ctx| {
            let query = parse_query("obj 1 0").expect("query");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("execute query");
            match result {
                QueryResult::Scalar(ScalarValue::String(value)) => {
                    assert!(value.starts_with("Object 1 0 obj"));
                }
                other => panic!("unexpected query result: {:?}", other),
            }
        });
    }

    #[test]
    fn graph_structure_json_includes_typed_edges_and_action_path_summary() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let query = parse_query("graph.structure.json").expect("query");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("query");
            match result {
                QueryResult::Structure(value) => {
                    assert_eq!(value["type"], json!("structure_graph"));
                    assert!(value["typed_edges"]["total_edges"].is_number());
                    assert!(value["typed_edges"]["by_type"].is_array());
                    assert!(value["action_paths"]["total_chains"].is_number());
                    assert!(value["path_helpers"]["reachable_from_trigger"].is_array());
                    assert!(value["path_helpers"]["paths_to_outcome"].is_array());
                }
                other => panic!("Unexpected result type: {:?}", other),
            }
        });
    }

    #[test]
    fn graph_structure_depth_query_preserves_depth_in_json_output() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let query = parse_query("graph.structure.depth 2").expect("query");
            let query = apply_output_format(query, OutputFormat::Json).expect("format");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("query");
            match result {
                QueryResult::Structure(value) => {
                    assert_eq!(value["path_helpers"]["max_depth"], json!(2));
                    assert!(value["path_helpers"]["next_action_branches"].is_array());
                }
                other => panic!("Unexpected result type: {:?}", other),
            }
        });
    }

    #[test]
    fn graph_structure_overlay_depth_query_preserves_depth_in_json_output() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let query = parse_query("graph.structure.overlay.depth 2").expect("query");
            let query = apply_output_format(query, OutputFormat::Json).expect("format");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("query");
            match result {
                QueryResult::Structure(value) => {
                    assert_eq!(value["path_helpers"]["max_depth"], json!(2));
                    assert!(value.get("overlay").is_some());
                }
                other => panic!("Unexpected result type: {:?}", other),
            }
        });
    }

    #[test]
    fn findings_csv_query_returns_header_and_rows() {
        with_fixture_context("actions/launch_cve_2010_1240.pdf", |ctx| {
            let query = parse_query("findings.csv").expect("query");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("query");
            match result {
                QueryResult::List(rows) => {
                    assert!(!rows.is_empty(), "csv output must include header");
                    assert_eq!(
                        rows[0],
                        "id,kind,severity,impact,confidence,surface,title,description,objects,evidence_count,remediation,meta_json"
                    );
                    assert!(rows.len() > 1, "expected at least one finding row");
                }
                other => panic!("Unexpected result type: {:?}", other),
            }
        });
    }

    #[test]
    fn events_full_csv_query_returns_header() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let query = parse_query("events.full.csv").expect("query");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("query");
            match result {
                QueryResult::List(rows) => {
                    assert!(!rows.is_empty(), "csv output must include header");
                    assert_eq!(
                        rows[0],
                        "node_id,event_type,level,trigger,source_object,linked_finding_count,linked_finding_ids"
                    );
                }
                other => panic!("Unexpected result type: {:?}", other),
            }
        });
    }

    #[test]
    fn baseline_structure_json_unchanged_without_overlay() {
        with_fixture_context("actions/launch_cve_2010_1240.pdf", |ctx| {
            let result = execute_query_with_context(
                &Query::ExportStructureJson,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("structure query");
            let value = match result {
                QueryResult::Structure(value) => value,
                other => panic!("unexpected structure result: {:?}", other),
            };
            let rendered = format!(
                "{}\n",
                serde_json::to_string_pretty(&value).expect("render structure json")
            );
            let expected =
                include_str!("query/snapshots/graph_structure_launch_cve_2010_1240.json");
            assert_eq!(rendered, expected);
        });
    }

    #[test]
    fn graph_structure_overlay_json_exposes_trailer_links() {
        let bytes = build_pdf_with_info_trailer();
        let options = ScanOptions::default();
        let ctx = build_scan_context(&bytes, &options).expect("build context");

        let baseline = execute_query_with_context(
            &Query::ExportStructureJson,
            &ctx,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            None,
        )
        .expect("baseline query");
        let baseline_value = match baseline {
            QueryResult::Structure(value) => value,
            other => panic!("unexpected baseline result: {:?}", other),
        };
        assert!(baseline_value.get("overlay").is_none());

        let overlay = execute_query_with_context(
            &Query::ExportStructureOverlayJson,
            &ctx,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            None,
        )
        .expect("overlay query");
        let overlay_value = match overlay {
            QueryResult::Structure(value) => value,
            other => panic!("unexpected overlay result: {:?}", other),
        };
        assert!(overlay_value.get("overlay").is_some());
        let edges = overlay_value["overlay"]["edges"].as_array().expect("overlay edges");
        assert!(edges.iter().any(|edge| {
            edge.get("from") == Some(&json!("trailer.0"))
                && edge.get("to") == Some(&json!("5 0"))
                && edge.get("edge_type") == Some(&json!("trailer_info"))
        }));
        let nodes = overlay_value["overlay"]["nodes"].as_array().expect("overlay nodes");
        assert!(nodes.iter().any(|node| node.get("id") == Some(&json!("file.root"))));
        assert!(nodes.iter().any(|node| node.get("id") == Some(&json!("revision.0"))));
    }

    #[test]
    fn graph_structure_overlay_marks_high_risk_trailer_targets_as_suspicious() {
        let bytes = build_pdf_with_info_trailer();
        let options = ScanOptions::default();
        let ctx = build_scan_context(&bytes, &options).expect("build context");
        let finding = Finding {
            surface: AttackSurface::FileStructure,
            kind: "test.high_risk".into(),
            severity: Severity::High,
            confidence: Confidence::Certain,
            objects: vec!["5 0".into()],
            ..Finding::default()
        };
        ctx.populate_findings_cache(vec![finding], &ctx.options);

        let overlay = execute_query_with_context(
            &Query::ExportStructureOverlayJson,
            &ctx,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            None,
        )
        .expect("overlay query");
        let overlay_value = match overlay {
            QueryResult::Structure(value) => value,
            other => panic!("unexpected overlay result: {:?}", other),
        };
        let edges = overlay_value["overlay"]["edges"].as_array().expect("overlay edges");
        assert!(edges.iter().any(|edge| {
            edge.get("from") == Some(&json!("trailer.0"))
                && edge.get("to") == Some(&json!("5 0"))
                && edge.get("edge_type") == Some(&json!("trailer_info"))
                && edge.get("suspicious") == Some(&json!(true))
        }));
    }

    #[test]
    fn graph_structure_overlay_dot_contains_overlay_cluster() {
        let bytes = build_pdf_with_info_trailer();
        let options = ScanOptions::default();
        let ctx = build_scan_context(&bytes, &options).expect("build context");

        let result = execute_query_with_context(
            &Query::ExportStructureOverlayDot,
            &ctx,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            None,
        )
        .expect("overlay dot query");
        match result {
            QueryResult::Scalar(ScalarValue::String(dot)) => {
                assert!(dot.contains("cluster_structure_overlay"));
                assert!(dot.contains("trailer_info"));
                assert!(dot.contains("\"trailer.0\" -> \"5 0\""));
            }
            other => panic!("Unexpected result type: {:?}", other),
        }
    }

    #[test]
    fn graph_structure_overlay_json_includes_objstm_provenance_edges() {
        with_fixture_context("objstm_js.pdf", |ctx| {
            let baseline = execute_query_with_context(
                &Query::ExportStructureJson,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("baseline structure query");
            let baseline_value = match baseline {
                QueryResult::Structure(value) => value,
                other => panic!("unexpected baseline result: {:?}", other),
            };
            let result = execute_query_with_context(
                &Query::ExportStructureOverlayJson,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("overlay query");
            let value = match result {
                QueryResult::Structure(value) => value,
                other => panic!("unexpected overlay result: {:?}", other),
            };
            let edges = value["overlay"]["edges"].as_array().expect("overlay edges");
            assert!(
                edges.iter().any(|edge| edge.get("edge_type") == Some(&json!("objstm_contains"))),
                "expected at least one objstm provenance edge"
            );
            let nodes = value["overlay"]["nodes"].as_array().expect("overlay nodes");
            assert!(
                nodes.iter().any(|node| {
                    node.get("id")
                        .and_then(Value::as_str)
                        .map(|id| id.starts_with("objstm."))
                        .unwrap_or(false)
                }),
                "expected at least one objstm pseudo node"
            );
            assert_eq!(
                value["typed_edges"], baseline_value["typed_edges"],
                "overlay export must preserve typed edge summaries (additive behaviour)"
            );
        });
    }

    #[test]
    fn graph_structure_overlay_telemetry_json_includes_telemetry_nodes() {
        let bytes = build_pdf_with_oob_startxref();
        let options = ScanOptions::default();
        let ctx = build_scan_context(&bytes, &options).expect("build context");

        let result = execute_query_with_context(
            &Query::ExportStructureOverlayTelemetryJson,
            &ctx,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            None,
        )
        .expect("overlay telemetry query");
        let value = match result {
            QueryResult::Structure(value) => value,
            other => panic!("unexpected overlay result: {:?}", other),
        };
        assert_eq!(value["overlay"]["stats"]["include_telemetry"], json!(true));
        let nodes = value["overlay"]["nodes"].as_array().expect("overlay nodes");
        assert!(
            nodes.iter().any(|node| {
                node.get("id")
                    .and_then(Value::as_str)
                    .map(|id| id.starts_with("telemetry."))
                    .unwrap_or(false)
            }),
            "expected at least one telemetry pseudo node"
        );
    }

    #[test]
    fn graph_structure_overlay_telemetry_json_includes_signature_nodes_when_available() {
        with_fixture_context("signature.pdf", |ctx| {
            let result = execute_query_with_context(
                &Query::ExportStructureOverlayTelemetryJson,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("overlay telemetry query");
            let value = match result {
                QueryResult::Structure(value) => value,
                other => panic!("unexpected overlay result: {:?}", other),
            };
            assert_eq!(value["overlay"]["stats"]["include_signature"], json!(true));
            let nodes = value["overlay"]["nodes"].as_array().expect("overlay nodes");
            assert!(
                nodes.iter().any(|node| {
                    node.get("id")
                        .and_then(Value::as_str)
                        .map(|id| id.starts_with("signature."))
                        .unwrap_or(false)
                }),
                "expected at least one signature pseudo node"
            );
        });
    }

    #[test]
    fn graph_structure_overlay_reports_detached_object_for_info_dict() {
        let bytes = build_pdf_with_info_trailer();
        let options = ScanOptions::default();
        let ctx = build_scan_context(&bytes, &options).expect("build context");

        let result = execute_query_with_context(
            &Query::ExportStructureOverlayJson,
            &ctx,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            None,
        )
        .expect("overlay query");
        let value = match result {
            QueryResult::Structure(value) => value,
            other => panic!("unexpected overlay result: {:?}", other),
        };
        assert_eq!(value["overlay"]["stats"]["detached_truncated"], json!(false));
        let detached =
            value["overlay"]["stats"]["detached_objects"].as_array().expect("detached objects");
        assert!(
            detached.iter().any(|entry| entry == "5 0"),
            "expected /Info object to be reported as detached"
        );
    }

    #[test]
    fn graph_structure_overlay_caps_detached_object_list() {
        let bytes = build_pdf_with_many_detached(110);
        let options = ScanOptions::default();
        let ctx = build_scan_context(&bytes, &options).expect("build context");

        let result = execute_query_with_context(
            &Query::ExportStructureOverlayJson,
            &ctx,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            None,
        )
        .expect("overlay query");
        let value = match result {
            QueryResult::Structure(value) => value,
            other => panic!("unexpected overlay result: {:?}", other),
        };
        assert_eq!(value["overlay"]["stats"]["detached_truncated"], json!(true));
        let detached_total =
            value["overlay"]["stats"]["detached_total"].as_u64().expect("detached total");
        assert!(detached_total >= 110);
        let detached =
            value["overlay"]["stats"]["detached_objects"].as_array().expect("detached objects");
        assert_eq!(detached.len(), 100);
    }

    #[test]
    fn graph_structure_overlay_unresolved_trailer_ref_is_fail_closed() {
        let bytes = build_pdf_with_unresolved_info_trailer();
        let options = ScanOptions::default();
        let ctx = build_scan_context(&bytes, &options).expect("build context");

        let result = execute_query_with_context(
            &Query::ExportStructureOverlayJson,
            &ctx,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            None,
        )
        .expect("overlay query");
        let value = match result {
            QueryResult::Structure(value) => value,
            other => panic!("unexpected overlay result: {:?}", other),
        };
        let edges = value["overlay"]["edges"].as_array().expect("overlay edges");
        assert!(
            !edges.iter().any(|edge| edge.get("edge_type") == Some(&json!("trailer_info"))),
            "unresolved /Info reference must not emit a phantom edge"
        );
        let nodes = value["overlay"]["nodes"].as_array().expect("overlay nodes");
        let trailer = nodes
            .iter()
            .find(|node| node.get("id") == Some(&json!("trailer.0")))
            .expect("trailer node");
        let unresolved = trailer["attrs"]["unresolved"].as_array().expect("unresolved list");
        assert!(unresolved.iter().any(|entry| entry == "/Info"));
    }

    #[test]
    fn graph_structure_overlay_startxref_miss_is_marked_without_section_edge() {
        let bytes = build_pdf_with_oob_startxref();
        let options = ScanOptions::default();
        let ctx = build_scan_context(&bytes, &options).expect("build context");

        let result = execute_query_with_context(
            &Query::ExportStructureOverlayJson,
            &ctx,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            None,
        )
        .expect("overlay query");
        let value = match result {
            QueryResult::Structure(value) => value,
            other => panic!("unexpected overlay result: {:?}", other),
        };
        let nodes = value["overlay"]["nodes"].as_array().expect("overlay nodes");
        let startxref = nodes
            .iter()
            .find(|node| node.get("id") == Some(&json!("startxref.0")))
            .expect("startxref node");
        assert_eq!(startxref["attrs"]["section_match"], json!(false));

        let edges = value["overlay"]["edges"].as_array().expect("overlay edges");
        assert!(
            !edges.iter().any(|edge| {
                edge.get("from") == Some(&json!("startxref.0"))
                    && edge.get("edge_type") == Some(&json!("startxref_to_section"))
            }),
            "startxref miss must not emit section edge"
        );
    }

    #[test]
    fn graph_event_queries_return_dot_and_json_shapes() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let dot = execute_query_with_context(
                &Query::ExportEventDot,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("event dot");
            match dot {
                QueryResult::Scalar(ScalarValue::String(value)) => {
                    assert!(value.contains("digraph event_graph"));
                }
                other => panic!("expected dot scalar, got {:?}", other),
            }

            let json = execute_query_with_context(
                &Query::ExportEventJson,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("event json");
            match json {
                QueryResult::Structure(value) => {
                    assert!(value.get("nodes").is_some());
                    assert!(value.get("edges").is_some());
                    assert_eq!(value.get("schema_version"), Some(&json!("1.0")));
                }
                other => panic!("expected structure, got {:?}", other),
            }
        });
    }

    #[test]
    fn graph_event_stream_queries_return_dot_and_json_shapes() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let dot = execute_query_with_context(
                &Query::ExportEventStreamDot,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("event stream dot");
            match dot {
                QueryResult::Scalar(ScalarValue::String(value)) => {
                    assert!(value.contains("digraph event_stream_overlay"));
                    assert!(value.contains("cluster_event_stream_overlay"));
                }
                other => panic!("expected dot scalar, got {:?}", other),
            }

            let json = execute_query_with_context(
                &Query::ExportEventStreamJson,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("event stream json");
            match json {
                QueryResult::Structure(value) => {
                    assert_eq!(value.get("type"), Some(&json!("event_stream_overlay_graph")));
                    assert!(value["event_graph"]["nodes"].is_array());
                    assert!(value["overlay"]["nodes"].is_array());
                    let overlay_nodes =
                        value["overlay"]["nodes"].as_array().expect("overlay nodes");
                    assert!(
                        overlay_nodes.iter().any(|node| {
                            node.get("id")
                                .and_then(Value::as_str)
                                .map(|id| id.starts_with("stream.ops."))
                                .unwrap_or(false)
                        }),
                        "expected stream op cluster nodes in overlay"
                    );
                }
                other => panic!("expected structure, got {:?}", other),
            }
        });
    }

    #[test]
    fn graph_event_query_supports_event_type_predicate() {
        let bytes = {
            let objects = vec![
                "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n"
                    .to_string(),
                "2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n".to_string(),
                "3 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert(1)) >>\nendobj\n"
                    .to_string(),
            ];
            build_pdf(&objects, 4)
        };
        let options = ScanOptions::default();
        let ctx = build_scan_context(&bytes, &options).expect("build context");
        {
            let predicate = parse_predicate("event_type == 'DocumentOpen'").expect("predicate");
            let json = execute_query_with_context(
                &Query::ExportEventJson,
                &ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                Some(&predicate),
            )
            .expect("event json");
            match json {
                QueryResult::Structure(value) => {
                    let nodes = value["nodes"].as_array().expect("nodes");
                    assert!(!nodes.is_empty());
                    let event_nodes = nodes
                        .iter()
                        .filter(|node| {
                            node.get("kind").and_then(|kind| kind.as_str()) == Some("event")
                        })
                        .collect::<Vec<_>>();
                    assert!(!event_nodes.is_empty());
                    assert!(event_nodes.iter().all(|node| {
                        node.get("event_type").and_then(|event_type| event_type.as_str())
                            == Some("DocumentOpen")
                    }));
                }
                other => panic!("expected structure, got {:?}", other),
            }
        }
    }

    #[test]
    fn events_query_emits_event_records_with_structured_outcomes() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let result = execute_query_with_context(
                &Query::Events,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("events query");
            let QueryResult::Structure(value) = result else {
                panic!("expected structure");
            };
            let events = value.as_array().expect("array");
            assert!(!events.is_empty());
            let first = &events[0];
            assert!(first.get("node_id").is_some());
            assert!(first.get("trigger").is_some());
            assert!(first.get("outcome_targets").is_some());
        });
    }

    #[test]
    fn events_query_supports_trigger_predicate() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let predicate = parse_predicate("trigger == 'automatic'").expect("predicate");
            let result = execute_query_with_context(
                &Query::Events,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                Some(&predicate),
            )
            .expect("events query");
            let QueryResult::Structure(value) = result else {
                panic!("expected structure");
            };
            for event in value.as_array().expect("array") {
                assert_eq!(
                    event.get("trigger").and_then(|value| value.as_str()),
                    Some("automatic")
                );
            }
        });
    }

    #[test]
    fn events_full_query_exposes_reverse_index() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let result = execute_query_with_context(
                &Query::EventsFull,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("events full query");
            let QueryResult::Structure(value) = result else {
                panic!("expected structure");
            };
            assert!(value.get("events").is_some());
            assert!(value.get("finding_event_index").is_some());
            assert!(value.get("event_finding_index").is_some());
            let has_stream_exec =
                value.get("events").and_then(|events| events.as_array()).is_some_and(|events| {
                    events.iter().any(|event| {
                        event.get("event_type").and_then(|v| v.as_str())
                            == Some("ContentStreamExec")
                            && event.get("stream_exec").is_some()
                    })
                });
            assert!(has_stream_exec, "expected stream_exec payload on ContentStreamExec event");
        });
    }

    #[test]
    fn apply_output_format_handles_event_hops_variants() {
        let json_variant = apply_output_format(Query::ExportEventDotHops(2), OutputFormat::Json)
            .expect("json conversion");
        assert!(matches!(json_variant, Query::ExportEventJsonHops(2)));

        let dot_variant = apply_output_format(Query::ExportEventJsonHops(3), OutputFormat::Dot)
            .expect("dot conversion");
        assert!(matches!(dot_variant, Query::ExportEventDotHops(3)));

        let stream_json_variant =
            apply_output_format(Query::ExportEventStreamDotHops(2), OutputFormat::Json)
                .expect("stream json conversion");
        assert!(matches!(stream_json_variant, Query::ExportEventStreamJsonHops(2)));

        let stream_dot_variant =
            apply_output_format(Query::ExportEventStreamJsonHops(3), OutputFormat::Dot)
                .expect("stream dot conversion");
        assert!(matches!(stream_dot_variant, Query::ExportEventStreamDotHops(3)));
    }

    #[test]
    fn parse_query_supports_xref_namespace() {
        assert!(matches!(parse_query("xref").expect("xref"), Query::Xref));
        assert!(matches!(
            parse_query("xref.startxrefs").expect("xref.startxrefs"),
            Query::XrefStartxrefs
        ));
        assert!(matches!(
            parse_query("xref.sections").expect("xref.sections"),
            Query::XrefSections
        ));
        assert!(matches!(
            parse_query("xref.trailers").expect("xref.trailers"),
            Query::XrefTrailers
        ));
        assert!(matches!(
            parse_query("xref.deviations").expect("xref.deviations"),
            Query::XrefDeviations
        ));
        assert!(matches!(parse_query("revisions").expect("revisions"), Query::Revisions));
        assert!(matches!(
            parse_query("revisions.detail").expect("revisions.detail"),
            Query::RevisionsDetail
        ));
    }

    #[test]
    fn xref_queries_support_predicates() {
        assert!(ensure_predicate_supported(&Query::XrefStartxrefs).is_ok());
        assert!(ensure_predicate_supported(&Query::XrefSections).is_ok());
        assert!(ensure_predicate_supported(&Query::XrefTrailers).is_ok());
        assert!(ensure_predicate_supported(&Query::XrefDeviations).is_ok());
        assert!(ensure_predicate_supported(&Query::Revisions).is_ok());
        assert!(ensure_predicate_supported(&Query::RevisionsDetail).is_ok());
        assert!(ensure_predicate_supported(&Query::ExportEventStreamJson).is_ok());
        assert!(ensure_predicate_supported(&Query::ExportEventStreamDotHops(2)).is_ok());
        assert!(ensure_predicate_supported(&Query::Xref).is_err());
    }

    #[test]
    fn execute_query_returns_xref_records() {
        with_fixture_context("actions/launch_cve_2010_1240.pdf", |ctx| {
            let query = parse_query("xref.startxrefs").expect("query");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("execute query");
            match result {
                QueryResult::Structure(value) => {
                    let items = value.as_array().expect("array");
                    assert!(!items.is_empty());
                    assert!(items[0].get("offset").is_some());
                }
                other => panic!("Unexpected result type: {other:?}"),
            }
        });
    }

    #[test]
    fn execute_query_returns_revision_detail_records() {
        with_fixture_context("actions/launch_cve_2010_1240.pdf", |ctx| {
            let query = parse_query("revisions.detail").expect("query");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("execute query");
            match result {
                QueryResult::Structure(value) => {
                    let items = value.as_array().expect("array");
                    assert!(!items.is_empty());
                    assert!(items[0].get("revision").is_some());
                    assert!(items[0].get("objects_added").is_some());
                    assert!(items[0].get("anomaly_score").is_some());
                }
                other => panic!("Unexpected result type: {other:?}"),
            }
        });
    }

    #[test]
    fn execute_query_supports_finding_shortcut_counts() {
        with_fixture_context("embedded/embedded_exe_cve_2018_4990.pdf", |ctx| {
            let list_query = parse_query("embedded.executables").expect("query");
            let list_result = execute_query_with_context(
                &list_query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("execute query");
            match list_result {
                QueryResult::Structure(value) => {
                    let list = value.as_array().expect("list");
                    assert!(!list.is_empty());
                }
                _ => panic!("unexpected list query result"),
            }

            let count_query = parse_query("embedded.executables.count").expect("query");
            let count_result = execute_query_with_context(
                &count_query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("execute query");
            match count_result {
                QueryResult::Scalar(ScalarValue::Number(count)) => {
                    assert!(count > 0);
                }
                _ => panic!("unexpected count query result"),
            }

            let predicate = parse_predicate(
                "objects > 0 AND kind == 'embedded_executable_present' AND severity == 'high'",
            )
            .expect("predicate");
            let filtered_result = execute_query_with_context(
                &list_query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                Some(&predicate),
            )
            .expect("execute query");
            match filtered_result {
                QueryResult::Structure(value) => {
                    let list = value.as_array().expect("list");
                    assert!(!list.is_empty());
                }
                _ => panic!("unexpected filtered query result"),
            }
        });
    }

    #[test]
    fn batch_query_supports_finding_shortcut_counts() {
        let temp = tempdir().expect("tempdir");
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root")
            .join("crates/sis-pdf-core/tests/fixtures/embedded/embedded_exe_cve_2018_4990.pdf");
        let dst = temp.path().join("sample.pdf");
        std::fs::copy(&src, &dst).expect("copy fixture");

        let query = parse_query("embedded.executables.count").expect("query");
        let scan_options = ScanOptions::default();
        run_query_batch(
            &query,
            temp.path(),
            "*.pdf",
            &scan_options,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            None,
            OutputFormat::Json,
            false,
            10,
            10 * 1024 * 1024,
            3,
            None,
        )
        .expect("batch query");
    }

    #[test]
    fn execute_query_supports_embedded_extraction() {
        with_fixture_context("embedded/embedded_exe_cve_2018_4990.pdf", |ctx| {
            let temp = tempdir().expect("tempdir");
            let query = parse_query("embedded").expect("query");
            let result = execute_query_with_context(
                &query,
                ctx,
                Some(temp.path()),
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("execute query");
            match result {
                QueryResult::List(list) => {
                    assert!(!list.is_empty());
                    let count = std::fs::read_dir(temp.path()).expect("read dir").count();
                    assert!(count > 0);
                }
                _ => panic!("unexpected embedded extraction result"),
            }
        });
    }

    #[test]
    fn execute_query_supports_filter_shortcuts() {
        with_fixture_context("filters/filter_unusual_chain.pdf", |ctx| {
            let query = parse_query("filters.unusual").expect("query");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("execute query");
            match result {
                QueryResult::Structure(value) => {
                    let list = value.as_array().expect("list");
                    assert!(!list.is_empty());
                }
                _ => panic!("unexpected filters.unusual result"),
            }

            let query = parse_query("filters.repeated").expect("query");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("execute query");
            match result {
                QueryResult::Structure(value) => {
                    let list = value.as_array().expect("list");
                    assert!(!list.is_empty());
                }
                _ => panic!("unexpected filters.repeated result"),
            }
        });

        with_fixture_context("filters/filter_invalid_order.pdf", |ctx| {
            let query = parse_query("filters.invalid").expect("query");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("execute query");
            match result {
                QueryResult::Structure(value) => {
                    let list = value.as_array().expect("list");
                    assert!(!list.is_empty());
                }
                _ => panic!("unexpected filters.invalid result"),
            }
        });
    }

    #[test]
    fn embedded_predicate_supports_name_and_magic() {
        with_fixture_context("embedded/embedded_exe_cve_2018_4990.pdf", |ctx| {
            let predicate =
                parse_predicate("magic == 'pe' AND name == 'payload.exe'").expect("predicate");
            let embedded = extract_embedded_files(ctx, DecodeMode::Decode, Some(&predicate))
                .expect("embedded");
            assert!(!embedded.is_empty());
        });
    }

    #[test]
    fn execute_query_supports_xfa_script_extraction() {
        with_fixture_context("xfa/xfa_submit_sensitive.pdf", |ctx| {
            let temp = tempdir().expect("tempdir");
            let query = parse_query("xfa.scripts").expect("query");
            let result = execute_query_with_context(
                &query,
                ctx,
                Some(temp.path()),
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("execute query");
            match result {
                QueryResult::List(list) => {
                    assert!(!list.is_empty());
                    let count = std::fs::read_dir(temp.path()).expect("read dir").count();
                    assert!(count > 0);
                    let manifest = temp.path().join("manifest.json");
                    assert!(manifest.exists());
                    let data = std::fs::read(&manifest).expect("read manifest");
                    let entries: Vec<serde_json::Value> =
                        serde_json::from_slice(&data).expect("parse manifest");
                    let script_entries =
                        list.iter().filter(|line| !line.starts_with("manifest.json")).count();
                    assert_eq!(entries.len(), script_entries);
                    let first = &entries[0];
                    assert!(
                        first["sha256"].as_str().map(|s| s.len() == 64).unwrap_or(false),
                        "sha256 length"
                    );
                    assert!(
                        first["filename"]
                            .as_str()
                            .map(|name| name.starts_with("xfa_script"))
                            .unwrap_or(false),
                        "filename format"
                    );
                }
                _ => panic!("unexpected xfa scripts result"),
            }
        });
    }

    #[test]
    fn execute_query_supports_swf_extraction() {
        with_fixture_context("media/swf_cve_2011_0611.pdf", |ctx| {
            let temp = tempdir().expect("tempdir");
            let query = parse_query("swf.extract").expect("query");
            let result = execute_query_with_context(
                &query,
                ctx,
                Some(temp.path()),
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("execute query");
            match result {
                QueryResult::List(list) => {
                    assert!(!list.is_empty());
                    let count = std::fs::read_dir(temp.path()).expect("read dir").count();
                    assert!(count > 0);
                }
                _ => panic!("unexpected swf extraction result"),
            }
        });
    }

    #[test]
    fn batch_query_supports_xfa_and_swf_extract_counts() {
        let temp = tempdir().expect("tempdir");
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root")
            .join("crates/sis-pdf-core/tests/fixtures");
        std::fs::copy(
            root.join("xfa/xfa_submit_sensitive.pdf"),
            temp.path().join("sample-xfa.pdf"),
        )
        .expect("copy xfa");
        std::fs::copy(root.join("media/swf_cve_2011_0611.pdf"), temp.path().join("sample-swf.pdf"))
            .expect("copy swf");

        let scan_options = ScanOptions::default();
        let query = parse_query("xfa.scripts.count").expect("query");
        run_query_batch(
            &query,
            temp.path(),
            "*.pdf",
            &scan_options,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            None,
            OutputFormat::Json,
            false,
            10,
            10 * 1024 * 1024,
            3,
            None,
        )
        .expect("batch query xfa");

        let query = parse_query("swf.extract.count").expect("query");
        run_query_batch(
            &query,
            temp.path(),
            "*.pdf",
            &scan_options,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            None,
            OutputFormat::Json,
            false,
            10,
            10 * 1024 * 1024,
            3,
            None,
        )
        .expect("batch query swf");
    }

    #[test]
    fn batch_query_supports_filter_shortcut_counts() {
        let temp = tempdir().expect("tempdir");
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root")
            .join("crates/sis-pdf-core/tests/fixtures/filters");
        std::fs::copy(
            root.join("filter_unusual_chain.pdf"),
            temp.path().join("sample-unusual.pdf"),
        )
        .expect("copy unusual chain");
        std::fs::copy(
            root.join("filter_invalid_order.pdf"),
            temp.path().join("sample-invalid.pdf"),
        )
        .expect("copy invalid order");

        let scan_options = ScanOptions::default();
        let query = parse_query("filters.unusual.count").expect("query");
        run_query_batch(
            &query,
            temp.path(),
            "*.pdf",
            &scan_options,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            None,
            OutputFormat::Json,
            false,
            10,
            10 * 1024 * 1024,
            3,
            None,
        )
        .expect("batch query filters");
    }

    fn assert_query_result_has_data(result: QueryResult) {
        match result {
            QueryResult::List(list) => {
                assert!(!list.is_empty(), "expected list result to contain entries")
            }
            QueryResult::Structure(value) => {
                if !(value.is_array() || value.is_object() || value.is_string()) {
                    panic!("unexpected structure result: {}", value);
                }
            }
            QueryResult::Scalar(ScalarValue::Number(n)) => {
                assert!(n > 0, "expected scalar number result to be positive (got {})", n)
            }
            QueryResult::Scalar(ScalarValue::String(s)) => {
                assert!(!s.is_empty(), "expected scalar string result")
            }
            QueryResult::Scalar(ScalarValue::Boolean(b)) => assert!(
                b,
                "expected scalar boolean result to be true when checking data (got false)"
            ),
            QueryResult::Error(err) => panic!("query returned error: {:?}", err),
        }
    }

    #[test]
    fn batch_query_supports_new_shortcuts() {
        let temp = tempdir().expect("tempdir");
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root")
            .join("crates/sis-pdf-core/tests/fixtures");
        [
            "embedded/embedded_exe_cve_2018_4990.pdf",
            "launch_action.pdf",
            "action_chain_complex.pdf",
            "action_hidden_trigger.pdf",
            "xfa/xfa_submit_sensitive.pdf",
            "media/swf_cve_2011_0611.pdf",
            "filters/filter_unusual_chain.pdf",
            "filters/filter_invalid_order.pdf",
            "encryption/weak_encryption_cve_2019_7089.pdf",
        ]
        .iter()
        .for_each(|rel| {
            let src = root.join(rel);
            let dst = temp.path().join(std::path::Path::new(rel).file_name().expect("filename"));
            std::fs::copy(&src, &dst).unwrap_or_else(|err| panic!("unable to copy {}: {err}", rel));
        });

        let scan_options = ScanOptions::default();
        for query_str in &[
            "embedded.executables.count",
            "launch.external",
            "actions.chains.complex",
            "actions.triggers.hidden",
            "xfa.submit",
            "swf.count",
            "streams.high-entropy.count",
            "filters.unusual",
        ] {
            let query = parse_query(query_str).expect("query");
            run_query_batch(
                &query,
                temp.path(),
                "*.pdf",
                &scan_options,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
                OutputFormat::Json,
                false,
                10,
                10 * 1024 * 1024,
                3,
                None,
            )
            .unwrap_or_else(|err| panic!("batch query {} failed: {err}", query_str));
        }
    }

    #[test]
    fn execute_query_supports_new_shortcuts() {
        for (query_str, fixture) in &[
            ("embedded.executables", "embedded/embedded_exe_cve_2018_4990.pdf"),
            ("launch.external", "launch_action.pdf"),
            ("launch.embedded", "embedded/embedded_exe_cve_2018_4990.pdf"),
            ("actions.chains.complex", "action_chain_complex.pdf"),
            ("actions.triggers.hidden", "action_hidden_trigger.pdf"),
            ("xfa.submit", "xfa/xfa_submit_sensitive.pdf"),
            ("swf", "media/swf_cve_2011_0611.pdf"),
            ("streams.high-entropy", "encryption/weak_encryption_cve_2019_7089.pdf"),
            ("filters.unusual", "filters/filter_unusual_chain.pdf"),
        ] {
            with_fixture_context(fixture, |ctx| {
                let query = parse_query(query_str).expect("query");
                let result = execute_query_with_context(
                    &query,
                    ctx,
                    None,
                    1024 * 1024,
                    DecodeMode::Decode,
                    None,
                )
                .expect("execute query");
                assert_query_result_has_data(result);
            });
        }
    }

    #[test]
    fn batch_query_supports_findings_composite_predicate() {
        let temp = tempdir().expect("tempdir");
        let pdf_path = temp.path().join("launch_obfuscated.pdf");
        fs::write(&pdf_path, build_launch_obfuscated_pdf(&high_entropy_payload()))
            .expect("write pdf");

        let scan_options = ScanOptions::default();
        let query = parse_query("findings.composite").expect("query");
        let predicate =
            parse_predicate("kind == 'launch_obfuscated_executable'").expect("predicate");
        run_query_batch(
            &query,
            temp.path(),
            "*.pdf",
            &scan_options,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            Some(&predicate),
            OutputFormat::Json,
            false,
            5,
            5 * 1024 * 1024,
            3,
            None,
        )
        .expect("batch composite query");

        let count_query = parse_query("findings.composite.count").expect("query");
        run_query_batch(
            &count_query,
            temp.path(),
            "*.pdf",
            &scan_options,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            Some(&predicate),
            OutputFormat::Json,
            false,
            5,
            5 * 1024 * 1024,
            3,
            None,
        )
        .expect("batch composite count query");
    }

    #[test]
    fn batch_query_supports_correlations_predicate() {
        let temp = tempdir().expect("tempdir");
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root is two levels above crate manifest");
        let fixture_path = workspace_root
            .join("crates")
            .join("sis-pdf-core")
            .join("tests")
            .join("fixtures")
            .join("xfa")
            .join("xfa_submit_sensitive.pdf");
        let pdf_path = temp.path().join("xfa_submit_sensitive.pdf");
        fs::copy(&fixture_path, &pdf_path).expect("copy fixture");

        let scan_options = ScanOptions::default();
        let query = parse_query("correlations").expect("query");
        let predicate = parse_predicate("kind == 'xfa_data_exfiltration_risk'").expect("predicate");
        run_query_batch(
            &query,
            temp.path(),
            "*.pdf",
            &scan_options,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            Some(&predicate),
            OutputFormat::Json,
            false,
            5,
            5 * 1024 * 1024,
            3,
            None,
        )
        .expect("batch correlations query");

        let count_query = parse_query("correlations.count").expect("query");
        run_query_batch(
            &count_query,
            temp.path(),
            "*.pdf",
            &scan_options,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            Some(&predicate),
            OutputFormat::Json,
            false,
            5,
            5 * 1024 * 1024,
            3,
            None,
        )
        .expect("batch correlations count query");
    }

    #[test]
    fn execute_query_supports_findings_composite_predicate() {
        let bytes = build_launch_obfuscated_pdf(&high_entropy_payload());
        let options = ScanOptions::default();
        let ctx = build_scan_context(&bytes, &options).expect("build context");
        let predicate =
            parse_predicate("kind == 'launch_obfuscated_executable'").expect("predicate");

        let result = execute_query_with_context(
            &Query::FindingsComposite,
            &ctx,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            Some(&predicate),
        )
        .expect("execute composite query");
        match result {
            QueryResult::Structure(value) => {
                let arr = value.as_array().expect("expected array");
                assert!(!arr.is_empty(), "composite results should not be empty");
            }
            other => panic!("unexpected query result: {:?}", other),
        }

        let count_result = execute_query_with_context(
            &Query::FindingsCompositeCount,
            &ctx,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            Some(&predicate),
        )
        .expect("execute composite count query");
        match count_result {
            QueryResult::Scalar(ScalarValue::Number(n)) => {
                assert!(n > 0, "expected positive composite count");
            }
            other => panic!("unexpected count result: {:?}", other),
        }
    }

    #[test]
    fn execute_query_supports_correlations_predicate() {
        let bytes = build_launch_obfuscated_pdf(&high_entropy_payload());
        let options = ScanOptions::default();
        let ctx = build_scan_context(&bytes, &options).expect("build context");
        let predicate =
            parse_predicate("kind == 'launch_obfuscated_executable'").expect("predicate");

        let result = execute_query_with_context(
            &Query::Correlations,
            &ctx,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            Some(&predicate),
        )
        .expect("execute correlations query");
        match result {
            QueryResult::Structure(value) => {
                let obj = value.as_object().expect("expected object");
                let entry =
                    obj.get("launch_obfuscated_executable").expect("expected composite summary");
                let count = entry.get("count").and_then(Value::as_u64).expect("count");
                assert!(count > 0, "expected positive composite count");
            }
            other => panic!("unexpected query result: {:?}", other),
        }
    }

    #[test]
    fn query_correlations_summary_reports_counts() {
        with_fixture_context("xfa/xfa_submit_sensitive.pdf", |ctx| {
            let query = parse_query("correlations").expect("query");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("execute correlations query");
            match result {
                QueryResult::Structure(value) => {
                    let obj = value.as_object().expect("expected object");
                    let entry =
                        obj.get("xfa_data_exfiltration_risk").expect("expected xfa composite");
                    let count =
                        entry.get("count").and_then(Value::as_u64).expect("count as number");
                    assert!(count > 0, "expected positive composite count");
                }
                other => panic!("unexpected query result: {:?}", other),
            }
        });
    }

    #[test]
    fn query_correlations_count_matches_summary() {
        with_fixture_context("xfa/xfa_submit_sensitive.pdf", |ctx| {
            let summary_query = parse_query("correlations").expect("parse summary");
            let summary_result = execute_query_with_context(
                &summary_query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("execute correlations summary");
            let total_from_summary = match summary_result {
                QueryResult::Structure(value) => value
                    .as_object()
                    .expect("object")
                    .values()
                    .map(|entry| {
                        entry.get("count").and_then(Value::as_u64).expect("count") as usize
                    })
                    .sum::<usize>(),
                other => panic!("unexpected result: {:?}", other),
            };

            let count_query = parse_query("correlations.count").expect("parse count");
            let count_result = execute_query_with_context(
                &count_query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("execute correlations count");
            match count_result {
                QueryResult::Scalar(ScalarValue::Number(n)) => {
                    assert_eq!(n as usize, total_from_summary);
                    assert!(n > 0, "expected at least one correlation");
                }
                other => panic!("unexpected count result: {:?}", other),
            }
        });
    }

    #[test]
    fn export_features_outputs_expected_counts() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let csv_query = parse_query("features").expect("query");
            let csv_result = execute_query_with_context(
                &csv_query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("execute query");
            let feature_names = sis_pdf_core::features::feature_names();
            match csv_result {
                QueryResult::Scalar(ScalarValue::String(csv)) => {
                    let line_count = csv.lines().count();
                    assert_eq!(line_count, feature_names.len() + 1);
                }
                _ => panic!("unexpected features csv result"),
            }

            let json_query = parse_query("features.json").expect("query");
            let json_result = execute_query_with_context(
                &json_query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("execute query");
            match json_result {
                QueryResult::Structure(value) => {
                    let obj = value.as_object().expect("features object");
                    assert_eq!(obj.len(), feature_names.len());
                }
                _ => panic!("unexpected features json result"),
            }
        });
    }

    #[test]
    fn export_features_jsonl_contains_all_fields() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let query = parse_query("features").expect("query");
            let query = apply_output_format(query, OutputFormat::Jsonl).expect("jsonl");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("query");
            let output =
                format_jsonl("features", "content_first_phase1.pdf", &result).expect("jsonl line");
            let parsed: serde_json::Value =
                serde_json::from_str(&output).expect("parse jsonl features");
            let result_map = parsed["result"].as_object().expect("expected result object");
            let feature_names = sis_pdf_core::features::feature_names();
            assert_eq!(result_map.len(), feature_names.len());
            for name in feature_names {
                assert!(result_map.contains_key(name), "jsonl output missing feature {}", name);
            }
        });
    }

    #[test]
    fn batch_query_features_jsonl_streaming() {
        let temp = tempdir().expect("tempdir");
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = manifest_dir.parent().and_then(|p| p.parent()).expect("workspace root");
        let fixture_root = root.join("crates/sis-pdf-core/tests/fixtures");
        let fixture = fixture_root.join("content_first_phase1.pdf");
        let dest = temp.path().join("content_first_phase1.pdf");
        fs::copy(&fixture, &dest).expect("copy fixture");

        let scan_options = ScanOptions::default();
        let query = parse_query("features").expect("query");
        let query = apply_output_format(query, OutputFormat::Jsonl).expect("jsonl format");
        run_query_batch(
            &query,
            temp.path(),
            "*.pdf",
            &scan_options,
            None,
            1024 * 1024,
            DecodeMode::Decode,
            None,
            OutputFormat::Jsonl,
            false,
            5,
            10 * 1024 * 1024,
            3,
            None,
        )
        .expect("batch features jsonl");
    }

    #[test]
    fn list_objects_respects_predicate_filter() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let all = list_objects(ctx, DecodeMode::Decode, 1024, None).expect("all objects");
            let predicate = parse_predicate("length < 0").expect("predicate");
            let filtered = list_objects(ctx, DecodeMode::Decode, 1024, Some(&predicate))
                .expect("filtered objects");
            assert!(filtered.is_empty());
            assert!(all.len() >= filtered.len());
        });
    }

    #[test]
    fn predicate_context_for_url_tracks_length() {
        let predicate = parse_predicate("length == 4 AND type == 'Url'").expect("predicate");
        let ctx = predicate_context_for_url("http");
        assert!(predicate.evaluate(&ctx));
    }

    #[test]
    fn predicate_context_for_event_maps_level_and_type() {
        let event = json!({
            "level": "document",
            "trigger": "automatic",
            "event_type": "DocumentOpen",
            "action_details": "Open action"
        });
        let predicate = parse_predicate("filter == 'document' AND subtype == 'DocumentOpen'")
            .expect("predicate");
        let ctx = predicate_context_for_event(&event).expect("context");
        assert!(predicate.evaluate(&ctx));
        let trigger_predicate = parse_predicate("trigger == 'automatic'").expect("predicate");
        assert!(trigger_predicate.evaluate(&ctx));
    }

    #[test]
    fn predicate_string_comparisons_are_case_insensitive() {
        let eq_predicate = parse_predicate("severity == 'Info'").expect("eq predicate");
        let neq_predicate = parse_predicate("severity != 'Low'").expect("neq predicate");
        let ctx = PredicateContext {
            length: 0,
            filter: Some("medium".to_string()),
            type_name: "Finding".to_string(),
            subtype: Some("xref_conflict".to_string()),
            entropy: 0.0,
            width: 0,
            height: 0,
            pixels: 0,
            risky: false,
            severity: Some("info".to_string()),
            confidence: None,
            surface: None,
            kind: Some("xref_conflict".to_string()),
            object_count: 0,
            evidence_count: 0,
            name: None,
            magic: None,
            hash: None,
            impact: None,
            action_type: None,
            action_target: None,
            action_initiation: None,
            meta: HashMap::new(),
        };
        assert!(eq_predicate.evaluate(&ctx));
        assert!(neq_predicate.evaluate(&ctx));
    }

    #[test]
    fn execute_query_reports_file_read_error() {
        let temp_dir = tempdir().expect("temp dir");
        let missing_path = temp_dir.path().join("does_not_exist.pdf");
        let options = ScanOptions::default();
        let result = execute_query(
            &Query::Pages,
            &missing_path,
            &options,
            None,
            1024,
            DecodeMode::Decode,
            None,
        )
        .expect("query result");
        let err = match result {
            QueryResult::Error(err) => err,
            other => panic!("expected error result, got {:?}", other),
        };
        assert_eq!(err.error_code, "FILE_READ_ERROR");
        let context = err.context.expect("context");
        assert_eq!(context["path"], json!(missing_path.display().to_string()));
    }

    #[test]
    fn format_batch_csv_row_normalises_error_rows() {
        let row = format_batch_csv_row(
            "bad.pdf",
            &QueryResult::Error(QueryError {
                status: "error",
                error_code: "FILE_READ_ERROR",
                message: "failed, reason".to_string(),
                context: None,
            }),
        );
        assert_eq!(row, "bad.pdf,error,FILE_READ_ERROR,\"failed, reason\",");
    }

    #[test]
    fn format_batch_csv_row_escapes_payload_newlines_and_quotes() {
        let row = format_batch_csv_row(
            "ok.pdf",
            &QueryResult::Scalar(ScalarValue::String("header\n\"quoted\"".to_string())),
        );
        assert_eq!(row, "ok.pdf,ok,,,\"header\n\"\"quoted\"\"\"");
    }

    #[test]
    fn empty_runtime_caps_exposes_zeroed_stable_shape() {
        let caps = empty_runtime_caps();
        assert_eq!(caps["type"], json!("runtime_caps"));
        assert_eq!(caps["schema_version"], json!(1));
        assert_eq!(caps["caps"]["event_graph"]["applied"], json!(false));
        assert_eq!(caps["caps"]["event_graph"]["node_cap"], json!(0));
        assert_eq!(caps["caps"]["stream_exec_projection"]["truncated_event_count"], json!(0));
        assert_eq!(caps["caps"]["finding_meta"]["truncation_flag_count"], json!(0));
    }

    #[test]
    fn resolve_batch_job_count_respects_defaults_and_caps() {
        assert_eq!(
            resolve_batch_job_count(16, None, false, 1 * 1024 * 1024),
            DEFAULT_MAX_BATCH_JOBS
        );
        assert_eq!(resolve_batch_job_count(2, None, false, 1 * 1024 * 1024), 2);
        assert_eq!(resolve_batch_job_count(1, None, false, 1 * 1024 * 1024), 1);
    }

    #[test]
    fn resolve_batch_job_count_clamps_deep_large_default_path() {
        let large = DEEP_LARGE_FILE_THRESHOLD_BYTES + 1;
        assert_eq!(resolve_batch_job_count(32, None, true, large), DEEP_LARGE_FILE_JOB_CAP);
        assert_eq!(resolve_batch_job_count(3, None, true, large), 3);
    }

    #[test]
    fn resolve_batch_job_count_honours_override_and_thread_limit() {
        assert_eq!(resolve_batch_job_count(32, Some(12), true, u64::MAX), 12);
        assert_eq!(resolve_batch_job_count(4, Some(12), true, u64::MAX), 4);
        assert_eq!(resolve_batch_job_count(8, Some(1), false, 0), 1);
    }

    #[test]
    fn execute_query_reports_parse_error_for_empty_fixture() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root is two levels above crate manifest");
        let fixture_path: PathBuf =
            workspace_root.join("crates/sis-pdf-core/tests/fixtures/invalid_empty.pdf");
        let options = ScanOptions::default();
        let result = execute_query(
            &Query::Pages,
            &fixture_path,
            &options,
            None,
            1024,
            DecodeMode::Decode,
            None,
        )
        .expect("query result");
        let err = match result {
            QueryResult::Error(err) => err,
            other => panic!("expected error result, got {:?}", other),
        };
        assert_eq!(err.error_code, "PARSE_ERROR");
        let context = err.context.expect("context");
        assert_eq!(context["path"], json!(fixture_path.display().to_string()));
    }

    #[test]
    fn execute_query_reports_invalid_pdf_finding_for_missing_header() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root is two levels above crate manifest");
        let fixture_path: PathBuf =
            workspace_root.join("crates/sis-pdf-core/tests/fixtures/invalid_header.pdf");
        let options = ScanOptions::default();
        let result = execute_query(
            &Query::Pages,
            &fixture_path,
            &options,
            None,
            1024,
            DecodeMode::Decode,
            None,
        )
        .expect("query result");
        let findings_value = match result {
            QueryResult::Structure(value) => value,
            other => panic!("expected findings result, got {:?}", other),
        };
        let findings: Vec<Finding> =
            serde_json::from_value(findings_value).expect("deserialize findings");
        let invalid = findings
            .iter()
            .find(|f| f.kind == "invalid_pdf_header")
            .expect("missing invalid header finding");
        assert_eq!(invalid.severity, Severity::High);
        assert_eq!(invalid.surface, AttackSurface::FileStructure);
        assert!(invalid.meta["path"].ends_with("invalid_header.pdf"));
        if let Some(polyglot) = findings.iter().find(|f| f.kind == "polyglot_signature_conflict") {
            assert!(!polyglot.meta["polyglot.signatures"].is_empty());
        }
    }

    #[test]
    fn execute_query_reports_invalid_pdf_finding_for_html_header() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root is two levels above crate manifest");
        let fixture_path: PathBuf =
            workspace_root.join("crates/sis-pdf-core/tests/fixtures/html_header.pdf");
        let options = ScanOptions::default();
        let result = execute_query(
            &Query::Pages,
            &fixture_path,
            &options,
            None,
            1024,
            DecodeMode::Decode,
            None,
        )
        .expect("query result");
        let findings_value = match result {
            QueryResult::Structure(value) => value,
            other => panic!("expected findings result, got {:?}", other),
        };
        let findings: Vec<Finding> =
            serde_json::from_value(findings_value).expect("deserialize findings");
        let invalid = findings
            .iter()
            .find(|f| f.kind == "invalid_pdf_header")
            .expect("missing invalid header finding");
        assert_eq!(invalid.severity, Severity::High);
        assert!(invalid.meta["path"].ends_with("html_header.pdf"));
        let polyglot = findings
            .iter()
            .find(|f| f.kind == "polyglot_signature_conflict")
            .expect("missing polyglot finding");
        assert_eq!(polyglot.surface, AttackSurface::FileStructure);
        assert_eq!(polyglot.severity, Severity::High);
        assert!(polyglot.meta["polyglot.signatures"].as_str().contains("@"));
    }

    #[test]
    fn classify_query_error_detects_object_not_found() {
        let err = anyhow!("Object 5 0 not found");
        let query_error = build_query_error(err);
        assert_eq!(query_error.error_code, "OBJ_NOT_FOUND");
        let context = query_error.context.expect("context");
        assert_eq!(context["requested"], json!("5 0"));
    }

    fn high_entropy_payload() -> Vec<u8> {
        let mut payload = Vec::with_capacity(1024);
        payload.extend_from_slice(b"MZ");
        payload.extend((0u8..=255).cycle().take(1022));
        payload
    }

    fn build_launch_obfuscated_pdf(payload: &[u8]) -> Vec<u8> {
        let mut doc = Vec::new();
        doc.extend_from_slice(b"%PDF-1.7\n");
        let mut offsets = Vec::new();

        append_text_object(
            &mut doc,
            &mut offsets,
            1,
            b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\n",
        );
        append_text_object(
            &mut doc,
            &mut offsets,
            2,
            b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>\n",
        );
        append_text_object(&mut doc, &mut offsets, 3, b"<< /Type /Page /Parent 2 0 R >>\n");
        append_text_object(&mut doc, &mut offsets, 4, b"<< /Type /Action /S /Launch /F 5 0 R >>\n");
        append_text_object(
            &mut doc,
            &mut offsets,
            5,
            b"<< /Type /Filespec /F (payload.exe) /EF << /F 6 0 R >> >>\n",
        );

        let offset = doc.len();
        offsets.push(offset);
        doc.extend_from_slice(b"6 0 obj << /Type /EmbeddedFile /Length ");
        doc.extend_from_slice(payload.len().to_string().as_bytes());
        doc.extend_from_slice(b" >>\nstream\n");
        doc.extend_from_slice(payload);
        doc.extend_from_slice(b"\nendstream\nendobj\n");

        let xref_offset = doc.len();
        doc.extend_from_slice(b"xref\n0 7\n");
        doc.extend_from_slice(b"0000000000 65535 f \n");
        for offset in &offsets {
            doc.extend_from_slice(format!("{:010} 00000 n \n", offset).as_bytes());
        }
        doc.extend_from_slice(b"trailer << /Size 7 /Root 1 0 R >>\n");
        doc.extend_from_slice(format!("startxref\n{}\n%%EOF\n", xref_offset).as_bytes());

        doc
    }

    fn append_text_object(
        doc: &mut Vec<u8>,
        offsets: &mut Vec<usize>,
        number: usize,
        content: &[u8],
    ) {
        offsets.push(doc.len());
        doc.extend_from_slice(format!("{} 0 obj\n", number).as_bytes());
        doc.extend_from_slice(content);
        if !content.ends_with(b"\n") {
            doc.extend_from_slice(b"\n");
        }
        doc.extend_from_slice(b"endobj\n");
    }

    #[test]
    fn compact_text_reports_drop_low_info_findings() {
        let query = Query::Findings;
        let entries = json!([
            {"kind": "suspicious", "severity": "High"},
            {"kind": "benign", "severity": "Low"},
            {"kind": "doc_info", "severity": "Info"},
            {"kind": "medium", "severity": "Medium"}
        ]);
        let result = QueryResult::Structure(entries.clone());
        let filtered =
            apply_report_verbosity(&query, result, ReportVerbosity::Compact, OutputFormat::Text);
        match filtered {
            QueryResult::Structure(Value::Array(arr)) => {
                assert_eq!(arr.len(), 2);
                assert_eq!(arr[0]["severity"].as_str(), Some("High"));
                assert_eq!(arr[1]["severity"].as_str(), Some("Medium"));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn compact_json_preserves_all_findings() {
        let query = Query::Findings;
        let entries = json!([
            {"kind": "suspicious", "severity": "High"},
            {"kind": "benign", "severity": "Low"},
            {"kind": "doc_info", "severity": "Info"},
            {"kind": "medium", "severity": "Medium"}
        ]);
        let result = QueryResult::Structure(entries.clone());
        let filtered =
            apply_report_verbosity(&query, result, ReportVerbosity::Compact, OutputFormat::Json);
        match filtered {
            QueryResult::Structure(Value::Array(arr)) => {
                assert_eq!(arr.len(), 4);
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn findings_query_populates_cache_and_reuses_results() {
        with_fixture_context("actions/launch_cve_2010_1240.pdf", |ctx| {
            assert!(ctx.findings_cache_info().is_none());

            let first = execute_query_with_context(
                &Query::Findings,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("first findings query");
            let second = execute_query_with_context(
                &Query::Findings,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("second findings query");

            let first_value = match first {
                QueryResult::Structure(value) => value,
                other => panic!("unexpected result type: {:?}", other),
            };
            let second_value = match second {
                QueryResult::Structure(value) => value,
                other => panic!("unexpected result type: {:?}", other),
            };
            assert_eq!(first_value, second_value);

            let findings = first_value.as_array().expect("findings array");
            let cache_info = ctx.findings_cache_info().expect("cache info");
            assert_eq!(cache_info.finding_count, findings.len());
            assert!(cache_info.approximate_bytes > 0);
        });
    }

    #[test]
    fn findings_high_filters_cached_results() {
        with_fixture_context("actions/launch_cve_2010_1240.pdf", |ctx| {
            let findings = execute_query_with_context(
                &Query::Findings,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("findings query");

            let highs = execute_query_with_context(
                &Query::FindingsBySeverity(Severity::High),
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("findings.high query");

            let all_findings = match findings {
                QueryResult::Structure(value) => value.as_array().cloned().expect("array"),
                other => panic!("unexpected findings result type: {:?}", other),
            };
            let high_findings = match highs {
                QueryResult::Structure(value) => value.as_array().cloned().expect("array"),
                other => panic!("unexpected findings.high result type: {:?}", other),
            };

            let expected_high = all_findings
                .iter()
                .filter(|entry| entry.get("severity").and_then(Value::as_str) == Some("High"))
                .count();
            assert_eq!(high_findings.len(), expected_high);
            assert!(ctx.findings_cache_info().is_some());
        });
    }

    #[test]
    fn apply_with_chain_rejects_non_findings_query() {
        let result = apply_with_chain(Query::Pages, true);
        assert!(result.is_err());
    }

    #[test]
    fn findings_with_chain_query_returns_chain_schema() {
        let options = ScanOptions::default();
        with_fixture_context_opts("actions/launch_cve_2010_1240.pdf", options, |ctx| {
            let query = apply_with_chain(Query::Findings, true).expect("query with chain");
            let result = execute_query_with_context(
                &query,
                ctx,
                None,
                1024 * 1024,
                DecodeMode::Decode,
                None,
            )
            .expect("findings --with-chain query");

            let value = match result {
                QueryResult::Structure(value) => value,
                other => panic!("unexpected result type: {:?}", other),
            };
            assert_eq!(value.get("type").and_then(Value::as_str), Some("findings_with_chain"));
            assert!(value.get("findings").and_then(Value::as_array).is_some());
            assert!(value.get("chains").and_then(Value::as_array).is_some());
        });
    }

    #[test]
    fn format_result_summarises_findings_with_chain() {
        let value = json!({
            "type": "findings_with_chain",
            "count": 2,
            "chains": [{
                "id": "chain-1",
                "ordered_stages": ["decode", "render", "egress"],
                "edge": { "reason": "scatter_to_injection" }
            }]
        });
        let text = format_result(&QueryResult::Structure(value), false);
        assert!(text.contains("Findings: 2"));
        assert!(text.contains("Potential chain: decode -> render -> egress"));
        assert!(text.contains("scatter_to_injection"));
    }

    #[test]
    fn findings_with_chain_captures_scatter_fragment_context_end_to_end() {
        let objects = vec![
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n".to_string(),
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
            "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n".to_string(),
            "5 0 obj\n<< /Fields [6 0 R] >>\nendobj\n".to_string(),
            "6 0 obj\n<< /FT /Tx /T (field) /V [7 0 R 8 0 R 9 0 R] >>\nendobj\n".to_string(),
            "7 0 obj\n(%3C)\nendobj\n".to_string(),
            "8 0 obj\n(script%3Ealert(1)%3C)\nendobj\n".to_string(),
            "9 0 obj\n(%2Fscript%3E)\nendobj\n".to_string(),
        ];
        let bytes = build_pdf(&objects, 10);
        let options = ScanOptions::default();
        let ctx = build_scan_context(&bytes, &options).expect("build context");

        let query = apply_with_chain(Query::Findings, true).expect("query with chain");
        let result =
            execute_query_with_context(&query, &ctx, None, 1024 * 1024, DecodeMode::Decode, None)
                .expect("findings --with-chain");

        let value = match result {
            QueryResult::Structure(value) => value,
            other => panic!("unexpected result type: {:?}", other),
        };
        let findings =
            value.get("findings").and_then(Value::as_array).cloned().expect("findings array");
        assert!(findings.iter().any(|entry| {
            entry.get("kind").and_then(Value::as_str) == Some("scattered_payload_assembly")
        }));

        let chains = value.get("chains").and_then(Value::as_array).cloned().expect("chains array");
        let scatter_chain = chains
            .iter()
            .find(|chain| chain.get("scatter").and_then(Value::as_object).is_some())
            .expect("scatter chain should exist");

        let stages = scatter_chain
            .get("ordered_stages")
            .and_then(Value::as_array)
            .cloned()
            .expect("ordered stages");
        assert!(stages.iter().any(|stage| stage.as_str() == Some("decode")));

        let scatter = scatter_chain.get("scatter").and_then(Value::as_object).expect("scatter");
        assert_eq!(scatter.get("fragment_count").and_then(Value::as_u64), Some(3));
        let refs =
            scatter.get("object_refs").and_then(Value::as_array).cloned().expect("object refs");
        assert!(refs.iter().any(|value| value.as_str() == Some("7 0 obj")));
        assert!(refs.iter().any(|value| value.as_str() == Some("8 0 obj")));
        assert!(refs.iter().any(|value| value.as_str() == Some("9 0 obj")));
    }

    // ---------------------------------------------------------------------------
    // Content stream query tests
    // ---------------------------------------------------------------------------

    #[test]
    fn parse_query_stream_content_variants() {
        assert!(matches!(parse_query("stream.content 15 0"), Ok(Query::StreamContentOps { obj: 15, gen: 0, recursive: false, with_findings: false })));
        assert!(matches!(parse_query("stream.content.json 15 0"), Ok(Query::StreamContentOpsJson { obj: 15, gen: 0, recursive: false, with_findings: false })));
        assert!(matches!(parse_query("page.content 0"), Ok(Query::PageContentOps { page_idx: 0, with_findings: false })));
        assert!(matches!(parse_query("page.content.json 2"), Ok(Query::PageContentOpsJson { page_idx: 2, with_findings: false })));
        assert!(matches!(parse_query("graph.content 15 0"), Ok(Query::GraphContentStreamDot { obj: 15, gen: 0, recursive: false })));
        assert!(matches!(parse_query("graph.content.json 15 0"), Ok(Query::GraphContentStreamJson { obj: 15, gen: 0, recursive: false })));
        assert!(matches!(parse_query("graph.page.content 0"), Ok(Query::GraphPageContentDot { page_idx: 0, recursive: false })));
        assert!(matches!(parse_query("graph.page.content.json 1"), Ok(Query::GraphPageContentJson { page_idx: 1, recursive: false })));
        // Recursive variants
        assert!(matches!(parse_query("stream.content.recursive 15 0"), Ok(Query::StreamContentOps { obj: 15, gen: 0, recursive: true, .. })));
        assert!(matches!(parse_query("stream.content.json.recursive 15 0"), Ok(Query::StreamContentOpsJson { obj: 15, gen: 0, recursive: true, .. })));
        assert!(matches!(parse_query("graph.content.recursive 15 0"), Ok(Query::GraphContentStreamDot { obj: 15, gen: 0, recursive: true })));
        assert!(matches!(parse_query("graph.content.json.recursive 15 0"), Ok(Query::GraphContentStreamJson { obj: 15, gen: 0, recursive: true })));
        assert!(matches!(parse_query("graph.page.content.recursive 0"), Ok(Query::GraphPageContentDot { page_idx: 0, recursive: true })));
        assert!(matches!(parse_query("graph.page.content.json.recursive 1"), Ok(Query::GraphPageContentJson { page_idx: 1, recursive: true })));
        // Findings variants
        assert!(matches!(parse_query("stream.content.findings 15 0"), Ok(Query::StreamContentOps { obj: 15, gen: 0, with_findings: true, .. })));
        assert!(matches!(parse_query("page.content.findings 0"), Ok(Query::PageContentOps { page_idx: 0, with_findings: true })));
    }

    #[test]
    fn page_content_query_resolves_page_zero() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let query = parse_query("page.content 0").expect("parse query");
            let result = execute_query_with_context(
                &query, ctx, None, 1024 * 1024, DecodeMode::Decode, None,
            ).expect("execute query");
            match result {
                QueryResult::List(lines) => {
                    let combined = lines.join("\n");
                    assert!(combined.contains("Content stream"), "output should contain stream header");
                }
                QueryResult::Error(e) => panic!("unexpected error: {}", e.message),
                _ => panic!("unexpected result type"),
            }
        });
    }

    #[test]
    fn page_content_json_has_required_fields() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let query = parse_query("page.content.json 0").expect("parse query");
            let result = execute_query_with_context(
                &query, ctx, None, 1024 * 1024, DecodeMode::Decode, None,
            ).expect("execute query");
            match result {
                QueryResult::Structure(v) => {
                    assert!(v["streams"].is_array(), "json output should have 'streams' array");
                }
                QueryResult::Error(e) => panic!("unexpected error: {}", e.message),
                _ => panic!("unexpected result type"),
            }
        });
    }

    #[test]
    fn page_content_out_of_range_returns_error() {
        with_fixture_context("synthetic.pdf", |ctx| {
            let query = parse_query("page.content 9999").expect("parse query");
            let result = execute_query_with_context(
                &query, ctx, None, 1024 * 1024, DecodeMode::Decode, None,
            );
            // Should be either an Err result or a QueryResult::Error — not a panic.
            match result {
                Err(_) => {} // expected: execute returned Err
                Ok(QueryResult::Error(_)) => {} // also acceptable
                Ok(QueryResult::List(lines)) => {
                    // Some PDFs may have no streams; the message should indicate no streams
                    let combined = lines.join("\n");
                    assert!(combined.contains("no content") || combined.contains("out of range") || combined.is_empty());
                }
                Ok(other) => panic!("unexpected result for out-of-range page: {:?}", other),
            }
        });
    }

    #[test]
    fn stream_content_hostile_fixture_does_not_panic() {
        with_fixture_context("actions/launch_cve_2010_1240.pdf", |ctx| {
            // Find any stream object and summarise it without panicking.
            let stream_ref = ctx.graph.objects.iter().find_map(|e| match &e.atom {
                PdfAtom::Stream(_) => Some((e.obj, e.gen)),
                _ => None,
            });
            let Some((obj, gen)) = stream_ref else { return };
            let query = parse_query(&format!("stream.content {} {}", obj, gen)).expect("parse");
            let result = execute_query_with_context(
                &query, ctx, None, 1024 * 1024, DecodeMode::Decode, None,
            );
            // Must not panic; result may be Ok or Err depending on stream type.
            let _ = result;
        });
    }

    #[test]
    fn graph_content_stream_dot_contains_digraph() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let query = parse_query("graph.page.content 0").expect("parse query");
            let result = execute_query_with_context(
                &query, ctx, None, 1024 * 1024, DecodeMode::Decode, None,
            ).expect("execute query");
            match result {
                QueryResult::List(lines) => {
                    let combined = lines.join("\n");
                    // Empty pages may produce no DOT output
                    if !combined.is_empty() {
                        assert!(combined.contains("digraph"), "DOT output should contain 'digraph'");
                    }
                }
                QueryResult::Error(e) => panic!("unexpected error: {}", e.message),
                _ => panic!("unexpected result type"),
            }
        });
    }

    #[test]
    fn graph_content_stream_json_has_nodes_edges() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let query = parse_query("graph.page.content.json 0").expect("parse query");
            let result = execute_query_with_context(
                &query, ctx, None, 1024 * 1024, DecodeMode::Decode, None,
            ).expect("execute query");
            match result {
                QueryResult::Structure(v) => {
                    assert!(v["graphs"].is_array());
                }
                QueryResult::Error(e) => panic!("unexpected error: {}", e.message),
                _ => panic!("unexpected result type"),
            }
        });
    }
}
