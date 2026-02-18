#![forbid(unsafe_code)]

mod commands;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use flate2::read::GzDecoder;
use globset::Glob;
use js_analysis::{DynamicOptions, DynamicOutcome};
use rayon::{prelude::*, ThreadPoolBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sis_pdf_core::filter_allowlist::{default_filter_allowlist_toml, load_filter_allowlist};
use sis_pdf_core::model::Severity as SecuritySeverity;
use sis_pdf_core::scan::CorrelationOptions;
use sis_pdf_core::security_log::{SecurityDomain, SecurityEvent};
use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use tar::Archive;
use tempfile::tempdir;
use toml_edit::{value, Array, DocumentMut, Item, Table, Value};
use tracing::{debug, error, info, warn, Level};
use ureq::Agent;
use walkdir::WalkDir;
use zip::ZipArchive;
const MAX_REPORT_BYTES: u64 = 50 * 1024 * 1024;
const WARN_PDF_BYTES: u64 = 50 * 1024 * 1024;
const MAX_PDF_BYTES: u64 = 500 * 1024 * 1024;
const MAX_BATCH_FILES: usize = 500_000;
const MAX_BATCH_BYTES: u64 = 50 * 1024 * 1024 * 1024;
const MAX_JSONL_BYTES: u64 = 100 * 1024 * 1024;
const MAX_JSONL_LINE_BYTES: usize = 10 * 1024;
const MAX_JSONL_ENTRIES: usize = 1_000_000;
const MAX_CAMPAIGN_INTENT_LEN: usize = 1024;
const MAX_WALK_DEPTH: usize = 10;
const BATCH_WORKER_STACK_SIZE: usize = 16 * 1024 * 1024;
const UPDATE_REPO_DEFAULT: &str = "michiel/sis-pdf";
const UPDATE_USER_AGENT: &str = "sis-update";
const ORT_VERSION_DEFAULT: &str = "1.23.2";
const ORT_USER_AGENT: &str = "sis-ort-download";
const ORT_RELEASE_BASE: &str = "https://github.com/microsoft/onnxruntime/releases/download";
#[derive(Parser)]
#[command(name = "sis", version = env!("CARGO_PKG_VERSION"), propagate_version = true)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Serialize)]
struct SandboxEvalReport {
    path: String,
    asset_type: String,
    status: String,
    timeout_ms: Option<u128>,
    timeout_context: Option<SandboxTimeoutContextReport>,
    skip_reason: Option<String>,
    skip_limit: Option<usize>,
    skip_actual: Option<usize>,
    signals: Option<SandboxSignalsReport>,
}

#[derive(Serialize)]
struct SandboxTimeoutContextReport {
    runtime_profile: String,
    phase: Option<String>,
    elapsed_ms: Option<u128>,
    budget_ratio: Option<f64>,
}

#[derive(Serialize)]
struct SandboxSignalsReport {
    replay_id: String,
    runtime_profile: String,
    errors: Vec<String>,
    calls: Vec<String>,
    call_args: Vec<String>,
    urls: Vec<String>,
    domains: Vec<String>,
    prop_reads: Vec<String>,
    prop_writes: Vec<String>,
    prop_deletes: Vec<String>,
    reflection_probes: Vec<String>,
    dynamic_code_calls: Vec<String>,
    call_count: usize,
    unique_calls: usize,
    unique_prop_reads: usize,
    elapsed_ms: Option<u128>,
    truncation: SandboxTruncationSummaryReport,
    phases: Vec<SandboxPhaseSummaryReport>,
    delta_summary: Option<SandboxDeltaSummaryReport>,
    execution_stats: SandboxExecutionStats,
    behavioral_patterns: Vec<SandboxBehaviorPattern>,
}

#[derive(Serialize)]
struct SandboxTruncationSummaryReport {
    calls_dropped: usize,
    call_args_dropped: usize,
    prop_reads_dropped: usize,
    errors_dropped: usize,
    urls_dropped: usize,
    domains_dropped: usize,
}

#[derive(Serialize)]
struct SandboxPhaseSummaryReport {
    phase: String,
    call_count: usize,
    prop_read_count: usize,
    error_count: usize,
    elapsed_ms: u128,
}

#[derive(Serialize)]
struct SandboxDeltaSummaryReport {
    phase: String,
    trigger_calls: Vec<String>,
    generated_snippets: usize,
    added_identifier_count: usize,
    added_string_literal_count: usize,
    added_call_count: usize,
    new_identifiers: Vec<String>,
    new_string_literals: Vec<String>,
    new_calls: Vec<String>,
}

#[derive(Serialize)]
struct SandboxExecutionStats {
    total_function_calls: usize,
    unique_function_calls: usize,
    variable_promotions: usize,
    error_recoveries: usize,
    successful_recoveries: usize,
    execution_depth: usize,
    loop_iteration_limit_hits: usize,
    adaptive_loop_iteration_limit: usize,
    adaptive_loop_profile: String,
    downloader_scheduler_hardening: bool,
    probe_loop_short_circuit_hits: usize,
}

#[derive(Serialize)]
struct SandboxBehaviorPattern {
    name: String,
    confidence: f64,
    evidence: String,
    severity: String,
    metadata: std::collections::BTreeMap<String, String>,
}
#[derive(Subcommand)]
enum Command {
    #[command(subcommand, about = "Manage sis configuration")]
    Config(ConfigCommand),
    #[command(subcommand, about = "Manage ML runtime configuration and ONNX Runtime")]
    Ml(MlCommand),
    #[command(about = "Update sis from the latest GitHub release")]
    Update {
        #[arg(long, help = "Include prerelease builds when checking for updates")]
        include_prerelease: bool,
    },
    #[command(about = "Query PDF structure, content, and findings")]
    Query {
        #[arg(help = "PDF file path (required unless --path is used)")]
        pdf: Option<String>,
        #[arg(
            help = "Query string (e.g., 'pages', 'js', 'findings.high'). Omit for interactive REPL."
        )]
        query: Option<String>,
        #[arg(long, help = "Output as JSON")]
        json: bool,
        #[arg(
            long,
            default_value = "text",
            value_parser = ["text", "json", "jsonl", "yaml", "yml", "csv", "dot"],
            help = "Output format (text, json, jsonl, yaml, csv, dot). Example: --format jsonl"
        )]
        format: String,
        #[arg(long = "colour", alias = "color", help = "Enable colourised JSON/YAML output")]
        colour: bool,
        #[arg(long, short = 'c', help = "Compact output (numbers only)")]
        compact: bool,
        #[arg(
            long,
            value_enum,
            default_value_t = commands::query::ReportVerbosity::Standard,
            help = "Report verbosity (compact, standard, verbose)"
        )]
        report_verbosity: commands::query::ReportVerbosity,
        #[arg(
            long,
            value_enum,
            default_value_t = commands::query::ChainSummaryLevel::Events,
            help = "Chain summary level (minimal, events, full)"
        )]
        chain_summary: commands::query::ChainSummaryLevel,
        #[arg(long, help = "Filter results with a predicate expression")]
        r#where: Option<String>,
        #[arg(long, help = "Deep scan mode")]
        deep: bool,
        #[arg(long, default_value_t = 32 * 1024 * 1024)]
        max_decode_bytes: usize,
        #[arg(long, default_value_t = 256 * 1024 * 1024)]
        max_total_decoded_bytes: usize,
        #[arg(long)]
        no_recover: bool,
        #[arg(long, default_value_t = 500_000)]
        max_objects: usize,
        #[arg(long, help = "Extract JavaScript and embedded files to directory")]
        extract_to: Option<PathBuf>,
        #[arg(long, help = "Scan directory instead of single file")]
        path: Option<PathBuf>,
        #[arg(long, default_value = "*.pdf", help = "Glob pattern for batch mode")]
        glob: String,
        #[arg(
            long,
            help = "Maximum bytes to extract per file",
            default_value_t = 128 * 1024 * 1024
        )]
        max_extract_bytes: usize,
        #[arg(long, help = "Extract raw stream bytes without decoding filters")]
        raw: bool,
        #[arg(long, help = "Decode stream filters (default)")]
        decode: bool,
        #[arg(long, help = "Write hex + ASCII dump output for extracted streams")]
        hexdump: bool,
        #[arg(long, help = "Disable chain grouping in chain output")]
        ungroup_chains: bool,
    },
    #[command(about = "Scan PDFs for suspicious indicators and report findings")]
    Scan {
        #[arg(value_name = "PDF", required_unless_present = "path")]
        pdf: Option<String>,
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long, default_value = "*.pdf")]
        glob: String,
        #[arg(long)]
        deep: bool,
        #[arg(long, default_value_t = 32 * 1024 * 1024)]
        max_decode_bytes: usize,
        #[arg(long, default_value_t = 256 * 1024 * 1024)]
        max_total_decoded_bytes: usize,
        #[arg(long)]
        no_recover: bool,
        #[arg(long, help = "Disable chain grouping in scan output")]
        ungroup_chains: bool,
        #[arg(long)]
        json: bool,
        #[arg(long, help = "Reduce output to high-priority and runtime-gap triage findings")]
        focused_triage: bool,
        #[arg(long)]
        jsonl: bool,
        #[arg(long, help = "Emit JSONL findings with input path per entry")]
        jsonl_findings: bool,
        #[arg(long)]
        sarif: bool,
        #[arg(long)]
        sarif_out: Option<PathBuf>,
        #[arg(long)]
        export_intents: bool,
        #[arg(long)]
        export_intents_out: Option<PathBuf>,
        #[arg(long, help = "Include derived intent entries (domains and obfuscated URLs)")]
        intents_derived: bool,
        #[arg(long)]
        yara: bool,
        #[arg(long)]
        yara_out: Option<PathBuf>,
        #[arg(long, default_value = "high")]
        yara_scope: String,
        #[arg(long)]
        diff_parser: bool,
        #[arg(long)]
        fast: bool,
        #[arg(long)]
        focus_trigger: Option<String>,
        #[arg(long, default_value_t = 5)]
        focus_depth: usize,
        #[arg(long)]
        strict: bool,
        #[arg(
            long,
            help = "Summarise strict parser deviations instead of emitting each deviation"
        )]
        strict_summary: bool,
        #[arg(long)]
        ir: bool,
        #[arg(long, default_value_t = 500_000)]
        max_objects: usize,
        #[arg(long, default_value_t = 64)]
        max_recursion_depth: usize,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long, help = "Path to filter allowlist TOML file")]
        filter_allowlist: Option<PathBuf>,
        #[arg(long, help = "Treat all filter chains as unusual")]
        filter_allowlist_strict: bool,
        #[arg(long, help = "Print default filter allowlist and exit")]
        show_filter_allowlist: bool,
        #[arg(long)]
        cache_dir: Option<PathBuf>,
        #[arg(long, alias = "seq")]
        sequential: bool,
        #[arg(long, help = "Enable runtime profiling to measure detector performance")]
        runtime_profile: bool,
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        runtime_profile_format: String,
        #[arg(long)]
        ml: bool,
        #[arg(long)]
        ml_model_dir: Option<PathBuf>,
        #[arg(long, default_value_t = 0.9)]
        ml_threshold: f32,
        #[arg(long, default_value = "traditional", value_parser = ["traditional", "graph"])]
        ml_mode: String,
        #[arg(long, help = "Use extended 333-feature vector for ML (default with --ml)")]
        ml_extended_features: bool,
        #[arg(long, help = "Generate comprehensive ML explanation")]
        ml_explain: bool,
        #[arg(
            long,
            help = "Include advanced ML explainability (counterfactuals and interactions)"
        )]
        ml_advanced: bool,
        #[arg(long, help = "Compute ML temporal analysis across incremental updates")]
        ml_temporal: bool,
        #[arg(long, help = "Compute non-ML temporal signals across incremental updates")]
        temporal_signals: bool,
        #[arg(long, help = "Path to benign baseline JSON for explanations")]
        ml_baseline: Option<PathBuf>,
        #[arg(long, help = "Path to calibration model JSON")]
        ml_calibration: Option<PathBuf>,
        #[arg(
            long,
            help = "Preferred ML execution provider (auto, cpu, cuda, rocm, migraphx, directml, coreml, onednn, openvino)"
        )]
        ml_provider: Option<String>,
        #[arg(long, help = "Comma-separated ML execution provider order override")]
        ml_provider_order: Option<String>,
        #[arg(long, help = "Print selected ML execution provider to STDERR")]
        ml_provider_info: bool,
        #[arg(long, help = "Path to ONNX Runtime dynamic library")]
        ml_ort_dylib: Option<PathBuf>,
        #[arg(long, help = "Prefer quantised ML models when available")]
        ml_quantized: bool,
        #[arg(long, help = "Override embedding batch size")]
        ml_batch_size: Option<usize>,
        #[arg(long)]
        no_js_ast: bool,
        #[arg(long)]
        no_js_sandbox: bool,
        #[arg(long, help = "Disable image analysis (static and dynamic)")]
        no_image_analysis: bool,
        #[arg(long, help = "Disable dynamic image decoding (deep scan)")]
        no_image_dynamic: bool,
        #[arg(long, help = "Disable font CVE signature matching (enabled by default)")]
        no_font_signatures: bool,
        #[arg(long, help = "Custom directory containing font CVE signature YAML files")]
        font_signature_dir: Option<PathBuf>,
    },
    #[command(about = "Sanitise PDF active content (CDR strip-and-report, phase 1)")]
    Sanitize {
        #[arg(value_name = "PDF")]
        pdf: String,
        #[arg(short, long, help = "Output path for the sanitised PDF")]
        out: PathBuf,
        #[arg(long, help = "Optional JSON report output path")]
        report_json: Option<PathBuf>,
        #[arg(long, help = "Enable phase-2 safe rebuild validation and integrity checks")]
        safe_rebuild: bool,
    },
    #[command(subcommand, about = "Run sandbox evaluation for dynamic assets")]
    Sandbox(SandboxCommand),
    #[command(about = "Generate a full Markdown report for a PDF scan")]
    Report {
        pdf: String,
        #[arg(long)]
        deep: bool,
        #[arg(long, default_value_t = 32 * 1024 * 1024)]
        max_decode_bytes: usize,
        #[arg(long, default_value_t = 256 * 1024 * 1024)]
        max_total_decoded_bytes: usize,
        #[arg(long)]
        no_recover: bool,
        #[arg(long, help = "Disable chain grouping in report output")]
        ungroup_chains: bool,
        #[arg(long)]
        diff_parser: bool,
        #[arg(long, default_value_t = 500_000)]
        max_objects: usize,
        #[arg(long, default_value_t = 64)]
        max_recursion_depth: usize,
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        ir: bool,
        #[arg(
            long,
            value_enum,
            default_value_t = commands::query::ChainSummaryLevel::Events,
            help = "Chain summary level for report output (minimal, events, full)"
        )]
        report_chain_summary: commands::query::ChainSummaryLevel,
        #[arg(
            long,
            value_enum,
            default_value_t = commands::query::ReportVerbosity::Standard,
            help = "Report verbosity for Markdown output (compact, standard, verbose)"
        )]
        report_verbosity: commands::query::ReportVerbosity,
        #[arg(long, help = "Disable image analysis (static and dynamic)")]
        no_image_analysis: bool,
        #[arg(long, help = "Disable dynamic image decoding (deep scan)")]
        no_image_dynamic: bool,
        #[arg(short, long)]
        out: Option<PathBuf>,
        #[arg(long)]
        ml: bool,
        #[arg(long)]
        ml_model_dir: Option<PathBuf>,
        #[arg(long, default_value_t = 0.9)]
        ml_threshold: f32,
        #[arg(long, default_value = "traditional", value_parser = ["traditional", "graph"])]
        ml_mode: String,
        #[arg(long, help = "Use extended 333-feature vector for ML (default with --ml)")]
        ml_extended_features: bool,
        #[arg(long, help = "Generate comprehensive ML explanation")]
        ml_explain: bool,
        #[arg(
            long,
            help = "Include advanced ML explainability (counterfactuals and interactions)"
        )]
        ml_advanced: bool,
        #[arg(long, help = "Compute ML temporal analysis across incremental updates")]
        ml_temporal: bool,
        #[arg(long, help = "Compute non-ML temporal signals across incremental updates")]
        temporal_signals: bool,
        #[arg(long, help = "Path to benign baseline JSON for explanations")]
        ml_baseline: Option<PathBuf>,
        #[arg(long, help = "Path to calibration model JSON")]
        ml_calibration: Option<PathBuf>,
        #[arg(
            long,
            help = "Preferred ML execution provider (auto, cpu, cuda, rocm, migraphx, directml, coreml, onednn, openvino)"
        )]
        ml_provider: Option<String>,
        #[arg(long, help = "Comma-separated ML execution provider order override")]
        ml_provider_order: Option<String>,
        #[arg(long, help = "Print selected ML execution provider to STDERR")]
        ml_provider_info: bool,
        #[arg(long, help = "Path to ONNX Runtime dynamic library")]
        ml_ort_dylib: Option<PathBuf>,
        #[arg(long, help = "Prefer quantised ML models when available")]
        ml_quantized: bool,
        #[arg(long, help = "Override embedding batch size")]
        ml_batch_size: Option<usize>,
        #[arg(long)]
        no_js_ast: bool,
        #[arg(long)]
        no_js_sandbox: bool,
    },
    #[command(about = "Explain a specific finding with evidence details")]
    Explain {
        pdf: String,
        finding_id: String,
        #[arg(long, help = "Custom scan config to match the original scan")]
        config: Option<PathBuf>,
    },
    #[command(subcommand, about = "Streaming analysis of PDF content")]
    Stream(StreamCommand),
    #[command(subcommand, about = "Correlate findings across multiple PDFs")]
    Correlate(CorrelateCommand),
    #[command(subcommand, about = "Generate test fixtures and response rules")]
    Generate(GenerateCommand),
    #[command(subcommand, about = "Print bundled documentation")]
    Doc(DocCommand),
    #[command(about = "Print sis version")]
    Version,
}

const AGENT_QUERY_GUIDE: &str = include_str!("../../../docs/agent-query-guide.md");

#[derive(Subcommand)]
enum SandboxCommand {
    #[command(about = "Evaluate a dynamic asset in the sandbox")]
    Eval {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long = "type", default_value = "js", value_parser = ["js"])]
        asset_type: String,
        #[arg(long)]
        max_bytes: Option<usize>,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    #[command(about = "Create a default configuration file")]
    Init {
        #[arg(long, help = "Override config path")]
        path: Option<PathBuf>,
    },
    #[command(about = "Validate configuration file")]
    Verify {
        #[arg(long, help = "Override config path")]
        path: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum DocCommand {
    #[command(about = "Print the agent query guide")]
    AgentQuery,
}

#[derive(Subcommand)]
enum MlCommand {
    #[command(about = "Validate ML runtime setup and execution providers")]
    Health {
        #[arg(long)]
        ml_model_dir: Option<PathBuf>,
        #[arg(
            long,
            help = "Preferred ML execution provider (auto, cpu, cuda, rocm, migraphx, directml, coreml, onednn, openvino)"
        )]
        ml_provider: Option<String>,
        #[arg(long, help = "Comma-separated ML execution provider order override")]
        ml_provider_order: Option<String>,
        #[arg(long, help = "Print selected ML execution provider to STDERR")]
        ml_provider_info: bool,
        #[arg(long, help = "Path to ONNX Runtime dynamic library")]
        ml_ort_dylib: Option<PathBuf>,
        #[arg(long, help = "Prefer quantised ML models when available")]
        ml_quantized: bool,
        #[arg(long, help = "Override embedding batch size")]
        ml_batch_size: Option<usize>,
    },
    #[command(subcommand)]
    Ort(MlOrtCommand),
    #[command(about = "Detect ML runtime capabilities and provider recommendations")]
    Detect {
        #[arg(long, value_parser = ["text", "json"], default_value = "text")]
        format: String,
        #[arg(long, help = "Override config path")]
        config: Option<PathBuf>,
        #[arg(
            long,
            help = "Preferred ML execution provider (auto, cpu, cuda, rocm, migraphx, directml, coreml, onednn, openvino)"
        )]
        ml_provider: Option<String>,
        #[arg(long, help = "Comma-separated ML execution provider order override")]
        ml_provider_order: Option<String>,
        #[arg(long, help = "Path to ONNX Runtime dynamic library")]
        ml_ort_dylib: Option<PathBuf>,
    },
    #[command(about = "Auto-configure ML runtime settings from detection output")]
    Autoconfig {
        #[arg(long)]
        dry_run: bool,
        #[arg(long, help = "Override config path")]
        config: Option<PathBuf>,
        #[arg(
            long,
            help = "Preferred ML execution provider (auto, cpu, cuda, rocm, migraphx, directml, coreml, onednn, openvino)"
        )]
        ml_provider: Option<String>,
        #[arg(long, help = "Comma-separated ML execution provider order override")]
        ml_provider_order: Option<String>,
        #[arg(long, help = "Path to ONNX Runtime dynamic library")]
        ml_ort_dylib: Option<PathBuf>,
    },
    #[command(about = "Compute benign baseline from feature vectors")]
    ComputeBaseline {
        #[arg(long, help = "Path to JSONL file with benign feature vectors")]
        input: PathBuf,
        #[arg(short, long, help = "Output baseline JSON file")]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum MlOrtCommand {
    #[command(about = "Download the correct ONNX Runtime library for this host")]
    Download {
        #[arg(long)]
        write_config: bool,
        #[arg(long, help = "Override config path")]
        config: Option<PathBuf>,
        #[arg(
            long,
            help = "Preferred ML execution provider (auto, cpu, cuda, rocm, migraphx, directml, coreml, onednn, openvino)"
        )]
        ml_provider: Option<String>,
        #[arg(long, help = "Comma-separated ML execution provider order override")]
        ml_provider_order: Option<String>,
        #[arg(long, help = "Path to ONNX Runtime dynamic library")]
        ml_ort_dylib: Option<PathBuf>,
        #[arg(long, help = "Override ONNX Runtime version (default via SIS_ORT_VERSION)")]
        ort_version: Option<String>,
        #[arg(long, help = "Checksum URL override for the ORT archive")]
        checksum_url: Option<String>,
        #[arg(long, help = "Checksum file path override for the ORT archive")]
        checksum_file: Option<PathBuf>,
        #[arg(long, help = "Checksum SHA256 override for the ORT archive")]
        checksum_sha256: Option<String>,
    },
}

#[derive(Subcommand)]
enum StreamCommand {
    #[command(about = "Analyze a PDF stream in chunks and stop on indicators", alias = "analyze")]
    Analyse {
        pdf: String,
        #[arg(long, default_value_t = 64 * 1024)]
        chunk_size: usize,
        #[arg(long, default_value_t = 256 * 1024)]
        max_buffer: usize,
    },
}

#[derive(Subcommand)]
enum CorrelateCommand {
    #[command(about = "Correlate network intents across PDFs from JSONL input")]
    Campaign {
        #[arg(long)]
        input: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum GenerateCommand {
    #[command(about = "Generate response YARA rules for a threat kind or report")]
    Response {
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        from_report: Option<PathBuf>,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    #[command(about = "Generate mutated PDFs for detection testing")]
    Mutate {
        pdf: String,
        #[arg(short, long)]
        out: PathBuf,
        #[arg(long)]
        scan: bool,
    },
    #[command(about = "Generate red-team evasive PDF fixtures")]
    RedTeam {
        #[arg(long)]
        target: String,
        #[arg(short, long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();
    let config_path = resolve_config_path_from_args(&args);
    let log_level = config_path
        .as_deref()
        .and_then(|path| sis_pdf_core::config::Config::load(path).ok())
        .and_then(|cfg| cfg.logging.and_then(|l| l.level));
    init_tracing(log_level.as_deref());
    match args.command {
        Command::Config(cmd) => match cmd {
            ConfigCommand::Init { path } => run_config_init(path.as_deref()),
            ConfigCommand::Verify { path } => run_config_verify(path.as_deref()),
        },
        Command::Ml(cmd) => match cmd {
            MlCommand::Health {
                ml_model_dir,
                ml_provider,
                ml_provider_order,
                ml_provider_info,
                ml_ort_dylib,
                ml_quantized,
                ml_batch_size,
            } => run_ml_health(
                ml_model_dir.as_deref(),
                ml_provider.as_deref(),
                ml_provider_order.as_deref(),
                ml_provider_info,
                ml_ort_dylib.as_deref(),
                ml_quantized,
                ml_batch_size,
            ),
            MlCommand::Ort(MlOrtCommand::Download {
                write_config,
                config,
                ml_provider,
                ml_provider_order,
                ml_ort_dylib,
                ort_version,
                checksum_url,
                checksum_file,
                checksum_sha256,
            }) => run_ml_ort_download(
                config.as_deref(),
                ml_provider.as_deref(),
                ml_provider_order.as_deref(),
                ml_ort_dylib.as_deref(),
                write_config,
                ort_version.as_deref(),
                checksum_url.as_deref(),
                checksum_file.as_deref(),
                checksum_sha256.as_deref(),
            ),
            MlCommand::Detect { format, config, ml_provider, ml_provider_order, ml_ort_dylib } => {
                run_ml_detect(
                    &format,
                    config.as_deref(),
                    ml_provider.as_deref(),
                    ml_provider_order.as_deref(),
                    ml_ort_dylib.as_deref(),
                )
            }
            MlCommand::Autoconfig {
                dry_run,
                config,
                ml_provider,
                ml_provider_order,
                ml_ort_dylib,
            } => run_ml_autoconfig(
                config.as_deref(),
                ml_provider.as_deref(),
                ml_provider_order.as_deref(),
                ml_ort_dylib.as_deref(),
                dry_run,
            ),
            MlCommand::ComputeBaseline { input, out } => run_compute_baseline(&input, &out),
        },
        Command::Update { include_prerelease } => run_update(include_prerelease),
        Command::Query {
            query,
            pdf,
            json,
            format,
            colour,
            compact,
            report_verbosity,
            chain_summary,
            r#where,
            deep,
            max_decode_bytes,
            max_total_decoded_bytes,
            no_recover,
            max_objects,
            extract_to,
            path,
            glob,
            max_extract_bytes,
            raw,
            decode,
            hexdump,
            ungroup_chains,
        } => {
            let where_clause_raw = r#where.clone();
            let config_query_colour = config_path
                .as_deref()
                .and_then(|path| sis_pdf_core::config::Config::load(path).ok())
                .and_then(|cfg| cfg.query.and_then(|query| query.colour))
                .unwrap_or(false);
            let colour = colour || config_query_colour;
            let mut output_format = commands::query::OutputFormat::parse(&format)?;
            if json {
                if output_format != commands::query::OutputFormat::Text
                    && output_format != commands::query::OutputFormat::Json
                {
                    return Err(anyhow!(
                        "--json is shorthand for --format json; remove --json or set --format json"
                    ));
                }
                if output_format == commands::query::OutputFormat::Text {
                    output_format = commands::query::OutputFormat::Json;
                }
            }
            let predicate = match r#where {
                Some(where_clause) => Some(commands::query::parse_predicate(&where_clause)?),
                None => None,
            };
            let decode_flags = [raw, decode, hexdump];
            let decode_count = decode_flags.iter().filter(|flag| **flag).count();
            if decode_count > 1 {
                return Err(anyhow!("Use only one of --raw, --decode, or --hexdump"));
            }
            let decode_mode = if raw {
                commands::query::DecodeMode::Raw
            } else if hexdump {
                commands::query::DecodeMode::Hexdump
            } else {
                commands::query::DecodeMode::Decode
            };

            // Validate that either path or pdf is provided, but not both
            // Note: When using --path, the query string might be parsed as the PDF argument
            // due to positional argument ordering. We need to handle this case.
            let (actual_pdf, actual_query) = if path.is_some() {
                // In batch mode, if both pdf and query are provided, the "pdf" is actually the query
                match (&pdf, &query) {
                    (Some(q), None) => (None, Some(q.clone())),
                    (Some(_), Some(_)) => {
                        return Err(anyhow!(
                            "When using --path, provide only the query string as a positional argument"
                        ));
                    }
                    (None, Some(q)) => (None, Some(q.clone())),
                    (None, None) => (None, None),
                }
            } else {
                // Single file mode
                if pdf.is_none() {
                    return Err(anyhow!("must specify either PDF file argument or --path"));
                }
                (pdf.clone(), query.clone())
            };

            let format_flag_present = std::env::args_os().any(|arg| {
                if let Some(arg) = arg.to_str() {
                    arg == "--format" || arg.starts_with("--format=")
                } else {
                    false
                }
            });

            if let Some(query_str) = actual_query {
                // One-shot query mode
                run_query_oneshot(
                    &query_str,
                    actual_pdf.as_deref(),
                    output_format,
                    compact,
                    colour,
                    deep,
                    max_decode_bytes,
                    max_total_decoded_bytes,
                    !no_recover,
                    max_objects,
                    !ungroup_chains,
                    extract_to.as_deref(),
                    path.as_deref(),
                    &glob,
                    max_extract_bytes,
                    decode_mode,
                    predicate.as_ref(),
                    report_verbosity,
                    chain_summary,
                    config_path.clone(),
                )
            } else {
                // Interactive REPL mode requires a single PDF file
                if path.is_some() {
                    return Err(anyhow!("REPL mode requires a single PDF file, not --path"));
                }
                if matches!(
                    output_format,
                    commands::query::OutputFormat::Csv | commands::query::OutputFormat::Dot
                ) {
                    return Err(anyhow!(
                        "REPL mode supports text, json, jsonl, or yaml output formats only"
                    ));
                }
                let repl_output_format = if !format_flag_present && !json {
                    commands::query::OutputFormat::Readable
                } else {
                    output_format
                };
                run_query_repl(
                    actual_pdf.as_deref().ok_or_else(|| anyhow!("no PDF path available"))?,
                    deep,
                    max_decode_bytes,
                    max_total_decoded_bytes,
                    !no_recover,
                    max_objects,
                    !ungroup_chains,
                    extract_to.as_deref(),
                    max_extract_bytes,
                    repl_output_format,
                    colour,
                    decode_mode,
                    predicate.as_ref(),
                    where_clause_raw.as_deref(),
                    report_verbosity,
                    chain_summary,
                    config_path.clone(),
                )
            }
        }
        Command::Scan {
            pdf,
            path,
            glob,
            deep,
            max_decode_bytes,
            max_total_decoded_bytes,
            no_recover,
            ungroup_chains,
            json,
            focused_triage,
            jsonl,
            jsonl_findings,
            sarif,
            sarif_out,
            export_intents,
            export_intents_out,
            intents_derived,
            yara,
            yara_out,
            yara_scope,
            diff_parser,
            fast,
            focus_trigger,
            focus_depth,
            strict,
            strict_summary,
            ir,
            max_objects,
            max_recursion_depth,
            config: _,
            profile,
            filter_allowlist,
            filter_allowlist_strict,
            show_filter_allowlist,
            cache_dir,
            sequential,
            runtime_profile,
            runtime_profile_format,
            ml,
            ml_model_dir,
            ml_threshold,
            ml_mode,
            ml_extended_features,
            ml_explain,
            ml_advanced,
            ml_temporal,
            temporal_signals,
            ml_baseline,
            ml_calibration,
            ml_provider,
            ml_provider_order,
            ml_provider_info,
            ml_ort_dylib,
            ml_quantized,
            ml_batch_size,
            no_js_ast,
            no_js_sandbox,
            no_image_analysis,
            no_image_dynamic,
            no_font_signatures,
            font_signature_dir,
        } => {
            if show_filter_allowlist {
                print_filter_allowlist()?;
                return Ok(());
            }
            run_scan(
                pdf.as_deref(),
                path.as_deref(),
                &glob,
                deep,
                max_decode_bytes,
                max_total_decoded_bytes,
                !no_recover,
                !ungroup_chains,
                json,
                focused_triage,
                jsonl,
                jsonl_findings,
                sarif,
                sarif_out.as_deref(),
                export_intents,
                export_intents_out.as_deref(),
                intents_derived,
                yara,
                yara_out.as_deref(),
                &yara_scope,
                diff_parser,
                fast,
                focus_trigger,
                focus_depth,
                strict,
                strict_summary,
                ir,
                max_objects,
                max_recursion_depth,
                config_path.as_deref(),
                profile.as_deref(),
                filter_allowlist.as_deref(),
                filter_allowlist_strict,
                cache_dir.as_deref(),
                sequential,
                runtime_profile,
                &runtime_profile_format,
                ml,
                ml_model_dir.as_deref(),
                ml_threshold,
                &ml_mode,
                ml_extended_features,
                ml_explain,
                ml_advanced,
                ml_temporal,
                temporal_signals,
                ml_baseline.as_deref(),
                ml_calibration.as_deref(),
                ml_provider.as_deref(),
                ml_provider_order.as_deref(),
                ml_provider_info,
                ml_ort_dylib.as_deref(),
                ml_quantized,
                ml_batch_size,
                !no_js_ast,
                !no_js_sandbox,
                !no_image_analysis,
                !no_image_dynamic,
                !no_font_signatures,
                font_signature_dir.as_deref(),
            )
        }
        Command::Sanitize { pdf, out, report_json, safe_rebuild } => {
            run_sanitize(&pdf, &out, report_json.as_deref(), safe_rebuild)
        }
        Command::Sandbox(cmd) => match cmd {
            SandboxCommand::Eval { file, asset_type, max_bytes } => {
                run_sandbox_eval(&file, &asset_type, max_bytes)
            }
        },
        Command::Report {
            pdf,
            deep,
            max_decode_bytes,
            max_total_decoded_bytes,
            no_recover,
            ungroup_chains,
            diff_parser,
            max_objects,
            max_recursion_depth,
            strict,
            ir,
            out,
            ml,
            ml_model_dir,
            ml_threshold,
            ml_mode,
            ml_extended_features,
            ml_explain,
            ml_advanced,
            ml_temporal,
            temporal_signals,
            ml_baseline,
            ml_calibration,
            ml_provider,
            ml_provider_order,
            ml_provider_info,
            ml_ort_dylib,
            ml_quantized,
            ml_batch_size,
            no_js_ast,
            no_js_sandbox,
            no_image_analysis,
            no_image_dynamic,
            report_chain_summary,
            report_verbosity,
        } => run_report(
            &pdf,
            deep,
            max_decode_bytes,
            max_total_decoded_bytes,
            !no_recover,
            !ungroup_chains,
            diff_parser,
            max_objects,
            max_recursion_depth,
            strict,
            ir,
            out.as_deref(),
            ml,
            ml_model_dir.as_deref(),
            ml_threshold,
            &ml_mode,
            ml_extended_features,
            ml_explain,
            ml_advanced,
            ml_temporal,
            temporal_signals,
            ml_baseline.as_deref(),
            ml_calibration.as_deref(),
            ml_provider.as_deref(),
            ml_provider_order.as_deref(),
            ml_provider_info,
            ml_ort_dylib.as_deref(),
            ml_quantized,
            ml_batch_size,
            !no_js_ast,
            !no_js_sandbox,
            !no_image_analysis,
            !no_image_dynamic,
            report_chain_summary,
            report_verbosity,
        ),
        Command::Explain { pdf, finding_id, .. } => {
            run_explain(&pdf, &finding_id, config_path.as_deref())
        }
        Command::Stream(cmd) => match cmd {
            StreamCommand::Analyse { pdf, chunk_size, max_buffer } => {
                run_stream_analyze(&pdf, chunk_size, max_buffer)
            }
        },
        Command::Correlate(cmd) => match cmd {
            CorrelateCommand::Campaign { input, out } => {
                run_campaign_correlate(&input, out.as_deref())
            }
        },
        Command::Generate(cmd) => match cmd {
            GenerateCommand::Response { kind, from_report, out } => {
                run_response_generate(kind.as_deref(), from_report.as_deref(), out.as_deref())
            }
            GenerateCommand::Mutate { pdf, out, scan } => run_mutate(&pdf, &out, scan),
            GenerateCommand::RedTeam { target, out } => run_redteam(&target, &out),
        },
        Command::Doc(cmd) => match cmd {
            DocCommand::AgentQuery => {
                println!("{}", AGENT_QUERY_GUIDE);
                Ok(())
            }
        },
        Command::Version => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

fn init_tracing(level: Option<&str>) {
    let default_level = level.unwrap_or("warn");
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false);
    let _ = subscriber.try_init();
}

fn resolve_config_path_from_args(args: &Args) -> Option<PathBuf> {
    match &args.command {
        Command::Scan { config, .. } => resolve_config_path(config.as_deref()),
        Command::Explain { config, .. } => resolve_config_path(config.as_deref()),
        Command::Ml(cmd) => match cmd {
            MlCommand::Detect { config, .. } => resolve_config_path(config.as_deref()),
            MlCommand::Autoconfig { config, .. } => resolve_config_path(config.as_deref()),
            MlCommand::Ort(MlOrtCommand::Download { config, .. }) => {
                resolve_config_path(config.as_deref())
            }
            _ => resolve_config_path(None),
        },
        _ => resolve_config_path(None),
    }
}

fn resolve_config_path(config: Option<&std::path::Path>) -> Option<PathBuf> {
    if let Some(path) = config {
        return Some(path.to_path_buf());
    }
    let default_path = default_config_path()?;
    if default_path.exists() {
        Some(default_path)
    } else {
        None
    }
}

fn default_config_path() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        return dirs::home_dir().map(|dir| dir.join(".config").join("sis").join("config.toml"));
    }
    dirs::config_dir().map(|dir| dir.join("sis").join("config.toml"))
}

fn run_config_init(path: Option<&std::path::Path>) -> Result<()> {
    let path = path
        .map(|p| p.to_path_buf())
        .or_else(default_config_path)
        .ok_or_else(|| anyhow!("config path not available on this platform"))?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    if path.exists() {
        return Err(anyhow!("config already exists at {}", path.display()));
    }
    fs::write(&path, default_config_template())?;
    println!("Created config at {}", path.display());
    Ok(())
}

fn run_config_verify(path: Option<&std::path::Path>) -> Result<()> {
    let path = path
        .map(|p| p.to_path_buf())
        .or_else(default_config_path)
        .ok_or_else(|| anyhow!("config path not available on this platform"))?;
    let cfg = sis_pdf_core::config::Config::load(&path)?;
    let log_level = cfg.logging.and_then(|l| l.level).unwrap_or_else(|| "warn".into());
    println!("Config ok: {}", path.display());
    println!("Logging level: {}", log_level);
    if let Some(scan) = cfg.scan {
        validate_ml_config(&scan)?;
    }
    Ok(())
}

fn default_config_template() -> &'static str {
    include_str!("../../../docs/config.toml")
}

fn run_sandbox_eval(
    path: &std::path::Path,
    asset_type: &str,
    max_bytes: Option<usize>,
) -> Result<()> {
    if asset_type != "js" {
        return Err(anyhow!("unsupported sandbox type: {}", asset_type));
    }
    let bytes = fs::read(path)?;
    let mut options = DynamicOptions::default();
    if let Some(max_bytes) = max_bytes {
        options.max_bytes = max_bytes;
    }
    let outcome = js_analysis::run_sandbox(&bytes, &options);
    let report = match outcome {
        DynamicOutcome::Executed(signals) => SandboxEvalReport {
            path: path.display().to_string(),
            asset_type: asset_type.to_string(),
            status: "executed".to_string(),
            timeout_ms: None,
            timeout_context: None,
            skip_reason: None,
            skip_limit: None,
            skip_actual: None,
            signals: Some(SandboxSignalsReport {
                replay_id: signals.replay_id,
                runtime_profile: signals.runtime_profile,
                errors: signals.errors,
                calls: signals.calls,
                call_args: signals.call_args,
                urls: signals.urls,
                domains: signals.domains,
                prop_reads: signals.prop_reads,
                prop_writes: signals.prop_writes,
                prop_deletes: signals.prop_deletes,
                reflection_probes: signals.reflection_probes,
                dynamic_code_calls: signals.dynamic_code_calls,
                call_count: signals.call_count,
                unique_calls: signals.unique_calls,
                unique_prop_reads: signals.unique_prop_reads,
                elapsed_ms: signals.elapsed_ms,
                truncation: SandboxTruncationSummaryReport {
                    calls_dropped: signals.truncation.calls_dropped,
                    call_args_dropped: signals.truncation.call_args_dropped,
                    prop_reads_dropped: signals.truncation.prop_reads_dropped,
                    errors_dropped: signals.truncation.errors_dropped,
                    urls_dropped: signals.truncation.urls_dropped,
                    domains_dropped: signals.truncation.domains_dropped,
                },
                phases: signals
                    .phases
                    .into_iter()
                    .map(|phase| SandboxPhaseSummaryReport {
                        phase: phase.phase,
                        call_count: phase.call_count,
                        prop_read_count: phase.prop_read_count,
                        error_count: phase.error_count,
                        elapsed_ms: phase.elapsed_ms,
                    })
                    .collect(),
                delta_summary: signals.delta_summary.map(|delta| SandboxDeltaSummaryReport {
                    phase: delta.phase,
                    trigger_calls: delta.trigger_calls,
                    generated_snippets: delta.generated_snippets,
                    added_identifier_count: delta.added_identifier_count,
                    added_string_literal_count: delta.added_string_literal_count,
                    added_call_count: delta.added_call_count,
                    new_identifiers: delta.new_identifiers,
                    new_string_literals: delta.new_string_literals,
                    new_calls: delta.new_calls,
                }),
                execution_stats: SandboxExecutionStats {
                    total_function_calls: signals.execution_stats.total_function_calls,
                    unique_function_calls: signals.execution_stats.unique_function_calls,
                    variable_promotions: signals.execution_stats.variable_promotions,
                    error_recoveries: signals.execution_stats.error_recoveries,
                    successful_recoveries: signals.execution_stats.successful_recoveries,
                    execution_depth: signals.execution_stats.execution_depth,
                    loop_iteration_limit_hits: signals.execution_stats.loop_iteration_limit_hits,
                    adaptive_loop_iteration_limit: signals
                        .execution_stats
                        .adaptive_loop_iteration_limit,
                    adaptive_loop_profile: signals.execution_stats.adaptive_loop_profile,
                    downloader_scheduler_hardening: signals
                        .execution_stats
                        .downloader_scheduler_hardening,
                    probe_loop_short_circuit_hits: signals
                        .execution_stats
                        .probe_loop_short_circuit_hits,
                },
                behavioral_patterns: signals
                    .behavioral_patterns
                    .into_iter()
                    .map(|pattern| SandboxBehaviorPattern {
                        name: pattern.name,
                        confidence: pattern.confidence,
                        evidence: pattern.evidence,
                        severity: pattern.severity,
                        metadata: pattern
                            .metadata
                            .into_iter()
                            .collect::<std::collections::BTreeMap<_, _>>(),
                    })
                    .collect(),
            }),
        },
        DynamicOutcome::TimedOut { timeout_ms, context } => SandboxEvalReport {
            path: path.display().to_string(),
            asset_type: asset_type.to_string(),
            status: "timeout".to_string(),
            timeout_ms: Some(timeout_ms),
            timeout_context: Some(SandboxTimeoutContextReport {
                runtime_profile: context.runtime_profile,
                phase: context.phase,
                elapsed_ms: context.elapsed_ms,
                budget_ratio: context.budget_ratio,
            }),
            skip_reason: None,
            skip_limit: None,
            skip_actual: None,
            signals: None,
        },
        DynamicOutcome::Skipped { reason, limit, actual } => SandboxEvalReport {
            path: path.display().to_string(),
            asset_type: asset_type.to_string(),
            status: "skipped".to_string(),
            timeout_ms: None,
            timeout_context: None,
            skip_reason: Some(reason),
            skip_limit: Some(limit),
            skip_actual: Some(actual),
            signals: None,
        },
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<ReleaseAsset>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

#[derive(Clone, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
}

enum ArchiveFormat {
    TarGz,
    Zip,
}

fn run_update(include_prerelease: bool) -> Result<()> {
    let (owner, repo) = github_repo()?;
    let (target, archive_format, bin_name) = current_release_target()?;
    let ext = match archive_format {
        ArchiveFormat::TarGz => "tar.gz",
        ArchiveFormat::Zip => "zip",
    };
    let suffix = format!("-{target}.{ext}");
    let (release, asset) = fetch_release_with_asset(&owner, &repo, &suffix, include_prerelease)?;
    if is_up_to_date(&release.tag_name) {
        eprintln!("sis is already up to date ({})", release.tag_name);
        return Ok(());
    }
    eprintln!("Downloading {}", asset.name);
    let temp_dir = tempdir()?;
    let archive_path = temp_dir.path().join(&asset.name);
    let mut reader = http_get_reader(&asset.browser_download_url, UPDATE_USER_AGENT)
        .map_err(|err| anyhow!("failed to download {}: {err}", asset.name))?;
    let mut out = fs::File::create(&archive_path)?;
    std::io::copy(&mut reader, &mut out)?;
    verify_release_checksum(&release, &asset, &archive_path)?;
    let extract_dir = temp_dir.path().join("extract");
    fs::create_dir_all(&extract_dir)?;
    match archive_format {
        ArchiveFormat::TarGz => extract_tar_gz(&archive_path, &extract_dir)?,
        ArchiveFormat::Zip => extract_zip(&archive_path, &extract_dir)?,
    }
    let new_bin = find_extracted_binary(&extract_dir, &bin_name)?;
    install_update(&new_bin)?;
    eprintln!("Updated sis to {}", release.tag_name);
    Ok(())
}

fn fetch_release_with_asset(
    owner: &str,
    repo: &str,
    suffix: &str,
    include_prerelease: bool,
) -> Result<(Release, ReleaseAsset)> {
    let latest_url = format!("https://api.github.com/repos/{owner}/{repo}/releases/latest");
    if let Ok(release) = fetch_release(&latest_url) {
        if let Some(asset) = find_release_asset(&release, suffix) {
            return Ok((release, asset));
        }
    }
    let list_url = format!("https://api.github.com/repos/{owner}/{repo}/releases?per_page=20");
    let releases = fetch_release_list(&list_url)?;
    for release in releases {
        if release.draft {
            continue;
        }
        if release.prerelease && !include_prerelease {
            continue;
        }
        if let Some(asset) = find_release_asset(&release, suffix) {
            return Ok((release, asset));
        }
    }
    Err(anyhow!("no release asset found matching {suffix}"))
}

fn fetch_release(url: &str) -> Result<Release> {
    let reader = http_get_reader(url, UPDATE_USER_AGENT)
        .map_err(|err| anyhow!("failed to query GitHub releases: {err}"))?;
    Ok(serde_json::from_reader(reader)?)
}

fn fetch_release_list(url: &str) -> Result<Vec<Release>> {
    let reader = http_get_reader(url, UPDATE_USER_AGENT)
        .map_err(|err| anyhow!("failed to query GitHub releases: {err}"))?;
    Ok(serde_json::from_reader(reader)?)
}

fn find_release_asset(release: &Release, suffix: &str) -> Option<ReleaseAsset> {
    release
        .assets
        .iter()
        .find(|asset| asset.name.starts_with("sis-") && asset.name.ends_with(suffix))
        .cloned()
}

fn is_up_to_date(tag: &str) -> bool {
    let current = env!("CARGO_PKG_VERSION");
    let trimmed = tag.strip_prefix('v').unwrap_or(tag);
    trimmed == current
}

fn verify_release_checksum(
    release: &Release,
    asset: &ReleaseAsset,
    archive_path: &std::path::Path,
) -> Result<()> {
    let Some(checksum_asset) = find_checksum_asset(release) else {
        warn!(
            asset = %asset.name,
            "Release does not include checksum asset; skipping verification"
        );
        return Ok(());
    };
    let mut reader = http_get_reader(&checksum_asset.browser_download_url, UPDATE_USER_AGENT)
        .map_err(|err| anyhow!("failed to download {}: {err}", checksum_asset.name))?;
    let mut contents = String::new();
    reader.read_to_string(&mut contents)?;
    let Some(expected) = parse_checksum(&contents, &asset.name) else {
        return Err(anyhow!(
            "checksum file {} does not include {}",
            checksum_asset.name,
            asset.name
        ));
    };
    let actual = sha256_file(archive_path)?;
    if expected != actual {
        return Err(anyhow!(
            "checksum mismatch for {} (expected {}, got {})",
            asset.name,
            expected,
            actual
        ));
    }
    eprintln!("Verified checksum for {}", asset.name);
    Ok(())
}

fn find_checksum_asset(release: &Release) -> Option<ReleaseAsset> {
    let tag = release.tag_name.as_str();
    let preferred = format!("sis-{tag}-checksums.txt");
    if let Some(asset) = release.assets.iter().find(|asset| asset.name == preferred) {
        return Some(asset.clone());
    }
    release
        .assets
        .iter()
        .find(|asset| {
            let name = asset.name.to_lowercase();
            (name.contains("checksum") || name.contains("sha256"))
                && (name.ends_with(".txt") || name.ends_with(".sha256"))
        })
        .cloned()
}

fn parse_checksum(contents: &str, asset_name: &str) -> Option<String> {
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || !line.contains(asset_name) {
            continue;
        }
        for token in line.split_whitespace() {
            let token = token.trim_start_matches('*').trim();
            if is_hex_64(token) {
                return Some(token.to_lowercase());
            }
        }
        if let Some(hash) = line.strip_prefix("sha256:") {
            let hash = hash.trim();
            if is_hex_64(hash) {
                return Some(hash.to_lowercase());
            }
        }
    }
    let single = contents.trim();
    if is_hex_64(single) {
        return Some(single.to_lowercase());
    }
    None
}

fn is_hex_64(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn sha256_file(path: &std::path::Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn github_repo() -> Result<(String, String)> {
    let repo = std::env::var("SIS_GITHUB_REPO").unwrap_or_else(|_| UPDATE_REPO_DEFAULT.into());
    let mut parts = repo.split('/');
    let owner = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    if owner.is_empty() || name.is_empty() || parts.next().is_some() {
        return Err(anyhow!("invalid repository format: {repo} (expected owner/name)"));
    }
    Ok((owner.to_string(), name.to_string()))
}

fn current_release_target() -> Result<(String, ArchiveFormat, String)> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    match (os, arch) {
        ("linux", "x86_64") => {
            Ok(("x86_64-unknown-linux-gnu".to_string(), ArchiveFormat::TarGz, "sis".to_string()))
        }
        ("windows", "x86_64") => {
            Ok(("x86_64-pc-windows-msvc".to_string(), ArchiveFormat::Zip, "sis.exe".to_string()))
        }
        ("macos", "aarch64") => {
            Ok(("aarch64-apple-darwin".to_string(), ArchiveFormat::TarGz, "sis".to_string()))
        }
        _ => Err(anyhow!("unsupported platform for self-update ({os} {arch})")),
    }
}

fn extract_tar_gz(archive_path: &std::path::Path, out_dir: &std::path::Path) -> Result<()> {
    let tar_gz = fs::File::open(archive_path)?;
    let decompressor = GzDecoder::new(tar_gz);
    let mut archive = Archive::new(decompressor);
    for entry in archive.entries()? {
        let mut entry = entry?;
        entry.unpack_in(out_dir)?;
    }
    Ok(())
}

fn extract_zip(archive_path: &std::path::Path, out_dir: &std::path::Path) -> Result<()> {
    let file = fs::File::open(archive_path)?;
    let mut archive = ZipArchive::new(file)?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let Some(path) = entry.enclosed_name() else {
            continue;
        };
        let out_path = out_dir.join(path);
        if entry.name().ends_with('/') {
            fs::create_dir_all(&out_path)?;
            continue;
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out = fs::File::create(&out_path)?;
        std::io::copy(&mut entry, &mut out)?;
    }
    Ok(())
}

fn find_extracted_binary(base_dir: &std::path::Path, bin_name: &str) -> Result<PathBuf> {
    for entry in WalkDir::new(base_dir) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.file_name() == bin_name {
            return Ok(entry.path().to_path_buf());
        }
    }
    Err(anyhow!("updated binary not found after extraction"))
}

fn install_update(new_bin: &std::path::Path) -> Result<()> {
    let current_exe = std::env::current_exe()?;
    if cfg!(windows) {
        stage_windows_update(new_bin, &current_exe)?;
        return Ok(());
    }
    fs::copy(new_bin, &current_exe).map_err(|err| {
        anyhow!(
            "failed to replace {}: {err}. Try reinstalling via scripts/install.sh or update permissions.",
            current_exe.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&current_exe)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&current_exe, perms)?;
    }
    Ok(())
}

fn stage_windows_update(new_bin: &std::path::Path, current_exe: &std::path::Path) -> Result<()> {
    let staged = current_exe.with_extension("new.exe");
    fs::copy(new_bin, &staged)?;
    let command = format!(
        "ping -n 2 127.0.0.1 > NUL & move /Y \"{}\" \"{}\"",
        staged.display(),
        current_exe.display()
    );
    ProcessCommand::new("cmd")
        .args(["/C", &command])
        .spawn()
        .map_err(|err| anyhow!("failed to stage update: {err}"))?;
    eprintln!("Update staged; restart the shell to pick up the new binary.");
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct OrtTarget {
    os: &'static str,
    arch: &'static str,
}

#[derive(Debug, Serialize)]
struct MlDetectOutput {
    os: String,
    arch: String,
    cpu_features: Vec<String>,
    ort_dylib: Option<String>,
    provider_order: Vec<String>,
    provider_available: Vec<String>,
    provider_selected: Option<String>,
    provider_suggestions: Vec<String>,
    gpu_tools: Vec<GpuToolDetection>,
    provider_detection_note: Option<String>,
}

#[derive(Debug, Serialize)]
struct GpuToolDetection {
    tool: String,
    available: bool,
    detail: Option<String>,
}

#[derive(Debug, Clone)]
struct MlConfigHints {
    provider: Option<String>,
    provider_order: Option<Vec<String>>,
    ort_dylib: Option<PathBuf>,
}

fn run_ml_ort_download(
    config: Option<&std::path::Path>,
    ml_provider: Option<&str>,
    ml_provider_order: Option<&str>,
    ml_ort_dylib: Option<&std::path::Path>,
    write_config: bool,
    ort_version: Option<&str>,
    checksum_url: Option<&str>,
    checksum_file: Option<&std::path::Path>,
    checksum_sha256: Option<&str>,
) -> Result<()> {
    ensure_single_checksum_override(checksum_url, checksum_file, checksum_sha256)?;
    let target = current_ort_target()?;
    let config_scan = load_scan_config(config)?;
    let hints = ml_config_hints(config_scan.as_ref());
    let runtime_overrides =
        build_ml_runtime_config(ml_provider, ml_provider_order, false, ml_ort_dylib, false, None);
    if let Some(path) = runtime_overrides.ort_dylib_path.as_ref().or(hints.ort_dylib.as_ref()) {
        println!("{}", path.display());
        return Ok(());
    }
    let version = resolve_ort_version(ort_version);
    let mut provider_order = resolve_provider_order(&runtime_overrides, &hints, target.os);
    let preferred_provider = runtime_overrides.provider.as_deref().or(hints.provider.as_deref());
    if preferred_provider.is_none()
        && runtime_overrides.provider_order.is_none()
        && hints.provider_order.is_none()
    {
        provider_order = prefer_gpu_provider_order(&provider_order);
    }
    let provider =
        select_provider_for_download(preferred_provider, &provider_order, &target, &version)?;
    // ROCm/MIGraphX support was dropped after 1.17.3; force that version if user didn't specify
    let version = if ort_version.is_none() && (provider == "migraphx" || provider == "rocm") {
        eprintln!("NOTE: Microsoft stopped publishing ROCm builds after ORT 1.17.3");
        eprintln!("NOTE: The ort crate currently requires ORT >= 1.23.x, which is incompatible");
        eprintln!("NOTE: ROCm users must either:");
        eprintln!("      - Build ONNX Runtime 1.23+ from source with ROCm support");
        eprintln!("      - Use CPU provider instead: --ml-provider cpu");
        eprintln!("      - Wait for ort crate downgrade to 2.0.0-rc.2 (ORT 1.17.3 compatible)");
        eprintln!();
        eprintln!("Downloading ORT 1.17.3 ROCm build anyway (for future use)...");
        "1.17.3".to_string()
    } else {
        version
    };
    let (archive_name, archive_format) = ort_archive_name(&target, &provider, &version)
        .ok_or_else(|| anyhow!("no ORT archive for {provider} on {} {}", target.os, target.arch))?;
    let base = ort_release_base(&version);
    let url = format!("{base}/{archive_name}");
    eprintln!("Downloading {archive_name} for {provider} ({})", target.arch);
    let temp_dir = tempdir()?;
    let archive_path = temp_dir.path().join(&archive_name);
    let mut reader = http_get_reader(&url, ORT_USER_AGENT)
        .map_err(|err| anyhow!("failed to download {archive_name}: {err}"))?;
    let mut out = fs::File::create(&archive_path)?;
    std::io::copy(&mut reader, &mut out)?;
    if let Some(checksum) = checksum_sha256 {
        verify_checksum_hash(checksum, &archive_path)?;
    } else {
        match fetch_checksum_contents(&base, &version, &archive_name, checksum_url, checksum_file) {
            Ok(checksum_contents) => {
                verify_checksum_contents(&checksum_contents, &archive_name, &archive_path)?;
            }
            Err(_) => {
                manual_checksum_verification(&archive_name, &archive_path)?;
            }
        }
    }
    let extract_dir = temp_dir.path().join("extract");
    fs::create_dir_all(&extract_dir)?;
    match archive_format {
        ArchiveFormat::TarGz => extract_tar_gz(&archive_path, &extract_dir)?,
        ArchiveFormat::Zip => extract_zip(&archive_path, &extract_dir)?,
    }
    let lib_path = find_ort_library(&extract_dir, target)?;
    let cache_dir =
        ort_cache_dir()?.join(&version).join(format!("{}-{}-{}", target.os, target.arch, provider));
    fs::create_dir_all(&cache_dir)?;

    // Copy all ORT libraries (main + providers) from the same directory
    let lib_dir = lib_path.parent().ok_or_else(|| anyhow!("library path has no parent"))?;
    let mut main_dest = None;
    for entry in fs::read_dir(lib_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // Copy all libonnxruntime*.so files (main library + provider libraries)
        if (target.os == "windows" && name.ends_with(".dll"))
            || (target.os == "macos"
                && name.starts_with("libonnxruntime")
                && name.ends_with(".dylib"))
            || (target.os == "linux"
                && name.starts_with("libonnxruntime")
                && (name.ends_with(".so") || name.contains(".so.")))
        {
            let dest = cache_dir.join(path.file_name().ok_or_else(|| anyhow!("missing filename"))?);
            fs::copy(&path, &dest)?;
            if is_ort_library(name, target) {
                main_dest = Some(dest);
            }
        }
    }

    let dest = main_dest.ok_or_else(|| anyhow!("main ORT library not found after copy"))?;
    println!("{}", dest.display());
    if write_config {
        let path = config
            .map(|p| p.to_path_buf())
            .or_else(default_config_path)
            .ok_or_else(|| anyhow!("config path not available on this platform"))?;
        write_ml_runtime_config(
            &path,
            &MlRuntimeUpdate { provider: None, provider_order: None, ort_dylib: Some(dest) },
        )?;
    }
    Ok(())
}

fn run_ml_detect(
    format: &str,
    config: Option<&std::path::Path>,
    ml_provider: Option<&str>,
    ml_provider_order: Option<&str>,
    ml_ort_dylib: Option<&std::path::Path>,
) -> Result<()> {
    let target = current_ort_target()?;
    let config_scan = load_scan_config(config)?;
    let hints = ml_config_hints(config_scan.as_ref());
    let mut runtime_overrides =
        build_ml_runtime_config(ml_provider, ml_provider_order, false, ml_ort_dylib, false, None);
    if runtime_overrides.ort_dylib_path.is_none() {
        runtime_overrides.ort_dylib_path = hints.ort_dylib.clone();
    }
    let ort_dylib = runtime_overrides.ort_dylib_path.clone().or(hints.ort_dylib.clone());
    let provider_order = resolve_provider_order(&runtime_overrides, &hints, target.os);
    let (provider_available, provider_selected, provider_detection_note) = {
        #[cfg(feature = "ml-graph")]
        {
            match detect_provider_info(&runtime_overrides, &provider_order) {
                Ok(info) => (info.available, info.selected, None),
                Err(err) => (Vec::new(), None, Some(format!("provider detection failed: {err}"))),
            }
        }
        #[cfg(not(feature = "ml-graph"))]
        {
            (Vec::new(), None, Some("provider detection requires the ml-graph feature".into()))
        }
    };
    let provider_suggestions = suggest_providers(&provider_order, &provider_available);
    let output = MlDetectOutput {
        os: target.os.to_string(),
        arch: target.arch.to_string(),
        cpu_features: detect_cpu_features(),
        ort_dylib: ort_dylib.map(|p| p.display().to_string()),
        provider_order,
        provider_available,
        provider_selected,
        provider_suggestions,
        gpu_tools: detect_gpu_tools(),
        provider_detection_note,
    };
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }
    print_ml_detect_text(&output);
    Ok(())
}

fn run_ml_autoconfig(
    config: Option<&std::path::Path>,
    ml_provider: Option<&str>,
    ml_provider_order: Option<&str>,
    ml_ort_dylib: Option<&std::path::Path>,
    dry_run: bool,
) -> Result<()> {
    let target = current_ort_target()?;
    let config_path = config
        .map(|p| p.to_path_buf())
        .or_else(default_config_path)
        .ok_or_else(|| anyhow!("config path not available on this platform"))?;
    let config_scan = load_scan_config(Some(&config_path))?;
    let hints = ml_config_hints(config_scan.as_ref());
    let runtime_overrides =
        build_ml_runtime_config(ml_provider, ml_provider_order, false, ml_ort_dylib, false, None);
    let provider_order = resolve_provider_order(&runtime_overrides, &hints, target.os);
    let provider_available = {
        #[cfg(feature = "ml-graph")]
        {
            detect_provider_info(&runtime_overrides, &provider_order)
                .map(|info| info.available)
                .unwrap_or_default()
        }
        #[cfg(not(feature = "ml-graph"))]
        {
            Vec::new()
        }
    };
    let provider_suggestions = suggest_providers(&provider_order, &provider_available);
    let selected = provider_suggestions.first().cloned().unwrap_or_else(|| "cpu".into());
    let update = MlRuntimeUpdate {
        provider: Some(selected),
        provider_order: Some(provider_suggestions),
        ort_dylib: runtime_overrides.ort_dylib_path.clone(),
    };
    if dry_run {
        println!(
            "Config path: {}\nml_provider = {}\nml_provider_order = [{}]{}",
            config_path.display(),
            update.provider.clone().unwrap_or_else(|| "cpu".into()),
            update.provider_order.as_ref().map(|list| list.join(", ")).unwrap_or_default(),
            update
                .ort_dylib
                .as_ref()
                .map(|p| format!("\nml_ort_dylib = {}", p.display()))
                .unwrap_or_default()
        );
        return Ok(());
    }
    write_ml_runtime_config(&config_path, &update)?;
    println!(
        "Updated config at {} (ml_provider = {})",
        config_path.display(),
        update.provider.unwrap_or_else(|| "cpu".into())
    );
    Ok(())
}

fn load_scan_config(
    config: Option<&std::path::Path>,
) -> Result<Option<sis_pdf_core::config::ScanConfig>> {
    let Some(path) = config else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }
    let cfg = sis_pdf_core::config::Config::load(path)?;
    Ok(cfg.scan)
}

fn ml_config_hints(scan: Option<&sis_pdf_core::config::ScanConfig>) -> MlConfigHints {
    let (provider, provider_order, ort_dylib) = if let Some(scan) = scan {
        let provider = scan
            .ml_provider
            .as_deref()
            .map(normalise_provider_name)
            .filter(|p| !p.is_empty() && p != "auto");
        let provider_order = scan.ml_provider_order.as_ref().map(|list| {
            list.iter()
                .map(|p| normalise_provider_name(p))
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
        });
        let ort_dylib = scan.ml_ort_dylib.as_ref().map(PathBuf::from);
        (provider, provider_order, ort_dylib)
    } else {
        (None, None, None)
    };
    MlConfigHints { provider, provider_order, ort_dylib }
}

fn resolve_provider_order(
    overrides: &sis_pdf_core::ml::MlRuntimeConfig,
    hints: &MlConfigHints,
    os: &str,
) -> Vec<String> {
    if let Some(order) = overrides.provider_order.as_ref() {
        return ensure_cpu(sanitise_provider_list(order));
    }
    if let Some(provider) = overrides.provider.as_deref() {
        return ensure_cpu(vec![normalise_provider_name(provider)]);
    }
    if let Some(order) = hints.provider_order.as_ref() {
        return ensure_cpu(sanitise_provider_list(order));
    }
    if let Some(provider) = hints.provider.as_deref() {
        return ensure_cpu(vec![normalise_provider_name(provider)]);
    }
    default_provider_order(os)
}

fn default_provider_order(os: &str) -> Vec<String> {
    let mut order = Vec::new();
    if os == "windows" {
        order.push("directml".into());
        order.push("cuda".into());
    } else if os == "macos" {
        order.push("coreml".into());
    } else {
        order.push("cuda".into());
        order.push("openvino".into());
        order.push("migraphx".into());
    }
    order.push("cpu".into());
    order
}

fn sanitise_provider_list(list: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for raw in list {
        let name = normalise_provider_name(raw);
        if name.is_empty() {
            continue;
        }
        if name == "auto" {
            continue;
        }
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

fn normalise_provider_name(name: &str) -> String {
    let name = name.trim().to_lowercase();
    if name == "rocm" {
        return "migraphx".into();
    }
    name
}

fn ensure_cpu(mut list: Vec<String>) -> Vec<String> {
    if !list.iter().any(|p| p == "cpu") {
        list.push("cpu".into());
    }
    list
}

fn suggest_providers(order: &[String], available: &[String]) -> Vec<String> {
    if available.is_empty() {
        return ensure_cpu(order.to_vec());
    }
    let mut out = Vec::new();
    for name in order {
        if available.iter().any(|p| p == name) {
            out.push(name.clone());
        }
    }
    ensure_cpu(out)
}

#[cfg(feature = "ml-graph")]
fn detect_provider_info(
    overrides: &sis_pdf_core::ml::MlRuntimeConfig,
    provider_order: &[String],
) -> Result<sis_pdf_ml_graph::ProviderInfo> {
    if resolve_ort_dylib_hint(overrides).is_none() {
        return Err(anyhow!(
            "ORT dylib not configured; set ml_ort_dylib or run `sis ml ort download`"
        ));
    }
    let settings = sis_pdf_ml_graph::RuntimeSettings {
        provider: None,
        provider_order: Some(provider_order.to_vec()),
        ort_dylib_path: overrides.ort_dylib_path.clone(),
        prefer_quantized: overrides.prefer_quantized,
        max_embedding_batch_size: overrides.max_embedding_batch_size,
        print_provider: overrides.print_provider,
    };
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sis_pdf_ml_graph::runtime_provider_info(&settings)
    }));
    std::panic::set_hook(previous_hook);
    match result {
        Ok(info) => info,
        Err(_) => Err(anyhow!(
            "ORT initialisation panicked; configure ml_ort_dylib or run `sis ml ort download`"
        )),
    }
}

#[cfg(feature = "ml-graph")]
fn resolve_ort_dylib_hint(overrides: &sis_pdf_core::ml::MlRuntimeConfig) -> Option<PathBuf> {
    if let Some(path) = overrides.ort_dylib_path.as_ref() {
        return Some(path.clone());
    }
    if let Ok(path) = std::env::var("SIS_ORT_DYLIB_PATH") {
        if !path.trim().is_empty() {
            return Some(PathBuf::from(path));
        }
    }
    None
}

fn detect_cpu_features() -> Vec<String> {
    let mut features = Vec::new();
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if std::is_x86_feature_detected!("sse4.2") {
            features.push("sse4.2".into());
        }
        if std::is_x86_feature_detected!("avx") {
            features.push("avx".into());
        }
        if std::is_x86_feature_detected!("avx2") {
            features.push("avx2".into());
        }
        if std::is_x86_feature_detected!("avx512f") {
            features.push("avx512f".into());
        }
    }
    features
}

fn detect_gpu_tools() -> Vec<GpuToolDetection> {
    let mut detections = Vec::new();
    detections.push(run_gpu_tool("nvidia-smi", &["-L"]));
    if cfg!(target_os = "linux") {
        detections.push(run_gpu_tool("rocminfo", &[]));
    }
    if cfg!(target_os = "macos") {
        detections.push(run_gpu_tool("system_profiler", &["SPDisplaysDataType"]));
    }
    detections
}

fn run_gpu_tool(tool: &str, args: &[&str]) -> GpuToolDetection {
    let output = ProcessCommand::new(tool).args(args).output();
    match output {
        Ok(out) if out.status.success() => {
            let detail = String::from_utf8_lossy(&out.stdout);
            let detail = detail.lines().next().map(|line| line.trim().to_string());
            let detail = detail.filter(|line| !line.is_empty());
            GpuToolDetection { tool: tool.to_string(), available: true, detail }
        }
        Ok(out) => {
            let detail = String::from_utf8_lossy(&out.stderr);
            let detail = detail.lines().next().map(|line| line.trim().to_string());
            let detail = detail.filter(|line| !line.is_empty());
            GpuToolDetection { tool: tool.to_string(), available: false, detail }
        }
        Err(_) => GpuToolDetection { tool: tool.to_string(), available: false, detail: None },
    }
}

fn print_ml_detect_text(output: &MlDetectOutput) {
    println!("OS: {}", output.os);
    println!("Arch: {}", output.arch);
    if output.cpu_features.is_empty() {
        println!("CPU features: none");
    } else {
        println!("CPU features: {}", output.cpu_features.join(", "));
    }
    if let Some(path) = &output.ort_dylib {
        println!("ORT dylib: {}", path);
    }
    println!("Provider order: {}", output.provider_order.join(", "));
    if output.provider_available.is_empty() {
        println!("Available providers: none");
    } else {
        println!("Available providers: {}", output.provider_available.join(", "));
    }
    println!(
        "Selected provider: {}",
        output.provider_selected.clone().unwrap_or_else(|| "none".into())
    );
    println!("Suggested providers: {}", output.provider_suggestions.join(", "));
    if let Some(note) = &output.provider_detection_note {
        println!("Provider detection: {}", note);
    }
    for tool in &output.gpu_tools {
        println!(
            "GPU tool {}: {}{}",
            tool.tool,
            if tool.available { "available" } else { "unavailable" },
            tool.detail.as_ref().map(|d| format!(" ({})", d)).unwrap_or_default()
        );
    }
}

fn current_ort_target() -> Result<OrtTarget> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    match (os, arch) {
        ("linux", "x86_64") => Ok(OrtTarget { os: "linux", arch: "x86_64" }),
        ("windows", "x86_64") => Ok(OrtTarget { os: "windows", arch: "x86_64" }),
        ("macos", "aarch64") => Ok(OrtTarget { os: "macos", arch: "aarch64" }),
        _ => Err(anyhow!("unsupported platform for ORT download ({os} {arch})")),
    }
}

fn ort_archive_name(
    target: &OrtTarget,
    provider: &str,
    version: &str,
) -> Option<(String, ArchiveFormat)> {
    let provider = provider.to_lowercase();
    match (target.os, target.arch, provider.as_str()) {
        ("linux", "x86_64", "cpu") => {
            Some((format!("onnxruntime-linux-x64-{version}.tgz"), ArchiveFormat::TarGz))
        }
        ("linux", "x86_64", "cuda") => {
            Some((format!("onnxruntime-linux-x64-gpu-{version}.tgz"), ArchiveFormat::TarGz))
        }
        ("linux", "x86_64", "openvino") => {
            Some((format!("onnxruntime-linux-x64-openvino-{version}.tgz"), ArchiveFormat::TarGz))
        }
        ("linux", "x86_64", "migraphx") => {
            Some((format!("onnxruntime-linux-x64-rocm-{version}.tgz"), ArchiveFormat::TarGz))
        }
        ("windows", "x86_64", "cpu") => {
            Some((format!("onnxruntime-win-x64-{version}.zip"), ArchiveFormat::Zip))
        }
        ("windows", "x86_64", "cuda") => {
            Some((format!("onnxruntime-win-x64-gpu-{version}.zip"), ArchiveFormat::Zip))
        }
        ("windows", "x86_64", "directml") => {
            Some((format!("onnxruntime-win-x64-directml-{version}.zip"), ArchiveFormat::Zip))
        }
        ("macos", "aarch64", "cpu") => {
            Some((format!("onnxruntime-osx-arm64-{version}.tgz"), ArchiveFormat::TarGz))
        }
        ("macos", "aarch64", "coreml") => {
            Some((format!("onnxruntime-osx-arm64-coreml-{version}.tgz"), ArchiveFormat::TarGz))
        }
        _ => None,
    }
}

fn resolve_ort_version(override_version: Option<&str>) -> String {
    if let Some(value) = override_version {
        if !value.trim().is_empty() {
            return value.trim().to_string();
        }
    }
    std::env::var("SIS_ORT_VERSION").unwrap_or_else(|_| ORT_VERSION_DEFAULT.to_string())
}

fn embedded_ort_checksum(version: &str, archive_name: &str) -> Option<&'static str> {
    match (version, archive_name) {
        ("1.17.3", "onnxruntime-linux-x64-rocm-1.17.3.tgz") => {
            Some("82a0efd31abf4f3ad1997094915245ab936a7f395d801c8864d6991d9a16f696")
        }
        _ => None,
    }
}

fn ort_release_base(version: &str) -> String {
    if let Ok(base) = std::env::var("SIS_ORT_BASE_URL") {
        let trimmed = base.trim_end_matches('/');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    format!("{}/v{}", ORT_RELEASE_BASE, version)
}

fn fetch_checksum_contents(
    base: &str,
    version: &str,
    archive_name: &str,
    checksum_url: Option<&str>,
    checksum_file: Option<&std::path::Path>,
) -> Result<String> {
    if let Some(url) = checksum_url {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            return download_text(trimmed, ORT_USER_AGENT);
        }
    }
    if let Some(path) = checksum_file {
        return fs::read_to_string(path)
            .map_err(|err| anyhow!("failed to read checksum file {}: {err}", path.display()));
    }
    if let Ok(url) = std::env::var("SIS_ORT_CHECKSUM_URL") {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            return download_text(trimmed, ORT_USER_AGENT);
        }
    }
    if let Some(checksum) = embedded_ort_checksum(version, archive_name) {
        eprintln!("Using embedded checksum for {archive_name}");
        return Ok(format!("{checksum}  {archive_name}"));
    }
    let urls = [
        format!("{base}/{archive_name}.sha256"),
        format!("{base}/{archive_name}.sha256.txt"),
        format!("{base}/{archive_name}.sha256sum"),
        format!("{base}/{archive_name}.sha256sum.txt"),
        format!("{base}/onnxruntime-{version}-sha256.txt"),
        format!("{base}/onnxruntime-{version}.sha256"),
        format!("{base}/onnxruntime-{version}-sha256sum.txt"),
    ];
    for url in urls {
        match download_text_optional(&url, ORT_USER_AGENT) {
            Ok(Some(contents)) => return Ok(contents),
            Ok(None) => continue,
            Err(err) => return Err(err),
        }
    }
    if let Ok(contents) = fetch_checksum_from_release(version, archive_name) {
        return Ok(contents);
    }
    Err(anyhow!(
        "checksum file not available for {archive_name}; use --checksum-url, --checksum-file, or --checksum-sha256"
    ))
}

fn download_text(url: &str, user_agent: &str) -> Result<String> {
    let mut reader = http_get_reader(url, user_agent)
        .map_err(|err| anyhow!("failed to download {url}: {err}"))?;
    let mut contents = String::new();
    reader.read_to_string(&mut contents)?;
    Ok(contents)
}

fn download_text_optional(url: &str, user_agent: &str) -> Result<Option<String>> {
    match http_get_reader(url, user_agent) {
        Ok(mut reader) => {
            let mut contents = String::new();
            reader.read_to_string(&mut contents)?;
            Ok(Some(contents))
        }
        Err(ureq::Error::StatusCode(404)) => Ok(None),
        Err(err) => Err(anyhow!("failed to download {url}: {err}")),
    }
}

fn http_get_reader(url: &str, user_agent: &str) -> Result<impl Read, ureq::Error> {
    let agent: Agent = Agent::config_builder().user_agent(user_agent).build().into();
    agent.get(url).call().map(|res| res.into_body().into_reader())
}

fn fetch_checksum_from_release(version: &str, archive_name: &str) -> Result<String> {
    let api_url =
        format!("https://api.github.com/repos/microsoft/onnxruntime/releases/tags/v{version}");
    let release_reader = http_get_reader(&api_url, ORT_USER_AGENT)
        .map_err(|err| anyhow!("failed to query ORT release metadata: {err}"))?;
    let release: Release = serde_json::from_reader(release_reader)?;
    let mut candidates = release
        .assets
        .iter()
        .filter(|asset| {
            let name = asset.name.to_lowercase();
            (name.contains("sha256") || name.contains("checksum"))
                && (name.ends_with(".txt") || name.ends_with(".sha256") || name.ends_with(".sum"))
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|asset| asset.name.len());
    for asset in candidates {
        let contents = download_text(&asset.browser_download_url, ORT_USER_AGENT)?;
        if parse_checksum(&contents, archive_name).is_some() {
            return Ok(contents);
        }
    }
    Err(anyhow!("checksum metadata not found in ORT release assets"))
}

fn prefer_gpu_provider_order(order: &[String]) -> Vec<String> {
    let detections = detect_gpu_tools();
    let has_rocm = detections.iter().any(|d| d.tool == "rocminfo" && d.available);
    let has_nvidia = detections.iter().any(|d| d.tool == "nvidia-smi" && d.available);
    let mut preferred = order.to_vec();
    if has_rocm {
        preferred = move_provider_to_front(&preferred, "migraphx");
    } else if has_nvidia {
        preferred = move_provider_to_front(&preferred, "cuda");
    }
    preferred
}

fn move_provider_to_front(order: &[String], provider: &str) -> Vec<String> {
    let mut out = Vec::new();
    let target = provider.to_string();
    if order.iter().any(|p| p == &target) {
        out.push(target.clone());
    }
    for entry in order {
        if entry != &target {
            out.push(entry.clone());
        }
    }
    out
}

fn verify_checksum_contents(
    contents: &str,
    asset_name: &str,
    archive_path: &std::path::Path,
) -> Result<()> {
    let Some(expected) = parse_checksum(contents, asset_name) else {
        return Err(anyhow!("checksum file does not include {}", asset_name));
    };
    let actual = sha256_file(archive_path)?;
    if expected != actual {
        return Err(anyhow!(
            "checksum mismatch for {} (expected {}, got {})",
            asset_name,
            expected,
            actual
        ));
    }
    eprintln!("Verified checksum for {}", asset_name);
    Ok(())
}

fn verify_checksum_hash(checksum: &str, archive_path: &std::path::Path) -> Result<()> {
    let checksum = checksum.trim();
    if !is_hex_64(checksum) {
        return Err(anyhow!("checksum must be 64 hex characters"));
    }
    let actual = sha256_file(archive_path)?;
    let expected = checksum.to_lowercase();
    if expected != actual {
        return Err(anyhow!(
            "checksum mismatch for archive (expected {}, got {})",
            expected,
            actual
        ));
    }
    eprintln!("Verified checksum for {}", archive_path.display());
    Ok(())
}

fn manual_checksum_verification(archive_name: &str, archive_path: &std::path::Path) -> Result<()> {
    eprintln!("\nWARNING: No checksum available for {archive_name}");
    eprintln!("Computing checksum for downloaded file...");
    let checksum = sha256_file(archive_path)?;
    eprintln!("\nSHA256: {checksum}");
    eprintln!("\nPlease verify this checksum matches the official release.");
    eprintln!("Visit: https://github.com/microsoft/onnxruntime/releases");
    eprint!("\nProceed with installation? [y/N]: ");
    use std::io::Write;
    std::io::stderr().flush()?;
    let mut response = String::new();
    std::io::stdin().read_line(&mut response)?;
    let response = response.trim().to_lowercase();
    if response == "y" || response == "yes" {
        eprintln!("Proceeding with installation (checksum: {checksum})");
        Ok(())
    } else {
        Err(anyhow!("Installation cancelled by user"))
    }
}

fn ensure_single_checksum_override(
    checksum_url: Option<&str>,
    checksum_file: Option<&std::path::Path>,
    checksum_sha256: Option<&str>,
) -> Result<()> {
    let count = checksum_url.is_some() as u8
        + checksum_file.is_some() as u8
        + checksum_sha256.is_some() as u8;
    if count > 1 {
        return Err(anyhow!(
            "checksum overrides are mutually exclusive (use only one of --checksum-url, --checksum-file, --checksum-sha256)"
        ));
    }
    Ok(())
}

fn ort_cache_dir() -> Result<PathBuf> {
    if cfg!(windows) {
        if let Some(dir) = dirs::data_local_dir() {
            return Ok(dir.join("sis").join("ort"));
        }
    } else if let Some(home) = dirs::home_dir() {
        return Ok(home.join(".cache").join("sis").join("ort"));
    }
    dirs::cache_dir()
        .map(|dir| dir.join("sis").join("ort"))
        .ok_or_else(|| anyhow!("cache directory not available on this platform"))
}

fn find_ort_library(base_dir: &std::path::Path, target: OrtTarget) -> Result<PathBuf> {
    for entry in WalkDir::new(base_dir) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        if is_ort_library(entry.file_name().to_string_lossy().as_ref(), target) {
            return Ok(entry.path().to_path_buf());
        }
    }
    Err(anyhow!("ORT library not found in extracted archive"))
}

fn is_ort_library(name: &str, target: OrtTarget) -> bool {
    if target.os == "windows" {
        return name.eq_ignore_ascii_case("onnxruntime.dll");
    }
    if target.os == "macos" {
        return name == "libonnxruntime.dylib"
            || name.starts_with("libonnxruntime.") && name.ends_with(".dylib");
    }
    // Match libonnxruntime.so or libonnxruntime.so.X.Y.Z, but NOT libonnxruntime_providers_*.so
    (name == "libonnxruntime.so" || name.starts_with("libonnxruntime.so."))
        && !name.contains("_providers_")
}

fn select_provider_for_download(
    preferred_provider: Option<&str>,
    provider_order: &[String],
    target: &OrtTarget,
    version: &str,
) -> Result<String> {
    if let Some(provider) = preferred_provider {
        let provider = normalise_provider_name(provider);
        if ort_archive_name(target, &provider, version).is_some() {
            return Ok(provider);
        }
        return Err(anyhow!(
            "provider {} is not supported for ORT download on {} {}",
            provider,
            target.os,
            target.arch
        ));
    }
    for provider in provider_order {
        if ort_archive_name(target, provider, version).is_some() {
            return Ok(provider.clone());
        }
    }
    Err(anyhow!("no supported ORT download found for {} {}", target.os, target.arch))
}

#[derive(Debug, Clone)]
struct MlRuntimeUpdate {
    provider: Option<String>,
    provider_order: Option<Vec<String>>,
    ort_dylib: Option<PathBuf>,
}

fn write_ml_runtime_config(path: &std::path::Path, update: &MlRuntimeUpdate) -> Result<()> {
    let mut doc = load_or_create_config_document(path)?;
    let scan = scan_table(&mut doc);
    if let Some(provider) = update.provider.as_ref() {
        scan["ml_provider"] = value(provider.clone());
    }
    if let Some(order) = update.provider_order.as_ref() {
        scan["ml_provider_order"] = Item::Value(Value::Array(toml_array(order)));
    }
    if let Some(path) = update.ort_dylib.as_ref() {
        scan["ml_ort_dylib"] = value(path.display().to_string());
    }
    write_config_document(path, &doc)?;
    Ok(())
}

fn load_or_create_config_document(path: &std::path::Path) -> Result<DocumentMut> {
    let contents = if path.exists() {
        fs::read_to_string(path)?
    } else {
        default_config_template().to_string()
    };
    let doc = contents
        .parse::<DocumentMut>()
        .map_err(|err| anyhow!("failed to parse config TOML: {err}"))?;
    Ok(doc)
}

fn scan_table(doc: &mut DocumentMut) -> &mut Table {
    if doc.get("scan").is_none() {
        doc["scan"] = Item::Table(Table::new());
    }
    doc["scan"].as_table_mut().expect("scan table should always be a table")
}

fn write_config_document(path: &std::path::Path, doc: &DocumentMut) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, doc.to_string())?;
    Ok(())
}

fn toml_array(values: &[String]) -> Array {
    let mut array = Array::default();
    for value in values {
        array.push(value.as_str());
    }
    array
}

fn validate_ml_config(scan: &sis_pdf_core::config::ScanConfig) -> Result<()> {
    const ALLOWED_MODES: &[&str] = &["traditional", "graph"];
    const ALLOWED_PROVIDERS: &[&str] =
        &["auto", "cpu", "cuda", "rocm", "migraphx", "directml", "coreml", "onednn", "openvino"];
    if let Some(mode) = &scan.ml_mode {
        let mode = mode.trim().to_lowercase();
        if !ALLOWED_MODES.contains(&mode.as_str()) {
            return Err(anyhow!(
                "invalid ml_mode {} (expected: {})",
                mode,
                ALLOWED_MODES.join(", ")
            ));
        }
    }
    if let Some(threshold) = scan.ml_threshold {
        if !(0.0..=1.0).contains(&threshold) {
            return Err(anyhow!("invalid ml_threshold {} (expected 0.0..=1.0)", threshold));
        }
    }
    if let Some(provider) = &scan.ml_provider {
        let provider = provider.trim().to_lowercase();
        if !ALLOWED_PROVIDERS.contains(&provider.as_str()) {
            return Err(anyhow!(
                "invalid ml_provider {} (expected: {})",
                provider,
                ALLOWED_PROVIDERS.join(", ")
            ));
        }
        if provider == "rocm" {
            warn!("ml_provider rocm is deprecated; use migraphx with ROCm builds");
        }
    }
    if let Some(order) = &scan.ml_provider_order {
        for provider in order {
            let provider = provider.trim().to_lowercase();
            if !ALLOWED_PROVIDERS.contains(&provider.as_str()) {
                return Err(anyhow!(
                    "invalid ml_provider_order entry {} (expected: {})",
                    provider,
                    ALLOWED_PROVIDERS.join(", ")
                ));
            }
            if provider == "rocm" {
                warn!("ml_provider_order entry rocm is deprecated; use migraphx with ROCm builds");
            }
        }
    }
    if let Some(batch) = scan.ml_batch_size {
        if batch == 0 {
            return Err(anyhow!("invalid ml_batch_size 0 (expected > 0)"));
        }
    }
    if let Some(path) = &scan.ml_ort_dylib {
        let path = path.trim();
        if path.is_empty() {
            return Err(anyhow!("invalid ml_ort_dylib (empty path)"));
        }
    }
    Ok(())
}
fn read_pdf_bytes(path: &str) -> Result<Vec<u8>> {
    let mut f = fs::File::open(path)?;
    let size = f.metadata()?.len();
    if size > WARN_PDF_BYTES {
        SecurityEvent {
            level: Level::WARN,
            domain: SecurityDomain::PdfStructure,
            severity: SecuritySeverity::Low,
            kind: "file_size_warning",
            policy: None,
            object_id: None,
            object_type: None,
            vector: None,
            technique: None,
            confidence: None,
            fatal: false,
            message: "Large PDF file size may impact scan performance",
        }
        .emit();
        warn!(path = path, size_bytes = size, "Large PDF file");
    }
    if size > MAX_PDF_BYTES {
        SecurityEvent {
            level: Level::ERROR,
            domain: SecurityDomain::PdfStructure,
            severity: SecuritySeverity::High,
            kind: "file_size_rejected",
            policy: None,
            object_id: None,
            object_type: None,
            vector: None,
            technique: None,
            confidence: None,
            fatal: false,
            message: "PDF file exceeds max size limit",
        }
        .emit();
        error!(
            path = path,
            size_bytes = size,
            max_bytes = MAX_PDF_BYTES,
            "PDF file exceeds max size limit"
        );
        return Err(anyhow!("file exceeds max size: {} bytes", size));
    }
    let mut buffer = Vec::with_capacity(size as usize);
    f.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn maybe_colourise_output(
    output: String,
    output_format: commands::query::OutputFormat,
    colour: bool,
) -> String {
    if !colour || !std::io::stdout().is_terminal() {
        return output;
    }
    match commands::query::colourise_output(&output, output_format) {
        Ok(colourised) => colourised,
        Err(_) => output,
    }
}

fn run_query_oneshot(
    query_str: &str,
    pdf_path: Option<&str>,
    output_format: commands::query::OutputFormat,
    compact: bool,
    colour: bool,
    deep: bool,
    max_decode_bytes: usize,
    max_total_decoded_bytes: usize,
    recover_xref: bool,
    max_objects: usize,
    group_chains: bool,
    extract_to: Option<&std::path::Path>,
    path: Option<&std::path::Path>,
    glob: &str,
    max_extract_bytes: usize,
    decode_mode: commands::query::DecodeMode,
    predicate: Option<&commands::query::PredicateExpr>,
    report_verbosity: commands::query::ReportVerbosity,
    chain_summary: commands::query::ChainSummaryLevel,
    _config_path: Option<PathBuf>,
) -> Result<()> {
    use commands::query;

    // Parse the query
    let query = match query::parse_query(query_str) {
        Ok(parsed) => parsed,
        Err(e) => {
            let error = query::query_syntax_error(format!("Failed to parse query: {}", e));
            let file_label = pdf_path.unwrap_or("<batch>");
            match output_format {
                query::OutputFormat::Json => {
                    let output = query::format_json(query_str, file_label, &error)?;
                    println!("{}", maybe_colourise_output(output, output_format, colour));
                    return Ok(());
                }
                query::OutputFormat::Jsonl => {
                    let output = query::format_jsonl(query_str, file_label, &error)?;
                    println!("{}", output);
                    return Ok(());
                }
                query::OutputFormat::Yaml => {
                    let output = query::format_yaml(query_str, file_label, &error)?;
                    println!("{}", maybe_colourise_output(output, output_format, colour));
                    return Ok(());
                }
                _ => return Err(anyhow!("Failed to parse query: {}", e)),
            }
        }
    };
    let query = query::apply_output_format(query, output_format)?;

    // Build scan options
    let scan_options = query::ScanOptions {
        deep,
        max_decode_bytes,
        max_total_decoded_bytes,
        no_recover: !recover_xref,
        max_objects,
        group_chains,
        correlation: sis_pdf_core::scan::CorrelationOptions::default(),
    };

    // Phase 3: Batch mode - execute query across directory
    if let Some(dir_path) = path {
        return query::run_query_batch(
            &query,
            dir_path,
            glob,
            &scan_options,
            extract_to,
            max_extract_bytes,
            decode_mode,
            predicate,
            output_format,
            colour,
            MAX_BATCH_FILES,
            MAX_BATCH_BYTES,
            MAX_WALK_DEPTH,
        );
    }

    // Single file mode
    let pdf_path =
        pdf_path.ok_or_else(|| anyhow!("PDF file path required for single file mode"))?;
    let result = query::execute_query(
        &query,
        std::path::Path::new(pdf_path),
        &scan_options,
        extract_to,
        max_extract_bytes,
        decode_mode,
        predicate,
    )
    .map_err(|e| anyhow!("Query execution failed: {}", e))?;

    let result = query::apply_report_verbosity(&query, result, report_verbosity, output_format);
    let result = query::apply_chain_summary(&query, result, chain_summary, output_format);

    // Format and print the result
    match output_format {
        query::OutputFormat::Json => {
            let output = query::format_json(query_str, pdf_path, &result)?;
            println!("{}", maybe_colourise_output(output, output_format, colour));
        }
        query::OutputFormat::Jsonl => {
            let output = query::format_jsonl(query_str, pdf_path, &result)?;
            println!("{}", output);
        }
        query::OutputFormat::Yaml => {
            let output = query::format_yaml(query_str, pdf_path, &result)?;
            println!("{}", maybe_colourise_output(output, output_format, colour));
        }
        query::OutputFormat::Text | query::OutputFormat::Csv | query::OutputFormat::Dot => {
            let output = query::format_result(&result, compact);
            println!("{}", output);
        }
        query::OutputFormat::Readable => {
            let output = query::format_readable_result(&result, compact);
            println!("{}", output);
        }
    }

    Ok(())
}

fn run_query_repl(
    pdf_path: &str,
    deep: bool,
    max_decode_bytes: usize,
    max_total_decoded_bytes: usize,
    recover_xref: bool,
    max_objects: usize,
    group_chains: bool,
    extract_to: Option<&std::path::Path>,
    max_extract_bytes: usize,
    output_format: commands::query::OutputFormat,
    colour: bool,
    decode_mode: commands::query::DecodeMode,
    predicate: Option<&commands::query::PredicateExpr>,
    predicate_text: Option<&str>,
    report_verbosity: commands::query::ReportVerbosity,
    chain_summary: commands::query::ChainSummaryLevel,
    config_path: Option<PathBuf>,
) -> Result<()> {
    use commands::query;
    use rustyline::error::ReadlineError;
    use rustyline::DefaultEditor;

    // Phase 2: Extraction now supported in REPL mode
    // Load and parse PDF once
    eprintln!("Loading PDF: {}", pdf_path);
    let bytes = std::fs::read(pdf_path)?;

    let scan_options = query::ScanOptions {
        deep,
        max_decode_bytes,
        max_total_decoded_bytes,
        no_recover: !recover_xref,
        max_objects,
        group_chains,
        correlation: CorrelationOptions::default(),
    };

    // Build scan context (this is expensive, so we do it once)
    let ctx = query::build_scan_context_public(&bytes, &scan_options)?;
    eprintln!("PDF loaded. Enter queries (or 'help' for help, 'exit' to quit).\n");

    // Initialize REPL editor with history
    let mut rl = DefaultEditor::new()?;
    let history_file = dirs::cache_dir()
        .map(|d| d.join("sis").join("query_history.txt"))
        .unwrap_or_else(|| std::path::PathBuf::from(".sis_query_history"));

    // Create cache directory if it doesn't exist
    if let Some(parent) = history_file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // Load history (ignore errors if file doesn't exist)
    let _ = rl.load_history(&history_file);

    // REPL state
    let mut json_mode =
        matches!(output_format, query::OutputFormat::Json | query::OutputFormat::Jsonl);
    let mut jsonl_mode = output_format == query::OutputFormat::Jsonl;
    let mut yaml_mode = output_format == query::OutputFormat::Yaml;
    let mut colour_mode = colour;
    let mut compact_mode = false;
    let mut readable_mode = output_format == query::OutputFormat::Readable;
    let mut predicate_expr = predicate.cloned();
    let mut predicate_display = predicate_text.map(|value| value.to_string());

    loop {
        let prompt = if predicate_expr.is_some() { "sis(:where)> " } else { "sis> " };
        let readline = rl.readline(prompt);

        match readline {
            Ok(line) => {
                let line = line.trim();

                // Skip empty lines
                if line.is_empty() {
                    continue;
                }

                // Add to history
                let _ = rl.add_history_entry(line);

                let (query_line, destination) = split_repl_destination(line);
                let query_line = query_line.trim();
                if query_line.is_empty() {
                    continue;
                }

                // Handle REPL commands
                if let Some(rest) = query_line.strip_prefix(":where") {
                    let expr = rest.trim();
                    if expr.is_empty() {
                        if let Some(current) = predicate_display.as_deref() {
                            eprintln!("Predicate: {}", current);
                        } else if predicate_expr.is_some() {
                            eprintln!("Predicate set (source unavailable)");
                        } else {
                            eprintln!("No predicate set");
                        }
                    } else if matches!(
                        expr.to_ascii_lowercase().as_str(),
                        "clear" | "reset" | "off" | "none"
                    ) {
                        predicate_expr = None;
                        predicate_display = None;
                        eprintln!("Predicate cleared");
                    } else {
                        match query::parse_predicate(expr) {
                            Ok(parsed) => {
                                predicate_expr = Some(parsed);
                                predicate_display = Some(expr.to_string());
                                eprintln!("Predicate set");
                            }
                            Err(err) => eprintln!("Invalid predicate: {}", err),
                        }
                    }
                    continue;
                }

                if query_line == "explain" {
                    eprintln!("Usage: explain <finding-id>");
                    continue;
                } else if let Some(arg) = query_line.strip_prefix("explain ") {
                    let finding_id = arg.trim();
                    if finding_id.is_empty() {
                        eprintln!("Usage: explain <finding-id>");
                    } else if let Err(err) =
                        run_explain(pdf_path, finding_id, config_path.as_deref())
                    {
                        eprintln!("Explain failed: {}", err);
                    }
                    continue;
                }
                if let Some(rest) = query_line.strip_prefix(":doc") {
                    handle_doc_command(rest.trim());
                    continue;
                }
                if query_line == "cache.info" {
                    print_repl_cache_info(&ctx);
                    continue;
                }

                match query_line {
                    "exit" | "quit" | ":q" => {
                        eprintln!("Goodbye!");
                        break;
                    }
                    "help" | ":help" | "?" => {
                        print_repl_help();
                        continue;
                    }
                    ":json" => {
                        json_mode = !json_mode;
                        if json_mode {
                            jsonl_mode = false;
                            yaml_mode = false;
                            readable_mode = false;
                        }
                        if !json_mode && !jsonl_mode && !yaml_mode {
                            readable_mode = true;
                        }
                        eprintln!("JSON mode: {}", if json_mode { "enabled" } else { "disabled" });
                        continue;
                    }
                    ":jsonl" => {
                        jsonl_mode = !jsonl_mode;
                        if jsonl_mode {
                            json_mode = true;
                            yaml_mode = false;
                            readable_mode = false;
                        }
                        if !jsonl_mode && !json_mode && !yaml_mode {
                            readable_mode = true;
                        }
                        eprintln!(
                            "JSONL mode: {}",
                            if jsonl_mode { "enabled" } else { "disabled" }
                        );
                        continue;
                    }
                    ":yaml" => {
                        yaml_mode = !yaml_mode;
                        if yaml_mode {
                            json_mode = false;
                            jsonl_mode = false;
                            readable_mode = false;
                        }
                        if !yaml_mode && !json_mode && !jsonl_mode {
                            readable_mode = true;
                        }
                        eprintln!("YAML mode: {}", if yaml_mode { "enabled" } else { "disabled" });
                        continue;
                    }
                    ":readable" => {
                        readable_mode = !readable_mode;
                        if readable_mode {
                            json_mode = false;
                            jsonl_mode = false;
                            yaml_mode = false;
                        }
                        eprintln!(
                            "Readable mode: {}",
                            if readable_mode { "enabled" } else { "disabled" }
                        );
                        continue;
                    }
                    ":colour" | ":color" => {
                        colour_mode = !colour_mode;
                        eprintln!(
                            "Colour mode: {}",
                            if colour_mode { "enabled" } else { "disabled" }
                        );
                        continue;
                    }
                    ":compact" => {
                        compact_mode = !compact_mode;
                        eprintln!(
                            "Compact mode: {}",
                            if compact_mode { "enabled" } else { "disabled" }
                        );
                        continue;
                    }
                    _ => {}
                }

                // Parse and execute query
                match query::parse_query(query_line) {
                    Ok(q) => {
                        let output_format = if yaml_mode {
                            query::OutputFormat::Yaml
                        } else if jsonl_mode {
                            query::OutputFormat::Jsonl
                        } else if json_mode {
                            query::OutputFormat::Json
                        } else if readable_mode {
                            query::OutputFormat::Readable
                        } else {
                            query::OutputFormat::Text
                        };
                        let q = match query::apply_output_format(q, output_format) {
                            Ok(resolved) => resolved,
                            Err(e) => {
                                eprintln!("Format error: {}", e);
                                continue;
                            }
                        };
                        match query::maybe_stream_raw_bytes(
                            &q,
                            &ctx,
                            decode_mode,
                            max_extract_bytes,
                        ) {
                            Ok(Some(bytes)) => {
                                match destination {
                                    ReplDestination::Stdout => {
                                        if let Err(err) = std::io::stdout().write_all(&bytes) {
                                            eprintln!("[stream] failed to write stdout: {}", err);
                                        }
                                    }
                                    ReplDestination::Pipe(cmd) => {
                                        match run_repl_pipeline(cmd.trim(), &bytes) {
                                            Ok((stdout, stderr, status)) => {
                                                if !stdout.is_empty() {
                                                    print!("{}", stdout);
                                                }
                                                if !stderr.is_empty() {
                                                    eprint!("{}", stderr);
                                                }
                                                if !status.success() {
                                                    let status_code = status
                                                        .code()
                                                        .map(|code| code.to_string())
                                                        .unwrap_or_else(|| "unknown".into());
                                                    eprintln!(
                                                        "[pipe] `{}` exited ({})",
                                                        cmd, status_code
                                                    );
                                                }
                                            }
                                            Err(err) => {
                                                eprintln!(
                                                    "[pipe] failed to run '{}': {}",
                                                    cmd, err
                                                );
                                            }
                                        }
                                    }
                                    ReplDestination::Redirect(path) => {
                                        if let Err(err) = std::fs::write(path.trim(), &bytes) {
                                            eprintln!(
                                                "[redirect] failed to write '{}': {}",
                                                path, err
                                            );
                                        }
                                    }
                                }
                                continue;
                            }
                            Ok(None) => {}
                            Err(err) => {
                                eprintln!("Query failed: {}", err);
                                continue;
                            }
                        }
                        match query::execute_query_with_context(
                            &q,
                            &ctx,
                            extract_to,
                            max_extract_bytes,
                            decode_mode,
                            predicate_expr.as_ref(),
                        ) {
                            Ok(result) => {
                                let result = query::apply_report_verbosity(
                                    &q,
                                    result,
                                    report_verbosity,
                                    output_format,
                                );
                                let result = query::apply_chain_summary(
                                    &q,
                                    result,
                                    chain_summary,
                                    output_format,
                                );
                                let formatted = match output_format {
                                    query::OutputFormat::Yaml => {
                                        match query::format_yaml(query_line, pdf_path, &result) {
                                            Ok(output) => maybe_colourise_output(
                                                output,
                                                query::OutputFormat::Yaml,
                                                colour_mode,
                                            ),
                                            Err(e) => {
                                                eprintln!("Error formatting result: {}", e);
                                                continue;
                                            }
                                        }
                                    }
                                    query::OutputFormat::Jsonl => {
                                        match query::format_jsonl(query_line, pdf_path, &result) {
                                            Ok(output) => output,
                                            Err(e) => {
                                                eprintln!("Error formatting result: {}", e);
                                                continue;
                                            }
                                        }
                                    }
                                    query::OutputFormat::Json => {
                                        match query::format_json(query_line, pdf_path, &result) {
                                            Ok(output) => maybe_colourise_output(
                                                output,
                                                query::OutputFormat::Json,
                                                colour_mode,
                                            ),
                                            Err(e) => {
                                                eprintln!("Error formatting result: {}", e);
                                                continue;
                                            }
                                        }
                                    }
                                    query::OutputFormat::Readable => {
                                        query::format_readable_result(&result, compact_mode)
                                    }
                                    query::OutputFormat::Text
                                    | query::OutputFormat::Csv
                                    | query::OutputFormat::Dot => {
                                        query::format_result(&result, compact_mode)
                                    }
                                };

                                match destination {
                                    ReplDestination::Stdout => println!("{}", formatted),
                                    ReplDestination::Pipe(cmd) => {
                                        match run_repl_pipeline(cmd.trim(), formatted.as_bytes()) {
                                            Ok((stdout, stderr, status)) => {
                                                if !stdout.is_empty() {
                                                    print!("{}", stdout);
                                                }
                                                if !stderr.is_empty() {
                                                    eprint!("{}", stderr);
                                                }
                                                if !status.success() {
                                                    let status_code = status
                                                        .code()
                                                        .map(|code| code.to_string())
                                                        .unwrap_or_else(|| "unknown".into());
                                                    eprintln!(
                                                        "[pipe] `{}` exited ({})",
                                                        cmd, status_code
                                                    );
                                                }
                                            }
                                            Err(err) => {
                                                eprintln!(
                                                    "[pipe] failed to run '{}': {}",
                                                    cmd, err
                                                );
                                                println!("{}", formatted);
                                            }
                                        }
                                    }
                                    ReplDestination::Redirect(path) => {
                                        if let Err(err) = std::fs::write(path.trim(), &formatted) {
                                            eprintln!(
                                                "[redirect] failed to write '{}': {}",
                                                path, err
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => eprintln!("Query failed: {}", e),
                        }
                    }
                    Err(e) => {
                        let error = query::query_syntax_error(format!("Invalid query: {}", e));
                        if yaml_mode {
                            match query::format_yaml(query_line, pdf_path, &error) {
                                Ok(output) => println!(
                                    "{}",
                                    maybe_colourise_output(
                                        output,
                                        query::OutputFormat::Yaml,
                                        colour_mode
                                    )
                                ),
                                Err(err) => eprintln!("Error formatting result: {}", err),
                            }
                        } else if jsonl_mode {
                            match query::format_jsonl(query_line, pdf_path, &error) {
                                Ok(output) => println!("{}", output),
                                Err(err) => eprintln!("Error formatting result: {}", err),
                            }
                        } else if json_mode {
                            match query::format_json(query_line, pdf_path, &error) {
                                Ok(output) => println!(
                                    "{}",
                                    maybe_colourise_output(
                                        output,
                                        query::OutputFormat::Json,
                                        colour_mode
                                    )
                                ),
                                Err(err) => eprintln!("Error formatting result: {}", err),
                            }
                        } else {
                            eprintln!("Invalid query: {}", e);
                        }
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl-C
                eprintln!("^C");
                continue;
            }
            Err(ReadlineError::Eof) => {
                // Ctrl-D
                eprintln!("Goodbye!");
                break;
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                break;
            }
        }
    }

    // Save history
    let _ = rl.save_history(&history_file);

    Ok(())
}

enum ReplDestination<'a> {
    Stdout,
    Pipe(&'a str),
    Redirect(&'a str),
}

fn split_repl_destination(line: &str) -> (&str, ReplDestination<'_>) {
    if let Some(idx) = line.find(['|', '>']) {
        let (primary, rest) = line.split_at(idx);
        let command = rest[1..].trim();
        let query = primary.trim_end();
        if command.is_empty() {
            return (query, ReplDestination::Stdout);
        }
        return match rest.chars().next().unwrap_or(' ') {
            '|' => (query, ReplDestination::Pipe(command)),
            '>' => (query, ReplDestination::Redirect(command)),
            _ => (line, ReplDestination::Stdout),
        };
    }
    (line, ReplDestination::Stdout)
}

fn run_repl_pipeline(command: &str, input: &[u8]) -> Result<(String, String, ExitStatus)> {
    let mut child = ProcessCommand::new("sh")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("failed to run pipeline '{}': {}", command, e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input)?;
        stdin.write_all(b"\n")?;
    }

    let output = child.wait_with_output()?;
    Ok((
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status,
    ))
}

fn print_repl_cache_info(ctx: &sis_pdf_core::scan::ScanContext<'_>) {
    let rendered = render_repl_cache_info(ctx.findings_cache_info());
    print!("{rendered}");
}

fn render_repl_cache_info(info: Option<sis_pdf_core::scan::FindingsCacheInfo>) -> String {
    if let Some(info) = info {
        format!(
            "findings_cache_populated: true\nfindings_cache_count: {}\nfindings_cache_fingerprint: {}\nfindings_cache_approx_bytes: {}\n",
            info.finding_count, info.option_fingerprint, info.approximate_bytes
        )
    } else {
        "findings_cache_populated: false\n".to_string()
    }
}

#[cfg(test)]
mod repl_tests {
    use super::*;
    use sis_pdf_core::scan::FindingsCacheInfo;

    #[test]
    fn split_repl_pipe_detects_command() {
        let (query, dest) = split_repl_destination("findings | jq .");
        assert_eq!(query, "findings");
        if let ReplDestination::Pipe(cmd) = dest {
            assert_eq!(cmd, "jq .");
        } else {
            panic!("expected pipe destination");
        }
    }

    #[test]
    fn split_repl_pipe_without_command() {
        let (query, dest) = split_repl_destination("findings");
        assert_eq!(query, "findings");
        assert!(matches!(dest, ReplDestination::Stdout));
    }

    #[test]
    fn split_repl_destination_redirect() {
        let (query, dest) = split_repl_destination("org > graph.dot");
        assert_eq!(query, "org");
        if let ReplDestination::Redirect(path) = dest {
            assert_eq!(path, "graph.dot");
        } else {
            panic!("expected redirect destination");
        }
    }

    #[test]
    fn run_repl_pipeline_invokes_shell() {
        let (stdout, stderr, status) = run_repl_pipeline("cat", b"hello").unwrap();
        assert_eq!(stdout.trim(), "hello");
        assert!(stderr.is_empty());
        assert!(status.success());
    }

    #[test]
    fn render_repl_cache_info_reports_empty_cache() {
        let rendered = render_repl_cache_info(None);
        assert_eq!(rendered, "findings_cache_populated: false\n");
    }

    #[test]
    fn render_repl_cache_info_reports_populated_cache() {
        let rendered = render_repl_cache_info(Some(FindingsCacheInfo {
            finding_count: 12,
            option_fingerprint: 42,
            approximate_bytes: 4096,
        }));
        assert!(rendered.contains("findings_cache_populated: true"));
        assert!(rendered.contains("findings_cache_count: 12"));
        assert!(rendered.contains("findings_cache_fingerprint: 42"));
        assert!(rendered.contains("findings_cache_approx_bytes: 4096"));
    }
}

fn print_repl_help() {
    println!("Query Interface Help:");
    println!();
    println!("Metadata queries:");
    println!("  pages              - Page count");
    println!("  version            - PDF version");
    println!("  creator            - Creator metadata");
    println!("  producer           - Producer metadata");
    println!("  title              - Document title");
    println!("  created            - Creation date");
    println!("  modified           - Modification date");
    println!("  encrypted          - Encryption status");
    println!("  filesize           - File size in bytes");
    println!("  objects            - Object count");
    println!();
    println!("Content queries:");
    println!("  js                 - Extract JavaScript");
    println!("  js.count           - JavaScript count");
    println!("  urls               - Extract URLs");
    println!("  urls.count         - URL count");
    println!("  embedded           - List embedded files");
    println!("  embedded.count     - Embedded file count");
    println!("  images             - List images");
    println!("  images.count       - Image count");
    println!("  images.<filter>    - JBIG2/JPEG2000/CCITT variants (options: [jbig2, jpx, ccitt])");
    println!("  images.risky       - Risky image formats");
    println!("  images.malformed   - Malformed image decodes (requires --deep)");
    println!();
    println!("REPL commands:");
    println!("  cache.info         - Show findings cache status");
    println!();
    println!("Finding queries:");
    println!("  findings           - List all findings");
    println!("  findings.count     - Finding count");
    println!("  findings.<severity> - Findings of level [info, low, medium, high, critical]");
    println!("  findings.kind KIND - Findings of specific kind");
    println!();
    println!("Event trigger queries:");
    println!("  events             - List all event triggers");
    println!("  events.count       - Event trigger count");
    println!(
        "  events.<level>     - Document/page/field events (options: [document, page, field])"
    );
    println!();
    println!("Object inspection queries:");
    println!("  object N           - Show object N (generation 0)");
    println!("  object N G         - Show object N generation G");
    println!("  stream N G         - Extract stream object N G (requires --extract-to)");
    println!("  objects.list       - List all object IDs");
    println!("  objects.with TYPE  - Filter objects by type (e.g., Page, Font)");
    println!("  trailer            - Show PDF trailer");
    println!("  catalog            - Show PDF catalog");
    println!(
        "  xref               - Summarise startxrefs, sections, trailers, and xref deviations"
    );
    println!("  xref.startxrefs    - List startxref markers");
    println!("  xref.sections      - List parsed xref chain sections");
    println!("  xref.trailers      - List trailer dictionary summaries");
    println!("  xref.deviations    - List xref parser deviations");
    println!("  revisions          - List revision summaries derived from xref/trailer state");
    println!(
        "  revisions.detail   - Detailed revision timeline with per-revision structural diffs"
    );
    println!();
    println!("Advanced queries:");
    println!("  chains             - Describe action chains (rich JSON output)");
    println!("  chains.js          - JavaScript action chains with edge details");
    println!("  cycles             - Document reference cycles");
    println!("  cycles.page        - Page tree cycles");
    println!("  ref OBJ GEN        - Incoming references for an object (generation optional)");
    println!();
    println!("Graph exports:");
    println!("  org                - Export ORG graph (dot/text output, use :json for JSON, :readable for dot)");
    println!(
        "  graph.event        - Export event graph with outcomes (dot/text output, use :json for JSON)"
    );
    println!("  ir                 - Export intent graph (text output, use :json for JSON)");
    println!();
    println!("REPL commands:");
    println!("  :json              - Toggle JSON output mode");
    println!("  :jsonl             - Toggle JSONL output mode");
    println!("  :yaml              - Toggle YAML output mode");
    println!("  :colour            - Toggle colourised JSON/YAML output");
    println!("  :compact           - Toggle compact output mode");
    println!("  :readable          - Toggle readable output mode (default)");
    println!("  queries can append '| command' to pipe current output to the shell or '> file' to save it (e.g., findings | jq . or org > graph.dot)");
    println!("  :where EXPR        - Set predicate filter");
    println!("  :where             - Show current predicate");
    println!("  :where clear       - Clear predicate filter");
    println!("  explain ID         - Run `sis explain` for the specified finding ID");
    println!("  :doc TOPIC         - Show the fixit doc path and description (topics: filter-flatedecode, objstm)");
    println!("  help / ?           - Show this help");
    println!("  exit / quit / :q   - Exit REPL");
    println!();
}

fn handle_doc_command(topic: &str) {
    if topic.is_empty() {
        eprintln!("Doc topics: filter-flatedecode, objstm");
        return;
    }
    match doc_topic_info(topic) {
        Some((desc, path)) => {
            eprintln!("Doc [{}]: {}", topic, path);
            eprintln!("{}", desc);
        }
        None => {
            eprintln!("Unknown doc topic '{}'; available: filter-flatedecode, objstm", topic);
        }
    }
}

fn doc_topic_info(topic: &str) -> Option<(&'static str, &'static str)> {
    match topic {
        "filter-flatedecode" => Some((
            "Explains `/FlateDecode` decoding heuristics and reporting. Useful for interpreting declared filter errors.",
            "docs/filter-flatedecode.md",
        )),
        "objstm" => Some((
            "Summarizes ObjStm embedded object behavior and why deep scans surface the embedded payloads.",
            "docs/findings.md#objstm_embedded_summary",
        )),
        _ => None,
    }
}

fn print_filter_allowlist() -> Result<()> {
    let toml = default_filter_allowlist_toml()?;
    println!("{}", toml.trim_end());
    Ok(())
}

fn apply_filter_allowlist_options(
    opts: &mut sis_pdf_core::scan::ScanOptions,
    filter_allowlist: Option<&std::path::Path>,
    filter_allowlist_strict: bool,
) -> Result<()> {
    if filter_allowlist_strict {
        opts.filter_allowlist_strict = true;
    }
    if let Some(path) = filter_allowlist {
        opts.filter_allowlist = Some(load_filter_allowlist(path)?);
    }
    Ok(())
}

fn run_scan(
    pdf: Option<&str>,
    path: Option<&std::path::Path>,
    glob: &str,
    deep: bool,
    max_decode_bytes: usize,
    max_total_decoded_bytes: usize,
    recover_xref: bool,
    group_chains: bool,
    json: bool,
    focused_triage: bool,
    jsonl: bool,
    jsonl_findings: bool,
    sarif: bool,
    sarif_out: Option<&std::path::Path>,
    export_intents: bool,
    export_intents_out: Option<&std::path::Path>,
    intents_derived: bool,
    yara: bool,
    yara_out: Option<&std::path::Path>,
    yara_scope: &str,
    diff_parser: bool,
    fast: bool,
    focus_trigger: Option<String>,
    focus_depth: usize,
    strict: bool,
    strict_summary: bool,
    ir: bool,
    max_objects: usize,
    max_recursion_depth: usize,
    config: Option<&std::path::Path>,
    profile: Option<&str>,
    filter_allowlist: Option<&std::path::Path>,
    filter_allowlist_strict: bool,
    cache_dir: Option<&std::path::Path>,
    sequential: bool,
    runtime_profile: bool,
    runtime_profile_format: &str,
    ml: bool,
    ml_model_dir: Option<&std::path::Path>,
    ml_threshold: f32,
    ml_mode: &str,
    ml_extended_features: bool,
    ml_explain: bool,
    ml_advanced: bool,
    ml_temporal: bool,
    temporal_signals: bool,
    ml_baseline: Option<&std::path::Path>,
    ml_calibration: Option<&std::path::Path>,
    ml_provider: Option<&str>,
    ml_provider_order: Option<&str>,
    ml_provider_info: bool,
    ml_ort_dylib: Option<&std::path::Path>,
    ml_quantized: bool,
    ml_batch_size: Option<usize>,
    js_ast: bool,
    js_sandbox: bool,
    image_analysis_enabled: bool,
    image_dynamic_enabled: bool,
    font_signatures_enabled: bool,
    font_signature_dir: Option<&std::path::Path>,
) -> Result<()> {
    if path.is_some() && pdf.is_some() {
        return Err(anyhow!("provide either a PDF path or --path, not both"));
    }
    if strict_summary && !strict {
        return Err(anyhow!("--strict-summary requires --strict"));
    }
    let diff_parser = diff_parser || strict;
    if diff_parser && strict {
        SecurityEvent {
            level: Level::INFO,
            domain: SecurityDomain::Parser,
            severity: SecuritySeverity::Info,
            kind: "diff_parser_enabled",
            policy: None,
            object_id: None,
            object_type: None,
            vector: None,
            technique: None,
            confidence: None,
            fatal: false,
            message: "Enabling diff parser in strict mode",
        }
        .emit();
        info!(strict = true, diff_parser = true, "Diff parser enabled for strict mode");
    }
    let mut opts = sis_pdf_core::scan::ScanOptions {
        deep,
        max_decode_bytes,
        max_total_decoded_bytes,
        recover_xref,
        parallel: false,
        batch_parallel: !sequential,
        diff_parser,
        max_objects,
        max_recursion_depth,
        fast,
        focus_trigger,
        focus_depth,
        yara_scope: Some(yara_scope.to_string()),
        strict,
        strict_summary,
        ir,
        ml_config: None,
        font_analysis: sis_pdf_core::scan::FontAnalysisOptions {
            enabled: true,
            dynamic_enabled: false,
            dynamic_timeout_ms: 120,
            max_fonts: 32, // Reduced from 256 to limit analysis time
            signature_matching_enabled: font_signatures_enabled,
            signature_directory: font_signature_dir.map(|p| p.to_string_lossy().to_string()),
        },
        image_analysis: sis_pdf_core::scan::ImageAnalysisOptions {
            enabled: image_analysis_enabled,
            dynamic_enabled: image_analysis_enabled && image_dynamic_enabled,
            ..sis_pdf_core::scan::ImageAnalysisOptions::default()
        },
        filter_allowlist: None,
        filter_allowlist_strict: false,
        profile: runtime_profile,
        profile_format: match runtime_profile_format {
            "json" => sis_pdf_core::scan::ProfileFormat::Json,
            _ => sis_pdf_core::scan::ProfileFormat::Text,
        },
        group_chains,
        correlation: CorrelationOptions::default(),
    };
    let runtime_overrides = build_ml_runtime_config(
        ml_provider,
        ml_provider_order,
        ml_provider_info,
        ml_ort_dylib,
        ml_quantized,
        ml_batch_size,
    );
    if let Some(path) = config {
        let cfg = sis_pdf_core::config::Config::load(path)?;
        cfg.apply(&mut opts, profile);
    }
    apply_filter_allowlist_options(&mut opts, filter_allowlist, filter_allowlist_strict)?;
    if ml {
        let model_dir = ml_model_dir.ok_or_else(|| anyhow!("--ml requires --ml-model-dir"))?;
        opts.ml_config = Some(sis_pdf_core::ml::MlConfig {
            model_path: model_dir.to_path_buf(),
            threshold: ml_threshold,
            mode: parse_ml_mode(ml_mode),
            runtime: runtime_overrides.clone(),
        });
    } else if let Some(dir) = ml_model_dir {
        opts.ml_config = Some(sis_pdf_core::ml::MlConfig {
            model_path: dir.to_path_buf(),
            threshold: ml_threshold,
            mode: parse_ml_mode(ml_mode),
            runtime: runtime_overrides.clone(),
        });
    }
    if let Some(cfg) = opts.ml_config.as_mut() {
        apply_ml_runtime_overrides(&mut cfg.runtime, &runtime_overrides);
        if cfg.runtime.print_provider {
            log_ml_provider_info(&cfg.runtime)?;
        }
    }
    let want_export_intents = export_intents || export_intents_out.is_some();
    let detectors =
        sis_pdf_detectors::default_detectors_with_settings(sis_pdf_detectors::DetectorSettings {
            js_ast,
            js_sandbox,
        });
    let ml_inference_requested = ml_extended_features
        || ml_explain
        || ml_advanced
        || ml_temporal
        || ml_baseline.is_some()
        || ml_calibration.is_some();
    let temporal_requested = temporal_signals || ml_temporal;
    if let Some(dir) = path {
        if ml_inference_requested || temporal_requested {
            return Err(anyhow!("ML inference is not supported for batch scans"));
        }
        let batch_parallel = opts.batch_parallel;
        return run_scan_batch(
            dir,
            glob,
            opts,
            &detectors,
            json,
            focused_triage,
            jsonl,
            jsonl_findings,
            sarif,
            sarif_out,
            want_export_intents,
            export_intents_out,
            intents_derived,
            yara,
            yara_out,
            cache_dir,
            batch_parallel,
        );
    }
    let pdf = pdf.ok_or_else(|| anyhow!("PDF path is required unless --path is set"))?;
    let bytes = read_pdf_bytes(pdf)?;
    let sandbox_summary = sis_pdf_detectors::sandbox_summary(js_sandbox);
    let mut report =
        run_scan_single(&bytes, pdf, &opts, &detectors)?.with_sandbox_summary(sandbox_summary);
    if focused_triage {
        sis_pdf_core::report::apply_focused_triage(&mut report);
    }
    if ml_inference_requested {
        match run_ml_inference_for_scan(
            &bytes,
            &opts,
            &report,
            ml_model_dir,
            ml_threshold,
            ml_extended_features,
            ml_explain,
            ml_advanced,
            ml_baseline,
            ml_calibration,
        ) {
            Ok(ml_result) => {
                report = report.with_ml_inference(Some(ml_result));
            }
            Err(err) => {
                warn!(error = %err, "ML inference failed");
            }
        }
    }
    if temporal_requested {
        let (temporal_summary, temporal_snapshots, temporal_explanation) = run_temporal_analysis(
            &bytes,
            &opts,
            &detectors,
            ml_model_dir,
            ml_threshold,
            ml_extended_features,
            ml_explain,
            ml_baseline,
            ml_calibration,
            ml_temporal,
        )?;
        report = report
            .with_temporal_signals(temporal_summary)
            .with_temporal_snapshots(temporal_snapshots);
        if let (Some(ml), Some(explanation)) = (report.ml_inference.as_mut(), temporal_explanation)
        {
            if let Some(expl) = ml.explanation.as_mut() {
                expl.temporal_analysis = Some(explanation);
            }
        }
    }
    if want_export_intents {
        let mut writer: Box<dyn Write> = if let Some(path) = export_intents_out {
            Box::new(fs::File::create(path)?)
        } else {
            Box::new(std::io::stdout())
        };
        write_intents_jsonl(&report, writer.as_mut(), intents_derived)?;
        return Ok(());
    }
    let want_sarif = sarif || sarif_out.is_some();
    let want_yara = yara || yara_out.is_some();
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if jsonl_findings {
        sis_pdf_core::report::print_jsonl_findings(&report)?;
    } else if jsonl {
        sis_pdf_core::report::print_jsonl(&report)?;
    } else if want_sarif {
        let v = sis_pdf_core::sarif::to_sarif(&report, Some(pdf));
        let data = serde_json::to_string_pretty(&v)?;
        if let Some(path) = sarif_out {
            fs::write(path, data)?;
        } else {
            println!("{}", data);
        }
    } else {
        sis_pdf_core::report::print_human(&report);
    }
    if want_yara {
        let rules = sis_pdf_core::yara::render_rules(&report.yara_rules);
        println!("YARA summary: {} rule(s)", report.yara_rules.len());
        if let Some(path) = yara_out {
            fs::write(path, rules)?;
        } else {
            println!("{}", rules);
        }
    }
    Ok(())
}

fn build_scan_context<'a>(
    mmap: &'a [u8],
    opts: &sis_pdf_core::scan::ScanOptions,
) -> Result<sis_pdf_core::scan::ScanContext<'a>> {
    let graph = sis_pdf_pdf::parse_pdf(
        mmap,
        sis_pdf_pdf::ParseOptions {
            recover_xref: opts.recover_xref,
            deep: opts.deep,
            strict: opts.strict,
            max_objstm_bytes: opts.max_decode_bytes,
            max_objects: opts.max_objects,
            max_objstm_total_bytes: opts.max_total_decoded_bytes,
            carve_stream_objects: false,
            max_carved_objects: 0,
            max_carved_bytes: 0,
        },
    )?;
    Ok(sis_pdf_core::scan::ScanContext::new(mmap, graph, opts.clone()))
}

fn run_ml_inference_for_scan(
    mmap: &[u8],
    opts: &sis_pdf_core::scan::ScanOptions,
    report: &sis_pdf_core::report::Report,
    ml_model_dir: Option<&std::path::Path>,
    ml_threshold: f32,
    ml_extended_features: bool,
    ml_explain: bool,
    ml_advanced: bool,
    ml_baseline: Option<&std::path::Path>,
    ml_calibration: Option<&std::path::Path>,
) -> Result<sis_pdf_core::ml_inference::MlInferenceResult> {
    let model_path =
        ml_model_dir.ok_or_else(|| anyhow!("--ml-model-dir is required for ML inference"))?;
    if ml_advanced && !ml_explain {
        return Err(anyhow!("--ml-advanced requires --ml-explain"));
    }
    if ml_explain && ml_baseline.is_none() {
        return Err(anyhow!("--ml-explain requires --ml-baseline"));
    }
    let config = sis_pdf_core::ml_inference::MlInferenceConfig {
        model_path: model_path.to_path_buf(),
        baseline_path: ml_baseline.map(|p| p.to_path_buf()),
        calibration_path: ml_calibration.map(|p| p.to_path_buf()),
        threshold: ml_threshold,
        explain: ml_explain,
        use_extended_features: ml_extended_features || ml_explain || ml_baseline.is_some(),
        explain_advanced: ml_advanced,
    };
    let ctx = build_scan_context(mmap, opts)?;
    sis_pdf_core::ml_inference::run_ml_inference(&ctx, &report.findings, &config)
}

fn run_temporal_analysis(
    mmap: &[u8],
    opts: &sis_pdf_core::scan::ScanOptions,
    detectors: &[Box<dyn sis_pdf_core::detect::Detector>],
    ml_model_dir: Option<&std::path::Path>,
    ml_threshold: f32,
    ml_extended_features: bool,
    ml_explain: bool,
    ml_baseline: Option<&std::path::Path>,
    ml_calibration: Option<&std::path::Path>,
    ml_temporal: bool,
) -> Result<(
    Option<sis_pdf_core::report::TemporalSignalSummary>,
    Option<Vec<sis_pdf_core::explainability::TemporalSnapshot>>,
    Option<sis_pdf_core::explainability::TemporalExplanation>,
)> {
    let mut opts_temporal = opts.clone();
    opts_temporal.ml_config = None;
    let scans = sis_pdf_core::temporal::build_versioned_scans(mmap, &opts_temporal, detectors)?;
    let temporal_summary = Some(sis_pdf_core::temporal::build_temporal_signal_summary(&scans));

    if !ml_temporal {
        return Ok((temporal_summary, None, None));
    }
    if !ml_explain {
        return Err(anyhow!("--ml-temporal requires --ml-explain"));
    }
    let model_path = ml_model_dir
        .ok_or_else(|| anyhow!("--ml-model-dir is required for ML temporal analysis"))?;
    let baseline_path =
        ml_baseline.ok_or_else(|| anyhow!("--ml-temporal requires --ml-baseline"))?;

    let config = sis_pdf_core::ml_inference::MlInferenceConfig {
        model_path: model_path.to_path_buf(),
        baseline_path: Some(baseline_path.to_path_buf()),
        calibration_path: ml_calibration.map(|p| p.to_path_buf()),
        threshold: ml_threshold,
        explain: false,
        use_extended_features: ml_extended_features || ml_baseline.is_some(),
        explain_advanced: false,
    };

    let mut snapshots = Vec::new();
    for scan in &scans {
        let inference = sis_pdf_core::ml_inference::run_ml_inference(
            &scan.context,
            &scan.report.findings,
            &config,
        )?;
        let high_severity = scan
            .report
            .findings
            .iter()
            .filter(|f| {
                matches!(
                    f.severity,
                    sis_pdf_core::model::Severity::High | sis_pdf_core::model::Severity::Critical
                )
            })
            .count();
        snapshots.push(sis_pdf_core::explainability::TemporalSnapshot {
            version_label: scan.label.clone(),
            score: inference.prediction.calibrated_score,
            high_severity_count: high_severity,
            finding_count: scan.report.findings.len(),
        });
    }

    let temporal_explanation =
        Some(sis_pdf_core::explainability::analyse_temporal_risk(&snapshots));

    Ok((temporal_summary, Some(snapshots), temporal_explanation))
}

fn run_scan_single(
    bytes: &[u8],
    pdf: &str,
    opts: &sis_pdf_core::scan::ScanOptions,
    detectors: &[Box<dyn sis_pdf_core::detect::Detector>],
) -> Result<sis_pdf_core::report::Report> {
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts.clone(), detectors)?
        .with_input_path(Some(pdf.to_string()));
    Ok(report)
}
fn write_intents_jsonl(
    report: &sis_pdf_core::report::Report,
    writer: &mut dyn Write,
    intents_derived: bool,
) -> Result<()> {
    let path = report.input_path.as_deref().unwrap_or("-");
    let intents = if intents_derived {
        let options = sis_pdf_core::campaign::IntentExtractionOptions {
            include_domains: true,
            include_obfuscated: true,
            include_scheme_less: true,
        };
        sis_pdf_core::campaign::extract_network_intents_from_findings(&report.findings, &options)
    } else {
        report.network_intents.clone()
    };
    for intent in intents {
        let record = serde_json::json!({
            "path": path,
            "url": intent.url,
            "domain": intent.domain,
        });
        writer.write_all(serde_json::to_string(&record)?.as_bytes())?;
        writer.write_all(b"\n")?;
    }
    Ok(())
}
fn run_scan_batch(
    dir: &std::path::Path,
    glob: &str,
    opts: sis_pdf_core::scan::ScanOptions,
    detectors: &[Box<dyn sis_pdf_core::detect::Detector>],
    json: bool,
    focused_triage: bool,
    jsonl: bool,
    jsonl_findings: bool,
    sarif: bool,
    sarif_out: Option<&std::path::Path>,
    export_intents: bool,
    export_intents_out: Option<&std::path::Path>,
    intents_derived: bool,
    yara: bool,
    yara_out: Option<&std::path::Path>,
    cache_dir: Option<&std::path::Path>,
    batch_parallel: bool,
) -> Result<()> {
    if sarif || sarif_out.is_some() {
        return Err(anyhow!("SARIF output is not supported for batch scans"));
    }
    if yara || yara_out.is_some() {
        return Err(anyhow!("YARA output is not supported for batch scans"));
    }
    let cache = if let Some(dir) = cache_dir {
        Some(Arc::new(sis_pdf_core::cache::ScanCache::new(dir)?))
    } else {
        None
    };
    let matcher = Glob::new(glob)?.compile_matcher();
    let intent_writer: Option<Arc<Mutex<Box<dyn Write + Send>>>> = if export_intents {
        let writer: Box<dyn Write + Send> = if let Some(path) = export_intents_out {
            Box::new(fs::File::create(path)?)
        } else {
            Box::new(std::io::stdout())
        };
        Some(Arc::new(Mutex::new(writer)))
    } else {
        None
    };
    let findings_writer: Option<Arc<Mutex<Box<dyn Write + Send>>>> = if jsonl_findings {
        let writer: Box<dyn Write + Send> = Box::new(std::io::stdout());
        Some(Arc::new(Mutex::new(writer)))
    } else {
        None
    };
    let iter = if dir.is_file() {
        WalkDir::new(dir.parent().unwrap_or(dir)).follow_links(false).max_depth(MAX_WALK_DEPTH)
    } else {
        WalkDir::new(dir).follow_links(false).max_depth(MAX_WALK_DEPTH)
    };
    let mut total_bytes = 0u64;
    let mut file_count = 0usize;
    let mut paths = Vec::new();
    for entry in iter.into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if !matcher.is_match(path) {
            continue;
        }
        file_count += 1;
        if file_count > MAX_BATCH_FILES {
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
                message: "Batch scan file count exceeded",
            }
            .emit();
            error!(max_files = MAX_BATCH_FILES, "Batch scan file count exceeded");
            return Err(anyhow!("batch file count exceeds limit"));
        }
        if let Ok(meta) = entry.metadata() {
            total_bytes = total_bytes.saturating_add(meta.len());
            if total_bytes > MAX_BATCH_BYTES {
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
                    message: "Batch scan byte limit exceeded",
                }
                .emit();
                error!(
                    total_bytes = total_bytes,
                    max_bytes = MAX_BATCH_BYTES,
                    "Batch scan byte limit exceeded"
                );
                return Err(anyhow!("batch size exceeds limit"));
            }
        }
        paths.push(path.to_path_buf());
    }
    if paths.is_empty() {
        return Err(anyhow!("no files matched {} in {}", glob, dir.display()));
    }
    let thread_count = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let use_parallel = batch_parallel && thread_count > 1 && paths.len() > 1;
    let indexed_paths: Vec<(usize, PathBuf)> = paths.into_iter().enumerate().collect();
    let process_path = |path: &PathBuf| -> Result<sis_pdf_core::report::BatchEntry> {
        let path_str = path.display().to_string();
        let start = std::time::Instant::now();
        let bytes = read_pdf_bytes(&path_str)?;
        let hash = sha256_hex(&bytes);
        let mut report = if let Some(cache) = &cache { cache.load(&hash) } else { None };
        if report.is_none() {
            report = Some(
                sis_pdf_core::runner::run_scan_with_detectors(&bytes, opts.clone(), detectors)?
                    .with_input_path(Some(path_str.clone())),
            );
            if let (Some(cache), Some(report)) = (&cache, report.as_ref()) {
                let _ = cache.store(&hash, report);
            }
        } else if let Some(rep) = report.take() {
            report = Some(rep.with_input_path(Some(path_str.clone())));
        }
        let report = report.ok_or_else(|| anyhow!("report not produced for {}", path.display()))?;
        let mut report = report;
        if focused_triage {
            sis_pdf_core::report::apply_focused_triage(&mut report);
        }
        if let Some(writer) = intent_writer.as_ref() {
            let mut guard = writer.lock().map_err(|_| anyhow!("intent writer lock poisoned"))?;
            write_intents_jsonl(&report, guard.as_mut(), intents_derived)?;
        }
        if let Some(writer) = findings_writer.as_ref() {
            let mut guard = writer.lock().map_err(|_| anyhow!("findings writer lock poisoned"))?;
            sis_pdf_core::report::write_jsonl_findings(&report, guard.as_mut())?;
        }
        let duration_ms = start.elapsed().as_millis() as u64;
        let detection_duration_ms = report.detection_duration_ms;
        let summary = report.summary;
        let js_emulation_breakpoint_buckets =
            sis_pdf_core::report::js_emulation_breakpoint_bucket_counts(&report.findings);
        let js_script_timeout_findings =
            sis_pdf_core::report::js_script_timeout_finding_count(&report.findings);
        let js_loop_iteration_limit_hits =
            sis_pdf_core::report::js_loop_iteration_limit_hit_count(&report.findings);
        let js_runtime_error_findings =
            sis_pdf_core::report::js_runtime_error_finding_count(&report.findings);
        Ok(sis_pdf_core::report::BatchEntry {
            path: path_str,
            duration_ms,
            summary,
            detection_duration_ms,
            js_emulation_breakpoint_buckets,
            js_script_timeout_findings,
            js_loop_iteration_limit_hits,
            js_runtime_error_findings,
        })
    };
    let mut entries: Vec<(usize, sis_pdf_core::report::BatchEntry)> = if use_parallel {
        let pool = ThreadPoolBuilder::new()
            .num_threads(thread_count)
            .stack_size(BATCH_WORKER_STACK_SIZE)
            .build();
        match pool {
            Ok(pool) => pool.install(|| {
                indexed_paths
                    .par_iter()
                    .map(|(idx, path)| process_path(path).map(|entry| (*idx, entry)))
                    .collect::<Result<Vec<_>>>()
            })?,
            Err(err) => {
                SecurityEvent {
                    level: Level::WARN,
                    domain: SecurityDomain::Detection,
                    severity: SecuritySeverity::Low,
                    kind: "batch_pool_fallback",
                    policy: None,
                    object_id: None,
                    object_type: None,
                    vector: None,
                    technique: None,
                    confidence: None,
                    fatal: false,
                    message: "Failed to build batch worker pool; falling back to sequential",
                }
                .emit();
                warn!(error = %err, "Failed to build batch worker pool; falling back to sequential");
                indexed_paths
                    .iter()
                    .map(|(idx, path)| process_path(path).map(|entry| (*idx, entry)))
                    .collect::<Result<Vec<_>>>()?
            }
        }
    } else {
        indexed_paths
            .iter()
            .map(|(idx, path)| process_path(path).map(|entry| (*idx, entry)))
            .collect::<Result<Vec<_>>>()?
    };
    entries.sort_by_key(|(idx, _)| *idx);
    let mut summary =
        sis_pdf_core::report::Summary { total: 0, high: 0, medium: 0, low: 0, info: 0 };
    let mut timing_total_ms = 0u64;
    let mut timing_max_ms = 0u64;
    let entries: Vec<sis_pdf_core::report::BatchEntry> = entries
        .into_iter()
        .map(|(_, entry)| {
            timing_total_ms = timing_total_ms.saturating_add(entry.duration_ms);
            timing_max_ms = timing_max_ms.max(entry.duration_ms);
            summary.total += entry.summary.total;
            summary.high += entry.summary.high;
            summary.medium += entry.summary.medium;
            summary.low += entry.summary.low;
            summary.info += entry.summary.info;
            entry
        })
        .collect();
    if export_intents {
        return Ok(());
    }
    if jsonl_findings {
        return Ok(());
    }
    let avg_ms = if entries.is_empty() { 0 } else { timing_total_ms / entries.len() as u64 };
    let batch = sis_pdf_core::report::BatchReport {
        summary,
        entries,
        timing: sis_pdf_core::report::BatchTiming {
            total_ms: timing_total_ms,
            avg_ms,
            max_ms: timing_max_ms,
        },
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&batch)?);
        return Ok(());
    }
    if jsonl {
        for entry in &batch.entries {
            println!("{}", serde_json::to_string(entry)?);
        }
        return Ok(());
    }
    let md = sis_pdf_core::report::render_batch_markdown(&batch);
    println!("{}", md);
    Ok(())
}
fn run_explain(pdf: &str, finding_id: &str, config: Option<&std::path::Path>) -> Result<()> {
    let bytes = read_pdf_bytes(pdf)?;
    let mut opts = sis_pdf_core::scan::ScanOptions {
        strict: false,
        strict_summary: false,
        ir: false,
        deep: true,
        max_decode_bytes: 32 * 1024 * 1024,
        max_total_decoded_bytes: 256 * 1024 * 1024,
        recover_xref: true,
        parallel: false,
        batch_parallel: false,
        diff_parser: false,
        max_objects: 500_000,
        max_recursion_depth: 64,
        fast: false,
        focus_trigger: None,
        focus_depth: 0,
        yara_scope: None,
        ml_config: None,
        font_analysis: sis_pdf_core::scan::FontAnalysisOptions::default(),
        image_analysis: sis_pdf_core::scan::ImageAnalysisOptions::default(),
        filter_allowlist: None,
        filter_allowlist_strict: false,
        profile: false,
        profile_format: sis_pdf_core::scan::ProfileFormat::Text,
        group_chains: true,
        correlation: CorrelationOptions::default(),
    };
    if let Some(path) = config {
        let cfg = sis_pdf_core::config::Config::load(path)?;
        cfg.apply(&mut opts, None);
    }
    let detectors = sis_pdf_detectors::default_detectors();
    let sandbox_summary = sis_pdf_detectors::sandbox_summary(true);
    let report = sis_pdf_core::runner::run_scan_with_detectors(&bytes, opts, &detectors)?
        .with_input_path(Some(pdf.to_string()))
        .with_sandbox_summary(sandbox_summary);
    let resolved_id = resolve_explain_finding_id(&report.findings, finding_id);
    let Some(finding) =
        resolved_id.as_deref().and_then(|id| report.findings.iter().find(|f| f.id == id))
    else {
        return Err(anyhow!("finding id not found; the scan that produced this ID may have been run with a different configuration (rerun this explain with the same --config or default settings)."));
    };
    println!("{} - {}", escape_terminal(&finding.id), escape_terminal(&finding.title));
    println!("{}", escape_terminal(&finding.description));
    println!("Severity: {:?}  Confidence: {:?}", finding.severity, finding.confidence);
    if let Some(keywords) =
        finding.meta.get("content.phishing_keywords").or_else(|| finding.meta.get("keyword"))
    {
        println!("Matched keywords: {}", escape_terminal(keywords));
    }
    if let Some(value) = finding.meta.get("js.runtime.calls") {
        println!("Runtime calls: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.replay_id") {
        println!("Runtime replay ID: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.ordering") {
        println!("Runtime ordering: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.profile") {
        println!("Runtime profile: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.call_args") {
        println!("Runtime call args: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.urls") {
        println!("Runtime URLs: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.domains") {
        println!("Runtime domains: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.prop_reads") {
        println!("Runtime property reads: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.prop_writes") {
        println!("Runtime property writes: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.prop_deletes") {
        println!("Runtime property deletes: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.reflection_probes") {
        println!("Runtime reflection probes: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.dynamic_code_calls") {
        println!("Runtime dynamic code calls: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.errors") {
        println!("Runtime errors: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.call_count") {
        println!("Runtime call count: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.unique_calls") {
        println!("Runtime unique calls: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.unique_prop_reads") {
        println!("Runtime unique property reads: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.phase_order") {
        println!("Runtime phase order: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.phase_count") {
        println!("Runtime phase count: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.phase_summaries") {
        println!("Runtime phase summaries: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.profile_count") {
        println!("Runtime profile count: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.profile_executed_count") {
        println!("Runtime profile executed: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.profile_divergence") {
        println!("Runtime profile divergence: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.script_timeout_profiles") {
        println!("Runtime timeout profiles: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.timeout_profile") {
        println!("Runtime timeout profile: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.timeout_phase") {
        println!("Runtime timeout phase: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.timeout_elapsed_ms") {
        println!("Runtime timeout elapsed (ms): {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.timeout_budget_ratio") {
        println!("Runtime timeout budget ratio: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.timeout_contexts") {
        println!("Runtime timeout contexts: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.script_timeout_ratio") {
        println!("Runtime timeout ratio: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.loop_iteration_limit_hits") {
        println!("Runtime loop iteration limit hits: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.profile_status") {
        println!("Runtime profile status: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.profile_consistency_signal") {
        println!("Runtime consistency signal: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.profile_consistency_ratio") {
        println!("Runtime consistency ratio: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.profile_severity_adjusted") {
        println!("Runtime severity adjusted: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.profile_confidence_adjusted") {
        println!("Runtime confidence adjusted: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.timeout_confidence_adjusted") {
        println!("Runtime timeout confidence adjusted: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.truncation.calls_dropped") {
        println!("Runtime calls dropped: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.truncation.call_args_dropped") {
        println!("Runtime call args dropped: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.truncation.prop_reads_dropped") {
        println!("Runtime property reads dropped: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.truncation.errors_dropped") {
        println!("Runtime errors dropped: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.truncation.urls_dropped") {
        println!("Runtime URLs dropped: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.runtime.truncation.domains_dropped") {
        println!("Runtime domains dropped: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.delta.phase") {
        println!("Runtime delta phase: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.delta.trigger_calls") {
        println!("Runtime delta trigger calls: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.delta.generated_snippets") {
        println!("Runtime generated snippets: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.delta.added_identifier_count") {
        println!("Runtime delta added identifiers: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.delta.added_string_literal_count") {
        println!("Runtime delta added string literals: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.delta.added_call_count") {
        println!("Runtime delta added calls: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.delta.new_identifiers") {
        println!("Runtime delta new identifiers: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.delta.new_string_literals") {
        println!("Runtime delta new string literals: {}", escape_terminal(value));
    }
    if let Some(value) = finding.meta.get("js.delta.new_calls") {
        println!("Runtime delta new calls: {}", escape_terminal(value));
    }
    print_finding_context_hints(&finding.meta);
    println!();
    for ev in &finding.evidence {
        println!(
            "Evidence: source={:?} offset={} length={} note={}",
            ev.source,
            ev.offset,
            ev.length,
            escape_terminal(ev.note.as_deref().unwrap_or("-"))
        );
        if matches!(ev.source, sis_pdf_core::model::EvidenceSource::File) {
            let start = ev.offset as usize;
            let end = start.saturating_add(ev.length as usize).min(bytes.len());
            let slice = &bytes[start..end];
            println!("{}", preview_bytes(slice));
        } else {
            println!("(decoded evidence preview not available)");
        }
    }
    if finding.kind.contains("xref")
        || finding.surface == sis_pdf_core::model::AttackSurface::XRefTrailer
    {
        println!();
        println!("Suggested follow-up queries:");
        println!("  sis query {pdf} xref.startxrefs");
        println!("  sis query {pdf} xref.sections");
        println!("  sis query {pdf} xref.deviations");
    }
    Ok(())
}

fn resolve_explain_finding_id(
    findings: &[sis_pdf_core::model::Finding],
    requested_id: &str,
) -> Option<String> {
    if findings.iter().any(|f| f.id == requested_id) {
        return Some(requested_id.to_string());
    }

    let mut prefix_matches = findings.iter().filter(|f| f.id.starts_with(requested_id));
    if let Some(first) = prefix_matches.next() {
        if prefix_matches.next().is_none() {
            return Some(first.id.clone());
        }
    }

    sis_pdf_core::id_shortener::resolve_short_id(requested_id)
}

fn print_finding_context_hints(meta: &std::collections::HashMap<String, String>) {
    const IMPORTANT_KEYS: &[&str] = &[
        "expected.filter_declared",
        "expected.compression",
        "observed.compression_guess",
        "observed.signature_hint",
        "decode.expected_types",
        "decode.expected_signatures",
        "decode.observed_type",
        "decode.observed_signature",
        "threshold.depth",
        "observed.chain_depth",
        "observed.terminal_action",
        "action.chain_path",
        "action.type",
        "action.target",
        "action.initiation",
        "url.domain",
        "url.external",
        "uri.domain",
        "uri.scheme",
        "uri.userinfo",
        "uri.ip_host",
        "parser.deviation_top",
        "secondary_parser.error_class",
        "secondary_parser.error_message",
        "diff.missing_in_secondary_ids",
        "diff.missing_in_secondary_offsets",
        "diff.missing_in_secondary_hazards",
        "diff.missing_in_primary_ids",
        "diff.missing_in_primary_offsets",
        "xref.integrity.level",
        "xref.startxref.count",
        "xref.section.count",
        "xref.section.kinds",
        "xref.prev_chain.valid",
        "xref.prev_chain.length",
        "xref.prev_chain.cycle",
        "xref.offsets.in_bounds",
        "xref.deviation.count",
        "xref.deviation.kinds",
        "query.next",
    ];
    let mut printed_any = false;
    for key in IMPORTANT_KEYS {
        if let Some(value) = meta.get(*key) {
            if !printed_any {
                println!("Context:");
                printed_any = true;
            }
            println!("  {}: {}", key, escape_terminal(value));
        }
    }
}

fn run_report(
    pdf: &str,
    deep: bool,
    max_decode_bytes: usize,
    max_total_decoded_bytes: usize,
    recover_xref: bool,
    group_chains: bool,
    diff_parser: bool,
    max_objects: usize,
    max_recursion_depth: usize,
    strict: bool,
    ir: bool,
    out: Option<&std::path::Path>,
    ml: bool,
    ml_model_dir: Option<&std::path::Path>,
    ml_threshold: f32,
    ml_mode: &str,
    ml_extended_features: bool,
    ml_explain: bool,
    ml_advanced: bool,
    ml_temporal: bool,
    temporal_signals: bool,
    ml_baseline: Option<&std::path::Path>,
    ml_calibration: Option<&std::path::Path>,
    ml_provider: Option<&str>,
    ml_provider_order: Option<&str>,
    ml_provider_info: bool,
    ml_ort_dylib: Option<&std::path::Path>,
    ml_quantized: bool,
    ml_batch_size: Option<usize>,
    js_ast: bool,
    js_sandbox: bool,
    image_analysis_enabled: bool,
    image_dynamic_enabled: bool,
    _report_chain_summary: commands::query::ChainSummaryLevel,
    _report_verbosity: commands::query::ReportVerbosity,
) -> Result<()> {
    let bytes = read_pdf_bytes(pdf)?;
    let diff_parser = diff_parser || strict;
    if diff_parser && strict {
        SecurityEvent {
            level: Level::INFO,
            domain: SecurityDomain::Parser,
            severity: SecuritySeverity::Info,
            kind: "diff_parser_enabled",
            policy: None,
            object_id: None,
            object_type: None,
            vector: None,
            technique: None,
            confidence: None,
            fatal: false,
            message: "Enabling diff parser in strict mode",
        }
        .emit();
        info!(strict = true, diff_parser = true, "Diff parser enabled for strict mode");
    }
    let opts = sis_pdf_core::scan::ScanOptions {
        deep,
        max_decode_bytes,
        max_total_decoded_bytes,
        recover_xref,
        parallel: false,
        batch_parallel: false,
        diff_parser,
        max_objects,
        max_recursion_depth,
        fast: false,
        focus_trigger: None,
        yara_scope: None,
        focus_depth: 0,
        strict,
        strict_summary: false,
        ir,
        ml_config: None,
        font_analysis: sis_pdf_core::scan::FontAnalysisOptions::default(),
        image_analysis: sis_pdf_core::scan::ImageAnalysisOptions {
            enabled: image_analysis_enabled,
            dynamic_enabled: image_analysis_enabled && image_dynamic_enabled,
            ..sis_pdf_core::scan::ImageAnalysisOptions::default()
        },
        filter_allowlist: None,
        filter_allowlist_strict: false,
        profile: false,
        profile_format: sis_pdf_core::scan::ProfileFormat::Text,
        group_chains,
        correlation: CorrelationOptions::default(),
    };
    let mut opts = opts;
    let runtime_overrides = build_ml_runtime_config(
        ml_provider,
        ml_provider_order,
        ml_provider_info,
        ml_ort_dylib,
        ml_quantized,
        ml_batch_size,
    );
    if ml {
        let model_dir = ml_model_dir.ok_or_else(|| anyhow!("--ml requires --ml-model-dir"))?;
        opts.ml_config = Some(sis_pdf_core::ml::MlConfig {
            model_path: model_dir.to_path_buf(),
            threshold: ml_threshold,
            mode: parse_ml_mode(ml_mode),
            runtime: runtime_overrides.clone(),
        });
    } else if let Some(dir) = ml_model_dir {
        opts.ml_config = Some(sis_pdf_core::ml::MlConfig {
            model_path: dir.to_path_buf(),
            threshold: ml_threshold,
            mode: parse_ml_mode(ml_mode),
            runtime: runtime_overrides.clone(),
        });
    }
    if let Some(cfg) = opts.ml_config.as_mut() {
        apply_ml_runtime_overrides(&mut cfg.runtime, &runtime_overrides);
        if cfg.runtime.print_provider {
            log_ml_provider_info(&cfg.runtime)?;
        }
    }
    let detectors =
        sis_pdf_detectors::default_detectors_with_settings(sis_pdf_detectors::DetectorSettings {
            js_ast,
            js_sandbox,
        });
    let mut report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, opts.clone(), &detectors)?
            .with_input_path(Some(pdf.to_string()));
    let ml_inference_requested = ml_extended_features
        || ml_explain
        || ml_advanced
        || ml_temporal
        || ml_baseline.is_some()
        || ml_calibration.is_some();
    let temporal_requested = temporal_signals || ml_temporal;
    if ml_inference_requested {
        match run_ml_inference_for_scan(
            &bytes,
            &opts,
            &report,
            ml_model_dir,
            ml_threshold,
            ml_extended_features,
            ml_explain,
            ml_advanced,
            ml_baseline,
            ml_calibration,
        ) {
            Ok(ml_result) => {
                report = report.with_ml_inference(Some(ml_result));
            }
            Err(err) => {
                warn!(error = %err, "ML inference failed");
            }
        }
    }
    if temporal_requested {
        let (temporal_summary, temporal_snapshots, temporal_explanation) = run_temporal_analysis(
            &bytes,
            &opts,
            &detectors,
            ml_model_dir,
            ml_threshold,
            ml_extended_features,
            ml_explain,
            ml_baseline,
            ml_calibration,
            ml_temporal,
        )?;
        report = report
            .with_temporal_signals(temporal_summary)
            .with_temporal_snapshots(temporal_snapshots);
        if let (Some(ml), Some(explanation)) = (report.ml_inference.as_mut(), temporal_explanation)
        {
            if let Some(expl) = ml.explanation.as_mut() {
                expl.temporal_analysis = Some(explanation);
            }
        }
    }
    let md = sis_pdf_core::report::render_markdown(&report, Some(pdf));
    if let Some(path) = out {
        fs::write(path, md)?;
    } else {
        println!("{}", md);
    }
    Ok(())
}

fn run_compute_baseline(input: &PathBuf, out: &PathBuf) -> Result<()> {
    // Read JSONL file with feature vectors
    let data = fs::read_to_string(input)?;
    let mut feature_samples = Vec::new();

    for (line_num, line) in data.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let record: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                warn!(line = line_num + 1, error = %e, "Skipping invalid JSONL line");
                continue;
            }
        };

        // Extract features array
        if let Some(features) = record.get("features").and_then(|f| f.as_array()) {
            let vec: Vec<f32> =
                features.iter().filter_map(|v| v.as_f64().map(|f| f as f32)).collect();

            if vec.len() == 333 || vec.len() == 35 {
                feature_samples.push(vec);
            } else {
                warn!(line = line_num + 1, feature_count = vec.len(), "Unexpected feature count");
            }
        } else {
            warn!(line = line_num + 1, "Missing features array");
        }
    }

    if feature_samples.is_empty() {
        return Err(anyhow!("No valid feature vectors found in input file"));
    }

    info!(samples = feature_samples.len(), "Loaded benign samples");

    // Get feature names based on vector size
    let feature_names = if feature_samples[0].len() == 333 {
        sis_pdf_core::features_extended::extended_feature_names()
    } else {
        sis_pdf_core::features::feature_names()
            .into_iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    };

    // Convert Vec<f32> to HashMap<String, f32>
    let feature_maps: Vec<std::collections::HashMap<String, f32>> = feature_samples
        .iter()
        .map(|vec| {
            feature_names
                .iter()
                .zip(vec.iter())
                .map(|(name, &value)| (name.clone(), value))
                .collect()
        })
        .collect();

    // Compute baseline using explainability module
    let baseline = sis_pdf_core::explainability::compute_baseline_from_samples(&feature_maps);

    // Save to JSON
    let json = serde_json::to_string_pretty(&baseline)?;
    fs::write(out, json)?;

    info!(path = %out.display(), "Baseline saved");
    debug!(feature_count = baseline.feature_means.len(), "Baseline feature count");
    debug!(sample_count = feature_samples.len(), "Baseline sample count");

    Ok(())
}

fn run_stream_analyze(pdf: &str, chunk_size: usize, max_buffer: usize) -> Result<()> {
    let mut f = fs::File::open(pdf)?;
    let mut analyzer = sis_pdf_core::stream_analyzer::StreamAnalyzer::new(max_buffer);
    let mut buf = vec![0u8; chunk_size];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let state = analyzer.analyze_chunk(&buf[..n]);
        if let Some(threat) = analyzer.early_terminate(&state) {
            println!("early_terminate kind={} reason={}", threat.kind, threat.reason);
            return Ok(());
        }
    }
    let state = analyzer.analyze_chunk(&[]);
    if state.indicators.is_empty() {
        println!("no indicators found");
    } else {
        println!("indicators: {}", state.indicators.join(", "));
    }
    Ok(())
}
fn run_campaign_correlate(input: &std::path::Path, out: Option<&std::path::Path>) -> Result<()> {
    let data = read_text_with_limit(input, MAX_JSONL_BYTES)?;
    let mut by_path: std::collections::HashMap<String, sis_pdf_core::campaign::PDFAnalysis> =
        std::collections::HashMap::new();
    let mut entries = 0usize;
    for (idx, line) in data.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if line.len() > MAX_JSONL_LINE_BYTES {
            SecurityEvent {
                level: Level::WARN,
                domain: SecurityDomain::Parser,
                severity: SecuritySeverity::Low,
                kind: "jsonl_line_too_large",
                policy: None,
                object_id: None,
                object_type: None,
                vector: None,
                technique: None,
                confidence: None,
                fatal: false,
                message: "JSONL line exceeds size limit",
            }
            .emit();
            warn!(
                line = idx + 1,
                max_bytes = MAX_JSONL_LINE_BYTES,
                "JSONL line exceeds size limit"
            );
            continue;
        }
        entries += 1;
        if entries > MAX_JSONL_ENTRIES {
            SecurityEvent {
                level: Level::ERROR,
                domain: SecurityDomain::Parser,
                severity: SecuritySeverity::Medium,
                kind: "jsonl_entry_limit_exceeded",
                policy: None,
                object_id: None,
                object_type: None,
                vector: None,
                technique: None,
                confidence: None,
                fatal: false,
                message: "JSONL entry limit exceeded",
            }
            .emit();
            error!(max_entries = MAX_JSONL_ENTRIES, "JSONL entry limit exceeded");
            return Err(anyhow!("JSONL entry limit exceeded"));
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(err) => {
                SecurityEvent {
                    level: Level::WARN,
                    domain: SecurityDomain::Parser,
                    severity: SecuritySeverity::Low,
                    kind: "jsonl_parse_error",
                    policy: None,
                    object_id: None,
                    object_type: None,
                    vector: None,
                    technique: None,
                    confidence: None,
                    fatal: false,
                    message: "JSONL parse error",
                }
                .emit();
                warn!(line = idx + 1, error = %err, "JSONL parse error");
                continue;
            }
        };
        let path = v.get("path").and_then(|v| v.as_str()).unwrap_or("unknown");
        let url = v.get("url").and_then(|v| v.as_str()).unwrap_or("");
        if url.is_empty() {
            continue;
        }
        if url.len() > MAX_CAMPAIGN_INTENT_LEN || !is_printable_ascii(url) {
            SecurityEvent {
                level: Level::WARN,
                domain: SecurityDomain::Parser,
                severity: SecuritySeverity::Low,
                kind: "jsonl_url_rejected",
                policy: None,
                object_id: None,
                object_type: None,
                vector: None,
                technique: None,
                confidence: None,
                fatal: false,
                message: "JSONL URL rejected",
            }
            .emit();
            warn!(
                url_len = url.len(),
                printable_ascii = is_printable_ascii(url),
                "JSONL URL rejected"
            );
            continue;
        }
        let domain = sis_pdf_core::campaign::extract_domain(url);
        let entry = by_path.entry(path.to_string()).or_insert_with(|| {
            sis_pdf_core::campaign::PDFAnalysis {
                id: path.to_string(),
                path: Some(path.to_string()),
                network_intents: Vec::new(),
            }
        });
        entry
            .network_intents
            .push(sis_pdf_core::campaign::NetworkIntent { url: url.to_string(), domain });
    }
    let analyses: Vec<sis_pdf_core::campaign::PDFAnalysis> = by_path.into_values().collect();
    let correlator = sis_pdf_core::campaign::MultiStageCorrelator;
    let campaigns = correlator.correlate_campaign(&analyses);
    let mut output = serde_json::json!({
        "campaigns": campaigns,
    });
    if let serde_json::Value::Object(map) = &mut output {
        let intents: Vec<sis_pdf_core::campaign::NetworkIntent> =
            analyses.iter().flat_map(|a| a.network_intents.iter().cloned()).collect();
        let c2 = correlator.detect_c2_infrastructure(&intents);
        map.insert("c2_domains".into(), serde_json::json!(c2));
    }
    let rendered = serde_json::to_string_pretty(&output)?;
    if let Some(path) = out {
        fs::write(path, rendered)?;
    } else {
        println!("{}", rendered);
    }
    Ok(())
}
fn run_response_generate(
    kind: Option<&str>,
    from_report: Option<&std::path::Path>,
    out: Option<&std::path::Path>,
) -> Result<()> {
    let generator = sis_pdf_core::response::ResponseGenerator;
    let mut rules = Vec::new();
    if let Some(path) = from_report {
        let data = read_text_with_limit(path, MAX_REPORT_BYTES)?;
        let report: sis_pdf_core::report::Report = serde_json::from_str(&data)?;
        if let Some(summary) = &report.behavior_summary {
            for pattern in &summary.patterns {
                rules.extend(generator.generate_yara_variants(pattern));
            }
        }
    }
    if rules.is_empty() {
        let kind = kind.ok_or_else(|| anyhow!("--kind or --from-report is required"))?;
        let pattern = sis_pdf_core::behavior::ThreatPattern {
            id: format!("kind:{}", kind),
            kinds: vec![kind.to_string()],
            objects: vec!["-".into()],
            severity: sis_pdf_core::model::Severity::Medium,
            summary: format!("Generated for {}", kind),
        };
        rules.extend(generator.generate_yara_variants(&pattern));
    }
    let rendered = sis_pdf_core::yara::render_rules(&rules);
    if let Some(path) = out {
        fs::write(path, rendered)?;
    } else {
        println!("{}", rendered);
    }
    Ok(())
}
fn run_mutate(pdf: &str, out: &std::path::Path, scan: bool) -> Result<()> {
    let data = fs::read(pdf)?;
    fs::create_dir_all(out)?;
    let tester = sis_pdf_core::mutation::MutationTester;
    let mutants = tester.mutate_malware(&data);
    for (idx, mutant) in mutants.iter().enumerate() {
        let name = format!("mutant_{:02}_{}.pdf", idx + 1, sanitize_filename(&mutant.note));
        let path = out.join(name);
        fs::write(path, &mutant.bytes)?;
    }
    println!("generated {} mutants", mutants.len());
    if scan {
        let detectors = sis_pdf_detectors::default_detectors();
        let opts = sis_pdf_core::scan::ScanOptions {
            strict: false,
            strict_summary: false,
            ir: false,
            deep: true,
            max_decode_bytes: 32 * 1024 * 1024,
            max_total_decoded_bytes: 256 * 1024 * 1024,
            recover_xref: true,
            parallel: false,
            batch_parallel: false,
            diff_parser: false,
            max_objects: 500_000,
            max_recursion_depth: 64,
            fast: false,
            focus_trigger: None,
            focus_depth: 0,
            yara_scope: None,
            ml_config: None,
            font_analysis: sis_pdf_core::scan::FontAnalysisOptions::default(),
            image_analysis: sis_pdf_core::scan::ImageAnalysisOptions::default(),
            filter_allowlist: None,
            filter_allowlist_strict: false,
            profile: false,
            profile_format: sis_pdf_core::scan::ProfileFormat::Text,
            group_chains: true,
            correlation: CorrelationOptions::default(),
        };
        let base_report =
            sis_pdf_core::runner::run_scan_with_detectors(&data, opts.clone(), &detectors)?;
        let base_counts = count_kinds(&base_report.findings);
        println!("base findings: {}", base_report.findings.len());
        for (idx, mutant) in mutants.iter().enumerate() {
            let report = sis_pdf_core::runner::run_scan_with_detectors(
                &mutant.bytes,
                opts.clone(),
                &detectors,
            )?;
            let counts = count_kinds(&report.findings);
            let deltas = diff_kind_counts(&base_counts, &counts);
            println!("mutant {:02} {} deltas: {}", idx + 1, mutant.note, deltas.join(", "));
        }
    }
    Ok(())
}
fn count_kinds(
    findings: &[sis_pdf_core::model::Finding],
) -> std::collections::BTreeMap<String, usize> {
    let mut out = std::collections::BTreeMap::new();
    for f in findings {
        *out.entry(f.kind.clone()).or_insert(0) += 1;
    }
    out
}
fn diff_kind_counts(
    base: &std::collections::BTreeMap<String, usize>,
    current: &std::collections::BTreeMap<String, usize>,
) -> Vec<String> {
    let mut out = Vec::new();
    let keys: std::collections::BTreeSet<&String> = base.keys().chain(current.keys()).collect();
    for key in keys {
        let b = *base.get(key).unwrap_or(&0) as i64;
        let c = *current.get(key).unwrap_or(&0) as i64;
        if b != c {
            out.push(format!("{} {:+}", key, c - b));
        }
    }
    if out.is_empty() {
        out.push("no_deltas".into());
    }
    out
}
fn run_redteam(target: &str, out: &std::path::Path) -> Result<()> {
    let sim = sis_pdf_core::redteam::RedTeamSimulator;
    let pdf = sim.generate_evasive_pdf(&sis_pdf_core::redteam::DetectorProfile {
        target: target.to_string(),
    });
    fs::write(out, pdf.bytes)?;
    println!("wrote red-team fixture: {}", out.display());
    Ok(())
}

fn run_sanitize(
    pdf: &str,
    out: &std::path::Path,
    report_json: Option<&std::path::Path>,
    safe_rebuild: bool,
) -> Result<()> {
    let data = read_pdf_bytes(pdf)?;
    let result = if safe_rebuild {
        sis_pdf_core::cdr::strip_active_content_safe_rebuild(
            &data,
            &sis_pdf_core::cdr::StripOptions::default(),
        )?
    } else {
        sis_pdf_core::cdr::strip_active_content(&data, &sis_pdf_core::cdr::StripOptions::default())?
    };
    fs::write(out, &result.sanitised_bytes)?;

    let report = serde_json::to_string_pretty(&result.report)?;
    if let Some(report_path) = report_json {
        fs::write(report_path, &report)?;
    }

    println!("sanitised output: {}", out.display());
    println!(
        "removed entries: {} (degraded_output={})",
        result.report.removed_total, result.report.output_degraded
    );
    for (class, count) in &result.report.removed_by_class {
        println!("  {}: {}", class, count);
    }
    if safe_rebuild {
        println!(
            "safe_rebuild: applied={} parseable_after_rebuild={} unresolved_reference_count={}",
            result.report.safe_rebuild_applied,
            result.report.parseable_after_rebuild,
            result.report.unresolved_reference_count
        );
        if let Some(reason) = &result.report.safe_rebuild_excluded_reason {
            println!("safe_rebuild_excluded_reason: {}", reason);
        }
    }
    if let Some(report_path) = report_json {
        println!("report written: {}", report_path.display());
    }
    Ok(())
}

#[cfg(feature = "ml-graph")]
fn run_ml_health(
    ml_model_dir: Option<&std::path::Path>,
    ml_provider: Option<&str>,
    ml_provider_order: Option<&str>,
    ml_provider_info: bool,
    ml_ort_dylib: Option<&std::path::Path>,
    ml_quantized: bool,
    ml_batch_size: Option<usize>,
) -> Result<()> {
    let runtime = build_ml_runtime_config(
        ml_provider,
        ml_provider_order,
        ml_provider_info,
        ml_ort_dylib,
        ml_quantized,
        ml_batch_size,
    );
    let info = sis_pdf_ml_graph::ml_health_check(
        ml_model_dir,
        &sis_pdf_ml_graph::RuntimeSettings {
            provider: runtime.provider.clone(),
            provider_order: runtime.provider_order.clone(),
            ort_dylib_path: runtime.ort_dylib_path.clone(),
            prefer_quantized: runtime.prefer_quantized,
            max_embedding_batch_size: runtime.max_embedding_batch_size,
            print_provider: runtime.print_provider,
        },
    )?;
    println!("ML runtime health");
    println!("Requested providers: {}", info.requested.join(", "));
    println!("Available providers: {}", info.available.join(", "));
    println!("Selected provider: {}", info.selected.unwrap_or_else(|| "none".into()));
    if ml_model_dir.is_some() {
        println!("Model load: ok");
    }
    Ok(())
}

#[cfg(not(feature = "ml-graph"))]
fn run_ml_health(
    _ml_model_dir: Option<&std::path::Path>,
    _ml_provider: Option<&str>,
    _ml_provider_order: Option<&str>,
    _ml_provider_info: bool,
    _ml_ort_dylib: Option<&std::path::Path>,
    _ml_quantized: bool,
    _ml_batch_size: Option<usize>,
) -> Result<()> {
    Err(anyhow!("ml-health requires the ml-graph feature"))
}
fn sanitize_filename(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect()
}
fn preview_bytes(bytes: &[u8]) -> String {
    let mut s = String::new();
    for &b in bytes.iter().take(256) {
        if (0x20..=0x7E).contains(&b) {
            s.push(b as char);
        } else {
            s.push('.');
        }
    }
    s
}
fn escape_terminal(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_control() && ch != '\n' && ch != '\t' {
            out.push_str(&format!("\\x{:02X}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
}
fn is_printable_ascii(input: &str) -> bool {
    input.bytes().all(|b| (0x20..=0x7E).contains(&b))
}
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    hex::encode(digest)
}
fn read_text_with_limit(path: &std::path::Path, max_bytes: u64) -> Result<String> {
    if let Ok(meta) = fs::metadata(path) {
        if meta.len() > max_bytes {
            SecurityEvent {
                level: Level::ERROR,
                domain: SecurityDomain::Parser,
                severity: SecuritySeverity::Medium,
                kind: "read_limit_exceeded",
                policy: None,
                object_id: None,
                object_type: None,
                vector: None,
                technique: None,
                confidence: None,
                fatal: false,
                message: "Read rejected due to size limit",
            }
            .emit();
            error!(
                path = %path.display(),
                size_bytes = meta.len(),
                max_bytes = max_bytes,
                "Read rejected due to size limit"
            );
            return Err(anyhow!("file {} exceeds {} bytes", path.display(), max_bytes));
        }
    }
    Ok(fs::read_to_string(path)?)
}

fn build_ml_runtime_config(
    provider: Option<&str>,
    provider_order: Option<&str>,
    print_provider: bool,
    ort_dylib: Option<&std::path::Path>,
    prefer_quantized: bool,
    batch_size: Option<usize>,
) -> sis_pdf_core::ml::MlRuntimeConfig {
    let provider = provider.and_then(|p| {
        let p = p.trim();
        if p.is_empty() || p.eq_ignore_ascii_case("auto") {
            None
        } else {
            Some(p.to_string())
        }
    });
    let provider_order = provider_order.map(|s| {
        s.split(',')
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
    });
    sis_pdf_core::ml::MlRuntimeConfig {
        provider,
        provider_order,
        ort_dylib_path: ort_dylib.map(|p| p.to_path_buf()),
        prefer_quantized,
        max_embedding_batch_size: batch_size,
        print_provider,
    }
}

fn apply_ml_runtime_overrides(
    runtime: &mut sis_pdf_core::ml::MlRuntimeConfig,
    overrides: &sis_pdf_core::ml::MlRuntimeConfig,
) {
    if overrides.provider.is_some() {
        runtime.provider = overrides.provider.clone();
    }
    if overrides.provider_order.is_some() {
        runtime.provider_order = overrides.provider_order.clone();
    }
    if overrides.ort_dylib_path.is_some() {
        runtime.ort_dylib_path = overrides.ort_dylib_path.clone();
    }
    if overrides.prefer_quantized {
        runtime.prefer_quantized = true;
    }
    if overrides.max_embedding_batch_size.is_some() {
        runtime.max_embedding_batch_size = overrides.max_embedding_batch_size;
    }
    if overrides.print_provider {
        runtime.print_provider = true;
    }
}

#[cfg(feature = "ml-graph")]
fn log_ml_provider_info(runtime: &sis_pdf_core::ml::MlRuntimeConfig) -> Result<()> {
    let info = sis_pdf_ml_graph::runtime_provider_info(&sis_pdf_ml_graph::RuntimeSettings {
        provider: runtime.provider.clone(),
        provider_order: runtime.provider_order.clone(),
        ort_dylib_path: runtime.ort_dylib_path.clone(),
        prefer_quantized: runtime.prefer_quantized,
        max_embedding_batch_size: runtime.max_embedding_batch_size,
        print_provider: runtime.print_provider,
    })?;
    warn!(
        requested = %info.requested.join(","),
        available = %info.available.join(","),
        selected = %info.selected.clone().unwrap_or_else(|| "none".into()),
        "ML execution provider selection"
    );
    Ok(())
}

#[cfg(not(feature = "ml-graph"))]
fn log_ml_provider_info(_runtime: &sis_pdf_core::ml::MlRuntimeConfig) -> Result<()> {
    Err(anyhow!("ml-provider-info requires the ml-graph feature"))
}
fn parse_ml_mode(value: &str) -> sis_pdf_core::ml::MlMode {
    match value.to_lowercase().as_str() {
        "graph" => sis_pdf_core::ml::MlMode::Graph,
        _ => sis_pdf_core::ml::MlMode::Traditional,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scan_opts() -> sis_pdf_core::scan::ScanOptions {
        sis_pdf_core::scan::ScanOptions {
            deep: false,
            max_decode_bytes: 32 * 1024 * 1024,
            max_total_decoded_bytes: 256 * 1024 * 1024,
            recover_xref: true,
            parallel: false,
            batch_parallel: false,
            diff_parser: false,
            max_objects: 500_000,
            max_recursion_depth: 64,
            fast: false,
            focus_trigger: None,
            focus_depth: 0,
            yara_scope: None,
            strict: false,
            strict_summary: false,
            ir: false,
            ml_config: None,
            font_analysis: sis_pdf_core::scan::FontAnalysisOptions::default(),
            image_analysis: sis_pdf_core::scan::ImageAnalysisOptions::default(),
            filter_allowlist: None,
            filter_allowlist_strict: false,
            profile: false,
            profile_format: sis_pdf_core::scan::ProfileFormat::Text,
            group_chains: true,
            correlation: CorrelationOptions::default(),
        }
    }

    #[test]
    fn resolve_provider_order_prefers_override_provider() {
        let overrides = sis_pdf_core::ml::MlRuntimeConfig {
            provider: Some("cuda".into()),
            provider_order: None,
            ort_dylib_path: None,
            prefer_quantized: false,
            max_embedding_batch_size: None,
            print_provider: false,
        };
        let hints =
            MlConfigHints { provider: Some("cpu".into()), provider_order: None, ort_dylib: None };
        let order = resolve_provider_order(&overrides, &hints, "linux");
        assert_eq!(order, vec!["cuda".to_string(), "cpu".to_string()]);
    }

    #[test]
    fn ort_archive_name_maps_linux_cpu() {
        let target = OrtTarget { os: "linux", arch: "x86_64" };
        let (name, fmt) = ort_archive_name(&target, "cpu", "1.2.3").expect("archive");
        assert_eq!(name, "onnxruntime-linux-x64-1.2.3.tgz");
        assert!(matches!(fmt, ArchiveFormat::TarGz));
    }

    #[test]
    fn ort_archive_name_maps_linux_openvino() {
        let target = OrtTarget { os: "linux", arch: "x86_64" };
        let (name, fmt) = ort_archive_name(&target, "openvino", "1.2.3").expect("archive");
        assert_eq!(name, "onnxruntime-linux-x64-openvino-1.2.3.tgz");
        assert!(matches!(fmt, ArchiveFormat::TarGz));
    }

    #[test]
    fn verify_checksum_contents_accepts_match() {
        let mut file = tempfile::NamedTempFile::new().expect("tempfile");
        file.write_all(b"hello").expect("write");
        let hash = sha256_file(file.path()).expect("hash");
        let contents = format!("{hash}  onnxruntime-linux-x64-1.2.3.tgz\n");
        verify_checksum_contents(&contents, "onnxruntime-linux-x64-1.2.3.tgz", file.path())
            .expect("checksum should match");
    }

    #[test]
    fn verify_checksum_contents_rejects_mismatch() {
        let mut file = tempfile::NamedTempFile::new().expect("tempfile");
        file.write_all(b"hello").expect("write");
        let contents = "0000000000000000000000000000000000000000000000000000000000000000  onnxruntime-linux-x64-1.2.3.tgz\n";
        assert!(verify_checksum_contents(contents, "onnxruntime-linux-x64-1.2.3.tgz", file.path())
            .is_err());
    }

    #[test]
    fn filter_allowlist_flags_apply_and_print() {
        let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root")
            .join("config/filter-chains-allowlist.toml");
        let mut opts = scan_opts();
        apply_filter_allowlist_options(&mut opts, Some(&config_path), true)
            .expect("apply allowlist");
        assert!(opts.filter_allowlist_strict);
        assert!(opts.filter_allowlist.as_ref().map(|v| !v.is_empty()).unwrap_or(false));

        print_filter_allowlist().expect("print allowlist");
    }
}
