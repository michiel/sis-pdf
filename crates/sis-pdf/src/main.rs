use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use globset::Glob;
use memmap2::Mmap;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use sis_pdf_core::model::Severity as SecuritySeverity;
use sis_pdf_core::security_log::{SecurityDomain, SecurityEvent};
use tracing::{debug, error, info, warn, Level};
use walkdir::WalkDir;
const MAX_REPORT_BYTES: u64 = 50 * 1024 * 1024;
const WARN_PDF_BYTES: u64 = 50 * 1024 * 1024;
const MAX_PDF_BYTES: u64 = 500 * 1024 * 1024;
const MAX_BATCH_FILES: usize = 10_000;
const MAX_BATCH_BYTES: u64 = 50 * 1024 * 1024 * 1024;
const MAX_JSONL_BYTES: u64 = 100 * 1024 * 1024;
const MAX_JSONL_LINE_BYTES: usize = 10 * 1024;
const MAX_JSONL_ENTRIES: usize = 1_000_000;
const MAX_CAMPAIGN_INTENT_LEN: usize = 1024;
const MAX_WALK_DEPTH: usize = 10;
#[derive(Parser)]
#[command(name = "sis")]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    #[command(subcommand)]
    Config(ConfigCommand),
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
        #[arg(long)]
        json: bool,
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
        #[arg(long, help = "Summarise strict parser deviations instead of emitting each deviation")]
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
        #[arg(long)]
        cache_dir: Option<PathBuf>,
        #[arg(long, alias = "seq")]
        sequential: bool,
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
        #[arg(long, help = "Include advanced ML explainability (counterfactuals and interactions)")]
        ml_advanced: bool,
        #[arg(long, help = "Compute ML temporal analysis across incremental updates")]
        ml_temporal: bool,
        #[arg(long, help = "Compute non-ML temporal signals across incremental updates")]
        temporal_signals: bool,
        #[arg(long, help = "Path to benign baseline JSON for explanations")]
        ml_baseline: Option<PathBuf>,
        #[arg(long, help = "Path to calibration model JSON")]
        ml_calibration: Option<PathBuf>,
        #[arg(long, help = "Preferred ML execution provider (auto, cpu, cuda, rocm, migraphx, directml, coreml, onednn, openvino)")]
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
    },
    #[command(about = "Detect files that contain specific findings")]
    Detect {
        #[arg(long)]
        path: PathBuf,
        #[arg(long, default_value = "*.pdf")]
        glob: String,
        #[arg(long, value_delimiter = ',', required = true)]
        findings: Vec<String>,
        #[arg(long)]
        deep: bool,
        #[arg(long, default_value_t = 32 * 1024 * 1024)]
        max_decode_bytes: usize,
        #[arg(long, default_value_t = 256 * 1024 * 1024)]
        max_total_decoded_bytes: usize,
        #[arg(long)]
        no_recover: bool,
        #[arg(long)]
        strict: bool,
        #[arg(long, default_value_t = 500_000)]
        max_objects: usize,
        #[arg(long, alias = "seq")]
        sequential: bool,
        #[arg(long)]
        no_js_ast: bool,
        #[arg(long)]
        no_js_sandbox: bool,
    },
    #[command(about = "Extract JavaScript or embedded files from a PDF")]
    Extract {
        #[arg(value_parser = ["js", "embedded"])]
        kind: String,
        pdf: String,
        #[arg(short, long)]
        out: PathBuf,
        #[arg(long, default_value_t = 128 * 1024 * 1024)]
        max_extract_bytes: usize,
    },
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
        #[arg(long, help = "Include advanced ML explainability (counterfactuals and interactions)")]
        ml_advanced: bool,
        #[arg(long, help = "Compute ML temporal analysis across incremental updates")]
        ml_temporal: bool,
        #[arg(long, help = "Compute non-ML temporal signals across incremental updates")]
        temporal_signals: bool,
        #[arg(long, help = "Path to benign baseline JSON for explanations")]
        ml_baseline: Option<PathBuf>,
        #[arg(long, help = "Path to calibration model JSON")]
        ml_calibration: Option<PathBuf>,
        #[arg(long, help = "Preferred ML execution provider (auto, cpu, cuda, rocm, migraphx, directml, coreml, onednn, openvino)")]
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
    #[command(about = "Validate ML runtime setup and execution providers")]
    MlHealth {
        #[arg(long)]
        ml_model_dir: Option<PathBuf>,
        #[arg(long, help = "Preferred ML execution provider (auto, cpu, cuda, rocm, migraphx, directml, coreml, onednn, openvino)")]
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
    #[command(about = "Export action chains from a scan as DOT or JSON")]
    ExportGraph {
        pdf: String,
        #[arg(long)]
        chains_only: bool,
        #[arg(long, default_value = "dot", value_parser = ["dot", "json"])]
        format: String,
        #[arg(short, long)]
        out: PathBuf,
    },
    #[command(about = "Export object reference graph with suspicious paths (DOT or JSON)")]
    ExportOrg {
        pdf: String,
        #[arg(long, default_value = "dot", value_parser = ["dot", "json"])]
        format: String,
        #[arg(short, long)]
        out: PathBuf,
        #[arg(long, help = "Export basic graph only (no enhancements, paths, or classifications)")]
        basic: bool,
    },
    #[command(about = "Export enhanced IR with findings and risk scores (text or JSON)")]
    ExportIr {
        pdf: String,
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        format: String,
        #[arg(short, long)]
        out: PathBuf,
        #[arg(long, help = "Export basic IR only (no findings or risk analysis)")]
        basic: bool,
    },
    #[command(about = "Export extended 333-feature vectors for ML pipelines")]
    ExportFeatures {
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
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        label: Option<String>,
        #[arg(long, default_value = "jsonl", value_parser = ["jsonl", "csv"])]
        format: String,
        #[arg(short, long)]
        out: Option<PathBuf>,
        #[arg(long, help = "Export basic 35-feature vector only (legacy format)")]
        basic: bool,
        #[arg(long, help = "Include feature names in JSONL output records")]
        feature_names: bool,
    },
    #[command(about = "Compute benign baseline from feature vectors")]
    ComputeBaseline {
        #[arg(long, help = "Path to JSONL file with benign feature vectors")]
        input: PathBuf,
        #[arg(short, long, help = "Output baseline JSON file")]
        out: PathBuf,
    },
    #[command(about = "Analyze a PDF stream in chunks and stop on indicators")]
    StreamAnalyze {
        pdf: String,
        #[arg(long, default_value_t = 64 * 1024)]
        chunk_size: usize,
        #[arg(long, default_value_t = 256 * 1024)]
        max_buffer: usize,
    },
    #[command(about = "Correlate network intents across PDFs from JSONL input")]
    CampaignCorrelate {
        #[arg(long)]
        input: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    #[command(about = "Generate response YARA rules for a threat kind or report")]
    ResponseGenerate {
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
        Command::Scan {
            pdf,
            path,
            glob,
            deep,
            max_decode_bytes,
            max_total_decoded_bytes,
            no_recover,
            json,
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
            cache_dir,
            sequential,
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
        } => run_scan(
            pdf.as_deref(),
            path.as_deref(),
            &glob,
            deep,
            max_decode_bytes,
            max_total_decoded_bytes,
            !no_recover,
            json,
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
            cache_dir.as_deref(),
            sequential,
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
        ),
        Command::Explain { pdf, finding_id } => run_explain(&pdf, &finding_id),
        Command::Detect {
            path,
            glob,
            findings,
            deep,
            max_decode_bytes,
            max_total_decoded_bytes,
            no_recover,
            strict,
            max_objects,
            sequential,
            no_js_ast,
            no_js_sandbox,
        } => run_detect(
            &path,
            &glob,
            &findings,
            deep,
            max_decode_bytes,
            max_total_decoded_bytes,
            !no_recover,
            strict,
            max_objects,
            sequential,
            !no_js_ast,
            !no_js_sandbox,
        ),
        Command::Extract {
            kind,
            pdf,
            out,
            max_extract_bytes,
        } => run_extract(&kind, &pdf, &out, max_extract_bytes),
        Command::Report {
            pdf,
            deep,
            max_decode_bytes,
            max_total_decoded_bytes,
            no_recover,
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
        } => run_report(
            &pdf,
            deep,
            max_decode_bytes,
            max_total_decoded_bytes,
            !no_recover,
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
        ),
        Command::MlHealth {
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
        Command::ExportGraph {
            pdf,
            chains_only,
            format,
            out,
        } => run_export_graph(&pdf, chains_only, &format, &out),
        Command::ExportOrg { pdf, format, out, basic } => run_export_org(&pdf, &format, &out, !basic),
        Command::ExportIr { pdf, format, out, basic } => run_export_ir(&pdf, &format, &out, !basic),
        Command::ExportFeatures {
            pdf,
            path,
            glob,
            deep,
            max_decode_bytes,
            max_total_decoded_bytes,
            no_recover,
            strict,
            label,
            format,
            out,
            basic,
            feature_names,
        } => run_export_features(
            pdf.as_deref(),
            path.as_deref(),
            &glob,
            deep,
            max_decode_bytes,
            max_total_decoded_bytes,
            !no_recover,
            strict,
            label.as_deref(),
            &format,
            out.as_deref(),
            !basic,
            feature_names,
        ),
        Command::ComputeBaseline { input, out } => {
            run_compute_baseline(&input, &out)
        }
        Command::StreamAnalyze {
            pdf,
            chunk_size,
            max_buffer,
        } => run_stream_analyze(&pdf, chunk_size, max_buffer),
        Command::CampaignCorrelate { input, out } => {
            run_campaign_correlate(&input, out.as_deref())
        }
        Command::ResponseGenerate {
            kind,
            from_report,
            out,
        } => run_response_generate(kind.as_deref(), from_report.as_deref(), out.as_deref()),
        Command::Mutate { pdf, out, scan } => run_mutate(&pdf, &out, scan),
        Command::RedTeam { target, out } => run_redteam(&target, &out),
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

fn validate_ml_config(scan: &sis_pdf_core::config::ScanConfig) -> Result<()> {
    const ALLOWED_MODES: &[&str] = &["traditional", "graph"];
    const ALLOWED_PROVIDERS: &[&str] = &[
        "auto",
        "cpu",
        "cuda",
        "rocm",
        "migraphx",
        "directml",
        "coreml",
        "onednn",
        "openvino",
    ];
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
            return Err(anyhow!(
                "invalid ml_threshold {} (expected 0.0..=1.0)",
                threshold
            ));
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
fn mmap_file(path: &str) -> Result<Mmap> {
    let f = fs::File::open(path)?;
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
    unsafe { Mmap::map(&f).map_err(|e| anyhow!(e)) }
}
fn run_scan(
    pdf: Option<&str>,
    path: Option<&std::path::Path>,
    glob: &str,
    deep: bool,
    max_decode_bytes: usize,
    max_total_decoded_bytes: usize,
    recover_xref: bool,
    json: bool,
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
    cache_dir: Option<&std::path::Path>,
    sequential: bool,
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
    let detectors = sis_pdf_detectors::default_detectors_with_settings(
        sis_pdf_detectors::DetectorSettings {
            js_ast,
            js_sandbox,
        },
    );
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
    let mmap = mmap_file(pdf)?;
    let sandbox_summary = sis_pdf_detectors::sandbox_summary(js_sandbox);
    let mut report =
        run_scan_single(&mmap, pdf, &opts, &detectors)?.with_sandbox_summary(sandbox_summary);
    if ml_inference_requested {
        match run_ml_inference_for_scan(
            &mmap,
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
        let (temporal_summary, temporal_snapshots, temporal_explanation) =
            run_temporal_analysis(
                &mmap,
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
        if let (Some(ml), Some(explanation)) =
            (report.ml_inference.as_mut(), temporal_explanation)
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
        },
    )?;
    Ok(sis_pdf_core::scan::ScanContext::new(
        mmap,
        graph,
        opts.clone(),
    ))
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
    let model_path = ml_model_dir.ok_or_else(|| anyhow!("--ml-model-dir is required for ML inference"))?;
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
    let model_path = ml_model_dir.ok_or_else(|| anyhow!("--ml-model-dir is required for ML temporal analysis"))?;
    let baseline_path = ml_baseline.ok_or_else(|| anyhow!("--ml-temporal requires --ml-baseline"))?;

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
            .filter(|f| matches!(f.severity, sis_pdf_core::model::Severity::High | sis_pdf_core::model::Severity::Critical))
            .count();
        snapshots.push(sis_pdf_core::explainability::TemporalSnapshot {
            version_label: scan.label.clone(),
            score: inference.prediction.calibrated_score,
            high_severity_count: high_severity,
            finding_count: scan.report.findings.len(),
        });
    }

    let temporal_explanation = Some(
        sis_pdf_core::explainability::analyse_temporal_risk(&snapshots),
    );

    Ok((temporal_summary, Some(snapshots), temporal_explanation))
}

fn run_scan_single(
    mmap: &Mmap,
    pdf: &str,
    opts: &sis_pdf_core::scan::ScanOptions,
    detectors: &[Box<dyn sis_pdf_core::detect::Detector>],
) -> Result<sis_pdf_core::report::Report> {
    let report = sis_pdf_core::runner::run_scan_with_detectors(&mmap, opts.clone(), detectors)?
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
        sis_pdf_core::campaign::extract_network_intents_from_findings(
            &report.findings,
            &options,
        )
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
        WalkDir::new(dir.parent().unwrap_or(dir))
            .follow_links(false)
            .max_depth(MAX_WALK_DEPTH)
    } else {
        WalkDir::new(dir)
            .follow_links(false)
            .max_depth(MAX_WALK_DEPTH)
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
    let thread_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let use_parallel = batch_parallel && thread_count > 1 && paths.len() > 1;
    let indexed_paths: Vec<(usize, PathBuf)> = paths.into_iter().enumerate().collect();
    let process_path = |path: &PathBuf| -> Result<sis_pdf_core::report::BatchEntry> {
        let path_str = path.display().to_string();
        let start = std::time::Instant::now();
        let mmap = mmap_file(&path_str)?;
        let hash = sha256_hex(&mmap);
        let mut report = if let Some(cache) = &cache {
            cache.load(&hash)
        } else {
            None
        };
        if report.is_none() {
            report = Some(
                sis_pdf_core::runner::run_scan_with_detectors(&mmap, opts.clone(), detectors)?
                    .with_input_path(Some(path_str.clone())),
            );
            if let (Some(cache), Some(ref report)) = (&cache, report.as_ref()) {
                let _ = cache.store(&hash, report);
            }
        } else if let Some(rep) = report.take() {
            report = Some(rep.with_input_path(Some(path_str.clone())));
        }
        let report = report.expect("report");
        if let Some(writer) = intent_writer.as_ref() {
            let mut guard = writer
                .lock()
                .map_err(|_| anyhow!("intent writer lock poisoned"))?;
            write_intents_jsonl(&report, guard.as_mut(), intents_derived)?;
        }
        if let Some(writer) = findings_writer.as_ref() {
            let mut guard = writer
                .lock()
                .map_err(|_| anyhow!("findings writer lock poisoned"))?;
            sis_pdf_core::report::write_jsonl_findings(&report, guard.as_mut())?;
        }
        let duration_ms = start.elapsed().as_millis() as u64;
        Ok(sis_pdf_core::report::BatchEntry {
            path: path_str,
            summary: report.summary,
            duration_ms,
        })
    };
    let mut entries: Vec<(usize, sis_pdf_core::report::BatchEntry)> = if use_parallel {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(thread_count)
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
    let mut summary = sis_pdf_core::report::Summary {
        total: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
    };
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
    let avg_ms = if entries.is_empty() {
        0
    } else {
        timing_total_ms / entries.len() as u64
    };
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
fn run_explain(pdf: &str, finding_id: &str) -> Result<()> {
    let mmap = mmap_file(pdf)?;
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
    };
    let detectors = sis_pdf_detectors::default_detectors();
    let sandbox_summary = sis_pdf_detectors::sandbox_summary(true);
    let report = sis_pdf_core::runner::run_scan_with_detectors(&mmap, opts, &detectors)?
        .with_input_path(Some(pdf.to_string()))
        .with_sandbox_summary(sandbox_summary);
    let Some(finding) = report.findings.iter().find(|f| f.id == finding_id) else {
        return Err(anyhow!("finding id not found"));
    };
    println!(
        "{} - {}",
        escape_terminal(&finding.id),
        escape_terminal(&finding.title)
    );
    println!("{}", escape_terminal(&finding.description));
    println!("Severity: {:?}  Confidence: {:?}", finding.severity, finding.confidence);
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
            let end = start.saturating_add(ev.length as usize).min(mmap.len());
            let slice = &mmap[start..end];
            println!("{}", preview_bytes(slice));
        } else {
            println!("(decoded evidence preview not available)");
        }
    }
    Ok(())
}

fn run_detect(
    path: &std::path::Path,
    glob: &str,
    findings: &[String],
    deep: bool,
    max_decode_bytes: usize,
    max_total_decoded_bytes: usize,
    recover_xref: bool,
    strict: bool,
    max_objects: usize,
    sequential: bool,
    js_ast: bool,
    js_sandbox: bool,
) -> Result<()> {
    if findings.is_empty() {
        return Err(anyhow!("--findings must specify at least one finding ID"));
    }

    let opts = sis_pdf_core::scan::ScanOptions {
        deep,
        max_decode_bytes,
        max_total_decoded_bytes,
        recover_xref,
        parallel: false,
        batch_parallel: !sequential,
        diff_parser: strict,
        max_objects,
        max_recursion_depth: 64,
        strict,
        strict_summary: false,
        ir: false,
        fast: false,
        focus_trigger: None,
        focus_depth: 0,
        yara_scope: None,
        ml_config: None,
    };

    let settings = sis_pdf_detectors::DetectorSettings {
        js_ast,
        js_sandbox,
    };
    let detectors = sis_pdf_detectors::default_detectors_with_settings(settings);

    // Set up glob matcher
    let matcher = Glob::new(glob)?.compile_matcher();

    // Walk directory and collect matching files
    let iter = WalkDir::new(path)
        .follow_links(false)
        .max_depth(MAX_WALK_DEPTH);

    let mut paths = Vec::new();
    for entry in iter.into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if !matcher.is_match(path) {
            continue;
        }
        paths.push(path.to_path_buf());
    }

    // Scan files and filter by findings
    let matching_files: Vec<String> = if opts.batch_parallel {
        paths
            .par_iter()
            .filter_map(|path| {
                scan_and_check_findings(path, &opts, &detectors, findings)
            })
            .collect()
    } else {
        paths
            .iter()
            .filter_map(|path| {
                scan_and_check_findings(path, &opts, &detectors, findings)
            })
            .collect()
    };

    // Output only the filenames, one per line
    for file in matching_files {
        println!("{}", file);
    }

    Ok(())
}

fn scan_and_check_findings(
    path: &std::path::Path,
    opts: &sis_pdf_core::scan::ScanOptions,
    detectors: &[Box<dyn sis_pdf_core::detect::Detector>],
    required_findings: &[String],
) -> Option<String> {
    // Attempt to scan the file
    let mmap = match mmap_file(path.to_str()?) {
        Ok(m) => m,
        Err(_) => return None, // Skip files that can't be read
    };

    let report = match sis_pdf_core::runner::run_scan_with_detectors(&mmap, opts.clone(), detectors) {
        Ok(r) => r,
        Err(_) => return None, // Skip files that fail to scan
    };

    // Check if ALL required findings are present
    let mut found_findings = std::collections::HashSet::new();
    for finding in &report.findings {
        found_findings.insert(finding.kind.as_str());
    }

    let has_all_findings = required_findings
        .iter()
        .all(|required| found_findings.contains(required.as_str()));

    if has_all_findings {
        Some(path.to_string_lossy().to_string())
    } else {
        None
    }
}

fn run_extract(kind: &str, pdf: &str, outdir: &PathBuf, max_extract_bytes: usize) -> Result<()> {
    let mmap = mmap_file(pdf)?;
    fs::create_dir_all(outdir)?;
    let graph = sis_pdf_pdf::parse_pdf(
        &mmap,
        sis_pdf_pdf::ParseOptions {
            recover_xref: true,
            deep: false,
            strict: false,
            max_objstm_bytes: 32 * 1024 * 1024,
            max_objects: 500_000,
            max_objstm_total_bytes: 256 * 1024 * 1024,
        },
    )?;
    match kind {
        "js" => extract_js(&graph, &mmap, outdir),
        "embedded" => extract_embedded(&graph, &mmap, outdir, max_extract_bytes),
        _ => Err(anyhow!("unknown extract kind")),
    }
}
fn run_export_graph(pdf: &str, chains_only: bool, format: &str, outdir: &PathBuf) -> Result<()> {
    let mmap = mmap_file(pdf)?;
    fs::create_dir_all(outdir)?;
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
    };
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(&mmap, opts, &detectors)?
        .with_input_path(Some(pdf.to_string()));
    let ext = if format == "json" { "json" } else { "dot" };
    for chain in &report.chains {
        let path = outdir.join(format!("chain_{}.{}", chain.id, ext));
        match format {
            "json" => {
                let v = sis_pdf_core::graph_export::export_chain_json(chain);
                fs::write(path, serde_json::to_vec_pretty(&v)?)?;
            }
            _ => {
                let dot = sis_pdf_core::graph_export::export_chain_dot(chain);
                fs::write(path, dot)?;
            }
        }
    }
    if chains_only {
        return Ok(());
    }
    Ok(())
}
fn run_export_org(pdf: &str, format: &str, out: &PathBuf, enhanced: bool) -> Result<()> {
    let mmap = mmap_file(pdf)?;
    let graph = sis_pdf_pdf::parse_pdf(
        &mmap,
        sis_pdf_pdf::ParseOptions {
            recover_xref: true,
            deep: false,
            strict: false,
            max_objstm_bytes: 32 * 1024 * 1024,
            max_objects: 500_000,
            max_objstm_total_bytes: 256 * 1024 * 1024,
        },
    )?;

    if enhanced {
        // Build enhanced ORG with classifications, typed edges, and suspicious paths
        let opts = sis_pdf_core::scan::ScanOptions {
            deep: false,
            max_decode_bytes: 32 * 1024 * 1024,
            max_total_decoded_bytes: 256 * 1024 * 1024,
            recover_xref: true,
            parallel: false,
            batch_parallel: false,
            diff_parser: false,
            max_objects: 500_000,
            max_recursion_depth: 50,
            fast: false,
            focus_trigger: None,
            yara_scope: None,
            focus_depth: 5,
            strict: false,
            strict_summary: false,
            ir: false,
            ml_config: None,
        };
        let ctx = sis_pdf_core::scan::ScanContext::new(&mmap, graph, opts.clone());
        let classifications = ctx.classifications();
        let typed_graph = ctx.build_typed_graph();
        let org = sis_pdf_core::org::OrgGraph::from_object_graph_enhanced(
            &ctx.graph,
            classifications,
            &typed_graph,
        );

        // Run detectors to get findings for path analysis
        let detectors = sis_pdf_detectors::default_detectors_with_settings(
            sis_pdf_detectors::DetectorSettings {
                js_ast: true,
                js_sandbox: false,
            },
        );
        let report = sis_pdf_core::runner::run_scan_with_detectors(&mmap, opts, &detectors)?;
        let findings = &report.findings;

        // Extract suspicious paths
        let path_finder = typed_graph.path_finder();
        let action_chains = path_finder.find_all_action_chains();
        let path_explanation = sis_pdf_core::explainability::extract_suspicious_paths(&action_chains, findings, None);

        // Create enhanced export with paths
        let export = sis_pdf_core::org_export::OrgExportWithPaths::enhanced(org, path_explanation);

        match format {
            "json" => {
                let v = sis_pdf_core::org_export::export_org_with_paths_json(&export);
                fs::write(out, serde_json::to_vec_pretty(&v)?)?;
            }
            _ => {
                // For DOT format, just export the ORG without paths (paths don't render well in DOT)
                let dot = sis_pdf_core::org_export::export_org_dot(&export.org);
                fs::write(out, dot)?;
            }
        }
    } else {
        // Basic ORG export (no enhancements)
        let org = sis_pdf_core::org::OrgGraph::from_object_graph(&graph);
        match format {
            "json" => {
                let v = sis_pdf_core::org_export::export_org_json(&org);
                fs::write(out, serde_json::to_vec_pretty(&v)?)?;
            }
            _ => {
                let dot = sis_pdf_core::org_export::export_org_dot(&org);
                fs::write(out, dot)?;
            }
        }
    }
    Ok(())
}

fn run_export_ir(pdf: &str, format: &str, out: &PathBuf, enhanced: bool) -> Result<()> {
    let mmap = mmap_file(pdf)?;
    let graph = sis_pdf_pdf::parse_pdf(
        &mmap,
        sis_pdf_pdf::ParseOptions {
            recover_xref: true,
            deep: false,
            strict: false,
            max_objstm_bytes: 32 * 1024 * 1024,
            max_objects: 500_000,
            max_objstm_total_bytes: 256 * 1024 * 1024,
        },
    )?;
    let ir_opts = sis_pdf_pdf::ir::IrOptions::default();
    let ir_objects = sis_pdf_pdf::ir::ir_for_graph(&graph.objects, &ir_opts);

    if enhanced {
        // Run detectors to get findings
        let opts = sis_pdf_core::scan::ScanOptions {
            deep: false,
            max_decode_bytes: 32 * 1024 * 1024,
            max_total_decoded_bytes: 256 * 1024 * 1024,
            recover_xref: true,
            parallel: false,
            batch_parallel: false,
            diff_parser: false,
            max_objects: 500_000,
            max_recursion_depth: 50,
            fast: false,
            focus_trigger: None,
            yara_scope: None,
            focus_depth: 5,
            strict: false,
            strict_summary: false,
            ir: false,
            ml_config: None,
        };
        let detectors = sis_pdf_detectors::default_detectors_with_settings(
            sis_pdf_detectors::DetectorSettings {
                js_ast: true,
                js_sandbox: false,
            },
        );
        let report = sis_pdf_core::runner::run_scan_with_detectors(&mmap, opts, &detectors)?;
        let findings = &report.findings;

        // Generate enhanced IR export
        let enhanced_export = sis_pdf_core::ir_export::generate_enhanced_ir_export(&ir_objects, findings);

        match format {
            "json" => {
                let v = sis_pdf_core::ir_export::export_enhanced_ir_json(&enhanced_export);
                fs::write(out, serde_json::to_vec_pretty(&v)?)?;
            }
            _ => {
                let text = sis_pdf_core::ir_export::export_enhanced_ir_text(&enhanced_export);
                fs::write(out, text)?;
            }
        }
    } else {
        // Basic IR export (no findings)
        match format {
            "json" => {
                let v = sis_pdf_core::ir_export::export_ir_json(&ir_objects);
                fs::write(out, serde_json::to_vec_pretty(&v)?)?;
            }
            _ => {
                let text = sis_pdf_core::ir_export::export_ir_text(&ir_objects);
                fs::write(out, text)?;
            }
        }
    }
    Ok(())
}
fn run_report(
    pdf: &str,
    deep: bool,
    max_decode_bytes: usize,
    max_total_decoded_bytes: usize,
    recover_xref: bool,
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
) -> Result<()> {
    let mmap = mmap_file(pdf)?;
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
    let detectors = sis_pdf_detectors::default_detectors_with_settings(
        sis_pdf_detectors::DetectorSettings {
            js_ast,
            js_sandbox,
        },
    );
    let mut report = sis_pdf_core::runner::run_scan_with_detectors(&mmap, opts.clone(), &detectors)?
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
            &mmap,
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
        let (temporal_summary, temporal_snapshots, temporal_explanation) =
            run_temporal_analysis(
                &mmap,
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
        if let (Some(ml), Some(explanation)) =
            (report.ml_inference.as_mut(), temporal_explanation)
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
fn run_export_features(
    pdf: Option<&str>,
    path: Option<&std::path::Path>,
    glob: &str,
    deep: bool,
    max_decode_bytes: usize,
    max_total_decoded_bytes: usize,
    recover_xref: bool,
    strict: bool,
    label: Option<&str>,
    format: &str,
    out: Option<&std::path::Path>,
    extended: bool,
    feature_names: bool,
) -> Result<()> {
    if path.is_some() && pdf.is_some() {
        return Err(anyhow!("provide either a PDF path or --path, not both"));
    }
    let opts_template = sis_pdf_core::scan::ScanOptions {
        deep,
        max_decode_bytes,
        max_total_decoded_bytes,
        recover_xref,
        parallel: false,
        batch_parallel: false,
        diff_parser: false,
        max_objects: 500_000,
        max_recursion_depth: 64,
        fast: false,
        focus_trigger: None,
        yara_scope: None,
        focus_depth: 0,
        strict,
        strict_summary: false,
        ir: false,
        ml_config: None,
    };
    let mut paths = Vec::new();
    if let Some(pdf) = pdf {
        paths.push(std::path::PathBuf::from(pdf));
    } else if let Some(dir) = path {
        let matcher = Glob::new(glob)?.compile_matcher();
        let iter = if dir.is_file() {
            WalkDir::new(dir.parent().unwrap_or(dir))
                .follow_links(false)
                .max_depth(MAX_WALK_DEPTH)
        } else {
            WalkDir::new(dir)
                .follow_links(false)
                .max_depth(MAX_WALK_DEPTH)
        };
        let mut total_bytes = 0u64;
        let mut file_count = 0usize;
        for entry in iter.into_iter().filter_map(Result::ok) {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if matcher.is_match(path) {
                file_count += 1;
                if file_count > MAX_BATCH_FILES {
                    SecurityEvent {
                        level: Level::ERROR,
                        domain: SecurityDomain::Detection,
                        severity: SecuritySeverity::Medium,
                        kind: "export_file_limit_exceeded",
                        policy: None,
                        object_id: None,
                        object_type: None,
                        vector: None,
                        technique: None,
                        confidence: None,
                        message: "Export file count exceeded",
                    }
                    .emit();
                    error!(max_files = MAX_BATCH_FILES, "Export file count exceeded");
                    return Err(anyhow!("export file count exceeds limit"));
                }
                if let Ok(meta) = entry.metadata() {
                    total_bytes = total_bytes.saturating_add(meta.len());
                    if total_bytes > MAX_BATCH_BYTES {
                        SecurityEvent {
                            level: Level::ERROR,
                            domain: SecurityDomain::Detection,
                            severity: SecuritySeverity::Medium,
                            kind: "export_size_limit_exceeded",
                            policy: None,
                            object_id: None,
                            object_type: None,
                            vector: None,
                            technique: None,
                            confidence: None,
                            message: "Export byte limit exceeded",
                        }
                        .emit();
                        error!(
                            total_bytes = total_bytes,
                            max_bytes = MAX_BATCH_BYTES,
                            "Export byte limit exceeded"
                        );
                        return Err(anyhow!("export size exceeds limit"));
                    }
                }
                paths.push(path.to_path_buf());
            }
        }
    }
    if paths.is_empty() {
        return Err(anyhow!("no files matched {} in export", glob));
    }
    let mut writer: Box<dyn Write> = if let Some(path) = out {
        Box::new(fs::File::create(path)?)
    } else {
        Box::new(std::io::stdout())
    };

    // Get feature names based on extended flag
    let names = if extended {
        sis_pdf_core::features_extended::extended_feature_names()
    } else {
        sis_pdf_core::features::feature_names()
            .into_iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    };

    if format == "csv" {
        let mut header = String::from("path,label");
        for name in &names {
            header.push(',');
            header.push_str(name);
        }
        header.push('\n');
        writer.write_all(header.as_bytes())?;
    }

    // For extended features, we need detectors
    let detectors = if extended {
        Some(sis_pdf_detectors::default_detectors_with_settings(
            sis_pdf_detectors::DetectorSettings {
                js_ast: true,
                js_sandbox: false,
            },
        ))
    } else {
        None
    };

    for path in paths {
        let path_str = path.display().to_string();
        let mmap = mmap_file(&path_str)?;

        let feature_vec = if extended {
            // Clone opts for this iteration to avoid move issues
            let opts1 = opts_template.clone();
            let opts2 = opts_template.clone();

            // Run full scan to get findings
            let report = sis_pdf_core::runner::run_scan_with_detectors(&mmap, opts1, detectors.as_ref().unwrap())?;

            // Parse PDF again to create ScanContext for feature extraction
            let graph = sis_pdf_pdf::parse_pdf(
                &mmap,
                sis_pdf_pdf::ParseOptions {
                    recover_xref: opts_template.recover_xref,
                    deep: opts_template.deep,
                    strict: opts_template.strict,
                    max_objstm_bytes: opts_template.max_decode_bytes,
                    max_objects: opts_template.max_objects,
                    max_objstm_total_bytes: opts_template.max_total_decoded_bytes,
                },
            )?;
            let ctx = sis_pdf_core::scan::ScanContext::new(&mmap, graph, opts2);

            // Extract extended features
            let extended_fv = sis_pdf_core::features_extended::extract_extended_features(&ctx, &report.findings);
            extended_fv.as_f32_vec()
        } else {
            // Basic feature extraction
            let fv = sis_pdf_core::features::FeatureExtractor::extract_from_bytes(&mmap, &opts_template)?;
            fv.as_f32_vec()
        };

        match format {
            "jsonl" => {
                let record = if feature_names {
                    serde_json::json!({
                        "path": path_str,
                        "label": label,
                        "features": feature_vec,
                        "feature_names": &names,
                    })
                } else {
                    serde_json::json!({
                        "path": path_str,
                        "label": label,
                        "features": feature_vec,
                    })
                };
                writer.write_all(serde_json::to_string(&record)?.as_bytes())?;
                writer.write_all(b"\n")?;
            }
            "csv" => {
                let mut row = String::new();
                row.push_str(&path_str);
                row.push(',');
                row.push_str(label.unwrap_or(""));
                for v in feature_vec {
                    row.push(',');
                    row.push_str(&format!("{:.6}", v));
                }
                row.push('\n');
                writer.write_all(row.as_bytes())?;
            }
            _ => return Err(anyhow!("unsupported format: {}", format)),
        }
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
            let vec: Vec<f32> = features
                .iter()
                .filter_map(|v| v.as_f64().map(|f| f as f32))
                .collect();

            if vec.len() == 333 || vec.len() == 35 {
                feature_samples.push(vec);
            } else {
                warn!(
                    line = line_num + 1,
                    feature_count = vec.len(),
                    "Unexpected feature count"
                );
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
        entry.network_intents.push(sis_pdf_core::campaign::NetworkIntent {
            url: url.to_string(),
            domain,
        });
    }
    let analyses: Vec<sis_pdf_core::campaign::PDFAnalysis> = by_path.into_values().collect();
    let correlator = sis_pdf_core::campaign::MultiStageCorrelator;
    let campaigns = correlator.correlate_campaign(&analyses);
    let mut output = serde_json::json!({
        "campaigns": campaigns,
    });
    if let serde_json::Value::Object(map) = &mut output {
        let intents: Vec<sis_pdf_core::campaign::NetworkIntent> = analyses
            .iter()
            .flat_map(|a| a.network_intents.iter().cloned())
            .collect();
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
            println!(
                "mutant {:02} {} deltas: {}",
                idx + 1,
                mutant.note,
                deltas.join(", ")
            );
        }
    }
    Ok(())
}
fn count_kinds(findings: &[sis_pdf_core::model::Finding]) -> std::collections::BTreeMap<String, usize> {
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
    let keys: std::collections::BTreeSet<&String> =
        base.keys().chain(current.keys()).collect();
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
    let info = sis_pdf_ml_graph::ml_health_check(ml_model_dir, &sis_pdf_ml_graph::RuntimeSettings {
        provider: runtime.provider.clone(),
        provider_order: runtime.provider_order.clone(),
        ort_dylib_path: runtime.ort_dylib_path.clone(),
        prefer_quantized: runtime.prefer_quantized,
        max_embedding_batch_size: runtime.max_embedding_batch_size,
        print_provider: runtime.print_provider,
    })?;
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
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}
fn extract_js(graph: &sis_pdf_pdf::ObjectGraph<'_>, bytes: &[u8], outdir: &PathBuf) -> Result<()> {
    let mut count = 0usize;
    for entry in &graph.objects {
        if let Some(dict) = entry_dict(entry) {
            if let Some((_, obj)) = dict.get_first(b"/JS") {
                if let Some(data) = extract_obj_bytes(graph, bytes, obj) {
                    let path = outdir.join(format!("js_{}_{}.js", entry.obj, entry.gen));
                    fs::write(path, data)?;
                    count += 1;
                }
            }
        }
    }
    println!("Extracted {} JavaScript payloads", count);
    Ok(())
}
fn extract_embedded(
    graph: &sis_pdf_pdf::ObjectGraph<'_>,
    bytes: &[u8],
    outdir: &PathBuf,
    max_extract_bytes: usize,
) -> Result<()> {
    let mut count = 0usize;
    let mut total_written = 0usize;
    for entry in &graph.objects {
        if let sis_pdf_pdf::object::PdfAtom::Stream(st) = &entry.atom {
            if st.dict.has_name(b"/Type", b"/EmbeddedFile") {
                if let Ok(decoded) = sis_pdf_pdf::decode::decode_stream(bytes, st, 32 * 1024 * 1024)
                {
                    let name = embedded_filename(&st.dict).unwrap_or_else(|| {
                        format!("embedded_{}_{}.bin", entry.obj, entry.gen)
                    });
                    let safe_name = sanitize_embedded_filename(&name);
                    let path = outdir.join(&safe_name);
                    if max_extract_bytes > 0
                        && total_written.saturating_add(decoded.data.len()) > max_extract_bytes
                    {
                        println!(
                            "Embedded extraction budget exceeded ({} bytes), stopping",
                            max_extract_bytes
                        );
                        break;
                    }
                    let hash = sha256_hex(&decoded.data);
                    let magic = magic_type(&decoded.data);
                    let data_len = decoded.data.len();
                    fs::write(path, decoded.data)?;
                    println!("Embedded file: sha256={} magic={}", hash, magic);
                    total_written = total_written.saturating_add(data_len);
                    count += 1;
                }
            }
        }
    }
    println!("Extracted {} embedded files", count);
    Ok(())
}
fn embedded_filename(dict: &sis_pdf_pdf::object::PdfDict<'_>) -> Option<String> {
    if let Some((_, obj)) = dict.get_first(b"/F") {
        if let sis_pdf_pdf::object::PdfAtom::Str(s) = &obj.atom {
            return Some(String::from_utf8_lossy(&string_bytes(s)).to_string());
        }
    }
    if let Some((_, obj)) = dict.get_first(b"/UF") {
        if let sis_pdf_pdf::object::PdfAtom::Str(s) = &obj.atom {
            return Some(String::from_utf8_lossy(&string_bytes(s)).to_string());
        }
    }
    None
}
fn sanitize_embedded_filename(name: &str) -> String {
    let leaf = std::path::Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("embedded.bin");
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
fn entry_dict<'a>(entry: &'a sis_pdf_pdf::graph::ObjEntry<'a>) -> Option<&'a sis_pdf_pdf::object::PdfDict<'a>> {
    match &entry.atom {
        sis_pdf_pdf::object::PdfAtom::Dict(d) => Some(d),
        sis_pdf_pdf::object::PdfAtom::Stream(st) => Some(&st.dict),
        _ => None,
    }
}
fn extract_obj_bytes(
    graph: &sis_pdf_pdf::ObjectGraph<'_>,
    bytes: &[u8],
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
) -> Option<Vec<u8>> {
    match &obj.atom {
        sis_pdf_pdf::object::PdfAtom::Str(s) => Some(string_bytes(s)),
        sis_pdf_pdf::object::PdfAtom::Stream(st) => {
            sis_pdf_pdf::decode::decode_stream(bytes, st, 32 * 1024 * 1024)
                .ok()
                .map(|d| d.data)
        }
        sis_pdf_pdf::object::PdfAtom::Ref { .. } => {
            let entry = graph.resolve_ref(obj)?;
            match &entry.atom {
                sis_pdf_pdf::object::PdfAtom::Str(s) => Some(string_bytes(s)),
                sis_pdf_pdf::object::PdfAtom::Stream(st) => {
                    sis_pdf_pdf::decode::decode_stream(bytes, st, 32 * 1024 * 1024)
                        .ok()
                        .map(|d| d.data)
                }
                _ => None,
            }
        }
        _ => None,
    }
}
fn string_bytes(s: &sis_pdf_pdf::object::PdfStr<'_>) -> Vec<u8> {
    match s {
        sis_pdf_pdf::object::PdfStr::Literal { decoded, .. } => decoded.clone(),
        sis_pdf_pdf::object::PdfStr::Hex { decoded, .. } => decoded.clone(),
    }
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
    input
        .bytes()
        .all(|b| (0x20..=0x7E).contains(&b))
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
                message: "Read rejected due to size limit",
            }
            .emit();
            error!(
                path = %path.display(),
                size_bytes = meta.len(),
                max_bytes = max_bytes,
                "Read rejected due to size limit"
            );
            return Err(anyhow!(
                "file {} exceeds {} bytes",
                path.display(),
                max_bytes
            ));
        }
    }
    Ok(fs::read_to_string(path)?)
}
fn magic_type(data: &[u8]) -> String {
    if data.starts_with(b"MZ") {
        "pe".into()
    } else if data.starts_with(b"%PDF") {
        "pdf".into()
    } else if data.starts_with(b"PK\x03\x04") {
        "zip".into()
    } else if data.starts_with(b"\x7fELF") {
        "elf".into()
    } else if data.starts_with(b"#!") {
        "script".into()
    } else {
        "unknown".into()
    }
}

fn build_ml_runtime_config(
    provider: Option<&str>,
    provider_order: Option<&str>,
    print_provider: bool,
    ort_dylib: Option<&std::path::Path>,
    prefer_quantized: bool,
    batch_size: Option<usize>,
) -> sis_pdf_core::ml::MlRuntimeConfig {
    let provider = provider
        .and_then(|p| {
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
    use super::sanitize_embedded_filename;
    #[test]
    fn sanitize_embedded_filename_strips_paths() {
        let name = "../evil/../../payload.exe";
        let safe = sanitize_embedded_filename(name);
        assert!(!safe.contains('/'));
        assert!(!safe.contains('\\'));
        assert!(safe.ends_with("payload.exe"));
    }
}
