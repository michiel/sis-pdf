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
        #[arg(long)]
        sarif: bool,
        #[arg(long)]
        sarif_out: Option<PathBuf>,
        #[arg(long)]
        export_intents: bool,
        #[arg(long)]
        export_intents_out: Option<PathBuf>,
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
        #[arg(long)]
        no_js_ast: bool,
        #[arg(long)]
        no_js_sandbox: bool,
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
    #[command(about = "Export object reference graph as DOT or JSON")]
    ExportOrg {
        pdf: String,
        #[arg(long, default_value = "dot", value_parser = ["dot", "json"])]
        format: String,
        #[arg(short, long)]
        out: PathBuf,
    },
    #[command(about = "Export PDFObj IR as text or JSON")]
    ExportIr {
        pdf: String,
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        format: String,
        #[arg(short, long)]
        out: PathBuf,
    },
    #[command(about = "Export feature vectors for ML pipelines")]
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
fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
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
            sarif,
            sarif_out,
            export_intents,
            export_intents_out,
            yara,
            yara_out,
            yara_scope,
            diff_parser,
            fast,
            focus_trigger,
            focus_depth,
            strict,
            ir,
            max_objects,
            max_recursion_depth,
            config,
            profile,
            cache_dir,
            sequential,
            ml,
            ml_model_dir,
            ml_threshold,
            ml_mode,
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
            sarif,
            sarif_out.as_deref(),
            export_intents,
            export_intents_out.as_deref(),
            yara,
            yara_out.as_deref(),
            &yara_scope,
            diff_parser,
            fast,
            focus_trigger,
            focus_depth,
            strict,
            ir,
            max_objects,
            max_recursion_depth,
            config.as_deref(),
            profile.as_deref(),
            cache_dir.as_deref(),
            sequential,
            ml,
            ml_model_dir.as_deref(),
            ml_threshold,
            &ml_mode,
            !no_js_ast,
            !no_js_sandbox,
        ),
        Command::Explain { pdf, finding_id } => run_explain(&pdf, &finding_id),
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
            !no_js_ast,
            !no_js_sandbox,
        ),
        Command::ExportGraph {
            pdf,
            chains_only,
            format,
            out,
        } => run_export_graph(&pdf, chains_only, &format, &out),
        Command::ExportOrg { pdf, format, out } => run_export_org(&pdf, &format, &out),
        Command::ExportIr { pdf, format, out } => run_export_ir(&pdf, &format, &out),
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
        ),
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
fn mmap_file(path: &str) -> Result<Mmap> {
    let f = fs::File::open(path)?;
    let size = f.metadata()?.len();
    if size > WARN_PDF_BYTES {
        eprintln!(
            "security_boundary: large file {} ({} bytes)",
            path, size
        );
    }
    if size > MAX_PDF_BYTES {
        eprintln!(
            "security_boundary: mmap rejected for {} ({} bytes exceeds limit {})",
            path, size, MAX_PDF_BYTES
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
    sarif: bool,
    sarif_out: Option<&std::path::Path>,
    export_intents: bool,
    export_intents_out: Option<&std::path::Path>,
    yara: bool,
    yara_out: Option<&std::path::Path>,
    yara_scope: &str,
    diff_parser: bool,
    fast: bool,
    focus_trigger: Option<String>,
    focus_depth: usize,
    strict: bool,
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
    js_ast: bool,
    js_sandbox: bool,
) -> Result<()> {
    if path.is_some() && pdf.is_some() {
        return Err(anyhow!("provide either a PDF path or --path, not both"));
    }
    let diff_parser = diff_parser || strict;
    if diff_parser && strict {
        eprintln!("security_boundary: enabling diff parser in strict mode");
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
        ir,
        ml_config: None,
    };
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
        });
    } else if let Some(dir) = ml_model_dir {
        opts.ml_config = Some(sis_pdf_core::ml::MlConfig {
            model_path: dir.to_path_buf(),
            threshold: ml_threshold,
            mode: parse_ml_mode(ml_mode),
        });
    }
    let want_export_intents = export_intents || export_intents_out.is_some();
    let detectors = sis_pdf_detectors::default_detectors_with_settings(
        sis_pdf_detectors::DetectorSettings {
            js_ast,
            js_sandbox,
        },
    );
    if let Some(dir) = path {
        let batch_parallel = opts.batch_parallel;
        return run_scan_batch(
            dir,
            glob,
            opts,
            &detectors,
            json,
            jsonl,
            sarif,
            sarif_out,
            want_export_intents,
            export_intents_out,
            yara,
            yara_out,
            cache_dir,
            batch_parallel,
        );
    }
    let pdf = pdf.ok_or_else(|| anyhow!("PDF path is required unless --path is set"))?;
    let sandbox_summary = sis_pdf_detectors::sandbox_summary(js_sandbox);
    let report = run_scan_single(pdf, &opts, &detectors)?.with_sandbox_summary(sandbox_summary);
    if want_export_intents {
        let mut writer: Box<dyn Write> = if let Some(path) = export_intents_out {
            Box::new(fs::File::create(path)?)
        } else {
            Box::new(std::io::stdout())
        };
        write_intents_jsonl(&report, writer.as_mut())?;
        return Ok(());
    }
    let want_sarif = sarif || sarif_out.is_some();
    let want_yara = yara || yara_out.is_some();
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
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
fn run_scan_single(
    pdf: &str,
    opts: &sis_pdf_core::scan::ScanOptions,
    detectors: &[Box<dyn sis_pdf_core::detect::Detector>],
) -> Result<sis_pdf_core::report::Report> {
    let mmap = mmap_file(pdf)?;
    let report = sis_pdf_core::runner::run_scan_with_detectors(&mmap, opts.clone(), detectors)?
        .with_input_path(Some(pdf.to_string()));
    Ok(report)
}
fn write_intents_jsonl(
    report: &sis_pdf_core::report::Report,
    writer: &mut dyn Write,
) -> Result<()> {
    let path = report.input_path.as_deref().unwrap_or("-");
    for intent in &report.network_intents {
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
    sarif: bool,
    sarif_out: Option<&std::path::Path>,
    export_intents: bool,
    export_intents_out: Option<&std::path::Path>,
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
            eprintln!(
                "security_boundary: batch file count exceeded (max {})",
                MAX_BATCH_FILES
            );
            return Err(anyhow!("batch file count exceeds limit"));
        }
        if let Ok(meta) = entry.metadata() {
            total_bytes = total_bytes.saturating_add(meta.len());
            if total_bytes > MAX_BATCH_BYTES {
                eprintln!(
                    "security_boundary: batch size exceeded ({} bytes, max {})",
                    total_bytes, MAX_BATCH_BYTES
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
            write_intents_jsonl(&report, guard.as_mut())?;
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
                eprintln!(
                    "security_boundary: failed to build batch worker pool; falling back to sequential ({})",
                    err
                );
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
fn run_export_org(pdf: &str, format: &str, out: &PathBuf) -> Result<()> {
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
    Ok(())
}

fn run_export_ir(pdf: &str, format: &str, out: &PathBuf) -> Result<()> {
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
    js_ast: bool,
    js_sandbox: bool,
) -> Result<()> {
    let mmap = mmap_file(pdf)?;
    let diff_parser = diff_parser || strict;
    if diff_parser && strict {
        eprintln!("security_boundary: enabling diff parser in strict mode");
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
        ir,
        ml_config: None,
    };
    let mut opts = opts;
    if ml {
        let model_dir = ml_model_dir.ok_or_else(|| anyhow!("--ml requires --ml-model-dir"))?;
        opts.ml_config = Some(sis_pdf_core::ml::MlConfig {
            model_path: model_dir.to_path_buf(),
            threshold: ml_threshold,
            mode: parse_ml_mode(ml_mode),
        });
    } else if let Some(dir) = ml_model_dir {
        opts.ml_config = Some(sis_pdf_core::ml::MlConfig {
            model_path: dir.to_path_buf(),
            threshold: ml_threshold,
            mode: parse_ml_mode(ml_mode),
        });
    }
    let detectors = sis_pdf_detectors::default_detectors_with_settings(
        sis_pdf_detectors::DetectorSettings {
            js_ast,
            js_sandbox,
        },
    );
    let report = sis_pdf_core::runner::run_scan_with_detectors(&mmap, opts, &detectors)?
        .with_input_path(Some(pdf.to_string()));
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
) -> Result<()> {
    if path.is_some() && pdf.is_some() {
        return Err(anyhow!("provide either a PDF path or --path, not both"));
    }
    let opts = sis_pdf_core::scan::ScanOptions {
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
                    eprintln!(
                        "security_boundary: export file count exceeded (max {})",
                        MAX_BATCH_FILES
                    );
                    return Err(anyhow!("export file count exceeds limit"));
                }
                if let Ok(meta) = entry.metadata() {
                    total_bytes = total_bytes.saturating_add(meta.len());
                    if total_bytes > MAX_BATCH_BYTES {
                        eprintln!(
                            "security_boundary: export size exceeded ({} bytes, max {})",
                            total_bytes, MAX_BATCH_BYTES
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
    let names = sis_pdf_core::features::feature_names();
    if format == "csv" {
        let mut header = String::from("path,label");
        for name in &names {
            header.push(',');
            header.push_str(name);
        }
        header.push('\n');
        writer.write_all(header.as_bytes())?;
    }
    for path in paths {
        let path_str = path.display().to_string();
        let mmap = mmap_file(&path_str)?;
        let fv = sis_pdf_core::features::FeatureExtractor::extract_from_bytes(&mmap, &opts)?;
        match format {
            "jsonl" => {
                let record = serde_json::json!({
                    "path": path_str,
                    "label": label,
                    "features": fv,
                });
                writer.write_all(serde_json::to_string(&record)?.as_bytes())?;
                writer.write_all(b"\n")?;
            }
            "csv" => {
                let mut row = String::new();
                row.push_str(&path_str);
                row.push(',');
                row.push_str(label.unwrap_or(""));
                for v in fv.as_f32_vec() {
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
            eprintln!(
                "security_boundary: JSONL line {} exceeds {} bytes",
                idx + 1,
                MAX_JSONL_LINE_BYTES
            );
            continue;
        }
        entries += 1;
        if entries > MAX_JSONL_ENTRIES {
            eprintln!(
                "security_boundary: JSONL entry limit exceeded (max {})",
                MAX_JSONL_ENTRIES
            );
            return Err(anyhow!("JSONL entry limit exceeded"));
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(err) => {
                eprintln!(
                    "security_boundary: JSONL parse error on line {}: {}",
                    idx + 1,
                    err
                );
                continue;
            }
        };
        let path = v.get("path").and_then(|v| v.as_str()).unwrap_or("unknown");
        let url = v.get("url").and_then(|v| v.as_str()).unwrap_or("");
        if url.is_empty() {
            continue;
        }
        if url.len() > MAX_CAMPAIGN_INTENT_LEN || !is_printable_ascii(url) {
            eprintln!(
                "security_boundary: JSONL url rejected (len={}, printable_ascii={})",
                url.len(),
                is_printable_ascii(url)
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
            eprintln!(
                "security_boundary: read rejected for {} ({} bytes exceeds limit {})",
                path.display(),
                meta.len(),
                max_bytes
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
