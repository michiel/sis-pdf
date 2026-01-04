use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use globset::Glob;
use memmap2::Mmap;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

#[derive(Parser)]
#[command(name = "sis")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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
        #[arg(long)]
        ml: bool,
        #[arg(long)]
        ml_model_dir: Option<PathBuf>,
        #[arg(long, default_value_t = 0.9)]
        ml_threshold: f32,
    },
    Explain {
        pdf: String,
        finding_id: String,
    },
    Extract {
        #[arg(value_parser = ["js", "embedded"])]
        kind: String,
        pdf: String,
        #[arg(short, long)]
        out: PathBuf,
    },
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
        #[arg(short, long)]
        out: Option<PathBuf>,
        #[arg(long)]
        ml: bool,
        #[arg(long)]
        ml_model_dir: Option<PathBuf>,
        #[arg(long, default_value_t = 0.9)]
        ml_threshold: f32,
    },
    ExportGraph {
        pdf: String,
        #[arg(long)]
        chains_only: bool,
        #[arg(long, default_value = "dot", value_parser = ["dot", "json"])]
        format: String,
        #[arg(short, long)]
        out: PathBuf,
    },
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
            yara,
            yara_out,
            yara_scope,
            diff_parser,
            fast,
            focus_trigger,
            focus_depth,
            strict,
            max_objects,
            max_recursion_depth,
            config,
            profile,
            cache_dir,
            ml,
            ml_model_dir,
            ml_threshold,
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
            yara,
            yara_out.as_deref(),
            &yara_scope,
            diff_parser,
            fast,
            focus_trigger,
            focus_depth,
            strict,
            max_objects,
            max_recursion_depth,
            config.as_deref(),
            profile.as_deref(),
            cache_dir.as_deref(),
            ml,
            ml_model_dir.as_deref(),
            ml_threshold,
        ),
        Command::Explain { pdf, finding_id } => run_explain(&pdf, &finding_id),
        Command::Extract { kind, pdf, out } => run_extract(&kind, &pdf, &out),
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
            out,
            ml,
            ml_model_dir,
            ml_threshold,
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
            out.as_deref(),
            ml,
            ml_model_dir.as_deref(),
            ml_threshold,
        ),
        Command::ExportGraph {
            pdf,
            chains_only,
            format,
            out,
        } => run_export_graph(&pdf, chains_only, &format, &out),
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
    }
}

fn mmap_file(path: &str) -> Result<Mmap> {
    let f = fs::File::open(path)?;
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
    yara: bool,
    yara_out: Option<&std::path::Path>,
    yara_scope: &str,
    diff_parser: bool,
    fast: bool,
    focus_trigger: Option<String>,
    focus_depth: usize,
    strict: bool,
    max_objects: usize,
    max_recursion_depth: usize,
    config: Option<&std::path::Path>,
    profile: Option<&str>,
    cache_dir: Option<&std::path::Path>,
    ml: bool,
    ml_model_dir: Option<&std::path::Path>,
    ml_threshold: f32,
) -> Result<()> {
    if path.is_some() && pdf.is_some() {
        return Err(anyhow!("provide either a PDF path or --path, not both"));
    }
    let mut opts = sis_pdf_core::scan::ScanOptions {
        deep,
        max_decode_bytes,
        max_total_decoded_bytes,
        recover_xref,
        parallel: true,
        diff_parser,
        max_objects,
        max_recursion_depth,
        fast,
        focus_trigger,
        focus_depth,
        yara_scope: Some(yara_scope.to_string()),
        strict,
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
        });
    } else if let Some(dir) = ml_model_dir {
        opts.ml_config = Some(sis_pdf_core::ml::MlConfig {
            model_path: dir.to_path_buf(),
            threshold: ml_threshold,
        });
    }
    let detectors = sis_pdf_detectors::default_detectors();
    if let Some(dir) = path {
        return run_scan_batch(
            dir,
            glob,
            opts,
            &detectors,
            json,
            jsonl,
            sarif,
            sarif_out,
            yara,
            yara_out,
            cache_dir,
        );
    }
    let pdf = pdf.ok_or_else(|| anyhow!("PDF path is required unless --path is set"))?;
    let report = run_scan_single(pdf, &opts, &detectors)?;
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

fn run_scan_batch(
    dir: &std::path::Path,
    glob: &str,
    opts: sis_pdf_core::scan::ScanOptions,
    detectors: &[Box<dyn sis_pdf_core::detect::Detector>],
    json: bool,
    jsonl: bool,
    sarif: bool,
    sarif_out: Option<&std::path::Path>,
    yara: bool,
    yara_out: Option<&std::path::Path>,
    cache_dir: Option<&std::path::Path>,
) -> Result<()> {
    if sarif || sarif_out.is_some() {
        return Err(anyhow!("SARIF output is not supported for batch scans"));
    }
    if yara || yara_out.is_some() {
        return Err(anyhow!("YARA output is not supported for batch scans"));
    }
    let cache = if let Some(dir) = cache_dir {
        Some(sis_pdf_core::cache::ScanCache::new(dir)?)
    } else {
        None
    };
    let matcher = Glob::new(glob)?.compile_matcher();
    let mut entries = Vec::new();
    let mut summary = sis_pdf_core::report::Summary {
        total: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
    };
    let mut timing_total_ms = 0u64;
    let mut timing_max_ms = 0u64;
    let iter = if dir.is_file() {
        WalkDir::new(dir.parent().unwrap_or(dir))
    } else {
        WalkDir::new(dir)
    };
    for entry in iter.into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if !matcher.is_match(path) {
            continue;
        }
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
        let duration_ms = start.elapsed().as_millis() as u64;
        timing_total_ms = timing_total_ms.saturating_add(duration_ms);
        timing_max_ms = timing_max_ms.max(duration_ms);
        summary.total += report.summary.total;
        summary.high += report.summary.high;
        summary.medium += report.summary.medium;
        summary.low += report.summary.low;
        summary.info += report.summary.info;
        entries.push(sis_pdf_core::report::BatchEntry {
            path: path_str,
            summary: report.summary,
            duration_ms,
        });
    }
    if entries.is_empty() {
        return Err(anyhow!("no files matched {} in {}", glob, dir.display()));
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
        deep: true,
        max_decode_bytes: 32 * 1024 * 1024,
        max_total_decoded_bytes: 256 * 1024 * 1024,
        recover_xref: true,
        parallel: false,
        diff_parser: false,
        max_objects: 500_000,
        max_recursion_depth: 64,
        fast: false,
        focus_trigger: None,
        focus_depth: 0,
        yara_scope: None,
        strict: false,
        ml_config: None,
    };
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(&mmap, opts, &detectors)?
        .with_input_path(Some(pdf.to_string()));
    let Some(finding) = report.findings.iter().find(|f| f.id == finding_id) else {
        return Err(anyhow!("finding id not found"));
    };
    println!("{} - {}", finding.id, finding.title);
    println!("{}", finding.description);
    println!("Severity: {:?}  Confidence: {:?}", finding.severity, finding.confidence);
    println!();
    for ev in &finding.evidence {
        println!(
            "Evidence: source={:?} offset={} length={} note={}",
            ev.source,
            ev.offset,
            ev.length,
            ev.note.as_deref().unwrap_or("-")
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

fn run_extract(kind: &str, pdf: &str, outdir: &PathBuf) -> Result<()> {
    let mmap = mmap_file(pdf)?;
    fs::create_dir_all(outdir)?;
    let graph = sis_pdf_pdf::parse_pdf(
        &mmap,
        sis_pdf_pdf::ParseOptions {
            recover_xref: true,
            deep: false,
            strict: false,
            max_objstm_bytes: 32 * 1024 * 1024,
        },
    )?;
    match kind {
        "js" => extract_js(&graph, &mmap, outdir),
        "embedded" => extract_embedded(&graph, &mmap, outdir),
        _ => Err(anyhow!("unknown extract kind")),
    }
}

fn run_export_graph(pdf: &str, chains_only: bool, format: &str, outdir: &PathBuf) -> Result<()> {
    let mmap = mmap_file(pdf)?;
    fs::create_dir_all(outdir)?;
    let opts = sis_pdf_core::scan::ScanOptions {
        deep: true,
        max_decode_bytes: 32 * 1024 * 1024,
        max_total_decoded_bytes: 256 * 1024 * 1024,
        recover_xref: true,
        parallel: false,
        diff_parser: false,
        max_objects: 500_000,
        max_recursion_depth: 64,
        fast: false,
        focus_trigger: None,
        focus_depth: 0,
        yara_scope: None,
        strict: false,
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
    out: Option<&std::path::Path>,
    ml: bool,
    ml_model_dir: Option<&std::path::Path>,
    ml_threshold: f32,
) -> Result<()> {
    let mmap = mmap_file(pdf)?;
    let opts = sis_pdf_core::scan::ScanOptions {
        deep,
        max_decode_bytes,
        max_total_decoded_bytes,
        recover_xref,
        parallel: false,
        diff_parser,
        max_objects,
        max_recursion_depth,
        fast: false,
        focus_trigger: None,
        yara_scope: None,
        focus_depth: 0,
        strict,
        ml_config: None,
    };
    let mut opts = opts;
    if ml {
        let model_dir = ml_model_dir.ok_or_else(|| anyhow!("--ml requires --ml-model-dir"))?;
        opts.ml_config = Some(sis_pdf_core::ml::MlConfig {
            model_path: model_dir.to_path_buf(),
            threshold: ml_threshold,
        });
    } else if let Some(dir) = ml_model_dir {
        opts.ml_config = Some(sis_pdf_core::ml::MlConfig {
            model_path: dir.to_path_buf(),
            threshold: ml_threshold,
        });
    }
    let detectors = sis_pdf_detectors::default_detectors();
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
        diff_parser: false,
        max_objects: 500_000,
        max_recursion_depth: 64,
        fast: false,
        focus_trigger: None,
        yara_scope: None,
        focus_depth: 0,
        strict,
        ml_config: None,
    };
    let mut paths = Vec::new();
    if let Some(pdf) = pdf {
        paths.push(std::path::PathBuf::from(pdf));
    } else if let Some(dir) = path {
        let matcher = Glob::new(glob)?.compile_matcher();
        let iter = if dir.is_file() {
            WalkDir::new(dir.parent().unwrap_or(dir))
        } else {
            WalkDir::new(dir)
        };
        for entry in iter.into_iter().filter_map(Result::ok) {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if matcher.is_match(path) {
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
) -> Result<()> {
    let mut count = 0usize;
    for entry in &graph.objects {
        if let sis_pdf_pdf::object::PdfAtom::Stream(st) = &entry.atom {
            if st.dict.has_name(b"/Type", b"/EmbeddedFile") {
                if let Ok(decoded) = sis_pdf_pdf::decode::decode_stream(bytes, st, 32 * 1024 * 1024)
                {
                    let name = embedded_filename(&st.dict).unwrap_or_else(|| {
                        format!("embedded_{}_{}.bin", entry.obj, entry.gen)
                    });
                    let path = outdir.join(name);
                    let hash = sha256_hex(&decoded.data);
                    let magic = magic_type(&decoded.data);
                    fs::write(path, decoded.data)?;
                    println!("Embedded file: sha256={} magic={}", hash, magic);
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
        if b.is_ascii_graphic() || b == b' ' {
            s.push(b as char);
        } else {
            s.push('.');
        }
    }
    s
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    hex::encode(digest)
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
