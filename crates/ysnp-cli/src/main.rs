use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use memmap2::Mmap;
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(name = "ysnp")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Scan {
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
        json: bool,
        #[arg(long)]
        jsonl: bool,
        #[arg(long)]
        sarif: bool,
        #[arg(long)]
        diff_parser: bool,
        #[arg(long)]
        fast: bool,
        #[arg(long)]
        focus_trigger: Option<String>,
        #[arg(long, default_value_t = 500_000)]
        max_objects: usize,
        #[arg(long, default_value_t = 64)]
        max_recursion_depth: usize,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        profile: Option<String>,
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
        #[arg(short, long)]
        out: Option<PathBuf>,
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
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Scan {
            pdf,
            deep,
            max_decode_bytes,
            max_total_decoded_bytes,
            no_recover,
            json,
            jsonl,
            sarif,
            diff_parser,
            fast,
            focus_trigger,
            max_objects,
            max_recursion_depth,
            config,
            profile,
        } => run_scan(
            &pdf,
            deep,
            max_decode_bytes,
            max_total_decoded_bytes,
            !no_recover,
            json,
            jsonl,
            sarif,
            diff_parser,
            fast,
            focus_trigger,
            max_objects,
            max_recursion_depth,
            config.as_deref(),
            profile.as_deref(),
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
            out,
        } => run_report(
            &pdf,
            deep,
            max_decode_bytes,
            max_total_decoded_bytes,
            !no_recover,
            diff_parser,
            max_objects,
            max_recursion_depth,
            out.as_deref(),
        ),
        Command::ExportGraph {
            pdf,
            chains_only,
            format,
            out,
        } => run_export_graph(&pdf, chains_only, &format, &out),
    }
}

fn mmap_file(path: &str) -> Result<Mmap> {
    let f = fs::File::open(path)?;
    unsafe { Mmap::map(&f).map_err(|e| anyhow!(e)) }
}

fn run_scan(
    pdf: &str,
    deep: bool,
    max_decode_bytes: usize,
    max_total_decoded_bytes: usize,
    recover_xref: bool,
    json: bool,
    jsonl: bool,
    sarif: bool,
    diff_parser: bool,
    fast: bool,
    focus_trigger: Option<String>,
    max_objects: usize,
    max_recursion_depth: usize,
    config: Option<&std::path::Path>,
    profile: Option<&str>,
) -> Result<()> {
    let mmap = mmap_file(pdf)?;
    let mut opts = ysnp_core::scan::ScanOptions {
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
    };
    if let Some(path) = config {
        let cfg = ysnp_core::config::Config::load(path)?;
        cfg.apply(&mut opts, profile);
    }
    let detectors = ysnp_detectors::default_detectors();
    let report = ysnp_core::runner::run_scan_with_detectors(&mmap, opts, &detectors)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if jsonl {
        ysnp_core::report::print_jsonl(&report)?;
    } else if sarif {
        let v = ysnp_core::report::to_sarif(&report);
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        ysnp_core::report::print_human(&report);
    }
    Ok(())
}

fn run_explain(pdf: &str, finding_id: &str) -> Result<()> {
    let mmap = mmap_file(pdf)?;
    let opts = ysnp_core::scan::ScanOptions {
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
    };
    let detectors = ysnp_detectors::default_detectors();
    let report = ysnp_core::runner::run_scan_with_detectors(&mmap, opts, &detectors)?;
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
        if matches!(ev.source, ysnp_core::model::EvidenceSource::File) {
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
    let graph = ysnp_pdf::parse_pdf(&mmap, ysnp_pdf::ParseOptions { recover_xref: true })?;
    match kind {
        "js" => extract_js(&graph, &mmap, outdir),
        "embedded" => extract_embedded(&graph, &mmap, outdir),
        _ => Err(anyhow!("unknown extract kind")),
    }
}

fn run_export_graph(pdf: &str, chains_only: bool, format: &str, outdir: &PathBuf) -> Result<()> {
    let mmap = mmap_file(pdf)?;
    fs::create_dir_all(outdir)?;
    let opts = ysnp_core::scan::ScanOptions {
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
    };
    let detectors = ysnp_detectors::default_detectors();
    let report = ysnp_core::runner::run_scan_with_detectors(&mmap, opts, &detectors)?;
    let ext = if format == "json" { "json" } else { "dot" };
    for chain in &report.chains {
        let path = outdir.join(format!("chain_{}.{}", chain.id, ext));
        match format {
            "json" => {
                let v = ysnp_core::graph_export::export_chain_json(chain);
                fs::write(path, serde_json::to_vec_pretty(&v)?)?;
            }
            _ => {
                let dot = ysnp_core::graph_export::export_chain_dot(chain);
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
    out: Option<&std::path::Path>,
) -> Result<()> {
    let mmap = mmap_file(pdf)?;
    let opts = ysnp_core::scan::ScanOptions {
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
    };
    let detectors = ysnp_detectors::default_detectors();
    let report = ysnp_core::runner::run_scan_with_detectors(&mmap, opts, &detectors)?;
    let md = ysnp_core::report::render_markdown(&report);
    if let Some(path) = out {
        fs::write(path, md)?;
    } else {
        println!("{}", md);
    }
    Ok(())
}

fn extract_js(graph: &ysnp_pdf::ObjectGraph<'_>, bytes: &[u8], outdir: &PathBuf) -> Result<()> {
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
    graph: &ysnp_pdf::ObjectGraph<'_>,
    bytes: &[u8],
    outdir: &PathBuf,
) -> Result<()> {
    let mut count = 0usize;
    for entry in &graph.objects {
        if let ysnp_pdf::object::PdfAtom::Stream(st) = &entry.atom {
            if st.dict.has_name(b"/Type", b"/EmbeddedFile") {
                if let Ok(decoded) = ysnp_pdf::decode::decode_stream(bytes, st, 32 * 1024 * 1024)
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

fn embedded_filename(dict: &ysnp_pdf::object::PdfDict<'_>) -> Option<String> {
    if let Some((_, obj)) = dict.get_first(b"/F") {
        if let ysnp_pdf::object::PdfAtom::Str(s) = &obj.atom {
            return Some(String::from_utf8_lossy(&string_bytes(s)).to_string());
        }
    }
    if let Some((_, obj)) = dict.get_first(b"/UF") {
        if let ysnp_pdf::object::PdfAtom::Str(s) = &obj.atom {
            return Some(String::from_utf8_lossy(&string_bytes(s)).to_string());
        }
    }
    None
}

fn entry_dict<'a>(entry: &'a ysnp_pdf::graph::ObjEntry<'a>) -> Option<&'a ysnp_pdf::object::PdfDict<'a>> {
    match &entry.atom {
        ysnp_pdf::object::PdfAtom::Dict(d) => Some(d),
        ysnp_pdf::object::PdfAtom::Stream(st) => Some(&st.dict),
        _ => None,
    }
}

fn extract_obj_bytes(
    graph: &ysnp_pdf::ObjectGraph<'_>,
    bytes: &[u8],
    obj: &ysnp_pdf::object::PdfObj<'_>,
) -> Option<Vec<u8>> {
    match &obj.atom {
        ysnp_pdf::object::PdfAtom::Str(s) => Some(string_bytes(s)),
        ysnp_pdf::object::PdfAtom::Stream(st) => {
            ysnp_pdf::decode::decode_stream(bytes, st, 32 * 1024 * 1024)
                .ok()
                .map(|d| d.data)
        }
        ysnp_pdf::object::PdfAtom::Ref { .. } => {
            let entry = graph.resolve_ref(obj)?;
            match &entry.atom {
                ysnp_pdf::object::PdfAtom::Str(s) => Some(string_bytes(s)),
                ysnp_pdf::object::PdfAtom::Stream(st) => {
                    ysnp_pdf::decode::decode_stream(bytes, st, 32 * 1024 * 1024)
                        .ok()
                        .map(|d| d.data)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn string_bytes(s: &ysnp_pdf::object::PdfStr<'_>) -> Vec<u8> {
    match s {
        ysnp_pdf::object::PdfStr::Literal { decoded, .. } => decoded.clone(),
        ysnp_pdf::object::PdfStr::Hex { decoded, .. } => decoded.clone(),
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
