use js_analysis::corpus_regression::{evaluate_corpus, CorpusThresholds};
use std::env;
use std::fs;
use std::path::PathBuf;

fn usage() -> String {
    [
        "Usage:",
        "  js-corpus-harness --corpus-root <path> [--output <path>] [--enforce-thresholds]",
        "  js-corpus-harness --help",
        "",
        "Threshold defaults:",
        "  execution_rate >= 0.75",
        "  true_positive_rate >= 0.85",
        "  false_positive_rate < 0.05",
    ]
    .join("\n")
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let mut corpus_root: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut enforce = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                println!("{}", usage());
                return Ok(());
            }
            "--corpus-root" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --corpus-root".to_string());
                };
                corpus_root = Some(PathBuf::from(value));
            }
            "--output" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --output".to_string());
                };
                output = Some(PathBuf::from(value));
            }
            "--enforce-thresholds" => {
                enforce = true;
            }
            unknown => {
                return Err(format!("unknown argument: {unknown}\n\n{}", usage()));
            }
        }
    }

    let Some(corpus_root) = corpus_root else {
        return Err(format!("missing required --corpus-root\n\n{}", usage()));
    };

    let report = evaluate_corpus(&corpus_root, CorpusThresholds::default())?;
    let value = report.to_json_value();
    let rendered = serde_json::to_string_pretty(&value)
        .map_err(|error| format!("failed to serialise report JSON: {error}"))?;

    if let Some(path) = output {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!("failed to create output directory {}: {error}", parent.display())
            })?;
        }
        fs::write(&path, &rendered)
            .map_err(|error| format!("failed to write {}: {error}", path.display()))?;
        println!("wrote report: {}", path.display());
    } else {
        println!("{rendered}");
    }

    if enforce && !report.passes_thresholds() {
        return Err(format!(
            "threshold check failed: execution_rate={:.3}, true_positive_rate={:.3}, false_positive_rate={:.3}",
            report.summary.execution_rate,
            report.summary.true_positive_rate,
            report.summary.false_positive_rate,
        ));
    }

    Ok(())
}
