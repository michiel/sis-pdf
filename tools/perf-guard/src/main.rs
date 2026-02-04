#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "perf-guard")]
#[command(about = "Compare sis runtime profiles against thresholds/baselines", long_about = None)]
struct Args {
    /// Runtime profile JSON produced by `sis scan --runtime-profile --runtime-profile-format json`
    #[arg(long, value_name = "FILE")]
    profile: PathBuf,

    /// Baseline profile JSON for regression comparison
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,

    /// Maximum allowed parse duration in milliseconds
    #[arg(long, default_value_t = 10.0)]
    parse_threshold: f64,

    /// Maximum allowed detection duration in milliseconds
    #[arg(long, default_value_t = 50.0)]
    detection_threshold: f64,

    /// Multiplier against the baseline parse duration (requires --baseline)
    #[arg(long, default_value_t = 1.25)]
    parse_ratio: f64,

    /// Multiplier against the baseline detection duration (requires --baseline)
    #[arg(long, default_value_t = 1.25)]
    detection_ratio: f64,
}

#[derive(Deserialize)]
struct RuntimeProfile {
    phases: Vec<Phase>,
}

#[derive(Deserialize)]
struct Phase {
    name: String,
    duration_ms: f64,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let profile = load_profile(&args.profile)?;

    let parse_ms =
        phase_duration(&profile, "parse").context("Profile is missing a 'parse' phase")?;
    let detection_ms =
        phase_duration(&profile, "detection").context("Profile is missing a 'detection' phase")?;

    println!("Current parse duration: {:.2} ms", parse_ms);
    println!("Current detection duration: {:.2} ms", detection_ms);

    if parse_ms > args.parse_threshold {
        anyhow::bail!(
            "Parse duration {:.2} ms exceeds threshold {:.2} ms",
            parse_ms,
            args.parse_threshold
        );
    }
    if detection_ms > args.detection_threshold {
        anyhow::bail!(
            "Detection duration {:.2} ms exceeds threshold {:.2} ms",
            detection_ms,
            args.detection_threshold
        );
    }

    if let Some(baseline_path) = args.baseline {
        let baseline = load_profile(&baseline_path)?;
        let base_parse =
            phase_duration(&baseline, "parse").context("Baseline profile lacks a 'parse' phase")?;
        let base_detection = phase_duration(&baseline, "detection")
            .context("Baseline profile lacks a 'detection' phase")?;

        if parse_ms > base_parse * args.parse_ratio {
            anyhow::bail!(
                "Parse regression: {:.2} ms (> {:.2}x baseline {:.2} ms)",
                parse_ms,
                args.parse_ratio,
                base_parse
            );
        }
        if detection_ms > base_detection * args.detection_ratio {
            anyhow::bail!(
                "Detection regression: {:.2} ms (> {:.2}x baseline {:.2} ms)",
                detection_ms,
                args.detection_ratio,
                base_detection
            );
        }
    }

    println!(
        "Profile guard passed (parse ≤ {:.2} ms, detection ≤ {:.2} ms)",
        args.parse_threshold, args.detection_threshold
    );
    Ok(())
}

fn load_profile(path: &PathBuf) -> Result<RuntimeProfile> {
    let file =
        File::open(path).with_context(|| format!("Failed to open profile: {}", path.display()))?;
    serde_json::from_reader(file).context("Failed to deserialize runtime profile")
}

fn phase_duration(profile: &RuntimeProfile, name: &str) -> Option<f64> {
    profile.phases.iter().find(|phase| phase.name == name).map(|phase| phase.duration_ms)
}
