//! Test hostile JavaScript payloads directly through the sandbox
//!
//! Usage: cargo run --release --features js-sandbox --example test_hostile -- <js_file>

use js_analysis::dynamic::run_sandbox;
use js_analysis::types::{DynamicOptions, DynamicOutcome};
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <js_file>", args[0]);
        eprintln!();
        eprintln!("Tests a JavaScript file through the sis-pdf enhanced sandbox");
        std::process::exit(1);
    }

    let js_file = Path::new(&args[1]);

    let js_code = match fs::read(js_file) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Failed to read {}: {}", js_file.display(), e);
            std::process::exit(1);
        }
    };

    let options = DynamicOptions {
        max_bytes: 64 * 1024,
        timeout_ms: 5000,
        max_call_args: 100,
        max_args_per_call: 10,
        max_arg_preview: 200,
        max_urls: 50,
        max_domains: 25,
    };

    eprintln!("Testing: {}", js_file.display());
    eprintln!("Size: {} bytes", js_code.len());
    eprintln!();

    match run_sandbox(&js_code, &options) {
        DynamicOutcome::Executed(signals) => {
            eprintln!("✅ EXECUTED");
            eprintln!();
            eprintln!("Outcome: executed");
            eprintln!("Unique calls: {}", signals.unique_calls);
            eprintln!("Total calls: {}", signals.calls.len());
            eprintln!("Property reads: {}", signals.prop_reads.len());
            eprintln!("Unique prop reads: {}", signals.unique_prop_reads);
            eprintln!("Errors: {}", signals.errors.len());
            eprintln!("Elapsed: {:?}ms", signals.elapsed_ms);
            eprintln!();

            if !signals.errors.is_empty() {
                eprintln!("⚠️  Errors encountered:");
                for (i, error) in signals.errors.iter().enumerate().take(10) {
                    eprintln!("  {}. {}", i + 1, error);
                }
                if signals.errors.len() > 10 {
                    eprintln!("  ... and {} more", signals.errors.len() - 10);
                }
                eprintln!();
            }

            if !signals.behavioral_patterns.is_empty() {
                eprintln!("🔍 Behavioral patterns:");
                for pattern in &signals.behavioral_patterns {
                    eprintln!("  - {}: {} (confidence: {:.2})",
                           pattern.name, pattern.evidence, pattern.confidence);
                }
                eprintln!();
            }

            if !signals.calls.is_empty() {
                eprintln!("📞 Top function calls:");
                let mut call_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
                for call in &signals.calls {
                    *call_counts.entry(call).or_insert(0) += 1;
                }
                let mut sorted: Vec<_> = call_counts.iter().collect();
                sorted.sort_by(|a, b| b.1.cmp(a.1));
                for (call, count) in sorted.iter().take(15) {
                    eprintln!("  - {} ({}x)", call, count);
                }
                eprintln!();
            }

            // JSON output to stdout for parsing
            if let Ok(json) = serde_json::to_string(&serde_json::json!({
                "outcome": "executed",
                "unique_calls": signals.unique_calls,
                "total_calls": signals.calls.len(),
                "errors": signals.errors.len(),
                "elapsed_ms": signals.elapsed_ms,
                "behavioral_patterns": signals.behavioral_patterns.len(),
                "patterns": signals.behavioral_patterns.iter().map(|p| &p.name).collect::<Vec<_>>(),
                "has_errors": !signals.errors.is_empty(),
                "error_samples": signals.errors.iter().take(5).collect::<Vec<_>>()
            })) {
                println!("{}", json);
            }
        }
        DynamicOutcome::TimedOut { timeout_ms } => {
            eprintln!("⏱️  TIMED OUT after {}ms", timeout_ms);
            println!("{{\"outcome\":\"timed_out\",\"timeout_ms\":{}}}", timeout_ms);
            std::process::exit(0);  // Exit 0 so we can collect stats
        }
        DynamicOutcome::Skipped { reason, limit, actual } => {
            eprintln!("⏭️  SKIPPED: {}", reason);
            eprintln!("Limit: {}, Actual: {}", limit, actual);
            println!("{{\"outcome\":\"skipped\",\"reason\":\"{}\",\"limit\":{},\"actual\":{}}}",
                     reason, limit, actual);
            std::process::exit(0);  // Exit 0 so we can collect stats
        }
    }
}
