#!/usr/bin/env rust-script
//! Quick JS Sandbox Testing Tool
//!
//! Tests JavaScript files directly through the sandbox
//!
//! ```cargo
//! [dependencies]
//! js-analysis = { path = "crates/js-analysis", features = ["js-sandbox"] }
//! serde_json = "1.0"
//! ```

use js_analysis::dynamic::{run_sandbox, DynamicOptions, DynamicOutcome};
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <js_file>", args[0]);
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

    println!("Testing: {}", js_file.display());
    println!("Size: {} bytes", js_code.len());
    println!();

    match run_sandbox(&js_code, &options) {
        DynamicOutcome::Executed(signals) => {
            println!("✅ EXECUTED");
            println!();
            println!("Outcome: executed");
            println!("Unique calls: {}", signals.unique_calls);
            println!("Total calls: {}", signals.calls.len());
            println!("Property reads: {}", signals.prop_reads.len());
            println!("Unique prop reads: {}", signals.unique_prop_reads);
            println!("Errors: {}", signals.errors.len());
            println!("Elapsed: {:?}ms", signals.elapsed_ms);
            println!();

            if !signals.errors.is_empty() {
                println!("Errors encountered:");
                for (i, error) in signals.errors.iter().enumerate().take(10) {
                    println!("  {}. {}", i + 1, error);
                }
                if signals.errors.len() > 10 {
                    println!("  ... and {} more", signals.errors.len() - 10);
                }
                println!();
            }

            if !signals.behavioral_patterns.is_empty() {
                println!("Behavioral patterns:");
                for pattern in &signals.behavioral_patterns {
                    println!("  - {}: {} (confidence: {:.2})",
                           pattern.name, pattern.evidence, pattern.confidence);
                }
                println!();
            }

            if !signals.calls.is_empty() {
                println!("Top function calls:");
                let mut call_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
                for call in &signals.calls {
                    *call_counts.entry(call).or_insert(0) += 1;
                }
                let mut sorted: Vec<_> = call_counts.iter().collect();
                sorted.sort_by(|a, b| b.1.cmp(a.1));
                for (call, count) in sorted.iter().take(10) {
                    println!("  - {} ({}x)", call, count);
                }
                println!();
            }

            // JSON output for parsing
            println!("JSON:");
            if let Ok(json) = serde_json::to_string_pretty(&signals) {
                println!("{}", json);
            }
        }
        DynamicOutcome::TimedOut { timeout_ms } => {
            println!("⏱️  TIMED OUT after {}ms", timeout_ms);
            std::process::exit(2);
        }
        DynamicOutcome::Skipped { reason, limit, actual } => {
            println!("⏭️  SKIPPED: {}", reason);
            println!("Limit: {}, Actual: {}", limit, actual);
            std::process::exit(3);
        }
    }
}
