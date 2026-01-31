//! Font security analysis example
//!
//! Usage: cargo run --example analyze_font -- <font_file>
//! Usage (with dynamic analysis): cargo run --features dynamic --example analyze_font -- <font_file>

use font_analysis::analyse_font;
use font_analysis::model::{FontAnalysisConfig, Severity};
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <font_file>", args[0]);
        eprintln!();
        eprintln!("Performs security analysis on font files (TrueType, OpenType, Type 1, etc.)");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  {} suspicious.ttf", args[0]);
        eprintln!("  {} malicious.otf", args[0]);
        eprintln!();
        #[cfg(feature = "dynamic")]
        eprintln!("Note: Dynamic analysis is enabled (compiled with 'dynamic' feature)");
        #[cfg(not(feature = "dynamic"))]
        eprintln!("Note: Dynamic analysis is disabled. Build with --features dynamic to enable.");
        std::process::exit(1);
    }

    let font_file = Path::new(&args[1]);

    let font_data = match fs::read(font_file) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to read {}: {}", font_file.display(), e);
            std::process::exit(1);
        }
    };

    eprintln!("Analyzing: {}", font_file.display());
    eprintln!("Size: {} bytes", font_data.len());
    eprintln!();

    // Configure analysis
    let config = FontAnalysisConfig {
        enabled: true,
        #[cfg(feature = "dynamic")]
        dynamic_enabled: true,
        #[cfg(not(feature = "dynamic"))]
        dynamic_enabled: false,
        dynamic_timeout_ms: 5000,
        max_charstring_ops: 50_000,
        max_stack_depth: 256,
        max_fonts: 100,
        network_access: false,
        signature_matching_enabled: true,
        signature_directory: None,
    };

    // Perform analysis
    let outcome = analyse_font(&font_data, &config);

    // Display results
    display_results(&outcome);

    // Summary
    let total_findings = outcome.findings.len();
    if total_findings == 0 {
        eprintln!("✅ No security issues detected");
    } else {
        eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        eprintln!("Total findings: {}", total_findings);
        if outcome.timed_out {
            eprintln!("⚠️  Dynamic analysis timed out");
        }
    }
}

fn display_results(outcome: &font_analysis::model::DynamicAnalysisOutcome) {
    if outcome.findings.is_empty() {
        return;
    }

    eprintln!("🔍 ANALYSIS RESULTS:");
    eprintln!();

    // Group findings by category
    let mut type1_findings = Vec::new();
    let mut cve_findings = Vec::new();
    let mut anomaly_findings = Vec::new();
    let mut other_findings = Vec::new();

    for finding in &outcome.findings {
        if finding.kind.starts_with("font.type1_") {
            type1_findings.push(finding);
        } else if finding.kind.contains("cve_") {
            cve_findings.push(finding);
        } else if finding.kind.contains("anomalous") {
            anomaly_findings.push(finding);
        } else {
            other_findings.push(finding);
        }
    }

    // Display Type 1 font findings
    if !type1_findings.is_empty() {
        eprintln!("🔴 TYPE 1 FONT ANALYSIS:");
        for finding in &type1_findings {
            let icon = match finding.severity {
                Severity::High => "🔴",
                Severity::Medium => "🟡",
                Severity::Low => "🟠",
                Severity::Info => "ℹ️",
            };
            eprintln!("  {} {} - {}", icon, finding.kind, finding.title);
            eprintln!("    {}", finding.description);
            if !finding.meta.is_empty() {
                for (key, value) in &finding.meta {
                    eprintln!("    • {}: {}", key, value);
                }
            }
            eprintln!();
        }
    }

    // Display CVE detections
    if !cve_findings.is_empty() {
        eprintln!("🔴 CVE DETECTIONS:");
        for finding in &cve_findings {
            eprintln!("  ✓ {} - {}", finding.kind.to_uppercase(), finding.title);
            eprintln!("    {}", finding.description);
            if let Some(cve_ref) = finding.meta.get("cve_reference") {
                eprintln!("    📋 Reference: {}", cve_ref);
            }
            if !finding.meta.is_empty() {
                for (key, value) in &finding.meta {
                    if key != "cve_reference" {
                        eprintln!("    • {}: {}", key, value);
                    }
                }
            }
            eprintln!();
        }
    }

    // Display anomaly findings
    if !anomaly_findings.is_empty() {
        eprintln!("🟡 ANOMALY DETECTIONS:");
        for finding in &anomaly_findings {
            eprintln!("  ✓ {} - {}", finding.kind, finding.title);
            eprintln!("    {}", finding.description);
            if !finding.meta.is_empty() {
                for (key, value) in &finding.meta {
                    eprintln!("    • {}: {}", key, value);
                }
            }
            eprintln!();
        }
    }

    // Display other findings
    if !other_findings.is_empty() {
        eprintln!("ℹ️  OTHER DETECTIONS:");
        for finding in &other_findings {
            let icon = match finding.severity {
                Severity::High => "🔴",
                Severity::Medium => "🟡",
                Severity::Low => "🟠",
                Severity::Info => "ℹ️",
            };
            eprintln!("  {} {} - {}", icon, finding.kind, finding.title);
            eprintln!("    {}", finding.description);
            if !finding.meta.is_empty() {
                for (key, value) in &finding.meta {
                    eprintln!("    • {}: {}", key, value);
                }
            }
            eprintln!();
        }
    }
}
