/// Font Analysis Example
///
/// This example demonstrates how to use sis-pdf's font analysis capabilities
/// to detect potential security issues in PDF embedded fonts.
///
/// Usage:
///   cargo run --example font_analysis path/to/file.pdf

use sis_pdf_core::{ScanOptions, scan_file};
use std::env;
use std::process;

fn main() {
    // Get PDF path from command line
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <pdf-file>", args[0]);
        eprintln!("\nExample:");
        eprintln!("  {} suspicious.pdf", args[0]);
        process::exit(1);
    }

    let pdf_path = &args[1];

    println!("Font Analysis Example");
    println!("====================");
    println!("Analyzing: {}\n", pdf_path);

    // Configure scan with font analysis enabled
    let mut options = ScanOptions::default();

    // Enable font analysis features
    options.font_analysis.enabled = true;
    options.font_analysis.dynamic_enabled = true;
    options.font_analysis.dynamic_timeout_ms = 5000; // 5 seconds per font
    options.font_analysis.max_fonts = 100;

    // Run scan
    println!("Scanning PDF with font analysis enabled...\n");
    match scan_file(pdf_path, &options) {
        Ok(findings) => {
            // Filter for font-related findings
            let font_findings: Vec<_> = findings.iter()
                .filter(|f| f.kind.starts_with("font"))
                .collect();

            if font_findings.is_empty() {
                println!("✓ No font security issues detected");
            } else {
                println!("Found {} font-related findings:\n", font_findings.len());

                for finding in font_findings {
                    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    println!("Finding: {}", finding.kind);
                    println!("Severity: {:?}", finding.severity);
                    println!("Confidence: {:?}", finding.confidence);
                    println!("Title: {}", finding.title);
                    println!("Description: {}", finding.description);

                    if !finding.meta.is_empty() {
                        println!("\nMetadata:");
                        for (key, value) in &finding.meta {
                            println!("  {}: {}", key, value);
                        }
                    }

                    println!();
                }
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            }

            // Display summary by finding type
            display_summary(&font_findings);

            // Exit with error code if high-severity findings found
            let has_high_severity = font_findings.iter()
                .any(|f| matches!(f.severity, sis_pdf_core::model::Severity::High | sis_pdf_core::model::Severity::Critical));

            if has_high_severity {
                println!("\n⚠️  HIGH SEVERITY font issues detected!");
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error scanning PDF: {}", e);
            process::exit(1);
        }
    }
}

fn display_summary(findings: &[&sis_pdf_core::model::Finding]) {
    use std::collections::HashMap;
    use sis_pdf_core::model::Severity;

    let mut by_type: HashMap<&str, Vec<&sis_pdf_core::model::Finding>> = HashMap::new();
    let mut by_severity: HashMap<&Severity, usize> = HashMap::new();

    for finding in findings {
        by_type.entry(finding.kind.as_str())
            .or_insert_with(Vec::new)
            .push(finding);

        *by_severity.entry(&finding.severity).or_insert(0) += 1;
    }

    println!("Summary");
    println!("-------");
    println!("Total font findings: {}", findings.len());

    if !by_severity.is_empty() {
        println!("\nBy Severity:");
        for (severity, count) in by_severity.iter() {
            println!("  {:?}: {}", severity, count);
        }
    }

    if !by_type.is_empty() {
        println!("\nBy Type:");
        for (kind, findings) in by_type.iter() {
            println!("  {}: {}", kind, findings.len());
        }
    }
}
