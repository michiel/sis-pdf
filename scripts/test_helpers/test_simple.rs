use sis_pdf::run_scan;
use sis_pdf_core::scan::{ScanOptions, ScanContext};
use sis_pdf_core::runner::RunOptions;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a simple test PDF with embedded JS
    let js_code = fs::read("test_payload.js")?;
    
    println!("Testing JS payload ({} bytes):", js_code.len());
    println!("{}", String::from_utf8_lossy(&js_code));
    
    // Test with the js-analysis crate directly
    let signals = js_analysis::run_sandbox(&js_code, &js_analysis::DynamicOptions::default());
    
    match signals {
        js_analysis::DynamicOutcome::Executed(sig) => {
            println!("\n=== Sandbox Execution Results ===");
            println!("Call count: {}", sig.call_count);
            println!("Unique calls: {}", sig.unique_calls);
            println!("Calls: {:?}", sig.calls);
            println!("Property reads: {:?}", sig.prop_reads);
            println!("Unique property reads: {}", sig.unique_prop_reads);
            println!("Errors: {:?}", sig.errors);
            if let Some(elapsed) = sig.elapsed_ms {
                println!("Elapsed: {}ms", elapsed);
            }
        }
        js_analysis::DynamicOutcome::TimedOut { timeout_ms } => {
            println!("Execution timed out after {}ms", timeout_ms);
        }
        js_analysis::DynamicOutcome::Skipped { reason, limit, actual } => {
            println!("Execution skipped: {} (limit: {}, actual: {})", reason, limit, actual);
        }
    }
    
    Ok(())
}