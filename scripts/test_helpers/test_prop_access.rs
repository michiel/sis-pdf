use js_analysis::{run_sandbox, DynamicOptions, DynamicOutcome};
use std::fs;

fn main() {
    let js_code = fs::read("test_payload.js").expect("Failed to read test file");
    let options = DynamicOptions::default();
    
    match run_sandbox(&js_code, &options) {
        DynamicOutcome::Executed(signals) => {
            println!("JS executed successfully:");
            println!("  Call count: {}", signals.call_count);
            println!("  Unique calls: {}", signals.unique_calls);
            println!("  Calls: {:?}", signals.calls);
            println!("  Property reads: {:?}", signals.prop_reads);
            println!("  Unique property reads: {}", signals.unique_prop_reads);
            println!("  Errors: {:?}", signals.errors);
            if let Some(elapsed) = signals.elapsed_ms {
                println!("  Elapsed: {}ms", elapsed);
            }
        }
        DynamicOutcome::TimedOut { timeout_ms } => {
            println!("Execution timed out after {}ms", timeout_ms);
        }
        DynamicOutcome::Skipped { reason, limit, actual } => {
            println!("Execution skipped: {} (limit: {}, actual: {})", reason, limit, actual);
        }
    }
}