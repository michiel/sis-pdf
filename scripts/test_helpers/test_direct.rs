fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    
    // Read the JS test payload
    let js_code = fs::read("test_payload.js")?;
    
    println!("Testing JS payload ({} bytes):", js_code.len());
    println!("{}\n", String::from_utf8_lossy(&js_code));
    
    // Test manually with the basic script
    let test_basic = br#"
var title = this.info.title;
console.log("Title:", title);
"#;
    
    println!("=== Testing Basic Access ===");
    test_js_execution(test_basic);
    
    println!("\n=== Testing Full Payload ===");
    test_js_execution(&js_code);
    
    Ok(())
}

#[cfg(feature = "js-sandbox")]
fn test_js_execution(js_code: &[u8]) {
    use js_analysis::{run_sandbox, DynamicOptions, DynamicOutcome};
    
    let options = DynamicOptions::default();
    match run_sandbox(js_code, &options) {
        DynamicOutcome::Executed(sig) => {
            println!("✓ Executed successfully:");
            println!("  Call count: {}", sig.call_count);
            println!("  Unique calls: {}", sig.unique_calls);
            if !sig.calls.is_empty() {
                println!("  Calls: {:?}", sig.calls);
            }
            if !sig.prop_reads.is_empty() {
                println!("  Property reads: {:?}", sig.prop_reads);
                println!("  Unique property reads: {}", sig.unique_prop_reads);
            }
            if !sig.errors.is_empty() {
                println!("  Errors: {:?}", sig.errors);
            }
            if let Some(elapsed) = sig.elapsed_ms {
                println!("  Elapsed: {}ms", elapsed);
            }
        }
        DynamicOutcome::TimedOut { timeout_ms } => {
            println!("✗ Timed out after {}ms", timeout_ms);
        }
        DynamicOutcome::Skipped { reason, limit, actual } => {
            println!("✗ Skipped: {} (limit: {}, actual: {})", reason, limit, actual);
        }
    }
}

#[cfg(not(feature = "js-sandbox"))]
fn test_js_execution(_js_code: &[u8]) {
    println!("JS sandbox feature not enabled");
}