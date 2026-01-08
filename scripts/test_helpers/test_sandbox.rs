use js_analysis::{run_sandbox, DynamicOptions, DynamicOutcome};

fn main() {
    // Test the enhanced JavaScript sandbox
    let test_code = br#"
        eval("var M7pzjRpdcM5RVyTMS = 'test_value';");
        console.log("Variable set via eval");
        
        // This should work now due to variable promotion
        var result = M7pzjRpdcM5RVyTMS + "_processed";
        
        // Test String.fromCharCode
        var decoded = String.fromCharCode(72, 101, 108, 108, 111);
        
        // Test unescape
        var unescaped = unescape("Hello%20World");
        
        result;
    "#;
    
    let options = DynamicOptions {
        max_bytes: 64 * 1024,
        timeout_ms: 5000,
        max_call_args: 100,
        max_args_per_call: 10,
        max_arg_preview: 200,
        max_urls: 50,
        max_domains: 25,
    };
    
    println!("Testing enhanced JavaScript sandbox...");
    
    match run_sandbox(test_code, &options) {
        DynamicOutcome::Executed(signals) => {
            println!("✅ Sandbox execution completed successfully!");
            println!("Calls detected: {}", signals.calls.len());
            println!("Unique calls: {}", signals.unique_calls);
            println!("Property reads: {}", signals.prop_reads.len());
            println!("Unique property reads: {}", signals.unique_prop_reads);
            println!("Execution time: {:?}ms", signals.elapsed_ms);
            println!("Errors: {:?}", signals.errors);
            
            println!("\nCall details:");
            for call in &signals.calls[..std::cmp::min(signals.calls.len(), 10)] {
                println!("  - {}", call);
            }
            
            if !signals.call_args.is_empty() {
                println!("\nCall arguments:");
                for arg in &signals.call_args[..std::cmp::min(signals.call_args.len(), 5)] {
                    println!("  - {}", arg);
                }
            }
        }
        DynamicOutcome::TimedOut { timeout_ms } => {
            println!("❌ Sandbox execution timed out after {}ms", timeout_ms);
        }
        DynamicOutcome::Skipped { reason, limit: _, actual: _ } => {
            println!("⚠️  Sandbox execution skipped: {}", reason);
        }
    }
}