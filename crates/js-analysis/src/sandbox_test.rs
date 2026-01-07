#[cfg(test)]
#[cfg(feature = "js-sandbox")]
mod tests {
    use crate::dynamic::run_sandbox;
    use crate::types::{DynamicOptions, DynamicOutcome};

    #[test]
    fn test_enhanced_variable_promotion() {
        let test_code = br#"
            eval("var M7pzjRpdcM5RVyTMS = 'test_value';");
            
            // This should work now due to variable promotion
            var result = M7pzjRpdcM5RVyTMS + "_processed";
            
            // Test String.fromCharCode
            var decoded = String.fromCharCode(72, 101, 108, 108, 111);
            
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
        
        match run_sandbox(test_code, &options) {
            DynamicOutcome::Executed(signals) => {
                println!("✅ Enhanced sandbox test completed successfully!");
                println!("Calls detected: {}", signals.calls.len());
                println!("Unique calls: {}", signals.unique_calls);
                println!("Property reads: {}", signals.prop_reads.len());
                println!("Unique property reads: {}", signals.unique_prop_reads);
                println!("Execution time: {:?}ms", signals.elapsed_ms);
                
                // Check that eval was called
                assert!(signals.calls.iter().any(|call| call == "eval"));
                
                // Check that String.fromCharCode was called
                assert!(signals.calls.iter().any(|call| call == "String.fromCharCode"));
                
                // Should have minimal errors (or recovered errors)
                println!("Errors (should be minimal): {:?}", signals.errors);
                
                println!("\nAll calls:");
                for call in &signals.calls {
                    println!("  - {}", call);
                }
                
                if !signals.call_args.is_empty() {
                    println!("\nCall arguments:");
                    for arg in &signals.call_args {
                        println!("  - {}", arg);
                    }
                }
            }
            DynamicOutcome::TimedOut { timeout_ms } => {
                panic!("❌ Sandbox execution timed out after {}ms", timeout_ms);
            }
            DynamicOutcome::Skipped { reason, limit: _, actual: _ } => {
                panic!("⚠️  Sandbox execution skipped: {}", reason);
            }
        }
    }

    #[test]
    fn test_error_recovery_with_undefined_variables() {
        let test_code = br#"
            // This should trigger error recovery
            var result = someUndefinedVariable + "test";
            var finalResult = result || "fallback_worked";
            finalResult;
        "#;
        
        let options = DynamicOptions::default();
        
        match run_sandbox(test_code, &options) {
            DynamicOutcome::Executed(signals) => {
                println!("✅ Error recovery test completed!");
                println!("Errors (should show recovery): {:?}", signals.errors);
                
                // Should have completed execution despite errors
                assert!(signals.elapsed_ms.is_some());
            }
            other => {
                panic!("Expected successful execution with error recovery, got: {:?}", other);
            }
        }
    }
}