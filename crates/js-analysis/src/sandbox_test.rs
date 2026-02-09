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
            phase_timeout_ms: 1_250,
            phases: vec![
                crate::types::RuntimePhase::Open,
                crate::types::RuntimePhase::Idle,
                crate::types::RuntimePhase::Click,
                crate::types::RuntimePhase::Form,
            ],
            runtime_profile: Default::default(),
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
            DynamicOutcome::TimedOut { timeout_ms, .. } => {
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

    #[test]
    fn test_behavioral_pattern_detection() {
        let test_code = br#"
            // Test code that should trigger multiple behavioral patterns
            
            // Pattern 1: Obfuscated string construction (trigger threshold of 5+)
            var decoded = String.fromCharCode(72, 101, 108, 108, 111);
            decoded += String.fromCharCode(32, 87, 111, 114, 108, 100);
            decoded += String.fromCharCode(33);
            decoded += String.fromCharCode(34);
            decoded += String.fromCharCode(35);
            decoded += String.fromCharCode(36);
            
            // Pattern 2: Dynamic code generation
            eval("var dynamicVar = 'created_by_eval';");
            eval("var anotherVar = dynamicVar + '_extended';");
            
            // Pattern 3: Environment fingerprinting
            var title = info.title;
            var author = info.author;
            var subject = info.subject;
            
            // Pattern 4: Variable promotion (should be detected)
            var promotedVar = "test";
            
            // Return result
            decoded + anotherVar + title + author;
        "#;

        let options = DynamicOptions::default();

        match run_sandbox(test_code, &options) {
            DynamicOutcome::Executed(signals) => {
                println!("✅ Behavioral pattern detection test completed!");

                // Check behavioral patterns
                println!("🔍 Behavioral patterns detected: {}", signals.behavioral_patterns.len());
                for pattern in &signals.behavioral_patterns {
                    println!(
                        "   - {}: {} (confidence: {:.2})",
                        pattern.name, pattern.evidence, pattern.confidence
                    );
                }

                // Check execution stats
                println!("📊 Execution stats:");
                println!(
                    "   - Total function calls: {}",
                    signals.execution_stats.total_function_calls
                );
                println!(
                    "   - Variable promotions: {}",
                    signals.execution_stats.variable_promotions
                );
                println!("   - Error recoveries: {}", signals.execution_stats.error_recoveries);
                println!("   - Execution depth: {}", signals.execution_stats.execution_depth);

                // Should detect String.fromCharCode pattern
                assert!(signals
                    .behavioral_patterns
                    .iter()
                    .any(|p| p.name == "obfuscated_string_construction"));

                // Should detect dynamic code generation
                assert!(signals
                    .behavioral_patterns
                    .iter()
                    .any(|p| p.name == "dynamic_code_generation"));

                // Should detect environment fingerprinting
                assert!(signals
                    .behavioral_patterns
                    .iter()
                    .any(|p| p.name == "environment_fingerprinting"));

                // Should have execution stats
                assert!(signals.execution_stats.total_function_calls > 0);

                println!("✅ All behavioral patterns detected correctly!");
            }
            other => {
                panic!("Expected successful execution with behavioral analysis, got: {:?}", other);
            }
        }
    }

    #[test]
    fn test_execution_flow_tracking() {
        let test_code = br#"
            // Test nested function calls and variable tracking
            function testFunction(arg) {
                var localVar = arg + "_processed";
                return localVar;
            }
            
            var result1 = eval("testFunction('test1')");
            var result2 = String.fromCharCode(84, 101, 115, 116);
            
            // Test error recovery
            try {
                var errorVar = undefinedVariable + "test";
            } catch (e) {
                var errorVar = "recovered";
            }
            
            result1 + result2 + errorVar;
        "#;

        let options = DynamicOptions::default();

        match run_sandbox(test_code, &options) {
            DynamicOutcome::Executed(signals) => {
                println!("✅ Execution flow tracking test completed!");

                // Check that we tracked function calls
                assert!(signals.calls.contains(&"eval".to_string()));
                assert!(signals.calls.contains(&"String.fromCharCode".to_string()));

                // Check execution stats
                println!("📈 Execution flow stats:");
                println!(
                    "   - Total calls tracked: {}",
                    signals.execution_stats.total_function_calls
                );
                println!("   - Unique calls: {}", signals.execution_stats.unique_function_calls);
                println!("   - Max execution depth: {}", signals.execution_stats.execution_depth);

                // Should have tracked multiple calls
                assert!(signals.execution_stats.total_function_calls >= 2);

                println!("✅ Execution flow tracking working correctly!");
            }
            other => {
                panic!("Expected successful execution with flow tracking, got: {:?}", other);
            }
        }
    }
}
