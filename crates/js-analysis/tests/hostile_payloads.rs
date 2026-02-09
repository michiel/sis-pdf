//! Integration tests for hostile JavaScript payloads
//!
//! This test suite verifies that the sandbox can execute real-world malicious
//! JavaScript samples extracted from VirusShare PDFs without crashing or hanging.
//!
//! Each test represents a different malware pattern or obfuscation technique.

use js_analysis::dynamic::run_sandbox;
use js_analysis::types::{DynamicOptions, DynamicOutcome};

/// Standard test options for hostile payloads
fn test_options() -> DynamicOptions {
    DynamicOptions {
        max_bytes: 64 * 1024,
        timeout_ms: 5000,
        max_call_args: 100,
        max_args_per_call: 10,
        max_arg_preview: 200,
        max_urls: 50,
        max_domains: 25,
        phase_timeout_ms: 1_250,
        phases: vec![
            js_analysis::types::RuntimePhase::Open,
            js_analysis::types::RuntimePhase::Idle,
            js_analysis::types::RuntimePhase::Click,
            js_analysis::types::RuntimePhase::Form,
        ],
        runtime_profile: Default::default(),
    }
}

/// Test helper to run a fixture file through the sandbox
fn test_fixture(fixture_name: &str) -> DynamicOutcome {
    let fixture_path = format!("tests/fixtures/{}", fixture_name);
    let js_code = std::fs::read(&fixture_path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", fixture_path, e));

    run_sandbox(&js_code, &test_options())
}

#[test]
fn test_event_target_eval_obfuscated() {
    // Tests: event.target.eval with string concatenation obfuscation
    // Uses: replace, unescape, getAnnots, syncAnnotScan
    let outcome = test_fixture("event_target_eval_obfuscated.js");

    match outcome {
        DynamicOutcome::Executed(signals) => {
            // Should execute without timeout
            assert!(signals.elapsed_ms.is_some());
            // May have errors due to missing getAnnots, but should execute
        }
        DynamicOutcome::TimedOut { .. } => {
            panic!("Should not timeout on simple obfuscated code");
        }
        DynamicOutcome::Skipped { .. } => {
            // Size limits are acceptable
        }
    }
}

#[test]
fn test_getannots_unescape_eval() {
    // Tests: app.doc.getAnnots with unescape and eval
    // Pattern: if (app) { app.doc.syncAnnotScan(); var ioper = app.doc.getAnnots(...); }
    let outcome = test_fixture("getannots_unescape_eval.js");

    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.elapsed_ms.is_some());
            // Should call app-related functions
        }
        DynamicOutcome::TimedOut { .. } => {
            panic!("Should not timeout on simple getAnnots code");
        }
        DynamicOutcome::Skipped { .. } => {}
    }
}

#[test]
fn test_charcode_array_decrypt() {
    // Tests: Comma-separated character codes with String.fromCharCode decryption
    // Pattern: decrypt function splits by comma and converts to chars
    let outcome = test_fixture("charcode_array_decrypt.js");

    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.elapsed_ms.is_some());
            // Should successfully execute the decrypt function
        }
        DynamicOutcome::TimedOut { .. } => {
            panic!("Should not timeout on decrypt function");
        }
        DynamicOutcome::Skipped { .. } => {}
    }
}

#[test]
fn test_arguments_callee_obfuscation() {
    // Tests: arguments.callee.toString() for code introspection
    // Pattern: Builds eval code from function source
    let outcome = test_fixture("arguments_callee_obfuscation.js");

    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.elapsed_ms.is_some());
            // Should handle arguments.callee without error
        }
        DynamicOutcome::TimedOut { .. } => {
            panic!("Should not timeout on callee introspection");
        }
        DynamicOutcome::Skipped { .. } => {}
    }
}

#[test]
fn test_simple_charcode_decrypt() {
    // Tests: Simple character code decryption with eval
    // Pattern: String.fromCharCode with Date-based key
    let outcome = test_fixture("simple_charcode_decrypt.js");

    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.elapsed_ms.is_some());
            // Small payload should execute quickly
        }
        DynamicOutcome::TimedOut { .. } => {
            panic!("Should not timeout on small decrypt");
        }
        DynamicOutcome::Skipped { .. } => {}
    }
}

#[test]
fn test_complex_obfuscation_custom_accessors() {
    // Tests: Complex obfuscation with custom property accessor functions
    // Pattern: VAR_AQpFfxovabrefKe function for array access, event.target manipulation
    let outcome = test_fixture("complex_obfuscation_custom_accessors.js");

    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.elapsed_ms.is_some());
            // Should handle complex accessor patterns
        }
        DynamicOutcome::TimedOut { .. } => {
            panic!("Should not timeout on complex accessors");
        }
        DynamicOutcome::Skipped { .. } => {}
    }
}

#[test]
fn test_base64_custom_decoder() {
    // Tests: Custom Base64 decoder implementation with eval
    // Pattern: Full Base64 decoder with _keyStr and decode method
    let outcome = test_fixture("base64_custom_decoder.js");

    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.elapsed_ms.is_some());
            // Should execute the Base64 decoder
        }
        DynamicOutcome::TimedOut { .. } => {
            panic!("Should not timeout on Base64 decoder");
        }
        DynamicOutcome::Skipped { .. } => {}
    }
}

#[test]
fn test_heap_spray_exploit() {
    // Tests: Heap spray exploit with shellcode in String.fromCharCode
    // Pattern: Creates large padding strings, builds shellcode with while loops
    // This is a real exploit payload and may timeout due to heap spray loops
    let outcome = test_fixture("heap_spray_exploit.js");

    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.elapsed_ms.is_some());
            // If it executes, should have loop iterations limited
        }
        DynamicOutcome::TimedOut { timeout_ms } => {
            // Expected: heap spray may hit timeout
            assert_eq!(timeout_ms, 5000);
        }
        DynamicOutcome::Skipped { .. } => {}
    }
}

#[test]
fn test_whitespace_obfuscation() {
    // Tests: Extreme whitespace padding obfuscation
    // Pattern: Code spread across many lines with excessive whitespace
    let outcome = test_fixture("whitespace_obfuscation.js");

    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.elapsed_ms.is_some());
            // Should handle whitespace-padded code
        }
        DynamicOutcome::TimedOut { .. } => {
            panic!("Should not timeout on whitespace obfuscation");
        }
        DynamicOutcome::Skipped { .. } => {
            // May be skipped due to size
        }
    }
}

#[test]
fn test_all_fixtures_no_crash() {
    // Comprehensive test: all fixtures should execute without crashing
    let fixtures = [
        "event_target_eval_obfuscated.js",
        "getannots_unescape_eval.js",
        "charcode_array_decrypt.js",
        "arguments_callee_obfuscation.js",
        "simple_charcode_decrypt.js",
        "complex_obfuscation_custom_accessors.js",
        "base64_custom_decoder.js",
        "heap_spray_exploit.js",
        "whitespace_obfuscation.js",
        "regression_20170127_wscript_chain.js",
        "regression_20170202_function_ctor_chain.js",
        "regression_20170203_activex_constructor.js",
    ];

    let mut executed = 0;
    let mut timed_out = 0;
    let mut skipped = 0;

    for fixture in &fixtures {
        match test_fixture(fixture) {
            DynamicOutcome::Executed(_) => executed += 1,
            DynamicOutcome::TimedOut { .. } => timed_out += 1,
            DynamicOutcome::Skipped { .. } => skipped += 1,
        }
    }

    // At least 70% should execute successfully (not timeout or skip)
    let success_rate = executed as f64 / fixtures.len() as f64;
    assert!(
        success_rate >= 0.7,
        "Success rate too low: {}/{} = {:.1}%",
        executed,
        fixtures.len(),
        success_rate * 100.0
    );

    println!("Hostile payload test results:");
    println!("  Executed: {}/{}", executed, fixtures.len());
    println!("  Timed out: {}/{}", timed_out, fixtures.len());
    println!("  Skipped: {}/{}", skipped, fixtures.len());
}

#[test]
fn regression_20170127_wscript_chain_executes_deep_com_flow() {
    let outcome = test_fixture("regression_20170127_wscript_chain.js");
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.calls.iter().any(|call| call == "WScript.CreateObject"));
            assert!(signals
                .calls
                .iter()
                .any(|call| call == "Scripting.FileSystemObject.GetSpecialFolder"));
            assert!(signals.calls.iter().any(|call| call == "MSXML2.XMLHTTP.open"));
            assert!(signals.calls.iter().any(|call| call == "ADODB.Stream.SaveToFile"));
            assert!(!signals.errors.iter().any(|error| error.contains("not a callable function")));
            assert!(!signals.errors.iter().any(|error| error.contains("not a constructor")));
        }
        _ => panic!("expected executed"),
    }
}

#[test]
fn regression_20170202_function_ctor_chain_keeps_shell_callable() {
    let outcome = test_fixture("regression_20170202_function_ctor_chain.js");
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.calls.iter().any(|call| call == "Function"));
            assert!(signals.calls.iter().any(|call| call == "WScript.CreateObject"));
            assert!(signals.calls.iter().any(|call| call == "WScript.Shell.Run"));
            assert!(!signals.errors.iter().any(|error| error.contains("not a callable function")));
            assert!(!signals.errors.iter().any(|error| error.contains("not a constructor")));
        }
        _ => panic!("expected executed"),
    }
}

#[test]
fn regression_20170203_activex_constructor_is_supported() {
    let outcome = test_fixture("regression_20170203_activex_constructor.js");
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.calls.iter().any(|call| call == "ActiveXObject"));
            assert!(signals.calls.iter().any(|call| call == "MSXML2.XMLHTTP.Open"));
            assert!(signals.calls.iter().any(|call| call == "MSXML2.XMLHTTP.Send"));
            assert!(!signals.errors.iter().any(|error| error.contains("not a constructor")));
            assert!(!signals.errors.iter().any(|error| error.contains("not a callable function")));
        }
        _ => panic!("expected executed"),
    }
}
