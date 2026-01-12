use js_analysis::{DynamicOptions, DynamicOutcome};

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_skips_large_payload() {
    let mut options = DynamicOptions::default();
    options.max_bytes = 8;
    let data = b"this is too large";
    let outcome = js_analysis::run_sandbox(data, &options);
    match outcome {
        DynamicOutcome::Skipped {
            reason,
            limit,
            actual,
        } => {
            assert_eq!(reason, "payload_too_large");
            assert_eq!(limit, 8);
            assert_eq!(actual, data.len());
        }
        _ => panic!("expected skip"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_exec_records_calls() {
    let options = DynamicOptions::default();
    let outcome = js_analysis::run_sandbox(b"app.alert('hi')", &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.calls.iter().any(|c| c == "alert"));
            assert!(signals.call_count >= 1);
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(not(feature = "js-sandbox"))]
#[test]
fn sandbox_reports_unavailable_without_feature() {
    let options = DynamicOptions::default();
    let outcome = js_analysis::run_sandbox(b"alert(1)", &options);
    match outcome {
        DynamicOutcome::Skipped { reason, .. } => assert_eq!(reason, "sandbox_unavailable"),
        _ => panic!("expected skip"),
    }
}
