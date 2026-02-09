use js_analysis::{DynamicOptions, DynamicOutcome, RuntimeKind, RuntimeMode, RuntimeProfile};

#[cfg(feature = "js-sandbox")]
fn profile_options(kind: RuntimeKind) -> DynamicOptions {
    let mut options = DynamicOptions::default();
    options.runtime_profile = RuntimeProfile {
        kind,
        vendor: match kind {
            RuntimeKind::PdfReader => "adobe".to_string(),
            RuntimeKind::Browser => "chromium".to_string(),
            RuntimeKind::Node => "nodejs".to_string(),
        },
        version: "1".to_string(),
        mode: RuntimeMode::Compat,
    };
    options
}

#[cfg(feature = "js-sandbox")]
fn executed(outcome: DynamicOutcome) -> Box<js_analysis::DynamicSignals> {
    match outcome {
        DynamicOutcome::Executed(signals) => signals,
        DynamicOutcome::TimedOut { timeout_ms } => {
            panic!("sandbox timed out unexpectedly at {} ms", timeout_ms)
        }
        DynamicOutcome::Skipped { reason, .. } => panic!("sandbox skipped unexpectedly: {reason}"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn profile_id_is_emitted_in_dynamic_signals() {
    let options = profile_options(RuntimeKind::PdfReader);
    let signals = executed(js_analysis::run_sandbox(b"app.alert('hi')", &options));
    assert_eq!(signals.runtime_profile, "pdf_reader:adobe:1:compat");
}

#[cfg(feature = "js-sandbox")]
#[test]
fn pdf_profile_contract_exposes_reader_stubs() {
    let options = profile_options(RuntimeKind::PdfReader);
    let payload = b"
        if (typeof app.viewerVersion !== 'function') throw new Error('viewerVersion');
        if (typeof app.viewerType !== 'function') throw new Error('viewerType');
        app.viewerVersion();
        app.viewerType();
        app.plugIns.length;
    ";
    let signals = executed(js_analysis::run_sandbox(payload, &options));
    assert!(signals.calls.iter().any(|call| call == "app.viewerVersion"));
    assert!(signals.calls.iter().any(|call| call == "app.viewerType"));
    assert!(signals.prop_reads.iter().any(|prop| prop == "app.plugIns"));
    assert!(signals.errors.is_empty(), "unexpected errors: {:?}", signals.errors);
}

#[cfg(feature = "js-sandbox")]
#[test]
fn browser_profile_contract_exposes_fetch_stub() {
    let options = profile_options(RuntimeKind::Browser);
    let payload = b"
        if (typeof fetch !== 'function') throw new Error('fetch');
        fetch('https://example.test/path');
    ";
    let signals = executed(js_analysis::run_sandbox(payload, &options));
    assert!(signals.calls.iter().any(|call| call == "fetch"));
    assert!(signals.errors.is_empty(), "unexpected errors: {:?}", signals.errors);
}

#[cfg(feature = "js-sandbox")]
#[test]
fn node_profile_contract_exposes_require_and_process() {
    let options = profile_options(RuntimeKind::Node);
    let payload = b"
        if (typeof require !== 'function') throw new Error('require');
        if (typeof process.exit !== 'function') throw new Error('process.exit');
        require('fs');
        process.exit(0);
    ";
    let signals = executed(js_analysis::run_sandbox(payload, &options));
    assert!(signals.calls.iter().any(|call| call == "require"));
    assert!(signals.calls.iter().any(|call| call == "process.exit"));
    assert!(signals.errors.is_empty(), "unexpected errors: {:?}", signals.errors);
}

#[cfg(feature = "js-sandbox")]
#[test]
fn browser_profile_missing_pdf_api_has_stable_error_signature() {
    let options = profile_options(RuntimeKind::Browser);
    let payload = b"app.viewerVersion();";
    let signals = executed(js_analysis::run_sandbox(payload, &options));
    assert!(!signals.errors.is_empty(), "expected profile mismatch error");
    let combined = signals.errors.join(" | ").to_ascii_lowercase();
    assert!(
        combined.contains("cannot convert")
            || combined.contains("undefined")
            || combined.contains("not defined")
            || combined.contains("not a callable function"),
        "unexpected error signature: {}",
        combined
    );
}
