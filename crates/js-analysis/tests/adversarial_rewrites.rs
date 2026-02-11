use std::path::PathBuf;

use js_analysis::types::{DynamicOptions, DynamicOutcome};

#[cfg(feature = "js-sandbox")]
fn read_fixture(name: &str) -> Vec<u8> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures/adversarial");
    path.push(name);
    std::fs::read(path).expect("fixture must be readable")
}

#[cfg(feature = "js-sandbox")]
#[test]
fn adversarial_rewrites_trigger_behavioural_resilience_patterns() {
    let options = DynamicOptions::default();
    let fixtures = [
        "variant_01.js",
        "variant_02.js",
        "variant_03.js",
        "variant_04.js",
        "variant_05.js",
        "variant_06.js",
        "variant_07.js",
        "variant_08.js",
        "variant_09.js",
        "variant_10.js",
    ];

    for fixture in fixtures {
        let payload = read_fixture(fixture);
        let outcome = js_analysis::run_sandbox(&payload, &options);
        match outcome {
            DynamicOutcome::Executed(signals) => {
                let names: Vec<&str> = signals
                    .behavioral_patterns
                    .iter()
                    .map(|pattern| pattern.name.as_str())
                    .collect();
                let has_pr19_pattern = names.iter().any(|name| {
                    matches!(
                        *name,
                        "api_call_sequence_malicious"
                            | "source_sink_complexity"
                            | "dynamic_string_materialisation_sink"
                    )
                });
                assert!(
                    has_pr19_pattern,
                    "fixture {fixture} should trigger PR-19 behavioural pattern, observed: {:?}",
                    names
                );
            }
            _ => panic!("expected executed for {fixture}"),
        }
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn benign_transform_chain_without_sink_does_not_trigger_pr19_patterns() {
    let options = DynamicOptions::default();
    let payload = br#"
        var data = '%61%62%63';
        var decoded = unescape(data);
        var text = String.fromCharCode(100, 101, 102);
        var out = decoded + text;
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            for name in [
                "api_call_sequence_malicious",
                "source_sink_complexity",
                "entropy_at_sink",
                "dynamic_string_materialisation_sink",
            ] {
                assert!(
                    !signals.behavioral_patterns.iter().any(|pattern| pattern.name == name),
                    "benign payload unexpectedly triggered {name}"
                );
            }
        }
        _ => panic!("expected executed"),
    }
}
