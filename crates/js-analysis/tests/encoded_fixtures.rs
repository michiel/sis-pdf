use std::path::PathBuf;

use js_analysis::static_analysis::{decode_layers, extract_js_signals_with_ast};

fn read_fixture_bytes(name: &str) -> Vec<u8> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures/encoded");
    path.push(name);
    std::fs::read(path).expect("fixture must be readable")
}

fn trim_ascii_whitespace(data: &[u8]) -> Vec<u8> {
    data.iter().copied().filter(|byte| !byte.is_ascii_whitespace()).collect()
}

#[test]
fn esoteric_malicious_fixtures_raise_expected_signals() {
    let cases = [
        ("esoteric_malicious_jsfuck.js", "js.jsfuck_encoding"),
        ("esoteric_malicious_jjencode.js", "js.jjencode_encoding"),
        ("esoteric_malicious_aaencode.js", "js.aaencode_encoding"),
    ];

    for (fixture, signal) in cases {
        let bytes = read_fixture_bytes(fixture);
        let signals = extract_js_signals_with_ast(&bytes, false);
        assert_eq!(
            signals.get(signal).map(String::as_str),
            Some("true"),
            "fixture {fixture} should raise {signal}"
        );
    }
}

#[test]
fn esoteric_benign_fixtures_do_not_raise_esoteric_signals() {
    let fixtures = [
        "esoteric_benign_jsfuck_like.js",
        "esoteric_benign_jjencode_like.js",
        "esoteric_benign_aaencode_like.js",
    ];

    for fixture in fixtures {
        let bytes = read_fixture_bytes(fixture);
        let signals = extract_js_signals_with_ast(&bytes, false);
        for signal in ["js.jsfuck_encoding", "js.jjencode_encoding", "js.aaencode_encoding"] {
            assert_ne!(
                signals.get(signal).map(String::as_str),
                Some("true"),
                "benign fixture {fixture} unexpectedly raised {signal}"
            );
        }
    }
}

#[test]
fn decode_then_analyse_detects_eval_in_nested_payload() {
    let bytes = read_fixture_bytes("decode_malicious_nested_base64_eval.js");
    let decoded = decode_layers(&trim_ascii_whitespace(&bytes), 8);
    assert!(decoded.layers >= 2, "expected at least two decode layers");
    let decoded_signals = extract_js_signals_with_ast(&decoded.bytes, false);
    assert_eq!(decoded_signals.get("js.contains_eval").map(String::as_str), Some("true"));
}

#[test]
fn decode_then_analyse_keeps_benign_payload_below_eval_threshold() {
    let bytes = read_fixture_bytes("decode_benign_nested_base64_console.js");
    let decoded = decode_layers(&trim_ascii_whitespace(&bytes), 8);
    assert!(decoded.layers >= 2, "expected at least two decode layers");
    let decoded_signals = extract_js_signals_with_ast(&decoded.bytes, false);
    assert_ne!(decoded_signals.get("js.contains_eval").map(String::as_str), Some("true"));
}
