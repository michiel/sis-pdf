use js_analysis::static_analysis::{decode_layers, extract_js_signals_with_ast};

#[test]
fn detects_basic_js_signals() {
    let data = b"eval('a'+String.fromCharCode(98))";
    let signals = extract_js_signals_with_ast(data, false);
    assert_eq!(signals.get("js.contains_eval").map(String::as_str), Some("true"));
    assert_eq!(signals.get("js.contains_fromcharcode").map(String::as_str), Some("true"));
    assert_eq!(signals.get("js.ast_parsed").map(String::as_str), Some("false"));
}

#[test]
fn decode_layers_unescapes_hex() {
    let data = br"\x48\x65\x6c\x6c\x6f";
    let decoded = decode_layers(data, 2);
    assert!(decoded.layers >= 1);
    assert_eq!(decoded.bytes, b"Hello");
}
