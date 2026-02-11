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

#[test]
fn decode_layers_handles_nested_escapes_and_base64() {
    let data = br"\x53\x47\x56\x73\x62\x47\x39\x49\x5a\x57\x78\x73\x62\x30\x68\x6c\x62\x47\x78\x76\x53\x47\x56\x73\x62\x47\x38\x3d";
    let decoded = decode_layers(data, 8);
    assert!(decoded.layers >= 2);
    assert_eq!(decoded.bytes, b"HelloHelloHelloHello");
}

#[test]
fn decode_layers_honours_hard_layer_cap() {
    let data = br"\x31";
    let decoded = decode_layers(data, 99);
    assert!(decoded.layers <= 8);
}

#[test]
fn detects_jsfuck_encoding_signal() {
    let data = b"[]+[]+(![]+[])[+[]]+([][[]]+[])[+!![]]+(![]+[])[!![]+!![]]+(!![]+[])[+[]]";
    let signals = extract_js_signals_with_ast(data, false);
    assert_eq!(signals.get("js.jsfuck_encoding").map(String::as_str), Some("true"));
}

#[test]
fn detects_jjencode_encoding_signal() {
    let data = br#"$=~[];$={___:++$,$$$$:(![]+"")[$],$_:++$,$$_:(![]+"")[$],$_$_:++$,$_$$:([]+"")[$],$$_$:++$,$$$:({}+"")[$],$__:++$,$_$:++$,$$__:({}+"")[$],$$_$_:++$,$$$_:++$,$$$$_:++$,$__:++$};"#;
    let signals = extract_js_signals_with_ast(data, false);
    assert_eq!(signals.get("js.jjencode_encoding").map(String::as_str), Some("true"));
}

#[test]
fn detects_aaencode_encoding_signal() {
    let data =
        "(function(){ var x = '＠＠｀ω´＠＠＾＾＠＠'; return this.constructor('return 1')(); })();";
    let signals = extract_js_signals_with_ast(data.as_bytes(), false);
    assert_eq!(signals.get("js.aaencode_encoding").map(String::as_str), Some("true"));
}

#[cfg(feature = "js-ast")]
#[test]
fn ast_reconstructs_string_concatenation_payloads() {
    let data = b"var payload = 'ev' + 'al' + '(' + \"1\" + ')';";
    let signals = extract_js_signals_with_ast(data, true);
    assert_eq!(
        signals.get("payload.concatenation_reconstructed").map(String::as_str),
        Some("true")
    );
    assert_eq!(signals.get("payload.concatenation_count").map(String::as_str), Some("1"));
}

#[cfg(feature = "js-ast")]
#[test]
fn ast_reconstructs_mixed_concatenation_payloads() {
    let data = b"var p = 'ev' + suffix + 'al' + '(' + arg + ')';";
    let signals = extract_js_signals_with_ast(data, true);
    assert_eq!(
        signals.get("payload.concatenation_reconstructed").map(String::as_str),
        Some("true")
    );
}

#[cfg(feature = "js-ast")]
#[test]
fn concatenation_reconstruction_is_deterministic() {
    let data = b"var payload = 'ev' + 'al' + '(' + \"1\" + ')';";
    let first = extract_js_signals_with_ast(data, true);
    let second = extract_js_signals_with_ast(data, true);
    assert_eq!(first.get("payload.concatenation_count"), second.get("payload.concatenation_count"));
    assert_eq!(
        first.get("payload.concatenation_reconstructed"),
        second.get("payload.concatenation_reconstructed")
    );
}
