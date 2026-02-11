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
fn decode_layers_handles_nested_percent_and_base64_wrappers() {
    let data = b"eval(atob('U0dWc2JHOD0='))";
    let decoded = decode_layers(data, 8);
    assert!(decoded.layers >= 2);
    assert_eq!(decoded.bytes, b"Hello");
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

#[cfg(feature = "js-ast")]
#[test]
fn ast_semantic_flow_detects_source_transform_sink_chain() {
    let data = br#"
        var f = getField('username');
        var encoded = '%61%6c%65%72%74%28%31%29';
        var decoded = unescape(encoded);
        eval(decoded);
    "#;
    let signals = extract_js_signals_with_ast(data, true);
    assert_eq!(signals.get("js.semantic_source_to_sink_flow").map(String::as_str), Some("true"));
    assert_eq!(signals.get("js.ast_parsed").map(String::as_str), Some("true"));
    assert!(
        signals
            .get("js.semantic_flow_complexity")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0)
            >= 1
    );
}

#[test]
fn detects_heap_grooming_signal() {
    let data = include_bytes!("fixtures/modern_heap/cve_2023_21608_sanitised.js");
    let signals = extract_js_signals_with_ast(data, false);
    assert_eq!(signals.get("js.heap_grooming").map(String::as_str), Some("true"));
}

#[test]
fn detects_lfh_priming_signal() {
    let data = br#"
        var pool = [];
        for (var i = 0; i < 64; i++) {
            pool.push(new ArrayBuffer(0x400));
        }
        for (var j = 0; j < pool.length; j++) {
            pool[j] = null;
        }
        var target = new DataView(new ArrayBuffer(0x400));
    "#;
    let signals = extract_js_signals_with_ast(data, false);
    assert_eq!(signals.get("js.lfh_priming").map(String::as_str), Some("true"));
}

#[test]
fn detects_rop_chain_construction_signal() {
    let data = include_bytes!("fixtures/modern_heap/cve_2023_26369_sanitised.js");
    let signals = extract_js_signals_with_ast(data, false);
    assert_eq!(signals.get("js.rop_chain_construction").map(String::as_str), Some("true"));
}

#[test]
fn detects_info_leak_primitive_signal() {
    let data = include_bytes!("fixtures/modern_heap/cve_2023_26369_sanitised.js");
    let signals = extract_js_signals_with_ast(data, false);
    assert_eq!(signals.get("js.info_leak_primitive").map(String::as_str), Some("true"));
}

#[test]
fn detects_enhanced_control_flow_flattening_signal() {
    let data = br#"
        var state = 0;
        while (true) {
            switch(state) {
                case 0: state = 1; break;
                case 1: state = 2; break;
                case 2: return;
            }
        }
    "#;
    let signals = extract_js_signals_with_ast(data, false);
    assert_eq!(signals.get("js.control_flow_flattening").map(String::as_str), Some("true"));
}

#[test]
fn detects_dead_code_injection_signal() {
    let data = br#"
        function run() {
            if (false) { var a = 1; var b = 2; }
            if (0) { console.log('dead'); }
            return;
            var never = 123;
        }
    "#;
    let signals = extract_js_signals_with_ast(data, false);
    assert_eq!(signals.get("js.dead_code_injection").map(String::as_str), Some("true"));
}

#[test]
fn detects_array_rotation_decode_signal() {
    let data = br#"
        var _0xabc=['a','b','c'];
        (function(_0xarr,_0xseed){
            while(--_0xseed){ _0xarr.push(_0xarr.shift()); }
        }(_0xabc,0x12));
        var out = _0xabc[0x1];
    "#;
    let signals = extract_js_signals_with_ast(data, false);
    assert_eq!(signals.get("js.array_rotation_decode").map(String::as_str), Some("true"));
}

#[test]
fn benign_typed_array_processing_no_heap_exploit_signals() {
    let data = br#"
        var payload = new Uint8Array([72, 101, 108, 108, 111]);
        var copy = payload.slice(0, payload.length);
        var text = '';
        for (var i = 0; i < copy.length; i++) {
            text += String.fromCharCode(copy[i]);
        }
    "#;
    let signals = extract_js_signals_with_ast(data, false);
    assert_eq!(signals.get("js.heap_grooming").map(String::as_str), Some("false"));
    assert_eq!(signals.get("js.lfh_priming").map(String::as_str), Some("false"));
    assert_eq!(signals.get("js.rop_chain_construction").map(String::as_str), Some("false"));
    assert_eq!(signals.get("js.info_leak_primitive").map(String::as_str), Some("false"));
}
