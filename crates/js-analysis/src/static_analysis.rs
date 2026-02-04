use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

#[derive(Debug, Clone)]
pub struct DecodedLayers {
    pub bytes: Vec<u8>,
    pub layers: usize,
}

pub fn extract_js_signals(data: &[u8]) -> HashMap<String, String> {
    extract_js_signals_with_ast(data, true)
}

pub fn extract_js_signals_with_ast(data: &[u8], enable_ast: bool) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let entropy = shannon_entropy(data);
    out.insert("js.entropy".into(), format!("{:.3}", entropy));
    out.insert(
        "js.has_base64_like".into(),
        bool_str(count_base64_like_runs(data, 40) > 0),
    );
    out.insert(
        "js.long_token_run".into(),
        bool_str(longest_token_run(data) >= 32),
    );

    // Attempt payload reconstruction (fromCharCode, concatenation, etc.)
    if enable_ast {
        if let Some(reconstructed) = reconstruct_payloads(data) {
            if !reconstructed.from_charcode.is_empty() {
                out.insert("payload.fromCharCode_reconstructed".into(), "true".into());
                out.insert(
                    "payload.fromCharCode_count".into(),
                    reconstructed.from_charcode.len().to_string(),
                );
                // Include first reconstructed payload as preview
                if let Some(first) = reconstructed.from_charcode.first() {
                    let preview = if first.len() > 200 {
                        format!("{}...", &first[..200])
                    } else {
                        first.clone()
                    };
                    out.insert("payload.fromCharCode_preview".into(), preview);
                }
            }
            if !reconstructed.concatenations.is_empty() {
                out.insert("payload.concatenation_reconstructed".into(), "true".into());
                out.insert(
                    "payload.concatenation_count".into(),
                    reconstructed.concatenations.len().to_string(),
                );
            }
        }
    }
    out.insert(
        "js.contains_hex_escapes".into(),
        bool_str(contains_hex_escape(data)),
    );
    out.insert(
        "js.contains_unicode_escapes".into(),
        bool_str(contains_unicode_escape(data)),
    );
    out.insert(
        "js.contains_eval".into(),
        bool_str(find_token(data, b"eval")),
    );
    out.insert(
        "js.dynamic_eval_construction".into(),
        bool_str(contains_dynamic_eval_construction(data)),
    );
    out.insert(
        "js.contains_unescape".into(),
        bool_str(find_token(data, b"unescape")),
    );
    out.insert(
        "js.contains_fromcharcode".into(),
        bool_str(find_token(data, b"fromCharCode")),
    );
    out.insert(
        "js.hex_fromcharcode_pattern".into(),
        bool_str(contains_hex_fromcharcode_pattern(data)),
    );
    out.insert(
        "js.environment_fingerprinting".into(),
        bool_str(contains_environment_fingerprinting(data)),
    );
    out.insert(
        "js.string_concat_density".into(),
        format!("{:.3}", byte_density(data, b'+')),
    );
    out.insert(
        "js.escape_density".into(),
        format!("{:.3}", byte_density(data, b'\\')),
    );
    out.insert(
        "js.regex_packing".into(),
        bool_str(contains_regex_packing(data)),
    );
    out.insert(
        "js.suspicious_apis".into(),
        bool_str(contains_suspicious_api(data)),
    );

    // Shellcode detection
    out.insert(
        "js.shellcode_pattern".into(),
        bool_str(detect_shellcode_pattern(data)),
    );
    out.insert("js.nop_sled".into(), bool_str(detect_nop_sled(data)));

    // Memory corruption primitives
    out.insert(
        "js.type_confusion_risk".into(),
        bool_str(detect_type_confusion(data)),
    );
    out.insert(
        "js.integer_overflow_setup".into(),
        bool_str(detect_integer_overflow(data)),
    );
    out.insert(
        "js.array_manipulation_exploit".into(),
        bool_str(detect_array_manipulation(data)),
    );

    // Anti-analysis techniques
    out.insert(
        "js.debugger_detection".into(),
        bool_str(detect_debugger_detection(data)),
    );
    out.insert(
        "js.sandbox_evasion".into(),
        bool_str(detect_sandbox_evasion(data)),
    );
    out.insert(
        "js.exception_abuse".into(),
        bool_str(detect_exception_abuse(data)),
    );
    out.insert("js.time_bomb".into(), bool_str(detect_time_bomb(data)));

    // Data exfiltration
    out.insert(
        "js.form_manipulation".into(),
        bool_str(detect_form_manipulation(data)),
    );
    out.insert(
        "js.credential_harvesting".into(),
        bool_str(detect_credential_harvesting(data)),
    );
    out.insert(
        "js.encoded_transmission".into(),
        bool_str(detect_encoded_transmission(data)),
    );

    // Advanced obfuscation
    out.insert(
        "js.control_flow_flattening".into(),
        bool_str(detect_control_flow_flattening(data)),
    );
    out.insert(
        "js.opaque_predicates".into(),
        bool_str(detect_opaque_predicates(data)),
    );
    out.insert(
        "js.identifier_mangling".into(),
        bool_str(detect_identifier_mangling(data)),
    );

    // PDF exploitation
    out.insert(
        "js.font_exploitation".into(),
        bool_str(detect_font_exploitation(data)),
    );
    out.insert(
        "js.annotation_abuse".into(),
        bool_str(detect_annotation_abuse(data)),
    );
    out.insert(
        "js.xfa_exploitation".into(),
        bool_str(detect_xfa_exploitation(data)),
    );

    // C2 patterns
    out.insert("js.dga_pattern".into(), bool_str(detect_dga_pattern(data)));
    out.insert(
        "js.beaconing_pattern".into(),
        bool_str(detect_beaconing_pattern(data)),
    );

    // Cryptomining
    out.insert(
        "js.cryptomining_library".into(),
        bool_str(detect_cryptomining_library(data)),
    );
    out.insert("js.wasm_mining".into(), bool_str(detect_wasm_mining(data)));

    // Unicode abuse
    out.insert(
        "js.unicode_obfuscation".into(),
        bool_str(detect_unicode_obfuscation(data)),
    );
    out.insert(
        "js.rtl_override".into(),
        bool_str(detect_rtl_override(data)),
    );
    out.insert(
        "js.homoglyph_attack".into(),
        bool_str(detect_homoglyph_attack(data)),
    );

    // Custom decoders
    out.insert(
        "js.custom_decoder".into(),
        bool_str(detect_custom_decoder(data)),
    );

    // Function introspection
    out.insert(
        "js.function_introspection".into(),
        bool_str(detect_function_introspection(data)),
    );

    // Excessive string allocation
    out.insert(
        "js.excessive_string_allocation".into(),
        bool_str(detect_excessive_string_allocation(data)),
    );

    // Resource exhaustion & DoS
    out.insert(
        "js.infinite_loop_risk".into(),
        bool_str(detect_infinite_loop_risk(data)),
    );
    out.insert("js.memory_bomb".into(), bool_str(detect_memory_bomb(data)));
    out.insert(
        "js.computational_bomb".into(),
        bool_str(detect_computational_bomb(data)),
    );
    out.insert(
        "js.recursive_bomb".into(),
        bool_str(detect_recursive_bomb(data)),
    );
    out.insert(
        "js.redos_pattern".into(),
        bool_str(detect_redos_pattern(data)),
    );

    // Code injection & DOM manipulation
    out.insert(
        "js.dom_xss_sink".into(),
        bool_str(detect_dom_xss_sink(data)),
    );
    out.insert(
        "js.innerHTML_injection".into(),
        bool_str(detect_innerhtml_injection(data)),
    );
    out.insert(
        "js.prototype_pollution_gadget".into(),
        bool_str(detect_prototype_pollution_gadget(data)),
    );
    out.insert(
        "js.script_injection".into(),
        bool_str(detect_script_injection(data)),
    );
    out.insert("js.eval_sink".into(), bool_str(detect_eval_sink(data)));

    // Exploit kit signatures
    out.insert("js.angler_ek".into(), bool_str(detect_angler_ek(data)));
    out.insert(
        "js.magnitude_ek".into(),
        bool_str(detect_magnitude_ek(data)),
    );
    out.insert("js.rig_ek".into(), bool_str(detect_rig_ek(data)));
    out.insert(
        "js.exploit_kit_pattern".into(),
        bool_str(detect_exploit_kit_pattern(data)),
    );

    // Ransomware patterns
    out.insert(
        "js.file_enumeration".into(),
        bool_str(detect_file_enumeration(data)),
    );
    out.insert(
        "js.bulk_encryption".into(),
        bool_str(detect_bulk_encryption(data)),
    );
    out.insert("js.ransom_note".into(), bool_str(detect_ransom_note(data)));
    out.insert(
        "js.bitcoin_address".into(),
        bool_str(detect_bitcoin_address(data)),
    );

    // Advanced shellcode techniques
    out.insert("js.jit_spray".into(), bool_str(detect_jit_spray(data)));
    out.insert(
        "js.unicode_shellcode".into(),
        bool_str(detect_unicode_shellcode(data)),
    );
    out.insert(
        "js.constant_spray".into(),
        bool_str(detect_constant_spray(data)),
    );

    // Advanced evasion
    out.insert(
        "js.fingerprint_check".into(),
        bool_str(detect_fingerprint_check(data)),
    );
    out.insert(
        "js.timing_evasion".into(),
        bool_str(detect_timing_evasion(data)),
    );
    out.insert(
        "js.interaction_required".into(),
        bool_str(detect_interaction_required(data)),
    );
    out.insert(
        "js.targeted_execution".into(),
        bool_str(detect_targeted_execution(data)),
    );

    // Persistence & state manipulation
    out.insert(
        "js.localStorage_write".into(),
        bool_str(detect_localstorage_write(data)),
    );
    out.insert(
        "js.cookie_manipulation".into(),
        bool_str(detect_cookie_manipulation(data)),
    );
    out.insert(
        "js.global_pollution".into(),
        bool_str(detect_global_pollution(data)),
    );
    out.insert(
        "js.history_manipulation".into(),
        bool_str(detect_history_manipulation(data)),
    );

    // Supply chain attacks
    out.insert(
        "js.dynamic_import".into(),
        bool_str(detect_dynamic_import(data)),
    );
    out.insert(
        "js.remote_script_load".into(),
        bool_str(detect_remote_script_load(data)),
    );
    out.insert(
        "js.suspicious_package".into(),
        bool_str(detect_suspicious_package(data)),
    );

    // Network abuse
    out.insert("js.port_scan".into(), bool_str(detect_port_scan(data)));
    out.insert(
        "js.internal_probe".into(),
        bool_str(detect_internal_probe(data)),
    );
    out.insert(
        "js.dns_rebinding".into(),
        bool_str(detect_dns_rebinding(data)),
    );

    // Steganography
    out.insert(
        "js.comment_payload".into(),
        bool_str(detect_comment_payload(data)),
    );
    out.insert(
        "js.zero_width_chars".into(),
        bool_str(detect_zero_width_chars(data)),
    );
    out.insert(
        "js.canvas_decode".into(),
        bool_str(detect_canvas_decode(data)),
    );

    // Polyglot files
    out.insert(
        "js.polyglot_pdf".into(),
        bool_str(detect_polyglot_pdf(data)),
    );
    out.insert(
        "js.polyglot_html".into(),
        bool_str(detect_polyglot_html(data)),
    );

    // Browser fingerprinting
    out.insert(
        "js.canvas_fingerprint".into(),
        bool_str(detect_canvas_fingerprint(data)),
    );
    out.insert(
        "js.webgl_fingerprint".into(),
        bool_str(detect_webgl_fingerprint(data)),
    );
    out.insert(
        "js.font_enumeration".into(),
        bool_str(detect_font_enumeration(data)),
    );

    out.insert("js.ast_parsed".into(), "false".into());
    out.insert("js.sandbox_exec".into(), "false".into());
    #[cfg(feature = "js-ast")]
    {
        if enable_ast {
            if let Some(summary) = ast_behaviour_summary(data) {
                out.insert("js.ast_parsed".into(), "true".into());
                if let Some(summary) = summary.summary {
                    out.insert("js.behaviour_summary".into(), summary);
                }
                if !summary.call_args.is_empty() {
                    out.insert("js.ast_call_args".into(), summary.call_args.join("; "));
                }
                if !summary.urls.is_empty() {
                    out.insert("js.ast_urls".into(), summary.urls.join(", "));
                }
                if !summary.domains.is_empty() {
                    out.insert("js.ast_domains".into(), summary.domains.join(", "));
                }
            }
        }
    }

    let obf = is_obfuscationish(&out);
    out.insert("js.obfuscation_suspected".into(), bool_str(obf));
    out
}

pub fn decode_layers(data: &[u8], max_layers: usize) -> DecodedLayers {
    let mut current = data.to_vec();
    let mut layers = 0usize;
    loop {
        if layers >= max_layers {
            break;
        }
        if let Some(next) = decode_once(&current) {
            current = next;
            layers += 1;
            continue;
        }
        break;
    }
    DecodedLayers {
        bytes: current,
        layers,
    }
}

fn decode_once(data: &[u8]) -> Option<Vec<u8>> {
    if let Some(decoded) = decode_js_escapes(data) {
        return Some(decoded);
    }
    if let Some(decoded) = decode_hex_string(data) {
        return Some(decoded);
    }
    if is_base64_like(data) {
        if let Ok(decoded) = STANDARD.decode(data) {
            if decoded.len() > 16 {
                return Some(decoded);
            }
        }
    }
    None
}

fn decode_js_escapes(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0usize;
    let mut changed = false;
    while i < data.len() {
        if data[i] == b'\\' && i + 1 < data.len() {
            match data[i + 1] {
                b'x' if i + 3 < data.len() => {
                    if let Ok(v) =
                        u8::from_str_radix(&String::from_utf8_lossy(&data[i + 2..i + 4]), 16)
                    {
                        out.push(v);
                        i += 4;
                        changed = true;
                        continue;
                    }
                }
                b'u' if i + 5 < data.len() => {
                    if let Ok(v) =
                        u16::from_str_radix(&String::from_utf8_lossy(&data[i + 2..i + 6]), 16)
                    {
                        if let Some(s) = std::char::from_u32(v as u32) {
                            out.push(s as u8);
                            i += 6;
                            changed = true;
                            continue;
                        }
                    }
                }
                _ => {}
            }
        }
        out.push(data[i]);
        i += 1;
    }
    if changed {
        Some(out)
    } else {
        None
    }
}

fn decode_hex_string(data: &[u8]) -> Option<Vec<u8>> {
    let mut cleaned = Vec::new();
    for &b in data {
        if (b as char).is_ascii_hexdigit() {
            cleaned.push(b);
        } else if !b.is_ascii_whitespace() {
            return None;
        }
    }
    if cleaned.len() < 16 || cleaned.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        let s = String::from_utf8_lossy(&cleaned[i..i + 2]);
        if let Ok(v) = u8::from_str_radix(&s, 16) {
            out.push(v);
        } else {
            return None;
        }
    }
    Some(out)
}

fn is_base64_like(data: &[u8]) -> bool {
    data.iter().all(|b| {
        b.is_ascii_alphanumeric()
            || *b == b'+'
            || *b == b'/'
            || *b == b'='
            || b.is_ascii_whitespace()
    })
}

fn count_base64_like_runs(data: &[u8], min_len: usize) -> usize {
    let mut count = 0usize;
    let mut run = 0usize;
    for &b in data {
        if b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' {
            run += 1;
        } else {
            if run >= min_len {
                count += 1;
            }
            run = 0;
        }
    }
    if run >= min_len {
        count += 1;
    }
    count
}

fn longest_token_run(data: &[u8]) -> usize {
    let mut max = 0usize;
    let mut current = 0usize;
    for &b in data {
        if b.is_ascii_alphanumeric() || b == b'_' {
            current += 1;
        } else {
            if current > max {
                max = current;
            }
            current = 0;
        }
    }
    max.max(current)
}

fn contains_hex_escape(data: &[u8]) -> bool {
    find_token(data, b"\\x")
}

fn contains_unicode_escape(data: &[u8]) -> bool {
    find_token(data, b"\\u")
}

fn contains_regex_packing(data: &[u8]) -> bool {
    find_token(data, b"/") && find_token(data, b".replace")
}

fn contains_suspicious_api(data: &[u8]) -> bool {
    let apis: &[&[u8]] = &[
        // Existing APIs
        b"app.launchURL",
        b"util.printf",
        b"this.getURL",
        b"submitForm",
        b"importDataObject",
        b"exportDataObject",
        b"app.mailMsg",
        // PDF annotation manipulation (high risk)
        b"app.doc.syncAnnotScan",
        b"app.doc.getAnnots",
        b"app.doc.addAnnot",
        b"app.doc.removeAnnot",
        b".subject",
        // Environment fingerprinting
        b"app.plugIns.length",
        b"app.viewerType",
        b"app.platform",
        // Media exploitation
        b"this.media.newPlayer",
        b"app.media.newPlayer",
        // Advanced execution contexts
        b"this.getOCGs",
        b"app.doc.getOCGs",
    ];
    apis.iter().any(|pat| find_token(data, pat))
}

fn find_token(data: &[u8], token: &[u8]) -> bool {
    data.windows(token.len())
        .any(|w| w.eq_ignore_ascii_case(token))
}

fn contains_dynamic_eval_construction(data: &[u8]) -> bool {
    // Detect patterns like: 'ev' + 'a' + 'l' or variable[function_name]()
    let patterns: &[&[u8]] = &[
        // String concatenation to form "eval"
        b"'ev'", b"\"ev\"", // Common eval construction fragments
        b"'a'", b"\"a\"", b"'l'", b"\"l\"",
    ];

    // Look for string concatenation operators near eval fragments
    let has_eval_fragments = patterns.iter().any(|pat| find_token(data, pat));
    let has_concat = find_token(data, b"+");
    let has_dynamic_access = find_token(data, b"[") && find_token(data, b"]");

    (has_eval_fragments && has_concat) || has_dynamic_access
}

fn contains_hex_fromcharcode_pattern(data: &[u8]) -> bool {
    // Detect String.fromCharCode with hex patterns like "0x" or parseInt usage
    let has_fromcharcode = find_token(data, b"fromCharCode");
    let has_hex_prefix = find_token(data, b"0x") || find_token(data, b"\"0x");
    let has_parseint = find_token(data, b"parseInt");

    has_fromcharcode && (has_hex_prefix || has_parseint)
}

fn contains_environment_fingerprinting(data: &[u8]) -> bool {
    // Detect conditional execution based on environment properties
    let fingerprint_props: &[&[u8]] = &[
        b"app.plugIns.length",
        b"app.viewerType",
        b"app.platform",
        b"app.viewerVersion",
        b"this.info.title",
        b"this.info.author",
    ];

    let has_fingerprinting = fingerprint_props.iter().any(|pat| find_token(data, pat));
    let has_conditional = find_token(data, b"if")
        && (find_token(data, b">") || find_token(data, b"==") || find_token(data, b"!="));

    has_fingerprinting && has_conditional
}

fn byte_density(data: &[u8], byte: u8) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let count = data.iter().filter(|b| **b == byte).count();
    count as f64 / data.len() as f64
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut out = 0.0;
    for &c in freq.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        out -= p * p.log2();
    }
    out
}

fn bool_str(val: bool) -> String {
    if val {
        "true".into()
    } else {
        "false".into()
    }
}

fn is_obfuscationish(meta: &HashMap<String, String>) -> bool {
    let base64_like = meta
        .get("js.has_base64_like")
        .map(|v| v == "true")
        .unwrap_or(false);
    let has_eval = meta
        .get("js.contains_eval")
        .map(|v| v == "true")
        .unwrap_or(false);
    let has_fcc = meta
        .get("js.contains_fromcharcode")
        .map(|v| v == "true")
        .unwrap_or(false);
    let has_unescape = meta
        .get("js.contains_unescape")
        .map(|v| v == "true")
        .unwrap_or(false);
    let has_hex = meta
        .get("js.contains_hex_escapes")
        .map(|v| v == "true")
        .unwrap_or(false);
    let has_unicode = meta
        .get("js.contains_unicode_escapes")
        .map(|v| v == "true")
        .unwrap_or(false);
    base64_like || (has_eval && (has_fcc || has_unescape)) || has_hex || has_unicode
}

#[cfg(feature = "js-ast")]
struct AstSummary {
    summary: Option<String>,
    call_args: Vec<String>,
    urls: Vec<String>,
    domains: Vec<String>,
}

#[cfg(feature = "js-ast")]
fn ast_behaviour_summary(data: &[u8]) -> Option<AstSummary> {
    use boa_ast::expression::literal::Literal;
    use boa_ast::expression::Call;
    use boa_ast::scope::Scope;
    use boa_ast::visitor::{VisitWith, Visitor};
    use boa_interner::{Interner, ToInternedString};
    use boa_parser::{Parser, Source};
    use std::collections::{BTreeMap, BTreeSet, HashMap as Map};

    let src = std::str::from_utf8(data).ok()?;
    let mut interner = Interner::default();
    let source = Source::from_bytes(src);
    let mut parser = Parser::new(source);
    let scope = Scope::new_global();
    let script = parser.parse_script(&scope, &mut interner).ok()?;

    struct JsAstVisitor<'a> {
        interner: &'a Interner,
        calls: Map<String, usize>,
        urls: BTreeSet<String>,
        domains: BTreeSet<String>,
        call_args: BTreeMap<String, BTreeSet<String>>,
    }

    impl<'ast, 'a> Visitor<'ast> for JsAstVisitor<'a> {
        type BreakTy = ();

        fn visit_call(&mut self, node: &'ast Call) -> std::ops::ControlFlow<Self::BreakTy> {
            let name = node.function().to_interned_string(self.interner);
            if !name.is_empty() {
                *self.calls.entry(name.clone()).or_insert(0) += 1;
            }
            if !name.is_empty() {
                for arg in node.args() {
                    if let boa_ast::expression::Expression::Literal(literal) = arg {
                        if let Some(sym) = literal.as_string() {
                            let value = self.interner.resolve_expect(sym).join(
                                |s: &str| s.to_string(),
                                String::from_utf16_lossy,
                                true,
                            );
                            let summary = summarise_arg_value(&value, 60);
                            self.call_args
                                .entry(name.clone())
                                .or_default()
                                .insert(summary);
                            if looks_like_url(&value) {
                                self.urls.insert(value.clone());
                                if let Some(domain) = domain_from_url(&value) {
                                    self.domains.insert(domain);
                                }
                            }
                        }
                    }
                }
            }
            node.visit_with(self)
        }

        fn visit_literal(&mut self, node: &'ast Literal) -> std::ops::ControlFlow<Self::BreakTy> {
            if let Some(sym) = node.as_string() {
                let value = self.interner.resolve_expect(sym).join(
                    |s: &str| s.to_string(),
                    String::from_utf16_lossy,
                    true,
                );
                if looks_like_url(&value) {
                    self.urls.insert(value.clone());
                    if let Some(domain) = domain_from_url(&value) {
                        self.domains.insert(domain);
                    }
                }
            }
            node.visit_with(self)
        }
    }

    let mut visitor = JsAstVisitor {
        interner: &interner,
        calls: Map::new(),
        urls: BTreeSet::new(),
        domains: BTreeSet::new(),
        call_args: BTreeMap::new(),
    };
    let _ = script.visit_with(&mut visitor);

    let mut parts = Vec::new();
    if !visitor.calls.is_empty() {
        let mut calls: Vec<_> = visitor.calls.into_iter().collect();
        calls.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let summary = calls
            .into_iter()
            .take(10)
            .map(|(name, count)| format!("{} ({})", name, count))
            .collect::<Vec<_>>()
            .join(", ");
        if !summary.is_empty() {
            parts.push(format!("Calls: {}", summary));
        }
    }
    if !visitor.urls.is_empty() {
        let summary = visitor
            .urls
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if !summary.is_empty() {
            parts.push(format!("URLs: {}", summary));
        }
    }
    if !visitor.domains.is_empty() {
        let summary = visitor
            .domains
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if !summary.is_empty() {
            parts.push(format!("Domains: {}", summary));
        }
    }
    let call_args = render_call_args(visitor.call_args, 6, 3);
    let urls = visitor.urls.iter().take(5).cloned().collect::<Vec<_>>();
    let domains = visitor.domains.iter().take(5).cloned().collect::<Vec<_>>();
    let summary = if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    };
    Some(AstSummary {
        summary,
        call_args,
        urls,
        domains,
    })
}

#[derive(Debug, Clone)]
struct ReconstructedPayloads {
    from_charcode: Vec<String>,
    concatenations: Vec<String>,
}

/// Reconstruct obfuscated payloads from JavaScript code
#[cfg(feature = "js-ast")]
fn reconstruct_payloads(data: &[u8]) -> Option<ReconstructedPayloads> {
    use boa_ast::expression::Call;
    use boa_ast::scope::Scope;
    use boa_ast::visitor::{VisitWith, Visitor};
    use boa_interner::{Interner, ToInternedString};
    use boa_parser::{Parser, Source};

    let src = std::str::from_utf8(data).ok()?;
    let mut interner = Interner::default();
    let source = Source::from_bytes(src);
    let mut parser = Parser::new(source);
    let scope = Scope::new_global();
    let script = parser.parse_script(&scope, &mut interner).ok()?;

    struct ReconstructionVisitor<'a> {
        interner: &'a Interner,
        from_charcode: Vec<String>,
    }

    impl<'ast, 'a> Visitor<'ast> for ReconstructionVisitor<'a> {
        type BreakTy = ();

        fn visit_call(&mut self, node: &'ast Call) -> std::ops::ControlFlow<Self::BreakTy> {
            // Check for String.fromCharCode(...) pattern
            let func_name = node.function().to_interned_string(self.interner);

            // Handle String.fromCharCode or fromCharCode
            let is_from_charcode = func_name == "String.fromCharCode"
                || func_name == "fromCharCode"
                || func_name.ends_with(".fromCharCode");

            if is_from_charcode {
                // Try to reconstruct the string from numeric arguments
                if let Some(reconstructed) = self.reconstruct_from_charcode_args(node.args()) {
                    if !reconstructed.is_empty() {
                        self.from_charcode.push(reconstructed);
                    }
                }
            }

            node.visit_with(self)
        }
    }

    impl<'a> ReconstructionVisitor<'a> {
        fn reconstruct_from_charcode_args(
            &self,
            args: &[boa_ast::expression::Expression],
        ) -> Option<String> {
            let mut result = String::new();

            for arg in args {
                // Try to get numeric literal
                // Convert the expression to a string and try to parse as number
                let arg_str = arg.to_interned_string(self.interner);
                if let Ok(code) = arg_str.parse::<i64>() {
                    if (0..=0x10FFFF).contains(&code) {
                        if let Some(ch) = char::from_u32(code as u32) {
                            result.push(ch);
                        } else {
                            return None; // Invalid character code
                        }
                    } else {
                        return None; // Out of range
                    }
                } else {
                    // Not a simple numeric literal, skip reconstruction
                    return None;
                }
            }

            if result.is_empty() {
                None
            } else {
                Some(result)
            }
        }
    }

    let mut visitor = ReconstructionVisitor {
        interner: &interner,
        from_charcode: Vec::new(),
    };

    let _ = script.visit_with(&mut visitor);

    Some(ReconstructedPayloads {
        from_charcode: visitor.from_charcode,
        concatenations: Vec::new(), // Will be implemented in Phase 2.1
    })
}

#[cfg(not(feature = "js-ast"))]
fn reconstruct_payloads(_data: &[u8]) -> Option<ReconstructedPayloads> {
    None
}

#[cfg(feature = "js-ast")]
fn looks_like_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("mailto:")
        || lower.starts_with("javascript:")
}

#[cfg(feature = "js-ast")]
fn render_call_args(
    map: std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
    max_calls: usize,
    max_args: usize,
) -> Vec<String> {
    let mut out = Vec::new();
    for (call, args) in map.into_iter().take(max_calls) {
        let mut list: Vec<String> = args.into_iter().take(max_args).collect();
        if list.is_empty() {
            continue;
        }
        if list.len() == 1 {
            out.push(format!("{}({})", call, list.remove(0)));
        } else {
            out.push(format!("{}({})", call, list.join(", ")));
        }
    }
    out
}

#[cfg(feature = "js-ast")]
fn summarise_arg_value(value: &str, max_len: usize) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if out.len() >= max_len {
            break;
        }
        if ch.is_ascii_graphic() || ch == ' ' {
            out.push(ch);
        } else if ch.is_whitespace() {
            out.push(' ');
        } else {
            out.push('.');
        }
    }
    out.trim().to_string()
}

#[cfg(feature = "js-ast")]
fn domain_from_url(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("mailto:") {
        let rest = &value[7..];
        return rest
            .split('@')
            .nth(1)
            .map(|s| s.split('?').next().unwrap_or(s).to_string());
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        let trimmed = value.split("://").nth(1)?;
        let host = trimmed.split('/').next().unwrap_or(trimmed);
        let host = host.split('?').next().unwrap_or(host);
        let host = host.split('#').next().unwrap_or(host);
        if host.is_empty() {
            None
        } else {
            Some(host.to_string())
        }
    } else {
        None
    }
}

// ============================================================================
// Shellcode Detection
// ============================================================================

fn detect_shellcode_pattern(data: &[u8]) -> bool {
    // Extract char codes from fromCharCode calls
    let char_codes = extract_char_codes(data);
    if char_codes.is_empty() {
        return false;
    }

    // Check for common shellcode signatures
    if has_shellcode_signature(&char_codes) {
        return true;
    }

    // Check for high entropy in char codes (encrypted shellcode)
    if !char_codes.is_empty() {
        let entropy = shannon_entropy(&char_codes);
        if entropy > 7.5 {
            return true;
        }
    }

    false
}

fn detect_nop_sled(data: &[u8]) -> bool {
    let char_codes = extract_char_codes(data);
    if char_codes.len() < 10 {
        return false;
    }

    // Check for NOP patterns (0x90 and equivalents)
    let nop_variants = [0x90, 0x97, 0x9F, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x98];
    let mut consecutive_nops = 0;

    for &byte in &char_codes {
        if nop_variants.contains(&byte) {
            consecutive_nops += 1;
            if consecutive_nops >= 10 {
                return true;
            }
        } else {
            consecutive_nops = 0;
        }
    }

    false
}

fn extract_char_codes(data: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(data);
    let mut codes = Vec::new();

    // Simple extraction of numeric values after fromCharCode
    for (i, _) in s.match_indices("fromCharCode") {
        let rest = &s[i..];
        // Find opening paren
        if let Some(paren_pos) = rest.find('(') {
            let after_paren = &rest[paren_pos + 1..];
            // Extract numbers until closing paren
            if let Some(close_paren) = after_paren.find(')') {
                let args = &after_paren[..close_paren];
                for num_str in args.split(',') {
                    let trimmed = num_str.trim();
                    // Parse decimal or hex numbers
                    if let Ok(val) = if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
                        u32::from_str_radix(&trimmed[2..], 16)
                    } else {
                        trimmed.parse::<u32>()
                    } {
                        if val <= 255 {
                            codes.push(val as u8);
                        }
                    }
                }
            }
        }
    }

    codes
}

fn has_shellcode_signature(bytes: &[u8]) -> bool {
    if bytes.len() < 10 {
        return false;
    }

    // Common x86/x64 shellcode patterns
    let signatures: &[&[u8]] = &[
        &[0x55, 0x89, 0xE5],             // push ebp; mov ebp, esp
        &[0x48, 0x89, 0xE5],             // mov rbp, rsp (x64)
        &[0xEB, 0xFE],                   // jmp $
        &[0xE8, 0x00, 0x00, 0x00, 0x00], // call $+5
        &[0xFF, 0xD0],                   // call eax
        &[0xFF, 0xE0],                   // jmp eax
        &[0x6A, 0x00],                   // push 0
        &[0x68],                         // push imm32
    ];

    for window in bytes.windows(3) {
        for sig in signatures {
            if window.starts_with(sig) {
                return true;
            }
        }
    }

    false
}

// ============================================================================
// Memory Corruption Primitives
// ============================================================================

fn detect_type_confusion(data: &[u8]) -> bool {
    // Array prototype manipulation
    let array_proto_patterns: &[&[u8]] = &[
        b"Array.prototype.__proto__",
        b"Array.prototype.constructor",
        b".prototype.__proto__",
    ];

    for pattern in array_proto_patterns {
        if find_token(data, pattern) {
            return true;
        }
    }

    // Suspicious array operations
    let suspicious_array_ops: &[&[u8]] = &[b".length = 0x", b".length = -", b"arr.length"];

    let mut array_length_manipulation = 0;
    for pattern in suspicious_array_ops {
        if find_token(data, pattern) {
            array_length_manipulation += 1;
        }
    }

    array_length_manipulation >= 2
}

fn detect_integer_overflow(data: &[u8]) -> bool {
    // Look for large integer constants and bitwise operations
    let patterns: &[&[u8]] = &[
        b"0x7fffffff",
        b"0x7FFFFFFF",
        b"0xffffffff",
        b"0xFFFFFFFF",
        b"MAX_SAFE_INTEGER",
        b"Number.MAX_VALUE",
    ];

    let has_large_constant = patterns.iter().any(|p| find_token(data, p));

    // Bitwise operations that might indicate overflow exploitation
    let bitwise_ops: &[&[u8]] = &[b">>>", b"<< ", b">> ", b"& 0x", b"| 0x"];

    let has_bitwise = bitwise_ops.iter().any(|p| find_token(data, p));

    has_large_constant && has_bitwise
}

fn detect_array_manipulation(data: &[u8]) -> bool {
    let array_methods: &[&[u8]] = &[
        b".push(",
        b".pop(",
        b".shift(",
        b".unshift(",
        b".splice(",
        b"Array(",
        b"new Array",
    ];

    let count = array_methods.iter().filter(|p| find_token(data, p)).count();

    // High density of array operations
    count >= 4
}

// ============================================================================
// Anti-Analysis Techniques
// ============================================================================

fn detect_debugger_detection(data: &[u8]) -> bool {
    let debugger_patterns: &[&[u8]] = &[
        b"eval.toString().length",
        b"Function.prototype.toString",
        b"performance.now()",
        b"Date.now()",
        b".toString.call(",
        b"constructor.name",
    ];

    let count = debugger_patterns
        .iter()
        .filter(|p| find_token(data, p))
        .count();
    count >= 2
}

fn detect_sandbox_evasion(data: &[u8]) -> bool {
    let sandbox_checks: &[&[u8]] = &[
        b"typeof window",
        b"typeof document",
        b"typeof navigator",
        b"app.viewerType",
        b"app.platform",
        b"app.viewerVersion",
        b"screen.width",
        b"screen.height",
        b"navigator.plugins",
    ];

    let count = sandbox_checks
        .iter()
        .filter(|p| find_token(data, p))
        .count();
    count >= 3
}

fn detect_exception_abuse(data: &[u8]) -> bool {
    // Count try-catch blocks
    let try_count = data.windows(3).filter(|w| w == b"try").count();
    let catch_count = data.windows(5).filter(|w| w == b"catch").count();

    // Excessive exception handling (more than 5 try-catch blocks)
    try_count >= 5 && catch_count >= 5
}

fn detect_time_bomb(data: &[u8]) -> bool {
    let time_apis: &[&[u8]] = &[
        b"Date()",
        b"getTime()",
        b"getHours()",
        b"getDate()",
        b"getMonth()",
    ];
    let has_time_api = time_apis.iter().any(|p| find_token(data, p));

    let conditionals: &[&[u8]] = &[b"if", b">", b"<", b"==", b"!="];
    let has_conditional = conditionals.iter().all(|p| find_token(data, p));

    has_time_api && has_conditional
}

// ============================================================================
// Data Exfiltration
// ============================================================================

fn detect_form_manipulation(data: &[u8]) -> bool {
    let form_patterns: &[&[u8]] = &[
        b"createElement('form')",
        b"createElement(\"form\")",
        b".submit(",
        b"type=\"hidden\"",
        b"type='hidden'",
    ];

    let count = form_patterns.iter().filter(|p| find_token(data, p)).count();
    count >= 2
}

fn detect_credential_harvesting(data: &[u8]) -> bool {
    let credential_patterns: &[&[u8]] = &[
        b"type=\"password\"",
        b"type='password'",
        b"addEventListener('input'",
        b"addEventListener(\"input\"",
        b".value",
        b"clipboard",
    ];

    let count = credential_patterns
        .iter()
        .filter(|p| find_token(data, p))
        .count();
    count >= 2
}

fn detect_encoded_transmission(data: &[u8]) -> bool {
    let encoding_funcs: &[&[u8]] = &[b"btoa(", b"encodeURIComponent(", b"encodeURI("];
    let has_encoding = encoding_funcs.iter().any(|p| find_token(data, p));

    let transmission_funcs: &[&[u8]] = &[
        b"submitForm",
        b"app.launchURL",
        b"this.submitForm",
        b"mailMsg",
    ];
    let has_transmission = transmission_funcs.iter().any(|p| find_token(data, p));

    has_encoding && has_transmission
}

// ============================================================================
// Advanced Obfuscation
// ============================================================================

fn detect_control_flow_flattening(data: &[u8]) -> bool {
    let switch_count = data.windows(6).filter(|w| w == b"switch").count();

    // Large switch statements (potential dispatcher)
    if switch_count >= 3 {
        return true;
    }

    // Check for while(true) with switch (common flattening pattern)
    let has_infinite_loop = find_token(data, b"while(true)") || find_token(data, b"while(1)");
    has_infinite_loop && switch_count >= 1
}

fn detect_opaque_predicates(data: &[u8]) -> bool {
    // Look for complex mathematical expressions in conditionals
    let math_funcs: &[&[u8]] = &[
        b"Math.abs(",
        b"Math.floor(",
        b"Math.ceil(",
        b"Math.random()",
    ];
    let has_math = math_funcs.iter().filter(|p| find_token(data, p)).count() >= 2;

    let if_count = data.windows(2).filter(|w| w == b"if").count();

    // Many conditionals with mathematical operations
    has_math && if_count >= 5
}

fn detect_identifier_mangling(data: &[u8]) -> bool {
    let s = String::from_utf8_lossy(data);

    // Count identifiers that look obfuscated (single letters or hex-like)
    let mut obfuscated_count = 0;
    let mut total_identifiers = 0;

    for word in s.split(|c: char| !c.is_alphanumeric() && c != '_') {
        if !word.is_empty()
            && word
                .chars()
                .next()
                .is_some_and(|c| c.is_alphabetic() || c == '_')
        {
            total_identifiers += 1;

            // Single letter variables (excluding common loop vars) or
            // hex-like identifiers (e.g., _0x1234, var_a1b2c3)
            if (word.len() == 1 && !matches!(word, "i" | "j" | "k" | "x" | "y" | "z"))
                || word.contains("0x")
                || (word.len() > 5
                    && word.chars().filter(|c| c.is_numeric()).count() > word.len() / 2)
            {
                obfuscated_count += 1;
            }
        }
    }

    if total_identifiers > 10 {
        let ratio = obfuscated_count as f64 / total_identifiers as f64;
        ratio > 0.5 // More than 50% obfuscated identifiers
    } else {
        false
    }
}

// ============================================================================
// PDF-Specific Exploitation
// ============================================================================

fn detect_font_exploitation(data: &[u8]) -> bool {
    let font_patterns: &[&[u8]] = &[
        b"FontMatrix",
        b"CIDFont",
        b"Type1Font",
        b"TrueType",
        b"FontFile",
        b"FontDescriptor",
    ];

    let count = font_patterns.iter().filter(|p| find_token(data, p)).count();

    // Multiple font-related operations suggest exploitation
    count >= 2
}

fn detect_annotation_abuse(data: &[u8]) -> bool {
    let annotation_patterns: &[&[u8]] = &[
        b"getAnnots",
        b"syncAnnotScan",
        b".subject",
        b"addAnnot",
        b"removeAnnot",
    ];

    let count = annotation_patterns
        .iter()
        .filter(|p| find_token(data, p))
        .count();

    // Two or more annotation operations
    count >= 2
}

fn detect_xfa_exploitation(data: &[u8]) -> bool {
    let xfa_patterns: &[&[u8]] = &[
        b"XFA",
        b"xfa.form",
        b"xfa.dataset",
        b"xfa.template",
        b"xfa.host",
    ];

    xfa_patterns.iter().any(|p| find_token(data, p))
}

// ============================================================================
// C2 Patterns
// ============================================================================

fn detect_dga_pattern(data: &[u8]) -> bool {
    let has_random = find_token(data, b"Math.random()");
    let has_time = find_token(data, b"getTime()") || find_token(data, b"getDate()");
    let has_string_building =
        find_token(data, b"String.fromCharCode") || find_token(data, b".concat(");
    let has_url = find_token(data, b"http://") || find_token(data, b"https://");

    // Algorithmic domain construction
    (has_random || has_time) && has_string_building && has_url
}

fn detect_beaconing_pattern(data: &[u8]) -> bool {
    let network_calls: &[&[u8]] = &[b"launchURL", b"submitForm", b"mailMsg", b"getURL"];

    let network_count = network_calls.iter().filter(|p| find_token(data, p)).count();

    // Multiple network operations suggest beaconing
    network_count >= 3
}

// ============================================================================
// Cryptomining
// ============================================================================

fn detect_cryptomining_library(data: &[u8]) -> bool {
    let mining_signatures: &[&[u8]] = &[
        b"coinhive",
        b"CoinHive",
        b"cryptonight",
        b"crypto-loot",
        b"CryptoLoot",
        b"stratum+tcp",
        b"xmr-stak",
        b"monero",
    ];

    mining_signatures.iter().any(|p| find_token(data, p))
}

fn detect_wasm_mining(data: &[u8]) -> bool {
    let wasm_patterns: &[&[u8]] = &[
        b"WebAssembly.instantiate",
        b"WebAssembly.Module",
        b"new Worker(",
        b"SharedArrayBuffer",
        b"Atomics.",
    ];

    let count = wasm_patterns.iter().filter(|p| find_token(data, p)).count();

    // WebAssembly with workers suggests mining
    count >= 2
}

// ============================================================================
// Unicode Abuse
// ============================================================================

fn detect_unicode_obfuscation(data: &[u8]) -> bool {
    // Check for non-ASCII characters
    let non_ascii_count = data.iter().filter(|&&b| b > 127).count();

    if data.is_empty() {
        return false;
    }

    let non_ascii_ratio = non_ascii_count as f64 / data.len() as f64;

    // More than 10% non-ASCII characters
    non_ascii_ratio > 0.1
}

fn detect_rtl_override(data: &[u8]) -> bool {
    // Check for RTL override character (U+202E)
    data.windows(3).any(|w| w == [0xE2, 0x80, 0xAE])
}

fn detect_homoglyph_attack(data: &[u8]) -> bool {
    let s = String::from_utf8_lossy(data);

    // Check for Cyrillic or Greek characters that look like Latin
    let homoglyph_ranges = [
        ('\u{0400}', '\u{04FF}'), // Cyrillic
        ('\u{0370}', '\u{03FF}'), // Greek
    ];

    for ch in s.chars() {
        for (start, end) in &homoglyph_ranges {
            if ch >= *start && ch <= *end {
                return true;
            }
        }
    }

    false
}

// ============================================================================
// Additional Detection Functions
// ============================================================================

fn detect_custom_decoder(data: &[u8]) -> bool {
    // Custom Base64 decoder
    let has_custom_base64 = find_token(
        data,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    );

    // Custom character code decoder
    let has_custom_decoder = find_token(data, b"function")
        && find_token(data, b"fromCharCode")
        && find_token(data, b"split(");

    // Hex decoder patterns
    let has_hex_decoder =
        find_token(data, b"parseInt") && (find_token(data, b", 16") || find_token(data, b",16"));

    has_custom_base64 || has_custom_decoder || has_hex_decoder
}

fn detect_function_introspection(data: &[u8]) -> bool {
    let introspection_patterns: &[&[u8]] = &[
        b"arguments.callee",
        b"Function.toString()",
        b".toString.call(",
        b"constructor.toString()",
    ];

    introspection_patterns.iter().any(|p| find_token(data, p))
}

fn detect_excessive_string_allocation(data: &[u8]) -> bool {
    // Look for large string allocations or repeated concatenations
    let string_patterns: &[&[u8]] = &[
        b"new Array(",
        b".substring(",
        b".concat(",
        b"while(",
        b"for(",
    ];

    let has_loops = find_token(data, b"while(") || find_token(data, b"for(");
    let has_string_ops = string_patterns
        .iter()
        .filter(|p| find_token(data, p))
        .count()
        >= 3;

    // Large string constants
    let s = String::from_utf8_lossy(data);
    let has_large_strings = s.contains("\"") && s.match_indices('"').count() >= 10;

    (has_loops && has_string_ops) || has_large_strings
}

// ============================================================================
// Advanced Detection Functions - Phase 2
// ============================================================================

// Resource Exhaustion & DoS
// ============================================================================

fn detect_infinite_loop_risk(data: &[u8]) -> bool {
    let infinite_patterns: &[&[u8]] = &[
        b"while(true)",
        b"while(1)",
        b"while (true)",
        b"while (1)",
        b"for(;;)",
        b"for (;;)",
    ];

    infinite_patterns.iter().any(|p| find_token(data, p))
}

fn detect_memory_bomb(data: &[u8]) -> bool {
    let s = String::from_utf8_lossy(data);

    // Large array allocation
    if find_token(data, b"new Array(") {
        // Look for large numbers
        if s.contains("new Array(") && (s.contains("999999") || s.contains("9999999")) {
            return true;
        }
    }

    // Array fill in loop
    let has_array_push_loop =
        find_token(data, b".push(") && (find_token(data, b"while(") || find_token(data, b"for("));

    // Object expansion
    let has_object_expansion =
        find_token(data, b"obj[") && find_token(data, b"for(") && find_token(data, b"new Array(");

    has_array_push_loop || has_object_expansion
}

fn detect_computational_bomb(data: &[u8]) -> bool {
    let s = String::from_utf8_lossy(data);

    // Count nested loops (3+ levels is suspicious)
    let for_count = s.matches("for(").count() + s.matches("for (").count();
    let while_count = s.matches("while(").count() + s.matches("while (").count();
    let total_loops = for_count + while_count;

    if total_loops >= 3 {
        return true;
    }

    // Check for large loop bounds product
    if s.contains("for") && (s.contains("10000") || s.contains("100000")) {
        return true;
    }

    false
}

fn detect_recursive_bomb(data: &[u8]) -> bool {
    let s = String::from_utf8_lossy(data);

    // Find function definitions
    for func_match in s.match_indices("function") {
        let rest = &s[func_match.0..];
        if let Some(name_start) = rest.find(|c: char| c.is_alphabetic()) {
            let name_rest = &rest[name_start..];
            if let Some(name_end) = name_rest.find(|c: char| !c.is_alphanumeric() && c != '_') {
                let func_name = &name_rest[..name_end];
                if !func_name.is_empty() {
                    // Check if function calls itself multiple times
                    let call_count = rest.matches(func_name).count();
                    if call_count > 3 {
                        return true;
                    }
                }
            }
        }
    }

    false
}

fn detect_redos_pattern(data: &[u8]) -> bool {
    // ReDoS patterns - nested quantifiers
    let redos_patterns: &[&[u8]] = &[b"(a+)+", b"(a*)*", b"(a|a)*", b"(.*)*", b"(.+)+"];

    redos_patterns.iter().any(|p| find_token(data, p))
}

// Code Injection & DOM Manipulation
// ============================================================================

fn detect_dom_xss_sink(data: &[u8]) -> bool {
    let xss_sinks: &[&[u8]] = &[
        b"document.write(",
        b"document.writeln(",
        b".innerHTML =",
        b".outerHTML =",
        b"insertAdjacentHTML(",
    ];

    xss_sinks.iter().any(|p| find_token(data, p))
}

fn detect_innerhtml_injection(data: &[u8]) -> bool {
    find_token(data, b".innerHTML")
        && (find_token(data, b"<script")
            || find_token(data, b"<iframe")
            || find_token(data, b"onerror"))
}

fn detect_prototype_pollution_gadget(data: &[u8]) -> bool {
    let pollution_patterns: &[&[u8]] = &[
        b"__proto__",
        b"constructor.prototype",
        b"Object.prototype",
        b"Array.prototype",
    ];

    // Look for assignment to prototype properties
    let has_proto = pollution_patterns.iter().any(|p| find_token(data, p));
    let has_assignment = find_token(data, b" = ") || find_token(data, b"]=");

    has_proto && has_assignment
}

fn detect_script_injection(data: &[u8]) -> bool {
    let injection_patterns: &[&[u8]] = &[
        b"createElement('script')",
        b"createElement(\"script\")",
        b"document.createElement('script')",
        b".appendChild(",
    ];

    let has_create_script = injection_patterns[0..2].iter().any(|p| find_token(data, p));
    let has_append = find_token(data, b".appendChild(");

    has_create_script && has_append
}

fn detect_eval_sink(data: &[u8]) -> bool {
    let eval_sinks: &[&[u8]] = &[b"eval(", b"Function(", b"setTimeout(", b"setInterval("];

    // Check if eval/Function used with variables
    let s = String::from_utf8_lossy(data);
    for sink in eval_sinks {
        if find_token(data, sink) {
            let sink_str = std::str::from_utf8(sink).unwrap_or("");
            // Check if followed by variable (not string literal)
            if let Some(pos) = s.find(sink_str) {
                let after = &s[pos + sink_str.len()..];
                if let Some(first_char) = after.chars().next() {
                    if first_char != '"' && first_char != '\'' {
                        return true;
                    }
                }
            }
        }
    }

    false
}

// Exploit Kit Signatures
// ============================================================================

fn detect_angler_ek(data: &[u8]) -> bool {
    // Angler EK patterns
    let angler_patterns: &[&[u8]] = &[
        b"window.external.Flash",
        b"unescape('%u9090%u9090')",
        b"Flash.ocx",
    ];

    angler_patterns
        .iter()
        .filter(|p| find_token(data, p))
        .count()
        >= 2
}

fn detect_magnitude_ek(data: &[u8]) -> bool {
    // Magnitude EK uses RC4
    let has_rc4 = find_token(data, b"rc4") || find_token(data, b"RC4");
    let has_decrypt = find_token(data, b"decrypt") || find_token(data, b"decode");
    let has_key = find_token(data, b"key");

    (has_rc4 || (has_decrypt && has_key)) && find_token(data, b"for(")
}

fn detect_rig_ek(data: &[u8]) -> bool {
    // RIG EK multi-stage loading
    let has_flash_check = find_token(data, b"Shockwave Flash") || find_token(data, b"Flash Player");
    let has_java_check = find_token(data, b"javaEnabled()") || find_token(data, b"Java Plug-in");
    let has_conditional = find_token(data, b"if(") && find_token(data, b"else");

    (has_flash_check || has_java_check) && has_conditional
}

fn detect_exploit_kit_pattern(data: &[u8]) -> bool {
    // Generic EK patterns
    let ek_indicators: &[&[u8]] = &[b"exploit", b"shellcode", b"payload", b"CVE-"];

    let indicator_count = ek_indicators.iter().filter(|p| find_token(data, p)).count();

    indicator_count >= 2
        || detect_angler_ek(data)
        || detect_magnitude_ek(data)
        || detect_rig_ek(data)
}

// Ransomware Patterns
// ============================================================================

fn detect_file_enumeration(data: &[u8]) -> bool {
    let file_api_patterns: &[&[u8]] = &[
        b"readdir",
        b"fs.readdir",
        b"opendir",
        b"listFiles",
        b"getFiles",
    ];

    let has_file_api = file_api_patterns.iter().any(|p| find_token(data, p));
    let has_iteration = find_token(data, b"forEach") || find_token(data, b"for(");

    has_file_api && has_iteration
}

fn detect_bulk_encryption(data: &[u8]) -> bool {
    let crypto_patterns: &[&[u8]] = &[
        b"encrypt(",
        b"crypto.encrypt",
        b"subtle.encrypt",
        b"AES",
        b"RSA",
    ];

    let has_crypto = crypto_patterns.iter().any(|p| find_token(data, p));
    let has_loop =
        find_token(data, b"forEach") || find_token(data, b"for(") || find_token(data, b"while(");
    let has_files = find_token(data, b"file") || find_token(data, b"File");

    has_crypto && has_loop && has_files
}

fn detect_ransom_note(data: &[u8]) -> bool {
    let s = String::from_utf8_lossy(data).to_lowercase();

    let ransom_keywords = [
        "encrypted",
        "ransom",
        "bitcoin",
        "btc",
        "payment",
        "decrypt",
        "locked",
        "restore",
    ];

    ransom_keywords
        .iter()
        .filter(|&keyword| s.contains(keyword))
        .count()
        >= 3
}

fn detect_bitcoin_address(data: &[u8]) -> bool {
    let s = String::from_utf8_lossy(data);

    // Bitcoin address regex pattern (simplified)
    // Starts with 1, 3, or bc1, length 26-90
    for word in s.split_whitespace() {
        if word.len() >= 26
            && word.len() <= 90
            && (word.starts_with('1') || word.starts_with('3') || word.starts_with("bc1"))
        {
            // Check if alphanumeric (excluding 0, O, I, l)
            if word
                .chars()
                .all(|c| c.is_ascii_alphanumeric() && c != '0' && c != 'O' && c != 'I' && c != 'l')
            {
                return true;
            }
        }
    }

    // Monero address (starts with 4)
    for word in s.split_whitespace() {
        if word.len() == 95 && word.starts_with('4') {
            return true;
        }
    }

    false
}

// Advanced Shellcode Techniques
// ============================================================================

fn detect_jit_spray(data: &[u8]) -> bool {
    let s = String::from_utf8_lossy(data);

    // Count hex constants
    let hex_constant_count = s.matches("0x").count();

    // JIT spray involves many hex constants in functions
    if hex_constant_count >= 10 {
        return true;
    }

    // Function generation in loops

    (find_token(data, b"eval(") || find_token(data, b"Function(")) && find_token(data, b"for(")
}

fn detect_unicode_shellcode(data: &[u8]) -> bool {
    let s = String::from_utf8_lossy(data);

    // Count Unicode escapes
    let unicode_escape_count = s.matches("\\u").count();

    if unicode_escape_count >= 20 {
        // Check if they decode to potential opcodes
        if find_token(data, b"unescape") {
            return true;
        }
    }

    false
}

fn detect_constant_spray(data: &[u8]) -> bool {
    let s = String::from_utf8_lossy(data);

    // Many large numeric constants
    let mut constant_count = 0;
    for word in s.split_whitespace() {
        if word.starts_with("0x") && word.len() > 6 {
            constant_count += 1;
        }
    }

    constant_count >= 15
}

// Advanced Evasion & Environment Detection
// ============================================================================

fn detect_fingerprint_check(data: &[u8]) -> bool {
    let fingerprint_patterns: &[&[u8]] = &[
        b"navigator.userAgent",
        b"navigator.language",
        b"navigator.platform",
        b"screen.width",
        b"screen.height",
        b"navigator.plugins",
    ];

    let fp_count = fingerprint_patterns
        .iter()
        .filter(|p| find_token(data, p))
        .count();
    let has_conditional = find_token(data, b"if(");

    fp_count >= 2 && has_conditional
}

fn detect_timing_evasion(data: &[u8]) -> bool {
    let timing_patterns: &[&[u8]] = &[
        b"performance.now()",
        b"Date.now()",
        b"new Date().getTime()",
        b"getTime()",
    ];

    let has_timing = timing_patterns.iter().any(|p| find_token(data, p));
    let has_comparison =
        find_token(data, b"if(") && (find_token(data, b" < ") || find_token(data, b" > "));

    has_timing && has_comparison
}

fn detect_interaction_required(data: &[u8]) -> bool {
    let interaction_patterns: &[&[u8]] = &[
        b"onclick",
        b"onmousemove",
        b"onkeypress",
        b"addEventListener",
    ];

    interaction_patterns.iter().any(|p| find_token(data, p))
}

fn detect_targeted_execution(data: &[u8]) -> bool {
    let targeting_patterns: &[&[u8]] = &[
        b"getTimezoneOffset()",
        b"navigator.language",
        b"toLocaleDateString()",
    ];

    let has_targeting = targeting_patterns.iter().any(|p| find_token(data, p));
    let has_conditional = find_token(data, b"if(") && find_token(data, b"==");

    has_targeting && has_conditional
}

// Persistence & State Manipulation
// ============================================================================

fn detect_localstorage_write(data: &[u8]) -> bool {
    find_token(data, b"localStorage.setItem") || find_token(data, b"localStorage[")
}

fn detect_cookie_manipulation(data: &[u8]) -> bool {
    find_token(data, b"document.cookie") && find_token(data, b" = ")
}

fn detect_global_pollution(data: &[u8]) -> bool {
    let global_patterns: &[&[u8]] = &[b"window.", b"globalThis.", b"global."];

    let has_global = global_patterns.iter().any(|p| find_token(data, p));
    let has_assignment = find_token(data, b" = ");

    has_global && has_assignment
}

fn detect_history_manipulation(data: &[u8]) -> bool {
    let history_patterns: &[&[u8]] = &[
        b"history.pushState",
        b"history.replaceState",
        b"window.location =",
        b"location.replace(",
    ];

    history_patterns.iter().any(|p| find_token(data, p))
}

// Supply Chain & Dependency Attacks
// ============================================================================

fn detect_dynamic_import(data: &[u8]) -> bool {
    let import_patterns: &[&[u8]] = &[b"import(", b"require(", b"importScripts("];

    import_patterns.iter().any(|p| find_token(data, p))
}

fn detect_remote_script_load(data: &[u8]) -> bool {
    let has_script_create = find_token(data, b"createElement('script')")
        || find_token(data, b"createElement(\"script\")");
    let has_src = find_token(data, b".src = ");
    let has_http = find_token(data, b"http://") || find_token(data, b"https://");

    has_script_create && has_src && has_http
}

fn detect_suspicious_package(data: &[u8]) -> bool {
    let s = String::from_utf8_lossy(data);

    // Very high version numbers (dependency confusion)
    if s.contains("999.999") || s.contains("9999.") {
        return true;
    }

    // Private scope indicators
    if s.contains("@internal") || s.contains("@private") || s.contains("@company") {
        return true;
    }

    false
}

// Network Abuse & Scanning
// ============================================================================

fn detect_port_scan(data: &[u8]) -> bool {
    let has_loop = find_token(data, b"for(") || find_token(data, b"while(");
    let has_network = find_token(data, b"new Image()")
        || find_token(data, b"fetch(")
        || find_token(data, b"XMLHttpRequest")
        || find_token(data, b"WebSocket");
    let has_port = find_token(data, b":8") || find_token(data, b":80") || find_token(data, b"port");

    has_loop && has_network && has_port
}

fn detect_internal_probe(data: &[u8]) -> bool {
    let internal_patterns: &[&[u8]] =
        &[b"192.168.", b"10.", b"172.16.", b"localhost", b"127.0.0.1"];

    internal_patterns.iter().any(|p| find_token(data, p))
}

fn detect_dns_rebinding(data: &[u8]) -> bool {
    let has_fetch = find_token(data, b"fetch(") || find_token(data, b"XMLHttpRequest");
    let has_retry = find_token(data, b"setTimeout") && has_fetch;
    let has_conditional = find_token(data, b"if(") && find_token(data, b".then(");

    has_retry && has_conditional
}

// Steganography & Covert Channels
// ============================================================================

fn detect_comment_payload(data: &[u8]) -> bool {
    let s = String::from_utf8_lossy(data);

    // Look for base64-like content in comments
    if let Some(comment_start) = s.find("/*") {
        if let Some(comment_end) = s[comment_start..].find("*/") {
            let comment = &s[comment_start..comment_start + comment_end];
            if comment.len() > 100 && comment.matches(|c: char| c.is_alphanumeric()).count() > 80 {
                return true;
            }
        }
    }

    // Extract from comments
    find_token(data, b".toString()") && find_token(data, b"/*") && find_token(data, b"*/")
}

fn detect_zero_width_chars(data: &[u8]) -> bool {
    // Zero-width characters: U+200B, U+200C, U+200D, U+FEFF
    let zero_width_patterns: &[&[u8]] = &[
        &[0xE2, 0x80, 0x8B], // U+200B
        &[0xE2, 0x80, 0x8C], // U+200C
        &[0xE2, 0x80, 0x8D], // U+200D
        &[0xEF, 0xBB, 0xBF], // U+FEFF
    ];

    for pattern in zero_width_patterns {
        if data.windows(pattern.len()).any(|w| w == *pattern) {
            return true;
        }
    }

    false
}

fn detect_canvas_decode(data: &[u8]) -> bool {
    let canvas_patterns: &[&[u8]] = &[
        b"getContext('2d')",
        b"getContext(\"2d\")",
        b"getImageData(",
        b".data[",
    ];

    let has_canvas = canvas_patterns[0..2].iter().any(|p| find_token(data, p));
    let has_image_data = find_token(data, b"getImageData(");
    let has_pixel_access = find_token(data, b".data[");

    has_canvas && has_image_data && has_pixel_access
}

// Polyglot & Multi-Format Attacks
// ============================================================================

fn detect_polyglot_pdf(data: &[u8]) -> bool {
    let pdf_patterns: &[&[u8]] = &[b"%PDF-", b"endobj", b"stream", b"endstream"];

    pdf_patterns.iter().filter(|p| find_token(data, p)).count() >= 2
}

fn detect_polyglot_html(data: &[u8]) -> bool {
    let html_patterns: &[&[u8]] = &[b"<!--", b"-->", b"<script", b"<html", b"<body"];

    html_patterns.iter().filter(|p| find_token(data, p)).count() >= 2
}

// Browser Fingerprinting & Tracking
// ============================================================================

fn detect_canvas_fingerprint(data: &[u8]) -> bool {
    let has_canvas =
        find_token(data, b"getContext('2d')") || find_token(data, b"getContext(\"2d\")");
    let has_text = find_token(data, b"fillText(") || find_token(data, b"strokeText(");
    let has_export = find_token(data, b"toDataURL()");

    has_canvas && has_text && has_export
}

fn detect_webgl_fingerprint(data: &[u8]) -> bool {
    let has_webgl = find_token(data, b"getContext('webgl')")
        || find_token(data, b"getContext(\"webgl\")")
        || find_token(data, b"getContext('experimental-webgl')");
    let has_param = find_token(data, b"getParameter(");

    has_webgl && has_param
}

fn detect_font_enumeration(data: &[u8]) -> bool {
    let has_font_test = find_token(data, b"offsetWidth") || find_token(data, b"offsetHeight");
    let has_fonts = find_token(data, b"Arial") && find_token(data, b"Verdana");
    let has_loop = find_token(data, b"for(") || find_token(data, b"forEach");

    has_font_test && has_fonts && has_loop
}
