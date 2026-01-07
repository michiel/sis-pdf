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
    out.insert(
        "js.contains_hex_escapes".into(),
        bool_str(contains_hex_escape(data)),
    );
    out.insert(
        "js.contains_unicode_escapes".into(),
        bool_str(contains_unicode_escape(data)),
    );
    out.insert("js.contains_eval".into(), bool_str(find_token(data, b"eval")));
    out.insert(
        "js.dynamic_eval_construction".into(),
        bool_str(contains_dynamic_eval_construction(data))
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
        bool_str(contains_hex_fromcharcode_pattern(data))
    );
    out.insert(
        "js.environment_fingerprinting".into(),
        bool_str(contains_environment_fingerprinting(data))
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
        bool_str(detect_shellcode_pattern(data))
    );
    out.insert(
        "js.nop_sled".into(),
        bool_str(detect_nop_sled(data))
    );

    // Memory corruption primitives
    out.insert(
        "js.type_confusion_risk".into(),
        bool_str(detect_type_confusion(data))
    );
    out.insert(
        "js.integer_overflow_setup".into(),
        bool_str(detect_integer_overflow(data))
    );
    out.insert(
        "js.array_manipulation_exploit".into(),
        bool_str(detect_array_manipulation(data))
    );

    // Anti-analysis techniques
    out.insert(
        "js.debugger_detection".into(),
        bool_str(detect_debugger_detection(data))
    );
    out.insert(
        "js.sandbox_evasion".into(),
        bool_str(detect_sandbox_evasion(data))
    );
    out.insert(
        "js.exception_abuse".into(),
        bool_str(detect_exception_abuse(data))
    );
    out.insert(
        "js.time_bomb".into(),
        bool_str(detect_time_bomb(data))
    );

    // Data exfiltration
    out.insert(
        "js.form_manipulation".into(),
        bool_str(detect_form_manipulation(data))
    );
    out.insert(
        "js.credential_harvesting".into(),
        bool_str(detect_credential_harvesting(data))
    );
    out.insert(
        "js.encoded_transmission".into(),
        bool_str(detect_encoded_transmission(data))
    );

    // Advanced obfuscation
    out.insert(
        "js.control_flow_flattening".into(),
        bool_str(detect_control_flow_flattening(data))
    );
    out.insert(
        "js.opaque_predicates".into(),
        bool_str(detect_opaque_predicates(data))
    );
    out.insert(
        "js.identifier_mangling".into(),
        bool_str(detect_identifier_mangling(data))
    );

    // PDF exploitation
    out.insert(
        "js.font_exploitation".into(),
        bool_str(detect_font_exploitation(data))
    );
    out.insert(
        "js.annotation_abuse".into(),
        bool_str(detect_annotation_abuse(data))
    );
    out.insert(
        "js.xfa_exploitation".into(),
        bool_str(detect_xfa_exploitation(data))
    );

    // C2 patterns
    out.insert(
        "js.dga_pattern".into(),
        bool_str(detect_dga_pattern(data))
    );
    out.insert(
        "js.beaconing_pattern".into(),
        bool_str(detect_beaconing_pattern(data))
    );

    // Cryptomining
    out.insert(
        "js.cryptomining_library".into(),
        bool_str(detect_cryptomining_library(data))
    );
    out.insert(
        "js.wasm_mining".into(),
        bool_str(detect_wasm_mining(data))
    );

    // Unicode abuse
    out.insert(
        "js.unicode_obfuscation".into(),
        bool_str(detect_unicode_obfuscation(data))
    );
    out.insert(
        "js.rtl_override".into(),
        bool_str(detect_rtl_override(data))
    );
    out.insert(
        "js.homoglyph_attack".into(),
        bool_str(detect_homoglyph_attack(data))
    );

    // Custom decoders
    out.insert(
        "js.custom_decoder".into(),
        bool_str(detect_custom_decoder(data))
    );

    // Function introspection
    out.insert(
        "js.function_introspection".into(),
        bool_str(detect_function_introspection(data))
    );

    // Excessive string allocation
    out.insert(
        "js.excessive_string_allocation".into(),
        bool_str(detect_excessive_string_allocation(data))
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
    DecodedLayers { bytes: current, layers }
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
                    if let Ok(v) = u8::from_str_radix(&String::from_utf8_lossy(&data[i + 2..i + 4]), 16) {
                        out.push(v);
                        i += 4;
                        changed = true;
                        continue;
                    }
                }
                b'u' if i + 5 < data.len() => {
                    if let Ok(v) = u16::from_str_radix(&String::from_utf8_lossy(&data[i + 2..i + 6]), 16) {
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
    if changed { Some(out) } else { None }
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
    data.iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/' || *b == b'=' || b.is_ascii_whitespace())
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
    find_token(data, b"/" ) && find_token(data, b".replace")
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
    data.windows(token.len()).any(|w| w.eq_ignore_ascii_case(token))
}

fn contains_dynamic_eval_construction(data: &[u8]) -> bool {
    // Detect patterns like: 'ev' + 'a' + 'l' or variable[function_name]()
    let patterns: &[&[u8]] = &[
        // String concatenation to form "eval"
        b"'ev'",
        b"\"ev\"", 
        // Common eval construction fragments
        b"'a'",
        b"\"a\"",
        b"'l'",
        b"\"l\"",
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
    let has_conditional = find_token(data, b"if") && (find_token(data, b">") || find_token(data, b"==") || find_token(data, b"!="));
    
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
    if val { "true".into() } else { "false".into() }
}

fn is_obfuscationish(meta: &HashMap<String, String>) -> bool {
    let base64_like = meta.get("js.has_base64_like").map(|v| v == "true").unwrap_or(false);
    let has_eval = meta.get("js.contains_eval").map(|v| v == "true").unwrap_or(false);
    let has_fcc = meta.get("js.contains_fromcharcode").map(|v| v == "true").unwrap_or(false);
    let has_unescape = meta.get("js.contains_unescape").map(|v| v == "true").unwrap_or(false);
    let has_hex = meta.get("js.contains_hex_escapes").map(|v| v == "true").unwrap_or(false);
    let has_unicode = meta.get("js.contains_unicode_escapes").map(|v| v == "true").unwrap_or(false);
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
                            let value = self
                                .interner
                                .resolve_expect(sym)
                                .join(|s: &str| s.to_string(), String::from_utf16_lossy, true);
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
                let value = self
                    .interner
                    .resolve_expect(sym)
                    .join(|s: &str| s.to_string(), String::from_utf16_lossy, true);
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
        &[0x68],                          // push imm32
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
    let suspicious_array_ops: &[&[u8]] = &[
        b".length = 0x",
        b".length = -",
        b"arr.length",
    ];

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
    let bitwise_ops: &[&[u8]] = &[
        b">>>",
        b"<< ",
        b">> ",
        b"& 0x",
        b"| 0x",
    ];

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

    let count = debugger_patterns.iter().filter(|p| find_token(data, p)).count();
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

    let count = sandbox_checks.iter().filter(|p| find_token(data, p)).count();
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
    let time_apis: &[&[u8]] = &[b"Date()", b"getTime()", b"getHours()", b"getDate()", b"getMonth()"];
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

    let count = credential_patterns.iter().filter(|p| find_token(data, p)).count();
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
    let math_funcs: &[&[u8]] = &[b"Math.abs(", b"Math.floor(", b"Math.ceil(", b"Math.random()"];
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
        if word.len() > 0 && (word.chars().next().unwrap().is_alphabetic() || word.starts_with('_')) {
            total_identifiers += 1;

            // Single letter variables (excluding common ones like i, j, k)
            if word.len() == 1 && !matches!(word, "i" | "j" | "k" | "x" | "y" | "z") {
                obfuscated_count += 1;
            }
            // Hex-like identifiers (e.g., _0x1234, var_a1b2c3)
            else if word.contains("0x") || (word.len() > 5 && word.chars().filter(|c| c.is_numeric()).count() > word.len() / 2) {
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

    let count = annotation_patterns.iter().filter(|p| find_token(data, p)).count();

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
    let has_string_building = find_token(data, b"String.fromCharCode") || find_token(data, b".concat(");
    let has_url = find_token(data, b"http://") || find_token(data, b"https://");

    // Algorithmic domain construction
    (has_random || has_time) && has_string_building && has_url
}

fn detect_beaconing_pattern(data: &[u8]) -> bool {
    let network_calls: &[&[u8]] = &[
        b"launchURL",
        b"submitForm",
        b"mailMsg",
        b"getURL",
    ];

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
    data.windows(3).any(|w| w == &[0xE2, 0x80, 0xAE])
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
    let has_custom_base64 = find_token(data, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");

    // Custom character code decoder
    let has_custom_decoder = find_token(data, b"function") &&
                            find_token(data, b"fromCharCode") &&
                            find_token(data, b"split(");

    // Hex decoder patterns
    let has_hex_decoder = find_token(data, b"parseInt") &&
                         (find_token(data, b", 16") || find_token(data, b",16"));

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
    let has_string_ops = string_patterns.iter().filter(|p| find_token(data, p)).count() >= 3;

    // Large string constants
    let s = String::from_utf8_lossy(data);
    let has_large_strings = s.contains("\"") &&
                           s.match_indices('"').count() >= 10;

    (has_loops && has_string_ops) || has_large_strings
}
