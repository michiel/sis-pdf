use std::collections::HashMap;

pub fn extract_js_signals(data: &[u8]) -> HashMap<String, String> {
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
        "js.contains_unescape".into(),
        bool_str(find_token(data, b"unescape")),
    );
    out.insert(
        "js.contains_fromcharcode".into(),
        bool_str(find_token(data, b"fromCharCode")),
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
    out.insert("js.ast_parsed".into(), "false".into());
    #[cfg(feature = "js-ast")]
    {
        if let Ok(src) = std::str::from_utf8(data) {
            let mut parser = boa_parser::Parser::new(src);
            if parser.parse().is_ok() {
                out.insert("js.ast_parsed".into(), "true".into());
            }
        }
    }

    let obf = is_obfuscationish(&out);
    out.insert("js.obfuscation_suspected".into(), bool_str(obf));
    out
}

fn bool_str(v: bool) -> String {
    if v { "true".into() } else { "false".into() }
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut ent = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        ent -= p * p.log2();
    }
    ent
}

fn contains_hex_escape(data: &[u8]) -> bool {
    let mut i = 0;
    while i + 3 < data.len() {
        if data[i] == b'\\' && data[i + 1] == b'x' {
            if is_hex(data[i + 2]) && is_hex(data[i + 3]) {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn contains_unicode_escape(data: &[u8]) -> bool {
    let mut i = 0;
    while i + 5 < data.len() {
        if data[i] == b'\\' && (data[i + 1] == b'u' || data[i + 1] == b'U') {
            if is_hex(data[i + 2])
                && is_hex(data[i + 3])
                && is_hex(data[i + 4])
                && is_hex(data[i + 5])
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn is_hex(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F')
}

fn longest_token_run(data: &[u8]) -> usize {
    let mut best = 0usize;
    let mut cur = 0usize;
    for &b in data {
        if is_token_char(b) {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

fn is_token_char(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'$')
}

fn count_base64_like_runs(data: &[u8], min_len: usize) -> usize {
    let mut runs = 0usize;
    let mut cur = 0usize;
    for &b in data {
        if is_b64_char(b) {
            cur += 1;
        } else {
            if cur >= min_len {
                runs += 1;
            }
            cur = 0;
        }
    }
    if cur >= min_len {
        runs += 1;
    }
    runs
}

fn is_b64_char(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'+' | b'/' | b'=')
}

fn find_token(data: &[u8], token: &[u8]) -> bool {
    data.windows(token.len()).any(|w| w == token)
}

fn is_obfuscationish(m: &HashMap<String, String>) -> bool {
    let ent: f64 = m.get("js.entropy").and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let has_b64 = m
        .get("js.has_base64_like")
        .map(|s| s == "true")
        .unwrap_or(false);
    let long_tok = m
        .get("js.long_token_run")
        .map(|s| s == "true")
        .unwrap_or(false);
    let hexesc = m
        .get("js.contains_hex_escapes")
        .map(|s| s == "true")
        .unwrap_or(false);
    let uniesc = m
        .get("js.contains_unicode_escapes")
        .map(|s| s == "true")
        .unwrap_or(false);
    let eval_ = m
        .get("js.contains_eval")
        .map(|s| s == "true")
        .unwrap_or(false);
    let unesc = m
        .get("js.contains_unescape")
        .map(|s| s == "true")
        .unwrap_or(false);
    let fcc = m
        .get("js.contains_fromcharcode")
        .map(|s| s == "true")
        .unwrap_or(false);

    (ent >= 5.2 && (has_b64 || long_tok || hexesc || uniesc)) || (eval_ && (unesc || fcc || has_b64))
}

fn byte_density(data: &[u8], needle: u8) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let count = data.iter().filter(|&&b| b == needle).count();
    count as f64 / data.len() as f64
}

fn contains_regex_packing(data: &[u8]) -> bool {
    let mut i = 0usize;
    while i < data.len() {
        if data[i] == b'/' {
            let start = i + 1;
            let mut j = start;
            while j < data.len() && data[j] != b'/' {
                j += 1;
            }
            if j < data.len() && j > start + 30 {
                return true;
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    false
}

fn contains_suspicious_api(data: &[u8]) -> bool {
    let apis: &[&[u8]] = &[
        b"app.launchURL",
        b"util.printf",
        b"this.getURL",
        b"submitForm",
        b"importDataObject",
        b"exportDataObject",
        b"app.mailMsg",
    ];
    apis.iter().any(|pat| find_token(data, pat))
}
