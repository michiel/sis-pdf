use blake3::Hasher;

use crate::config::NormalizeConfig;

pub fn normalize_ir_texts(
    texts: &[String],
    cfg: &NormalizeConfig,
    max_len: Option<usize>,
) -> Vec<String> {
    texts.iter().map(|t| normalize_ir_text(t, cfg, max_len)).collect()
}

fn normalize_ir_text(text: &str, cfg: &NormalizeConfig, max_len: Option<usize>) -> String {
    let mut out_lines = Vec::new();
    for line in text.split(" ; ") {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (path, value_type, value) = parse_ir_line(line);
        let norm_value = normalize_value(value_type, value, cfg);
        out_lines.push(format!("path={}\tvalue_type={}\tvalue={}", path, value_type, norm_value));
    }
    let mut out = out_lines.join(" ; ");
    if let Some(limit) = max_len {
        if out.len() > limit {
            out.truncate(limit);
        }
    }
    out
}

fn parse_ir_line(line: &str) -> (&str, &str, &str) {
    if line.contains("path=") && line.contains("value_type=") {
        let mut path = "";
        let mut value_type = "";
        let mut value = "";
        for part in line.split('\t') {
            let mut kv = part.splitn(2, '=');
            let key = kv.next().unwrap_or("");
            let val = kv.next().unwrap_or("");
            match key {
                "path" => path = val,
                "value_type" => value_type = val,
                "value" => value = val,
                _ => {}
            }
        }
        return (path, value_type, value);
    }
    let mut parts = line.splitn(3, ' ');
    let path = parts.next().unwrap_or("");
    let value_type = parts.next().unwrap_or("");
    let value = parts.next().unwrap_or("");
    (path, value_type, value)
}

fn normalize_value(value_type: &str, value: &str, cfg: &NormalizeConfig) -> String {
    if cfg.preserve_keywords.iter().any(|k| k == value) {
        return value.to_string();
    }
    match value_type {
        "ref" => {
            if cfg.collapse_obj_refs {
                "ref:OBJ".into()
            } else {
                value.to_string()
            }
        }
        "num" => {
            if cfg.normalize_numbers {
                "num".into()
            } else {
                value.to_string()
            }
        }
        "str" => {
            if cfg.normalize_strings {
                if cfg.hash_strings {
                    let mut h = Hasher::new();
                    h.update(value.as_bytes());
                    let hash = h.finalize();
                    format!("str:HASH_{}", &hash.to_hex()[..8])
                } else {
                    "str".into()
                }
            } else {
                value.to_string()
            }
        }
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> NormalizeConfig {
        NormalizeConfig {
            normalize_numbers: false,
            normalize_strings: true,
            collapse_obj_refs: false,
            preserve_keywords: vec![],
            hash_strings: false,
            include_deviation_markers: false,
        }
    }

    #[test]
    fn normalize_structured_line_format() {
        let input = "path=/OpenAction\tvalue_type=str\tvalue=alert(1)\tobj=1 0\tline_index=3";
        let out = normalize_ir_texts(&[input.to_string()], &cfg(), None);
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("path=/OpenAction"));
        assert!(out[0].contains("value_type=str"));
        assert!(out[0].contains("value=str"));
    }

    #[test]
    fn normalize_legacy_line_format() {
        let input = "/OpenAction str alert(1)";
        let out = normalize_ir_texts(&[input.to_string()], &cfg(), None);
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("path=/OpenAction"));
        assert!(out[0].contains("value_type=str"));
        assert!(out[0].contains("value=str"));
    }
}
