use blake3::Hasher;

use crate::config::NormalizeConfig;

pub fn normalize_ir_texts(
    texts: &[String],
    cfg: &NormalizeConfig,
    max_len: Option<usize>,
) -> Vec<String> {
    texts
        .iter()
        .map(|t| normalize_ir_text(t, cfg, max_len))
        .collect()
}

fn normalize_ir_text(text: &str, cfg: &NormalizeConfig, max_len: Option<usize>) -> String {
    let mut out_lines = Vec::new();
    for line in text.split(" ; ") {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(3, ' ');
        let path = parts.next().unwrap_or("");
        let value_type = parts.next().unwrap_or("");
        let value = parts.next().unwrap_or("");
        let norm_value = normalize_value(value_type, value, cfg);
        out_lines.push(format!("{} {} {}", path, value_type, norm_value));
    }
    let mut out = out_lines.join(" ; ");
    if let Some(limit) = max_len {
        if out.len() > limit {
            out.truncate(limit);
        }
    }
    out
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
