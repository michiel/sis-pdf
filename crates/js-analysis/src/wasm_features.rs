#[derive(Debug, Clone, Default)]
pub struct WasmStaticFeatures {
    pub preamble_detected: bool,
    pub section_count: usize,
    pub memory_sections: usize,
    pub suspicious_imports: Vec<String>,
    pub parse_skipped: bool,
}

const MAX_WASM_BLOB_BYTES: usize = 1024 * 1024;
const MAX_WASM_SECTIONS: usize = 32;

pub fn extract_wasm_static_features(bytes: &[u8]) -> WasmStaticFeatures {
    if bytes.len() > MAX_WASM_BLOB_BYTES {
        return WasmStaticFeatures { parse_skipped: true, ..WasmStaticFeatures::default() };
    }
    if !bytes.starts_with(b"\0asm") {
        return WasmStaticFeatures::default();
    }
    let mut features =
        WasmStaticFeatures { preamble_detected: true, ..WasmStaticFeatures::default() };
    let mut index = 8usize;
    let mut sections_seen = 0usize;

    while index < bytes.len() && sections_seen < MAX_WASM_SECTIONS {
        let Some(section_id) = bytes.get(index).copied() else {
            break;
        };
        index += 1;
        let Some((length, next)) = read_leb_u32(bytes, index) else {
            break;
        };
        index = next;
        let end = index.saturating_add(length as usize);
        if end > bytes.len() {
            break;
        }
        let section = &bytes[index..end];
        sections_seen += 1;
        features.section_count = sections_seen;
        if section_id == 5 {
            features.memory_sections += 1;
        }
        if section_id == 2 {
            collect_suspicious_imports(section, &mut features.suspicious_imports);
        }
        index = end;
    }

    features
}

fn read_leb_u32(bytes: &[u8], mut index: usize) -> Option<(u32, usize)> {
    let mut result = 0u32;
    let mut shift = 0u32;
    for _ in 0..5 {
        let byte = *bytes.get(index)?;
        index += 1;
        result |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            return Some((result, index));
        }
        shift += 7;
    }
    None
}

fn collect_suspicious_imports(section: &[u8], out: &mut Vec<String>) {
    let needles = ["env.eval", "env.fetch", "wasi_snapshot_preview1", "emscripten"];
    let text = String::from_utf8_lossy(section).to_ascii_lowercase();
    for needle in needles {
        if text.contains(&needle.to_ascii_lowercase()) && !out.iter().any(|value| value == needle) {
            out.push(needle.to_string());
        }
    }
    out.sort();
    out.dedup();
}
