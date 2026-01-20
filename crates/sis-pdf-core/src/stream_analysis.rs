use blake3::Hasher;

#[derive(Debug, Clone)]
pub struct StreamAnalysisResult {
    pub magic_type: String,
    pub entropy: f64,
    pub blake3: String,
    pub size_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct StreamLimits {
    pub max_bytes: usize,
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024,
        }
    }
}

pub fn analyse_stream(bytes: &[u8], limits: &StreamLimits) -> StreamAnalysisResult {
    let size_bytes = bytes.len();
    let sample = if bytes.len() > limits.max_bytes {
        &bytes[..limits.max_bytes]
    } else {
        bytes
    };
    let magic_type = magic_type(sample);
    let entropy = shannon_entropy(sample);
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    let blake3 = hasher.finalize().to_hex().to_string();
    StreamAnalysisResult {
        magic_type,
        entropy,
        blake3,
        size_bytes,
    }
}

fn magic_type(data: &[u8]) -> String {
    if data.starts_with(b"MZ") {
        "pe".into()
    } else if data.starts_with(b"%PDF") {
        "pdf".into()
    } else if data.starts_with(b"PK\x03\x04") {
        "zip".into()
    } else if data.starts_with(b"\x7fELF") {
        "elf".into()
    } else if is_macho(data) {
        "macho".into()
    } else if data.starts_with(b"#!") {
        "script".into()
    } else {
        "unknown".into()
    }
}

fn is_macho(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    matches!(
        data[..4],
        [0xfe, 0xed, 0xfa, 0xce]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xce, 0xfa, 0xed, 0xfe]
            | [0xcf, 0xfa, 0xed, 0xfe]
    )
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::{analyse_stream, shannon_entropy, StreamLimits};

    #[test]
    fn entropy_is_zero_for_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn analyse_stream_sets_magic_and_hash() {
        let data = b"%PDF-1.7";
        let res = analyse_stream(data, &StreamLimits::default());
        assert_eq!(res.magic_type, "pdf");
        assert_eq!(res.size_bytes, data.len());
        assert_eq!(res.blake3.len(), 64);
    }
}
