use blake3::Hasher;
use std::time::Duration;

use crate::timeout::TimeoutChecker;

pub const STREAM_MIN_BYTES: usize = 1024;
pub const STREAM_HIGH_ENTROPY_THRESHOLD: f64 = 7.5;

#[derive(Debug, Clone)]
pub struct StreamAnalysisResult {
    pub magic_type: String,
    pub entropy: f64,
    pub sample_bytes: usize,
    pub timed_out: bool,
    pub blake3: String,
    pub size_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct StreamLimits {
    pub max_bytes: usize,
    pub max_sample_bytes: usize,
    pub sample_window_bytes: usize,
    pub timeout_ms: Option<u64>,
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024,
            max_sample_bytes: 10 * 1024 * 1024,
            sample_window_bytes: 1024 * 1024,
            timeout_ms: Some(150),
        }
    }
}

pub fn analyse_stream(bytes: &[u8], limits: &StreamLimits) -> StreamAnalysisResult {
    let size_bytes = bytes.len();
    let sample_end = bytes.len().min(limits.max_sample_bytes);
    let window_bytes = limits.sample_window_bytes.max(1);
    let sample = &bytes[..sample_end];
    let magic_sample_end = bytes.len().min(limits.max_bytes);
    let magic_type = magic_type(&bytes[..magic_sample_end]);

    let mut entropy: f64 = 0.0;
    let mut offset = 0usize;
    let mut processed_bytes = 0usize;
    let mut timed_out = false;
    let mut timeout_checker = None;
    if let Some(ms) = limits.timeout_ms {
        if ms == 0 {
            timed_out = true;
        } else {
            timeout_checker = Some(TimeoutChecker::new(Duration::from_millis(ms)));
        }
    }

    if !timed_out {
        while offset < sample.len() {
            if let Some(checker) = &timeout_checker {
                if checker.check().is_err() {
                    timed_out = true;
                    break;
                }
            }
            let end = (offset + window_bytes).min(sample.len());
            let chunk = &sample[offset..end];
            processed_bytes += chunk.len();
            if !chunk.is_empty() {
                let chunk_entropy = shannon_entropy(chunk);
                entropy = entropy.max(chunk_entropy);
            }
            offset = end;
        }
    }

    let mut hasher = Hasher::new();
    hasher.update(bytes);
    let blake3 = hasher.finalize().to_hex().to_string();
    StreamAnalysisResult {
        magic_type,
        entropy,
        sample_bytes: processed_bytes,
        timed_out,
        blake3,
        size_bytes,
    }
}

const RAR4_MAGIC: &[u8] = b"Rar!\x1A\x07\x00";
const RAR5_MAGIC: &[u8] = b"Rar!\x1A\x07\x01\x00";

fn is_rar(data: &[u8]) -> bool {
    data.starts_with(RAR4_MAGIC) || data.starts_with(RAR5_MAGIC)
}

fn magic_type(data: &[u8]) -> String {
    if data.starts_with(b"MZ") {
        "pe".into()
    } else if data.starts_with(b"%PDF") {
        "pdf".into()
    } else if data.starts_with(b"PK\x03\x04") {
        "zip".into()
    } else if is_rar(data) {
        "rar".into()
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
        assert!(res.sample_bytes > 0);
        assert!(!res.timed_out);
    }

    #[test]
    fn entropy_high_for_untyped() {
        let mut data = Vec::new();
        for _ in 0..4 {
            for byte in 0..=255u8 {
                data.push(byte);
            }
        }
        let res = analyse_stream(&data, &StreamLimits::default());
        assert!(res.entropy > 7.9);
        assert!(!res.timed_out);
    }

    #[test]
    fn entropy_low_for_textual() {
        let data = b"hello world ".repeat(1024);
        let res = analyse_stream(&data, &StreamLimits::default());
        assert!(res.entropy < 6.0);
        assert!(!res.timed_out);
    }

    #[test]
    fn sliding_window_prefers_high_entropy() {
        let mut data = vec![b'A'; 1024 * 1024];
        for _ in 0..4096 {
            for byte in 0..=255u8 {
                data.push(byte);
            }
        }
        let limits = StreamLimits {
            max_sample_bytes: data.len(),
            sample_window_bytes: 1024 * 1024,
            ..Default::default()
        };
        let res = analyse_stream(&data, &limits);
        assert!(res.entropy > 7.8);
        assert_eq!(res.sample_bytes, data.len());
    }

    #[test]
    fn entropy_timeout_breaks_early() {
        let limits = StreamLimits { timeout_ms: Some(0), ..Default::default() };
        let data = vec![0u8; 1024 * 1024];
        let res = analyse_stream(&data, &limits);
        assert!(res.timed_out);
        assert_eq!(res.sample_bytes, 0);
    }
}
