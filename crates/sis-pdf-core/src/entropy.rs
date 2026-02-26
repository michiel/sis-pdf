/// Computes the Shannon entropy of a byte slice.
///
/// Returns a value in the range [0.0, 8.0], where 0.0 indicates
/// all bytes are identical and 8.0 indicates a perfectly uniform
/// distribution across all 256 byte values.
pub fn shannon_entropy(data: &[u8]) -> f64 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_returns_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn uniform_single_byte_returns_zero() {
        let data = vec![0xAAu8; 100];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn two_equal_symbols_returns_one() {
        // Equal mix of two byte values gives entropy = 1.0
        let data: Vec<u8> = (0..256).flat_map(|_| [0x00u8, 0x01u8]).collect();
        let e = shannon_entropy(&data);
        assert!((e - 1.0).abs() < 1e-10, "expected 1.0, got {}", e);
    }
}
