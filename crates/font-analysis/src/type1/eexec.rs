/// Type 1 font eexec decryption
///
/// The eexec encryption is a simple XOR-based encryption with a rolling key.
/// The algorithm uses a 16-bit unsigned integer as the cipher key.
const EEXEC_KEY_C1: u16 = 52845;
const EEXEC_KEY_C2: u16 = 22719;
const EEXEC_INITIAL_KEY: u16 = 55665;

/// Decrypt eexec-encrypted data
///
/// Type 1 fonts use eexec encryption for the private dictionary and charstrings.
/// This function decrypts the data using the standard Type 1 eexec algorithm.
pub fn decrypt_eexec(encrypted: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(encrypted.len());
    let mut key = EEXEC_INITIAL_KEY;

    for &byte in encrypted {
        let plain = byte ^ (key >> 8) as u8;
        result.push(plain);
        key = key.wrapping_add(byte as u16).wrapping_mul(EEXEC_KEY_C1).wrapping_add(EEXEC_KEY_C2);
    }

    result
}

/// Decrypt eexec data that may be in ASCII hex format
///
/// Some Type 1 fonts encode the encrypted data as ASCII hex (each byte as two hex digits).
/// This function handles both binary and ASCII hex encoded data.
pub fn decrypt_eexec_auto(data: &[u8]) -> Vec<u8> {
    // Check if data is ASCII hex encoded (all printable chars in hex range)
    if is_ascii_hex(data) {
        // Convert ASCII hex to binary first
        if let Some(binary) = hex_to_binary(data) {
            return decrypt_eexec(&binary);
        }
    }

    // Assume binary encoding
    decrypt_eexec(data)
}

/// Check if data appears to be ASCII hex encoded
fn is_ascii_hex(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    // Sample first 100 bytes to check
    let sample_len = data.len().min(100);
    let mut hex_count = 0;
    let mut total_non_whitespace = 0;

    for &byte in &data[0..sample_len] {
        if byte.is_ascii_hexdigit() {
            hex_count += 1;
            total_non_whitespace += 1;
        } else if byte.is_ascii_whitespace() {
            // Skip whitespace
        } else {
            return false; // Non-hex, non-whitespace character
        }
    }

    // Consider it hex if at least 80% of non-whitespace chars are hex digits
    total_non_whitespace > 0 && hex_count * 100 / total_non_whitespace >= 80
}

/// Convert ASCII hex string to binary
fn hex_to_binary(hex: &[u8]) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let mut chars = Vec::new();

    // Collect hex digits, skip whitespace
    for &byte in hex {
        if byte.is_ascii_hexdigit() {
            chars.push(byte);
        } else if !byte.is_ascii_whitespace() {
            return None; // Invalid character
        }
    }

    // Convert pairs of hex digits to bytes
    for chunk in chars.chunks(2) {
        if chunk.len() != 2 {
            break; // Odd number of hex digits, ignore remainder
        }

        let high = hex_digit_value(chunk[0])?;
        let low = hex_digit_value(chunk[1])?;
        result.push((high << 4) | low);
    }

    Some(result)
}

/// Convert a hex digit character to its numeric value
fn hex_digit_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_eexec() {
        // Test with known plaintext/ciphertext pair
        let plaintext = b"Hello, World!";

        // Encrypt manually to test decryption
        let mut encrypted = Vec::new();
        let mut key = EEXEC_INITIAL_KEY;

        for &byte in plaintext {
            let cipher = byte ^ (key >> 8) as u8;
            encrypted.push(cipher);
            key = key
                .wrapping_add(cipher as u16)
                .wrapping_mul(EEXEC_KEY_C1)
                .wrapping_add(EEXEC_KEY_C2);
        }

        // Decrypt and verify
        let decrypted = decrypt_eexec(&encrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hex_to_binary() {
        let hex = b"48656C6C6F"; // "Hello" in hex
        let binary = match hex_to_binary(hex) {
            Some(value) => value,
            None => panic!("hex to binary conversion failed"),
        };
        assert_eq!(binary, b"Hello");
    }

    #[test]
    fn test_hex_to_binary_with_whitespace() {
        let hex = b"48 65 6C 6C 6F"; // "Hello" in hex with spaces
        let binary = match hex_to_binary(hex) {
            Some(value) => value,
            None => panic!("hex to binary conversion failed"),
        };
        assert_eq!(binary, b"Hello");
    }

    #[test]
    fn test_is_ascii_hex() {
        assert!(is_ascii_hex(b"48656C6C6F"));
        assert!(is_ascii_hex(b"48 65 6C 6C 6F"));
        assert!(!is_ascii_hex(b"\x00\x01\x02\x03"));
        assert!(!is_ascii_hex(b"Hello"));
    }

    #[test]
    fn test_hex_digit_value() {
        assert_eq!(hex_digit_value(b'0'), Some(0));
        assert_eq!(hex_digit_value(b'9'), Some(9));
        assert_eq!(hex_digit_value(b'a'), Some(10));
        assert_eq!(hex_digit_value(b'f'), Some(15));
        assert_eq!(hex_digit_value(b'A'), Some(10));
        assert_eq!(hex_digit_value(b'F'), Some(15));
        assert_eq!(hex_digit_value(b'G'), None);
    }
}
