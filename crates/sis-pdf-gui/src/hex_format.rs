/// Shared hex formatting helpers used by the hex viewer and Object Inspector stream hex.

/// Format a single line of hex+ASCII output (16 bytes per line).
///
/// Format: `OOOOOOOO  HH HH HH HH HH HH HH HH  HH HH HH HH HH HH HH HH  |ASCII...........|`
pub fn format_hex_line(offset: usize, data: &[u8]) -> String {
    let mut line = format!("{:08X}  ", offset);

    // First group of 8 bytes
    for i in 0..8 {
        if i < data.len() {
            line.push_str(&format!("{:02X} ", data[i]));
        } else {
            line.push_str("   ");
        }
    }
    line.push(' ');

    // Second group of 8 bytes
    for i in 8..16 {
        if i < data.len() {
            line.push_str(&format!("{:02X} ", data[i]));
        } else {
            line.push_str("   ");
        }
    }
    line.push(' ');

    // ASCII column
    line.push('|');
    for i in 0..16.min(data.len()) {
        let ch = data[i];
        if ch >= 0x20 && ch <= 0x7E {
            line.push(ch as char);
        } else {
            line.push('.');
        }
    }
    // Pad ASCII column to 16 chars for alignment
    for _ in data.len()..16 {
        line.push(' ');
    }
    line.push('|');

    line
}

/// Format a block of bytes as hex+ASCII lines, returning all lines.
pub fn format_hex_block(data: &[u8], base_offset: usize) -> Vec<String> {
    data.chunks(16)
        .enumerate()
        .map(|(i, chunk)| format_hex_line(base_offset + i * 16, chunk))
        .collect()
}

/// Calculate total number of hex lines for a given byte count.
pub fn line_count(byte_count: usize) -> usize {
    (byte_count + 15) / 16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_full_line() {
        let data: Vec<u8> = (0x00..0x10).collect();
        let line = format_hex_line(0, &data);
        assert!(line.starts_with("00000000  "));
        assert!(line.contains("0F"));
        assert!(line.ends_with('|'));
    }

    #[test]
    fn format_partial_line() {
        let data = b"Hello";
        let line = format_hex_line(0x100, data);
        assert!(line.starts_with("00000100  "));
        assert!(line.contains("|Hello"));
    }

    #[test]
    fn format_block_line_count() {
        let data = vec![0u8; 48]; // 3 full lines
        let lines = format_hex_block(&data, 0);
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn line_count_rounding() {
        assert_eq!(line_count(0), 0);
        assert_eq!(line_count(1), 1);
        assert_eq!(line_count(16), 1);
        assert_eq!(line_count(17), 2);
        assert_eq!(line_count(32), 2);
    }
}
