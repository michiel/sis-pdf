/// Parse an object reference string like "5 0 R" or "5 0" into (obj, gen).
pub fn parse_obj_ref(s: &str) -> Option<(u32, u16)> {
    let s = s.trim();
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() >= 2 {
        let obj = parts[0].parse::<u32>().ok()?;
        let gen = parts[1].parse::<u16>().ok()?;
        Some((obj, gen))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_obj_ref_standard() {
        assert_eq!(parse_obj_ref("5 0 R"), Some((5, 0)));
        assert_eq!(parse_obj_ref("12 3 R"), Some((12, 3)));
    }

    #[test]
    fn parse_obj_ref_without_r() {
        assert_eq!(parse_obj_ref("5 0"), Some((5, 0)));
    }

    #[test]
    fn parse_obj_ref_trimmed() {
        assert_eq!(parse_obj_ref("  5 0 R  "), Some((5, 0)));
    }

    #[test]
    fn parse_obj_ref_invalid() {
        assert_eq!(parse_obj_ref("abc"), None);
        assert_eq!(parse_obj_ref("5"), None);
        assert_eq!(parse_obj_ref(""), None);
    }
}
