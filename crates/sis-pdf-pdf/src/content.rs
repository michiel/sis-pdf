use crate::span::Span;

#[derive(Debug, Clone)]
pub enum ContentOperand {
    Number(f32),
    Name(String),
    Str(String),
    Array(String),
    Dict(String),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone)]
pub struct ContentOp {
    pub op: String,
    pub operands: Vec<ContentOperand>,
    pub span: Span,
}

pub fn parse_content_ops(bytes: &[u8]) -> Vec<ContentOp> {
    let mut ops = Vec::new();
    let mut operands: Vec<ContentOperand> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        i = skip_layout(bytes, i);
        if i >= bytes.len() {
            break;
        }
        let start = i;
        let token = read_token(bytes, &mut i);
        let Some(token) = token else {
            break;
        };
        if is_operator(token.as_slice()) {
            let op = String::from_utf8_lossy(&token).to_string();
            ops.push(ContentOp {
                op: op.clone(),
                operands: std::mem::take(&mut operands),
                span: Span { start: start as u64, end: i as u64 },
            });
            // Inline image data between ID ... EI is opaque and should not be tokenised.
            if op == "ID" {
                skip_inline_image_data(bytes, &mut i, &mut ops);
            }
        } else if let Some(operand) = parse_operand(token.as_slice()) {
            operands.push(operand);
        } else {
            let op = String::from_utf8_lossy(&token).to_string();
            ops.push(ContentOp {
                op,
                operands: std::mem::take(&mut operands),
                span: Span { start: start as u64, end: i as u64 },
            });
        }
    }
    ops
}

fn is_operator(tok: &[u8]) -> bool {
    matches!(
        tok,
        b"q" | b"Q"
            | b"cm"
            | b"Do"
            | b"d0"
            | b"d1"
            | b"BT"
            | b"ET"
            | b"Tc"
            | b"Tw"
            | b"Tz"
            | b"TL"
            | b"Tf"
            | b"Tj"
            | b"TJ"
            | b"Td"
            | b"TD"
            | b"Tm"
            | b"Tr"
            | b"Ts"
            | b"T*"
            | b"'"
            | b"\""
            | b"re"
            | b"W"
            | b"W*"
            | b"m"
            | b"l"
            | b"c"
            | b"v"
            | b"y"
            | b"h"
            | b"S"
            | b"s"
            | b"f"
            | b"F"
            | b"B"
            | b"B*"
            | b"b"
            | b"b*"
            | b"n"
            | b"gs"
            | b"CS"
            | b"cs"
            | b"SC"
            | b"sc"
            | b"SCN"
            | b"scn"
            | b"sh"
            | b"rg"
            | b"RG"
            | b"k"
            | b"K"
            | b"g"
            | b"G"
            | b"w"
            | b"J"
            | b"j"
            | b"M"
            | b"d"
            | b"ri"
            | b"i"
            | b"MP"
            | b"DP"
            | b"BMC"
            | b"BDC"
            | b"EMC"
            | b"BX"
            | b"EX"
            | b"BI"
            | b"ID"
            | b"EI"
    )
}

fn parse_operand(tok: &[u8]) -> Option<ContentOperand> {
    if tok.starts_with(b"/") {
        return Some(ContentOperand::Name(String::from_utf8_lossy(tok).to_string()));
    }
    if tok == b"true" {
        return Some(ContentOperand::Bool(true));
    }
    if tok == b"false" {
        return Some(ContentOperand::Bool(false));
    }
    if tok == b"null" {
        return Some(ContentOperand::Null);
    }
    if tok.starts_with(b"(") || (tok.starts_with(b"<") && !tok.starts_with(b"<<")) {
        return Some(ContentOperand::Str(String::from_utf8_lossy(tok).to_string()));
    }
    if tok.starts_with(b"[") {
        return Some(ContentOperand::Array(String::from_utf8_lossy(tok).to_string()));
    }
    if tok.starts_with(b"<<") {
        return Some(ContentOperand::Dict(String::from_utf8_lossy(tok).to_string()));
    }
    if let Some(val) = parse_number(tok) {
        return Some(ContentOperand::Number(val));
    }
    None
}

fn parse_number(tok: &[u8]) -> Option<f32> {
    let s = std::str::from_utf8(tok).ok()?;
    s.parse::<f32>().ok()
}

fn skip_layout(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if bytes[i] == b'%' {
            while i < bytes.len() && bytes[i] != b'\n' && bytes[i] != b'\r' {
                i += 1;
            }
            continue;
        }
        break;
    }
    i
}

fn read_token(bytes: &[u8], i: &mut usize) -> Option<Vec<u8>> {
    if *i >= bytes.len() {
        return None;
    }
    let b = bytes[*i];
    if b == b'(' {
        return Some(read_literal_string(bytes, i));
    }
    if b == b'<' {
        if *i + 1 < bytes.len() && bytes[*i + 1] == b'<' {
            return Some(read_dict_token(bytes, i));
        }
        return Some(read_hex_string(bytes, i));
    }
    if b == b'[' {
        return Some(read_array_token(bytes, i));
    }
    if b == b'/' {
        return Some(read_name_token(bytes, i));
    }
    Some(read_simple_token(bytes, i))
}

fn read_simple_token(bytes: &[u8], i: &mut usize) -> Vec<u8> {
    let start = *i;
    while *i < bytes.len() && !is_whitespace_or_delim(bytes[*i]) {
        *i += 1;
    }
    if *i == start && *i < bytes.len() {
        *i += 1;
    }
    bytes[start..*i].to_vec()
}

fn read_name_token(bytes: &[u8], i: &mut usize) -> Vec<u8> {
    let start = *i;
    *i += 1;
    while *i < bytes.len() && !is_whitespace_or_delim(bytes[*i]) {
        *i += 1;
    }
    bytes[start..*i].to_vec()
}

fn read_literal_string(bytes: &[u8], i: &mut usize) -> Vec<u8> {
    let start = *i;
    let mut depth = 0i32;
    while *i < bytes.len() {
        let c = bytes[*i];
        if c == b'\\' {
            *i = (*i + 2).min(bytes.len());
            continue;
        }
        if c == b'(' {
            depth += 1;
        } else if c == b')' {
            depth -= 1;
            if depth <= 0 {
                *i += 1;
                break;
            }
        }
        *i += 1;
    }
    bytes[start..(*i).min(bytes.len())].to_vec()
}

fn read_hex_string(bytes: &[u8], i: &mut usize) -> Vec<u8> {
    let start = *i;
    *i += 1;
    while *i < bytes.len() {
        if bytes[*i] == b'>' {
            *i += 1;
            break;
        }
        *i += 1;
    }
    bytes[start..(*i).min(bytes.len())].to_vec()
}

fn read_array_token(bytes: &[u8], i: &mut usize) -> Vec<u8> {
    let start = *i;
    let mut depth = 0i32;
    while *i < bytes.len() {
        let c = bytes[*i];
        if c == b'(' {
            let _ = read_literal_string(bytes, i);
            continue;
        }
        if c == b'[' {
            depth += 1;
        } else if c == b']' {
            depth -= 1;
            *i += 1;
            if depth <= 0 {
                break;
            }
            continue;
        }
        *i += 1;
    }
    bytes[start..(*i).min(bytes.len())].to_vec()
}

fn read_dict_token(bytes: &[u8], i: &mut usize) -> Vec<u8> {
    let start = *i;
    let mut depth = 0i32;
    while *i < bytes.len() {
        if *i + 1 < bytes.len() && bytes[*i] == b'<' && bytes[*i + 1] == b'<' {
            depth += 1;
            *i += 2;
            continue;
        }
        if *i + 1 < bytes.len() && bytes[*i] == b'>' && bytes[*i + 1] == b'>' {
            depth -= 1;
            *i += 2;
            if depth <= 0 {
                break;
            }
            continue;
        }
        if bytes[*i] == b'(' {
            let _ = read_literal_string(bytes, i);
            continue;
        }
        *i += 1;
    }
    bytes[start..(*i).min(bytes.len())].to_vec()
}

fn skip_inline_image_data(bytes: &[u8], i: &mut usize, ops: &mut Vec<ContentOp>) {
    *i = skip_layout(bytes, *i);
    let mut cursor = *i;
    while cursor + 1 < bytes.len() {
        if bytes[cursor] == b'E'
            && bytes[cursor + 1] == b'I'
            && (cursor == 0 || bytes[cursor - 1].is_ascii_whitespace())
            && (cursor + 2 >= bytes.len() || bytes[cursor + 2].is_ascii_whitespace())
        {
            let start = cursor;
            cursor += 2;
            ops.push(ContentOp {
                op: "EI".into(),
                operands: Vec::new(),
                span: Span { start: start as u64, end: cursor as u64 },
            });
            *i = cursor;
            return;
        }
        cursor += 1;
    }
    *i = bytes.len();
}

fn is_whitespace_or_delim(b: u8) -> bool {
    b.is_ascii_whitespace() || matches!(b, b'[' | b']' | b'<' | b'>' | b'(' | b')' | b'/' | b'%')
}

#[cfg(test)]
mod tests {
    use super::{parse_content_ops, ContentOperand};

    #[test]
    fn parse_content_ops_handles_strings_arrays_and_quote_ops() {
        let data = b"BT /F1 12 Tf (abc) Tj [(a) 120 (b)] TJ (line) ' 1 2 (x) \" ET";
        let ops = parse_content_ops(data);
        assert!(ops.iter().any(|op| op.op == "TJ"));
        assert!(ops.iter().any(|op| op.op == "'"));
        assert!(ops.iter().any(|op| op.op == "\""));
        let tj = ops.iter().find(|op| op.op == "Tj").expect("Tj should parse");
        assert!(matches!(tj.operands.first(), Some(ContentOperand::Str(_))));
        let tj_array = ops.iter().find(|op| op.op == "TJ").expect("TJ should parse");
        assert!(matches!(tj_array.operands.first(), Some(ContentOperand::Array(_))));
    }

    #[test]
    fn parse_content_ops_emits_unknown_operator_tokens() {
        let data = b"1 2 3 XYZ";
        let ops = parse_content_ops(data);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].op, "XYZ");
        assert_eq!(ops[0].operands.len(), 3);
    }

    #[test]
    fn parse_content_ops_skips_inline_image_data() {
        let data = b"q BI /W 1 /H 1 ID abcdef EI Q";
        let ops = parse_content_ops(data);
        assert!(ops.iter().any(|op| op.op == "BI"));
        assert!(ops.iter().any(|op| op.op == "ID"));
        assert!(ops.iter().any(|op| op.op == "EI"));
        assert!(ops.iter().any(|op| op.op == "Q"));
    }
}
