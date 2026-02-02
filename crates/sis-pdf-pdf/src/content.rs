use crate::span::Span;

#[derive(Debug, Clone)]
pub enum ContentOperand {
    Number(f32),
    Name(String),
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
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if start == i {
            break;
        }
        let tok = &bytes[start..i];
        if is_operator(tok) {
            let op = String::from_utf8_lossy(tok).to_string();
            ops.push(ContentOp {
                op,
                operands: std::mem::take(&mut operands),
                span: Span {
                    start: start as u64,
                    end: i as u64,
                },
            });
        } else if tok.starts_with(b"/") {
            operands.push(ContentOperand::Name(
                String::from_utf8_lossy(tok).to_string(),
            ));
        } else if let Some(val) = parse_number(tok) {
            operands.push(ContentOperand::Number(val));
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
            | b"BT"
            | b"ET"
            | b"Tf"
            | b"Tj"
            | b"TJ"
            | b"Td"
            | b"Tm"
            | b"Tr"
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
            | b"rg"
            | b"RG"
            | b"k"
            | b"K"
            | b"g"
            | b"G"
    )
}

fn parse_number(tok: &[u8]) -> Option<f32> {
    let s = std::str::from_utf8(tok).ok()?;
    s.parse::<f32>().ok()
}
