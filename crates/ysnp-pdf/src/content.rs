use crate::span::Span;

#[derive(Debug, Clone)]
pub struct ContentOp {
    pub op: String,
    pub span: Span,
}

pub fn parse_content_ops(bytes: &[u8]) -> Vec<ContentOp> {
    let mut ops = Vec::new();
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
                span: Span {
                    start: start as u64,
                    end: i as u64,
                },
            });
        }
    }
    ops
}

fn is_operator(tok: &[u8]) -> bool {
    matches!(
        tok,
        b"q" | b"Q" | b"cm" | b"Do" | b"BT" | b"ET" | b"Tf" | b"Tj" | b"TJ" | b"Td" | b"Tm"
            | b"Tr" | b"re" | b"W" | b"W*"
    )
}
