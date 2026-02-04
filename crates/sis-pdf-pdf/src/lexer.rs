use crate::span::Span;

#[derive(Debug, Clone)]
pub struct Cursor<'a> {
    pub bytes: &'a [u8],
    pub pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub fn eof(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    pub fn mark(&self) -> usize {
        self.pos
    }

    pub fn restore(&mut self, mark: usize) {
        self.pos = mark;
    }

    pub fn span_from(&self, start: usize, end: usize) -> Span {
        Span { start: start as u64, end: end as u64 }
    }

    pub fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    pub fn peek_n(&self, n: usize) -> Option<u8> {
        self.bytes.get(self.pos + n).copied()
    }

    pub fn consume(&mut self) -> Option<u8> {
        if self.pos >= self.bytes.len() {
            return None;
        }
        let b = self.bytes[self.pos];
        self.pos += 1;
        Some(b)
    }

    pub fn consume_while<F: Fn(u8) -> bool>(&mut self, f: F) -> Span {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if !f(b) {
                break;
            }
            self.pos += 1;
        }
        self.span_from(start, self.pos)
    }

    pub fn skip_ws_and_comments(&mut self) {
        loop {
            let mut moved = false;
            while let Some(b) = self.peek() {
                if is_whitespace(b) {
                    self.pos += 1;
                    moved = true;
                } else {
                    break;
                }
            }
            if self.peek() == Some(b'%') {
                while let Some(b) = self.consume() {
                    if b == b'\n' || b == b'\r' {
                        break;
                    }
                }
                continue;
            }
            if !moved {
                break;
            }
        }
    }

    pub fn consume_keyword(&mut self, kw: &[u8]) -> bool {
        if self.bytes.len() < self.pos + kw.len() {
            return false;
        }
        if &self.bytes[self.pos..self.pos + kw.len()] == kw {
            self.pos += kw.len();
            true
        } else {
            false
        }
    }
}

pub fn is_whitespace(b: u8) -> bool {
    matches!(b, b'\x00' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

pub fn is_delim(b: u8) -> bool {
    matches!(b, b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%')
}
