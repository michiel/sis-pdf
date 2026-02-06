use anyhow::{anyhow, Result};

use crate::graph::{Deviation, ObjEntry};
use crate::lexer::{is_delim, is_whitespace, Cursor};
use crate::object::{PdfAtom, PdfDict, PdfName, PdfObj, PdfStr, PdfStream};
use crate::span::Span;
use tracing::{trace, warn};

pub struct Parser<'a> {
    cur: Cursor<'a>,
    strict: bool,
    deviations: Vec<Deviation>,
}

const MAX_ARRAY_ELEMENTS: usize = 100_000;
const MAX_DICT_ENTRIES: usize = 10_000;
const MAX_PARSE_DEPTH: usize = 64;

impl<'a> Parser<'a> {
    pub fn new(bytes: &'a [u8], pos: usize, strict: bool) -> Self {
        Self { cur: Cursor { bytes, pos }, strict, deviations: Vec::new() }
    }

    pub fn position(&self) -> usize {
        self.cur.pos
    }

    pub fn set_position(&mut self, pos: usize) {
        self.cur.pos = pos;
    }

    pub fn skip_ws_and_comments(&mut self) {
        self.cur.skip_ws_and_comments();
    }

    pub fn consume_keyword(&mut self, kw: &[u8]) -> bool {
        self.cur.consume_keyword(kw)
    }

    pub fn take_deviations(&mut self) -> Vec<Deviation> {
        std::mem::take(&mut self.deviations)
    }

    fn record_deviation(&mut self, kind: &str, span: Span, note: Option<String>) {
        if self.strict {
            let note_preview = note.as_deref();
            warn!(
                security = true,
                domain = "pdf.parser",
                kind = kind,
                span_start = span.start,
                span_end = span.end,
                note = note_preview,
                "Strict parser deviation"
            );
            self.deviations.push(Deviation { kind: kind.to_string(), span, note });
        }
    }

    pub fn parse_object(&mut self) -> Result<PdfObj<'a>> {
        self.parse_object_with_depth(0)
    }

    fn parse_object_with_depth(&mut self, depth: usize) -> Result<PdfObj<'a>> {
        if depth >= MAX_PARSE_DEPTH {
            let span = Span { start: self.cur.pos as u64, end: self.cur.pos as u64 };
            self.record_deviation("parse_depth_exceeded", span, Some(format!("depth={}", depth)));
            return Err(anyhow!("parse depth exceeded"));
        }
        self.cur.skip_ws_and_comments();
        let start = self.cur.pos;
        let b = self.cur.peek().ok_or_else(|| anyhow!("eof"))?;
        let obj = match b {
            b'/' => self.parse_name().map(PdfAtom::Name)?,
            b'<' => {
                if self.cur.peek_n(1) == Some(b'<') {
                    let dict = self.parse_dict_with_depth(depth + 1)?;
                    if self.try_parse_stream(&dict)? {
                        let stream = self.parse_stream(dict)?;
                        PdfAtom::Stream(stream)
                    } else {
                        PdfAtom::Dict(dict)
                    }
                } else {
                    let s = self.parse_hex_string()?;
                    PdfAtom::Str(s)
                }
            }
            b'(' => {
                let s = self.parse_literal_string()?;
                PdfAtom::Str(s)
            }
            b'[' => {
                let arr = self.parse_array_with_depth(depth + 1)?;
                PdfAtom::Array(arr)
            }
            b't' => {
                if self.cur.consume_keyword(b"true") {
                    PdfAtom::Bool(true)
                } else {
                    return Err(anyhow!("unexpected token"));
                }
            }
            b'f' => {
                if self.cur.consume_keyword(b"false") {
                    PdfAtom::Bool(false)
                } else {
                    return Err(anyhow!("unexpected token"));
                }
            }
            b'n' => {
                if self.cur.consume_keyword(b"null") {
                    PdfAtom::Null
                } else {
                    return Err(anyhow!("unexpected token"));
                }
            }
            b'+' | b'-' | b'.' | b'0'..=b'9' => self.parse_number_or_ref()?,
            _ => {
                self.record_deviation(
                    "unexpected_token",
                    Span { start: self.cur.pos as u64, end: (self.cur.pos + 1) as u64 },
                    Some(format!("byte=0x{:02x}", b)),
                );
                return Err(anyhow!("unexpected byte {:x}", b));
            }
        };
        let end = self.cur.pos;
        Ok(PdfObj { span: Span { start: start as u64, end: end as u64 }, atom: obj })
    }

    fn parse_number_or_ref(&mut self) -> Result<PdfAtom<'a>> {
        let (num1_span, num1_str) = self.read_number_token()?;
        let num1 = match parse_number(&num1_str) {
            Ok(v) => v,
            Err(e) => {
                self.record_deviation("invalid_number", num1_span, Some(num1_str.clone()));
                return Err(e);
            }
        };
        let after_first = self.cur.pos;

        self.cur.skip_ws_and_comments();
        let second_mark = self.cur.mark();
        if let Ok((num2_span, num2_str)) = self.read_number_token() {
            self.cur.skip_ws_and_comments();
            if self.cur.consume_keyword(b"R") {
                if let (Some(obj), Some(gen)) = (num1.as_i64(), parse_number(&num2_str)?.as_i64()) {
                    if obj >= 0 && gen >= 0 {
                        return Ok(PdfAtom::Ref { obj: obj as u32, gen: gen as u16 });
                    }
                }
            }
            if self.strict && parse_number(&num2_str).is_err() {
                self.record_deviation("invalid_number", num2_span, Some(num2_str.clone()));
            }
        }
        self.cur.restore(second_mark);
        self.cur.restore(after_first);
        Ok(match num1 {
            PdfNumber::Int(i) => PdfAtom::Int(i),
            PdfNumber::Real(f) => PdfAtom::Real(f),
        })
    }

    fn parse_array_with_depth(&mut self, depth: usize) -> Result<Vec<PdfObj<'a>>> {
        let mut out = Vec::new();
        let _ = self.cur.consume();
        loop {
            self.cur.skip_ws_and_comments();
            if self.cur.peek() == Some(b']') {
                self.cur.consume();
                break;
            }
            if self.cur.eof() {
                self.record_deviation(
                    "unterminated_array",
                    Span { start: self.cur.pos as u64, end: self.cur.pos as u64 },
                    None,
                );
                break;
            }
            if out.len() >= MAX_ARRAY_ELEMENTS {
                self.record_deviation(
                    "array_size_limit_exceeded",
                    Span { start: self.cur.pos as u64, end: self.cur.pos as u64 },
                    Some(format!("max_elements={}", MAX_ARRAY_ELEMENTS)),
                );
                warn!(
                    security = true,
                    domain = "pdf.parser",
                    kind = "array_size_limit_exceeded",
                    max_elements = MAX_ARRAY_ELEMENTS,
                    "Array size limit exceeded"
                );
                return Err(anyhow!("array size limit exceeded"));
            }
            out.push(self.parse_object_with_depth(depth + 1)?);
        }
        Ok(out)
    }

    fn parse_dict_with_depth(&mut self, depth: usize) -> Result<PdfDict<'a>> {
        let start = self.cur.pos;
        self.cur.consume_keyword(b"<<");
        let mut entries = Vec::new();
        loop {
            self.cur.skip_ws_and_comments();
            if self.cur.consume_keyword(b">>") {
                break;
            }
            if self.cur.eof() {
                self.record_deviation(
                    "unterminated_dict",
                    Span { start: start as u64, end: self.cur.pos as u64 },
                    None,
                );
                break;
            }
            let name = self.parse_name()?;
            self.cur.skip_ws_and_comments();
            if self.cur.peek() == Some(b'>') {
                break;
            }
            if let Ok(val) = self.parse_object_with_depth(depth + 1) {
                entries.push((name, val));
            } else {
                entries.push((
                    name,
                    PdfObj {
                        span: Span { start: self.cur.pos as u64, end: self.cur.pos as u64 },
                        atom: PdfAtom::Null,
                    },
                ));
            }
            if entries.len() >= MAX_DICT_ENTRIES {
                self.record_deviation(
                    "dict_size_limit_exceeded",
                    Span { start: start as u64, end: self.cur.pos as u64 },
                    Some(format!("max_entries={}", MAX_DICT_ENTRIES)),
                );
                warn!(
                    security = true,
                    domain = "pdf.parser",
                    kind = "dict_size_limit_exceeded",
                    max_entries = MAX_DICT_ENTRIES,
                    "Dictionary size limit exceeded"
                );
                return Err(anyhow!("dict size limit exceeded"));
            }
        }
        let end = self.cur.pos;
        Ok(PdfDict { span: Span { start: start as u64, end: end as u64 }, entries })
    }

    fn parse_name(&mut self) -> Result<PdfName<'a>> {
        let start = self.cur.pos;
        let _ = self.cur.consume();
        let raw_start = self.cur.pos;
        while let Some(b) = self.cur.peek() {
            if is_whitespace(b) || is_delim(b) {
                break;
            }
            self.cur.pos += 1;
        }
        let raw_end = self.cur.pos;
        if self.strict {
            let raw = &self.cur.bytes[raw_start..raw_end];
            let mut i = 0usize;
            while i < raw.len() {
                if raw[i] == b'#' {
                    let bad = i + 2 >= raw.len()
                        || hex_val(raw[i + 1]).is_none()
                        || hex_val(raw[i + 2]).is_none();
                    if bad {
                        self.record_deviation(
                            "invalid_name_escape",
                            Span {
                                start: (raw_start + i) as u64,
                                end: (raw_start + i + 1).min(raw_end) as u64,
                            },
                            None,
                        );
                    }
                    i += 3;
                    continue;
                }
                i += 1;
            }
        }
        let raw = &self.cur.bytes[start..raw_end];
        let decoded = decode_name(&self.cur.bytes[raw_start..raw_end]);
        Ok(PdfName {
            span: Span { start: start as u64, end: raw_end as u64 },
            raw: std::borrow::Cow::Borrowed(raw),
            decoded,
        })
    }

    fn parse_literal_string(&mut self) -> Result<PdfStr<'a>> {
        let start = self.cur.pos;
        let _ = self.cur.consume();
        let mut depth = 1;
        let mut out = Vec::new();
        let mut unterminated = false;
        while let Some(b) = self.cur.consume() {
            match b {
                b'(' => {
                    depth += 1;
                    out.push(b);
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    out.push(b);
                }
                b'\\' => {
                    let esc_pos = self.cur.pos.saturating_sub(1);
                    if let Some(next) = self.cur.consume() {
                        match next {
                            b'n' => out.push(b'\n'),
                            b'r' => out.push(b'\r'),
                            b't' => out.push(b'\t'),
                            b'b' => out.push(0x08),
                            b'f' => out.push(0x0c),
                            b'(' | b')' | b'\\' => out.push(next),
                            b'\n' | b'\r' => {
                                if next == b'\r' && self.cur.peek() == Some(b'\n') {
                                    self.cur.consume();
                                }
                            }
                            b'0'..=b'7' => {
                                let mut oct = vec![next];
                                for _ in 0..2 {
                                    if let Some(d) = self.cur.peek() {
                                        if (b'0'..=b'7').contains(&d) {
                                            oct.push(d);
                                            self.cur.consume();
                                        } else {
                                            break;
                                        }
                                    }
                                }
                                let val = oct.iter().fold(0u8, |acc, d| acc * 8 + (d - b'0'));
                                out.push(val);
                            }
                            other => {
                                self.record_deviation(
                                    "invalid_escape_sequence",
                                    Span {
                                        start: esc_pos as u64,
                                        end: (esc_pos + 2).min(self.cur.bytes.len()) as u64,
                                    },
                                    None,
                                );
                                out.push(other);
                            }
                        }
                    }
                }
                _ => out.push(b),
            }
        }
        if depth != 0 {
            unterminated = true;
        }
        let end = self.cur.pos;
        if unterminated {
            self.record_deviation(
                "unterminated_literal_string",
                Span { start: start as u64, end: end as u64 },
                None,
            );
        }
        Ok(PdfStr::Literal {
            span: Span { start: start as u64, end: end as u64 },
            raw: std::borrow::Cow::Borrowed(&self.cur.bytes[start..end]),
            decoded: out,
        })
    }

    fn parse_hex_string(&mut self) -> Result<PdfStr<'a>> {
        let start = self.cur.pos;
        let _ = self.cur.consume();
        let mut out = Vec::new();
        let mut buf = Vec::new();
        let mut saw_end = false;
        let mut invalid = false;
        while let Some(b) = self.cur.consume() {
            if b == b'>' {
                saw_end = true;
                break;
            }
            if is_whitespace(b) {
                continue;
            }
            if hex_val(b).is_none() {
                invalid = true;
            }
            buf.push(b);
        }
        let mut i = 0;
        while i < buf.len() {
            let hi = buf[i];
            let lo = if i + 1 < buf.len() { buf[i + 1] } else { b'0' };
            if let (Some(h), Some(l)) = (hex_val(hi), hex_val(lo)) {
                out.push((h << 4) | l);
            }
            i += 2;
        }
        let end = self.cur.pos;
        if !saw_end {
            self.record_deviation(
                "unterminated_hex_string",
                Span { start: start as u64, end: end as u64 },
                None,
            );
        }
        if invalid {
            self.record_deviation(
                "invalid_hex_string",
                Span { start: start as u64, end: end as u64 },
                None,
            );
        }
        if buf.len() % 2 == 1 {
            self.record_deviation(
                "odd_length_hex_string",
                Span { start: start as u64, end: end as u64 },
                None,
            );
        }
        Ok(PdfStr::Hex {
            span: Span { start: start as u64, end: end as u64 },
            raw: std::borrow::Cow::Borrowed(&self.cur.bytes[start..end]),
            decoded: out,
        })
    }

    fn read_number_token(&mut self) -> Result<(Span, String)> {
        let start = self.cur.pos;
        let mut out = Vec::new();
        let mut dot_count = 0usize;
        if let Some(b) = self.cur.peek() {
            if b == b'+' || b == b'-' || b == b'.' || b.is_ascii_digit() {
                out.push(b);
                if b == b'.' {
                    dot_count += 1;
                }
                self.cur.consume();
            } else {
                self.record_deviation(
                    "invalid_number_token",
                    Span { start: start as u64, end: (start + 1) as u64 },
                    None,
                );
                return Err(anyhow!("not a number"));
            }
        }
        while let Some(b) = self.cur.peek() {
            if b.is_ascii_digit() || b == b'.' {
                out.push(b);
                if b == b'.' {
                    dot_count += 1;
                }
                self.cur.consume();
            } else {
                break;
            }
        }
        let end = self.cur.pos;
        if dot_count > 1 {
            self.record_deviation(
                "invalid_number_format",
                Span { start: start as u64, end: end as u64 },
                None,
            );
        }
        Ok((
            Span { start: start as u64, end: end as u64 },
            String::from_utf8_lossy(&out).to_string(),
        ))
    }

    fn try_parse_stream(&mut self, _dict: &PdfDict<'a>) -> Result<bool> {
        let mark = self.cur.mark();
        self.cur.skip_ws_and_comments();
        if self.cur.consume_keyword(b"stream") {
            self.cur.restore(mark);
            return Ok(true);
        }
        self.cur.restore(mark);
        Ok(false)
    }

    fn parse_stream(&mut self, dict: PdfDict<'a>) -> Result<PdfStream<'a>> {
        self.cur.skip_ws_and_comments();
        self.cur.consume_keyword(b"stream");
        if self.cur.peek() == Some(b'\r') {
            self.cur.consume();
            if self.cur.peek() == Some(b'\n') {
                self.cur.consume();
            }
        } else if self.cur.peek() == Some(b'\n') {
            self.cur.consume();
        }
        let data_start = self.cur.pos;
        let length = stream_length_from_dict(&dict);
        let data_end = if let Some(len) = length {
            let end = match data_start.checked_add(len as usize) {
                Some(v) => v,
                None => {
                    self.record_deviation(
                        "stream_length_overflow",
                        Span { start: data_start as u64, end: data_start as u64 },
                        None,
                    );
                    warn!(
                        security = true,
                        domain = "pdf.parser",
                        kind = "stream_length_overflow",
                        start = data_start,
                        length = len,
                        "Stream length overflow"
                    );
                    return Err(anyhow!("stream length overflow"));
                }
            };
            if end > self.cur.bytes.len() {
                self.record_deviation(
                    "truncated_stream_data",
                    Span { start: data_start as u64, end: self.cur.bytes.len() as u64 },
                    None,
                );
            }
            end.min(self.cur.bytes.len())
        } else {
            find_endstream(self.cur.bytes, data_start).unwrap_or(self.cur.bytes.len())
        };
        self.cur.pos = data_end;
        if !consume_endstream(self.cur.bytes, &mut self.cur.pos) {
            self.record_deviation(
                "missing_endstream",
                Span { start: data_end as u64, end: data_end as u64 },
                None,
            );
        }
        Ok(PdfStream { dict, data_span: Span { start: data_start as u64, end: data_end as u64 } })
    }
}

#[derive(Debug)]
enum PdfNumber {
    Int(i64),
    Real(f64),
}

impl PdfNumber {
    fn as_i64(&self) -> Option<i64> {
        match self {
            PdfNumber::Int(i) => Some(*i),
            PdfNumber::Real(_) => None,
        }
    }
}

fn parse_number(s: &str) -> Result<PdfNumber> {
    if s.contains('.') {
        Ok(PdfNumber::Real(s.parse::<f64>()?))
    } else {
        Ok(PdfNumber::Int(s.parse::<i64>()?))
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

fn decode_name(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + 1);
    out.push(b'/');
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'#' && i + 2 < raw.len() {
            if let (Some(h), Some(l)) = (hex_val(raw[i + 1]), hex_val(raw[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(raw[i]);
        i += 1;
    }
    out
}

fn stream_length_from_dict(dict: &PdfDict<'_>) -> Option<u64> {
    let (_, obj) = dict.get_first(b"/Length")?;
    match &obj.atom {
        PdfAtom::Int(i) if *i >= 0 => Some(*i as u64),
        _ => None,
    }
}

fn find_endstream(bytes: &[u8], start: usize) -> Option<usize> {
    let needle = b"endstream";
    let mut i = start;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn consume_endstream(bytes: &[u8], pos: &mut usize) -> bool {
    let needle = b"endstream";
    if *pos + needle.len() <= bytes.len() && &bytes[*pos..*pos + needle.len()] == needle {
        *pos += needle.len();
        true
    } else {
        false
    }
}

pub fn parse_indirect_object_at<'a>(
    bytes: &'a [u8],
    offset: usize,
    strict: bool,
) -> (Result<(ObjEntry<'a>, usize)>, Vec<Deviation>) {
    let mut p = Parser::new(bytes, offset, strict);
    let res = (|| -> Result<(ObjEntry<'a>, usize)> {
        p.cur.skip_ws_and_comments();
        let header_start = p.cur.pos;
        let (_, obj_str) = p.read_number_token()?;
        p.cur.skip_ws_and_comments();
        let (_, gen_str) = p.read_number_token()?;
        p.cur.skip_ws_and_comments();
        if !p.cur.consume_keyword(b"obj") {
            p.record_deviation(
                "missing_obj_keyword",
                Span { start: header_start as u64, end: p.cur.pos as u64 },
                None,
            );
            return Err(anyhow!("missing obj keyword"));
        }
        let header_end = p.cur.pos;
        let obj_num = obj_str.parse::<u32>()?;
        let gen_num = gen_str.parse::<u16>()?;
        p.cur.skip_ws_and_comments();
        let body_start = p.cur.pos;
        let obj = p.parse_object()?;
        let body_end = p.cur.pos;
        p.cur.skip_ws_and_comments();
        if !p.cur.consume_keyword(b"endobj") {
            p.record_deviation(
                "missing_endobj",
                Span { start: p.cur.pos as u64, end: p.cur.pos as u64 },
                None,
            );
            if let Some(pos) = memchr::memmem::find(&bytes[p.cur.pos..], b"endobj") {
                p.cur.pos += pos + "endobj".len();
            }
        }
        let full_end = p.cur.pos;
        let entry = ObjEntry {
            obj: obj_num,
            gen: gen_num,
            atom: obj.atom,
            header_span: Span { start: header_start as u64, end: header_end as u64 },
            body_span: Span { start: body_start as u64, end: body_end as u64 },
            full_span: Span { start: header_start as u64, end: full_end as u64 },
            provenance: crate::graph::ObjProvenance::Indirect,
        };
        Ok((entry, full_end))
    })();
    let devs = p.take_deviations();
    (res, devs)
}

pub fn scan_indirect_objects<'a>(
    bytes: &'a [u8],
    strict: bool,
    max_objects: usize,
) -> (Vec<ObjEntry<'a>>, Vec<Deviation>) {
    let mut out = Vec::new();
    let mut deviations = Vec::new();
    let mut i = 0usize;
    while i + 7 < bytes.len() {
        if max_objects > 0 && out.len() >= max_objects {
            if strict {
                deviations.push(Deviation {
                    kind: "max_objects_reached".into(),
                    span: Span { start: i as u64, end: (i + 1) as u64 },
                    note: None,
                });
            }
            warn!(
                security = true,
                domain = "pdf.parser",
                kind = "max_objects_reached",
                max_objects = max_objects,
                "Max objects reached during indirect scan"
            );
            break;
        }
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let mark = i;
        let (res, mut devs) = parse_indirect_object_at(bytes, i, strict);
        if strict {
            deviations.append(&mut devs);
        }
        if let Ok((entry, end_pos)) = res {
            trace!(
                security = true,
                domain = "pdf.parser",
                kind = "indirect_object_parsed",
                obj = entry.obj,
                gen = entry.gen,
                end_pos = end_pos,
                "Parsed indirect object"
            );
            out.push(entry);
            i = end_pos;
        } else {
            if strict {
                deviations.push(Deviation {
                    kind: "indirect_object_parse_error".into(),
                    span: Span { start: mark as u64, end: (mark + 1) as u64 },
                    note: None,
                });
            }
            i = mark + 1;
        }
    }
    (out, deviations)
}

#[cfg(test)]
mod tests {
    use super::scan_indirect_objects;

    #[test]
    fn scan_respects_max_objects() {
        let data = b"1 0 obj<<>>endobj\n2 0 obj<<>>endobj\n3 0 obj<<>>endobj";
        let (objects, _) = scan_indirect_objects(data, false, 2);
        assert_eq!(objects.len(), 2);
    }
}
