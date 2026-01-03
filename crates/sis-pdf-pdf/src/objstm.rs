use crate::decode::decode_stream;
use crate::graph::ObjEntry;
use crate::object::{PdfAtom, PdfDict};
use crate::parser::Parser;
use crate::span::Span;

pub struct ObjStmExpansion<'a> {
    pub objects: Vec<ObjEntry<'a>>,
    pub buffers: Vec<Vec<u8>>,
}

pub fn expand_objstm<'a>(
    bytes: &'a [u8],
    objects: &[ObjEntry<'a>],
    strict: bool,
    max_objstm_bytes: usize,
) -> ObjStmExpansion<'a> {
    let mut out = Vec::new();
    let mut buffers = Vec::new();
    for entry in objects {
        let st = match &entry.atom {
            PdfAtom::Stream(st) => st,
            _ => continue,
        };
        if !st.dict.has_name(b"/Type", b"/ObjStm") {
            continue;
        }
        let n = match dict_int(&st.dict, b"/N") {
            Some(v) => v as usize,
            None => continue,
        };
        let first = match dict_int(&st.dict, b"/First") {
            Some(v) => v as usize,
            None => continue,
        };
        let mut decoded = match decode_stream(bytes, st, max_objstm_bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if decoded.data.len() <= first {
            continue;
        }
        let data = std::mem::take(&mut decoded.data);
        // SAFETY: caller stores `data` in the graph so the backing buffer lives for `'a`.
        let data_ref: &'a [u8] = unsafe { std::mem::transmute::<&[u8], &'a [u8]>(&data) };
        let header = &data_ref[..first];
        let tokens = parse_header_tokens(header, n * 2);
        if tokens.len() < n * 2 {
            continue;
        }
        for idx in 0..n {
            let obj_num = tokens[idx * 2] as u32;
            let offset = tokens[idx * 2 + 1] as usize;
            let obj_start = first.saturating_add(offset);
            if obj_start >= data_ref.len() {
                continue;
            }
            let mut parser = Parser::new(data_ref, obj_start, strict);
            let parsed = match parser.parse_object() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let obj_end = parser.position();
            let span = Span {
                start: st.data_span.start,
                end: st.data_span.end,
            };
            out.push(ObjEntry {
                obj: obj_num,
                gen: 0,
                atom: parsed.atom,
                header_span: span,
                body_span: span,
                full_span: span,
            });
            let _ = obj_end;
        }
        buffers.push(data);
    }
    ObjStmExpansion { objects: out, buffers }
}

fn dict_int(dict: &PdfDict<'_>, key: &[u8]) -> Option<u64> {
    let (_, obj) = dict.get_first(key)?;
    match &obj.atom {
        PdfAtom::Int(i) if *i >= 0 => Some(*i as u64),
        _ => None,
    }
}

fn parse_header_tokens(bytes: &[u8], max: usize) -> Vec<u64> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() && out.len() < max {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if start == i {
            break;
        }
        if let Ok(v) = std::str::from_utf8(&bytes[start..i]) {
            if let Ok(num) = v.parse::<u64>() {
                out.push(num);
            }
        }
    }
    out
}
