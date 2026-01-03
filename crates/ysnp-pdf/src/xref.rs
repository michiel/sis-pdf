use anyhow::{anyhow, Result};

use crate::object::{PdfAtom, PdfDict};
use crate::parser::{parse_indirect_object_at, Parser};

#[derive(Debug, Clone, Copy)]
pub enum XrefKind {
    Table,
    Stream,
    Unknown,
}

#[derive(Debug)]
pub struct XrefSection<'a> {
    pub offset: u64,
    pub trailer: Option<PdfDict<'a>>,
    pub kind: XrefKind,
}

#[derive(Debug)]
pub struct XrefChain<'a> {
    pub sections: Vec<XrefSection<'a>>,
}

pub fn parse_xref_chain<'a>(bytes: &'a [u8], startxref: u64) -> XrefChain<'a> {
    let mut sections = Vec::new();
    let mut next = Some(startxref);
    let mut seen = std::collections::HashSet::new();
    while let Some(off) = next {
        if !seen.insert(off) {
            break;
        }
        let offset = off as usize;
        if offset >= bytes.len() {
            break;
        }
        if bytes[offset..].starts_with(b"xref") {
            if let Ok((trailer, prev)) = parse_xref_table(bytes, offset) {
                sections.push(XrefSection {
                    offset: off,
                    trailer,
                    kind: XrefKind::Table,
                });
                next = prev;
                continue;
            }
        }
        if let Ok((trailer, prev)) = parse_xref_stream(bytes, offset) {
            sections.push(XrefSection {
                offset: off,
                trailer,
                kind: XrefKind::Stream,
            });
            next = prev;
            continue;
        }
        sections.push(XrefSection {
            offset: off,
            trailer: None,
            kind: XrefKind::Unknown,
        });
        break;
    }
    XrefChain { sections }
}

fn parse_xref_table<'a>(bytes: &'a [u8], offset: usize) -> Result<(Option<PdfDict<'a>>, Option<u64>)> {
    let mut p = Parser::new(bytes, offset, false);
    p.consume_keyword(b"xref");
    // Skip subsection headers and entries, then find "trailer".
    if let Some(pos) = memchr::memmem::find(&bytes[p.position()..], b"trailer") {
        p.set_position(p.position() + pos + "trailer".len());
        p.skip_ws_and_comments();
        let dict = p.parse_object()?;
        if let PdfAtom::Dict(d) = dict.atom {
            let prev = extract_prev(&d);
            return Ok((Some(d), prev));
        }
    }
    Err(anyhow!("trailer not found"))
}

fn parse_xref_stream<'a>(
    bytes: &'a [u8],
    offset: usize,
) -> Result<(Option<PdfDict<'a>>, Option<u64>)> {
    let (res, _) = parse_indirect_object_at(bytes, offset, false);
    let (entry, _) = res?;
    match entry.atom {
        PdfAtom::Stream(st) => {
            if st.dict.has_name(b"/Type", b"/XRef") {
                let prev = extract_prev(&st.dict);
                return Ok((Some(st.dict), prev));
            }
        }
        PdfAtom::Dict(d) => {
            if d.has_name(b"/Type", b"/XRef") {
                let prev = extract_prev(&d);
                return Ok((Some(d), prev));
            }
        }
        _ => {}
    }
    Err(anyhow!("not an xref stream"))
}

fn extract_prev(dict: &PdfDict<'_>) -> Option<u64> {
    let (_, obj) = dict.get_first(b"/Prev")?;
    match &obj.atom {
        PdfAtom::Int(i) if *i >= 0 => Some(*i as u64),
        _ => None,
    }
}
