use anyhow::{anyhow, Result};

use crate::object::{PdfAtom, PdfDict};
use crate::parser::{parse_indirect_object_at, Parser};
use crate::span::Span;
use tracing::{debug, warn};

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
    pub deviations: Vec<XrefDeviation>,
}

#[derive(Debug)]
pub struct XrefDeviation {
    pub kind: &'static str,
    pub span: Span,
    pub note: Option<String>,
}

pub fn parse_xref_chain<'a>(bytes: &'a [u8], startxref: u64) -> XrefChain<'a> {
    let mut sections = Vec::new();
    let mut next = Some(startxref);
    let mut seen = std::collections::HashSet::new();
    let mut deviations = Vec::new();
    while let Some(off) = next {
        if !seen.insert(off) {
            warn!(
                security = true,
                domain = "pdf.xref",
                kind = "xref_loop_detected",
                offset = off,
                "Detected xref loop"
            );
            break;
        }
        let offset = off as usize;
        if offset >= bytes.len() {
            warn!(
                security = true,
                domain = "pdf.xref",
                kind = "xref_offset_oob",
                offset = off,
                bytes_len = bytes.len(),
                "Xref offset out of range"
            );
            break;
        }
        if bytes[offset..].starts_with(b"xref") {
            if let Ok((trailer, prev)) = parse_xref_table(bytes, offset, &mut deviations) {
                sections.push(XrefSection { offset: off, trailer, kind: XrefKind::Table });
                debug!(offset = off, kind = ?XrefKind::Table, "Parsed xref table");
                next = prev;
                continue;
            }
        }
        if let Ok((trailer, prev)) = parse_xref_stream(bytes, offset) {
            sections.push(XrefSection { offset: off, trailer, kind: XrefKind::Stream });
            debug!(offset = off, kind = ?XrefKind::Stream, "Parsed xref stream");
            next = prev;
            continue;
        }
        sections.push(XrefSection { offset: off, trailer: None, kind: XrefKind::Unknown });
        debug!(offset = off, kind = ?XrefKind::Unknown, "Parsed xref with unknown type");
        break;
    }
    XrefChain { sections, deviations }
}

fn parse_xref_table<'a>(
    bytes: &'a [u8],
    offset: usize,
    deviations: &mut Vec<XrefDeviation>,
) -> Result<(Option<PdfDict<'a>>, Option<u64>)> {
    let mut p = Parser::new(bytes, offset, false);
    p.consume_keyword(b"xref");
    // Skip subsection headers and entries, then find "trailer".
    let haystack_start = p.position();
    let haystack = &bytes[haystack_start..];
    if haystack.is_empty() {
        deviations.push(XrefDeviation {
            kind: "xref_trailer_search_invalid",
            span: Span { start: haystack_start as u64, end: haystack_start as u64 },
            note: Some("trailer search haystack empty".into()),
        });
        return Err(anyhow!("trailer search haystack empty"));
    }
    if let Some(pos) = memchr::memmem::find(haystack, b"trailer") {
        p.set_position(haystack_start + pos + "trailer".len());
        p.skip_ws_and_comments();
        let dict = p.parse_object()?;
        if let PdfAtom::Dict(d) = dict.atom {
            let prev = extract_prev(&d);
            return Ok((Some(d), prev));
        }
    } else {
        deviations.push(XrefDeviation {
            kind: "xref_trailer_search_invalid",
            span: Span {
                start: haystack_start as u64,
                end: (haystack_start + haystack.len()) as u64,
            },
            note: Some("trailer keyword not found before EOF".into()),
        });
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
