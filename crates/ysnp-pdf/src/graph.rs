use std::collections::HashMap;

use anyhow::Result;

use crate::object::{PdfAtom, PdfDict, PdfObj};
use crate::parser::scan_indirect_objects;
use crate::span::Span;
use crate::xref::parse_xref_chain;
use crate::objstm::{expand_objstm, ObjStmExpansion};

#[derive(Debug, Clone, Copy)]
pub struct ParseOptions {
    pub recover_xref: bool,
    pub deep: bool,
    pub strict: bool,
    pub max_objstm_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct Deviation {
    pub kind: String,
    pub span: Span,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ObjEntry<'a> {
    pub obj: u32,
    pub gen: u16,
    pub atom: PdfAtom<'a>,
    pub header_span: Span,
    pub body_span: Span,
    pub full_span: Span,
}

#[derive(Debug)]
pub struct ObjectGraph<'a> {
    pub bytes: &'a [u8],
    pub objects: Vec<ObjEntry<'a>>,
    pub index: HashMap<(u32, u16), Vec<usize>>,
    pub trailers: Vec<PdfDict<'a>>,
    pub startxrefs: Vec<u64>,
    pub deviations: Vec<Deviation>,
    pub decoded_buffers: Vec<Vec<u8>>,
}

impl<'a> ObjectGraph<'a> {
    pub fn resolve_ref(&self, obj: &PdfObj<'a>) -> Option<ObjEntry<'a>> {
        match obj.atom {
            PdfAtom::Ref { obj, gen } => self.get_object(obj, gen).cloned(),
            _ => None,
        }
    }

    pub fn get_object(&self, obj: u32, gen: u16) -> Option<&ObjEntry<'a>> {
        self.index
            .get(&(obj, gen))
            .and_then(|v| v.first().copied())
            .and_then(|idx| self.objects.get(idx))
    }

    pub fn all_objects_by_id(&self, obj: u32, gen: u16) -> Vec<&ObjEntry<'a>> {
        self.index
            .get(&(obj, gen))
            .into_iter()
            .flat_map(|v| v.iter())
            .filter_map(|idx| self.objects.get(*idx))
            .collect()
    }
}

pub fn parse_pdf(bytes: &[u8], options: ParseOptions) -> Result<ObjectGraph<'_>> {
    let startxrefs = find_startxrefs(bytes);
    let mut trailers = Vec::new();
    if let Some(last) = startxrefs.last().copied() {
        let chain = parse_xref_chain(bytes, last);
        for sec in chain.sections {
            if let Some(t) = sec.trailer {
                trailers.push(t);
            }
        }
    }
    let (mut objects, deviations) = scan_indirect_objects(bytes, options.strict);
    let mut decoded_buffers = Vec::new();
    if options.deep {
        let ObjStmExpansion { objects: mut extra, buffers } =
            expand_objstm(bytes, &objects, options.strict, options.max_objstm_bytes);
        objects.append(&mut extra);
        decoded_buffers = buffers;
    }
    let mut index: HashMap<(u32, u16), Vec<usize>> = HashMap::new();
    for (i, o) in objects.iter().enumerate() {
        index.entry((o.obj, o.gen)).or_default().push(i);
    }
    Ok(ObjectGraph {
        bytes,
        objects,
        index,
        trailers,
        startxrefs,
        deviations,
        decoded_buffers,
    })
}

fn find_startxrefs(bytes: &[u8]) -> Vec<u64> {
    let mut out = Vec::new();
    let needle = b"startxref";
    let mut i = 0usize;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let mut j = i + needle.len();
            while j < bytes.len() && (bytes[j] == b'\r' || bytes[j] == b'\n' || bytes[j] == b' ') {
                j += 1;
            }
            let mut num = Vec::new();
            while j < bytes.len() && (bytes[j] as char).is_ascii_digit() {
                num.push(bytes[j]);
                j += 1;
            }
            if let Ok(s) = std::str::from_utf8(&num) {
                if let Ok(v) = s.parse::<u64>() {
                    out.push(v);
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}
