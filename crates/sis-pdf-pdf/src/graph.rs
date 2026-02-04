use std::collections::HashMap;

use anyhow::Result;

use crate::classification::{classify_all_objects, ClassificationMap};
use crate::object::{PdfAtom, PdfDict, PdfObj};
use crate::objstm::{expand_objstm, ObjStmExpansion};
use crate::parser::{parse_indirect_object_at, scan_indirect_objects};
use crate::span::Span;
use crate::xref::parse_xref_chain;
use tracing::{debug, info};

#[derive(Debug, Clone, Copy)]
pub struct ParseOptions {
    pub recover_xref: bool,
    pub deep: bool,
    pub strict: bool,
    pub max_objstm_bytes: usize,
    pub max_objects: usize,
    pub max_objstm_total_bytes: usize,
    pub carve_stream_objects: bool,
    pub max_carved_objects: usize,
    pub max_carved_bytes: usize,
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
    pub provenance: ObjProvenance,
}

#[derive(Debug, Clone, Copy)]
pub enum ObjProvenance {
    Indirect,
    ObjStm { obj: u32, gen: u16 },
    CarvedStream { obj: u32, gen: u16 },
}

#[derive(Debug)]
pub struct ObjectGraph<'a> {
    pub bytes: &'a [u8],
    pub objects: Vec<ObjEntry<'a>>,
    pub index: HashMap<(u32, u16), Vec<usize>>,
    pub trailers: Vec<PdfDict<'a>>,
    pub startxrefs: Vec<u64>,
    pub deviations: Vec<Deviation>,
}

impl<'a> ObjectGraph<'a> {
    pub fn resolve_ref(&self, obj: &PdfObj<'a>) -> Option<ObjEntry<'a>> {
        match obj.atom {
            PdfAtom::Ref { obj, gen } => self.get_object(obj, gen).cloned(),
            _ => None,
        }
    }

    pub fn get_object(&self, obj: u32, gen: u16) -> Option<&ObjEntry<'a>> {
        // Use last() instead of first() to get the most recent version
        // In PDFs with incremental updates, later definitions override earlier ones
        // This prevents evasion via object ID shadowing
        self.index
            .get(&(obj, gen))
            .and_then(|v| v.last().copied())
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

    /// Classifies all objects in the graph
    ///
    /// This builds a classification map that identifies object types (Catalog, Page, Action, etc.)
    /// and roles (JsContainer, ActionTarget, etc.) for all objects in the document.
    ///
    /// # Returns
    ///
    /// A map from (obj, gen) to ClassifiedObject containing type and role information.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let graph = parse_pdf(bytes, options)?;
    /// let classifications = graph.classify_objects();
    ///
    /// for ((obj, gen), classified) in &classifications {
    ///     println!("Object {} {} is type: {}", obj, gen, classified.obj_type.as_str());
    ///     if classified.has_role(ObjectRole::JsContainer) {
    ///         println!("  Contains JavaScript!");
    ///     }
    /// }
    /// ```
    pub fn classify_objects(&self) -> ClassificationMap {
        classify_all_objects(&self.objects)
    }
}

pub fn parse_pdf(bytes: &[u8], options: ParseOptions) -> Result<ObjectGraph<'_>> {
    let parse_span = tracing::info_span!(
        "parse_pdf",
        bytes_len = bytes.len(),
        deep = options.deep,
        strict = options.strict,
        recover_xref = options.recover_xref
    );
    let _parse_guard = parse_span.enter();
    info!("Parsing PDF object graph");
    let startxrefs = find_startxrefs(bytes);
    let mut trailers = Vec::new();
    if let Some(last) = startxrefs.last().copied() {
        let chain = parse_xref_chain(bytes, last);
        for sec in &chain.sections {
            if let Some(t) = sec.trailer.as_ref() {
                trailers.push(t.clone());
            }
        }
        debug!(startxrefs = startxrefs.len(), sections = chain.sections.len(), "Parsed xref chain");
    }
    let (mut objects, deviations) =
        scan_indirect_objects(bytes, options.strict, options.max_objects);
    debug!(objects = objects.len(), deviations = deviations.len(), "Scanned indirect objects");

    // Always expand object streams to detect hidden JavaScript and other content
    // Resource limits (max 100 ObjStm, byte limits) prevent DoS
    let ObjStmExpansion { objects: mut extra } = expand_objstm(
        bytes,
        &objects,
        options.strict,
        options.max_objstm_bytes,
        options.max_objects,
        options.max_objstm_total_bytes,
    );
    objects.append(&mut extra);
    if options.carve_stream_objects {
        let mut carved = carve_stream_objects(bytes, &objects, &options);
        objects.append(&mut carved);
    }
    let mut index: HashMap<(u32, u16), Vec<usize>> = HashMap::new();
    for (i, o) in objects.iter().enumerate() {
        index.entry((o.obj, o.gen)).or_default().push(i);
    }
    info!(
        objects = objects.len(),
        startxrefs = startxrefs.len(),
        trailers = trailers.len(),
        "Parsed PDF object graph"
    );
    Ok(ObjectGraph { bytes, objects, index, trailers, startxrefs, deviations })
}

fn carve_stream_objects<'a>(
    bytes: &'a [u8],
    objects: &[ObjEntry<'a>],
    options: &ParseOptions,
) -> Vec<ObjEntry<'a>> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut total = 0usize;
    for entry in objects {
        if options.max_objects > 0 && objects.len() + out.len() >= options.max_objects {
            break;
        }
        if total >= options.max_carved_objects {
            break;
        }
        let PdfAtom::Stream(stream) = &entry.atom else {
            continue;
        };
        if stream.dict.has_name(b"/Type", b"/ObjStm") {
            continue;
        }
        let start = stream.data_span.start as usize;
        let end = stream.data_span.end as usize;
        if start >= end || end > bytes.len() {
            continue;
        }
        let raw = &bytes[start..end];
        let max_len = options.max_carved_bytes.min(raw.len());
        let scan = &raw[..max_len];
        let mut i = 0usize;
        while i + 7 < scan.len() && total < options.max_carved_objects {
            if !scan[i].is_ascii_digit() {
                i += 1;
                continue;
            }
            let (res, _) = parse_indirect_object_at(scan, i, false);
            if let Ok((mut carved, end_pos)) = res {
                let offset = start as u64;
                carved.header_span.start += offset;
                carved.header_span.end += offset;
                carved.body_span.start += offset;
                carved.body_span.end += offset;
                carved.full_span.start += offset;
                carved.full_span.end += offset;
                carved.provenance = ObjProvenance::CarvedStream { obj: entry.obj, gen: entry.gen };
                let key = (carved.obj, carved.gen, carved.full_span.start, carved.full_span.end);
                if seen.insert(key) {
                    out.push(carved);
                    total += 1;
                }
                i = end_pos.max(i + 1);
            } else {
                i += 1;
            }
        }
    }
    out
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
