use std::collections::HashMap;

use anyhow::Result;

use crate::classification::{classify_all_objects, ClassificationMap};
use crate::object::{PdfAtom, PdfDict, PdfObj};
use crate::parser::scan_indirect_objects;
use crate::span::Span;
use crate::xref::parse_xref_chain;
use crate::objstm::{expand_objstm, ObjStmExpansion};
use tracing::{debug, info};

#[derive(Debug, Clone, Copy)]
pub struct ParseOptions {
    pub recover_xref: bool,
    pub deep: bool,
    pub strict: bool,
    pub max_objstm_bytes: usize,
    pub max_objects: usize,
    pub max_objstm_total_bytes: usize,
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
        debug!(
            startxrefs = startxrefs.len(),
            sections = chain.sections.len(),
            "Parsed xref chain"
        );
    }
    let (mut objects, deviations) =
        scan_indirect_objects(bytes, options.strict, options.max_objects);
    debug!(
        objects = objects.len(),
        deviations = deviations.len(),
        "Scanned indirect objects"
    );

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
    Ok(ObjectGraph {
        bytes,
        objects,
        index,
        trailers,
        startxrefs,
        deviations,
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
