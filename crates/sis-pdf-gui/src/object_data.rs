use std::collections::HashMap;

use sis_pdf_pdf::classification::ClassificationMap;
use sis_pdf_pdf::decode::decode_stream;
use sis_pdf_pdf::graph::{Deviation, ObjectGraph, XrefSectionSummary};
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj, PdfStr};

/// Maximum bytes to attempt decoding per stream for display purposes.
const MAX_STREAM_DECODE: usize = 64 * 1024; // 64 KB

/// Owned summary of all objects extracted from a parsed PDF.
///
/// This captures displayable object information while the borrowed
/// `ObjectGraph` is still alive, so the GUI can access it after the
/// graph is dropped.
#[derive(Debug, Default)]
pub struct ObjectData {
    pub objects: Vec<ObjectSummary>,
    /// (obj, gen) to index into `objects`.
    pub index: HashMap<(u32, u16), usize>,
    pub xref_sections: Vec<XrefSectionInfo>,
    pub deviations: Vec<DeviationInfo>,
}

/// Owned summary of a single PDF object for display in the Object Inspector.
#[derive(Debug)]
pub struct ObjectSummary {
    pub obj: u32,
    pub gen: u16,
    pub obj_type: String,
    pub roles: Vec<String>,
    pub dict_entries: Vec<(String, String)>,
    pub has_stream: bool,
    pub stream_text: Option<String>,
    pub stream_filters: Vec<String>,
    pub stream_length: Option<usize>,
    pub references_from: Vec<(u32, u16)>,
    pub references_to: Vec<(u32, u16)>,
}

/// Owned copy of xref section metadata.
#[derive(Debug, Clone)]
pub struct XrefSectionInfo {
    pub offset: u64,
    pub kind: String,
    pub has_trailer: bool,
    pub prev: Option<u64>,
    pub trailer_size: Option<u64>,
    pub trailer_root: Option<String>,
}

/// Owned copy of a parser deviation.
#[derive(Debug, Clone)]
pub struct DeviationInfo {
    pub kind: String,
    pub offset: u64,
    pub note: Option<String>,
}

/// Extract owned object data from a parsed `ObjectGraph`.
pub fn extract_object_data(
    bytes: &[u8],
    graph: &ObjectGraph<'_>,
    classifications: &ClassificationMap,
) -> ObjectData {
    let mut objects = Vec::with_capacity(graph.objects.len());
    let mut index = HashMap::new();
    let mut all_refs: Vec<Vec<(u32, u16)>> = Vec::with_capacity(graph.objects.len());

    // First pass: extract each object's summary
    for entry in &graph.objects {
        let key = (entry.obj, entry.gen);

        // Skip duplicate object IDs — keep only the latest version (last in list)
        if index.contains_key(&key) {
            // Update the existing entry (later version overrides)
            let existing_idx = index[&key];
            let summary = extract_one_object(bytes, entry, classifications);
            all_refs[existing_idx] = summary.references_from.clone();
            objects[existing_idx] = summary;
            continue;
        }

        let summary = extract_one_object(bytes, entry, classifications);
        let idx = objects.len();
        all_refs.push(summary.references_from.clone());
        objects.push(summary);
        index.insert(key, idx);
    }

    // Second pass: build reverse references (references_to)
    for (src_idx, refs) in all_refs.iter().enumerate() {
        let src_key = (objects[src_idx].obj, objects[src_idx].gen);
        for target in refs {
            if let Some(&tgt_idx) = index.get(target) {
                objects[tgt_idx].references_to.push(src_key);
            }
        }
    }

    // Deduplicate references_to
    for obj in &mut objects {
        obj.references_to.sort();
        obj.references_to.dedup();
    }

    let xref_sections = graph.xref_sections.iter().map(xref_section_to_owned).collect();
    let deviations = graph.deviations.iter().map(deviation_to_owned).collect();

    ObjectData { objects, index, xref_sections, deviations }
}

fn extract_one_object(
    bytes: &[u8],
    entry: &sis_pdf_pdf::graph::ObjEntry<'_>,
    classifications: &ClassificationMap,
) -> ObjectSummary {
    let key = (entry.obj, entry.gen);

    let (obj_type, roles) = classifications
        .get(&key)
        .map(|c| {
            let roles: Vec<String> = c.roles.iter().map(|r| r.as_str().to_string()).collect();
            (c.obj_type.as_str().to_string(), roles)
        })
        .unwrap_or_else(|| ("other".to_string(), Vec::new()));

    let mut dict_entries = Vec::new();
    let mut has_stream = false;
    let mut stream_text = None;
    let mut stream_filters = Vec::new();
    let mut stream_length = None;
    let mut references_from = Vec::new();

    match &entry.atom {
        PdfAtom::Dict(d) => {
            dict_entries = extract_dict_entries(d);
            collect_refs_from_dict(d, &mut references_from);
        }
        PdfAtom::Stream(s) => {
            has_stream = true;
            dict_entries = extract_dict_entries(&s.dict);
            collect_refs_from_dict(&s.dict, &mut references_from);
            stream_filters = sis_pdf_pdf::decode::stream_filters(&s.dict);

            // Compute raw stream length from span
            let raw_len = (s.data_span.end as usize).saturating_sub(s.data_span.start as usize);
            stream_length = Some(raw_len);

            // Try to decode and display as text
            if let Ok(decoded) = decode_stream(bytes, s, MAX_STREAM_DECODE) {
                if let Ok(text) = std::str::from_utf8(&decoded.data) {
                    let truncated = if text.len() > MAX_STREAM_DECODE {
                        &text[..MAX_STREAM_DECODE]
                    } else {
                        text
                    };
                    stream_text = Some(truncated.to_string());
                }
            }
        }
        PdfAtom::Array(arr) => {
            for (i, obj) in arr.iter().enumerate() {
                let val = atom_to_display_string(&obj.atom);
                dict_entries.push((format!("[{}]", i), val));
                collect_refs_from_obj(obj, &mut references_from);
            }
        }
        PdfAtom::Ref { obj, gen } => {
            references_from.push((*obj, *gen));
        }
        _ => {}
    }

    references_from.sort();
    references_from.dedup();

    ObjectSummary {
        obj: entry.obj,
        gen: entry.gen,
        obj_type,
        roles,
        dict_entries,
        has_stream,
        stream_text,
        stream_filters,
        stream_length,
        references_from,
        references_to: Vec::new(),
    }
}

fn extract_dict_entries(dict: &PdfDict<'_>) -> Vec<(String, String)> {
    dict.entries
        .iter()
        .map(|(name, obj)| {
            let key = String::from_utf8_lossy(&name.decoded).to_string();
            let val = atom_to_display_string(&obj.atom);
            (key, val)
        })
        .collect()
}

fn atom_to_display_string(atom: &PdfAtom<'_>) -> String {
    match atom {
        PdfAtom::Null => "null".to_string(),
        PdfAtom::Bool(b) => b.to_string(),
        PdfAtom::Int(i) => i.to_string(),
        PdfAtom::Real(r) => format!("{}", r),
        PdfAtom::Name(n) => String::from_utf8_lossy(&n.decoded).to_string(),
        PdfAtom::Str(s) => {
            let decoded = match s {
                PdfStr::Literal { decoded, .. } => decoded,
                PdfStr::Hex { decoded, .. } => decoded,
            };
            match std::str::from_utf8(decoded) {
                Ok(text) => {
                    if text.len() > 200 {
                        format!("({:.200}...)", text)
                    } else {
                        format!("({})", text)
                    }
                }
                Err(_) => format!("<{} bytes>", decoded.len()),
            }
        }
        PdfAtom::Ref { obj, gen } => format!("{} {} R", obj, gen),
        PdfAtom::Array(arr) => {
            if arr.len() <= 8 {
                let items: Vec<String> =
                    arr.iter().map(|o| atom_to_display_string(&o.atom)).collect();
                format!("[{}]", items.join(", "))
            } else {
                format!("[{} items]", arr.len())
            }
        }
        PdfAtom::Dict(d) => format!("<< {} entries >>", d.entries.len()),
        PdfAtom::Stream(s) => format!("<< {} entries >> stream", s.dict.entries.len()),
    }
}

fn collect_refs_from_dict(dict: &PdfDict<'_>, refs: &mut Vec<(u32, u16)>) {
    for (_, obj) in &dict.entries {
        collect_refs_from_obj(obj, refs);
    }
}

fn collect_refs_from_obj(obj: &PdfObj<'_>, refs: &mut Vec<(u32, u16)>) {
    match &obj.atom {
        PdfAtom::Ref { obj, gen } => {
            refs.push((*obj, *gen));
        }
        PdfAtom::Array(arr) => {
            for item in arr {
                collect_refs_from_obj(item, refs);
            }
        }
        PdfAtom::Dict(d) => {
            collect_refs_from_dict(d, refs);
        }
        PdfAtom::Stream(s) => {
            collect_refs_from_dict(&s.dict, refs);
        }
        _ => {}
    }
}

fn xref_section_to_owned(sec: &XrefSectionSummary) -> XrefSectionInfo {
    XrefSectionInfo {
        offset: sec.offset,
        kind: sec.kind.clone(),
        has_trailer: sec.has_trailer,
        prev: sec.prev,
        trailer_size: sec.trailer_size,
        trailer_root: sec.trailer_root.clone(),
    }
}

fn deviation_to_owned(dev: &Deviation) -> DeviationInfo {
    DeviationInfo { kind: dev.kind.clone(), offset: dev.span.start, note: dev.note.clone() }
}
