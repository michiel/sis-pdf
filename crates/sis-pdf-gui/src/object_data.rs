use std::collections::HashMap;

use sis_pdf_pdf::blob_classify::{classify_blob, BlobKind};
use sis_pdf_pdf::classification::ClassificationMap;
use sis_pdf_pdf::decode::decode_stream;
use sis_pdf_pdf::graph::{Deviation, ObjectGraph, ParseOptions, XrefSectionSummary};
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj, PdfStr};

use crate::image_preview::{build_preview_for_stream, ImagePreviewStatus, PreviewLimits};

/// Maximum bytes to attempt decoding per stream for display purposes.
const MAX_STREAM_DECODE: usize = 64 * 1024; // 64 KB

#[derive(Debug, Clone, Copy)]
pub struct ObjectExtractOptions {
    pub include_decoded_stream_bytes: bool,
    pub include_image_preview: bool,
    pub include_preview_status_details: bool,
}

impl ObjectExtractOptions {
    pub const FULL: Self = Self {
        include_decoded_stream_bytes: true,
        include_image_preview: false,
        include_preview_status_details: true,
    };
    pub const WORKER_COMPACT: Self = Self {
        include_decoded_stream_bytes: false,
        include_image_preview: false,
        include_preview_status_details: false,
    };
}

/// Owned summary of all objects extracted from a parsed PDF.
///
/// This captures displayable object information while the borrowed
/// `ObjectGraph` is still alive, so the GUI can access it after the
/// graph is dropped.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ObjectData {
    pub objects: Vec<ObjectSummary>,
    /// (obj, gen) to index into `objects`.
    #[serde(skip_serializing, skip_deserializing, default)]
    pub index: HashMap<(u32, u16), usize>,
    pub xref_sections: Vec<XrefSectionInfo>,
    pub deviations: Vec<DeviationInfo>,
}

impl ObjectData {
    pub fn rebuild_index(&mut self) {
        self.index.clear();
        for (idx, object) in self.objects.iter().enumerate() {
            self.index.insert((object.obj, object.gen), idx);
        }
    }
}

/// Owned summary of a single PDF object for display in the Object Inspector.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ObjectSummary {
    pub obj: u32,
    pub gen: u16,
    pub obj_type: String,
    pub roles: Vec<String>,
    pub dict_entries: Vec<(String, String)>,
    #[serde(default)]
    pub dict_entries_tree: Vec<(String, ObjectValue)>,
    pub has_stream: bool,
    pub stream_text: Option<String>,
    pub stream_raw: Option<Vec<u8>>,
    pub stream_filters: Vec<String>,
    pub stream_length: Option<usize>,
    pub stream_data_span: Option<(usize, usize)>,
    pub stream_content_type: Option<String>,
    pub image_width: Option<u32>,
    pub image_height: Option<u32>,
    pub image_bits: Option<u32>,
    pub image_color_space: Option<String>,
    /// JPEG image preview: (width, height, RGBA pixels).
    pub image_preview: Option<(u32, u32, Vec<u8>)>,
    #[serde(default)]
    pub image_preview_status: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preview_statuses: Vec<ImagePreviewStatus>,
    #[serde(default)]
    pub preview_summary: Option<String>,
    #[serde(default)]
    pub preview_source: Option<String>,
    pub references_from: Vec<(u32, u16)>,
    pub references_to: Vec<(u32, u16)>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ObjectValue {
    Null,
    Bool(bool),
    Int(i64),
    Real(f64),
    Name(String),
    Str(String),
    Ref { obj: u32, gen: u16 },
    Array(Vec<ObjectValue>),
    Dict(Vec<(String, ObjectValue)>),
    Stream { dict: Vec<(String, ObjectValue)> },
    Summary(String),
}

/// Owned copy of xref section metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct XrefSectionInfo {
    pub offset: u64,
    pub kind: String,
    pub has_trailer: bool,
    pub prev: Option<u64>,
    pub trailer_size: Option<u64>,
    pub trailer_root: Option<String>,
}

/// Owned copy of a parser deviation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    extract_object_data_with_options(bytes, graph, classifications, ObjectExtractOptions::FULL)
}

/// Extract owned object data with configurable payload size controls.
pub fn extract_object_data_with_options(
    bytes: &[u8],
    graph: &ObjectGraph<'_>,
    classifications: &ClassificationMap,
    options: ObjectExtractOptions,
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
            let summary = extract_one_object(bytes, graph, entry, classifications, options);
            all_refs[existing_idx] = summary.references_from.clone();
            objects[existing_idx] = summary;
            continue;
        }

        let summary = extract_one_object(bytes, graph, entry, classifications, options);
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
    #[allow(unused_variables)] graph: &ObjectGraph<'_>,
    entry: &sis_pdf_pdf::graph::ObjEntry<'_>,
    classifications: &ClassificationMap,
    options: ObjectExtractOptions,
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
    let mut dict_entries_tree = Vec::new();
    let mut has_stream = false;
    let mut stream_text = None;
    let mut stream_raw = None;
    let mut stream_filters = Vec::new();
    let mut stream_length = None;
    let mut stream_data_span = None;
    let mut stream_content_type = None;
    let mut image_width = None;
    let mut image_height = None;
    let mut image_bits = None;
    let mut image_color_space = None;
    #[allow(unused_mut)]
    let mut image_preview: Option<(u32, u32, Vec<u8>)> = None;
    let mut image_preview_status: Option<String> = None;
    let mut preview_statuses: Vec<ImagePreviewStatus> = Vec::new();
    let mut preview_summary: Option<String> = None;
    let mut preview_source: Option<String> = None;
    let mut references_from = Vec::new();

    match &entry.atom {
        PdfAtom::Dict(d) => {
            dict_entries_tree = extract_dict_entries_tree(d);
            dict_entries = flatten_dict_entries(&dict_entries_tree);
            collect_refs_from_dict(d, &mut references_from);
        }
        PdfAtom::Stream(s) => {
            has_stream = true;
            dict_entries_tree = extract_dict_entries_tree(&s.dict);
            dict_entries = flatten_dict_entries(&dict_entries_tree);
            collect_refs_from_dict(&s.dict, &mut references_from);
            stream_filters = sis_pdf_pdf::decode::stream_filters(&s.dict);

            // Compute raw stream length from span
            let start = s.data_span.start as usize;
            let end = s.data_span.end as usize;
            let raw_len = end.saturating_sub(start);
            stream_length = Some(raw_len);
            stream_data_span = Some((start, end));

            // Extract image metadata from dictionary for image objects without requiring decode.
            if obj_type == "image" {
                image_width = dict_entry_as_u32(&dict_entries, "Width");
                image_height = dict_entry_as_u32(&dict_entries, "Height");
                image_bits = dict_entry_as_u32(&dict_entries, "BitsPerComponent");
                image_color_space = dict_entry_as_name(&dict_entries, "ColorSpace");
            }

            // Compact worker extraction is metadata-only: skip decode to avoid large-PDF stalls.
            let should_decode_stream = options.include_decoded_stream_bytes || obj_type != "image";
            let decoded_stream = if should_decode_stream {
                let decode_budget = if obj_type == "image" && options.include_image_preview {
                    PreviewLimits::default().max_stream_decode_bytes
                } else {
                    MAX_STREAM_DECODE
                };
                decode_stream(bytes, s, decode_budget).ok()
            } else {
                None
            };

            if let Some(decoded) = &decoded_stream {
                // Classify the decoded stream content
                let blob_kind = classify_blob(&decoded.data);
                if blob_kind != BlobKind::Unknown {
                    stream_content_type = Some(blob_kind.as_str().to_string());
                }

                if options.include_decoded_stream_bytes {
                    stream_raw = Some(decoded.data.clone());
                }
                if let Ok(text) = std::str::from_utf8(&decoded.data) {
                    let truncated = if text.len() > MAX_STREAM_DECODE {
                        &text[..MAX_STREAM_DECODE]
                    } else {
                        text
                    };
                    stream_text = Some(truncated.to_string());
                }
            }

            if obj_type == "image" {
                if options.include_image_preview {
                    let built = build_preview_for_stream(
                        bytes,
                        s,
                        graph,
                        PreviewLimits::default(),
                        decoded_stream.as_ref().map(|decoded| decoded.data.as_slice()),
                    );
                    image_preview = built.preview;
                    image_preview_status = Some(built.summary.clone());
                    preview_summary = Some(built.summary);
                    preview_statuses = built.statuses;
                    preview_source = built.source_used;
                } else {
                    image_preview_status = Some("Preview on demand".to_string());
                    preview_summary = image_preview_status.clone();
                    if options.include_preview_status_details {
                        preview_statuses.push(ImagePreviewStatus {
                            stage: crate::image_preview::ImagePreviewStage::RawProbe,
                            outcome: crate::image_preview::ImagePreviewOutcome::SkippedBudget,
                            detail: "Preview generation deferred to on-demand dialog".to_string(),
                            source: None,
                            input_bytes: None,
                            output_bytes: None,
                            elapsed_ms: None,
                        });
                    }
                }
            }
        }
        PdfAtom::Array(arr) => {
            for (i, obj) in arr.iter().enumerate() {
                let value = atom_to_object_value(&obj.atom, 0);
                let val = object_value_summary(&value);
                dict_entries.push((format!("[{}]", i), val));
                dict_entries_tree.push((format!("[{}]", i), value));
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
        dict_entries_tree,
        has_stream,
        stream_text,
        stream_raw,
        stream_filters,
        stream_length,
        stream_data_span,
        stream_content_type,
        image_width,
        image_height,
        image_bits,
        image_color_space,
        image_preview,
        image_preview_status,
        preview_statuses,
        preview_summary,
        preview_source,
        references_from,
        references_to: Vec::new(),
    }
}

pub fn decode_stream_for_object(
    bytes: &[u8],
    obj: u32,
    gen: u16,
    max_decode_bytes: usize,
) -> Option<Vec<u8>> {
    let parse_opts = ParseOptions {
        recover_xref: true,
        deep: false,
        strict: false,
        max_objstm_bytes: max_decode_bytes,
        max_objects: 250_000,
        max_objstm_total_bytes: max_decode_bytes.saturating_mul(4),
        carve_stream_objects: false,
        max_carved_objects: 0,
        max_carved_bytes: 0,
    };
    let graph = sis_pdf_pdf::graph::parse_pdf(bytes, parse_opts).ok()?;
    let entry = graph.objects.iter().find(|entry| entry.obj == obj && entry.gen == gen)?;
    let PdfAtom::Stream(stream) = &entry.atom else {
        return None;
    };
    let decoded = decode_stream(bytes, stream, max_decode_bytes).ok()?;
    Some(decoded.data)
}

const MAX_OBJECT_VALUE_DEPTH: usize = 12;
const MAX_OBJECT_VALUE_ITEMS: usize = 128;

fn extract_dict_entries_tree(dict: &PdfDict<'_>) -> Vec<(String, ObjectValue)> {
    dict.entries
        .iter()
        .map(|(name, obj)| {
            let key = String::from_utf8_lossy(&name.decoded).to_string();
            let val = atom_to_object_value(&obj.atom, 0);
            (key, val)
        })
        .collect()
}

fn flatten_dict_entries(entries: &[(String, ObjectValue)]) -> Vec<(String, String)> {
    entries.iter().map(|(key, value)| (key.clone(), object_value_summary(value))).collect()
}

fn atom_to_object_value(atom: &PdfAtom<'_>, depth: usize) -> ObjectValue {
    if depth >= MAX_OBJECT_VALUE_DEPTH {
        return ObjectValue::Summary("<max depth reached>".to_string());
    }

    match atom {
        PdfAtom::Null => ObjectValue::Null,
        PdfAtom::Bool(b) => ObjectValue::Bool(*b),
        PdfAtom::Int(i) => ObjectValue::Int(*i),
        PdfAtom::Real(r) => ObjectValue::Real(*r),
        PdfAtom::Name(n) => ObjectValue::Name(String::from_utf8_lossy(&n.decoded).to_string()),
        PdfAtom::Str(s) => {
            let decoded = match s {
                PdfStr::Literal { decoded, .. } => decoded,
                PdfStr::Hex { decoded, .. } => decoded,
            };
            match std::str::from_utf8(decoded) {
                Ok(text) => {
                    if text.len() > 200 {
                        ObjectValue::Str(format!("({:.200}...)", text))
                    } else {
                        ObjectValue::Str(format!("({})", text))
                    }
                }
                Err(_) => ObjectValue::Summary(format!("<{} bytes>", decoded.len())),
            }
        }
        PdfAtom::Ref { obj, gen } => ObjectValue::Ref { obj: *obj, gen: *gen },
        PdfAtom::Array(arr) => {
            let mut items = arr
                .iter()
                .take(MAX_OBJECT_VALUE_ITEMS)
                .map(|o| atom_to_object_value(&o.atom, depth + 1))
                .collect::<Vec<_>>();
            let remaining = arr.len().saturating_sub(items.len());
            if remaining > 0 {
                items.push(ObjectValue::Summary(format!("<{} more items>", remaining)));
            }
            ObjectValue::Array(items)
        }
        PdfAtom::Dict(d) => {
            let mut entries = d
                .entries
                .iter()
                .take(MAX_OBJECT_VALUE_ITEMS)
                .map(|(name, obj)| {
                    (
                        String::from_utf8_lossy(&name.decoded).to_string(),
                        atom_to_object_value(&obj.atom, depth + 1),
                    )
                })
                .collect::<Vec<_>>();
            let remaining = d.entries.len().saturating_sub(entries.len());
            if remaining > 0 {
                entries.push((
                    "...".to_string(),
                    ObjectValue::Summary(format!("<{} more entries>", remaining)),
                ));
            }
            ObjectValue::Dict(entries)
        }
        PdfAtom::Stream(s) => {
            let mut entries = s
                .dict
                .entries
                .iter()
                .take(MAX_OBJECT_VALUE_ITEMS)
                .map(|(name, obj)| {
                    (
                        String::from_utf8_lossy(&name.decoded).to_string(),
                        atom_to_object_value(&obj.atom, depth + 1),
                    )
                })
                .collect::<Vec<_>>();
            let remaining = s.dict.entries.len().saturating_sub(entries.len());
            if remaining > 0 {
                entries.push((
                    "...".to_string(),
                    ObjectValue::Summary(format!("<{} more entries>", remaining)),
                ));
            }
            ObjectValue::Stream { dict: entries }
        }
    }
}

fn object_value_summary(value: &ObjectValue) -> String {
    match value {
        ObjectValue::Null => "null".to_string(),
        ObjectValue::Bool(value) => value.to_string(),
        ObjectValue::Int(value) => value.to_string(),
        ObjectValue::Real(value) => format!("{value}"),
        ObjectValue::Name(value) => value.clone(),
        ObjectValue::Str(value) => value.clone(),
        ObjectValue::Ref { obj, gen } => format!("{obj} {gen} R"),
        ObjectValue::Array(items) => {
            if items.len() <= 8 {
                let joined = items.iter().map(object_value_summary).collect::<Vec<_>>().join(", ");
                format!("[{joined}]")
            } else {
                format!("[{} items]", items.len())
            }
        }
        ObjectValue::Dict(entries) => format!("<< {} entries >>", entries.len()),
        ObjectValue::Stream { dict } => format!("<< {} entries >> stream", dict.len()),
        ObjectValue::Summary(value) => value.clone(),
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

/// Look up a dictionary entry value as u32 (for Width, Height, BitsPerComponent).
fn dict_entry_as_u32(entries: &[(String, String)], key: &str) -> Option<u32> {
    entries.iter().find(|(k, _)| k == key).and_then(|(_, v)| v.trim().parse::<u32>().ok())
}

/// Look up a dictionary entry value as a name string (for ColorSpace).
fn dict_entry_as_name(entries: &[(String, String)], key: &str) -> Option<String> {
    entries.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sis_pdf_pdf::object::PdfName;
    use sis_pdf_pdf::span::Span;
    use std::borrow::Cow;

    fn span() -> Span {
        Span { start: 0, end: 0 }
    }

    fn name(decoded: &[u8]) -> PdfName<'static> {
        PdfName { span: span(), raw: Cow::Owned(decoded.to_vec()), decoded: decoded.to_vec() }
    }

    fn obj(atom: PdfAtom<'static>) -> PdfObj<'static> {
        PdfObj { span: span(), atom }
    }

    #[test]
    fn extract_dict_entries_tree_keeps_nested_group_dictionary() {
        let group = PdfDict {
            span: span(),
            entries: vec![
                (name(b"/S"), obj(PdfAtom::Name(name(b"/Transparency")))),
                (name(b"/CS"), obj(PdfAtom::Name(name(b"/DeviceRGB")))),
                (name(b"/I"), obj(PdfAtom::Bool(true))),
            ],
        };
        let outer = PdfDict {
            span: span(),
            entries: vec![
                (name(b"/Type"), obj(PdfAtom::Name(name(b"/Page")))),
                (name(b"/Group"), obj(PdfAtom::Dict(group))),
            ],
        };

        let tree = extract_dict_entries_tree(&outer);
        let mut group_entries_len = None;
        for (key, value) in &tree {
            if key == "/Group" {
                if let ObjectValue::Dict(entries) = value {
                    group_entries_len = Some(entries.len());
                }
            }
        }

        assert_eq!(group_entries_len, Some(3));
    }

    #[test]
    fn flatten_dict_entries_uses_container_summary() {
        let entries = vec![(
            "/Group".to_string(),
            ObjectValue::Dict(vec![(
                "/S".to_string(),
                ObjectValue::Name("/Transparency".to_string()),
            )]),
        )];

        let flat = flatten_dict_entries(&entries);
        assert_eq!(flat.len(), 1);
        assert_eq!(flat[0].0, "/Group");
        assert_eq!(flat[0].1, "<< 1 entries >>");
    }
}
