use std::collections::HashMap;

use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj, PdfStr};
use sis_pdf_pdf::ObjectGraph;

#[derive(Debug, Clone)]
pub struct EmbeddedArtefactRef {
    pub stream_ref: (u32, u16),
    pub filespec_ref: Option<(u32, u16)>,
    pub filename: Option<String>,
}

pub fn build_embedded_artefact_index(
    graph: &ObjectGraph<'_>,
) -> HashMap<(u32, u16), EmbeddedArtefactRef> {
    let mut index = HashMap::new();

    for entry in &graph.objects {
        collect_embedded_mappings_from_atom(&entry.atom, (entry.obj, entry.gen), &mut index);
    }

    index
}

fn collect_embedded_mappings_from_atom(
    atom: &PdfAtom<'_>,
    container_ref: (u32, u16),
    index: &mut HashMap<(u32, u16), EmbeddedArtefactRef>,
) {
    match atom {
        PdfAtom::Dict(dict) => {
            maybe_index_filespec(dict, container_ref, index);
            for (_, value) in &dict.entries {
                collect_embedded_mappings_from_atom(&value.atom, container_ref, index);
            }
        }
        PdfAtom::Stream(stream) => {
            maybe_index_filespec(&stream.dict, container_ref, index);
            for (_, value) in &stream.dict.entries {
                collect_embedded_mappings_from_atom(&value.atom, container_ref, index);
            }
        }
        PdfAtom::Array(values) => {
            for value in values {
                collect_embedded_mappings_from_atom(&value.atom, container_ref, index);
            }
        }
        _ => {}
    }
}

fn maybe_index_filespec(
    dict: &PdfDict<'_>,
    container_ref: (u32, u16),
    index: &mut HashMap<(u32, u16), EmbeddedArtefactRef>,
) {
    if !is_filespec_dict(dict) {
        return;
    }

    let filename = extract_filespec_filename(dict);
    let refs = extract_embedded_refs(dict);
    for stream_ref in refs {
        index.insert(
            stream_ref,
            EmbeddedArtefactRef {
                stream_ref,
                filespec_ref: Some(container_ref),
                filename: filename.clone(),
            },
        );
    }
}

fn is_filespec_dict(dict: &PdfDict<'_>) -> bool {
    dict.has_name(b"/Type", b"/Filespec") || dict.get_first(b"/EF").is_some()
}

fn extract_embedded_refs(dict: &PdfDict<'_>) -> Vec<(u32, u16)> {
    let Some((_, ef_obj)) = dict.get_first(b"/EF") else {
        return Vec::new();
    };
    let PdfAtom::Dict(ef_dict) = &ef_obj.atom else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for key in [b"/UF".as_slice(), b"/F".as_slice()] {
        if let Some((_, value)) = ef_dict.get_first(key) {
            if let PdfAtom::Ref { obj, gen } = value.atom {
                out.push((obj, gen));
            }
        }
    }
    out
}

fn extract_filespec_filename(dict: &PdfDict<'_>) -> Option<String> {
    for key in [b"/UF".as_slice(), b"/F".as_slice()] {
        if let Some((_, value)) = dict.get_first(key) {
            if let Some(decoded) = decode_obj_text(value) {
                if !decoded.is_empty() {
                    return Some(decoded);
                }
            }
        }
    }
    None
}

fn decode_obj_text(obj: &PdfObj<'_>) -> Option<String> {
    match &obj.atom {
        PdfAtom::Str(value) => Some(decode_pdf_text_string(&string_bytes(value))),
        PdfAtom::Name(name) => Some(String::from_utf8_lossy(&name.decoded).to_string()),
        _ => None,
    }
}

fn string_bytes(value: &PdfStr<'_>) -> Vec<u8> {
    match value {
        PdfStr::Literal { decoded, .. } | PdfStr::Hex { decoded, .. } => decoded.clone(),
    }
}

fn decode_pdf_text_string(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        let mut chars = Vec::new();
        let mut i = 2usize;
        while i + 1 < bytes.len() {
            let code = u16::from_be_bytes([bytes[i], bytes[i + 1]]);
            chars.push(code);
            i += 2;
        }
        return String::from_utf16_lossy(&chars);
    }
    String::from_utf8_lossy(bytes).to_string()
}

#[cfg(test)]
mod tests {
    use super::build_embedded_artefact_index;
    use sis_pdf_pdf::graph::{ObjEntry, ObjProvenance, ObjectGraph};
    use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfName, PdfObj, PdfStr};
    use sis_pdf_pdf::span::Span;
    use std::borrow::Cow;
    use std::collections::HashMap;

    fn pdf_name(name: &'static str) -> PdfName<'static> {
        PdfName {
            span: Span { start: 0, end: name.len() as u64 },
            raw: Cow::Borrowed(name.as_bytes()),
            decoded: name.as_bytes().to_vec(),
        }
    }

    fn literal_str(value: &'static str) -> PdfStr<'static> {
        PdfStr::Literal {
            span: Span { start: 0, end: value.len() as u64 },
            raw: Cow::Borrowed(value.as_bytes()),
            decoded: value.as_bytes().to_vec(),
        }
    }

    fn obj(atom: PdfAtom<'static>) -> PdfObj<'static> {
        PdfObj { span: Span { start: 0, end: 0 }, atom }
    }

    #[test]
    fn maps_embedded_stream_to_filespec_filename() {
        let filespec = PdfDict {
            span: Span { start: 0, end: 0 },
            entries: vec![
                (pdf_name("/Type"), obj(PdfAtom::Name(pdf_name("/Filespec")))),
                (pdf_name("/F"), obj(PdfAtom::Str(literal_str("hello.bat")))),
                (
                    pdf_name("/EF"),
                    obj(PdfAtom::Dict(PdfDict {
                        span: Span { start: 0, end: 0 },
                        entries: vec![(pdf_name("/F"), obj(PdfAtom::Ref { obj: 11, gen: 0 }))],
                    })),
                ),
            ],
        };
        let objects = vec![
            ObjEntry {
                obj: 10,
                gen: 0,
                atom: PdfAtom::Dict(filespec),
                header_span: Span { start: 0, end: 0 },
                body_span: Span { start: 0, end: 0 },
                full_span: Span { start: 0, end: 0 },
                provenance: ObjProvenance::Indirect,
            },
            ObjEntry {
                obj: 11,
                gen: 0,
                atom: PdfAtom::Stream(sis_pdf_pdf::object::PdfStream {
                    dict: PdfDict {
                        span: Span { start: 0, end: 0 },
                        entries: vec![(
                            pdf_name("/Type"),
                            obj(PdfAtom::Name(pdf_name("/EmbeddedFile"))),
                        )],
                    },
                    data_span: Span { start: 0, end: 0 },
                }),
                header_span: Span { start: 0, end: 0 },
                body_span: Span { start: 0, end: 0 },
                full_span: Span { start: 0, end: 0 },
                provenance: ObjProvenance::Indirect,
            },
        ];
        let mut object_index = HashMap::new();
        object_index.insert((10, 0), vec![0]);
        object_index.insert((11, 0), vec![1]);
        let graph = ObjectGraph {
            bytes: b"%PDF-1.4\n",
            objects,
            index: object_index,
            trailers: Vec::new(),
            startxrefs: Vec::new(),
            xref_sections: Vec::new(),
            deviations: Vec::new(),
            telemetry_events: Vec::new(),
        };
        let embedded = build_embedded_artefact_index(&graph);
        let record = embedded.get(&(11, 0)).expect("embedded mapping");
        assert_eq!(record.filename.as_deref(), Some("hello.bat"));
        assert_eq!(record.filespec_ref, Some((10, 0)));
    }

    #[test]
    fn maps_embedded_stream_from_names_tree_inline_filespec() {
        let filespec_inline = PdfAtom::Dict(PdfDict {
            span: Span { start: 0, end: 0 },
            entries: vec![
                (pdf_name("/Type"), obj(PdfAtom::Name(pdf_name("/Filespec")))),
                (pdf_name("/F"), obj(PdfAtom::Str(literal_str("hello.ps1")))),
                (
                    pdf_name("/EF"),
                    obj(PdfAtom::Dict(PdfDict {
                        span: Span { start: 0, end: 0 },
                        entries: vec![(pdf_name("/F"), obj(PdfAtom::Ref { obj: 12, gen: 0 }))],
                    })),
                ),
            ],
        });
        let names_tree = PdfDict {
            span: Span { start: 0, end: 0 },
            entries: vec![(
                pdf_name("/Names"),
                obj(PdfAtom::Array(vec![
                    obj(PdfAtom::Str(literal_str("hello.ps1"))),
                    obj(filespec_inline),
                ])),
            )],
        };
        let objects = vec![
            ObjEntry {
                obj: 10,
                gen: 0,
                atom: PdfAtom::Dict(names_tree),
                header_span: Span { start: 0, end: 0 },
                body_span: Span { start: 0, end: 0 },
                full_span: Span { start: 0, end: 0 },
                provenance: ObjProvenance::Indirect,
            },
            ObjEntry {
                obj: 12,
                gen: 0,
                atom: PdfAtom::Stream(sis_pdf_pdf::object::PdfStream {
                    dict: PdfDict {
                        span: Span { start: 0, end: 0 },
                        entries: vec![(
                            pdf_name("/Type"),
                            obj(PdfAtom::Name(pdf_name("/EmbeddedFile"))),
                        )],
                    },
                    data_span: Span { start: 0, end: 0 },
                }),
                header_span: Span { start: 0, end: 0 },
                body_span: Span { start: 0, end: 0 },
                full_span: Span { start: 0, end: 0 },
                provenance: ObjProvenance::Indirect,
            },
        ];
        let mut object_index = HashMap::new();
        object_index.insert((10, 0), vec![0]);
        object_index.insert((12, 0), vec![1]);
        let graph = ObjectGraph {
            bytes: b"%PDF-1.4\n",
            objects,
            index: object_index,
            trailers: Vec::new(),
            startxrefs: Vec::new(),
            xref_sections: Vec::new(),
            deviations: Vec::new(),
            telemetry_events: Vec::new(),
        };
        let embedded = build_embedded_artefact_index(&graph);
        let record = embedded.get(&(12, 0)).expect("embedded mapping");
        assert_eq!(record.filename.as_deref(), Some("hello.ps1"));
        assert_eq!(record.filespec_ref, Some((10, 0)));
    }
}
