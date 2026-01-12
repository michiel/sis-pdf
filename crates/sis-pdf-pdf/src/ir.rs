use crate::decode::stream_filters;
use crate::graph::ObjEntry;
use crate::object::{PdfAtom, PdfDict, PdfName, PdfObj, PdfStr};

#[derive(Debug, Clone)]
pub struct IrOptions {
    pub max_lines_per_object: usize,
    pub max_string_len: usize,
    pub max_array_elems: usize,
}

impl Default for IrOptions {
    fn default() -> Self {
        Self {
            max_lines_per_object: 256,
            max_string_len: 120,
            max_array_elems: 12,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PdfIrLine {
    pub obj_ref: (u32, u16),
    pub path: String,
    pub value_type: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct PdfIrObject {
    pub obj_ref: (u32, u16),
    pub lines: Vec<PdfIrLine>,
    pub deviations: Vec<String>,
}

pub fn ir_for_object(entry: &ObjEntry<'_>, opts: &IrOptions) -> PdfIrObject {
    let mut lines = Vec::new();
    let obj_ref = (entry.obj, entry.gen);
    let mut deviations = Vec::new();
    let root_path = "$".to_string();
    emit_lines_for_atom(
        entry,
        &entry.atom,
        &root_path,
        opts,
        &mut lines,
        &mut deviations,
    );
    PdfIrObject {
        obj_ref,
        lines,
        deviations,
    }
}

pub fn ir_for_graph(objects: &[ObjEntry<'_>], opts: &IrOptions) -> Vec<PdfIrObject> {
    objects.iter().map(|e| ir_for_object(e, opts)).collect()
}

fn emit_lines_for_atom(
    entry: &ObjEntry<'_>,
    atom: &PdfAtom<'_>,
    path: &str,
    opts: &IrOptions,
    out: &mut Vec<PdfIrLine>,
    deviations: &mut Vec<String>,
) {
    if out.len() >= opts.max_lines_per_object {
        return;
    }
    match atom {
        PdfAtom::Dict(d) => {
            emit_lines_for_dict(entry, d, path, opts, out, deviations);
        }
        PdfAtom::Stream(st) => {
            let filters = stream_filters(&st.dict);
            let filter_list = if filters.is_empty() {
                "-".to_string()
            } else {
                filters.join(",")
            };
            let meta = format!("len={} filters={}", st.data_span.len(), filter_list);
            out.push(PdfIrLine {
                obj_ref: (entry.obj, entry.gen),
                path: path.to_string(),
                value_type: "stream".into(),
                value: meta,
            });
            emit_lines_for_dict(entry, &st.dict, path, opts, out, deviations);
        }
        PdfAtom::Array(items) => {
            let (value_type, value) = summarize_array(items, opts);
            out.push(PdfIrLine {
                obj_ref: (entry.obj, entry.gen),
                path: path.to_string(),
                value_type,
                value,
            });
        }
        PdfAtom::Ref { obj, gen } => {
            out.push(PdfIrLine {
                obj_ref: (entry.obj, entry.gen),
                path: path.to_string(),
                value_type: "ref".into(),
                value: format!("{}-{}", obj, gen),
            });
        }
        PdfAtom::Name(n) => {
            out.push(PdfIrLine {
                obj_ref: (entry.obj, entry.gen),
                path: path.to_string(),
                value_type: "name".into(),
                value: name_to_string(n),
            });
        }
        PdfAtom::Str(s) => {
            out.push(PdfIrLine {
                obj_ref: (entry.obj, entry.gen),
                path: path.to_string(),
                value_type: "str".into(),
                value: string_preview(s, opts.max_string_len),
            });
        }
        PdfAtom::Int(i) => {
            out.push(PdfIrLine {
                obj_ref: (entry.obj, entry.gen),
                path: path.to_string(),
                value_type: "num".into(),
                value: i.to_string(),
            });
        }
        PdfAtom::Real(f) => {
            out.push(PdfIrLine {
                obj_ref: (entry.obj, entry.gen),
                path: path.to_string(),
                value_type: "num".into(),
                value: format!("{:.6}", f),
            });
        }
        PdfAtom::Bool(b) => {
            out.push(PdfIrLine {
                obj_ref: (entry.obj, entry.gen),
                path: path.to_string(),
                value_type: "bool".into(),
                value: b.to_string(),
            });
        }
        PdfAtom::Null => {
            out.push(PdfIrLine {
                obj_ref: (entry.obj, entry.gen),
                path: path.to_string(),
                value_type: "null".into(),
                value: "null".into(),
            });
        }
    }
    if out.len() > opts.max_lines_per_object {
        deviations.push("ir_line_cap_reached".into());
        out.truncate(opts.max_lines_per_object);
    }
}

fn emit_lines_for_dict(
    entry: &ObjEntry<'_>,
    dict: &PdfDict<'_>,
    path: &str,
    opts: &IrOptions,
    out: &mut Vec<PdfIrLine>,
    deviations: &mut Vec<String>,
) {
    for (k, v) in &dict.entries {
        if out.len() >= opts.max_lines_per_object {
            break;
        }
        let key = name_to_string(k);
        let key_path = if path == "$" {
            format!("/{}", key.trim_start_matches('/'))
        } else {
            format!("{}/{}", path, key.trim_start_matches('/'))
        };
        match &v.atom {
            PdfAtom::Dict(_) => {
                out.push(PdfIrLine {
                    obj_ref: (entry.obj, entry.gen),
                    path: key_path.clone(),
                    value_type: "dict".into(),
                    value: "<blank>".into(),
                });
                emit_lines_for_atom(entry, &v.atom, &key_path, opts, out, deviations);
            }
            PdfAtom::Stream(_) => {
                out.push(PdfIrLine {
                    obj_ref: (entry.obj, entry.gen),
                    path: key_path.clone(),
                    value_type: "stream".into(),
                    value: "<stream>".into(),
                });
                emit_lines_for_atom(entry, &v.atom, &key_path, opts, out, deviations);
            }
            _ => emit_lines_for_atom(entry, &v.atom, &key_path, opts, out, deviations),
        }
    }
}

fn summarize_array(items: &[PdfObj<'_>], opts: &IrOptions) -> (String, String) {
    if items.is_empty() {
        return ("array".into(), "len=0".into());
    }
    let mut types = Vec::new();
    let mut values = Vec::new();
    for (idx, item) in items.iter().enumerate() {
        if idx >= opts.max_array_elems {
            break;
        }
        let (t, v) = atom_summary(&item.atom, opts.max_string_len);
        types.push(t);
        values.push(v);
    }
    let type_set: std::collections::BTreeSet<&str> = types.iter().map(|s| s.as_str()).collect();
    let value_type = if type_set.len() == 1 {
        format!("{}_list", types[0])
    } else {
        "mix_list".into()
    };
    let summary = format!("len={} values=[{}]", items.len(), values.join(","));
    (value_type, summary)
}

fn atom_summary(atom: &PdfAtom<'_>, max_string_len: usize) -> (String, String) {
    match atom {
        PdfAtom::Int(i) => ("num".into(), i.to_string()),
        PdfAtom::Real(f) => ("num".into(), format!("{:.6}", f)),
        PdfAtom::Bool(b) => ("bool".into(), b.to_string()),
        PdfAtom::Null => ("null".into(), "null".into()),
        PdfAtom::Name(n) => ("name".into(), name_to_string(n)),
        PdfAtom::Str(s) => ("str".into(), string_preview(s, max_string_len)),
        PdfAtom::Ref { obj, gen } => ("ref".into(), format!("{}-{}", obj, gen)),
        PdfAtom::Dict(_) => ("dict".into(), "<dict>".into()),
        PdfAtom::Stream(_) => ("stream".into(), "<stream>".into()),
        PdfAtom::Array(_) => ("array".into(), "<array>".into()),
    }
}

fn name_to_string(name: &PdfName<'_>) -> String {
    if !name.decoded.is_empty() {
        String::from_utf8_lossy(&name.decoded).to_string()
    } else {
        String::from_utf8_lossy(&name.raw).to_string()
    }
}

fn string_preview(s: &PdfStr<'_>, max_len: usize) -> String {
    let raw = match s {
        PdfStr::Literal { decoded, .. } => decoded,
        PdfStr::Hex { decoded, .. } => decoded,
    };
    let truncated = raw.len() > max_len;
    let end = std::cmp::min(raw.len(), max_len);
    let hex = raw[..end]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    let ascii = raw[..end]
        .iter()
        .map(|b| match b {
            b'\n' => "\\n".to_string(),
            b'\r' => "\\r".to_string(),
            b'\t' => "\\t".to_string(),
            b'\\' => "\\\\".to_string(),
            b'"' => "\\\"".to_string(),
            0x20..=0x7e => (*b as char).to_string(),
            _ => format!("\\x{:02x}", b),
        })
        .collect::<String>();
    format!(
        "len_bytes={} hex={} ascii={} truncated={}",
        raw.len(),
        hex,
        ascii,
        truncated
    )
}
