use std::collections::{HashMap, HashSet, VecDeque};

use sis_pdf_pdf::graph::ObjEntry;
use sis_pdf_pdf::object::{PdfAtom, PdfName, PdfObj};

const MAX_COLLECT_DEPTH: usize = 64;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct ObjRef {
    pub obj: u32,
    pub gen: u16,
}

#[derive(Debug, Clone)]
pub struct LabeledEdge {
    pub to: ObjRef,
    pub label: String,
}

pub fn build_adjacency(objects: &[ObjEntry<'_>]) -> HashMap<ObjRef, Vec<ObjRef>> {
    let mut map: HashMap<ObjRef, Vec<ObjRef>> = HashMap::new();
    for entry in objects {
        let key = ObjRef { obj: entry.obj, gen: entry.gen };
        let mut refs = Vec::new();
        collect_refs_from_atom(&entry.atom, &mut refs, 0);
        map.insert(key, refs);
    }
    map
}

pub fn build_labeled_adjacency(objects: &[ObjEntry<'_>]) -> HashMap<ObjRef, Vec<LabeledEdge>> {
    let mut map: HashMap<ObjRef, Vec<LabeledEdge>> = HashMap::new();
    for entry in objects {
        let key = ObjRef { obj: entry.obj, gen: entry.gen };
        let mut refs = Vec::new();
        collect_labeled_refs_from_atom(&entry.atom, None, &mut refs, 0);
        map.insert(key, refs);
    }
    map
}

pub fn reachable_from(
    adjacency: &HashMap<ObjRef, Vec<ObjRef>>,
    seeds: &[ObjRef],
    max_depth: usize,
) -> HashSet<ObjRef> {
    let mut seen = HashSet::new();
    let mut q = VecDeque::new();
    for s in seeds {
        seen.insert(*s);
        q.push_back((*s, 0usize));
    }
    while let Some((cur, depth)) = q.pop_front() {
        if depth >= max_depth {
            continue;
        }
        if let Some(next) = adjacency.get(&cur) {
            for r in next {
                if seen.insert(*r) {
                    q.push_back((*r, depth + 1));
                }
            }
        }
    }
    seen
}

pub fn reachable_paths(
    adjacency: &HashMap<ObjRef, Vec<LabeledEdge>>,
    seeds: &[ObjRef],
    max_depth: usize,
) -> HashMap<ObjRef, Vec<String>> {
    let mut paths: HashMap<ObjRef, Vec<String>> = HashMap::new();
    let mut q = VecDeque::new();
    for s in seeds {
        paths.insert(*s, Vec::new());
        q.push_back((*s, 0usize));
    }
    while let Some((cur, depth)) = q.pop_front() {
        if depth >= max_depth {
            continue;
        }
        if let Some(next) = adjacency.get(&cur) {
            for edge in next {
                if paths.contains_key(&edge.to) {
                    continue;
                }
                let mut path = paths.get(&cur).cloned().unwrap_or_default();
                path.push(edge.label.clone());
                paths.insert(edge.to, path);
                q.push_back((edge.to, depth + 1));
            }
        }
    }
    paths
}

fn collect_refs_from_atom(atom: &PdfAtom<'_>, out: &mut Vec<ObjRef>, depth: usize) {
    if depth >= MAX_COLLECT_DEPTH {
        return;
    }
    match atom {
        PdfAtom::Ref { obj, gen } => out.push(ObjRef { obj: *obj, gen: *gen }),
        PdfAtom::Array(arr) => {
            for o in arr {
                collect_refs_from_obj(o, out, depth + 1);
            }
        }
        PdfAtom::Dict(d) => {
            for (_, v) in &d.entries {
                collect_refs_from_obj(v, out, depth + 1);
            }
        }
        PdfAtom::Stream(st) => {
            for (_, v) in &st.dict.entries {
                collect_refs_from_obj(v, out, depth + 1);
            }
        }
        _ => {}
    }
}

fn collect_refs_from_obj(obj: &PdfObj<'_>, out: &mut Vec<ObjRef>, depth: usize) {
    collect_refs_from_atom(&obj.atom, out, depth);
}

fn collect_labeled_refs_from_atom(
    atom: &PdfAtom<'_>,
    label: Option<String>,
    out: &mut Vec<LabeledEdge>,
    depth: usize,
) {
    if depth >= MAX_COLLECT_DEPTH {
        return;
    }
    match atom {
        PdfAtom::Ref { obj, gen } => out.push(LabeledEdge {
            to: ObjRef { obj: *obj, gen: *gen },
            label: label.unwrap_or_else(|| "ref".into()),
        }),
        PdfAtom::Array(arr) => {
            for (idx, o) in arr.iter().enumerate() {
                let next = label
                    .as_ref()
                    .map(|l| format!("{}[{}]", l, idx))
                    .unwrap_or_else(|| format!("array[{}]", idx));
                collect_labeled_refs_from_atom(&o.atom, Some(next), out, depth + 1);
            }
        }
        PdfAtom::Dict(d) => {
            for (k, v) in &d.entries {
                let key = name_to_string(k);
                collect_labeled_refs_from_atom(&v.atom, Some(key), out, depth + 1);
            }
        }
        PdfAtom::Stream(st) => {
            for (k, v) in &st.dict.entries {
                let key = name_to_string(k);
                collect_labeled_refs_from_atom(&v.atom, Some(key), out, depth + 1);
            }
        }
        _ => {}
    }
}

fn name_to_string(name: &PdfName<'_>) -> String {
    String::from_utf8_lossy(&name.decoded).to_string()
}
