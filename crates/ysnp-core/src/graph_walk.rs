use std::collections::{HashMap, HashSet, VecDeque};

use ysnp_pdf::graph::ObjEntry;
use ysnp_pdf::object::{PdfAtom, PdfObj};

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct ObjRef {
    pub obj: u32,
    pub gen: u16,
}

pub fn build_adjacency(objects: &[ObjEntry<'_>]) -> HashMap<ObjRef, Vec<ObjRef>> {
    let mut map: HashMap<ObjRef, Vec<ObjRef>> = HashMap::new();
    for entry in objects {
        let key = ObjRef {
            obj: entry.obj,
            gen: entry.gen,
        };
        let mut refs = Vec::new();
        collect_refs_from_atom(&entry.atom, &mut refs);
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

fn collect_refs_from_atom(atom: &PdfAtom<'_>, out: &mut Vec<ObjRef>) {
    match atom {
        PdfAtom::Ref { obj, gen } => out.push(ObjRef { obj: *obj, gen: *gen }),
        PdfAtom::Array(arr) => {
            for o in arr {
                collect_refs_from_obj(o, out);
            }
        }
        PdfAtom::Dict(d) => {
            for (_, v) in &d.entries {
                collect_refs_from_obj(v, out);
            }
        }
        PdfAtom::Stream(st) => {
            for (_, v) in &st.dict.entries {
                collect_refs_from_obj(v, out);
            }
        }
        _ => {}
    }
}

fn collect_refs_from_obj(obj: &PdfObj<'_>, out: &mut Vec<ObjRef>) {
    collect_refs_from_atom(&obj.atom, out);
}
