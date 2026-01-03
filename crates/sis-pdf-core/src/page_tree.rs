use std::collections::HashMap;

use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};
use sis_pdf_pdf::ObjectGraph;

use crate::graph_walk::ObjRef;

#[derive(Debug, Clone)]
pub struct PageInfo {
    pub obj: u32,
    pub gen: u16,
    pub number: usize,
    pub media_box: Option<[f32; 4]>,
}

#[derive(Debug, Clone)]
pub struct PageRefInfo {
    pub obj: u32,
    pub gen: u16,
    pub number: usize,
}

#[derive(Debug, Clone)]
pub struct PageTree {
    pub pages: Vec<PageInfo>,
    pub annot_parent: HashMap<ObjRef, PageRefInfo>,
}

pub fn build_page_tree(graph: &ObjectGraph<'_>) -> PageTree {
    let mut pages = Vec::new();
    let mut annot_parent = HashMap::new();
    let root = graph
        .trailers
        .last()
        .and_then(|t| t.get_first(b"/Root"))
        .map(|(_, v)| v.clone());
    let catalog = root.as_ref().and_then(|o| resolve_dict(graph, o));
    let pages_ref = catalog
        .as_ref()
        .and_then(|d| d.get_first(b"/Pages"))
        .map(|(_, v)| v.clone());
    if let Some(pages_obj) = pages_ref {
        walk_pages(
            graph,
            &pages_obj,
            None,
            &mut pages,
            &mut annot_parent,
        );
    }
    PageTree { pages, annot_parent }
}

pub fn build_annotation_parent_map(graph: &ObjectGraph<'_>) -> HashMap<ObjRef, PageRefInfo> {
    build_page_tree(graph).annot_parent
}

fn walk_pages(
    graph: &ObjectGraph<'_>,
    obj: &PdfObj<'_>,
    inherited_media_box: Option<[f32; 4]>,
    pages: &mut Vec<PageInfo>,
    annot_parent: &mut HashMap<ObjRef, PageRefInfo>,
) {
    let dict = match resolve_dict(graph, obj) {
        Some(d) => d,
        None => return,
    };
    let media_box = media_box_from_dict(&dict).or(inherited_media_box);
    if dict.has_name(b"/Type", b"/Pages") {
        if let Some((_, kids)) = dict.get_first(b"/Kids") {
            if let PdfAtom::Array(arr) = &kids.atom {
                for kid in arr {
                    walk_pages(graph, kid, media_box, pages, annot_parent);
                }
            }
        }
        return;
    }
    if dict.has_name(b"/Type", b"/Page") {
        let (obj_id, gen_id) = object_id_from_obj(graph, obj).unwrap_or((0, 0));
        let number = pages.len() + 1;
        pages.push(PageInfo {
            obj: obj_id,
            gen: gen_id,
            number,
            media_box,
        });
        if let Some((_, annots)) = dict.get_first(b"/Annots") {
            if let PdfAtom::Array(arr) = &annots.atom {
                for annot in arr {
                    if let Some((ao, ag)) = object_id_from_obj(graph, annot) {
                        annot_parent.insert(
                            ObjRef { obj: ao, gen: ag },
                            PageRefInfo {
                                obj: obj_id,
                                gen: gen_id,
                                number,
                            },
                        );
                    }
                }
            } else if let Some((ao, ag)) = object_id_from_obj(graph, annots) {
                annot_parent.insert(
                    ObjRef { obj: ao, gen: ag },
                    PageRefInfo {
                        obj: obj_id,
                        gen: gen_id,
                        number,
                    },
                );
            }
        }
    }
}

fn resolve_dict<'a>(graph: &'a ObjectGraph<'a>, obj: &PdfObj<'a>) -> Option<PdfDict<'a>> {
    match &obj.atom {
        PdfAtom::Dict(d) => Some(d.clone()),
        PdfAtom::Ref { .. } => graph.resolve_ref(obj).and_then(|e| match &e.atom {
            PdfAtom::Dict(d) => Some(d.clone()),
            PdfAtom::Stream(st) => Some(st.dict.clone()),
            _ => None,
        }),
        PdfAtom::Stream(st) => Some(st.dict.clone()),
        _ => None,
    }
}

fn object_id_from_obj(graph: &ObjectGraph<'_>, obj: &PdfObj<'_>) -> Option<(u32, u16)> {
    match obj.atom {
        PdfAtom::Ref { obj, gen } => Some((obj, gen)),
        PdfAtom::Dict(_) | PdfAtom::Stream(_) => {
            let span_start = obj.span.start;
            graph
                .objects
                .iter()
                .find(|e| e.body_span.start == span_start)
                .map(|e| (e.obj, e.gen))
        }
        _ => None,
    }
}

fn media_box_from_dict(dict: &PdfDict<'_>) -> Option<[f32; 4]> {
    let (_, obj) = dict.get_first(b"/MediaBox")?;
    if let PdfAtom::Array(arr) = &obj.atom {
        let mut out = [0.0f32; 4];
        let mut idx = 0usize;
        for item in arr {
            if idx >= 4 {
                break;
            }
            match &item.atom {
                PdfAtom::Int(i) => {
                    out[idx] = *i as f32;
                    idx += 1;
                }
                PdfAtom::Real(f) => {
                    out[idx] = *f as f32;
                    idx += 1;
                }
                _ => {}
            }
        }
        if idx == 4 {
            return Some(out);
        }
    }
    None
}
