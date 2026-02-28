use std::collections::{HashMap, HashSet};

use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};
use sis_pdf_pdf::ObjectGraph;
use tracing::warn;

use crate::graph_walk::ObjRef;

/// Maximum recursion depth for page tree traversal to prevent stack overflow
const MAX_PAGE_TREE_DEPTH: usize = 128;

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
    let mut seen = HashSet::new();
    let root = graph.trailers.last().and_then(|t| t.get_first(b"/Root")).map(|(_, v)| v.clone());
    let catalog = root.as_ref().and_then(|o| graph.resolve_to_dict(o));
    let pages_ref = catalog.as_ref().and_then(|d| d.get_first(b"/Pages")).map(|(_, v)| v.clone());
    if let Some(pages_obj) = pages_ref {
        walk_pages(graph, &pages_obj, None, &mut pages, &mut annot_parent, &mut seen, 0);
    }
    PageTree { pages, annot_parent }
}

pub fn build_annotation_parent_map(graph: &ObjectGraph<'_>) -> HashMap<ObjRef, PageRefInfo> {
    build_page_tree(graph).annot_parent
}

/// Resolve the `/Resources` dict for a page object, including inherited resources from
/// parent `/Pages` nodes.
///
/// The returned dict is a clone that merges ancestor resources (lower precedence) with
/// the page's own resources (higher precedence). If the page dict has no `/Resources`
/// key, the parent chain is walked up to the `/Pages` root.
///
/// Returns `None` if neither the page nor any ancestor has a `/Resources` entry.
pub fn resolve_page_resources<'a>(
    graph: &'a ObjectGraph<'a>,
    page_obj: u32,
    page_gen: u16,
) -> Option<PdfDict<'a>> {
    let entry = graph.get_object(page_obj, page_gen)?;
    let page_dict = match &entry.atom {
        PdfAtom::Dict(d) => d.clone(),
        PdfAtom::Stream(st) => st.dict.clone(),
        _ => return None,
    };
    // If the page dict has its own /Resources, return it directly.
    if page_dict.get_first(b"/Resources").is_some() {
        if let Some((_, res_obj)) = page_dict.get_first(b"/Resources") {
            return match &res_obj.atom {
                PdfAtom::Dict(d) => Some(d.clone()),
                PdfAtom::Ref { .. } => graph.resolve_ref(res_obj).and_then(|e| match &e.atom {
                    PdfAtom::Dict(d) => Some(d.clone()),
                    PdfAtom::Stream(st) => Some(st.dict.clone()),
                    _ => None,
                }),
                _ => None,
            };
        }
    }
    // Walk parent chain looking for inherited /Resources.
    walk_parent_for_resources(graph, &page_dict, 0)
}

fn walk_parent_for_resources<'a>(
    graph: &'a ObjectGraph<'a>,
    dict: &PdfDict<'a>,
    depth: usize,
) -> Option<PdfDict<'a>> {
    if depth > MAX_PAGE_TREE_DEPTH {
        return None;
    }
    let (_, parent_obj) = dict.get_first(b"/Parent")?;
    let parent_dict = match &parent_obj.atom {
        PdfAtom::Dict(d) => d.clone(),
        PdfAtom::Ref { .. } => graph.resolve_ref(parent_obj).and_then(|e| match &e.atom {
            PdfAtom::Dict(d) => Some(d.clone()),
            PdfAtom::Stream(st) => Some(st.dict.clone()),
            _ => None,
        })?,
        _ => return None,
    };
    if let Some((_, res_obj)) = parent_dict.get_first(b"/Resources") {
        return match &res_obj.atom {
            PdfAtom::Dict(d) => Some(d.clone()),
            PdfAtom::Ref { .. } => graph.resolve_ref(res_obj).and_then(|e| match &e.atom {
                PdfAtom::Dict(d) => Some(d.clone()),
                PdfAtom::Stream(st) => Some(st.dict.clone()),
                _ => None,
            }),
            _ => None,
        };
    }
    walk_parent_for_resources(graph, &parent_dict, depth + 1)
}

fn walk_pages(
    graph: &ObjectGraph<'_>,
    obj: &PdfObj<'_>,
    inherited_media_box: Option<[f32; 4]>,
    pages: &mut Vec<PageInfo>,
    annot_parent: &mut HashMap<ObjRef, PageRefInfo>,
    seen: &mut HashSet<(u32, u16)>,
    depth: usize,
) {
    // Guard against excessive recursion depth
    if depth > MAX_PAGE_TREE_DEPTH {
        warn!(
            security = true,
            domain = "pdf.page_tree",
            kind = "page_tree_depth_exceeded",
            depth = depth,
            "[NON-FATAL][finding:page_tree_depth_exceeded] Page tree depth exceeded maximum; aborting traversal"
        );
        return;
    }

    // Cycle detection via object reference tracking
    if let Some((obj_id, gen_id)) = object_id_from_obj(graph, obj) {
        if !seen.insert((obj_id, gen_id)) {
            warn!(
                security = true,
                domain = "pdf.page_tree",
                kind = "page_tree_cycle_detected",
                obj = obj_id,
                gen = gen_id,
                "[NON-FATAL][finding:page_tree_cycle_detected] Page tree cycle detected; aborting traversal"
            );
            return;
        }
    }

    let dict = match graph.resolve_to_dict(obj) {
        Some(d) => d,
        None => return,
    };
    let media_box = media_box_from_dict(&dict).or(inherited_media_box);
    if dict.has_name(b"/Type", b"/Pages") {
        if let Some((_, kids)) = dict.get_first(b"/Kids") {
            if let PdfAtom::Array(arr) = &kids.atom {
                for kid in arr {
                    walk_pages(graph, kid, media_box, pages, annot_parent, seen, depth + 1);
                }
            }
        }
        return;
    }
    if dict.has_name(b"/Type", b"/Page") {
        let (obj_id, gen_id) = object_id_from_obj(graph, obj).unwrap_or((0, 0));
        let number = pages.len() + 1;
        pages.push(PageInfo { obj: obj_id, gen: gen_id, number, media_box });
        if let Some((_, annots)) = dict.get_first(b"/Annots") {
            if let PdfAtom::Array(arr) = &annots.atom {
                for annot in arr {
                    if let Some((ao, ag)) = object_id_from_obj(graph, annot) {
                        annot_parent.insert(
                            ObjRef { obj: ao, gen: ag },
                            PageRefInfo { obj: obj_id, gen: gen_id, number },
                        );
                    }
                }
            } else if let Some((ao, ag)) = object_id_from_obj(graph, annots) {
                annot_parent.insert(
                    ObjRef { obj: ao, gen: ag },
                    PageRefInfo { obj: obj_id, gen: gen_id, number },
                );
            }
        }
    }
}

fn object_id_from_obj(graph: &ObjectGraph<'_>, obj: &PdfObj<'_>) -> Option<(u32, u16)> {
    match obj.atom {
        PdfAtom::Ref { obj, gen } => Some((obj, gen)),
        PdfAtom::Dict(_) | PdfAtom::Stream(_) => {
            let span_start = obj.span.start;
            graph.objects.iter().find(|e| e.body_span.start == span_start).map(|e| (e.obj, e.gen))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sis_pdf_pdf::graph::{parse_pdf, ParseOptions};

    /// Build a minimal PDF bytes with `depth` nested `/Pages` nodes followed by a
    /// single `/Page` leaf. Used to stress-test the depth guard in `walk_pages`.
    fn build_deep_page_tree_pdf(depth: usize) -> Vec<u8> {
        // Object layout (1-indexed):
        //   1 0 obj: Catalog  (/Root 2 0 R)
        //   2 0 obj: Root Pages (/Kids [3 0 R])
        //   3 0 obj: Level-2 Pages (/Kids [4 0 R])
        //   ...
        //   (depth+1) 0 obj: Deepest Pages (/Kids [(depth+2) 0 R])
        //   (depth+2) 0 obj: Leaf /Page
        //
        // Total objects: depth + 2
        let total_objects = depth + 2;
        let mut offsets: Vec<usize> = vec![0; total_objects + 1]; // 1-indexed
        let mut buf: Vec<u8> = Vec::new();

        buf.extend_from_slice(b"%PDF-1.4\n");

        // Catalog
        offsets[1] = buf.len();
        buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

        // Pages nodes: objects 2 through (depth + 1), each pointing to the next
        for i in 2..=(depth + 1) {
            let next = i + 1;
            offsets[i] = buf.len();
            let entry =
                format!("{i} 0 obj\n<< /Type /Pages /Kids [{next} 0 R] /Count 1 >>\nendobj\n");
            buf.extend_from_slice(entry.as_bytes());
        }

        // Leaf Page
        let leaf = depth + 2;
        let parent = depth + 1;
        offsets[leaf] = buf.len();
        let entry = format!(
            "{leaf} 0 obj\n<< /Type /Page /Parent {parent} 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
        );
        buf.extend_from_slice(entry.as_bytes());

        // xref table
        let xref_offset = buf.len();
        let header = format!("xref\n0 {}\n", total_objects + 1);
        buf.extend_from_slice(header.as_bytes());
        buf.extend_from_slice(b"0000000000 65535 f \n");
        for i in 1..=total_objects {
            let line = format!("{:010} 00000 n \n", offsets[i]);
            buf.extend_from_slice(line.as_bytes());
        }

        // Trailer
        let trailer = format!(
            "trailer\n<< /Size {sz} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            sz = total_objects + 1,
            xref = xref_offset,
        );
        buf.extend_from_slice(trailer.as_bytes());
        buf
    }

    fn default_parse_opts(max_objects: usize) -> ParseOptions {
        ParseOptions {
            recover_xref: true,
            deep: false,
            strict: false,
            max_objstm_bytes: 1024 * 1024,
            max_objects,
            max_objstm_total_bytes: 1024 * 1024,
            carve_stream_objects: false,
            max_carved_objects: 0,
            max_carved_bytes: 0,
        }
    }

    #[test]
    fn annotation_parent_map_handles_deep_page_tree_without_panic() {
        // Use depth 130, which exceeds MAX_PAGE_TREE_DEPTH (128), to verify the
        // depth guard terminates traversal gracefully rather than stack-overflowing.
        let bytes = build_deep_page_tree_pdf(130);
        let opts = default_parse_opts(10_000);
        let graph = parse_pdf(&bytes, opts).expect("parse should succeed");
        // Should return without panic; map may be empty (no annotations in fixture).
        let map = build_annotation_parent_map(&graph);
        // The leaf page has no /Annots, so the map must be empty.
        assert!(map.is_empty(), "expected empty annotation parent map for a page-only fixture");
    }

    #[test]
    fn annotation_parent_map_handles_cyclic_page_tree_without_panic() {
        // Build a PDF where object 2 is a /Pages node with /Kids pointing to itself
        // (obj 2). The cycle detector should terminate traversal immediately.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"%PDF-1.4\n");

        let mut offsets = [0usize; 4]; // indices 1..=3

        // Catalog
        offsets[1] = buf.len();
        buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

        // Cyclic Pages: /Kids points back to itself
        offsets[2] = buf.len();
        buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [2 0 R] /Count 1 >>\nendobj\n");

        // Dummy object to make the xref well-formed
        offsets[3] = buf.len();
        buf.extend_from_slice(b"3 0 obj\nnull\nendobj\n");

        let xref_offset = buf.len();
        buf.extend_from_slice(b"xref\n0 4\n");
        buf.extend_from_slice(b"0000000000 65535 f \n");
        for i in 1..=3 {
            let line = format!("{:010} 00000 n \n", offsets[i]);
            buf.extend_from_slice(line.as_bytes());
        }
        buf.extend_from_slice(
            format!("trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n")
                .as_bytes(),
        );

        let opts = default_parse_opts(1_000);
        let graph = parse_pdf(&buf, opts).expect("parse should succeed");
        // Should return without panic; cycle detection must stop the traversal.
        let map = build_annotation_parent_map(&graph);
        assert!(map.is_empty());
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
