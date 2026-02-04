use std::collections::HashMap;

use sis_pdf_pdf::classification::{ClassificationMap, ObjectRole, PdfObjectType};
use sis_pdf_pdf::object::PdfAtom;
use sis_pdf_pdf::ObjectGraph;

use crate::graph_walk::{build_labeled_adjacency, reachable_paths, ObjRef};

pub fn canonical_position_for_obj(
    graph: &ObjectGraph<'_>,
    classifications: &ClassificationMap,
    obj: u32,
    gen: u16,
    path_hint: Option<&str>,
) -> String {
    let revision = revision_for_obj(graph, obj, gen);
    let path = path_hint
        .map(|p| p.to_string())
        .or_else(|| path_hint_for_obj(graph, classifications, obj, gen))
        .unwrap_or_else(|| "?".to_string());
    format!("doc:r{}/{}@{}:{}", revision, path, obj, gen)
}

pub fn parse_obj_ref(input: &str) -> Option<(u32, u16)> {
    let s = input.trim();
    let has_obj = s.contains("obj");
    if !has_obj && !s.chars().any(|c| c.is_ascii_digit()) {
        return None;
    }
    let nums: Vec<u32> = s
        .split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .filter_map(|p| p.parse::<u32>().ok())
        .collect();
    if nums.len() < 2 {
        return None;
    }
    let obj = nums[0];
    let gen = nums[1].min(u16::MAX as u32) as u16;
    Some((obj, gen))
}

pub fn build_path_map(graph: &ObjectGraph<'_>) -> HashMap<(u32, u16), String> {
    let mut out = HashMap::new();
    let Some((root_obj, root_gen)) = catalog_root_ref(graph) else {
        return out;
    };
    let adjacency = build_labeled_adjacency(&graph.objects);
    let root = ObjRef { obj: root_obj, gen: root_gen };
    let paths = reachable_paths(&adjacency, &[root], 64);
    for (obj_ref, labels) in paths {
        let mut segments = Vec::with_capacity(labels.len() + 1);
        segments.push("catalog".to_string());
        for label in labels {
            segments.push(normalise_path_segment(&label));
        }
        out.insert((obj_ref.obj, obj_ref.gen), segments.join("."));
    }
    out
}

fn revision_for_obj(graph: &ObjectGraph<'_>, obj: u32, gen: u16) -> usize {
    let entry = match graph.get_object(obj, gen) {
        Some(entry) => entry,
        None => return 0,
    };
    revision_for_offset(graph, entry.full_span.start)
}

fn revision_for_offset(graph: &ObjectGraph<'_>, offset: u64) -> usize {
    if graph.startxrefs.is_empty() {
        return 0;
    }
    let mut starts = graph.startxrefs.clone();
    starts.sort_unstable();
    let mut revision = 0usize;
    for (idx, start) in starts.iter().enumerate() {
        if offset >= *start {
            revision = idx;
        } else {
            break;
        }
    }
    revision
}

fn path_hint_for_obj(
    graph: &ObjectGraph<'_>,
    classifications: &ClassificationMap,
    obj: u32,
    gen: u16,
) -> Option<String> {
    if is_catalog_root(graph, obj, gen) {
        return Some("catalog".to_string());
    }
    let key = (obj, gen);
    let classified = classifications.get(&key)?;
    if classified.roles.contains(&ObjectRole::JsContainer) {
        return Some("js".to_string());
    }
    if classified.roles.contains(&ObjectRole::ActionTarget) {
        return Some("action".to_string());
    }
    if classified.roles.contains(&ObjectRole::UriTarget) {
        return Some("uri".to_string());
    }
    if classified.roles.contains(&ObjectRole::EmbeddedFile) {
        return Some("embedded".to_string());
    }
    if classified.obj_type == PdfObjectType::Annotation {
        return Some("annotation".to_string());
    }
    Some(classified.obj_type.as_str().to_ascii_lowercase())
}

fn normalise_path_segment(label: &str) -> String {
    let trimmed = label.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return "?".to_string();
    }
    if let Some((head, tail)) = trimmed.split_once('[') {
        let head = head.trim_end();
        if head.is_empty() {
            return format!("?[{}", tail);
        }
        return format!("{}[{}", head.to_ascii_lowercase(), tail);
    }
    trimmed.to_ascii_lowercase()
}

fn is_catalog_root(graph: &ObjectGraph<'_>, obj: u32, gen: u16) -> bool {
    let root = graph.trailers.last().and_then(|t| t.get_first(b"/Root")).map(|(_, v)| v.clone());
    if let Some(root) = root {
        if let PdfAtom::Ref { obj: root_obj, gen: root_gen } = root.atom {
            return root_obj == obj && root_gen == gen;
        }
    }
    false
}

fn catalog_root_ref(graph: &ObjectGraph<'_>) -> Option<(u32, u16)> {
    let root = graph.trailers.last().and_then(|t| t.get_first(b"/Root")).map(|(_, v)| v.clone())?;
    if let PdfAtom::Ref { obj: root_obj, gen: root_gen } = root.atom {
        return Some((root_obj, root_gen));
    }
    None
}
