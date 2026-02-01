use std::collections::HashSet;

use crate::graph::ObjectGraph;
use sis_pdf_pdf::decode::stream_filters;
use sis_pdf_pdf::object::PdfStream;

/// Returns a canonical string representation of a PDF name.
pub fn canonical_name(name_bytes: &[u8]) -> String {
    let normalized = String::from_utf8_lossy(name_bytes)
        .trim_start_matches('/')
        .trim()
        .to_ascii_uppercase();
    if normalized.is_empty() {
        "-".into()
    } else {
        normalized
    }
}

/// Produces a normalized filter chain for a stream.
pub fn canonical_filter_chain(stream: &PdfStream<'_>) -> Vec<String> {
    stream_filters(&stream.dict)
        .0
        .into_iter()
        .map(|filter| canonical_filter_name(&filter))
        .collect()
}

fn canonical_filter_name(filter: &str) -> String {
    filter.trim_start_matches('/').trim().to_ascii_uppercase()
}

/// Returns indices for the canonical object list, optionally dropping
/// prior versions introduced via incremental updates.
pub fn canonical_object_indices(graph: &ObjectGraph<'_>, strip_incremental: bool) -> Vec<usize> {
    if !strip_incremental {
        return (0..graph.objects.len()).collect();
    }
    let mut seen = HashSet::new();
    let mut indices = Vec::new();
    for (idx, entry) in graph.objects.iter().enumerate().rev() {
        if seen.insert((entry.obj, entry.gen)) {
            indices.push(idx);
        }
    }
    indices.reverse();
    indices
}
