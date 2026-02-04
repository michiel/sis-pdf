use std::collections::HashSet;

use sis_pdf_pdf::decode::stream_filters;
use sis_pdf_pdf::graph::ObjectGraph;
use sis_pdf_pdf::object::{PdfAtom, PdfName, PdfStream};
use tracing::info;

/// Returns a canonical string representation of a PDF name.
pub fn canonical_name(name_bytes: &[u8]) -> String {
    let normalized =
        String::from_utf8_lossy(name_bytes).trim_start_matches('/').trim().to_ascii_uppercase();
    if normalized.is_empty() {
        "-".into()
    } else {
        normalized
    }
}

/// Produces a normalized filter chain for a stream.
pub fn canonical_filter_chain(stream: &PdfStream<'_>) -> Vec<String> {
    stream_filters(&stream.dict).into_iter().map(|filter| canonical_filter_name(&filter)).collect()
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

/// Canonical view metadata used by detectors and summaries.
#[derive(Debug, Clone)]
pub struct CanonicalView {
    pub indices: Vec<usize>,
    pub incremental_removed: usize,
    pub normalized_name_changes: usize,
}

impl CanonicalView {
    pub fn build(graph: &ObjectGraph<'_>) -> Self {
        let indices = canonical_object_indices(graph, true);
        let incremental_removed = graph.objects.len().saturating_sub(indices.len());
        let normalized_name_changes = count_normalized_name_changes(graph);
        let view = Self { indices, incremental_removed, normalized_name_changes };
        info!(
            canonical_objects = view.indices.len(),
            total_objects = graph.objects.len(),
            incremental_removed = view.incremental_removed,
            normalized_name_changes = view.normalized_name_changes,
            "Computed canonical object view"
        );
        view
    }
}

fn count_normalized_name_changes(graph: &ObjectGraph<'_>) -> usize {
    graph
        .objects
        .iter()
        .filter_map(|entry| match &entry.atom {
            PdfAtom::Dict(dict) => Some(&dict.entries),
            PdfAtom::Stream(stream) => Some(&stream.dict.entries),
            _ => None,
        })
        .flat_map(|entries| entries.iter())
        .filter(|(name, _)| normalized_name_differs(name))
        .count()
}

fn normalized_name_differs(name: &PdfName<'_>) -> bool {
    let canonical = canonical_name(&name.decoded);
    let raw =
        String::from_utf8_lossy(&name.decoded).trim_start_matches('/').trim().to_ascii_uppercase();
    canonical != raw
}
