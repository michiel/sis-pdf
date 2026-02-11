use serde::Serialize;

use crate::revision_extract::extract_revision_content;
use crate::scan::ScanContext;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};

pub const DEFAULT_MAX_REVISIONS: usize = 32;

#[derive(Debug, Clone, Serialize)]
pub struct RevisionTimeline {
    pub revisions: Vec<RevisionRecord>,
    pub total_revisions: usize,
    pub skipped_revisions: usize,
    pub capped: bool,
    pub signature_boundaries: Vec<u64>,
    pub prev_chain_valid: bool,
    pub prev_chain_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RevisionRecord {
    pub revision: usize,
    pub startxref: u64,
    pub has_incremental_update: bool,
    pub covered_by_signature: bool,
    pub objects_added: usize,
    pub objects_modified: usize,
    pub objects_removed: usize,
    pub page_content_changed: usize,
    pub annotations_added: usize,
    pub annotations_modified: usize,
    pub catalog_changed: bool,
    pub action_or_js_changed: usize,
    pub anomaly_score: u32,
    pub anomaly_reasons: Vec<String>,
    pub objects_added_refs: Vec<String>,
    pub objects_modified_refs: Vec<String>,
    pub page_content_changed_refs: Vec<String>,
    pub annotation_added_refs: Vec<String>,
    pub annotation_modified_refs: Vec<String>,
    pub catalog_changed_refs: Vec<String>,
    pub action_or_js_changed_refs: Vec<String>,
}

impl RevisionRecord {
    fn new(revision: usize, startxref: u64, covered_by_signature: bool) -> Self {
        Self {
            revision,
            startxref,
            has_incremental_update: revision > 0,
            covered_by_signature,
            objects_added: 0,
            objects_modified: 0,
            objects_removed: 0,
            page_content_changed: 0,
            annotations_added: 0,
            annotations_modified: 0,
            catalog_changed: false,
            action_or_js_changed: 0,
            anomaly_score: 0,
            anomaly_reasons: Vec::new(),
            objects_added_refs: Vec::new(),
            objects_modified_refs: Vec::new(),
            page_content_changed_refs: Vec::new(),
            annotation_added_refs: Vec::new(),
            annotation_modified_refs: Vec::new(),
            catalog_changed_refs: Vec::new(),
            action_or_js_changed_refs: Vec::new(),
        }
    }
}

pub fn build_revision_timeline(ctx: &ScanContext<'_>, max_revisions: usize) -> RevisionTimeline {
    let extraction = extract_revision_content(ctx);
    let mut startxrefs = ctx.graph.startxrefs.clone();
    startxrefs.sort_unstable();
    startxrefs.dedup();
    if startxrefs.is_empty() {
        startxrefs.push(0);
    }
    let total_revisions = startxrefs.len();
    let effective_cap = max_revisions.max(1);
    let skip = total_revisions.saturating_sub(effective_cap);
    let analysed_starts = startxrefs[skip..].to_vec();

    let mut signature_boundaries = extraction
        .signatures
        .iter()
        .filter(|snapshot| snapshot.state_parseable && snapshot.covered_end > 0)
        .map(|snapshot| snapshot.covered_end)
        .collect::<Vec<_>>();
    signature_boundaries.sort_unstable();
    signature_boundaries.dedup();

    let mut revisions = analysed_starts
        .iter()
        .enumerate()
        .map(|(local_idx, startxref)| {
            let absolute_idx = local_idx + skip;
            let covered_by_signature =
                signature_boundaries.iter().any(|boundary| *boundary >= *startxref);
            RevisionRecord::new(absolute_idx, *startxref, covered_by_signature)
        })
        .collect::<Vec<_>>();

    let mut revision_map = std::collections::HashMap::new();
    for (idx, record) in revisions.iter().enumerate() {
        revision_map.insert(record.revision, idx);
    }

    for ((obj, gen), indexes) in &ctx.graph.index {
        let mut versions =
            indexes.iter().filter_map(|index| ctx.graph.objects.get(*index)).collect::<Vec<_>>();
        if versions.is_empty() {
            continue;
        }
        versions.sort_by_key(|entry| entry.full_span.start);

        let object_ref = format!("{obj} {gen} obj");
        let first_entry = versions[0];
        let first_revision = revision_index_for_offset(first_entry.full_span.start, &startxrefs);

        if let Some(local_idx) = revision_map.get(&first_revision) {
            if first_revision > 0 {
                let record = &mut revisions[*local_idx];
                record.objects_added += 1;
                push_unique(&mut record.objects_added_refs, object_ref.clone());
                if let Some(dict) = entry_dict(first_entry) {
                    if is_annotation_object(dict) {
                        record.annotations_added += 1;
                        push_unique(&mut record.annotation_added_refs, object_ref.clone());
                    }
                    if has_action_or_js_markers(dict) {
                        record.action_or_js_changed += 1;
                        push_unique(&mut record.action_or_js_changed_refs, object_ref.clone());
                    }
                }
            }
        }

        for pair in versions.windows(2) {
            let prev = pair[0];
            let current = pair[1];
            let prev_revision = revision_index_for_offset(prev.full_span.start, &startxrefs);
            let current_revision = revision_index_for_offset(current.full_span.start, &startxrefs);
            if current_revision == prev_revision {
                continue;
            }
            if object_semantic_fingerprint(prev) == object_semantic_fingerprint(current) {
                continue;
            }
            let Some(local_idx) = revision_map.get(&current_revision).copied() else {
                continue;
            };

            let record = &mut revisions[local_idx];
            record.objects_modified += 1;
            push_unique(&mut record.objects_modified_refs, object_ref.clone());

            let page_change = is_page_or_content_object(prev) || is_page_or_content_object(current);
            if page_change {
                record.page_content_changed += 1;
                push_unique(&mut record.page_content_changed_refs, object_ref.clone());
            }

            let annotation_change = entry_dict(prev).is_some_and(is_annotation_object)
                || entry_dict(current).is_some_and(is_annotation_object);
            if annotation_change {
                record.annotations_modified += 1;
                push_unique(&mut record.annotation_modified_refs, object_ref.clone());
            }

            let catalog_change = entry_dict(prev).is_some_and(is_catalog_object)
                || entry_dict(current).is_some_and(is_catalog_object);
            if catalog_change {
                record.catalog_changed = true;
                push_unique(&mut record.catalog_changed_refs, object_ref.clone());
            }

            let action_or_js_change = entry_dict(prev).is_some_and(has_action_or_js_markers)
                || entry_dict(current).is_some_and(has_action_or_js_markers);
            if action_or_js_change {
                record.action_or_js_changed += 1;
                push_unique(&mut record.action_or_js_changed_refs, object_ref.clone());
            }
        }
    }

    for record in &mut revisions {
        let mut score = 0u32;
        let mut reasons = Vec::new();

        if record.objects_added >= 5 {
            score += 1;
            reasons.push("many_objects_added".into());
        }
        if record.objects_modified >= 5 {
            score += 1;
            reasons.push("many_objects_modified".into());
        }
        if record.page_content_changed > 0 {
            score += 3;
            reasons.push("page_content_changed".into());
        }
        if record.annotations_added > 0 {
            score += 2;
            reasons.push("annotations_added".into());
        }
        if record.annotations_modified > 0 {
            score += 1;
            reasons.push("annotations_modified".into());
        }
        if record.catalog_changed {
            score += 3;
            reasons.push("catalog_changed".into());
        }
        if record.action_or_js_changed > 0 {
            score += 2;
            reasons.push("action_or_js_changed".into());
        }
        if !record.covered_by_signature
            && (record.page_content_changed > 0 || record.catalog_changed)
        {
            score += 2;
            reasons.push("outside_signature_coverage".into());
        }

        record.anomaly_score = score;
        record.anomaly_reasons = reasons;
    }

    RevisionTimeline {
        revisions,
        total_revisions,
        skipped_revisions: skip,
        capped: skip > 0,
        signature_boundaries,
        prev_chain_valid: extraction.prev_chain_valid,
        prev_chain_errors: extraction.prev_chain_errors,
    }
}

fn revision_index_for_offset(offset: u64, startxrefs: &[u64]) -> usize {
    if startxrefs.is_empty() {
        return 0;
    }
    for (idx, startxref) in startxrefs.iter().enumerate() {
        if offset < *startxref {
            return idx;
        }
    }
    startxrefs.len().saturating_sub(1)
}

fn push_unique(target: &mut Vec<String>, value: String) {
    if !target.contains(&value) {
        target.push(value);
    }
}

fn entry_dict<'a>(entry: &'a sis_pdf_pdf::graph::ObjEntry<'a>) -> Option<&'a PdfDict<'a>> {
    match &entry.atom {
        PdfAtom::Dict(dict) => Some(dict),
        PdfAtom::Stream(stream) => Some(&stream.dict),
        _ => None,
    }
}

fn is_page_or_content_object(entry: &sis_pdf_pdf::graph::ObjEntry<'_>) -> bool {
    match &entry.atom {
        PdfAtom::Stream(_) => true,
        PdfAtom::Dict(dict) => {
            dict.has_name(b"/Type", b"/Page")
                || dict.get_first(b"/Contents").is_some()
                || dict.get_first(b"/Resources").is_some()
        }
        _ => false,
    }
}

fn is_catalog_object(dict: &PdfDict<'_>) -> bool {
    dict.has_name(b"/Type", b"/Catalog")
}

fn is_annotation_object(dict: &PdfDict<'_>) -> bool {
    dict.has_name(b"/Type", b"/Annot") || dict.get_first(b"/Subtype").is_some()
}

fn has_action_or_js_markers(dict: &PdfDict<'_>) -> bool {
    dict.get_first(b"/JS").is_some()
        || dict.has_name(b"/S", b"/JavaScript")
        || dict.has_name(b"/S", b"/Launch")
        || dict.get_first(b"/OpenAction").is_some()
        || dict.get_first(b"/AA").is_some()
        || dict.get_first(b"/A").is_some()
}

fn object_semantic_fingerprint(entry: &sis_pdf_pdf::graph::ObjEntry<'_>) -> String {
    match &entry.atom {
        PdfAtom::Dict(dict) => dict_fingerprint(dict),
        PdfAtom::Stream(stream) => {
            let mut out = String::from("stream:");
            out.push_str(&dict_fingerprint(&stream.dict));
            out
        }
        atom => atom_fingerprint(atom),
    }
}

fn dict_fingerprint(dict: &PdfDict<'_>) -> String {
    let mut pairs = dict
        .entries
        .iter()
        .map(|(key, value)| {
            format!("{}={}", String::from_utf8_lossy(&key.decoded), obj_fingerprint(value))
        })
        .collect::<Vec<_>>();
    pairs.sort();
    pairs.join(";")
}

fn obj_fingerprint(obj: &PdfObj<'_>) -> String {
    atom_fingerprint(&obj.atom)
}

fn atom_fingerprint(atom: &PdfAtom<'_>) -> String {
    match atom {
        PdfAtom::Null => "null".into(),
        PdfAtom::Bool(value) => format!("bool:{value}"),
        PdfAtom::Int(value) => format!("int:{value}"),
        PdfAtom::Real(value) => format!("real:{value:.6}"),
        PdfAtom::Name(name) => format!("name:{}", String::from_utf8_lossy(&name.decoded)),
        PdfAtom::Str(value) => match value {
            sis_pdf_pdf::object::PdfStr::Literal { decoded, .. }
            | sis_pdf_pdf::object::PdfStr::Hex { decoded, .. } => {
                format!("str:{}", String::from_utf8_lossy(decoded))
            }
        },
        PdfAtom::Array(values) => {
            let mut out = String::from("array:");
            out.push_str(&values.iter().map(obj_fingerprint).collect::<Vec<_>>().join(","));
            out
        }
        PdfAtom::Dict(dict) => format!("dict:{}", dict_fingerprint(dict)),
        PdfAtom::Stream(stream) => format!("stream:{}", dict_fingerprint(&stream.dict)),
        PdfAtom::Ref { obj, gen } => format!("ref:{obj}:{gen}"),
    }
}
