use anyhow::Result;
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_core::revision_extract::extract_revision_content;
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};

use crate::entry_dict;

const MAX_FINGERPRINT_DEPTH: usize = 32;

pub struct ShadowAttackDetector;

impl Detector for ShadowAttackDetector {
    fn id(&self) -> &'static str {
        "shadow_attacks"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::FileStructure
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Moderate
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let extraction = extract_revision_content(ctx);
        let Some(signature_boundary) = extraction
            .signatures
            .iter()
            .filter(|snapshot| snapshot.state_parseable && snapshot.covered_end > 0)
            .map(|snapshot| snapshot.covered_end)
            .min()
        else {
            return Ok(Vec::new());
        };
        if signature_boundary >= ctx.bytes.len() as u64 {
            return Ok(Vec::new());
        }

        let mut replace_targets = Vec::new();
        let mut overlay_objects = Vec::new();
        let mut annotation_overlays = Vec::new();
        let mut form_field_overlays = Vec::new();
        let mut signature_field_overlays = Vec::new();

        for ((obj, gen), idxs) in &ctx.graph.index {
            if idxs.len() <= 1 {
                continue;
            }
            let versions =
                idxs.iter().filter_map(|idx| ctx.graph.objects.get(*idx)).collect::<Vec<_>>();
            let pre = versions
                .iter()
                .filter(|entry| entry.full_span.start < signature_boundary)
                .max_by_key(|entry| entry.full_span.start)
                .copied();
            let post = versions
                .iter()
                .filter(|entry| entry.full_span.start >= signature_boundary)
                .max_by_key(|entry| entry.full_span.start)
                .copied();
            let (Some(pre), Some(post)) = (pre, post) else {
                continue;
            };
            if !is_page_or_content_object(pre) {
                continue;
            }
            if object_semantic_fingerprint(pre) != object_semantic_fingerprint(post) {
                replace_targets.push(format!("{obj} {gen} obj"));
            }
        }

        for entry in &ctx.graph.objects {
            if entry.full_span.start < signature_boundary {
                continue;
            }
            let Some(dict) = entry_dict(entry) else {
                continue;
            };
            let object_ref = format!("{} {} obj", entry.obj, entry.gen);
            if !is_overlay_annotation_or_field(dict) {
                continue;
            }
            overlay_objects.push(object_ref.clone());
            if is_signature_field_overlay(dict) {
                signature_field_overlays.push(object_ref);
            } else if is_form_field_overlay(dict) {
                form_field_overlays.push(object_ref);
            } else if is_annotation_overlay(dict) {
                annotation_overlays.push(object_ref);
            }
        }

        let diff_summary = build_diff_summary(ctx, signature_boundary);
        let mut findings = Vec::new();
        let post_update_bytes = ctx.bytes.len() as u64 - signature_boundary;
        let mut base_meta = std::collections::HashMap::new();
        base_meta.insert("shadow.signature_boundary".into(), signature_boundary.to_string());
        base_meta.insert("shadow.post_update_bytes".into(), post_update_bytes.to_string());
        base_meta.insert("shadow.prev_chain_valid".into(), extraction.prev_chain_valid.to_string());
        merge_diff_summary_meta(&mut base_meta, &diff_summary);
        if !extraction.prev_chain_errors.is_empty() {
            base_meta.insert(
                "shadow.prev_chain_errors".into(),
                extraction.prev_chain_errors.join(" | "),
            );
        }

        if !overlay_objects.is_empty() {
            let mut meta = base_meta.clone();
            meta.insert("shadow.overlay_count".into(), overlay_objects.len().to_string());
            meta.insert("shadow.overlay_objects".into(), overlay_objects.join(", "));
            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "shadow_hide_attack".into(),
                severity: Severity::High,
                confidence: if extraction.prev_chain_valid {
                    Confidence::Probable
                } else {
                    Confidence::Tentative
                },
                impact: Impact::Unknown,
                title: "Shadow hide attack indicators".into(),
                description:
                    "Post-signature revision added overlay annotation/form appearances that can obscure signed content."
                        .into(),
                objects: overlay_objects.clone(),
                evidence: overlay_objects
                    .iter()
                    .filter_map(|object_ref| parse_obj_ref(object_ref))
                    .filter_map(|(obj, gen)| ctx.graph.get_object(obj, gen))
                    .map(|entry| span_to_evidence(entry.full_span, "Post-signature overlay object"))
                    .collect(),
                remediation: Some(
                    "Compare annotation/form overlays against signed revision content and validate intended visual changes."
                        .into(),
                ),
                meta,
                yara: None,
                positions: Vec::new(),
                ..Finding::default()
            });
        }

        if let Some(certified_finding) = build_certified_doc_finding(
            ctx,
            &base_meta,
            signature_boundary,
            &annotation_overlays,
            &signature_field_overlays,
        ) {
            findings.push(certified_finding);
        }

        if !replace_targets.is_empty() {
            let mut meta = base_meta.clone();
            meta.insert("shadow.replace_count".into(), replace_targets.len().to_string());
            meta.insert("shadow.replace_objects".into(), replace_targets.join(", "));
            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "shadow_replace_attack".into(),
                severity: Severity::High,
                confidence: if extraction.prev_chain_valid {
                    Confidence::Strong
                } else {
                    Confidence::Probable
                },
                impact: Impact::Unknown,
                title: "Shadow replace attack indicators".into(),
                description:
                    "Post-signature revision changed page/content object semantics compared with the signed revision."
                        .into(),
                objects: replace_targets.clone(),
                evidence: replace_targets
                    .iter()
                    .filter_map(|object_ref| parse_obj_ref(object_ref))
                    .filter_map(|(obj, gen)| ctx.graph.get_object(obj, gen))
                    .map(|entry| span_to_evidence(entry.full_span, "Post-signature replaced object"))
                    .collect(),
                remediation: Some(
                    "Diff page content/resources against the signed revision and treat unsanctioned replacements as tampering."
                        .into(),
                ),
                meta,
                yara: None,
                positions: Vec::new(),
                ..Finding::default()
            });
        }

        if !overlay_objects.is_empty() && !replace_targets.is_empty() {
            let mut meta = base_meta;
            meta.insert("shadow.overlay_count".into(), overlay_objects.len().to_string());
            meta.insert("shadow.replace_count".into(), replace_targets.len().to_string());
            meta.insert("shadow.annotations_added".into(), annotation_overlays.len().to_string());
            meta.insert("shadow.form_fields_added".into(), form_field_overlays.len().to_string());
            meta.insert(
                "shadow.signature_fields_added".into(),
                signature_field_overlays.len().to_string(),
            );
            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "shadow_hide_replace_attack".into(),
                severity: Severity::Critical,
                confidence: if extraction.prev_chain_valid {
                    Confidence::Strong
                } else {
                    Confidence::Probable
                },
                impact: Impact::Unknown,
                title: "Shadow hide-and-replace attack indicators".into(),
                description:
                    "Post-signature revision combines overlay additions with content replacement, consistent with hide-and-replace tampering."
                        .into(),
                objects: {
                    let mut combined = overlay_objects.clone();
                    combined.extend(replace_targets.clone());
                    combined.sort();
                    combined.dedup();
                    combined
                },
                evidence: Vec::new(),
                remediation: Some(
                    "Reconstruct and compare signed vs current document states before trusting visual content."
                        .into(),
                ),
                meta,
                yara: None,
                positions: Vec::new(),
                ..Finding::default()
            });
        }

        Ok(findings)
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

fn is_overlay_annotation_or_field(dict: &PdfDict<'_>) -> bool {
    let is_annotation = is_annotation_overlay(dict);
    let is_form = is_form_field_overlay(dict);
    let has_appearance = dict.get_first(b"/AP").is_some();
    let has_rect = has_non_trivial_rect(dict);
    (is_annotation || is_form) && has_appearance && has_rect
}

fn is_annotation_overlay(dict: &PdfDict<'_>) -> bool {
    dict.get_first(b"/Subtype").is_some() || dict.get_first(b"/Annot").is_some()
}

fn is_form_field_overlay(dict: &PdfDict<'_>) -> bool {
    dict.get_first(b"/FT").is_some()
}

fn is_signature_field_overlay(dict: &PdfDict<'_>) -> bool {
    dict.has_name(b"/FT", b"/Sig")
}

fn has_non_trivial_rect(dict: &PdfDict<'_>) -> bool {
    let Some((_, rect_obj)) = dict.get_first(b"/Rect") else {
        return false;
    };
    let PdfAtom::Array(values) = &rect_obj.atom else {
        return false;
    };
    if values.len() != 4 {
        return false;
    }
    let mut nums = [0f64; 4];
    for (idx, value) in values.iter().enumerate() {
        nums[idx] = match value.atom {
            PdfAtom::Int(v) => v as f64,
            PdfAtom::Real(v) => v,
            _ => return false,
        };
    }
    (nums[2] - nums[0]).abs() >= 16.0 && (nums[3] - nums[1]).abs() >= 16.0
}

fn object_semantic_fingerprint(entry: &sis_pdf_pdf::graph::ObjEntry<'_>) -> String {
    match &entry.atom {
        PdfAtom::Dict(dict) => dict_fingerprint(dict, 0),
        PdfAtom::Stream(stream) => {
            let mut out = String::from("stream:");
            out.push_str(&dict_fingerprint(&stream.dict, 0));
            out
        }
        atom => atom_fingerprint(atom, 0),
    }
}

fn dict_fingerprint(dict: &PdfDict<'_>, depth: usize) -> String {
    if depth >= MAX_FINGERPRINT_DEPTH {
        return String::new();
    }
    let mut pairs = dict
        .entries
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                String::from_utf8_lossy(&key.decoded),
                obj_fingerprint(value, depth + 1)
            )
        })
        .collect::<Vec<_>>();
    pairs.sort();
    pairs.join(";")
}

fn obj_fingerprint(obj: &PdfObj<'_>, depth: usize) -> String {
    atom_fingerprint(&obj.atom, depth)
}

fn atom_fingerprint(atom: &PdfAtom<'_>, depth: usize) -> String {
    if depth >= MAX_FINGERPRINT_DEPTH {
        return String::new();
    }
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
            out.push_str(
                &values.iter().map(|v| obj_fingerprint(v, depth + 1)).collect::<Vec<_>>().join(","),
            );
            out
        }
        PdfAtom::Dict(dict) => format!("dict:{}", dict_fingerprint(dict, depth + 1)),
        PdfAtom::Stream(stream) => {
            format!("stream:{}", dict_fingerprint(&stream.dict, depth + 1))
        }
        PdfAtom::Ref { obj, gen } => format!("ref:{obj}:{gen}"),
    }
}

fn parse_obj_ref(value: &str) -> Option<(u32, u16)> {
    let mut parts = value.split_whitespace();
    let obj = parts.next()?.parse::<u32>().ok()?;
    let gen = parts.next()?.parse::<u16>().ok()?;
    Some((obj, gen))
}

#[derive(Default)]
struct DiffSummary {
    objects_added: Vec<String>,
    objects_modified: Vec<String>,
    objects_removed_estimate: usize,
    annotations_added: Vec<String>,
    form_fields_added: Vec<String>,
    signature_fields_added: Vec<String>,
}

fn build_diff_summary(
    ctx: &sis_pdf_core::scan::ScanContext<'_>,
    signature_boundary: u64,
) -> DiffSummary {
    let mut summary = DiffSummary::default();
    for ((obj, gen), idxs) in &ctx.graph.index {
        let versions =
            idxs.iter().filter_map(|idx| ctx.graph.objects.get(*idx)).collect::<Vec<_>>();
        let pre = versions
            .iter()
            .filter(|entry| entry.full_span.start < signature_boundary)
            .max_by_key(|entry| entry.full_span.start)
            .copied();
        let post = versions
            .iter()
            .filter(|entry| entry.full_span.start >= signature_boundary)
            .max_by_key(|entry| entry.full_span.start)
            .copied();
        let object_ref = format!("{obj} {gen} obj");

        match (pre, post) {
            (None, Some(post_entry)) => {
                summary.objects_added.push(object_ref.clone());
                if let Some(dict) = entry_dict(post_entry) {
                    if is_annotation_overlay(&dict) {
                        summary.annotations_added.push(object_ref.clone());
                    }
                    if is_form_field_overlay(&dict) {
                        summary.form_fields_added.push(object_ref.clone());
                    }
                    if is_signature_field_overlay(&dict) {
                        summary.signature_fields_added.push(object_ref.clone());
                    }
                }
            }
            (Some(pre_entry), Some(post_entry)) => {
                if object_semantic_fingerprint(pre_entry) != object_semantic_fingerprint(post_entry)
                {
                    summary.objects_modified.push(object_ref);
                }
            }
            (Some(_), None) | (None, None) => {}
        }
    }
    summary
}

fn merge_diff_summary_meta(
    meta: &mut std::collections::HashMap<String, String>,
    summary: &DiffSummary,
) {
    meta.insert("shadow.diff.objects_added".into(), summary.objects_added.len().to_string());
    meta.insert("shadow.diff.objects_modified".into(), summary.objects_modified.len().to_string());
    meta.insert("shadow.diff.objects_removed".into(), summary.objects_removed_estimate.to_string());
    meta.insert(
        "shadow.diff.objects_removed_note".into(),
        "not_observable_in_incremental_updates".into(),
    );
    meta.insert(
        "shadow.diff.annotations_added".into(),
        summary.annotations_added.len().to_string(),
    );
    meta.insert(
        "shadow.diff.form_fields_added".into(),
        summary.form_fields_added.len().to_string(),
    );
    meta.insert(
        "shadow.diff.signature_fields_added".into(),
        summary.signature_fields_added.len().to_string(),
    );
    if !summary.objects_added.is_empty() {
        meta.insert(
            "shadow.diff.objects_added_refs".into(),
            list_preview(summary.objects_added.as_slice(), 12),
        );
    }
    if !summary.objects_modified.is_empty() {
        meta.insert(
            "shadow.diff.objects_modified_refs".into(),
            list_preview(summary.objects_modified.as_slice(), 12),
        );
    }
    if !summary.annotations_added.is_empty() {
        meta.insert(
            "shadow.diff.annotations_added_refs".into(),
            list_preview(summary.annotations_added.as_slice(), 12),
        );
    }
    if !summary.form_fields_added.is_empty() {
        meta.insert(
            "shadow.diff.form_fields_added_refs".into(),
            list_preview(summary.form_fields_added.as_slice(), 12),
        );
    }
}

fn list_preview(values: &[String], max_items: usize) -> String {
    if values.len() <= max_items {
        return values.join(", ");
    }
    let shown = values.iter().take(max_items).cloned().collect::<Vec<_>>().join(", ");
    format!("{shown} (+{} more)", values.len() - max_items)
}

fn build_certified_doc_finding(
    ctx: &sis_pdf_core::scan::ScanContext<'_>,
    base_meta: &std::collections::HashMap<String, String>,
    signature_boundary: u64,
    annotation_overlays: &[String],
    signature_field_overlays: &[String],
) -> Option<Finding> {
    let certification = extract_certification_policy(ctx, signature_boundary)?;
    if annotation_overlays.is_empty() && signature_field_overlays.is_empty() {
        return None;
    }

    let mut disallowed_changes = Vec::new();
    if certification.permission_level <= 2 && !annotation_overlays.is_empty() {
        disallowed_changes.push("annotations");
    }
    if certification.permission_level <= 1 && !signature_field_overlays.is_empty() {
        disallowed_changes.push("signature_fields");
    }
    let has_disallowed = !disallowed_changes.is_empty();
    let (severity, confidence) = if has_disallowed {
        if certification.permission_level <= 1 {
            (Severity::High, Confidence::Strong)
        } else {
            (Severity::High, Confidence::Probable)
        }
    } else {
        (Severity::Medium, Confidence::Tentative)
    };

    let mut objects = annotation_overlays.to_vec();
    objects.extend(signature_field_overlays.iter().cloned());
    objects.sort();
    objects.dedup();

    let mut evidence = Vec::new();
    for object_ref in &objects {
        if let Some((obj, gen)) = parse_obj_ref(object_ref) {
            if let Some(entry) = ctx.graph.get_object(obj, gen) {
                evidence
                    .push(span_to_evidence(entry.full_span, "Post-certification visual object"));
            }
        }
    }

    let mut meta = base_meta.clone();
    meta.insert("certified.permission_level".into(), certification.permission_level.to_string());
    meta.insert("certified.signature_object".into(), certification.signature_object);
    if let Some(perms_source) = certification.perms_source {
        meta.insert("certified.perms_source".into(), perms_source);
    }
    meta.insert("certified.annotations_added".into(), annotation_overlays.len().to_string());
    meta.insert(
        "certified.signature_fields_added".into(),
        signature_field_overlays.len().to_string(),
    );
    if has_disallowed {
        meta.insert("certified.permission_violation".into(), "true".into());
        meta.insert("certified.disallowed_changes".into(), disallowed_changes.join(","));
    } else {
        meta.insert("certified.permission_violation".into(), "false".into());
    }

    Some(Finding {
        id: String::new(),
        surface: AttackSurface::CryptoSignatures,
        kind: "certified_doc_manipulation".into(),
        severity,
        confidence,
        impact: Impact::High,
        title: "Certified document manipulation indicators".into(),
        description: "Certified document received post-certification visual updates (annotation/signature overlays) inconsistent with DocMDP permissions or analyst trust expectations.".into(),
        objects,
        evidence,
        remediation: Some(
            "Validate DocMDP permission level (P1-P3), review incremental updates, and treat post-certification overlays as potential tampering."
                .into(),
        ),
        meta,
        yara: None,
        positions: Vec::new(),
        ..Finding::default()
    })
}

struct CertificationPolicy {
    permission_level: i64,
    signature_object: String,
    perms_source: Option<String>,
}

fn extract_certification_policy(
    ctx: &sis_pdf_core::scan::ScanContext<'_>,
    signature_boundary: u64,
) -> Option<CertificationPolicy> {
    let mut candidate: Option<CertificationPolicy> = None;

    if let Some(catalog) = catalog_object_dict(ctx) {
        if let Some((_, perms_obj)) = catalog.get_first(b"/Perms") {
            if let Some(perms_dict) = ctx.graph.resolve_to_dict(perms_obj) {
                if let Some((_, docmdp_obj)) = perms_dict.get_first(b"/DocMDP") {
                    if let Some(signature_entry) = ctx.graph.resolve_ref(docmdp_obj) {
                        if signature_entry.full_span.start < signature_boundary {
                            if let Some(dict) = entry_dict(&signature_entry) {
                                if let Some(level) =
                                    extract_docmdp_permission_from_signature(ctx, &dict)
                                {
                                    candidate = Some(CertificationPolicy {
                                        permission_level: level,
                                        signature_object: format!(
                                            "{} {} obj",
                                            signature_entry.obj, signature_entry.gen
                                        ),
                                        perms_source: Some("/Catalog/Perms/DocMDP".into()),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if candidate.is_some() {
        return candidate;
    }

    for entry in &ctx.graph.objects {
        if entry.full_span.start >= signature_boundary {
            continue;
        }
        let Some(dict) = entry_dict(entry) else {
            continue;
        };
        if !is_signature_dict(&dict) {
            continue;
        }
        if let Some(level) = extract_docmdp_permission_from_signature(ctx, &dict) {
            return Some(CertificationPolicy {
                permission_level: level,
                signature_object: format!("{} {} obj", entry.obj, entry.gen),
                perms_source: Some("signature.Reference.DocMDP".into()),
            });
        }
    }

    None
}

fn catalog_object_dict<'a>(ctx: &'a sis_pdf_core::scan::ScanContext<'a>) -> Option<PdfDict<'a>> {
    for entry in &ctx.graph.objects {
        let Some(dict) = entry_dict(entry) else {
            continue;
        };
        if dict.has_name(b"/Type", b"/Catalog") {
            return Some(dict.clone());
        }
    }
    None
}

fn extract_docmdp_permission_from_signature(
    ctx: &sis_pdf_core::scan::ScanContext<'_>,
    signature_dict: &PdfDict<'_>,
) -> Option<i64> {
    let (_, reference_obj) = signature_dict.get_first(b"/Reference")?;
    let PdfAtom::Array(reference_items) = &reference_obj.atom else {
        return None;
    };
    for reference in reference_items {
        let Some(reference_dict) = ctx.graph.resolve_to_dict(reference) else {
            continue;
        };
        if !reference_dict.has_name(b"/TransformMethod", b"/DocMDP") {
            continue;
        }
        let (_, transform_obj) = reference_dict.get_first(b"/TransformParams")?;
        let Some(transform_dict) = ctx.graph.resolve_to_dict(transform_obj) else {
            continue;
        };
        if let Some((_, p_obj)) = transform_dict.get_first(b"/P") {
            if let PdfAtom::Int(value) = p_obj.atom {
                if (1..=3).contains(&value) {
                    return Some(value);
                }
            }
        }
    }
    None
}

fn is_signature_dict(dict: &PdfDict<'_>) -> bool {
    dict.has_name(b"/Type", b"/Sig") || dict.get_first(b"/ByteRange").is_some()
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfName, PdfObj};
    use sis_pdf_pdf::span::Span;

    use super::{atom_fingerprint, dict_fingerprint, MAX_FINGERPRINT_DEPTH};

    fn dummy_span() -> Span {
        Span { start: 0, end: 0 }
    }

    fn make_name(decoded: &[u8]) -> PdfName<'static> {
        PdfName { span: dummy_span(), raw: Cow::Owned(decoded.to_vec()), decoded: decoded.to_vec() }
    }

    fn make_int_obj(value: i64) -> PdfObj<'static> {
        PdfObj { span: dummy_span(), atom: PdfAtom::Int(value) }
    }

    fn make_dict_with_entry(key: &[u8], value: PdfObj<'static>) -> PdfDict<'static> {
        PdfDict { span: dummy_span(), entries: vec![(make_name(key), value)] }
    }

    /// Build a chain of nested dicts `depth` levels deep.
    fn build_nested_dict(depth: usize) -> PdfDict<'static> {
        if depth == 0 {
            make_dict_with_entry(b"/Value", make_int_obj(42))
        } else {
            let inner = build_nested_dict(depth - 1);
            let inner_obj = PdfObj { span: dummy_span(), atom: PdfAtom::Dict(inner) };
            make_dict_with_entry(b"/Inner", inner_obj)
        }
    }

    #[test]
    fn fingerprint_depth_guard_does_not_stack_overflow() {
        // Build a dict nested far beyond MAX_FINGERPRINT_DEPTH.
        let deep = build_nested_dict(MAX_FINGERPRINT_DEPTH + 10);
        // Must complete without panicking (no stack overflow).
        let result = dict_fingerprint(&deep, 0);
        assert!(!result.is_empty(), "top-level fingerprint should not be empty");
    }

    #[test]
    fn atom_fingerprint_truncates_at_max_depth() {
        // Calling atom_fingerprint at exactly MAX_FINGERPRINT_DEPTH must return empty.
        let atom = PdfAtom::Int(99);
        let result = atom_fingerprint(&atom, MAX_FINGERPRINT_DEPTH);
        assert_eq!(result, "", "fingerprint at max depth should be empty");
    }

    #[test]
    fn atom_fingerprint_works_below_max_depth() {
        let atom = PdfAtom::Int(7);
        let result = atom_fingerprint(&atom, 0);
        assert_eq!(result, "int:7");
    }
}
