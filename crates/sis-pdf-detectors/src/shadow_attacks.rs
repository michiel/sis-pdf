use anyhow::Result;
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::revision_extract::extract_revision_content;
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};

use crate::entry_dict;

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
            if is_overlay_annotation_or_field(dict) {
                overlay_objects.push(format!("{} {} obj", entry.obj, entry.gen));
            }
        }

        let mut findings = Vec::new();
        let post_update_bytes = ctx.bytes.len() as u64 - signature_boundary;
        let mut base_meta = std::collections::HashMap::new();
        base_meta.insert("shadow.signature_boundary".into(), signature_boundary.to_string());
        base_meta.insert("shadow.post_update_bytes".into(), post_update_bytes.to_string());
        base_meta.insert("shadow.prev_chain_valid".into(), extraction.prev_chain_valid.to_string());
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
                impact: None,
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
                position: None,
                positions: Vec::new(),
                ..Finding::default()
            });
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
                impact: None,
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
                position: None,
                positions: Vec::new(),
                ..Finding::default()
            });
        }

        if !overlay_objects.is_empty() && !replace_targets.is_empty() {
            let mut meta = base_meta;
            meta.insert("shadow.overlay_count".into(), overlay_objects.len().to_string());
            meta.insert("shadow.replace_count".into(), replace_targets.len().to_string());
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
                impact: None,
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
                position: None,
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
    let is_annotation =
        dict.get_first(b"/Subtype").is_some() || dict.get_first(b"/Annot").is_some();
    let is_form = dict.get_first(b"/FT").is_some();
    let has_appearance = dict.get_first(b"/AP").is_some();
    let has_rect = has_non_trivial_rect(dict);
    (is_annotation || is_form) && has_appearance && has_rect
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

fn parse_obj_ref(value: &str) -> Option<(u32, u16)> {
    let mut parts = value.split_whitespace();
    let obj = parts.next()?.parse::<u32>().ok()?;
    let gen = parts.next()?.parse::<u16>().ok()?;
    Some((obj, gen))
}
