use anyhow::Result;
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_core::page_tree::build_page_tree;
use sis_pdf_core::revision_extract::extract_revision_content;
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::content::{parse_content_ops, ContentOperand};
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj, PdfStream};
use std::collections::{BTreeMap, BTreeSet};

use crate::entry_dict;

pub struct ResourceUsageSemanticsDetector;

impl Detector for ResourceUsageSemanticsDetector {
    fn id(&self) -> &'static str {
        "resource_usage_semantics"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::FileStructure
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH | Needs::STREAM_DECODE | Needs::PAGE_CONTENT
    }

    fn cost(&self) -> Cost {
        Cost::Moderate
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        findings.extend(find_signature_scope_overrides(ctx));

        let page_tree = build_page_tree(&ctx.graph);
        for page in &page_tree.pages {
            let Some(page_entry) = ctx.graph.get_object(page.obj, page.gen) else {
                continue;
            };
            let Some(page_dict) = entry_dict(page_entry) else {
                continue;
            };
            let page_label = format!("{} {} obj", page.obj, page.gen);
            let resources = resolve_effective_resources(&ctx.graph, page_dict);
            let mut used_fonts = BTreeSet::new();
            let mut used_xobjects = BTreeSet::new();
            let mut do_count = 0usize;
            let mut tf_count = 0usize;
            let mut hidden_invocations = 0usize;
            let mut inline_findings = Vec::new();

            for stream in page_content_streams(ctx, page_dict) {
                let Ok(decoded) = ctx.decoded.get_or_decode(ctx.bytes, &stream) else {
                    continue;
                };
                let mut clip_active = false;
                let ops = parse_content_ops(&decoded.data);
                for op in ops {
                    match op.op.as_str() {
                        "W" | "W*" => clip_active = true,
                        "n" | "S" | "s" | "f" | "F" | "B" | "B*" | "b" | "b*" | "Q" => {
                            clip_active = false
                        }
                        "Tf" => {
                            tf_count += 1;
                            if let Some(name) = first_name(&op.operands) {
                                used_fonts.insert(name);
                            }
                        }
                        "Do" => {
                            do_count += 1;
                            if clip_active {
                                hidden_invocations += 1;
                            }
                            if let Some(name) = first_name(&op.operands) {
                                used_xobjects.insert(name);
                            }
                        }
                        _ => {}
                    }
                }
                inline_findings.extend(inline_image_findings(
                    &decoded.data,
                    page.obj,
                    page.gen,
                    stream.data_span,
                ));
            }
            findings.extend(inline_findings);

            let unused_fonts = resources
                .effective_fonts
                .keys()
                .filter(|name| !used_fonts.contains(*name))
                .cloned()
                .collect::<Vec<_>>();
            let unused_xobjects = resources
                .effective_xobjects
                .keys()
                .filter(|name| !used_xobjects.contains(*name))
                .cloned()
                .collect::<Vec<_>>();
            if !unused_fonts.is_empty() || !unused_xobjects.is_empty() {
                let (severity, confidence, impact) =
                    resource_semantics_profile("resource.declared_but_unused")
                        .expect("profile exists for declared-but-unused resources");
                let mut meta = std::collections::HashMap::new();
                meta.insert("resource.page".into(), page.number.to_string());
                meta.insert("resource.unused_font_count".into(), unused_fonts.len().to_string());
                meta.insert(
                    "resource.unused_xobject_count".into(),
                    unused_xobjects.len().to_string(),
                );
                if !unused_fonts.is_empty() {
                    meta.insert("resource.unused_fonts".into(), unused_fonts.join(","));
                }
                if !unused_xobjects.is_empty() {
                    meta.insert("resource.unused_xobjects".into(), unused_xobjects.join(","));
                }
                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::FileStructure,
                    kind: "resource.declared_but_unused".into(),
                    severity,
                    confidence,
                    impact: Some(impact),
                    title: "Declared resources are unused".into(),
                    description:
                        "Page resources declare fonts or XObjects that were not referenced by content operators."
                            .into(),
                    objects: vec![page_label.clone()],
                    evidence: vec![span_to_evidence(page_entry.full_span, "Page resource declarations")],
                    remediation: Some(
                        "Review unused resources for concealment or dead-asset staging.".into(),
                    ),
                    meta,
                    yara: None,
                    position: None,
                    positions: vec![format!("page:{}", page.number)],
                    ..Finding::default()
                });
            }

            if hidden_invocations > 0 {
                let (severity, confidence, impact) =
                    resource_semantics_profile("resource.hidden_invocation_pattern")
                        .expect("profile exists for hidden invocation pattern");
                let mut meta = std::collections::HashMap::new();
                meta.insert("resource.page".into(), page.number.to_string());
                meta.insert(
                    "resource.hidden_invocation_count".into(),
                    hidden_invocations.to_string(),
                );
                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::FileStructure,
                    kind: "resource.hidden_invocation_pattern".into(),
                    severity,
                    confidence,
                    impact: Some(impact),
                    title: "Hidden resource invocation pattern".into(),
                    description:
                        "XObject invocations occurred while clipping context was active, indicating potentially concealed rendering."
                            .into(),
                    objects: vec![page_label.clone()],
                    evidence: vec![span_to_evidence(page_entry.full_span, "Hidden invocation context")],
                    remediation: Some(
                        "Inspect clipping and draw-order semantics for concealed content.".into(),
                    ),
                    meta,
                    yara: None,
                    position: None,
                    positions: vec![format!("page:{}", page.number)],
                    ..Finding::default()
                });
            }

            if do_count + tf_count >= 250 {
                let (severity, confidence, impact) =
                    resource_semantics_profile("resource.operator_usage_anomalous")
                        .expect("profile exists for anomalous operator usage");
                let mut meta = std::collections::HashMap::new();
                meta.insert("resource.page".into(), page.number.to_string());
                meta.insert("resource.do_count".into(), do_count.to_string());
                meta.insert("resource.tf_count".into(), tf_count.to_string());
                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::FileStructure,
                    kind: "resource.operator_usage_anomalous".into(),
                    severity,
                    confidence,
                    impact: Some(impact),
                    title: "Anomalous resource operator usage".into(),
                    description:
                        "Content stream contains unusually high resource invocation volume, which can indicate obfuscation or parser stress behaviour."
                            .into(),
                    objects: vec![page_label.clone()],
                    evidence: vec![span_to_evidence(page_entry.full_span, "Content operator density")],
                    remediation: Some("Review content stream operator density and nesting.".into()),
                    meta,
                    yara: None,
                    position: None,
                    positions: vec![format!("page:{}", page.number)],
                    ..Finding::default()
                });
            }

            let font_conflicts =
                conflicting_resource_keys(&resources.local_fonts, &resources.inherited_fonts);
            if !font_conflicts.is_empty() {
                let (severity, confidence, impact) =
                    resource_semantics_profile("resource.inheritance_conflict_font")
                        .expect("profile exists for font inheritance conflict");
                let mut meta = std::collections::HashMap::new();
                meta.insert("resource.page".into(), page.number.to_string());
                meta.insert("resource.font_conflicts".into(), font_conflicts.join(","));
                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::FileStructure,
                    kind: "resource.inheritance_conflict_font".into(),
                    severity,
                    confidence,
                    impact: Some(impact),
                    title: "Font inheritance conflict".into(),
                    description:
                        "Page-local font resources override inherited entries with conflicting targets."
                            .into(),
                    objects: vec![page_label.clone()],
                    evidence: vec![span_to_evidence(page_entry.full_span, "Font inheritance conflict")],
                    remediation: Some("Validate page tree resource inheritance for font consistency.".into()),
                    meta,
                    yara: None,
                    position: None,
                    positions: vec![format!("page:{}", page.number)],
                    ..Finding::default()
                });
            }
            let xobject_conflicts =
                conflicting_resource_keys(&resources.local_xobjects, &resources.inherited_xobjects);
            if !xobject_conflicts.is_empty() {
                let (severity, confidence, impact) =
                    resource_semantics_profile("resource.inheritance_conflict_xobject")
                        .expect("profile exists for xobject inheritance conflict");
                let mut meta = std::collections::HashMap::new();
                meta.insert("resource.page".into(), page.number.to_string());
                meta.insert("resource.xobject_conflicts".into(), xobject_conflicts.join(","));
                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::FileStructure,
                    kind: "resource.inheritance_conflict_xobject".into(),
                    severity,
                    confidence,
                    impact: Some(impact),
                    title: "XObject inheritance conflict".into(),
                    description:
                        "Page-local XObject resources override inherited entries with conflicting targets."
                            .into(),
                    objects: vec![page_label.clone()],
                    evidence: vec![span_to_evidence(page_entry.full_span, "XObject inheritance conflict")],
                    remediation: Some(
                        "Validate page tree resource inheritance for XObject consistency.".into(),
                    ),
                    meta,
                    yara: None,
                    position: None,
                    positions: vec![format!("page:{}", page.number)],
                    ..Finding::default()
                });
            }
            if !font_conflicts.is_empty() || !xobject_conflicts.is_empty() {
                let (severity, confidence, impact) =
                    resource_semantics_profile("resource.inheritance_override_suspicious")
                        .expect("profile exists for suspicious inheritance override");
                let mut meta = std::collections::HashMap::new();
                meta.insert("resource.page".into(), page.number.to_string());
                meta.insert(
                    "resource.override_conflict_count".into(),
                    (font_conflicts.len() + xobject_conflicts.len()).to_string(),
                );
                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::FileStructure,
                    kind: "resource.inheritance_override_suspicious".into(),
                    severity,
                    confidence,
                    impact: Some(impact),
                    title: "Suspicious resource inheritance override".into(),
                    description:
                        "Page resources override inherited mappings in conflicting ways, which may cause renderer differentials."
                            .into(),
                    objects: vec![page_label],
                    evidence: vec![span_to_evidence(page_entry.full_span, "Resource inheritance override")],
                    remediation: Some(
                        "Compare effective inherited resources against page-local overrides.".into(),
                    ),
                    meta,
                    yara: None,
                    position: None,
                    positions: vec![format!("page:{}", page.number)],
                    ..Finding::default()
                });
            }
        }
        Ok(findings)
    }
}

#[derive(Default)]
struct EffectiveResources {
    effective_fonts: BTreeMap<String, String>,
    effective_xobjects: BTreeMap<String, String>,
    local_fonts: BTreeMap<String, String>,
    local_xobjects: BTreeMap<String, String>,
    inherited_fonts: BTreeMap<String, String>,
    inherited_xobjects: BTreeMap<String, String>,
}

fn resolve_effective_resources(
    graph: &sis_pdf_pdf::ObjectGraph<'_>,
    page_dict: &PdfDict<'_>,
) -> EffectiveResources {
    let mut chain = Vec::new();
    let mut current = Some(page_dict.clone());
    while let Some(dict) = current {
        chain.push(dict.clone());
        current = dict.get_first(b"/Parent").and_then(|(_, parent)| resolve_dict(graph, parent));
    }
    let mut out = EffectiveResources::default();
    for (idx, dict) in chain.iter().rev().enumerate() {
        let is_local = idx + 1 == chain.len();
        if let Some((_, resources_obj)) = dict.get_first(b"/Resources") {
            if let Some(resources) = resolve_dict(graph, resources_obj) {
                collect_resource_namespace(
                    &resources,
                    b"/Font",
                    &mut out.effective_fonts,
                    is_local,
                    &mut out.local_fonts,
                    &mut out.inherited_fonts,
                );
                collect_resource_namespace(
                    &resources,
                    b"/XObject",
                    &mut out.effective_xobjects,
                    is_local,
                    &mut out.local_xobjects,
                    &mut out.inherited_xobjects,
                );
            }
        }
    }
    out
}

fn collect_resource_namespace(
    resources: &PdfDict<'_>,
    key: &[u8],
    effective: &mut BTreeMap<String, String>,
    is_local: bool,
    local: &mut BTreeMap<String, String>,
    inherited: &mut BTreeMap<String, String>,
) {
    if let Some((_, obj)) = resources.get_first(key) {
        if let Some(dict) = obj_as_dict(obj) {
            for (name, value) in &dict.entries {
                let token = String::from_utf8_lossy(&name.decoded).to_string();
                let target = object_ref_label(value);
                effective.insert(token.clone(), target.clone());
                if is_local {
                    local.insert(token, target);
                } else {
                    inherited.insert(token, target);
                }
            }
        }
    }
}

fn conflicting_resource_keys(
    local: &BTreeMap<String, String>,
    inherited: &BTreeMap<String, String>,
) -> Vec<String> {
    local
        .iter()
        .filter_map(|(key, value)| {
            inherited
                .get(key)
                .filter(|inherited_value| *inherited_value != value)
                .map(|_| key.clone())
        })
        .collect()
}

fn object_ref_label(obj: &PdfObj<'_>) -> String {
    match obj.atom {
        PdfAtom::Ref { obj, gen } => format!("{obj} {gen} R"),
        _ => "-".into(),
    }
}

fn page_content_streams<'a>(
    ctx: &'a sis_pdf_core::scan::ScanContext<'a>,
    dict: &PdfDict<'a>,
) -> Vec<PdfStream<'a>> {
    let mut out = Vec::new();
    if let Some((_, obj)) = dict.get_first(b"/Contents") {
        match &obj.atom {
            PdfAtom::Stream(stream) => out.push(stream.clone()),
            PdfAtom::Array(items) => {
                for item in items {
                    if let Some(stream) = resolve_stream(ctx, item) {
                        out.push(stream);
                    }
                }
            }
            _ => {
                if let Some(stream) = resolve_stream(ctx, obj) {
                    out.push(stream);
                }
            }
        }
    }
    out
}

fn resolve_stream<'a>(
    ctx: &'a sis_pdf_core::scan::ScanContext<'a>,
    obj: &PdfObj<'a>,
) -> Option<PdfStream<'a>> {
    match &obj.atom {
        PdfAtom::Stream(stream) => Some(stream.clone()),
        PdfAtom::Ref { .. } => ctx.graph.resolve_ref(obj).and_then(|entry| match &entry.atom {
            PdfAtom::Stream(stream) => Some(stream.clone()),
            _ => None,
        }),
        _ => None,
    }
}

fn resolve_dict<'a>(
    graph: &'a sis_pdf_pdf::ObjectGraph<'a>,
    obj: &PdfObj<'a>,
) -> Option<PdfDict<'a>> {
    match &obj.atom {
        PdfAtom::Dict(dict) => Some(dict.clone()),
        PdfAtom::Stream(stream) => Some(stream.dict.clone()),
        PdfAtom::Ref { .. } => graph.resolve_ref(obj).and_then(|entry| match &entry.atom {
            PdfAtom::Dict(dict) => Some(dict.clone()),
            PdfAtom::Stream(stream) => Some(stream.dict.clone()),
            _ => None,
        }),
        _ => None,
    }
}

fn obj_as_dict<'a>(obj: &'a PdfObj<'a>) -> Option<&'a PdfDict<'a>> {
    match &obj.atom {
        PdfAtom::Dict(dict) => Some(dict),
        _ => None,
    }
}

fn first_name(operands: &[ContentOperand]) -> Option<String> {
    operands.iter().find_map(|operand| match operand {
        ContentOperand::Name(name) => Some(name.clone()),
        _ => None,
    })
}

fn find_signature_scope_overrides(ctx: &sis_pdf_core::scan::ScanContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let extraction = extract_revision_content(ctx);
    let Some(boundary) = extraction.signatures.iter().map(|s| s.covered_end).max() else {
        return findings;
    };
    let mut emitted = BTreeSet::new();
    for entry in &ctx.graph.objects {
        let Some(dict) = entry_dict(entry) else {
            continue;
        };
        let revisions = ctx.graph.all_objects_by_id(entry.obj, entry.gen).len();
        if revisions <= 1 || entry.full_span.start < boundary {
            continue;
        }
        let object_id = format!("{} {} obj", entry.obj, entry.gen);
        let mut common_meta = std::collections::HashMap::new();
        common_meta.insert("resource.object_id".into(), object_id.clone());
        common_meta.insert("resource.shadowed_revisions".into(), revisions.to_string());
        common_meta.insert("resource.signature_boundary".into(), boundary.to_string());
        if is_image_dict(dict) && emitted.insert((entry.obj, entry.gen, "image")) {
            let (severity, confidence, impact) =
                resource_semantics_profile("image.override_outside_signature_scope")
                    .expect("profile exists for image signature override");
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::Images,
                kind: "image.override_outside_signature_scope".into(),
                severity,
                confidence,
                impact: Some(impact),
                title: "Image override outside signature scope".into(),
                description: "Image object override occurs after signature coverage boundary."
                    .into(),
                objects: vec![object_id.clone()],
                evidence: vec![span_to_evidence(entry.full_span, "Post-signature image override")],
                remediation: Some(
                    "Compare signed revision image resources against current state.".into(),
                ),
                meta: common_meta.clone(),
                yara: None,
                position: None,
                positions: Vec::new(),
                ..Finding::default()
            });
        }
        if is_font_related_dict(dict) && emitted.insert((entry.obj, entry.gen, "font")) {
            let (severity, confidence, impact) =
                resource_semantics_profile("font.override_outside_signature_scope")
                    .expect("profile exists for font signature override");
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::StreamsAndFilters,
                kind: "font.override_outside_signature_scope".into(),
                severity,
                confidence,
                impact: Some(impact),
                title: "Font override outside signature scope".into(),
                description: "Font object override occurs after signature coverage boundary."
                    .into(),
                objects: vec![object_id.clone()],
                evidence: vec![span_to_evidence(entry.full_span, "Post-signature font override")],
                remediation: Some(
                    "Compare signed revision font resources against current state.".into(),
                ),
                meta: common_meta.clone(),
                yara: None,
                position: None,
                positions: Vec::new(),
                ..Finding::default()
            });
        }
        if emitted.insert((entry.obj, entry.gen, "resource")) {
            let (severity, confidence, impact) =
                resource_semantics_profile("resource.override_outside_signature_scope")
                    .expect("profile exists for resource signature override");
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::FileStructure,
                kind: "resource.override_outside_signature_scope".into(),
                severity,
                confidence,
                impact: Some(impact),
                title: "Resource override outside signature scope".into(),
                description:
                    "Object override occurs after signature coverage boundary and may alter rendered semantics."
                        .into(),
                objects: vec![object_id],
                evidence: vec![span_to_evidence(entry.full_span, "Post-signature resource override")],
                remediation: Some(
                    "Perform signed-state reconstruction and verify post-signature object deltas."
                        .into(),
                ),
                meta: common_meta,
                yara: None,
                position: None,
                positions: Vec::new(),
                ..Finding::default()
            });
        }
    }
    findings
}

fn is_image_dict(dict: &PdfDict<'_>) -> bool {
    dict.has_name(b"/Subtype", b"/Image")
}

fn is_font_related_dict(dict: &PdfDict<'_>) -> bool {
    dict.has_name(b"/Type", b"/Font")
        || dict.get_first(b"/FontDescriptor").is_some()
        || dict.get_first(b"/FontFile").is_some()
        || dict.get_first(b"/FontFile2").is_some()
        || dict.get_first(b"/FontFile3").is_some()
}

fn inline_image_findings(
    decoded: &[u8],
    obj: u32,
    gen: u16,
    span: sis_pdf_pdf::span::Span,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for info in parse_inline_images(decoded) {
        if info.filter_count > 1 && info.decode_parms_count == 1 {
            let (severity, confidence, impact) =
                resource_semantics_profile("image.inline_structure_filter_chain_inconsistent")
                    .expect("profile exists for inline filter chain inconsistency");
            findings.push(inline_finding(
                "image.inline_structure_filter_chain_inconsistent",
                "Inline image filter/decode parms mismatch",
                "Inline image uses multiple filters with a single decode parms entry.",
                severity,
                confidence,
                impact,
                obj,
                gen,
                span,
                &info,
            ));
        }
        if info.decode_count > 0 && info.decode_count % 2 != 0 {
            let (severity, confidence, impact) =
                resource_semantics_profile("image.inline_decode_array_invalid")
                    .expect("profile exists for inline decode array invalid");
            findings.push(inline_finding(
                "image.inline_decode_array_invalid",
                "Inline image decode array invalid",
                "Inline image /Decode entry has non-paired element count.",
                severity,
                confidence,
                impact,
                obj,
                gen,
                span,
                &info,
            ));
        }
        if info.image_mask && info.has_smask {
            let (severity, confidence, impact) =
                resource_semantics_profile("image.inline_mask_inconsistent")
                    .expect("profile exists for inline mask inconsistency");
            findings.push(inline_finding(
                "image.inline_mask_inconsistent",
                "Inline image mask inconsistency",
                "Inline image sets ImageMask together with SMask-style semantics.",
                severity,
                confidence,
                impact,
                obj,
                gen,
                span,
                &info,
            ));
        }
    }
    findings
}

fn inline_finding(
    kind: &str,
    title: &str,
    description: &str,
    severity: Severity,
    confidence: Confidence,
    impact: Impact,
    obj: u32,
    gen: u16,
    span: sis_pdf_pdf::span::Span,
    info: &InlineImageInfo,
) -> Finding {
    let mut meta = std::collections::HashMap::new();
    meta.insert("inline_image.filter_count".into(), info.filter_count.to_string());
    meta.insert("inline_image.decode_parms_count".into(), info.decode_parms_count.to_string());
    meta.insert("inline_image.decode_count".into(), info.decode_count.to_string());
    Finding {
        id: String::new(),
        surface: AttackSurface::Images,
        kind: kind.into(),
        severity,
        confidence,
        impact: Some(impact),
        title: title.into(),
        description: description.into(),
        objects: vec![format!("{obj} {gen} obj")],
        evidence: vec![span_to_evidence(span, "Inline image content stream")],
        remediation: Some("Inspect inline image dictionary semantics and decode behaviour.".into()),
        meta,
        yara: None,
        position: None,
        positions: Vec::new(),
        ..Finding::default()
    }
}

fn resource_semantics_profile(kind: &str) -> Option<(Severity, Confidence, Impact)> {
    match kind {
        "resource.declared_but_unused" => Some((Severity::Low, Confidence::Probable, Impact::Low)),
        "resource.hidden_invocation_pattern" => {
            Some((Severity::Medium, Confidence::Probable, Impact::Medium))
        }
        "resource.operator_usage_anomalous" => {
            Some((Severity::Medium, Confidence::Tentative, Impact::Medium))
        }
        "resource.inheritance_conflict_font" | "resource.inheritance_conflict_xobject" => {
            Some((Severity::Medium, Confidence::Strong, Impact::Medium))
        }
        "resource.inheritance_override_suspicious" => {
            Some((Severity::Medium, Confidence::Probable, Impact::Medium))
        }
        "resource.override_outside_signature_scope"
        | "image.override_outside_signature_scope"
        | "font.override_outside_signature_scope" => {
            Some((Severity::High, Confidence::Strong, Impact::High))
        }
        "image.inline_structure_filter_chain_inconsistent" => {
            Some((Severity::Medium, Confidence::Strong, Impact::Medium))
        }
        "image.inline_decode_array_invalid" => {
            Some((Severity::Low, Confidence::Strong, Impact::Low))
        }
        "image.inline_mask_inconsistent" => {
            Some((Severity::Medium, Confidence::Probable, Impact::Medium))
        }
        _ => None,
    }
}

#[derive(Default, Clone)]
struct InlineImageInfo {
    filter_count: usize,
    decode_parms_count: usize,
    decode_count: usize,
    image_mask: bool,
    has_smask: bool,
}

fn parse_inline_images(decoded: &[u8]) -> Vec<InlineImageInfo> {
    let text = String::from_utf8_lossy(decoded);
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(start_rel) = text[cursor..].find("BI") {
        let start = cursor + start_rel + 2;
        let rest = &text[start..];
        let Some(id_rel) = rest.find("ID") else {
            break;
        };
        let dict_text = &rest[..id_rel];
        let Some(ei_rel) = rest[id_rel + 2..].find("EI") else {
            break;
        };
        let info = parse_inline_dict(dict_text);
        out.push(info);
        cursor = start + id_rel + 2 + ei_rel + 2;
    }
    out
}

fn parse_inline_dict(dict_text: &str) -> InlineImageInfo {
    let mut info = InlineImageInfo::default();
    let tokens = dict_text
        .split_whitespace()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    let mut i = 0usize;
    while i < tokens.len() {
        let key = tokens[i];
        if !key.starts_with('/') {
            i += 1;
            continue;
        }
        let value = tokens.get(i + 1).copied().unwrap_or_default();
        match key {
            "/F" | "/Filter" => {
                if value.starts_with('[') {
                    let mut count = 0usize;
                    let mut j = i + 1;
                    while j < tokens.len() {
                        let token = tokens[j];
                        let clean = token.trim_start_matches('[').trim_end_matches(']');
                        if clean.starts_with('/') {
                            count += 1;
                        }
                        if token.ends_with(']') {
                            break;
                        }
                        j += 1;
                    }
                    info.filter_count = count.max(1);
                    i = j;
                } else if !value.is_empty() {
                    info.filter_count = 1;
                }
            }
            "/DP" | "/DecodeParms" => {
                if value.starts_with('[') {
                    let mut count = 0usize;
                    let mut j = i + 1;
                    while j < tokens.len() {
                        let token = tokens[j];
                        let clean = token.trim_start_matches('[').trim_end_matches(']');
                        if clean.starts_with("<<") {
                            count += 1;
                        }
                        if token.ends_with(']') {
                            break;
                        }
                        j += 1;
                    }
                    info.decode_parms_count = count.max(1);
                    i = j;
                } else if !value.is_empty() {
                    info.decode_parms_count = 1;
                }
            }
            "/D" | "/Decode" => {
                if value.starts_with('[') {
                    let mut count = 0usize;
                    let mut j = i + 1;
                    while j < tokens.len() {
                        let token = tokens[j];
                        let clean = token.trim_start_matches('[').trim_end_matches(']');
                        if clean.parse::<f32>().is_ok() {
                            count += 1;
                        }
                        if token.ends_with(']') {
                            break;
                        }
                        j += 1;
                    }
                    info.decode_count = count;
                    i = j;
                }
            }
            "/IM" | "/ImageMask" => {
                info.image_mask = value.eq_ignore_ascii_case("true");
            }
            "/SMask" => info.has_smask = true,
            _ => {}
        }
        i += 1;
    }
    info
}

#[cfg(test)]
mod tests {
    use sis_pdf_core::model::{Confidence, Impact, Severity};

    use super::{parse_inline_dict, parse_inline_images, resource_semantics_profile};

    #[test]
    fn inline_dict_detects_filter_decode_mismatch() {
        let info = parse_inline_dict(
            "/W 10 /H 10 /Filter [/FlateDecode /ASCII85Decode] /DP << /Columns 10 >>",
        );
        assert_eq!(info.filter_count, 2);
        assert_eq!(info.decode_parms_count, 1);
    }

    #[test]
    fn inline_image_parser_extracts_decode_count() {
        let content = b"q BI /W 1 /H 1 /D [0 1 0] ID abc EI Q";
        let parsed = parse_inline_images(content);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].decode_count, 3);
    }

    #[test]
    fn resource_semantics_profiles_match_expected_calibration() {
        let expected = [
            ("resource.declared_but_unused", Severity::Low, Confidence::Probable, Impact::Low),
            (
                "resource.hidden_invocation_pattern",
                Severity::Medium,
                Confidence::Probable,
                Impact::Medium,
            ),
            (
                "resource.operator_usage_anomalous",
                Severity::Medium,
                Confidence::Tentative,
                Impact::Medium,
            ),
            (
                "resource.inheritance_conflict_font",
                Severity::Medium,
                Confidence::Strong,
                Impact::Medium,
            ),
            (
                "resource.inheritance_conflict_xobject",
                Severity::Medium,
                Confidence::Strong,
                Impact::Medium,
            ),
            (
                "resource.inheritance_override_suspicious",
                Severity::Medium,
                Confidence::Probable,
                Impact::Medium,
            ),
            (
                "resource.override_outside_signature_scope",
                Severity::High,
                Confidence::Strong,
                Impact::High,
            ),
            (
                "image.override_outside_signature_scope",
                Severity::High,
                Confidence::Strong,
                Impact::High,
            ),
            (
                "font.override_outside_signature_scope",
                Severity::High,
                Confidence::Strong,
                Impact::High,
            ),
            (
                "image.inline_structure_filter_chain_inconsistent",
                Severity::Medium,
                Confidence::Strong,
                Impact::Medium,
            ),
            ("image.inline_decode_array_invalid", Severity::Low, Confidence::Strong, Impact::Low),
            (
                "image.inline_mask_inconsistent",
                Severity::Medium,
                Confidence::Probable,
                Impact::Medium,
            ),
        ];
        for (kind, severity, confidence, impact) in expected {
            let got = resource_semantics_profile(kind).expect("profile must exist");
            assert_eq!(got.0, severity, "severity drift for {kind}");
            assert_eq!(got.1, confidence, "confidence drift for {kind}");
            assert_eq!(got.2, impact, "impact drift for {kind}");
        }
    }
}
