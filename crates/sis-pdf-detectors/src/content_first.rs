use std::collections::{HashMap, HashSet};
use std::io::Read;

use anyhow::Result;
use flate2::read::ZlibDecoder;

use crate::dict_int;
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_core::stream_analysis::{analyse_stream, StreamLimits};
use sis_pdf_pdf::blob::Blob;
use sis_pdf_pdf::blob_classify::{classify_blob, validate_blob_kind, BlobKind};
use sis_pdf_pdf::classification::ClassificationMap;
use sis_pdf_pdf::decode::{looks_like_zlib, DecodeLimits, DecodeOutcome};
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfName, PdfObj, PdfStr, PdfStream};

pub struct ContentFirstDetector;

impl Detector for ContentFirstDetector {
    fn id(&self) -> &'static str {
        "content_first_stage1"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::StreamsAndFilters
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Expensive
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let limits = DecodeLimits {
            max_decoded_bytes: ctx.options.max_decode_bytes,
            ..DecodeLimits::default()
        };

        let obj_map: HashMap<(u32, u16), &PdfAtom<'_>> =
            ctx.graph.objects.iter().map(|entry| ((entry.obj, entry.gen), &entry.atom)).collect();
        let embedded_map = embedded_file_map(ctx, &obj_map);
        let xfa_map = xfa_stream_map(ctx, &obj_map);
        let classifications = ctx.classifications();

        for entry in &ctx.graph.objects {
            match &entry.atom {
                PdfAtom::Stream(stream) => {
                    let blob = match xfa_map.get(&(entry.obj, entry.gen)) {
                        Some(container) => Blob::from_xfa_package(
                            ctx.bytes,
                            *container,
                            (entry.obj, entry.gen),
                            stream,
                            limits,
                        ),
                        None => match embedded_map.get(&(entry.obj, entry.gen)) {
                            Some(embedded) => {
                                let origin = match embedded.origin {
                                    EmbeddedOriginKind::FileSpec => {
                                        sis_pdf_pdf::blob::BlobOrigin::EmbeddedFile {
                                            obj: embedded.file_spec.0,
                                            gen: embedded.file_spec.1,
                                        }
                                    }
                                    EmbeddedOriginKind::NameTree => {
                                        sis_pdf_pdf::blob::BlobOrigin::EmbeddedFileNameTree {
                                            obj: embedded.file_spec.0,
                                            gen: embedded.file_spec.1,
                                        }
                                    }
                                };
                                Blob::from_embedded_file(
                                    ctx.bytes,
                                    embedded.file_spec,
                                    (entry.obj, entry.gen),
                                    stream,
                                    limits,
                                    origin,
                                )
                            }
                            None => {
                                Blob::from_stream(ctx.bytes, entry.obj, entry.gen, stream, limits)
                            }
                        },
                    };
                    let blob = match blob {
                        Ok(blob) => blob,
                        Err(_) => continue,
                    };

                    let data = blob.decoded.as_deref().unwrap_or(blob.raw);
                    let kind = classify_blob(data);
                    let validation = validate_blob_kind(data, kind);
                    let declared_type = name_value(&stream.dict, b"/Type");
                    let declared_subtype = name_value(&stream.dict, b"/Subtype");
                    let origin_label = blob_origin_label(&blob);
                    let filter_expectations =
                        blob.decode_meta.as_ref().map(|meta| meta.filters.as_slice());
                    let carve_context = stream_carve_context(stream, &blob);

                    if let Some(finding) = label_mismatch_finding(
                        entry.obj,
                        entry.gen,
                        stream,
                        &declared_type,
                        &declared_subtype,
                        kind,
                        data,
                        origin_label,
                    ) {
                        findings.push(finding);
                    }

                    if let Some(finding) = validation_failure_finding(
                        entry.obj,
                        entry.gen,
                        stream,
                        kind,
                        &validation,
                        origin_label,
                    ) {
                        findings.push(finding);
                    }

                    if let Some(finding) = declared_filter_invalid_finding(
                        entry.obj,
                        entry.gen,
                        stream,
                        &blob,
                        origin_label,
                        &classifications,
                    ) {
                        findings.push(finding);
                    }
                    if let Some(finding) =
                        decode_recovered_finding(entry.obj, entry.gen, stream, &blob, origin_label)
                    {
                        findings.push(finding);
                    }

                    if let Some(finding) = undeclared_compression_finding(
                        ctx.bytes,
                        entry.obj,
                        entry.gen,
                        stream,
                        origin_label,
                    ) {
                        findings.push(finding);
                    }

                    findings.extend(carve_payloads(
                        entry.obj,
                        entry.gen,
                        stream.data_span,
                        data,
                        origin_label,
                        "Stream data",
                        filter_expectations,
                        Some(&carve_context),
                    ));

                    findings.extend(script_payload_findings(
                        entry.obj,
                        entry.gen,
                        stream.data_span,
                        data,
                        kind,
                        origin_label,
                        "Stream data",
                    ));

                    findings.extend(swf_findings(
                        entry.obj,
                        entry.gen,
                        stream.data_span,
                        data,
                        kind,
                        origin_label,
                        "Stream data",
                    ));

                    findings.extend(zip_container_findings(
                        entry.obj,
                        entry.gen,
                        stream.data_span,
                        data,
                        kind,
                        origin_label,
                        "Stream data",
                    ));
                }
                PdfAtom::Str(s) => {
                    let bytes = string_bytes(s);
                    let kind = classify_blob(&bytes);
                    let validation = validate_blob_kind(&bytes, kind);
                    if let Some(finding) = validation_failure_span_finding(
                        entry.obj,
                        entry.gen,
                        entry.body_span,
                        kind,
                        &validation,
                        "string",
                    ) {
                        findings.push(finding);
                    }

                    findings.extend(carve_payloads(
                        entry.obj,
                        entry.gen,
                        string_span(s),
                        &bytes,
                        "string",
                        "String data",
                        None,
                        None,
                    ));

                    findings.extend(script_payload_findings(
                        entry.obj,
                        entry.gen,
                        string_span(s),
                        &bytes,
                        kind,
                        "string",
                        "String data",
                    ));

                    findings.extend(swf_findings(
                        entry.obj,
                        entry.gen,
                        string_span(s),
                        &bytes,
                        kind,
                        "string",
                        "String data",
                    ));

                    findings.extend(zip_container_findings(
                        entry.obj,
                        entry.gen,
                        string_span(s),
                        &bytes,
                        kind,
                        "string",
                        "String data",
                    ));
                }
                _ => {
                    if let Some(bytes) = object_bytes(ctx.bytes, entry.body_span) {
                        let kind = classify_blob(bytes);
                        if kind != BlobKind::Unknown {
                            let validation = validate_blob_kind(bytes, kind);
                            if let Some(finding) = validation_failure_span_finding(
                                entry.obj,
                                entry.gen,
                                entry.body_span,
                                kind,
                                &validation,
                                "object",
                            ) {
                                findings.push(finding);
                            }
                        }

                        findings.extend(carve_payloads(
                            entry.obj,
                            entry.gen,
                            entry.body_span,
                            bytes,
                            "object",
                            "Object data",
                            None,
                            None,
                        ));

                        findings.extend(script_payload_findings(
                            entry.obj,
                            entry.gen,
                            entry.body_span,
                            bytes,
                            kind,
                            "object",
                            "Object data",
                        ));

                        findings.extend(swf_findings(
                            entry.obj,
                            entry.gen,
                            entry.body_span,
                            bytes,
                            kind,
                            "object",
                            "Object data",
                        ));

                        findings.extend(zip_container_findings(
                            entry.obj,
                            entry.gen,
                            entry.body_span,
                            bytes,
                            kind,
                            "object",
                            "Object data",
                        ));
                    }
                }
            }
        }

        Ok(findings)
    }
}

fn name_value(dict: &sis_pdf_pdf::object::PdfDict<'_>, key: &[u8]) -> Option<String> {
    let (_, obj) = dict.get_first(key)?;
    match &obj.atom {
        PdfAtom::Name(name) => Some(name_to_string(name)),
        _ => None,
    }
}

fn name_to_string(name: &PdfName<'_>) -> String {
    String::from_utf8_lossy(&name.decoded).to_string()
}

fn string_bytes(value: &PdfStr<'_>) -> Vec<u8> {
    match value {
        PdfStr::Literal { decoded, .. } => decoded.clone(),
        PdfStr::Hex { decoded, .. } => decoded.clone(),
    }
}

fn string_span(value: &PdfStr<'_>) -> sis_pdf_pdf::span::Span {
    match value {
        PdfStr::Literal { span, .. } => *span,
        PdfStr::Hex { span, .. } => *span,
    }
}

fn object_bytes(bytes: &[u8], span: sis_pdf_pdf::span::Span) -> Option<&[u8]> {
    let start = span.start as usize;
    let end = span.end as usize;
    if start >= end || end > bytes.len() {
        return None;
    }
    Some(&bytes[start..end])
}

#[derive(Clone, Copy)]
enum EmbeddedOriginKind {
    FileSpec,
    NameTree,
}

#[derive(Clone, Copy)]
struct EmbeddedOrigin {
    file_spec: (u32, u16),
    origin: EmbeddedOriginKind,
}

fn embedded_file_map<'a>(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj_map: &HashMap<(u32, u16), &'a PdfAtom<'a>>,
) -> HashMap<(u32, u16), EmbeddedOrigin> {
    let mut out = HashMap::new();
    for entry in &ctx.graph.objects {
        let PdfAtom::Dict(dict) = &entry.atom else {
            continue;
        };
        if let Some(refs) = extract_embedded_refs(dict) {
            for (obj, gen) in refs {
                out.insert(
                    (obj, gen),
                    EmbeddedOrigin {
                        file_spec: (entry.obj, entry.gen),
                        origin: EmbeddedOriginKind::FileSpec,
                    },
                );
            }
        }
    }

    for filespec in embedded_filespecs_from_names(ctx, obj_map) {
        let Some(atom) = obj_map.get(&filespec) else {
            continue;
        };
        let Some(dict) = dict_from_atom(atom) else {
            continue;
        };
        if let Some(refs) = extract_embedded_refs(dict) {
            for (obj, gen) in refs {
                match out.get(&(obj, gen)) {
                    Some(existing) if matches!(existing.origin, EmbeddedOriginKind::NameTree) => {
                        continue;
                    }
                    _ => {
                        out.insert(
                            (obj, gen),
                            EmbeddedOrigin {
                                file_spec: filespec,
                                origin: EmbeddedOriginKind::NameTree,
                            },
                        );
                    }
                }
            }
        }
    }

    out
}

fn extract_embedded_refs(dict: &PdfDict<'_>) -> Option<Vec<(u32, u16)>> {
    if !dict.has_name(b"/Type", b"/Filespec") && dict.get_first(b"/EF").is_none() {
        return None;
    }
    let (_, ef_obj) = dict.get_first(b"/EF")?;
    let PdfAtom::Dict(ef_dict) = &ef_obj.atom else {
        return None;
    };
    let mut refs = Vec::new();
    for key in [b"/F".as_slice(), b"/UF".as_slice()] {
        if let Some((_, v)) = ef_dict.get_first(key) {
            if let PdfAtom::Ref { obj, gen } = v.atom {
                refs.push((obj, gen));
            }
        }
    }
    if refs.is_empty() {
        None
    } else {
        Some(refs)
    }
}

fn dict_from_atom<'a>(atom: &'a PdfAtom<'a>) -> Option<&'a PdfDict<'a>> {
    match atom {
        PdfAtom::Dict(dict) => Some(dict),
        PdfAtom::Stream(stream) => Some(&stream.dict),
        _ => None,
    }
}

fn embedded_filespecs_from_names<'a>(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj_map: &HashMap<(u32, u16), &'a PdfAtom<'a>>,
) -> Vec<(u32, u16)> {
    let mut roots = Vec::new();
    for entry in &ctx.graph.objects {
        let Some(dict) = dict_from_atom(&entry.atom) else {
            continue;
        };
        let Some((_, names_obj)) = dict.get_first(b"/Names") else {
            continue;
        };
        let Some(names_dict) = dict_from_obj(obj_map, names_obj) else {
            continue;
        };
        let Some((_, embedded_obj)) = names_dict.get_first(b"/EmbeddedFiles") else {
            continue;
        };
        roots.push(embedded_obj);
    }

    let mut out = Vec::new();
    let mut visited = HashSet::new();
    for root in roots {
        collect_name_tree_filespecs(obj_map, root, 0, &mut visited, &mut out);
    }
    out
}

fn collect_name_tree_filespecs<'a>(
    obj_map: &HashMap<(u32, u16), &'a PdfAtom<'a>>,
    node: &'a PdfObj<'a>,
    depth: usize,
    visited: &mut HashSet<(u32, u16)>,
    out: &mut Vec<(u32, u16)>,
) {
    if depth > 6 {
        return;
    }
    if let PdfAtom::Ref { obj, gen } = node.atom {
        if !visited.insert((obj, gen)) {
            return;
        }
    }
    let Some(dict) = dict_from_obj(obj_map, node) else {
        return;
    };

    if let Some((_, names_obj)) = dict.get_first(b"/Names") {
        if let PdfAtom::Array(items) = &names_obj.atom {
            for pair in items.chunks(2) {
                let Some(value) = pair.get(1) else {
                    continue;
                };
                if let PdfAtom::Ref { obj, gen } = value.atom {
                    out.push((obj, gen));
                }
            }
        }
    }

    if let Some((_, kids_obj)) = dict.get_first(b"/Kids") {
        if let PdfAtom::Array(items) = &kids_obj.atom {
            for kid in items {
                collect_name_tree_filespecs(obj_map, kid, depth + 1, visited, out);
            }
        }
    }
}

fn dict_from_obj<'a>(
    obj_map: &HashMap<(u32, u16), &'a PdfAtom<'a>>,
    obj: &'a PdfObj<'a>,
) -> Option<&'a PdfDict<'a>> {
    match &obj.atom {
        PdfAtom::Ref { obj, gen } => {
            obj_map.get(&(*obj, *gen)).and_then(|atom| dict_from_atom(atom))
        }
        _ => dict_from_atom(&obj.atom),
    }
}

fn xfa_stream_map<'a>(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj_map: &HashMap<(u32, u16), &'a PdfAtom<'a>>,
) -> HashMap<(u32, u16), (u32, u16)> {
    let mut out = HashMap::new();
    for entry in &ctx.graph.objects {
        let Some(dict) = dict_from_atom(&entry.atom) else {
            continue;
        };
        let Some((_, xfa_obj)) = dict.get_first(b"/XFA") else {
            continue;
        };
        collect_xfa_refs(obj_map, xfa_obj, (entry.obj, entry.gen), &mut out, 0);
    }
    out
}

fn collect_xfa_refs<'a>(
    obj_map: &HashMap<(u32, u16), &'a PdfAtom<'a>>,
    obj: &'a PdfObj<'a>,
    container: (u32, u16),
    out: &mut HashMap<(u32, u16), (u32, u16)>,
    depth: usize,
) {
    if depth > 4 {
        return;
    }
    match &obj.atom {
        PdfAtom::Ref { obj: ref_obj, gen: ref_gen } => {
            out.insert((*ref_obj, *ref_gen), container);
            if let Some(atom) = obj_map.get(&(*ref_obj, *ref_gen)) {
                let child = PdfObj { span: obj.span, atom: (*atom).clone() };
                collect_xfa_refs(obj_map, &child, container, out, depth + 1);
            }
        }
        PdfAtom::Array(items) => {
            for item in items {
                if let PdfAtom::Ref { obj, gen } = item.atom {
                    out.insert((obj, gen), container);
                }
                collect_xfa_refs(obj_map, item, container, out, depth + 1);
            }
        }
        _ => {}
    }
}

fn blob_origin_label(blob: &Blob<'_>) -> &'static str {
    match blob.origin {
        sis_pdf_pdf::blob::BlobOrigin::EmbeddedFile { .. } => "embedded_file",
        sis_pdf_pdf::blob::BlobOrigin::EmbeddedFileNameTree { .. } => "embedded_file_name_tree",
        sis_pdf_pdf::blob::BlobOrigin::XfaPackage { .. } => "xfa_package",
        sis_pdf_pdf::blob::BlobOrigin::Stream { .. } => "stream",
        sis_pdf_pdf::blob::BlobOrigin::String { .. } => "string",
        sis_pdf_pdf::blob::BlobOrigin::XrefSpan { .. } => "xref_span",
        sis_pdf_pdf::blob::BlobOrigin::Recovered { .. } => "recovered",
    }
}

/// Check if a stream has valid image XObject dictionary keys
fn has_image_dict_keys(stream: &PdfStream<'_>) -> bool {
    let dict = &stream.dict;

    // Check for essential image XObject keys
    let has_width = dict.entries.iter().any(|(k, _)| {
        k.decoded.as_slice() == b"/Width"
            || k.decoded.as_slice() == b"Width"
            || k.decoded.as_slice() == b"/W"
            || k.decoded.as_slice() == b"W"
    });
    let has_height = dict.entries.iter().any(|(k, _)| {
        k.decoded.as_slice() == b"/Height"
            || k.decoded.as_slice() == b"Height"
            || k.decoded.as_slice() == b"/H"
            || k.decoded.as_slice() == b"H"
    });
    let has_colorspace = dict.entries.iter().any(|(k, _)| {
        k.decoded.as_slice() == b"/ColorSpace"
            || k.decoded.as_slice() == b"ColorSpace"
            || k.decoded.as_slice() == b"/CS"
            || k.decoded.as_slice() == b"CS"
    });
    let has_bpc = dict.entries.iter().any(|(k, _)| {
        k.decoded.as_slice() == b"/BitsPerComponent"
            || k.decoded.as_slice() == b"BitsPerComponent"
            || k.decoded.as_slice() == b"/BPC"
            || k.decoded.as_slice() == b"BPC"
    });

    // An image should have at least width, height, and either colorspace or BPC
    (has_width && has_height) && (has_colorspace || has_bpc)
}

fn label_mismatch_finding(
    obj: u32,
    gen: u16,
    stream: &PdfStream<'_>,
    declared_type: &Option<String>,
    declared_subtype: &Option<String>,
    kind: BlobKind,
    observed_data: &[u8],
    origin: &str,
) -> Option<Finding> {
    let declared_subtype = declared_subtype.as_ref()?;
    let declared_lower = declared_subtype.to_ascii_lowercase();
    let is_image_label = declared_lower == "/image";
    let is_xml_label = declared_lower == "/xml" || declared_lower == "/xfa";

    let mismatch = (is_image_label && !kind.is_image())
        || (is_xml_label && !matches!(kind, BlobKind::Xml | BlobKind::Html));

    if !mismatch {
        return None;
    }

    // Check if this is an image with valid dictionary but unknown signature
    // (common in PDF-native image formats like DeviceRGB raw data)
    let has_valid_image_dict = is_image_label && has_image_dict_keys(stream);
    let is_unknown_blob = matches!(kind, BlobKind::Unknown);

    let severity =
        if kind.is_container_or_executable() || matches!(kind, BlobKind::Pdf | BlobKind::Swf) {
            // Executable or container masquerading as image - High severity
            Severity::High
        } else if is_unknown_blob && has_valid_image_dict {
            // Image with valid dict keys but unknown signature - likely PDF-native format
            // Reduce to Info severity to avoid false positives on benign PDFs
            Severity::Info
        } else {
            // Other mismatches - Medium severity
            Severity::Medium
        };

    let mut meta = HashMap::new();
    if let Some(declared) = declared_type.as_ref() {
        meta.insert("declared.type".to_string(), declared.clone());
    }
    meta.insert("declared.subtype".to_string(), declared_subtype.clone());
    meta.insert("blob.kind".to_string(), kind.as_str().to_string());
    meta.insert("observed.signature_hint".to_string(), observed_signature_hint(observed_data));
    meta.insert("blob.origin".to_string(), origin.to_string());
    meta.insert(
        "declared.expected_family".to_string(),
        expected_family_for_subtype(&declared_lower).to_string(),
    );

    let description = format!(
        "Declared subtype {} expects {}, but observed content classifies as {} (signature hint: {}).",
        declared_subtype,
        expected_family_for_subtype(&declared_lower),
        kind.as_str(),
        meta.get("observed.signature_hint").cloned().unwrap_or_else(|| "unknown".to_string())
    );

    Some(Finding {
        id: String::new(),
        surface: AttackSurface::StreamsAndFilters,
        kind: "label_mismatch_stream_type".to_string(),
        severity,
        confidence: Confidence::Strong,
        impact: None,
        title: "Stream label mismatch".to_string(),
        description,
        objects: vec![format!("{} {} obj", obj, gen)],
        evidence: vec![span_to_evidence(stream.data_span, "Stream data")],
        remediation: Some("Verify stream subtype and inspect embedded content.".to_string()),
        meta,
        reader_impacts: Vec::new(),
        action_type: None,
        action_target: None,
        action_initiation: None,
        yara: None,
        position: None,
        positions: Vec::new(),
    })
}

fn expected_family_for_subtype(subtype_lower: &str) -> &'static str {
    match subtype_lower {
        "/image" => "image-like stream bytes",
        "/xml" | "/xfa" => "xml/html text payload",
        _ => "declared subtype-compatible bytes",
    }
}

fn validation_failure_finding(
    obj: u32,
    gen: u16,
    stream: &PdfStream<'_>,
    kind: BlobKind,
    validation: &sis_pdf_pdf::blob_classify::ValidationResult,
    origin: &str,
) -> Option<Finding> {
    if validation.valid {
        return None;
    }

    let mut meta = HashMap::new();
    meta.insert("blob.kind".to_string(), kind.as_str().to_string());
    meta.insert("blob.origin".to_string(), origin.to_string());
    if let Some(reason) = validation.reason.as_ref() {
        meta.insert("validation.reason".to_string(), reason.clone());
    }
    meta.insert("blob.kind".to_string(), kind.as_str().to_string());

    Some(Finding {
        id: String::new(),
        surface: AttackSurface::StreamsAndFilters,
        kind: "content_validation_failed".to_string(),
        severity: Severity::Medium,
        confidence: Confidence::Probable,
        impact: None,
        title: "Content validation failed".to_string(),
        description: "Stream signature matched, but lightweight validation failed.".to_string(),
        objects: vec![format!("{} {} obj", obj, gen)],
        evidence: vec![span_to_evidence(stream.data_span, "Stream data")],
        remediation: Some("Review stream structure and decode behaviour.".to_string()),
        meta,
        reader_impacts: Vec::new(),
        action_type: None,
        action_target: None,
        action_initiation: None,
        yara: None,
        position: None,
        positions: Vec::new(),
    })
}

fn validation_failure_span_finding(
    obj: u32,
    gen: u16,
    span: sis_pdf_pdf::span::Span,
    kind: BlobKind,
    validation: &sis_pdf_pdf::blob_classify::ValidationResult,
    origin: &str,
) -> Option<Finding> {
    if validation.valid {
        return None;
    }

    let mut meta = HashMap::new();
    meta.insert("blob.kind".to_string(), kind.as_str().to_string());
    meta.insert("blob.origin".to_string(), origin.to_string());
    if let Some(reason) = validation.reason.as_ref() {
        meta.insert("validation.reason".to_string(), reason.clone());
    }

    Some(Finding {
        id: String::new(),
        surface: AttackSurface::StreamsAndFilters,
        kind: "content_validation_failed".to_string(),
        severity: Severity::Medium,
        confidence: Confidence::Probable,
        impact: None,
        title: "Content validation failed".to_string(),
        description: "Content signature matched, but lightweight validation failed.".to_string(),
        objects: vec![format!("{} {} obj", obj, gen)],
        evidence: vec![span_to_evidence(span, "Object data")],
        remediation: Some("Review object bytes for malformed or hidden content.".to_string()),
        meta,
        reader_impacts: Vec::new(),
        action_type: None,
        action_target: None,
        action_initiation: None,
        yara: None,
        position: None,
        positions: Vec::new(),
    })
}

fn declared_filter_invalid_finding(
    obj: u32,
    gen: u16,
    stream: &PdfStream<'_>,
    blob: &Blob<'_>,
    origin: &str,
    classifications: &ClassificationMap,
) -> Option<Finding> {
    if stream_is_structural(stream) {
        return None;
    }

    let meta = blob.decode_meta.as_ref()?;
    if meta.filters.is_empty() {
        return None;
    }

    let (title, mut description, confidence) = match &meta.outcome {
        DecodeOutcome::Failed { reason, .. } => (
            "Declared filters failed to decode",
            format!("Stream decode failed: {reason}"),
            Confidence::Probable,
        ),
        DecodeOutcome::SuspectMismatch => (
            "Declared filters mismatched stream data",
            "Stream content does not match declared filters.".to_string(),
            Confidence::Strong,
        ),
        _ => return None,
    };

    let mut finding_meta = HashMap::new();
    finding_meta.insert("stream.filters".to_string(), meta.filters.join(","));
    finding_meta.insert("decode.outcome".to_string(), outcome_label(&meta.outcome));
    finding_meta.insert("blob.origin".to_string(), origin.to_string());
    let observed_data = blob.decoded.as_deref().unwrap_or(blob.raw);
    let observed_kind = classify_blob(observed_data);
    finding_meta.insert("decode.observed_type".to_string(), observed_kind.as_str().to_string());
    finding_meta
        .insert("decode.observed_signature".to_string(), observed_signature_hint(observed_data));

    let mut expected_types = Vec::new();
    let mut expected_signatures = Vec::new();
    for filter in &meta.filters {
        if let Some((expected_type, expected_signature)) = expected_profile_for_filter(filter) {
            let expected_type = expected_type.to_string();
            let expected_signature = expected_signature.to_string();
            if !expected_types.contains(&expected_type) {
                expected_types.push(expected_type);
            }
            if !expected_signatures.contains(&expected_signature) {
                expected_signatures.push(expected_signature);
            }
        }
    }
    if !expected_types.is_empty() {
        finding_meta.insert("decode.expected_types".to_string(), expected_types.join(","));
    }
    if !expected_signatures.is_empty() {
        finding_meta
            .insert("decode.expected_signatures".to_string(), expected_signatures.join(","));
    }

    if let Some(classified) = classifications.get(&(obj, gen)) {
        finding_meta
            .insert("stream.obj_type".to_string(), classified.obj_type.as_str().to_string());
        if !classified.roles.is_empty() {
            let roles =
                classified.roles.iter().map(|role| role.as_str()).collect::<Vec<_>>().join(",");
            finding_meta.insert("stream.roles".to_string(), roles);
        }
    }
    if !meta.mismatches.is_empty() {
        let reasons = meta
            .mismatches
            .iter()
            .map(|m| format!("{}:{}", m.filter, m.reason))
            .collect::<Vec<_>>();
        finding_meta.insert("decode.mismatch".to_string(), reasons.join(";"));
    }
    if !expected_types.is_empty()
        && matches!(meta.outcome, DecodeOutcome::SuspectMismatch | DecodeOutcome::Failed { .. })
    {
        let mismatch_summary = format!(
            "Declared filters expected {} (signature hints: {}), but observed {} (signature hint: {}).",
            expected_types.join(","),
            expected_signatures.join(","),
            observed_kind.as_str(),
            finding_meta
                .get("decode.observed_signature")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string())
        );
        if matches!(meta.outcome, DecodeOutcome::SuspectMismatch) {
            description = mismatch_summary;
        } else {
            description = format!("{description} {mismatch_summary}");
        }
    }

    Some(Finding {
        id: String::new(),
        surface: AttackSurface::StreamsAndFilters,
        kind: "declared_filter_invalid".to_string(),
        severity: Severity::High,
        confidence,
        impact: None,
        title: title.to_string(),
        description,
        objects: vec![format!("{} {} obj", obj, gen)],
        evidence: vec![span_to_evidence(stream.data_span, "Stream data")],
        remediation: Some("Inspect stream data and reconcile declared filters.".to_string()),
        meta: finding_meta,

        reader_impacts: Vec::new(),
        action_type: None,
        action_target: None,
        action_initiation: None,
        yara: None,
        position: None,
        positions: Vec::new(),
    })
}

fn expected_profile_for_filter(filter: &str) -> Option<(&'static str, &'static str)> {
    match filter.to_ascii_lowercase().as_str() {
        "/flatedecode" | "/fl" => Some(("zlib/deflate payload", "zlib header (typically 0x78..)")),
        "/dctdecode" | "/dct" => Some(("jpeg payload", "jpeg soi (ff d8 ff)")),
        "/jpxdecode" | "/jpx" => Some(("jpeg2000 payload", "jp2 signature box")),
        "/jbig2decode" | "/jbig2" => Some(("jbig2 payload", "jbig2 file header")),
        "/ccittfaxdecode" | "/ccittfax" => Some(("ccitt fax payload", "tiff/ccitt style header")),
        _ => None,
    }
}

fn observed_signature_hint(data: &[u8]) -> String {
    if data.is_empty() {
        return "empty".to_string();
    }
    let lower = data.iter().take(64).map(|b| b.to_ascii_lowercase()).collect::<Vec<_>>();
    if lower.starts_with(b"<?xml") {
        return "xml prefix (<?xml)".to_string();
    }
    if lower.starts_with(b"<?xpacket") {
        return "xml/xmp packet prefix (<?xpacket)".to_string();
    }
    if lower.starts_with(b"<x:xmpmeta") {
        return "xmp meta prefix (<x:xmpmeta)".to_string();
    }
    if data.starts_with(b"%PDF-") {
        return "%PDF-".to_string();
    }
    if data.starts_with(b"\xFF\xD8\xFF") {
        return "jpeg soi (ff d8 ff)".to_string();
    }
    if data.starts_with(b"\x89PNG\r\n\x1A\n") {
        return "png signature".to_string();
    }
    if data.starts_with(b"PK\x03\x04") {
        return "zip local header (pk\\x03\\x04)".to_string();
    }
    if looks_like_zlib(data) {
        return "zlib-like header".to_string();
    }
    let mut preview = String::new();
    let max = data.len().min(8);
    for byte in &data[..max] {
        use std::fmt::Write;
        let _ = write!(&mut preview, "{:02x}", byte);
    }
    format!("hex:{preview}")
}

fn stream_is_structural(stream: &PdfStream<'_>) -> bool {
    if let Some(type_name) = name_value(&stream.dict, b"/Type") {
        let lower = strip_leading_slash(&type_name).to_ascii_lowercase();
        if matches!(lower.as_str(), "objstm" | "xref" | "metadata") {
            return true;
        }
    }
    stream.dict.get_first(b"/Linearized").is_some()
}

fn strip_leading_slash(name: &str) -> &str {
    name.strip_prefix('/').unwrap_or(name)
}

#[cfg(test)]
mod declared_filter_invalid_tests {
    use super::*;
    use sis_pdf_pdf::blob::{Blob, BlobOrigin};
    use sis_pdf_pdf::classification::{ClassificationMap, ClassifiedObject, PdfObjectType};
    use sis_pdf_pdf::decode::{DecodeMeta, DecodeMismatch, DecodeOutcome};
    use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfName, PdfObj, PdfStream};
    use sis_pdf_pdf::span::Span;
    use std::borrow::Cow;

    fn pdf_name(token: &'static [u8]) -> PdfName<'static> {
        PdfName {
            span: Span { start: 0, end: 0 },
            raw: Cow::Owned(token.to_vec()),
            decoded: token.to_vec(),
        }
    }

    fn make_stream_with_entry(entry: (PdfName<'static>, PdfObj<'static>)) -> PdfStream<'static> {
        PdfStream {
            dict: PdfDict { span: Span { start: 0, end: 0 }, entries: vec![entry] },
            data_span: Span { start: 0, end: 0 },
        }
    }

    fn make_entry(
        key: &'static [u8],
        value: PdfAtom<'static>,
    ) -> (PdfName<'static>, PdfObj<'static>) {
        (pdf_name(key), PdfObj { span: Span { start: 0, end: 0 }, atom: value })
    }

    fn make_blob() -> Blob<'static> {
        Blob {
            origin: BlobOrigin::Stream { obj: 1, gen: 0 },
            pdf_path: vec![],
            raw: &[],
            decoded: None,
            decode_meta: Some(DecodeMeta {
                filters: vec!["/FlateDecode".into()],
                mismatches: vec![DecodeMismatch {
                    filter: "/FlateDecode".into(),
                    reason: "stream is not zlib-like".into(),
                }],
                outcome: DecodeOutcome::SuspectMismatch,
                input_len: 0,
                output_len: 0,
                recovered_filters: vec![],
            }),
        }
    }

    fn classification_map() -> ClassificationMap {
        let mut map = ClassificationMap::new();
        map.insert((1, 0), ClassifiedObject::new(1, 0, PdfObjectType::Stream));
        map
    }

    #[test]
    fn declared_filter_invalid_skips_objstm_streams() {
        let stream =
            make_stream_with_entry(make_entry(b"/Type", PdfAtom::Name(pdf_name(b"/ObjStm"))));
        assert!(declared_filter_invalid_finding(
            1,
            0,
            &stream,
            &make_blob(),
            "stream",
            &classification_map()
        )
        .is_none());
    }

    #[test]
    fn declared_filter_invalid_skips_xref_streams() {
        let stream =
            make_stream_with_entry(make_entry(b"/Type", PdfAtom::Name(pdf_name(b"/XRef"))));
        assert!(declared_filter_invalid_finding(
            1,
            0,
            &stream,
            &make_blob(),
            "stream",
            &classification_map()
        )
        .is_none());
    }

    #[test]
    fn declared_filter_invalid_skips_linearized_streams() {
        let stream = make_stream_with_entry(make_entry(b"/Linearized", PdfAtom::Int(1)));
        assert!(declared_filter_invalid_finding(
            1,
            0,
            &stream,
            &make_blob(),
            "stream",
            &classification_map()
        )
        .is_none());
    }

    #[test]
    fn declared_filter_invalid_reports_non_structural_streams() {
        let stream =
            make_stream_with_entry(make_entry(b"/Type", PdfAtom::Name(pdf_name(b"/XObject"))));
        let finding = declared_filter_invalid_finding(
            1,
            0,
            &stream,
            &make_blob(),
            "stream",
            &classification_map(),
        )
        .expect("finding");
        assert!(finding.description.contains("Declared filters expected"));
        assert_eq!(
            finding.meta.get("decode.expected_types").map(|v| v.as_str()),
            Some("zlib/deflate payload")
        );
        assert!(finding.meta.contains_key("decode.observed_type"));
        assert!(finding.meta.contains_key("decode.observed_signature"));
    }

    #[test]
    fn declared_filter_invalid_skips_metadata_streams() {
        let stream =
            make_stream_with_entry(make_entry(b"/Type", PdfAtom::Name(pdf_name(b"/Metadata"))));
        assert!(declared_filter_invalid_finding(
            1,
            0,
            &stream,
            &make_blob(),
            "stream",
            &classification_map()
        )
        .is_none());
    }
}

fn decode_recovered_finding(
    obj: u32,
    gen: u16,
    stream: &PdfStream<'_>,
    blob: &Blob<'_>,
    origin: &str,
) -> Option<Finding> {
    let meta = blob.decode_meta.as_ref()?;
    if meta.recovered_filters.is_empty() {
        return None;
    }

    let mut finding_meta = HashMap::new();
    finding_meta.insert("stream.filters".to_string(), meta.filters.join(","));
    finding_meta.insert("decode.recovered_filters".to_string(), meta.recovered_filters.join(","));
    finding_meta.insert("blob.origin".to_string(), origin.to_string());

    Some(Finding {
        id: String::new(),
        surface: AttackSurface::StreamsAndFilters,
        kind: "decode_recovery_used".to_string(),
        severity: Severity::Info,
        confidence: Confidence::Strong,
        impact: None,
        title: "Decode recovery used".to_string(),
        description: "Recovered stream payload using fallback decoding.".to_string(),
        objects: vec![format!("{} {} obj", obj, gen)],
        evidence: vec![span_to_evidence(stream.data_span, "Stream data")],
        remediation: Some(
            "Treat stream data as suspect and verify filter declarations.".to_string(),
        ),
        meta: finding_meta,

        reader_impacts: Vec::new(),
        action_type: None,
        action_target: None,
        action_initiation: None,
        yara: None,
        position: None,
        positions: Vec::new(),
    })
}

fn undeclared_compression_finding(
    bytes: &[u8],
    obj: u32,
    gen: u16,
    stream: &PdfStream<'_>,
    origin: &str,
) -> Option<Finding> {
    let filters = sis_pdf_pdf::decode::stream_filters(&stream.dict);
    if !filters.is_empty() {
        return None;
    }

    let start = stream.data_span.start as usize;
    let end = stream.data_span.end as usize;
    if start >= end || end > bytes.len() {
        return None;
    }

    let raw = &bytes[start..end];
    if !looks_like_zlib(raw) {
        return None;
    }

    let analysis = analyse_stream(raw, &StreamLimits::default());
    let mut meta = HashMap::new();
    meta.insert("expected.filter_declared".to_string(), "none".to_string());
    meta.insert(
        "expected.compression".to_string(),
        "uncompressed/plain stream bytes when /Filter is absent".to_string(),
    );
    meta.insert("observed.compression_guess".to_string(), "zlib".to_string());
    meta.insert("observed.signature_hint".to_string(), observed_signature_hint(raw));
    meta.insert("observed.stream_entropy".to_string(), format!("{:.2}", analysis.entropy));
    meta.insert(
        "observed.first_bytes".to_string(),
        observed_signature_hint(&raw[..raw.len().min(8)]),
    );
    meta.insert("blob.origin".to_string(), origin.to_string());
    meta.insert("query.next".to_string(), format!("stream {obj} {gen} --raw (or --decode)"));
    meta.insert("threshold.filter_count".to_string(), "0".to_string());
    meta.insert("threshold.zlib_like".to_string(), "true".to_string());

    Some(Finding {
        id: String::new(),
        surface: AttackSurface::StreamsAndFilters,
        kind: "undeclared_compression_present".to_string(),
        severity: Severity::High,
        confidence: Confidence::Probable,
        impact: None,
        title: "Undeclared compression detected".to_string(),
        description: format!(
            "No /Filter is declared (expected plain bytes), but stream bytes look zlib-compressed (signature hint: {}, entropy {:.2}).",
            meta.get("observed.signature_hint").cloned().unwrap_or_else(|| "unknown".to_string()),
            analysis.entropy
        ),
        objects: vec![format!("{} {} obj", obj, gen)],
        evidence: vec![span_to_evidence(stream.data_span, "Stream data")],
        remediation: Some(
            "Inspect stream bytes, add/repair /Filter declarations, and compare decoded content against viewer behaviour."
                .to_string(),
        ),
        meta,
        reader_impacts: Vec::new(),
        action_type: None,
        action_target: None,
        action_initiation: None,
        yara: None,
        position: None,
        positions: Vec::new(),
    })
}

fn outcome_label(outcome: &DecodeOutcome) -> String {
    match outcome {
        DecodeOutcome::Ok => "ok",
        DecodeOutcome::Truncated => "truncated",
        DecodeOutcome::Failed { .. } => "failed",
        DecodeOutcome::Deferred { .. } => "deferred",
        DecodeOutcome::SuspectMismatch => "suspect_mismatch",
    }
    .to_string()
}

struct CarveCorrelationContext {
    decode_outcome: Option<DecodeOutcome>,
    declared_length: Option<u32>,
    has_length_entry: bool,
    observed_length: usize,
    image_meta: Option<ImageDictMeta>,
}

struct ImageDictMeta {
    width: Option<u32>,
    height: Option<u32>,
    bits_per_component: Option<u32>,
    colour_space: Option<String>,
}

struct ImageHeaderMeta {
    width: u32,
    height: u32,
    bits_per_component: Option<u32>,
    channels: Option<u8>,
}

struct CarveScoring {
    severity: Severity,
    confidence: Confidence,
    summary: Option<String>,
}

fn stream_carve_context(stream: &PdfStream<'_>, blob: &Blob<'_>) -> CarveCorrelationContext {
    let declared_length = dict_int(&stream.dict, b"/Length");
    let has_length_entry = stream.dict.get_first(b"/Length").is_some();
    let image_meta = image_dict_meta(&stream.dict);
    CarveCorrelationContext {
        decode_outcome: blob.decode_meta.as_ref().map(|meta| meta.outcome.clone()),
        declared_length,
        has_length_entry,
        observed_length: blob.raw.len(),
        image_meta,
    }
}

fn image_dict_meta(dict: &PdfDict<'_>) -> Option<ImageDictMeta> {
    let width = dict_int(dict, b"/Width");
    let height = dict_int(dict, b"/Height");
    let bits_per_component = dict_int(dict, b"/BitsPerComponent");
    let colour_space = dict_name_or_first_array_name(dict, b"/ColorSpace");
    if width.is_none() && height.is_none() && bits_per_component.is_none() && colour_space.is_none()
    {
        return None;
    }
    Some(ImageDictMeta { width, height, bits_per_component, colour_space })
}

fn dict_name_or_first_array_name(dict: &PdfDict<'_>, key: &[u8]) -> Option<String> {
    let (_, obj) = dict.get_first(key)?;
    match &obj.atom {
        PdfAtom::Name(name) => Some(name_to_string(name)),
        PdfAtom::Array(items) => items.iter().find_map(|item| match &item.atom {
            PdfAtom::Name(name) => Some(name_to_string(name)),
            _ => None,
        }),
        _ => None,
    }
}

fn carve_payloads(
    obj: u32,
    gen: u16,
    span: sis_pdf_pdf::span::Span,
    data: &[u8],
    origin: &str,
    label: &str,
    filters: Option<&[String]>,
    context: Option<&CarveCorrelationContext>,
) -> Vec<Finding> {
    let max_scan_bytes = 512 * 1024;
    let max_hits = 3;
    let slice = if data.len() > max_scan_bytes { &data[..max_scan_bytes] } else { data };

    // Only flag signatures at stream start (0-100 bytes) to avoid false positives
    // from random bytes in compressed data (like SWF magic in image streams)
    let boundary_threshold = 100;

    let signatures = [
        ("pdf", b"%PDF-".as_slice()),
        ("zip", b"PK\x03\x04".as_slice()),
        ("mz", b"MZ".as_slice()),
        ("elf", b"\x7fELF".as_slice()),
        ("swf", b"FWS".as_slice()),
        ("swf", b"CWS".as_slice()),
        ("swf", b"ZWS".as_slice()),
        ("jpeg", b"\xFF\xD8\xFF".as_slice()),
        ("gif", b"GIF87a".as_slice()),
        ("gif", b"GIF89a".as_slice()),
        ("png", b"\x89PNG\r\n\x1a\n".as_slice()),
        ("gzip", b"\x1F\x8B\x08".as_slice()),
        ("ole", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1".as_slice()),
        ("rar", b"Rar!\x1A\x07\x00".as_slice()),
        ("rar", b"Rar!\x1A\x07\x01\x00".as_slice()),
        ("7z", b"7z\xBC\xAF\x27\x1C".as_slice()),
        ("cab", b"MSCF".as_slice()),
        ("tar", b"ustar".as_slice()),
        ("xml", b"<?xml".as_slice()),
        ("html", b"<!DOCTYPE html".as_slice()),
        ("html", b"<html".as_slice()),
    ];

    let mut findings = Vec::new();
    for (kind, needle) in signatures {
        if let Some(offset) = find_pattern(slice, needle) {
            // Only flag signatures at the very beginning of the stream
            // Skip signatures found deep in compressed data (likely random bytes)
            if offset > boundary_threshold {
                continue;
            }
            let mut meta = HashMap::new();
            meta.insert("carve.kind".to_string(), kind.to_string());
            meta.insert("carve.offset".to_string(), offset.to_string());
            let expectation = filters.and_then(|filters| {
                filters.iter().find_map(|filter| {
                    expected_kind_for_filter(filter.as_str())
                        .map(|expected| (expected, filter.as_str()))
                })
            });
            let mut description =
                "Detected an embedded payload signature inside another object.".to_string();
            if let Some((expected_kind, filter_name)) = expectation {
                let match_kind = expected_kind.eq_ignore_ascii_case(kind);
                meta.insert("carve.filter".to_string(), filter_name.to_string());
                meta.insert("carve.expected_kind".to_string(), expected_kind.to_string());
                meta.insert("carve.match".to_string(), match_kind.to_string());
                let actual_label = format_signature_kind(kind);
                if match_kind {
                    description = format!(
                        "Embedded {} signature matches declared filter {}.",
                        actual_label, filter_name
                    );
                } else {
                    description = format!(
                        "Found a {} signature in a stream where we expected {}.",
                        actual_label, expected_kind
                    );
                }
            }

            let scoring = correlate_carved_payload(kind, offset, &mut meta, filters, context, data);
            let severity = scoring.severity;
            let confidence = scoring.confidence;
            if let Some(summary) = scoring.summary {
                description = format!("{description} {summary}");
            }

            meta.insert("blob.origin".to_string(), origin.to_string());
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::StreamsAndFilters,
                kind: "embedded_payload_carved".to_string(),
                severity,
                confidence,
                impact: None,
                title: "Embedded payload carved".to_string(),
                description,
                objects: vec![format!("{} {} obj", obj, gen)],
                evidence: vec![span_to_evidence(span, label)],
                remediation: Some(
                    "Inspect the object for embedded payloads or polyglot content.".to_string(),
                ),
                meta,
                reader_impacts: Vec::new(),
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
            });
            if findings.len() >= max_hits {
                break;
            }
        }
    }
    findings
}

fn correlate_carved_payload(
    kind: &str,
    offset: usize,
    meta: &mut HashMap<String, String>,
    filters: Option<&[String]>,
    context: Option<&CarveCorrelationContext>,
    data: &[u8],
) -> CarveScoring {
    let mut score = 0i32;
    let mut strong_signals = 0usize;
    let mut missing_signals = 0usize;
    let mut summary = Vec::new();

    if let Some(filters) = filters {
        if let Some((expected_kind, filter_name)) = filters.iter().find_map(|filter| {
            expected_kind_for_filter(filter.as_str()).map(|expected| (expected, filter.as_str()))
        }) {
            let matches = expected_kind.eq_ignore_ascii_case(kind);
            if matches {
                score -= 2;
                strong_signals += 1;
                summary.push(format!("filter {} matches {}", filter_name, expected_kind));
            } else {
                score += 3;
                strong_signals += 1;
                summary.push(format!("filter {} expects {}", filter_name, expected_kind));
            }
        }
    }

    if let Some(context) = context {
        if let Some(outcome) = context.decode_outcome.as_ref() {
            let outcome_str = outcome_label(outcome);
            meta.insert("carve.decode.outcome".to_string(), outcome_str.clone());
            match outcome {
                DecodeOutcome::Ok | DecodeOutcome::Truncated => {
                    score -= 1;
                    strong_signals += 1;
                    summary.push(format!("decode outcome {outcome_str}"));
                }
                DecodeOutcome::Failed { .. }
                | DecodeOutcome::Deferred { .. }
                | DecodeOutcome::SuspectMismatch => {
                    score += 2;
                    strong_signals += 1;
                    summary.push(format!("decode outcome {outcome_str}"));
                }
            }
        }

        if !context.has_length_entry {
            meta.insert("carve.length.status".to_string(), "missing".to_string());
            score += 1;
            missing_signals += 1;
            summary.push("missing /Length".to_string());
        } else if let Some(declared_length) = context.declared_length {
            meta.insert("carve.length.declared".to_string(), declared_length.to_string());
            meta.insert(
                "carve.length.observed_raw".to_string(),
                context.observed_length.to_string(),
            );
            let length_match = declared_length as usize == context.observed_length;
            meta.insert("carve.length.match".to_string(), length_match.to_string());
            if length_match {
                score -= 1;
                strong_signals += 1;
                summary.push("declared /Length matches raw stream".to_string());
            } else {
                score += 2;
                strong_signals += 1;
                summary.push("declared /Length mismatches raw stream".to_string());
            }
        } else {
            meta.insert("carve.length.status".to_string(), "indirect".to_string());
            missing_signals += 1;
            summary.push("indirect /Length".to_string());
        }

        if let Some(image_meta) = context.image_meta.as_ref() {
            score += image_metadata_score(
                kind,
                offset,
                data,
                image_meta,
                meta,
                &mut strong_signals,
                &mut summary,
            );
        } else if matches!(kind, "jpeg" | "png" | "gif") {
            score += 1;
            missing_signals += 1;
            summary.push("missing image dictionary metadata".to_string());
        }
    } else {
        meta.insert("carve.context".to_string(), "none".to_string());
    }

    let severity = if score <= -3 {
        Severity::Info
    } else if score <= 0 {
        Severity::Low
    } else if score <= 2 {
        Severity::Medium
    } else {
        Severity::High
    };

    let confidence = if strong_signals >= 2 {
        Confidence::Strong
    } else if missing_signals >= 2 && strong_signals == 0 {
        Confidence::Tentative
    } else {
        Confidence::Probable
    };

    meta.insert("carve.score".to_string(), score.to_string());
    meta.insert(
        "carve.confidence_basis".to_string(),
        format!("strong={strong_signals},missing={missing_signals}"),
    );
    if !summary.is_empty() {
        meta.insert("carve.correlation_summary".to_string(), summary.join("; "));
    }

    CarveScoring {
        severity,
        confidence,
        summary: if summary.is_empty() {
            None
        } else {
            Some(format!("Metadata correlation: {}.", summary.join("; ")))
        },
    }
}

fn image_metadata_score(
    kind: &str,
    offset: usize,
    data: &[u8],
    image_meta: &ImageDictMeta,
    meta: &mut HashMap<String, String>,
    strong_signals: &mut usize,
    summary: &mut Vec<String>,
) -> i32 {
    let mut score = 0i32;
    let header = parse_image_header(kind, &data[offset..]);
    let Some(header) = header else {
        return score;
    };

    meta.insert("carve.image.header.width".to_string(), header.width.to_string());
    meta.insert("carve.image.header.height".to_string(), header.height.to_string());
    if let Some(bits) = header.bits_per_component {
        meta.insert("carve.image.header.bits_per_component".to_string(), bits.to_string());
    }
    if let Some(channels) = header.channels {
        meta.insert("carve.image.header.channels".to_string(), channels.to_string());
    }

    if let (Some(width), Some(height)) = (image_meta.width, image_meta.height) {
        let match_dimensions = width == header.width && height == header.height;
        meta.insert("carve.image.dimensions.match".to_string(), match_dimensions.to_string());
        if match_dimensions {
            score -= 1;
            *strong_signals += 1;
            summary.push("image dimensions match dictionary".to_string());
        } else {
            score += 2;
            *strong_signals += 1;
            summary.push("image dimensions mismatch dictionary".to_string());
        }
    }

    if let (Some(declared_bits), Some(header_bits)) =
        (image_meta.bits_per_component, header.bits_per_component)
    {
        let bits_match = declared_bits == header_bits;
        meta.insert("carve.image.bpc.match".to_string(), bits_match.to_string());
        if bits_match {
            score -= 1;
            *strong_signals += 1;
            summary.push("bits-per-component matches image header".to_string());
        } else {
            score += 1;
            *strong_signals += 1;
            summary.push("bits-per-component mismatches image header".to_string());
        }
    }

    if let (Some(colour_space), Some(channels)) =
        (image_meta.colour_space.as_ref(), header.channels)
    {
        if let Some(expected_channels) = expected_channels_for_colour_space(colour_space) {
            meta.insert("carve.image.colour_space".to_string(), colour_space.clone());
            meta.insert(
                "carve.image.colour_space.expected_channels".to_string(),
                expected_channels.to_string(),
            );
            let channels_match = channels == expected_channels;
            meta.insert("carve.image.channels.match".to_string(), channels_match.to_string());
            if channels_match {
                score -= 1;
                *strong_signals += 1;
                summary.push("colour space channels match image header".to_string());
            } else {
                score += 1;
                *strong_signals += 1;
                summary.push("colour space channels mismatch image header".to_string());
            }
        }
    }

    score
}

fn parse_image_header(kind: &str, bytes: &[u8]) -> Option<ImageHeaderMeta> {
    match kind {
        "jpeg" => parse_jpeg_header(bytes),
        "png" => parse_png_header(bytes),
        "gif" => parse_gif_header(bytes),
        _ => None,
    }
}

fn parse_jpeg_header(bytes: &[u8]) -> Option<ImageHeaderMeta> {
    if bytes.len() < 4 || bytes[0] != 0xFF || bytes[1] != 0xD8 {
        return None;
    }
    let mut index = 2usize;
    while index + 3 < bytes.len() {
        if bytes[index] != 0xFF {
            index += 1;
            continue;
        }
        while index < bytes.len() && bytes[index] == 0xFF {
            index += 1;
        }
        if index >= bytes.len() {
            return None;
        }
        let marker = bytes[index];
        index += 1;
        if marker == 0xD9 || marker == 0xDA {
            return None;
        }
        if marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            continue;
        }
        if index + 1 >= bytes.len() {
            return None;
        }
        let segment_length = u16::from_be_bytes([bytes[index], bytes[index + 1]]) as usize;
        index += 2;
        if segment_length < 2 || index + segment_length - 2 > bytes.len() {
            return None;
        }
        if is_jpeg_sof_marker(marker) && segment_length >= 7 {
            let bits_per_component = bytes[index];
            let height = u16::from_be_bytes([bytes[index + 1], bytes[index + 2]]) as u32;
            let width = u16::from_be_bytes([bytes[index + 3], bytes[index + 4]]) as u32;
            let channels = bytes[index + 5];
            return Some(ImageHeaderMeta {
                width,
                height,
                bits_per_component: Some(bits_per_component as u32),
                channels: Some(channels),
            });
        }
        index += segment_length - 2;
    }
    None
}

fn is_jpeg_sof_marker(marker: u8) -> bool {
    matches!(
        marker,
        0xC0 | 0xC1 | 0xC2 | 0xC3 | 0xC5 | 0xC6 | 0xC7 | 0xC9 | 0xCA | 0xCB | 0xCD | 0xCE | 0xCF
    )
}

fn parse_png_header(bytes: &[u8]) -> Option<ImageHeaderMeta> {
    if bytes.len() < 29 || &bytes[..8] != b"\x89PNG\r\n\x1a\n" {
        return None;
    }
    if &bytes[12..16] != b"IHDR" {
        return None;
    }
    let width = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let height = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    let bits = bytes[24] as u32;
    let colour_type = bytes[25];
    let channels = match colour_type {
        0 => Some(1),
        2 => Some(3),
        3 => Some(1),
        4 => Some(2),
        6 => Some(4),
        _ => None,
    };
    Some(ImageHeaderMeta { width, height, bits_per_component: Some(bits), channels })
}

fn parse_gif_header(bytes: &[u8]) -> Option<ImageHeaderMeta> {
    if bytes.len() < 10 || !(bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")) {
        return None;
    }
    let width = u16::from_le_bytes([bytes[6], bytes[7]]) as u32;
    let height = u16::from_le_bytes([bytes[8], bytes[9]]) as u32;
    Some(ImageHeaderMeta { width, height, bits_per_component: None, channels: Some(3) })
}

fn expected_channels_for_colour_space(colour_space: &str) -> Option<u8> {
    match colour_space.to_ascii_lowercase().as_str() {
        "/devicegray" | "/calgray" | "/g" => Some(1),
        "/devicergb" | "/calrgb" | "/rgb" => Some(3),
        "/devicecmyk" | "/cmyk" => Some(4),
        _ => None,
    }
}

fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn expected_kind_for_filter(filter: &str) -> Option<&'static str> {
    match filter.to_ascii_lowercase().as_str() {
        "/dctdecode" | "/dct" => Some("JPEG"),
        "/jpxdecode" | "/jpx" => Some("JPEG2000"),
        "/jbig2decode" | "/jbig2" => Some("JBIG2"),
        "/ccittfaxdecode" | "/ccittfax" => Some("TIFF/CCITT"),
        _ => None,
    }
}

fn format_signature_kind(kind: &str) -> String {
    kind.to_ascii_uppercase()
}

fn script_payload_findings(
    obj: u32,
    gen: u16,
    span: sis_pdf_pdf::span::Span,
    data: &[u8],
    kind: BlobKind,
    origin: &str,
    label: &str,
) -> Vec<Finding> {
    let max_scan_bytes = 512 * 1024;
    let slice = if data.len() > max_scan_bytes { &data[..max_scan_bytes] } else { data };

    let mut findings = Vec::new();
    let mut push = |kind_str: &str,
                    title: &str,
                    description: &str,
                    family: &str,
                    hits: Vec<String>| {
        if hits.is_empty() {
            return;
        }
        let printable_ratio = printable_ascii_ratio(slice);
        let text_like = printable_ratio >= 70;
        let corroborated =
            contains_any_ci(slice, &[b"/launch", b"/javascript", b"/openaction", b"/aa", b"/js"]);
        let hit_count = hits.len();
        let actual_severity = if !text_like || kind.is_image() || matches!(kind, BlobKind::Unknown)
        {
            Severity::Low
        } else if corroborated && hit_count >= 2 {
            Severity::High
        } else if hit_count >= 2 {
            Severity::Medium
        } else {
            Severity::Low
        };
        let mut meta = HashMap::new();
        meta.insert("blob.origin".to_string(), origin.to_string());
        meta.insert("script.pattern_family".to_string(), family.to_string());
        meta.insert("script.pattern_hits".to_string(), hits.join(","));
        meta.insert("script.pattern_hit_count".to_string(), hit_count.to_string());
        meta.insert("script.text_printable_ratio".to_string(), printable_ratio.to_string());
        meta.insert("script.corroborating_action_markers".to_string(), corroborated.to_string());
        if let Some(first_hit) = hits.first() {
            if let Some(offset) = find_ci(slice, first_hit.as_bytes()) {
                meta.insert("script.match_offset".to_string(), offset.to_string());
                meta.insert(
                    "script.match_snippet".to_string(),
                    snippet_around(slice, offset, first_hit.len(), 80),
                );
            }
        }
        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::StreamsAndFilters,
            kind: kind_str.to_string(),
            severity: actual_severity,
            confidence: Confidence::Probable,
            impact: None,
            title: title.to_string(),
            description: description.to_string(),
            objects: vec![format!("{} {} obj", obj, gen)],
            evidence: vec![span_to_evidence(
                span,
                &format!("{}; matched patterns: {}", label, hits.join(", ")),
            )],
            remediation: Some("Inspect the script payload and execution context.".to_string()),
            meta,
            yara: None,
            position: None,
            positions: Vec::new(),
            ..Finding::default()
        });
    };

    let vb_hits = collect_pattern_hits(
        slice,
        &[b"vbscript", b"wscript.shell", b"createscript", b"createobject(\"wscript.shell\")"],
    );
    if !vb_hits.is_empty() {
        push(
            "vbscript_payload_present",
            "VBScript payload present",
            "VBScript indicators detected in content.",
            "vbscript",
            vb_hits,
        );
    }
    let ps_hits = collect_pattern_hits(
        slice,
        &[b"powershell", b"invoke-expression", b"iex ", b"-encodedcommand", b"-nop"],
    );
    if !ps_hits.is_empty() {
        push(
            "powershell_payload_present",
            "PowerShell payload present",
            "PowerShell indicators detected in content.",
            "powershell",
            ps_hits,
        );
    }
    let bash_hits =
        collect_pattern_hits(slice, &[b"#!/bin/bash", b"/bin/sh", b"bash -c", b"sh -c"]);
    if !bash_hits.is_empty() {
        push(
            "bash_payload_present",
            "Shell payload present",
            "Shell script indicators detected in content.",
            "bash",
            bash_hits,
        );
    }
    let cmd_hits = collect_pattern_hits(
        slice,
        &[b"cmd.exe", b"cmd /c", b"\\cmd.exe", b" /k ", b"comspec", b"powershell -command"],
    );
    if !cmd_hits.is_empty() {
        push(
            "cmd_payload_present",
            "Command payload present",
            "Command shell indicators detected in content.",
            "cmd",
            cmd_hits,
        );
    }
    let apple_hits = collect_pattern_hits(
        slice,
        &[b"osascript", b"tell application", b"apple script", b"do shell script"],
    );
    if !apple_hits.is_empty() {
        push(
            "applescript_payload_present",
            "AppleScript payload present",
            "AppleScript indicators detected in content.",
            "applescript",
            apple_hits,
        );
    }
    if contains_any_ci(slice, &[b"<script", b"<xfa", b"<xdp"]) && looks_like_xml(slice) {
        push(
            "xfa_script_present",
            "XFA/XML script present",
            "Script tags detected inside XFA/XML content.",
            "xfa_xml",
            vec!["<script".to_string()],
        );
    }

    findings
}

fn collect_pattern_hits(haystack: &[u8], patterns: &[&[u8]]) -> Vec<String> {
    patterns
        .iter()
        .filter_map(|needle| {
            if find_ci(haystack, needle).is_some() {
                Some(String::from_utf8_lossy(needle).to_string())
            } else {
                None
            }
        })
        .collect()
}

fn printable_ascii_ratio(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        return 0;
    }
    let printable =
        bytes.iter().filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace()).count();
    (printable * 100) / bytes.len()
}

fn snippet_around(bytes: &[u8], offset: usize, match_len: usize, max_len: usize) -> String {
    let half = max_len / 2;
    let start = offset.saturating_sub(half);
    let end = (offset + match_len + half).min(bytes.len());
    bytes[start..end]
        .iter()
        .map(|b| if b.is_ascii_graphic() || *b == b' ' { *b as char } else { '.' })
        .collect()
}

fn contains_any_ci(haystack: &[u8], needles: &[&[u8]]) -> bool {
    needles.iter().any(|needle| find_ci(haystack, needle).is_some())
}

fn find_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let needle_lower: Vec<u8> = needle.iter().map(|b| b.to_ascii_lowercase()).collect();
    haystack.windows(needle_lower.len()).position(|window| {
        window.iter().zip(&needle_lower).all(|(a, b)| a.to_ascii_lowercase() == *b)
    })
}

fn looks_like_xml(bytes: &[u8]) -> bool {
    contains_any_ci(bytes, &[b"<?xml", b"<xdp", b"<xfa", b"<template", b"<form"])
}

fn swf_findings(
    obj: u32,
    gen: u16,
    span: sis_pdf_pdf::span::Span,
    data: &[u8],
    kind: BlobKind,
    origin: &str,
    label: &str,
) -> Vec<Finding> {
    if kind != BlobKind::Swf {
        return Vec::new();
    }
    let Some(swf_bytes) = swf_expanded_bytes(data) else {
        return Vec::new();
    };
    let scan = parse_swf_tags(&swf_bytes);
    let mut findings = Vec::new();

    if scan.actionscript_present {
        let mut meta = HashMap::new();
        meta.insert("blob.origin".to_string(), origin.to_string());
        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::StreamsAndFilters,
            kind: "actionscript_present".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            impact: None,
            title: "ActionScript present".to_string(),
            description: "SWF tags indicate embedded ActionScript bytecode.".to_string(),
            objects: vec![format!("{} {} obj", obj, gen)],
            evidence: vec![span_to_evidence(span, label)],
            remediation: Some("Inspect SWF bytecode for malicious behaviour.".to_string()),
            meta,
            yara: None,
            position: None,
            positions: Vec::new(),
            ..Finding::default()
        });
    }

    if !scan.url_iocs.is_empty() {
        let mut meta = HashMap::new();
        meta.insert("blob.origin".to_string(), origin.to_string());
        meta.insert("url.iocs".to_string(), scan.url_iocs.join(", "));
        meta.insert("url.count".to_string(), scan.url_iocs.len().to_string());
        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::StreamsAndFilters,
            kind: "swf_url_iocs".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            impact: None,
            title: "SWF URL indicators".to_string(),
            description: "Embedded URLs detected in SWF tag payloads.".to_string(),
            objects: vec![format!("{} {} obj", obj, gen)],
            evidence: vec![span_to_evidence(span, label)],
            remediation: Some("Review SWF payloads for external references.".to_string()),
            meta,
            yara: None,
            position: None,
            positions: Vec::new(),
            ..Finding::default()
        });
    }

    findings
}

fn swf_expanded_bytes(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 8 {
        return None;
    }
    let signature = &data[..3];
    if signature == b"FWS" {
        return Some(data.to_vec());
    }
    if signature == b"CWS" {
        let mut decoder = ZlibDecoder::new(&data[8..]);
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        let mut total = 0usize;
        let max_out = 512 * 1024;
        loop {
            let n = decoder.read(&mut buf).ok()?;
            if n == 0 {
                break;
            }
            total += n;
            if total > max_out {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        let mut rebuilt = Vec::with_capacity(8 + out.len());
        rebuilt.extend_from_slice(b"FWS");
        rebuilt.push(data[3]);
        rebuilt.extend_from_slice(&data[4..8]);
        rebuilt.extend_from_slice(&out);
        return Some(rebuilt);
    }
    None
}

struct SwfTagScan {
    actionscript_present: bool,
    url_iocs: Vec<String>,
}

fn parse_swf_tags(data: &[u8]) -> SwfTagScan {
    let mut scan = SwfTagScan { actionscript_present: false, url_iocs: Vec::new() };
    if data.len() < 12 {
        return scan;
    }
    let nbits = data[8] >> 3;
    let rect_bits = 5u32 + 4u32 * nbits as u32;
    let rect_bytes = usize::div_ceil(rect_bits as usize, 8);
    let mut offset = 8 + rect_bytes + 4;
    if offset >= data.len() {
        return scan;
    }

    let max_tags = 100;
    let max_urls = 5;
    let mut tags_seen = 0usize;
    while offset + 2 <= data.len() && tags_seen < max_tags {
        let tag_header = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let tag_code = tag_header >> 6;
        let mut tag_len = (tag_header & 0x3F) as usize;
        offset += 2;
        if tag_len == 0x3F {
            if offset + 4 > data.len() {
                break;
            }
            tag_len = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            offset += 4;
        }
        if offset + tag_len > data.len() {
            break;
        }
        let payload = &data[offset..offset + tag_len];
        if tag_code == 72 || tag_code == 82 {
            scan.actionscript_present = true;
        }
        if scan.url_iocs.len() < max_urls {
            let strings = extract_ascii_strings(payload, 6);
            for s in strings {
                if looks_like_url(&s) {
                    scan.url_iocs.push(s);
                    if scan.url_iocs.len() >= max_urls {
                        break;
                    }
                }
            }
        }
        offset += tag_len;
        tags_seen += 1;
        if tag_code == 0 {
            break;
        }
    }
    scan
}

fn extract_ascii_strings(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = Vec::new();
    for &b in bytes {
        if b.is_ascii_graphic() || b == b' ' {
            buf.push(b);
        } else {
            if buf.len() >= min_len {
                out.push(String::from_utf8_lossy(&buf).to_string());
            }
            buf.clear();
        }
    }
    if buf.len() >= min_len {
        out.push(String::from_utf8_lossy(&buf).to_string());
    }
    out
}

fn looks_like_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("ftp://")
        || lower.contains("mailto:")
}

fn zip_container_findings(
    obj: u32,
    gen: u16,
    span: sis_pdf_pdf::span::Span,
    data: &[u8],
    kind: BlobKind,
    origin: &str,
    label: &str,
) -> Vec<Finding> {
    if kind != BlobKind::Zip {
        return Vec::new();
    }
    let max_scan_bytes = 512 * 1024;
    let max_entry_bytes = 128 * 1024;
    let max_entries = 10;
    let max_hits = 3;
    let slice = if data.len() > max_scan_bytes { &data[..max_scan_bytes] } else { data };

    let signatures = [
        ("pdf", b"%PDF-".as_slice()),
        ("mz", b"MZ".as_slice()),
        ("elf", b"\x7fELF".as_slice()),
        ("swf", b"FWS".as_slice()),
        ("swf", b"CWS".as_slice()),
        ("swf", b"ZWS".as_slice()),
        ("jpeg", b"\xFF\xD8\xFF".as_slice()),
        ("png", b"\x89PNG\r\n\x1a\n".as_slice()),
        ("xml", b"<?xml".as_slice()),
        ("html", b"<!DOCTYPE html".as_slice()),
        ("html", b"<html".as_slice()),
    ];

    let mut findings = Vec::new();
    let mut cursor = 0usize;
    let mut entries = 0usize;
    while cursor + 30 <= slice.len() && entries < max_entries && findings.len() < max_hits {
        if slice[cursor..cursor + 4] != *b"PK\x03\x04" {
            cursor += 1;
            continue;
        }
        let name_len = u16::from_le_bytes([slice[cursor + 26], slice[cursor + 27]]) as usize;
        let extra_len = u16::from_le_bytes([slice[cursor + 28], slice[cursor + 29]]) as usize;
        let comp_size = u32::from_le_bytes([
            slice[cursor + 18],
            slice[cursor + 19],
            slice[cursor + 20],
            slice[cursor + 21],
        ]) as usize;
        let data_start = cursor + 30 + name_len + extra_len;
        if data_start > slice.len() {
            break;
        }
        let data_end = data_start.saturating_add(comp_size).min(slice.len());
        let entry_end = data_end.min(data_start + max_entry_bytes);
        let entry_name = &slice[cursor + 30..cursor + 30 + name_len.min(slice.len() - cursor - 30)];
        let entry_name = String::from_utf8_lossy(entry_name).to_string();
        let entry_slice = &slice[data_start..entry_end];

        for (nested_kind, needle) in signatures {
            if let Some(offset) = find_pattern(entry_slice, needle) {
                let mut meta = HashMap::new();
                meta.insert("container.kind".to_string(), "zip".to_string());
                meta.insert("container.entry".to_string(), entry_name.clone());
                meta.insert("container.entry_offset".to_string(), cursor.to_string());
                meta.insert("nested.kind".to_string(), nested_kind.to_string());
                meta.insert("nested.offset".to_string(), offset.to_string());
                meta.insert("blob.origin".to_string(), origin.to_string());
                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::StreamsAndFilters,
                    kind: "nested_container_chain".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::Probable,
                    impact: None,
                    title: "Nested container chain detected".to_string(),
                    description: "ZIP entry contains a nested file signature.".to_string(),
                    objects: vec![format!("{} {} obj", obj, gen)],
                    evidence: vec![span_to_evidence(span, label)],
                    remediation: Some(
                        "Inspect embedded archive entries for nested payloads.".to_string(),
                    ),
                    meta,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                    ..Finding::default()
                });
                break;
            }
        }

        entries += 1;
        cursor = data_end.max(cursor + 4);
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use sis_pdf_pdf::span::Span;

    #[test]
    fn embedded_payload_carved_info_when_filter_matches() {
        let data = b"\xFF\xD8\xFF\xE0\x00\x10";
        let filters = vec!["/DCTDecode".to_string()];
        let span = Span { start: 0, end: data.len() as u64 };
        let findings = carve_payloads(
            1,
            0,
            span,
            data,
            "stream",
            "Stream data",
            Some(filters.as_slice()),
            None,
        );
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(
            finding.description,
            "Embedded JPEG signature matches declared filter /DCTDecode. Metadata correlation: filter /DCTDecode matches JPEG."
        );
        assert_eq!(finding.meta.get("carve.match").map(|v| v.as_str()), Some("true"));
        assert_eq!(finding.meta.get("carve.expected_kind").map(|v| v.as_str()), Some("JPEG"));
    }

    #[test]
    fn embedded_payload_carved_high_when_filter_mismatch() {
        let data = b"\xFF\xD8\xFF\xE0\x00\x10";
        let filters = vec!["/CCITTFaxDecode".to_string()];
        let span = Span { start: 0, end: data.len() as u64 };
        let findings = carve_payloads(
            1,
            0,
            span,
            data,
            "stream",
            "Stream data",
            Some(filters.as_slice()),
            None,
        );
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(
            finding.description,
            "Found a JPEG signature in a stream where we expected TIFF/CCITT. Metadata correlation: filter /CCITTFaxDecode expects TIFF/CCITT."
        );
        assert_eq!(finding.meta.get("carve.match").map(|v| v.as_str()), Some("false"));
        assert_eq!(finding.meta.get("carve.expected_kind").map(|v| v.as_str()), Some("TIFF/CCITT"));
    }

    #[test]
    fn embedded_payload_carved_strong_info_when_stream_metadata_matches() {
        let data = b"\xFF\xD8\xFF\xC0\x00\x11\x08\x00\x10\x00\x20\x03\x01\x11\x00\x02\x11\x00\x03\x11\x00\xFF\xD9";
        let filters = vec!["/DCTDecode".to_string()];
        let context = CarveCorrelationContext {
            decode_outcome: Some(DecodeOutcome::Ok),
            declared_length: Some(data.len() as u32),
            has_length_entry: true,
            observed_length: data.len(),
            image_meta: Some(ImageDictMeta {
                width: Some(32),
                height: Some(16),
                bits_per_component: Some(8),
                colour_space: Some("/DeviceRGB".to_string()),
            }),
        };
        let span = Span { start: 0, end: data.len() as u64 };
        let findings = carve_payloads(
            1,
            0,
            span,
            data,
            "stream",
            "Stream data",
            Some(filters.as_slice()),
            Some(&context),
        );
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.confidence, Confidence::Strong);
        assert_eq!(finding.meta.get("carve.length.match").map(|v| v.as_str()), Some("true"));
        assert_eq!(
            finding.meta.get("carve.image.dimensions.match").map(|v| v.as_str()),
            Some("true")
        );
        assert_eq!(
            finding.meta.get("carve.image.channels.match").map(|v| v.as_str()),
            Some("true")
        );
    }

    #[test]
    fn embedded_payload_carved_high_when_stream_metadata_conflicts() {
        let data = b"\xFF\xD8\xFF\xC0\x00\x11\x08\x00\x10\x00\x20\x03\x01\x11\x00\x02\x11\x00\x03\x11\x00\xFF\xD9";
        let filters = vec!["/DCTDecode".to_string()];
        let context = CarveCorrelationContext {
            decode_outcome: Some(DecodeOutcome::Failed {
                filter: Some("/DCTDecode".to_string()),
                reason: "simulated failure".to_string(),
            }),
            declared_length: Some(1024),
            has_length_entry: true,
            observed_length: data.len(),
            image_meta: Some(ImageDictMeta {
                width: Some(120),
                height: Some(16),
                bits_per_component: Some(1),
                colour_space: Some("/DeviceCMYK".to_string()),
            }),
        };
        let span = Span { start: 0, end: data.len() as u64 };
        let findings = carve_payloads(
            1,
            0,
            span,
            data,
            "stream",
            "Stream data",
            Some(filters.as_slice()),
            Some(&context),
        );
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::Strong);
        assert_eq!(finding.meta.get("carve.length.match").map(|v| v.as_str()), Some("false"));
        assert_eq!(
            finding.meta.get("carve.image.dimensions.match").map(|v| v.as_str()),
            Some("false")
        );
        assert_eq!(
            finding.meta.get("carve.image.channels.match").map(|v| v.as_str()),
            Some("false")
        );
    }

    #[test]
    fn signature_hint_reports_xpacket_as_xml() {
        let hint =
            observed_signature_hint(b"<?xpacket begin=\"...\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>");
        assert_eq!(hint, "xml/xmp packet prefix (<?xpacket)");
    }

    #[test]
    fn script_payload_cmd_ignores_lone_c_switch_token() {
        let span = Span { start: 0, end: 32 };
        let data = b"benign text with /c in content";
        let findings =
            script_payload_findings(60, 0, span, data, BlobKind::Xml, "stream", "Stream data");
        assert!(findings.iter().all(|f| f.kind != "cmd_payload_present"));
    }

    #[test]
    fn script_payload_cmd_is_medium_with_multiple_hits_without_action_marker() {
        let span = Span { start: 0, end: 64 };
        let data = b"cmd.exe used with cmd /c in plain metadata text";
        let findings =
            script_payload_findings(60, 0, span, data, BlobKind::Xml, "stream", "Stream data");
        let cmd = findings
            .iter()
            .find(|finding| finding.kind == "cmd_payload_present")
            .expect("expected command payload finding");
        assert_eq!(cmd.severity, Severity::Medium);
        assert_eq!(
            cmd.meta.get("script.pattern_hits").map(|value| value.as_str()),
            Some("cmd.exe,cmd /c")
        );
        assert_eq!(
            cmd.meta.get("script.corroborating_action_markers").map(|value| value.as_str()),
            Some("false")
        );
    }

    #[test]
    fn script_payload_cmd_is_high_when_corroborated_and_multi_hit() {
        let span = Span { start: 0, end: 96 };
        let data =
            b"<< /OpenAction 1 0 R >> cmd.exe /c calc with cmd /c and comspec in same stream";
        let findings =
            script_payload_findings(60, 0, span, data, BlobKind::Xml, "stream", "Stream data");
        let cmd = findings
            .iter()
            .find(|finding| finding.kind == "cmd_payload_present")
            .expect("expected command payload finding");
        assert_eq!(cmd.severity, Severity::High);
        assert_eq!(
            cmd.meta.get("script.corroborating_action_markers").map(|value| value.as_str()),
            Some("true")
        );
        assert_eq!(cmd.meta.get("script.pattern_hit_count").map(|value| value.as_str()), Some("3"));
    }
}
