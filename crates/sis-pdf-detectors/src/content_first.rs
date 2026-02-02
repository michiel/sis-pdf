use std::collections::{HashMap, HashSet};
use std::io::Read;

use anyhow::Result;
use flate2::read::ZlibDecoder;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::blob::Blob;
use sis_pdf_pdf::blob_classify::{classify_blob, validate_blob_kind, BlobKind};
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

        let obj_map: HashMap<(u32, u16), &PdfAtom<'_>> = ctx
            .graph
            .objects
            .iter()
            .map(|entry| ((entry.obj, entry.gen), &entry.atom))
            .collect();
        let embedded_map = embedded_file_map(ctx, &obj_map);
        let xfa_map = xfa_stream_map(ctx, &obj_map);

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
                    let filter_expectations = blob
                        .decode_meta
                        .as_ref()
                        .map(|meta| meta.filters.as_slice());

                    if let Some(finding) = label_mismatch_finding(
                        entry.obj,
                        entry.gen,
                        stream,
                        &declared_type,
                        &declared_subtype,
                        kind,
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

fn object_bytes<'a>(bytes: &'a [u8], span: sis_pdf_pdf::span::Span) -> Option<&'a [u8]> {
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
        PdfAtom::Ref { obj, gen } => obj_map
            .get(&(*obj, *gen))
            .and_then(|atom| dict_from_atom(atom)),
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
        PdfAtom::Ref {
            obj: ref_obj,
            gen: ref_gen,
        } => {
            out.insert((*ref_obj, *ref_gen), container);
            if let Some(atom) = obj_map.get(&(*ref_obj, *ref_gen)) {
                let child = PdfObj {
                    span: obj.span,
                    atom: (*atom).clone(),
                };
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
    meta.insert("blob.origin".to_string(), origin.to_string());

    Some(Finding {
        id: String::new(),
        surface: AttackSurface::StreamsAndFilters,
        kind: "label_mismatch_stream_type".to_string(),
        severity,
        confidence: Confidence::Strong,
        impact: None,
        title: "Stream label mismatch".to_string(),
        description: "Stream subtype does not match observed content signature.".to_string(),
        objects: vec![format!("{} {} obj", obj, gen)],
        evidence: vec![span_to_evidence(stream.data_span, "Stream data")],
        remediation: Some("Verify stream subtype and inspect embedded content.".to_string()),
        meta,
        yara: None,
        position: None,
        positions: Vec::new(),
        ..Finding::default()
    })
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
        yara: None,
        position: None,
        positions: Vec::new(),
        ..Finding::default()
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
        yara: None,
        position: None,
        positions: Vec::new(),
        ..Finding::default()
    })
}

fn declared_filter_invalid_finding(
    obj: u32,
    gen: u16,
    stream: &PdfStream<'_>,
    blob: &Blob<'_>,
    origin: &str,
) -> Option<Finding> {
    let meta = blob.decode_meta.as_ref()?;
    if meta.filters.is_empty() {
        return None;
    }

    let (title, description, confidence) = match &meta.outcome {
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
    if !meta.mismatches.is_empty() {
        let reasons = meta
            .mismatches
            .iter()
            .map(|m| format!("{}:{}", m.filter, m.reason))
            .collect::<Vec<_>>();
        finding_meta.insert("decode.mismatch".to_string(), reasons.join(";"));
    }

    Some(Finding {
        id: String::new(),
        surface: AttackSurface::StreamsAndFilters,
        kind: "declared_filter_invalid".to_string(),
        severity: Severity::High,
        confidence,
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
        ..Finding::default()
    })
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
    finding_meta.insert(
        "decode.recovered_filters".to_string(),
        meta.recovered_filters.join(","),
    );
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
        ..Finding::default()
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

    let mut meta = HashMap::new();
    meta.insert("compression.guess".to_string(), "zlib".to_string());
    meta.insert("blob.origin".to_string(), origin.to_string());

    Some(Finding {
        id: String::new(),
        surface: AttackSurface::StreamsAndFilters,
        kind: "undeclared_compression_present".to_string(),
        severity: Severity::High,
        confidence: Confidence::Probable,
        impact: None,
        title: "Undeclared compression detected".to_string(),
        description: "Stream data looks compressed despite no declared filters.".to_string(),
        objects: vec![format!("{} {} obj", obj, gen)],
        evidence: vec![span_to_evidence(stream.data_span, "Stream data")],
        remediation: Some("Review stream for hidden compression or evasion.".to_string()),
        meta,
        yara: None,
        position: None,
        positions: Vec::new(),
        ..Finding::default()
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

fn carve_payloads(
    obj: u32,
    gen: u16,
    span: sis_pdf_pdf::span::Span,
    data: &[u8],
    origin: &str,
    label: &str,
    filters: Option<&[String]>,
) -> Vec<Finding> {
    let max_scan_bytes = 512 * 1024;
    let max_hits = 3;
    let slice = if data.len() > max_scan_bytes {
        &data[..max_scan_bytes]
    } else {
        data
    };

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
            let mut severity = Severity::High;
            if let Some((expected_kind, filter_name)) = expectation {
                let match_kind = expected_kind.eq_ignore_ascii_case(kind);
                meta.insert("carve.filter".to_string(), filter_name.to_string());
                meta.insert("carve.expected_kind".to_string(), expected_kind.to_string());
                meta.insert("carve.match".to_string(), match_kind.to_string());
                let actual_label = format_signature_kind(kind);
                if match_kind {
                    severity = Severity::Info;
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
            meta.insert("blob.origin".to_string(), origin.to_string());
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::StreamsAndFilters,
                kind: "embedded_payload_carved".to_string(),
                severity,
                confidence: Confidence::Probable,
                impact: None,
                title: "Embedded payload carved".to_string(),
                description,
                objects: vec![format!("{} {} obj", obj, gen)],
                evidence: vec![span_to_evidence(span, label)],
                remediation: Some(
                    "Inspect the object for embedded payloads or polyglot content.".to_string(),
                ),
                meta,
                yara: None,
                position: None,
                positions: Vec::new(),
                ..Finding::default()
            });
            if findings.len() >= max_hits {
                break;
            }
        }
    }
    findings
}

fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
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

#[cfg(test)]
mod tests {
    use super::*;
    use sis_pdf_pdf::span::Span;

    #[test]
    fn embedded_payload_carved_info_when_filter_matches() {
        let data = b"\xFF\xD8\xFF\xE0\x00\x10";
        let filters = vec!["/DCTDecode".to_string()];
        let span = Span {
            start: 0,
            end: data.len() as u64,
        };
        let findings = carve_payloads(
            1,
            0,
            span,
            data,
            "stream",
            "Stream data",
            Some(filters.as_slice()),
        );
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(
            finding.description,
            "Embedded JPEG signature matches declared filter /DCTDecode."
        );
        assert_eq!(
            finding.meta.get("carve.match").map(|v| v.as_str()),
            Some("true")
        );
        assert_eq!(
            finding.meta.get("carve.expected_kind").map(|v| v.as_str()),
            Some("JPEG")
        );
    }

    #[test]
    fn embedded_payload_carved_high_when_filter_mismatch() {
        let data = b"\xFF\xD8\xFF\xE0\x00\x10";
        let filters = vec!["/CCITTFaxDecode".to_string()];
        let span = Span {
            start: 0,
            end: data.len() as u64,
        };
        let findings = carve_payloads(
            1,
            0,
            span,
            data,
            "stream",
            "Stream data",
            Some(filters.as_slice()),
        );
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(
            finding.description,
            "Found a JPEG signature in a stream where we expected TIFF/CCITT."
        );
        assert_eq!(
            finding.meta.get("carve.match").map(|v| v.as_str()),
            Some("false")
        );
        assert_eq!(
            finding.meta.get("carve.expected_kind").map(|v| v.as_str()),
            Some("TIFF/CCITT")
        );
    }
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
    let slice = if data.len() > max_scan_bytes {
        &data[..max_scan_bytes]
    } else {
        data
    };

    let mut findings = Vec::new();
    let mut push = |kind_str: &str, title: &str, description: &str, default_severity: Severity| {
        let actual_severity = if kind.is_image()
            || matches!(kind, BlobKind::Xml | BlobKind::Html | BlobKind::Unknown)
        {
            // If the blob is an image, XML, HTML, or unknown, and we found a script indicator,
            // it's likely a false positive or benign data. Lower severity.
            Severity::Low
        } else {
            // Otherwise, use the default severity (which is High for most script payloads)
            default_severity
        };
        let mut meta = HashMap::new();
        meta.insert("blob.origin".to_string(), origin.to_string());
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
            evidence: vec![span_to_evidence(span, label)],
            remediation: Some("Inspect the script payload and execution context.".to_string()),
            meta,
            yara: None,
            position: None,
            positions: Vec::new(),
            ..Finding::default()
        });
    };

    if contains_any_ci(slice, &[b"vbscript", b"wscript.shell", b"createscript"]) {
        push(
            "vbscript_payload_present",
            "VBScript payload present",
            "VBScript indicators detected in content.",
            Severity::High,
        );
    }
    if contains_any_ci(slice, &[b"powershell", b"invoke-expression", b"iex "]) {
        push(
            "powershell_payload_present",
            "PowerShell payload present",
            "PowerShell indicators detected in content.",
            Severity::High,
        );
    }
    if contains_any_ci(slice, &[b"#!/bin/bash", b"/bin/sh", b"bash -c"]) {
        push(
            "bash_payload_present",
            "Shell payload present",
            "Shell script indicators detected in content.",
            Severity::High,
        );
    }
    if contains_any_ci(slice, &[b"cmd.exe", b"cmd /c", b" /c "]) {
        push(
            "cmd_payload_present",
            "Command payload present",
            "Command shell indicators detected in content.",
            Severity::High,
        );
    }
    if contains_any_ci(slice, &[b"osascript", b"tell application", b"apple script"]) {
        push(
            "applescript_payload_present",
            "AppleScript payload present",
            "AppleScript indicators detected in content.",
            Severity::High,
        );
    }
    if contains_any_ci(slice, &[b"<script", b"<xfa", b"<xdp"]) && looks_like_xml(slice) {
        push(
            "xfa_script_present",
            "XFA/XML script present",
            "Script tags detected inside XFA/XML content.",
            Severity::Medium,
        );
    }

    findings
}

fn contains_any_ci(haystack: &[u8], needles: &[&[u8]]) -> bool {
    needles
        .iter()
        .any(|needle| find_ci(haystack, needle).is_some())
}

fn find_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let needle_lower: Vec<u8> = needle.iter().map(|b| b.to_ascii_lowercase()).collect();
    haystack.windows(needle_lower.len()).position(|window| {
        window
            .iter()
            .zip(&needle_lower)
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
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
    let mut scan = SwfTagScan {
        actionscript_present: false,
        url_iocs: Vec::new(),
    };
    if data.len() < 12 {
        return scan;
    }
    let nbits = data[8] >> 3;
    let rect_bits = 5u32 + 4u32 * nbits as u32;
    let rect_bytes = ((rect_bits + 7) / 8) as usize;
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
    let slice = if data.len() > max_scan_bytes {
        &data[..max_scan_bytes]
    } else {
        data
    };

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
