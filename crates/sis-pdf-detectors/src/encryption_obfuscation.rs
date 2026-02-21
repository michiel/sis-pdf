use anyhow::Result;

use sis_pdf_core::crypto_analysis::classify_encryption_algorithm;
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::evidence::EvidenceBuilder;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_core::stream_analysis::{
    analyse_stream, StreamAnalysisResult, StreamLimits, STREAM_HIGH_ENTROPY_THRESHOLD,
    STREAM_MIN_BYTES,
};
use sis_pdf_core::timeout::TimeoutChecker;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};
use sis_pdf_pdf::typed_graph::{EdgeType, TypedEdge};

use crate::dict_int;

pub struct EncryptionObfuscationDetector;

impl Detector for EncryptionObfuscationDetector {
    fn id(&self) -> &'static str {
        "encryption_obfuscation"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::CryptoSignatures
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Cheap
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let timeout = TimeoutChecker::new(std::time::Duration::from_millis(150));
        let limits = StreamLimits::default();
        let typed_graph = ctx.build_typed_graph();
        let execution_bridge = packet_execution_bridge(&typed_graph.edges);

        for trailer in &ctx.graph.trailers {
            if let Some((_, encrypt_obj)) = trailer.get_first(b"/Encrypt") {
                if let Some(dict) = resolve_encrypt_dict(ctx, encrypt_obj) {
                    let mut meta = encryption_meta_from_dict(&dict);
                    if let Some(key_len) = dict_int(&dict, b"/Length") {
                        if key_len < 128 {
                            meta.insert("crypto.key_length".into(), key_len.to_string());
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "encryption_key_short".into(),
                                severity: Severity::Medium,
                                confidence: Confidence::Probable,
                                impact: None,
                                title: "Encryption key length short".into(),
                                description:
                                    "Encryption key length is below recommended threshold.".into(),
                                objects: vec!["trailer".into()],
                                evidence: EvidenceBuilder::new()
                                    .file_offset(
                                        trailer.span.start,
                                        trailer.span.len() as u32,
                                        "Trailer /Encrypt",
                                    )
                                    .build(),
                                remediation: Some("Treat encrypted content as higher risk.".into()),
                                meta,
                                yara: None,
                                position: None,
                                positions: Vec::new(),
                                ..Finding::default()
                            });
                        }
                    }
                }
            }
        }

        for entry in &ctx.graph.objects {
            if timeout.check().is_err() {
                break;
            }
            let PdfAtom::Stream(stream) = &entry.atom else {
                continue;
            };
            let Ok(decoded) = ctx.decoded.get_or_decode(ctx.bytes, stream) else {
                continue;
            };
            if decoded.data.len() < STREAM_MIN_BYTES {
                continue;
            }
            let analysis = analyse_stream(&decoded.data, &limits);
            if analysis.entropy >= STREAM_HIGH_ENTROPY_THRESHOLD {
                let meta = stream_entropy_meta(&analysis);
                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::StreamsAndFilters,
                    kind: "stream_high_entropy".into(),
                    severity: Severity::Low,
                    confidence: Confidence::Probable,
                    impact: None,
                    title: "High entropy stream".into(),
                    description: "Stream entropy exceeds expected threshold.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: EvidenceBuilder::new()
                        .file_offset(
                            stream.dict.span.start,
                            stream.dict.span.len() as u32,
                            "Stream dict",
                        )
                        .file_offset(
                            stream.data_span.start,
                            stream.data_span.len() as u32,
                            "Stream data",
                        )
                        .build(),
                    remediation: Some("Inspect stream content for hidden payloads.".into()),
                    meta: meta.clone(),
                    action_type: None,
                    action_target: None,
                    action_initiation: None,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                });

                if stream.dict.has_name(b"/Type", b"/EmbeddedFile")
                    && analysis.magic_type == "unknown"
                {
                    findings.push(Finding {
                        id: String::new(),
                        surface: AttackSurface::EmbeddedFiles,
                        kind: "embedded_encrypted".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Probable,
                        impact: None,
                        title: "Embedded file appears encrypted".into(),
                        description: "Embedded file has high entropy with unknown magic.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: EvidenceBuilder::new()
                            .file_offset(
                                stream.dict.span.start,
                                stream.dict.span.len() as u32,
                                "EmbeddedFile dict",
                            )
                            .file_offset(
                                stream.data_span.start,
                                stream.data_span.len() as u32,
                                "EmbeddedFile stream",
                            )
                            .build(),
                        remediation: Some(
                            "Attempt to extract and decrypt the embedded file.".into(),
                        ),
                        meta,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                        ..Finding::default()
                    });
                }
            }

            if let Some(packetised) = detect_packetised_payload_obfuscation(&decoded.data) {
                if !execution_bridge.any {
                    continue;
                }
                let mut meta = stream_entropy_meta(&analysis);
                meta.insert("packet.block_count".into(), packetised.block_count.to_string());
                meta.insert(
                    "packet.estimated_index_fields".into(),
                    packetised.estimated_index_fields.to_string(),
                );
                meta.insert(
                    "packet.reconstruction_feasibility".into(),
                    packetised.reconstruction_feasibility.into(),
                );
                meta.insert("packet.stride_bytes".into(), packetised.stride_bytes.to_string());
                meta.insert(
                    "packet.monotonic_index_ratio".into(),
                    format!("{:.3}", packetised.monotonic_index_ratio),
                );
                meta.insert(
                    "packet.length_field_ratio".into(),
                    format!("{:.3}", packetised.length_field_ratio),
                );
                meta.insert(
                    "packet.index_gap_ratio".into(),
                    format!("{:.3}", packetised.index_gap_ratio),
                );
                meta.insert(
                    "packet.unique_index_ratio".into(),
                    format!("{:.3}", packetised.unique_index_ratio),
                );
                meta.insert(
                    "packet.index_width_bytes".into(),
                    packetised.index_width_bytes.to_string(),
                );
                meta.insert(
                    "packet.length_width_bytes".into(),
                    packetised.length_width_bytes.to_string(),
                );
                meta.insert("packet.endianness".into(), packetised.endianness.into());
                meta.insert("packet.correlation.execution_bridge".into(), "true".into());
                meta.insert(
                    "packet.correlation.launch_path".into(),
                    execution_bridge.launch.to_string(),
                );
                meta.insert(
                    "packet.correlation.execution_sink".into(),
                    execution_bridge.execution_sink.to_string(),
                );
                meta.insert(
                    "packet.correlation.trigger_path".into(),
                    execution_bridge.trigger_path.to_string(),
                );
                meta.insert(
                    "packet.correlation.bridge_sources".into(),
                    execution_bridge.sources.join(","),
                );
                let (severity, confidence, impact) =
                    if execution_bridge.launch || execution_bridge.execution_sink {
                        (Severity::High, Confidence::Strong, Impact::High)
                    } else {
                        (Severity::Medium, Confidence::Probable, Impact::Medium)
                    };
                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::StreamsAndFilters,
                    kind: "packetised_payload_obfuscation".into(),
                    severity,
                    confidence,
                    impact: Some(impact),
                    title: "Packetised payload obfuscation".into(),
                    description:
                        "Stream exhibits packet-like high-entropy blocks with index/length traits consistent with staged payload reconstruction."
                            .into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: EvidenceBuilder::new()
                        .file_offset(
                            stream.dict.span.start,
                            stream.dict.span.len() as u32,
                            "Packetised stream dict",
                        )
                        .file_offset(
                            stream.data_span.start,
                            stream.data_span.len() as u32,
                            "Packetised stream data",
                        )
                        .build(),
                    remediation: Some(
                        "Decode and reorder packet blocks in a controlled environment, and correlate with launch/script execution paths."
                            .into(),
                    ),
                    meta,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                    ..Finding::default()
                });
            }
        }

        Ok(findings)
    }
}

struct PacketisedPayloadSignal {
    block_count: usize,
    estimated_index_fields: usize,
    reconstruction_feasibility: &'static str,
    stride_bytes: usize,
    monotonic_index_ratio: f64,
    length_field_ratio: f64,
    index_gap_ratio: f64,
    unique_index_ratio: f64,
    index_width_bytes: usize,
    length_width_bytes: usize,
    endianness: &'static str,
}

#[derive(Default, Clone)]
struct PacketExecutionBridge {
    any: bool,
    launch: bool,
    execution_sink: bool,
    trigger_path: bool,
    sources: Vec<String>,
}

fn packet_execution_bridge(edges: &[TypedEdge]) -> PacketExecutionBridge {
    let mut bridge = PacketExecutionBridge::default();
    for edge in edges {
        match &edge.edge_type {
            EdgeType::LaunchTarget => {
                bridge.launch = true;
                if !bridge.sources.iter().any(|source| source == "launch") {
                    bridge.sources.push("launch".to_string());
                }
            }
            EdgeType::JavaScriptPayload | EdgeType::JavaScriptNames => {
                bridge.execution_sink = true;
                if !bridge.sources.iter().any(|source| source == "javascript") {
                    bridge.sources.push("javascript".to_string());
                }
            }
            EdgeType::OpenAction
            | EdgeType::AdditionalAction { .. }
            | EdgeType::PageAction { .. }
            | EdgeType::FormFieldAction { .. } => {
                bridge.trigger_path = true;
                if !bridge.sources.iter().any(|source| source == "action-trigger") {
                    bridge.sources.push("action-trigger".to_string());
                }
            }
            _ => {}
        }
    }
    bridge.any = bridge.launch || bridge.execution_sink || bridge.trigger_path;
    bridge
}

#[derive(Clone, Copy)]
struct PacketFieldSpec {
    index_offset: usize,
    index_width: usize,
    length_offset: usize,
    length_width: usize,
    big_endian: bool,
}

fn decode_packet_value(
    block: &[u8],
    offset: usize,
    width: usize,
    big_endian: bool,
) -> Option<usize> {
    let end = offset.checked_add(width)?;
    let bytes = block.get(offset..end)?;
    match (width, big_endian) {
        (2, true) => Some(u16::from_be_bytes([bytes[0], bytes[1]]) as usize),
        (2, false) => Some(u16::from_le_bytes([bytes[0], bytes[1]]) as usize),
        (4, true) => Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize),
        (4, false) => Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize),
        _ => None,
    }
}

fn detect_packetised_payload_obfuscation(data: &[u8]) -> Option<PacketisedPayloadSignal> {
    if data.len() < 1024 {
        return None;
    }
    let mut best: Option<PacketisedPayloadSignal> = None;
    let field_specs = [
        PacketFieldSpec {
            index_offset: 0,
            index_width: 2,
            length_offset: 2,
            length_width: 2,
            big_endian: true,
        },
        PacketFieldSpec {
            index_offset: 0,
            index_width: 2,
            length_offset: 2,
            length_width: 2,
            big_endian: false,
        },
        PacketFieldSpec {
            index_offset: 0,
            index_width: 4,
            length_offset: 4,
            length_width: 2,
            big_endian: true,
        },
        PacketFieldSpec {
            index_offset: 0,
            index_width: 4,
            length_offset: 4,
            length_width: 4,
            big_endian: true,
        },
    ];
    let analysis = analyse_stream(data, &StreamLimits::default());
    if analysis.entropy < STREAM_HIGH_ENTROPY_THRESHOLD {
        return None;
    }
    for stride in [32usize, 48, 64, 96, 128] {
        let block_count = data.len() / stride;
        if block_count < 8 {
            continue;
        }
        for spec in field_specs {
            if stride < spec.length_offset + spec.length_width {
                continue;
            }
            let mut monotonic = 0usize;
            let mut length_like = 0usize;
            let mut sequential_gaps = 0usize;
            let mut prev_index: Option<usize> = None;
            let mut unique_indexes = std::collections::BTreeSet::new();
            for index in 0..block_count {
                let offset = index * stride;
                let block = &data[offset..offset + stride];
                let Some(packet_index) = decode_packet_value(
                    block,
                    spec.index_offset,
                    spec.index_width,
                    spec.big_endian,
                ) else {
                    continue;
                };
                let Some(packet_len) = decode_packet_value(
                    block,
                    spec.length_offset,
                    spec.length_width,
                    spec.big_endian,
                ) else {
                    continue;
                };
                unique_indexes.insert(packet_index);
                if index == 0 || packet_index == index || packet_index == index + 1 {
                    monotonic += 1;
                }
                if let Some(previous) = prev_index {
                    if packet_index > previous + 1 {
                        sequential_gaps += 1;
                    }
                }
                prev_index = Some(packet_index);
                if (4..=stride.saturating_sub(2)).contains(&packet_len) {
                    length_like += 1;
                }
            }
            let monotonic_ratio = monotonic as f64 / block_count as f64;
            let length_ratio = length_like as f64 / block_count as f64;
            let index_gap_ratio = sequential_gaps as f64 / block_count as f64;
            let unique_index_ratio = unique_indexes.len() as f64 / block_count as f64;
            if monotonic_ratio < 0.65 || length_ratio < 0.65 {
                continue;
            }
            let candidate = PacketisedPayloadSignal {
                block_count,
                estimated_index_fields: spec.index_width + spec.length_width,
                reconstruction_feasibility: if monotonic_ratio > 0.9
                    && length_ratio > 0.9
                    && unique_index_ratio > 0.9
                    && index_gap_ratio < 0.15
                {
                    "high"
                } else if monotonic_ratio > 0.75 && length_ratio > 0.75 {
                    "medium"
                } else {
                    "low"
                },
                stride_bytes: stride,
                monotonic_index_ratio: monotonic_ratio,
                length_field_ratio: length_ratio,
                index_gap_ratio,
                unique_index_ratio,
                index_width_bytes: spec.index_width,
                length_width_bytes: spec.length_width,
                endianness: if spec.big_endian { "big" } else { "little" },
            };
            if best
                .as_ref()
                .map(|current| {
                    candidate.block_count > current.block_count
                        || (candidate.block_count == current.block_count
                            && candidate.monotonic_index_ratio > current.monotonic_index_ratio)
                })
                .unwrap_or(true)
            {
                best = Some(candidate);
            }
        }
    }
    best
}

fn stream_entropy_meta(
    analysis: &StreamAnalysisResult,
) -> std::collections::HashMap<String, String> {
    let mut meta = std::collections::HashMap::new();
    meta.insert("entropy".into(), format!("{:.3}", analysis.entropy));
    meta.insert("stream.entropy".into(), format!("{:.3}", analysis.entropy));
    meta.insert("entropy_threshold".into(), format!("{:.1}", STREAM_HIGH_ENTROPY_THRESHOLD));
    meta.insert("sample_size_bytes".into(), analysis.sample_bytes.to_string());
    meta.insert("stream.sample_size_bytes".into(), analysis.sample_bytes.to_string());
    meta.insert("stream.sample_timed_out".into(), analysis.timed_out.to_string());
    meta.insert("stream.size_bytes".into(), analysis.size_bytes.to_string());
    meta.insert("stream.magic".into(), analysis.magic_type.clone());
    meta.insert("stream.magic_type".into(), analysis.magic_type.clone());
    meta
}

pub(crate) fn resolve_encrypt_dict<'a>(
    ctx: &'a sis_pdf_core::scan::ScanContext,
    obj: &'a PdfObj<'a>,
) -> Option<PdfDict<'a>> {
    match &obj.atom {
        PdfAtom::Dict(dict) => Some(dict.clone()),
        PdfAtom::Ref { obj, gen } => {
            ctx.graph.get_object(*obj, *gen).and_then(|entry| match &entry.atom {
                PdfAtom::Dict(dict) => Some(dict.clone()),
                _ => None,
            })
        }
        _ => None,
    }
}

pub(crate) fn encryption_meta_from_dict(
    dict: &PdfDict<'_>,
) -> std::collections::HashMap<String, String> {
    let mut meta = std::collections::HashMap::new();
    let version = dict_int(dict, b"/V");
    let revision = dict_int(dict, b"/R");
    let key_len = dict_int(dict, b"/Length");

    if let Some(v) = version {
        meta.insert("crypto.version".into(), v.to_string());
    }
    if let Some(r) = revision {
        meta.insert("crypto.revision".into(), r.to_string());
    }
    if let Some(len) = key_len {
        meta.insert("crypto.key_length".into(), len.to_string());
    }
    if let Some((_, obj)) = dict.get_first(b"/Filter") {
        if let PdfAtom::Name(name) = &obj.atom {
            meta.insert("crypto.filter".into(), String::from_utf8_lossy(&name.decoded).to_string());
        }
    }
    if let Some(algorithm) = classify_encryption_algorithm(version, key_len) {
        meta.insert("crypto.algorithm".into(), algorithm.into());
    }
    meta
}

#[cfg(test)]
mod tests {
    use super::{detect_packetised_payload_obfuscation, packet_execution_bridge};
    use sis_pdf_pdf::typed_graph::{EdgeType, TypedEdge};

    #[test]
    fn detects_packetised_entropy_blocks() {
        let stride = 64usize;
        let blocks = 24usize;
        let mut payload = Vec::new();
        for block_index in 0..blocks {
            payload.extend_from_slice(&(block_index as u16).to_be_bytes());
            payload.extend_from_slice(&60u16.to_be_bytes());
            for inner_index in 0..(stride - 4) {
                let value = ((block_index * 131 + inner_index * 17 + 73) % 251) as u8;
                payload.push(value);
            }
        }
        let detected =
            detect_packetised_payload_obfuscation(&payload).expect("packetised payload signal");
        assert_eq!(detected.stride_bytes, 64);
        assert_eq!(detected.block_count, 24);
        assert!(detected.monotonic_index_ratio >= 0.9);
        assert!(detected.length_field_ratio >= 0.9);
        assert_eq!(detected.endianness, "big");
        assert_eq!(detected.index_width_bytes, 2);
        assert_eq!(detected.length_width_bytes, 2);
    }

    #[test]
    fn detects_packetised_with_32bit_index_field_layout() {
        let stride = 64usize;
        let blocks = 20usize;
        let mut payload = Vec::new();
        for block_index in 0..blocks {
            payload.extend_from_slice(&(block_index as u32).to_be_bytes());
            payload.extend_from_slice(&52u16.to_be_bytes());
            for inner_index in 0..(stride - 6) {
                let value = ((block_index * 211 + inner_index * 13 + 19) % 251) as u8;
                payload.push(value);
            }
        }
        let detected =
            detect_packetised_payload_obfuscation(&payload).expect("packetised payload signal");
        assert_eq!(detected.stride_bytes, 64);
        assert_eq!(detected.index_width_bytes, 4);
        assert_eq!(detected.length_width_bytes, 2);
        assert_eq!(detected.endianness, "big");
    }

    #[test]
    fn packet_execution_bridge_reports_sources() {
        let edges = vec![
            TypedEdge::new((1, 0), (2, 0), EdgeType::OpenAction),
            TypedEdge::new((2, 0), (3, 0), EdgeType::JavaScriptPayload),
        ];
        let bridge = packet_execution_bridge(&edges);
        assert!(bridge.any);
        assert!(bridge.execution_sink);
        assert!(bridge.trigger_path);
        assert!(!bridge.launch);
        assert_eq!(bridge.sources.join(","), "action-trigger,javascript");
    }
}
