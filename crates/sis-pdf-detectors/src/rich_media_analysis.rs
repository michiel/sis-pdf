use anyhow::Result;

use std::collections::HashMap;
use std::time::Duration;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::evidence::EvidenceBuilder;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_core::rich_media::{
    analyze_swf, detect_3d_format, swf_compression_label, swf_magic, SWF_DECODE_TIMEOUT_MS,
    SWF_DECOMPRESSED_LIMIT, SWF_DECOMPRESSION_RATIO_LIMIT,
};
use sis_pdf_core::stream_analysis::{analyse_stream, StreamLimits};
use sis_pdf_core::timeout::TimeoutChecker;
use sis_pdf_pdf::object::{PdfAtom, PdfDict};

use crate::entry_dict;

pub struct RichMediaContentDetector;

impl Detector for RichMediaContentDetector {
    fn id(&self) -> &'static str {
        "rich_media_content"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::RichMedia3D
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Moderate
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let timeout = TimeoutChecker::new(Duration::from_millis(100));
        let has_media_surface = ctx.graph.objects.iter().any(|entry| {
            entry_dict(entry).is_some_and(|dict| is_rich_media_dict(dict) || is_3d_dict(dict))
        });
        if !has_media_surface {
            return Ok(findings);
        }
        for entry in &ctx.graph.objects {
            if timeout.check().is_err() {
                break;
            }
            let PdfAtom::Stream(stream) = &entry.atom else {
                continue;
            };
            let Some(dict) = entry_dict(entry) else {
                continue;
            };
            let is_rich_media = is_rich_media_dict(dict);
            let is_3d = is_3d_dict(dict);
            if !is_rich_media && !is_3d {
                continue;
            }

            let (stream_bytes, decode_success) = match ctx.decoded.get_or_decode(ctx.bytes, stream)
            {
                Ok(decoded) => (decoded.data, true),
                Err(_) => {
                    let start = stream.data_span.start as usize;
                    let end = stream.data_span.end as usize;
                    if start >= end || end > ctx.bytes.len() {
                        continue;
                    }
                    (ctx.bytes[start..end].to_vec(), false)
                }
            };

            if is_3d {
                findings.extend(analyse_3d_stream(
                    entry.obj,
                    entry.gen,
                    dict,
                    stream,
                    &stream_bytes,
                    decode_success,
                ));
            }

            if !is_rich_media || !swf_magic(&stream_bytes) {
                continue;
            }
            let mut decode_timeout =
                TimeoutChecker::new(Duration::from_millis(SWF_DECODE_TIMEOUT_MS));
            let Some(analysis) = analyze_swf(&stream_bytes, &mut decode_timeout) else {
                continue;
            };
            if analysis.decompressed_body_len >= SWF_DECOMPRESSED_LIMIT {
                continue;
            }
            let ratio = analysis.decompressed_body_len as f64 / analysis.compressed_len as f64;
            if ratio > SWF_DECOMPRESSION_RATIO_LIMIT {
                continue;
            }
            let mut meta = HashMap::new();
            insert_stream_analysis_meta(&mut meta, &stream_bytes);
            meta.insert("swf.magic".into(), String::from_utf8_lossy(&stream_bytes[..3]).into());
            meta.insert("swf.size".into(), stream_bytes.len().to_string());
            meta.insert("media_type".into(), "swf".into());
            meta.insert(
                "swf.decompressed_bytes".into(),
                analysis.decompressed_body_len.to_string(),
            );
            meta.insert("swf.decompression_ratio".into(), format!("{:.2}", ratio));
            meta.insert("swf.version".into(), analysis.header.version.to_string());
            meta.insert("swf.declared_length".into(), analysis.header.file_length.to_string());
            meta.insert(
                "swf.compression".into(),
                swf_compression_label(analysis.header.compression).to_string(),
            );
            if let Some(rate) = analysis.header.frame_rate {
                meta.insert("swf.frame_rate".into(), format!("{:.2}", rate));
            }
            if let Some(count) = analysis.header.frame_count {
                meta.insert("swf.frame_count".into(), count.to_string());
            }
            let evidence = EvidenceBuilder::new()
                .file_offset(
                    stream.dict.span.start,
                    stream.dict.span.len() as u32,
                    "RichMedia dict",
                )
                .file_offset(
                    stream.data_span.start,
                    stream.data_span.len() as u32,
                    "RichMedia stream",
                )
                .build();
            let action_evidence = evidence.clone();
            let mut action_tags = analysis.action_scan.action_tags.clone();
            if action_tags.is_empty() && analysis.action_scan.tags_scanned > 0 {
                action_tags.push("DoABC".to_string());
            }
            let actions_present = !action_tags.is_empty();
            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "swf_embedded".into(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                impact: None,
                title: "SWF content embedded".into(),
                description: format!(
                    "SWF payload detected (version {}, compression {}, ActionScript tags present: {}).",
                    analysis.header.version,
                    swf_compression_label(analysis.header.compression),
                    actions_present
                ),
                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                evidence: evidence.clone(),
                remediation: Some(
                    "Extract SWF, confirm version/compression, then inspect ActionScript tags for staged payload behaviour."
                        .into(),
                ),
                meta: meta.clone(),
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
            });
            if !action_tags.is_empty() {
                let mut action_meta = meta.clone();
                action_meta.insert("swf.action_tag_count".into(), action_tags.len().to_string());
                action_meta.insert(
                    "swf.tags_scanned".into(),
                    analysis.action_scan.tags_scanned.to_string(),
                );
                action_meta.insert("swf.action_tags".into(), encode_list(&action_tags));
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "swf_actionscript_detected".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    impact: None,
                    title: "SWF ActionScript tags detected".into(),
                    description:
                        "SWF stream contains ActionScript tags (DoAction/DoInitAction/DoABC)."
                            .into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: action_evidence,
                    remediation: Some("Review the ActionScript tags for malicious logic.".into()),
                    meta: action_meta,
                    action_type: None,
                    action_target: None,
                    action_initiation: None,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                });
            }
        }
        Ok(findings)
    }
}

fn insert_stream_analysis_meta(meta: &mut HashMap<String, String>, data: &[u8]) {
    let analysis = analyse_stream(data, &StreamLimits::default());
    meta.insert("stream.magic_type".into(), analysis.magic_type);
    meta.insert("stream.entropy".into(), format!("{:.2}", analysis.entropy));
    meta.insert("stream.blake3".into(), analysis.blake3);
    meta.insert("size_bytes".into(), analysis.size_bytes.to_string());
}

fn is_rich_media_dict(dict: &PdfDict<'_>) -> bool {
    dict.has_name(b"/Type", b"/RichMedia")
        || dict.has_name(b"/Subtype", b"/RichMedia")
        || dict.has_name(b"/Subtype", b"/Flash")
        || dict.get_first(b"/RichMedia").is_some()
}

fn is_3d_dict(dict: &PdfDict<'_>) -> bool {
    dict.has_name(b"/Type", b"/3D")
        || dict.has_name(b"/Subtype", b"/3D")
        || dict.get_first(b"/3D").is_some()
        || dict.get_first(b"/U3D").is_some()
        || dict.get_first(b"/PRC").is_some()
}

fn filter_depth(dict: &PdfDict<'_>) -> usize {
    let Some((_, filter_obj)) = dict.get_first(b"/Filter") else {
        return 0;
    };
    match &filter_obj.atom {
        PdfAtom::Name(_) => 1,
        PdfAtom::Array(items) => items
            .iter()
            .filter(|item| matches!(item.atom, PdfAtom::Name(_) | PdfAtom::Ref { .. }))
            .count(),
        _ => 0,
    }
}

const U3D_BLOCK_PARSE_LIMIT: usize = 512;
const RICHMEDIA_DECODE_EXPANSION_RATIO_LIMIT: f64 = 40.0;
const RICHMEDIA_DECLARED_LENGTH_TOLERANCE: usize = 32;

fn declared_stream_length(dict: &PdfDict<'_>) -> Option<usize> {
    let (_, value) = dict.get_first(b"/Length")?;
    if let PdfAtom::Int(length) = value.atom {
        return Some(length.max(0) as usize);
    }
    None
}

fn analyse_u3d_block_table(
    data: &[u8],
    anomalies: &mut Vec<String>,
    meta: &mut HashMap<String, String>,
) {
    if data.len() < 12 {
        anomalies.push("u3d_block_header_truncated".to_string());
        return;
    }

    let mut offset = 0usize;
    let mut block_count = 0usize;
    let mut parse_failed = false;
    while offset + 12 <= data.len() && block_count < U3D_BLOCK_PARSE_LIMIT {
        let block_len = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) as usize;
        let metadata_len = u32::from_be_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
        ]) as usize;
        let block_total =
            12usize.checked_add(block_len).and_then(|total| total.checked_add(metadata_len));
        let Some(block_total) = block_total else {
            anomalies.push("u3d_block_length_overflow".to_string());
            parse_failed = true;
            break;
        };

        if block_total == 12 {
            anomalies.push("u3d_zero_sized_block".to_string());
            parse_failed = true;
            break;
        }

        if offset + block_total > data.len() {
            anomalies.push("u3d_block_table_out_of_bounds".to_string());
            parse_failed = true;
            break;
        }

        offset += block_total;
        block_count += 1;
    }

    if block_count >= U3D_BLOCK_PARSE_LIMIT && offset < data.len() {
        anomalies.push("u3d_block_table_iteration_limit_reached".to_string());
    }
    if block_count == 0 {
        anomalies.push("u3d_no_complete_blocks".to_string());
    }
    if block_count > 256 {
        anomalies.push("u3d_block_count_excessive".to_string());
    }
    if !parse_failed && offset < data.len() {
        anomalies.push("u3d_block_table_trailing_bytes".to_string());
    }

    meta.insert("richmedia.3d.block_count_estimate".into(), block_count.to_string());
    meta.insert("richmedia.3d.block_table_consumed_bytes".into(), offset.to_string());
    meta.insert(
        "richmedia.3d.block_table_trailing_bytes".into(),
        data.len().saturating_sub(offset).to_string(),
    );
}

fn analyse_3d_stream(
    obj: u32,
    gen: u16,
    dict: &PdfDict<'_>,
    stream: &sis_pdf_pdf::object::PdfStream<'_>,
    stream_bytes: &[u8],
    decode_success: bool,
) -> Vec<Finding> {
    let Some(media_type) = detect_3d_format(stream_bytes) else {
        return Vec::new();
    };
    let mut anomaly_reasons = Vec::new();
    let encoded_stream_len = stream.data_span.len();
    let declared_stream_len = declared_stream_length(dict);
    if stream_bytes.len() < 16 {
        anomaly_reasons.push("too_small_for_3d_header".to_string());
    }
    if media_type == "u3d" {
        if stream_bytes.len() >= 8 {
            let declared_block_len = u32::from_be_bytes([
                stream_bytes[4],
                stream_bytes[5],
                stream_bytes[6],
                stream_bytes[7],
            ]) as usize;
            if declared_block_len > stream_bytes.len().saturating_sub(8) {
                anomaly_reasons.push("u3d_declared_block_len_out_of_bounds".to_string());
            }
            if declared_block_len == 0 {
                anomaly_reasons.push("u3d_zero_block_len".to_string());
            }
        } else {
            anomaly_reasons.push("u3d_header_truncated".to_string());
        }
    }
    let mut u3d_table_meta = HashMap::new();
    if media_type == "u3d" {
        analyse_u3d_block_table(stream_bytes, &mut anomaly_reasons, &mut u3d_table_meta);
    } else if media_type == "prc" {
        if stream_bytes.len() < 32 {
            anomaly_reasons.push("prc_header_truncated".to_string());
        }
        let printable = stream_bytes
            .iter()
            .take(32)
            .filter(|byte| byte.is_ascii_graphic() || **byte == b' ')
            .count();
        if printable < 3 {
            anomaly_reasons.push("prc_header_non_printable_bias".to_string());
        }
    }

    let analysis = analyse_stream(stream_bytes, &StreamLimits::default());
    let filter_depth = filter_depth(dict);
    let decode_expansion_ratio = if encoded_stream_len == 0 {
        1.0
    } else {
        stream_bytes.len() as f64 / encoded_stream_len as f64
    };
    if decode_success && decode_expansion_ratio > RICHMEDIA_DECODE_EXPANSION_RATIO_LIMIT {
        anomaly_reasons.push("richmedia_decode_expansion_ratio_high".to_string());
    }
    if !decode_success && filter_depth >= 1 {
        anomaly_reasons.push("richmedia_decode_failed_with_filters".to_string());
    }
    if let Some(declared) = declared_stream_len {
        let mismatch = (declared as i64 - encoded_stream_len as i64).unsigned_abs() as usize;
        if mismatch > RICHMEDIA_DECLARED_LENGTH_TOLERANCE {
            anomaly_reasons.push("richmedia_declared_length_mismatch".to_string());
        }
    }
    let has_decoder_correlation = !anomaly_reasons.is_empty()
        && (analysis.entropy >= 7.2
            || filter_depth >= 3
            || !decode_success
            || decode_expansion_ratio > RICHMEDIA_DECODE_EXPANSION_RATIO_LIMIT);

    if anomaly_reasons.is_empty() {
        return Vec::new();
    }

    let object_ref = format!("{} {} obj", obj, gen);
    let mut meta = HashMap::new();
    meta.insert("media_type".into(), media_type.to_string());
    meta.insert("richmedia.3d.decode_success".into(), decode_success.to_string());
    meta.insert("richmedia.3d.structure_anomalies".into(), anomaly_reasons.join(","));
    meta.insert("richmedia.3d.filter_depth".into(), filter_depth.to_string());
    meta.insert(
        "richmedia.3d.decoded_expansion_ratio".into(),
        format!("{decode_expansion_ratio:.2}"),
    );
    meta.insert("richmedia.3d.encoded_stream_bytes".into(), encoded_stream_len.to_string());
    if let Some(declared) = declared_stream_len {
        meta.insert("richmedia.3d.declared_stream_length".into(), declared.to_string());
    }
    meta.insert("stream.magic_type".into(), analysis.magic_type.clone());
    meta.insert("stream.entropy".into(), format!("{:.2}", analysis.entropy));
    meta.insert("stream.blake3".into(), analysis.blake3.clone());
    meta.insert("size_bytes".into(), stream_bytes.len().to_string());
    meta.extend(u3d_table_meta);

    let evidence = EvidenceBuilder::new()
        .file_offset(stream.dict.span.start, stream.dict.span.len() as u32, "3D stream dict")
        .file_offset(stream.data_span.start, stream.data_span.len() as u32, "3D stream data")
        .build();

    let mut findings = vec![Finding {
        id: String::new(),
        surface: AttackSurface::RichMedia3D,
        kind: "richmedia_3d_structure_anomaly".into(),
        severity: if has_decoder_correlation { Severity::High } else { Severity::Medium },
        confidence: if anomaly_reasons.len() >= 2 {
            Confidence::Strong
        } else {
            Confidence::Probable
        },
        impact: Some(if has_decoder_correlation { Impact::High } else { Impact::Medium }),
        title: "3D rich-media structure anomaly".into(),
        description:
            "U3D/PRC stream structure deviates from bounded sanity checks and may indicate malformed or exploit-oriented payload material."
                .into(),
        objects: vec![object_ref.clone()],
        evidence: evidence.clone(),
        remediation: Some(
            "Treat malformed 3D assets as high-risk and replay with strict decode/resource limits."
                .into(),
        ),
        meta: meta.clone(),
        action_type: None,
        action_target: None,
        action_initiation: None,
        yara: None,
        position: None,
        positions: Vec::new(),
    }];

    if has_decoder_correlation {
        let mut risk_meta = meta;
        risk_meta.insert(
            "richmedia.3d.decoder_correlation".into(),
            format!(
                "entropy={:.2},filter_depth={},decode_success={}",
                analysis.entropy, filter_depth, decode_success
            ),
        );
        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::RichMedia3D,
            kind: "richmedia_3d_decoder_risk".into(),
            severity: Severity::High,
            confidence: Confidence::Strong,
            impact: Some(Impact::High),
            title: "3D rich-media decoder risk correlation".into(),
            description:
                "3D structure anomalies co-occur with decoder-risk factors (high entropy, deep filter chain, or decode instability)."
                    .into(),
            objects: vec![object_ref],
            evidence,
            remediation: Some(
                "Prioritise this file for sandbox replay and isolate renderer pipelines handling embedded 3D content."
                    .into(),
            ),
            meta: risk_meta,
            action_type: None,
            action_target: None,
            action_initiation: None,
            yara: None,
            position: None,
            positions: Vec::new(),
        });
    }

    findings
}

fn encode_list(values: &[String]) -> String {
    let escaped: Vec<String> = values
        .iter()
        .map(|value| {
            format!(
                "\"{}\"",
                value.replace('\\', "\\\\").replace('"', "\\\"").replace(['\n', '\r'], " ")
            )
        })
        .collect();
    format!("[{}]", escaped.join(","))
}
